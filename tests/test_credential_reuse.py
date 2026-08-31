"""Credential-reuse (spray) loop — safety properties (Phase 2).

Spraying a credential across hosts is impactful and is NEVER autonomous in this
platform. The reuse endpoint must therefore: (1) PLAN by default (dispatch off),
(2) scope-gate every candidate target here AND rely on brutus re-gating, (3) not
record a spray that brutus refused. Source-checked (ast) so it runs offline, plus
a live dry-run that must return a plan without dispatching.

Sabotage: default `dispatch: bool = True` -> test_plan_only_by_default RED.
"""
import ast
import os
import re
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"


def _fn_src():
    src = API.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "credentials_reuse":
            return ast.get_source_segment(src, node), src
    pytest.skip("credentials_reuse endpoint not found")


def test_plan_only_by_default():
    src = API.read_text(encoding="utf-8")
    # the request model must default dispatch to False (plan-only, safe)
    m = re.search(r"class CredentialReuseRequest.*?dispatch:\s*bool\s*=\s*(\w+)", src, re.S)
    assert m and m.group(1) == "False", (
        "CredentialReuseRequest.dispatch must default to False — credential "
        "spraying is impactful and must be opt-in, never the default")


def test_reuse_scope_gates_every_target():
    body, _ = _fn_src()
    assert "check_dispatch(" in body, (
        "the reuse loop must call check_dispatch per target — a spray to an "
        "out-of-scope host must be refused")
    assert "refused_out_of_scope" in body


def test_reuse_honours_brutus_refusal():
    body, _ = _fn_src()
    assert "403" in body, (
        "a brutus 403 (out-of-scope / halted) must be handled — the spray is "
        "double-gated (here and at brutus)")
    # the 403 branch must not fall through to recording the attempt
    assert "continue" in body


def test_reuse_dedups_attempts():
    body, _ = _fn_src()
    assert "credential_spray_attempts" in body and "skipped_already_attempted" in body, (
        "the reuse loop must dedup against credential_spray_attempts so a "
        "(credential, target) pair is sprayed once")


# ── live dry-run (skip without a stack) ──────────────────────────────────────
BASE = os.environ.get("CRED_URL", "https://localhost:8000")


def _key():
    env = REPO / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def test_reuse_dry_run_returns_a_plan():
    requests = pytest.importorskip("requests")
    try:
        r = requests.post(f"{BASE}/credentials/reuse",
                          json={"dispatch": False, "max_targets": 20},
                          headers={"x-api-key": _key()}, timeout=25, verify=False)
    except Exception as e:
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, f"reuse 500/err: {r.text[:300]}"
    b = r.json()
    assert b["dispatch"] is False and b["dispatched"] == []
    for k in ("verified_credentials", "plan", "planned",
              "skipped_already_attempted", "refused_out_of_scope"):
        assert k in b
    assert isinstance(b["plan"], list)


# ── lockout-safety: rate limit + (account, service) approval ─────────────────

def test_require_approval_defaults_on():
    src = API.read_text(encoding="utf-8")
    m = re.search(r"class CredentialReuseRequest.*?require_approval:\s*bool\s*=\s*(\w+)", src, re.S)
    assert m and m.group(1) == "True", (
        "require_approval must default True — a spray to an (account, service) "
        "pair must be held until approved")


def test_per_account_rate_limit_is_enforced():
    body, src = _fn_src()
    assert "max_attempts_per_account" in src, "reuse must expose a per-account cap"
    # the loop must count recent attempts per account and throttle
    assert "throttled" in body and "_account_rate_limit(" in body, (
        "the loop must derive a per-account limit (from the discovered policy "
        "when present) and throttle once reached")


def test_policy_overrides_to_stay_under_lockout():
    src = API.read_text(encoding="utf-8")
    # the policy helper must use threshold-1 (stay under lockout)
    assert "thr - 1" in src, (
        "_account_rate_limit must cap at lockout_threshold-1 so a real account "
        "is never locked out")


def test_approval_is_tied_to_account_and_service():
    body, src = _fn_src()
    assert 'approvals.get((uname.lower(), proto)' in body, (
        "approval must be keyed on (account, service), not the whole run")
    assert "held_needs_approval" in body
    assert "credentials_spray_approval" in src, "an approval endpoint must exist"
