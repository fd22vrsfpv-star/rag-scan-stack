"""Lateral movement: chain harvested creds → scope-gated spray, bounded + logged.

Lateral movement here is emergent — post-ex harvests creds, then the reuse loop
sprays them to OTHER in-scope hosts. The safety that matters: every hop still
passes the scope gate + approval (the reuse loop already enforces this), chaining
is hop-bounded so it terminates, and the attack path is recorded for the report.
Source-checked (ast) + a live shape check on the ledger endpoint.
"""
import ast
import os
import re
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
RUNNER = REPO / "exploit_runner" / "exploit_runner.py"


def test_chain_recording_is_downstream_of_the_scope_gate():
    src = API.read_text(encoding="utf-8")
    node = next((n for n in ast.walk(ast.parse(src))
                 if isinstance(n, ast.FunctionDef) and n.name == "credentials_reuse"), None)
    assert node is not None
    body = ast.get_source_segment(src, node)
    # the chain is recorded from `plan`, which is only built AFTER check_dispatch
    gate = body.index("check_dispatch(")
    record = body.index("INSERT INTO public.lateral_movement")
    assert gate < record, (
        "lateral_movement must be recorded from the post-scope-gate plan — a hop "
        "is logged only after it passed the scope gate")


def test_lateral_is_hop_bounded_so_chaining_terminates():
    src = RUNNER.read_text(encoding="utf-8")
    assert "hop_depth < req.max_hops" in src, (
        "post-ex lateral must be bounded by max_hops or chaining never terminates")
    # lateral spray is plan-only from post-ex (dispatch stays behind approval)
    node = next((n for n in ast.walk(ast.parse(src))
                 if isinstance(n, ast.FunctionDef) and n.name == "postex_enumerate"), None)
    body = ast.get_source_segment(src, node) if node else src
    assert '"dispatch": False' in body, (
        "post-ex must PLAN the lateral spray, not auto-dispatch it — spraying "
        "stays behind the approval flow")


def test_lateral_only_chains_when_creds_were_harvested():
    src = RUNNER.read_text(encoding="utf-8")
    assert "req.lateral and harvested" in src, (
        "no harvested creds -> no lateral hop")


# ── live: the attack-path ledger endpoint ────────────────────────────────────
BASE = os.environ.get("LAT_URL", "https://localhost:8000")


def _key():
    env = REPO / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def test_lateral_ledger_endpoint_shape():
    requests = pytest.importorskip("requests")
    try:
        r = requests.get(f"{BASE}/lateral/00000000-0000-0000-0000-000000000000",
                         headers={"x-api-key": _key()}, timeout=15, verify=False)
    except Exception as e:
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, r.text[:200]
    b = r.json()
    assert isinstance(b["hops"], list)
    assert "hosts_reached" in b and "max_hop" in b
