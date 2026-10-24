"""A fact proven on one endpoint was enforced against a different one.

THE DEFECT (CVE-2023-37999 run 3, 2026-10-23)
---------------------------------------------
`confirmed_facts` is keyed on `ip:port`, so it accumulates every value any
build ever proved against that host. `_required_facts_for` read them all and
took the highest-confidence one, with no notion of WHICH endpoint a fact was
proven against and no preference for the run that is happening now.

Run 3 finally reached the right endpoint — the gather manifest read

    [gathered] endpoint    = /wp-admin/admin-ajax.php  (via plan_verify:LIVE)
    [gathered] input_field = reg_role                  (via plan_verify)

— and the gate armed itself from a PRIOR failed build instead:

    fact_predispatch_refused
      required: {"endpoint_exists": "/wp-admin/admin-ajax.php?action=htmega_ajax_register",
                 "input_field": "roles"}

`roles` is the WordPress REST parameter, proven against /wp-json/wp/v2/users in
an earlier build. The gate REFUSED the one command carrying the advisory's real
parameters (`reg_name`/`reg_role`/`reg_email`/`reg_password`), and the nine
commands that followed all used `roles=administrator` to satisfy it. HT Mega
ignores `roles`, so every one returned

    {"registerauth":false,"message":"Username, Password and E-Mail are required"}

— nine identical outcomes, `stop_reason=axis_exhausted`.

WHAT MUST NOT REGRESS
---------------------
The gate exists because a model that ignores a proven fact is not exercising
the vulnerability: "in a previous build a proven parameter was absent from all
26 dispatched commands, every one of which failed." Scoping must not empty it —
a fact proven on the endpoint under attack is still enforced, and an unscoped
legacy row still counts when this run has nothing to say
(`test_a_legacy_unscoped_fact_still_arms_the_gate`).

The primitives themselves (scope parsing, may_enforce, prefer_current) are
covered by tests/test_enforcement_scope.py; this file covers only what is
specific to the proven-fact gate.

Static extraction rather than importing api.py.

    pytest tests/test_proven_fact_scope.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _ast_assert  # noqa: E402
from _ast_assert import calls, call_kwarg, defines, call_order  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
API = ROOT / "app" / "rag-api" / "api.py"
GRAPH = ROOT / "app" / "rag-api" / "build_poc_graph.py"

REAL_ENDPOINT = "/wp-admin/admin-ajax.php"
PRIOR_ENDPOINT = "/wp-json/wp/v2/users"

# the real run-3 manifest
MANIFEST = {"items": [
    {"item": "target_reachable", "status": "gathered", "value": "HTTP 200"},
    {"item": "endpoint", "status": "gathered", "value": REAL_ENDPOINT},
    {"item": "method", "status": "gathered", "value": "GET,POST"},
    {"item": "input_field", "status": "gathered", "value": "reg_role"},
    {"item": "auth", "status": "n/a", "value": "not required by advisory"},
]}


def _load():
    tree = ast.parse(API.read_text(encoding="utf-8"))
    want = {"_manifest_enforceable_facts"}
    picked = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in want]
    missing = want - {n.name for n in picked}
    if missing:
        pytest.fail(f"function(s) gone from api.py: {sorted(missing)}")
    ns: dict = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=picked, type_ignores=[])),
                 "<api-subset>", "exec"), ns)
    return ns


@pytest.fixture(scope="module")
def ns():
    return _load()


def _src(path, name):
    txt = path.read_text(encoding="utf-8")
    fn = next((n for n in ast.walk(ast.parse(txt))
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn is not None, f"{name} is gone from {path.name}"
    return ast.get_source_segment(txt, fn) or ""


# ── the manifest is this run's own evidence ─────────────────────────────────

def test_the_manifest_yields_the_enforceable_claims(ns):
    got = ns["_manifest_enforceable_facts"](MANIFEST)
    assert got == {"endpoint_exists": REAL_ENDPOINT, "input_field": "reg_role"}


def test_an_ungathered_item_is_not_a_fact(ns):
    """`missing` / `unverified` / `n/a` items must not arm the gate."""
    man = {"items": [
        {"item": "input_field", "status": "missing", "value": None},
        {"item": "endpoint", "status": "unverified", "value": "/guess"},
    ]}
    assert ns["_manifest_enforceable_facts"](man) == {}


def test_an_absent_manifest_is_not_an_error(ns):
    for bad in (None, {}, {"items": []}, "not a dict"):
        assert ns["_manifest_enforceable_facts"](bad) == {}


def test_the_current_run_overrides_a_stored_fact():
    src = _src(API, "_required_facts_for")
    assert calls(src, "prefer_current"), \
        "the current run's manifest must win over a stored fact"
    assert src.index("prefer_current(") > src.index("cur.fetchall()"), \
        "the override must come AFTER the stored rows, or the stored one wins"


# ── a fact is proven ABOUT an endpoint ──────────────────────────────────────

def test_a_fact_from_another_endpoint_is_dropped():
    src = _src(API, "_required_facts_for")
    assert calls(src, "may_enforce"), "the gate must ask the shared primitive"
    assert calls(src, "_fact_scope_endpoint"), "it must read the fact's recorded scope"
    assert "continue" in src.split("may_enforce(")[1][:160], \
        "a fact scoped elsewhere must be skipped"


def test_a_legacy_unscoped_fact_still_arms_the_gate():
    """SABOTAGE GUARD. An unscoped row is not evidence AGAINST the command —
    dropping every legacy fact would empty the gate silently."""
    src = _src(API, "_required_facts_for")
    assert calls(src, "_enforcement_scope"), (
        "the skip must go through may_enforce, which fails OPEN on an unknown "
        "scope — see tests/test_enforcement_scope.py::test_an_unknown_scope_fails_open")


def test_the_fact_writer_records_its_endpoint():
    src = _src(API, "_preflight_prove_facts")
    assert calls(src, "_enforcement_scope"), \
        "a fact written without its endpoint can never be scoped"
    assert calls(src, "flat.get")


def test_recency_breaks_a_confidence_tie():
    src = _src(API, "_required_facts_for")
    assert "ORDER BY confidence DESC, last_checked_at DESC" in src, \
        "two equally-confident facts must not be ordered arbitrarily"


# ── wiring ──────────────────────────────────────────────────────────────────

def test_the_refine_loop_is_given_this_runs_manifest():
    src = _src(API, "_run_refine_poc")
    assert calls(src, "_manifest_enforceable_facts")
    assert call_kwarg(src, "_required_facts_for", "current_facts")
    assert calls(src, "_man_facts.get"), \
        "the scope filter needs the endpoint this run is attacking"


def test_both_graph_call_sites_pass_the_manifest():
    g = GRAPH.read_text(encoding="utf-8")
    assert g.count("gather_manifest=state.get(\"gather_manifest\")") == 2, (
        "the second refine pass (after deep recon) must pass it too — a "
        "name-only check passes while one call site is missed"
    )
