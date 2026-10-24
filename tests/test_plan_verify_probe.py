"""A plan-verify probe that could not test a candidate recorded FAKE.

THE DEFECT (CVE-2023-37999, three runs, 2026-10-22/23)
------------------------------------------------------
`_verify_strategist_plan` step 2 sends `?<param>=<canary>` by GET and compares
the response to a bare baseline. No delta => FAKE. It dropped two things the
plan supplied: the `method` (parsed, but only used in the 404 retry) and the
`payload_hint` (never parsed at all). So a plan reading

    PRIMARY: endpoint=/wp-admin/admin-ajax.php param=reg_role method=POST
             payload_hint=`action=htmega_ajax_register&…&reg_role=administrator`

was tested as `GET /wp-admin/admin-ajax.php?reg_role=z3st4v`.

WordPress admin-ajax.php DISPATCHES on `action`. Without it every reply is the
1-byte body "0", so no parameter can ever produce a delta. From the trace:

    PRIMARY endpoint=/wp-admin/admin-ajax.php param `reg_role` is IGNORED (baseline=1, probed=1 — no delta)
    ALT1    endpoint=/wp-admin/admin-ajax.php param `action`   is IGNORED (baseline=1, probed=1 — no delta)

ALT1 probed the dispatch key ITSELF and still read IGNORED. The correct
endpoint was unprovable by construction, and FAKE demoted it every run:
`gather_incomplete:endpoint`, then `max_iters` and `off_target` at the wrong
endpoint.

WHAT MUST NOT REGRESS
---------------------
This gate exists because the strategist DOES hallucinate — CVE-2024-32964's
`/api/proxy` was invented and the pipeline ran it to all_404. Widening the
verdict must not disarm it: a 404 is still FAKE, and a parameter that genuinely
changes nothing on a real response is still FAKE
(`test_a_genuinely_ignored_parameter_is_still_fake`).

Static extraction rather than importing api.py — same convention as
tests/test_assertion_drift_repair.py.

    pytest tests/test_plan_verify_probe.py
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

# the real plan line from poc_logs/CVE-2023-37999_172.19.150.154_1792767257.jsonl
PAYLOAD_HINT = ("action=htmega_ajax_register&reg_name=secvaluser&reg_password=Pass1234"
                "&reg_email=secval@example.com&reg_role=administrator")
CANARY = "z3st4v"


def _load():
    tree = ast.parse(API.read_text(encoding="utf-8"))
    want = {"_plan_probe_body", "_why_no_delta_is_unprovable", "_probe_with_plan_shape"}
    picked = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in want]
    missing = want - {n.name for n in picked}
    if missing:
        pytest.fail(f"function(s) gone from api.py: {sorted(missing)}")
    consts = [n for n in tree.body if isinstance(n, ast.Assign)
              and any(getattr(t, "id", "") == "_PLAN_PROBE_MIN_SIGNAL_BYTES" for t in n.targets)]
    ns: dict = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=consts + picked, type_ignores=[])),
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


# ── the probe now sends what the plan proposed ──────────────────────────────

def test_the_dispatch_parameter_survives_the_probe(ns):
    """`action=` is what routes the request to the vulnerable handler. Drop it
    and the endpoint cannot be tested by any parameter."""
    body = ns["_plan_probe_body"](PAYLOAD_HINT, "reg_role", CANARY)
    assert body["action"] == "htmega_ajax_register"
    assert body["reg_role"] == CANARY, "the parameter under test must carry the canary"
    assert body["reg_email"] == "secval@example.com", "other plan fields must be preserved"


def test_no_payload_hint_falls_back_to_the_old_single_param_probe(ns):
    for empty in (None, "", "   ", "not-form-encoded"):
        assert ns["_plan_probe_body"](empty, "x", CANARY) is None


def test_a_header_input_stays_a_header(ns):
    """SABOTAGE GUARD. The header path predates this change and must win over
    the plan body."""
    src = _src(API, "_probe_with_plan_shape")
    assert "if hdr_param:" in src
    assert src.index("if hdr_param:") < src.index("if data:"), \
        "a header-carried input must be decided BEFORE the plan body"


def test_a_non_get_sends_a_body_not_a_query_string():
    """POSTing the plan's fields as `?a=b` reaches a different handler, which is
    the same mistake as not sending them."""
    src = _src(API, "_verify_strategist_plan")
    assert {"GET", "HEAD", "DELETE"} <= _ast_assert.string_constants(src)
    assert call_kwarg(src, "cli.request", "data")


# ── "could not test" is no longer "is fake" ─────────────────────────────────

@pytest.mark.parametrize("bs,bl,ps,pl,why", [
    (400, 1, 400, 1, "the real admin-ajax case: 400 to both probes"),
    (200, 1, 200, 1, "constant sentinel body '0'"),
    (403, 900, 403, 900, "auth wall answering both identically"),
    (500, 120, 500, 120, "server error both times"),
])
def test_an_untestable_comparison_is_unproven_not_fake(ns, bs, bl, ps, pl, why):
    assert ns["_why_no_delta_is_unprovable"](bs, bl, ps, pl), why


def test_a_genuinely_ignored_parameter_is_still_fake(ns):
    """SABOTAGE GUARD, and the one that matters. The endpoint answered normally
    both times and the parameter changed nothing — the only case that justifies
    FAKE. If this returns a reason, the gate is disarmed and the hallucination
    detector is gone."""
    assert ns["_why_no_delta_is_unprovable"](200, 5000, 200, 5000) == ""
    assert ns["_why_no_delta_is_unprovable"](200, 193728, 200, 193728) == ""


def test_the_verdict_is_wired_into_the_function():
    src = _src(API, "_verify_strategist_plan")
    assert calls(src, "_why_no_delta_is_unprovable"), "the distinction is computed but never used"
    assert "UNPROVEN" in _ast_assert.string_constants(src)
    assert {"LIVE", "SUSPECT", "NEEDS_ID", "UNPROVEN"} <= _ast_assert.string_constants(src), \
        "an UNPROVEN candidate must survive into the plan, not trigger the ALL-FAKE directive"


# ── the end self-check ──────────────────────────────────────────────────────

def test_a_non_404_fake_primary_beside_a_live_alt_is_questioned():
    """The shape that appeared three runs running and was the probe every time."""
    src = _src(API, "_verify_strategist_plan")
    assert {"PRIMARY", "UNPROVEN"} <= _ast_assert.string_constants(src)
    assert "FAKE (404)" in _ast_assert.string_constants(src), \
        "a 404 IS evidence — only a no-delta FAKE may be questioned"


def test_the_all_fake_directive_does_not_claim_404():
    """It used to hardcode 'all returned 404 or network error ... proven
    unreachable' for candidates that had answered 200."""
    src = _src(API, "_verify_strategist_plan")
    assert "proven unreachable" not in src
    assert "ALL STRATEGIST CANDIDATES WERE EMPIRICALLY FAKE" not in src


# ── instrumentation ─────────────────────────────────────────────────────────

def test_the_reason_reaches_the_verdict_event():
    """`recon:plan_verified` recorded {'PRIMARY': 'FAKE'} and nothing else, so
    the cause was only findable by grepping a later phase's guidance blob."""
    api = _src(API, "_verify_strategist_plan")
    assert "return banner + \"\\n\" + new_plan, verdicts, notes" in api, \
        "notes must be returned, not only embedded in the plan text"
    graph = _src(GRAPH, "node_plan_verify")
    assert call_kwarg(graph, "_poc_trace", "extra"), "the verdict event must carry the reason"
    assert "verify_notes" in graph


def test_every_return_path_has_the_same_arity():
    """A 2-tuple return on an early exit unpacks into a 3-tuple caller as a
    ValueError at runtime — invisible to ast.parse and to import."""
    src = _src(API, "_verify_strategist_plan")
    tree = ast.parse(src)
    fn = tree.body[0]
    arities = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple):
            arities.append(len(n.value.elts))
    assert arities, "no tuple returns found — did the signature change?"
    assert set(arities) == {3}, f"mixed return arities {sorted(set(arities))}"
