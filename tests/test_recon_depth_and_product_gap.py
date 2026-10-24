"""Deeper recon for a target we cannot name, and a knob to ask for it.

THE TWO GAPS (CVE-Bench top-20 run 2, CVE-2023-37999, 2026-10-22)
-----------------------------------------------------------------
1. `_deep_recon_plan` branched on `endpoint` / `endpoint_id` / `input_field` /
   `method` / `auth`. "We do not know what this product IS" was not a gap it
   could plan for, so on an unidentified target it widened the PATH search
   while the thing that actually unlocks the attack path went unretried.
   `_identify_product_from_target` runs ONCE, against the landing page, before
   any crawling — and on this run it returned nothing, leaving
   `product=unknown` for the whole build.

2. First-pass depth is decided by `recon_source`, which defaults to `"basic"`
   and which the bench runner pins to `"basic"`. `_want("basic", "zap")` is
   False, so the ZAP spider never ran in the main chain — its paths appeared
   only in the remedial deep pass, 111 seconds after the gate that needed
   them. There was no way to ask for more without knowing the legacy tool-set
   vocabulary, and no way at all to get a SECOND remedial pass.

WHAT MUST NOT REGRESS
---------------------
Depth is not authorization and it is not unbounded. `_deep_recon_for_gaps`
re-checks the PoC grant and fails closed; the passes stay bounded by the
posture (`test_deep_posture_is_still_bounded`); an unrecognised depth falls
back rather than silently picking one.

Static extraction rather than importing api.py — same convention as
tests/test_assertion_drift_repair.py.

    pytest tests/test_recon_depth_and_product_gap.py
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


def _load():
    tree = ast.parse(API.read_text(encoding="utf-8"))
    want = {"_deep_recon_plan", "_product_is_known", "_recon_depth_profile"}
    picked = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in want]
    missing = want - {n.name for n in picked}
    if missing:
        pytest.fail(f"function(s) gone from api.py: {sorted(missing)}")
    wanted_consts = ("_UNNAMED_PRODUCT", "_RECON_DEPTH_PROFILES")
    consts = [n for n in tree.body if isinstance(n, ast.Assign)
              and any(getattr(t, "id", "") in wanted_consts for t in n.targets)]
    # A module-level name bound TWICE is a trap: Python keeps the last binding,
    # so the earlier one is dead and any test that execs both exercises the
    # wrong value. This is how the first version of this file passed a sabotage
    # of its own constant — `_PRODUCT_UNKNOWN` already existed elsewhere in
    # api.py and silently shadowed it.
    for name in wanted_consts:
        n_defs = sum(1 for n in tree.body if isinstance(n, ast.Assign)
                     and any(getattr(t, "id", "") == name for t in n.targets))
        if n_defs != 1:
            pytest.fail(f"{name} is defined {n_defs} times at module level in api.py "
                        f"(expected exactly 1 — a duplicate binding silently wins by line order)")
    mod = ast.Module(body=consts + picked, type_ignores=[])
    ns: dict = {}
    exec(compile(ast.fix_missing_locations(mod), "<api-subset>", "exec"), ns)
    return ns


@pytest.fixture(scope="module")
def ns():
    return _load()


def _src(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn is not None, f"{name} is gone from {path.name}"
    return ast.get_source_segment(path.read_text(encoding="utf-8"), fn) or ""


# ── 1. the product gap ───────────────────────────────────────────────────────

@pytest.mark.parametrize("blank", ["unknown", "", None, "n/a", "-", "none", "UNKNOWN", " Unknown "])
def test_a_filled_product_field_can_still_name_nothing(ns, blank):
    assert ns["_product_is_known"](blank) is False


@pytest.mark.parametrize("real", ["WordPress", "Zabbix", "SuiteCRM", "Apache HTTP Server"])
def test_a_real_product_is_known(ns, real):
    assert ns["_product_is_known"](real) is True


def test_an_unnamed_product_plans_identification_first(ns):
    """The real CVE-2023-37999 gap set."""
    plan = ns["_deep_recon_plan"](["endpoint"], has_session=False,
                                  vuln_class="privilege-escalation",
                                  product_known=False)
    assert plan and plan[0] == "product_id", plan


def test_a_named_product_does_not_re_identify(ns):
    plan = ns["_deep_recon_plan"](["endpoint"], has_session=False,
                                  vuln_class="privilege-escalation",
                                  product_known=True)
    assert "product_id" not in plan, plan


def test_identification_does_not_displace_the_other_steps(ns):
    """Adding a gap must not drop the remediation that already worked."""
    known = ns["_deep_recon_plan"](["endpoint", "input_field"], False, "", product_known=True)
    unknown = ns["_deep_recon_plan"](["endpoint", "input_field"], False, "", product_known=False)
    assert unknown == ["product_id"] + known, (known, unknown)


def test_an_artifact_only_gap_still_plans_nothing(ns):
    """SABOTAGE GUARD. An artifact gap is not a recon gap — not even for an
    unidentified target, or every artifact-blocked build grows a probe pass."""
    assert ns["_deep_recon_plan"](["artifact"], False, "", product_known=False) == []


def test_the_step_is_dispatchable():
    """A planned step with no branch is a silent no-op."""
    assert '"product_id"' in API.read_text(encoding="utf-8")
    src = _src(API, "_deep_recon_for_gaps")
    assert "product_id" in _ast_assert.string_constants(src), "product_id is planned but never executed"
    assert calls(src, "_deep_identify_product")
    assert 'if not _known and "product_id" not in plan:' in src, (
        "the solutions layer can supply its own plan and has no notion of an "
        "unnamed product — the step must be ensured after that merge"
    )


def test_the_step_is_declared():
    assert "product_id" in (_ast_assert.const_elements(API.read_text(encoding="utf-8"), "_DEEP_RECON_STEPS") or set())


def test_identification_sends_no_payloads():
    """It is recon, not a scan: fixed metadata paths, GET only."""
    src = _src(API, "_deep_identify_product")
    assert calls(src, "c.get")
    for verb in (".post(", ".put(", ".delete("):
        assert verb not in src, f"product identification must not {verb}"


def test_the_graph_backfills_an_identified_product():
    src = _src(GRAPH, "node_deep_recon")
    assert "product" in _ast_assert.string_constants(src), (
        "a product the deep pass identified must reach the rest of the run"
    )
    assert "detected_frameworks" in src, (
        "the fact challenge reads frameworks; an identified product belongs there too"
    )


# ── 2. the depth knob ────────────────────────────────────────────────────────

@pytest.mark.parametrize("depth,src,passes", [
    ("basic", "basic", 1),
    ("standard", "params", 1),
    ("deep", "full", 2),
])
def test_each_posture_maps_to_a_tool_set_and_a_pass_budget(ns, depth, src, passes):
    assert ns["_recon_depth_profile"](depth) == (src, passes)


def test_deep_asks_for_zap_up_front(ns):
    """The whole point: the spider's paths must exist BEFORE the strategist
    grounds against them, not 111 seconds after."""
    src, _ = ns["_recon_depth_profile"]("deep")
    # Mirrors _want(recon_source, "zap") in build_poc_graph.py
    assert src == "full", src


def test_an_unset_depth_changes_nothing(ns):
    assert ns["_recon_depth_profile"](None, "basic") == ("basic", 1)
    assert ns["_recon_depth_profile"](None, "params") == ("params", 1)


def test_an_unrecognised_depth_falls_back_rather_than_guessing(ns):
    """SABOTAGE GUARD. A typo must not silently select a posture — least of all
    a louder one."""
    assert ns["_recon_depth_profile"]("aggressive", "basic") == ("basic", 1)
    assert ns["_recon_depth_profile"]("DEEPER", "params") == ("params", 1)


def test_the_knob_is_on_the_request_and_reaches_the_graph():
    api = API.read_text(encoding="utf-8")
    assert "recon_depth" in api, "no request field"
    assert call_kwarg(api, "_build_poc_core", "recon_depth"), "the endpoint drops it"
    core = _src(API, "_build_poc_core")
    assert calls(core, "_recon_depth_profile")
    assert call_kwarg(core, "initial_state", "deep_recon_max"), "the pass budget never reaches the graph"


def test_deep_posture_is_still_bounded():
    """SABOTAGE GUARD. More passes is not unlimited passes."""
    g = GRAPH.read_text(encoding="utf-8")
    assert g.count("and _deep_passes_left(state)") == 2
    fn = _src(GRAPH, "_deep_passes_left")
    assert "deep_recon_runs" in fn and "deep_recon_max" in fn
    node = _src(GRAPH, "node_deep_recon")
    assert '"deep_recon_runs": _runs' in node, "a pass that is not counted is not bounded"


def test_depth_is_not_authorization():
    """SABOTAGE GUARD, and the one that matters. Asking for deeper recon must
    not become a way past the scope/grant gate — CLAUDE.md: fail closed."""
    src = _src(API, "_deep_recon_for_gaps")
    assert calls(src, "_poc_grant_active")
    assert "no active PoC grant for this target (fail-closed)" in _ast_assert.string_constants(src)
