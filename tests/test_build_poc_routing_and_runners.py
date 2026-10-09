"""2026-10-09: routing keys match the callers; runners do not call a dead route;
the refine loop records its outcome; scan evidence is engagement-filtered.

Found by the CVE-Bench path-detection analysis:
  * `_llm_for_model` routes by task=caller, and the synth/refine call sites are
    named cve_poc_synth / decomposed_craft / cve_poc_refine — an
    `llm.route.exploit.synth` seed row matched nothing (40/40 calls on the
    default model).
  * run_focused10.sh / run_other30.sh POSTed /engagements/{eid}/scope-add, a
    route that does not exist (silent 404; gym.sh does the scoping), and read
    the verdict from derived_cve_specs.verified, which the loop never wrote.
  * `_scan_evidence_for_target` accepted `eid` and ignored it; CVE-Bench reuses
    one IP for every target.

Structural, sabotage-provable (re-add the dead row / call and the test fails).
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
SQL = REPO / "db_init" / "ensure_all_tables.sql"
RUNNERS = [REPO / "cvebench_overnight" / "run_focused10.sh", REPO / "cvebench_overnight" / "run_other30.sh"]


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def _callers_in_api() -> set:
    return set(re.findall(r'caller="([A-Za-z0-9_.\-]+)"', API.read_text()))


def test_llm_for_model_routes_by_caller():
    src = _func_src("_llm_for_model")
    assert src and "task=caller" in src


def test_seeded_route_keys_name_real_callers():
    sql = SQL.read_text()
    seeded = set(re.findall(r"\('llm\.route\.([A-Za-z0-9_.\-]+)',", sql))
    callers = _callers_in_api()
    # every seeded per-task route must correspond to a caller string somewhere
    # in api.py — a route nobody asks for is the bug this guards against
    dead = sorted(k for k in seeded if k not in callers and not k.endswith(".fallback") and k != "default")
    assert not dead, f"seeded routes with no matching caller=: {dead}"
    for must in ("cve_poc_synth", "decomposed_craft", "cve_poc_refine", "exploit.gather_fallback", "exploit.judge"):
        assert must in seeded, must
    assert "exploit.synth" not in seeded


def test_runners_do_not_call_the_nonexistent_scope_add_route():
    for p in RUNNERS:
        s = p.read_text()
        assert "/scope-add" not in s, f"{p.name} still POSTs /engagements/<eid>/scope-add"
        assert "derived_cve_specs" not in s.split("# The verdict is the run's own result")[-1], f"{p.name} still reads derived_cve_specs for the verdict"
        assert "d.get('verified')" in s


def test_scope_add_route_really_does_not_exist():
    assert '"/engagements/{eid}/scope-add"' not in API.read_text()
    assert '"/engagements/{engagement_id}/scope-add"' not in API.read_text()


def test_refine_loop_records_its_outcome_on_derived_specs():
    src = _func_src("_run_refine_poc")
    assert src and "_touch_derived_spec_outcome(cve, verified, stop_reason)" in src
    helper = _func_src("_touch_derived_spec_outcome")
    assert helper and "UPDATE derived_cve_specs" in helper and "INSERT" not in helper


def test_scan_evidence_is_engagement_filtered_and_reads_prior_attempts():
    src = _func_src("_scan_evidence_for_target")
    assert src
    assert "a.engagement_id = %s OR a.engagement_id IS NULL" in src
    assert "FROM build_poc_attempts" in src and '"prior_live_recon"' in src
    gather = _func_src("_gather_manifest")
    assert gather and 'scan_ev.get("prior_live_recon")' in gather and '"prior_live_recon_runs"' in gather
