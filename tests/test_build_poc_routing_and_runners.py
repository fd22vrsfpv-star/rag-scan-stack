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
        assert "SELECT verified FROM derived_cve_specs" not in s, f"{p.name} still reads derived_cve_specs for the verdict"
        assert "d.get('verified')" in s


def test_scope_add_route_really_does_not_exist():
    assert '"/engagements/{eid}/scope-add"' not in API.read_text()
    assert '"/engagements/{engagement_id}/scope-add"' not in API.read_text()


def test_refine_loop_records_its_outcome_on_derived_specs():
    src = _func_src("_run_refine_poc")
    # the local in _run_refine_poc is `_stop_reason` — a bare `stop_reason` was a
    # NameError on the last line of every completed build (2026-10-09)
    assert src and '_touch_derived_spec_outcome(cve, verified, (_stop_reason or "max_iters"))' in src
    helper = _func_src("_touch_derived_spec_outcome")
    assert helper and "UPDATE derived_cve_specs" in helper and "INSERT" not in helper
    # 2026-10-09: an assertion that passed on a drifted endpoint stops as
    # `off_target`, never `success` (CVE-2024-5314 read `stop=success verified=False`)
    assert '_stop_reason = "off_target" if off_target else ("success" if success else None)' in src
    assert src.index("off_target = bool(success and not verified)") < src.index('_touch_derived_spec_outcome(cve, verified')


def test_build_wall_clock_is_unlimited_unless_explicit():
    """2026-10-09: operator asked for an unlimited build wall clock. Presets must
    not imply a cap (`eff_wall or 1800/7200` was the old shape) and the BFF
    proxy must not cut the request at 300 s while rag-api keeps building."""
    api = API.read_text()
    assert "eff_wall = eff_wall or 1800" not in api and "eff_wall = eff_wall or 7200" not in api
    assert "eff_wall = body.wall_timeout_sec if (body.wall_timeout_sec or 0) > 0 else None" in api
    bff = (REPO / "dashboard" / "bff" / "routers" / "assets.py").read_text()
    seg = bff[bff.index('"/api/software/build-poc"'):]
    seg = seg[:seg.index("async with httpx.AsyncClient") + 120]
    assert "timeout=300" not in seg
    assert "httpx.Timeout(None, connect=" in seg
    ui = (REPO / "dashboard" / "frontend" / "src" / "pages" / "ExploitManager.tsx").read_text()
    assert "useState<'quick'|'deep'|'custom'>('custom')" in ui   # UI default = no preset = no cap


BUILD_POC_TIMEOUT_KEYS = ("scan_timeout_build_poc_wall", "scan_timeout_build_poc_run",
                          "scan_timeout_build_poc_deep_recon")


def test_build_poc_timeouts_are_operator_settings():
    """2026-10-09: 'make the timeouts a setting that can be adjusted'. The three
    build-PoC timeouts ride the existing Settings → Scan timeouts plumbing: the
    BFF key list + defaults, the UI field list, and rag-api reads each key via
    `_build_poc_timeout_setting` at its consumer (wall clock, per-command run,
    deep-recon budget). Drop any one leg and this fails by key name."""
    api = API.read_text()
    helper = _func_src("_build_poc_timeout_setting")
    assert helper and '_get_setting(key, "")' in helper
    for k in BUILD_POC_TIMEOUT_KEYS:
        assert f'_build_poc_timeout_setting("{k}"' in api, f"rag-api never reads {k}"
    # wall: request value wins, else the setting, else unlimited
    assert '_build_poc_timeout_setting("scan_timeout_build_poc_wall", 0)' in api
    assert "eff_wall = _wall_setting if _wall_setting > 0 else None" in api
    bff = (REPO / "dashboard" / "bff" / "routers" / "settings.py").read_text()
    keys_src = bff[bff.index("SCAN_TIMEOUT_KEYS = ["):bff.index("]", bff.index("SCAN_TIMEOUT_KEYS = ["))]
    defaults_src = bff[bff.index("def _scan_timeout_defaults"):bff.index("@router.get(\"/api/settings/scan-timeouts\")")]
    ui = (REPO / "dashboard" / "frontend" / "src" / "pages" / "Settings.tsx").read_text()
    fields_src = ui[ui.index("const SCAN_TIMEOUT_FIELDS"):ui.index("function ScanTimeoutsTab")]
    for k in BUILD_POC_TIMEOUT_KEYS:
        assert f'"{k}"' in keys_src, f"BFF SCAN_TIMEOUT_KEYS lacks {k}"
        assert f'"{k}"' in defaults_src, f"BFF defaults lack {k}"
        assert f"'{k}'" in fields_src, f"Settings.tsx SCAN_TIMEOUT_FIELDS lacks {k}"
    assert '"scan_timeout_build_poc_wall": 0' in defaults_src   # unlimited by default


def test_scan_evidence_is_engagement_filtered_and_reads_prior_attempts():
    src = _func_src("_scan_evidence_for_target")
    assert src
    assert "a.engagement_id = %s OR a.engagement_id IS NULL" in src
    assert "FROM build_poc_attempts" in src and '"prior_live_recon"' in src
    gather = _func_src("_gather_manifest")
    assert gather and 'scan_ev.get("prior_live_recon")' in gather and '"prior_live_recon_runs"' in gather
