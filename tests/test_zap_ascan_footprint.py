"""The Playwright-driven ZAP active scan bounds its memory footprint.

Run on demand:

    pytest tests/test_zap_ascan_footprint.py -v

WHY THIS EXISTS
---------------
A deep authenticated scan of demo.testfire.net crawled + seeded fine, then the
ZAP active scan started (~23%) and ZAP recycled mid-scan: RestartCount grew,
OOMKilled=false, ExitCode=0 (a clean SIGTERM under a host "low on memory"
event, restart:unless-stopped). Because ZAP was gone, the /scan export never
ran and web_findings never got the /bank findings. playwright-scanner logs
showed "Failed to resolve 'zap' / Connection refused" during the active scan.

Two things drove the footprint: a full-rule active scan with ZAP's default
thread_per_host and NO scan-duration cap, run WHILE the ajax spider was still
driving real browsers (the heaviest memory consumer). This module proves the
fix's controls exist in playwright_scanner/zap_bridge.py and are wired into the
active-scan phase of scan_with_playwright_session:

  * an active-scan bounder (configure_ascan_bounds) exists, sets the ZAP
    thread_per_host + scan-duration options, and reads every value from an env
    knob with a conservative default;
  * the ajax spider is explicitly stopped (stop_ajax_spider) before the active
    scan runs, so its browsers never overlap the active scan;
  * scan_with_playwright_session calls BOTH before starting the active scan.

Static — no ZAP needed, runs in CI.

Sabotage checks:
  - drop the thread_per_host / max_scan_duration option in configure_ascan_bounds -> RED
  - remove self.stop_ajax_spider() from the active-scan phase -> RED
  - remove self.configure_ascan_bounds() from the active-scan phase -> RED
  - hardcode a knob instead of reading os.environ -> RED
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ZAP_BRIDGE = os.path.join(REPO, "playwright_scanner", "zap_bridge.py")

# Env knobs the fix must expose (name -> conservative default that must appear).
REQUIRED_ENV_KNOBS = {
    "ZAP_ASCAN_THREADS": "2",
    "ZAP_ASCAN_MAX_DURATION_MIN": "20",
}

# ZAP ascan option setters the bounder must call.
REQUIRED_ASCAN_OPTIONS = {
    "set_option_thread_per_host",
    "set_option_max_scan_duration_in_mins",
}


def _src():
    if not os.path.exists(ZAP_BRIDGE):
        pytest.skip("playwright_scanner/zap_bridge.py not present")
    return open(ZAP_BRIDGE, encoding="utf-8").read()


def _node(src, name):
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name:
            return ast.get_source_segment(src, n) or ""
    raise AssertionError(f"{name} not found — this guard would pass vacuously")


def test_module_parses():
    """ast.parse must succeed — a runtime-only defect still imports."""
    ast.parse(_src())


def test_active_scan_bounder_exists_and_sets_thread_and_duration_options():
    """Without lowering threads + capping duration, a full-rule scan is unbounded."""
    body = _node(_src(), "configure_ascan_bounds")
    for opt in REQUIRED_ASCAN_OPTIONS:
        assert opt in body, (
            f"configure_ascan_bounds does not call {opt!r} — the active scan is "
            "not bounded on that axis and can spike the JVM heap until the host "
            "recycles ZAP mid-scan"
        )


def test_footprint_knobs_are_env_tunable_with_conservative_defaults():
    """Every knob must read from env so it tunes without a rebuild, and its
    default must be conservative (not hardcoded aggressive) for other targets."""
    body = _node(_src(), "configure_ascan_bounds")
    for knob, default in REQUIRED_ENV_KNOBS.items():
        assert knob in body, f"{knob} is not read in configure_ascan_bounds"
        assert "os.environ" in body, "knobs are not read from the environment"
        assert default in body, (
            f"{knob} default is not the conservative {default} the guard pins — "
            "aggressive hardcoded values break other targets"
        )


def test_ajax_spider_is_stopped_before_the_active_scan():
    """A stop_ajax_spider helper must exist and actually issue ajaxSpider.stop()."""
    body = _node(_src(), "stop_ajax_spider")
    assert "ajaxSpider.stop" in body, (
        "stop_ajax_spider does not call ZAP's ajaxSpider.stop() — the browsers "
        "keep crawling during the active scan, which is what tipped the host "
        "into the low-memory event that recycled ZAP"
    )


def test_active_scan_phase_stops_ajax_and_bounds_before_scanning():
    """Both controls must be wired into scan_with_playwright_session's active
    scan phase, ahead of BOTH the chunked and whole-tree scan paths."""
    body = _node(_src(), "scan_with_playwright_session")

    stop_at = body.find("self.stop_ajax_spider()")
    bound_at = body.find("self.configure_ascan_bounds()")
    assert stop_at != -1, (
        "scan_with_playwright_session never calls self.stop_ajax_spider() — the "
        "ajax spider can still be running during the active scan"
    )
    assert bound_at != -1, (
        "scan_with_playwright_session never calls self.configure_ascan_bounds() "
        "— the active scan runs with ZAP's unbounded defaults"
    )

    # Both must precede the first active-scan invocation (chunked or whole-tree).
    first_scan = min(
        [p for p in (body.find("self._active_scan_chunked("),
                     body.find("self.active_scan(")) if p != -1]
        or [len(body)]
    )
    assert stop_at < first_scan, (
        "stop_ajax_spider() runs AFTER the active scan starts — the browsers "
        "overlap the scan, defeating the fix"
    )
    assert bound_at < first_scan, (
        "configure_ascan_bounds() runs AFTER the active scan starts — the scan "
        "is dispatched with unbounded defaults"
    )


def test_whole_tree_wait_tracks_the_duration_cap():
    """The poll window must follow the scan's own duration cap, so the export
    runs when the scan finishes instead of abandoning a still-running scan."""
    body = _node(_src(), "scan_with_playwright_session")
    assert "ZAP_ASCAN_MAX_DURATION_MIN" in body, (
        "the whole-tree wait does not derive from the active-scan duration cap; "
        "a fixed wait can abandon a scan that is still within its own budget"
    )
