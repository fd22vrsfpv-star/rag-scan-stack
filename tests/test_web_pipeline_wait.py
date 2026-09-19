"""The surface phase must WAIT for the web pipeline before building surface tests.

Run on demand:

    pytest tests/test_web_pipeline_wait.py -v

WHY THIS EXISTS
---------------
_ensure_web_pipeline dispatches the comprehensive web pipeline (Gobuster→ZAP→
Nuclei) fire-and-forget, and _build_surface_tests ran on the very next line — so
surface tests were built from pre-pipeline findings and the pipeline's app-layer
findings (SQLi/XSS/IDOR) landed minutes later, untested. A single-pass run thus
never kicked off the web app tests. The surface phase now blocks (bounded) on the
dispatched jobs via _wait_for_web_pipeline before building surface tests, unless
session config wait_for_web_pipeline=false.

SABOTAGE PROOF
--------------
Remove the _wait_for_web_pipeline call from the surface phase (or its
wait_for_web_pipeline gate) and this fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")


def _src():
    if not os.path.exists(ENGINE):
        pytest.skip("langgraph_engine.py not present")
    return open(ENGINE, encoding="utf-8").read()


def test_wait_helper_polls_job_status_until_terminal():
    src = _src()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_wait_for_web_pipeline"), None)
    assert fn is not None, "_wait_for_web_pipeline helper is missing"
    body = ast.get_source_segment(src, fn)
    assert "get_web_scan_job_status" in body, "the wait must poll each pipeline job's status"
    assert "_WEB_PIPELINE_WAIT_SECONDS" in body or "deadline" in body, (
        "the wait must be time-bounded")


def test_surface_phase_waits_before_building_tests():
    src = _src()
    # The wait must be invoked, gated by the opt-out config, and the constant declared.
    assert "_wait_for_web_pipeline(" in src, "surface phase must call _wait_for_web_pipeline"
    assert 'wait_for_web_pipeline"' in src or "wait_for_web_pipeline'" in src, (
        "the wait must be gated by the wait_for_web_pipeline session-config flag")
    assert "_WEB_PIPELINE_WAIT_SECONDS_DEEP" in src and "_web_wait_cap" in src, (
        "a deep web_profile must get a longer wait cap via _web_wait_cap")
    assert "_web_wait_cap(eng)" in src, (
        "the surface phase must use the profile-aware cap (_web_wait_cap)")
    assert "_WEB_PIPELINE_WAIT_SECONDS = int(os.environ.get(" in src, (
        "WEB_PIPELINE_WAIT_SECONDS must be a configurable bound")

    # The wait call must appear BEFORE _build_surface_tests in the surface node,
    # otherwise it doesn't help (tests would still be built from stale findings).
    wait_at = src.index("_wait_for_web_pipeline(pipe")
    build_at = src.index("candidates = _build_surface_tests(")
    assert wait_at < build_at, "the pipeline wait must run before _build_surface_tests"
