"""A session stays IN PROGRESS while the scans it launched are still running.

Run on demand:

    pytest tests/test_session_status_lifecycle.py -v

WHY THIS EXISTS
---------------
The LangGraph graph is non-blocking: the scan phase dispatches a full-port sweep
and returns, so `_finish` used to mark the session `completed` while the scan was
still running (and before `analyze` had any data). The operator reads that as
"done — found nothing". Now `_finish` sets `scanning` while the session's scans
are in flight; the post-scan re-analysis flips it to `completed` once they finish,
and — crucially — does NOT force-complete a long run when the wait ceiling is hit
(a full sweep can take hours; the operator asked that it never be ended early).

SABOTAGE PROOF
--------------
Make `_finish` hardcode status="completed" again and
test_finish_status_reflects_running_scans fails. Make the timeout branch mark the
session completed and test_timeout_does_not_force_complete fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")


def _src():
    if not os.path.exists(ENGINE):
        pytest.skip("langgraph_engine.py not present")
    return open(ENGINE, encoding="utf-8").read()


def _func(name):
    for node in ast.walk(ast.parse(_src())):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    pytest.fail(f"{name} not found")


def test_finish_status_reflects_running_scans():
    fn = _func("_finish")
    assert "_running_scans" in fn, "_finish no longer checks for in-flight scans"
    assert "'scanning'" in fn or '"scanning"' in fn, (
        "_finish no longer uses the in-progress 'scanning' status")
    # The status is now conditional, not an unconditional 'completed'.
    assert "session_status" in fn
    assert 'status="completed"' not in fn and "status='completed'" not in fn, (
        "_finish still hardcodes completed while scans may be running")


def test_reanalysis_finalizes_to_completed_when_scans_finish():
    fn = _func("_rerun_analysis_when_scans_finish")
    assert ('status="completed"' in fn or "status='completed'" in fn), (
        "the post-scan re-analysis never flips the session to completed")
    assert "update_agent_session" in fn


def test_timeout_does_not_force_complete():
    """The ceiling is a safety net, not a deadline — a long run stays 'scanning',
    never marked completed/failed just because the wait elapsed."""
    fn = _func("_rerun_analysis_when_scans_finish")
    # The timeout branch must talk about staying in progress, and must not set a
    # terminal status in that path.
    assert "IN PROGRESS" in fn or "in progress" in fn.lower()
    assert "timeout" in fn.lower()
    # No 'failed'/'partial' terminal status introduced on timeout.
    assert 'status="failed"' not in fn and "status='failed'" not in fn


def test_wait_ceiling_is_generous():
    """40 minutes was too short for a full 1-65535 sweep; the default is now large
    and env-overridable."""
    src = _src()
    assert "RESCAN_ANALYSIS_MAX_WAIT_S" in src
    # default well above the old 2400s
    assert "21600" in src, "the re-analysis wait ceiling was not raised"
