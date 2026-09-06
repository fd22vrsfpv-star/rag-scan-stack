"""A scan interrupted by a restart must report as failed, never as running.

Run on demand:

    pytest tests/test_job_reconciliation.py -v

WHY THIS EXISTS
---------------
`JobTracker.update_job` persisted only on TERMINAL status. A job still `running`
when the container was recreated therefore left **no record at all** — not a
failed one, nothing. The caller polling a stale registry saw `running` for ever,
which is indistinguishable from a slow scan, and the concurrency slot it held was
never released.

This is not hypothetical: two web pipelines were lost exactly that way. Bumping
`BUILD_VERSION` in `.env` changes every service's environment, so
`docker compose up -d <anything>` recreated 12 containers — web-scanner and zap
among them — and killed both scans mid-ZAP. They were reported as stuck in
`zap_running` for hours while ZAP in fact held zero scans.

Two changes are pinned here:
  * persist on ANY status change, so an in-flight job exists on disk;
  * reconcile at startup, rewriting non-terminal records to `failed` with the
    reason, so the operator is told rather than left waiting.

Static (ast/source) checks — no container needed, so this runs in CI.

Sabotage check: restore the terminal-only persist condition -> RED.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
WEB_SCAN = os.path.join(REPO, "web_scanner", "web_scan.py")


def _src():
    if not os.path.exists(WEB_SCAN):
        pytest.skip("web_scan.py not present")
    return open(WEB_SCAN, encoding="utf-8").read()


def _func(src, name):
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{name}() not found — this guard would pass vacuously")


def test_reconciliation_exists_and_runs_at_startup():
    src = _src()
    assert "_reconcile_orphaned_jobs" in src, "no reconciliation function"
    init = _func(src, "__init__")
    assert "_reconcile_orphaned_jobs" in init, (
        "reconciliation is defined but never called from __init__, so an "
        "interrupted job is never repaired"
    )


def test_in_flight_jobs_are_persisted_not_only_terminal_ones():
    """The whole fix: a running job must reach disk, or there is nothing to
    reconcile after a restart."""
    body = _func(_src(), "update_job")
    assert "_persist" in body, "update_job no longer persists at all"
    terminal_only = re.search(
        r'status.*in\s*\(\s*["\']completed["\'].*?\)\s*:\s*\n\s*self\._persist',
        body, re.S)
    assert not terminal_only, (
        "update_job persists only on terminal status again — an interrupted "
        "'running' job will leave no disk record and cannot be reconciled"
    )


def test_reconciliation_marks_non_terminal_as_failed_with_a_reason():
    body = _func(_src(), "_reconcile_orphaned_jobs")
    assert '"failed"' in body or "'failed'" in body, \
        "orphans must become failed, not be deleted or left running"
    assert "error" in body, "an interrupted job must carry the reason"
    assert "completed_at" in body, \
        "a terminal job needs completed_at or it reads as still open"


def test_the_reason_reports_the_PREVIOUS_status():
    """The status is overwritten before the message is built; reading it after
    produced 'restarted while this job was failed', which is nonsense."""
    body = _func(_src(), "_reconcile_orphaned_jobs")
    assigned = body.index('data["status"] = "failed"')
    captured = body.find("was = data.get(")
    assert captured != -1, "the previous status is not captured"
    assert captured < assigned, (
        "the previous status is read AFTER being overwritten — the reason will "
        "say the job was 'failed' when it was actually running"
    )


def test_terminal_records_are_left_alone():
    """A genuinely completed job must not be rewritten as failed."""
    body = _func(_src(), "_reconcile_orphaned_jobs")
    assert "_NON_TERMINAL" in body or "continue" in body, (
        "no guard skipping already-terminal records — reconciliation would "
        "clobber completed scans on every restart"
    )
