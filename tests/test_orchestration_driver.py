"""Phase-0 orchestration seam: the recon loop may hand off to a full session,
but a HANDS-OFF driver must not silently escalate.

These are the load-bearing safety properties, source-checked (ast) so they run
on a bare checkout:
  * the hand-off is OPT-IN per engagement (config auto_drive);
  * exploitation stays HUMAN-GATED — the driven session launches with
    enable_exploit_phase False and never turns auto-exploit on;
  * it only fires when recon coverage is complete, behind a cooldown, so an idle
    loop cannot relaunch every tick.

Sabotage: set enable_exploit_phase True in the launch body -> RED.
"""
import ast
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "dashboard" / "bff" / "services" / "recon_agent.py"


def _fn(name):
    if not SRC.exists():
        pytest.skip("recon_agent.py not present")
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == name:
            return node, ast.get_source_segment(SRC.read_text(encoding="utf-8"), node)
    return None, ""


def test_driver_exists():
    fn, _ = _fn("_maybe_drive_pipeline")
    assert fn is not None, "_maybe_drive_pipeline missing — the Phase-0 seam"


def test_handoff_is_opt_in():
    src = SRC.read_text(encoding="utf-8")
    # the CALL site (self._maybe_drive_pipeline(...)) must be guarded by auto_drive
    i = src.index("self._maybe_drive_pipeline(")
    window = src[max(0, i - 400):i]
    assert 'config.get("auto_drive")' in window, (
        "the pipeline hand-off must be gated on an opt-in auto_drive flag")


def test_driven_session_keeps_exploitation_human_gated():
    _, body = _fn("_maybe_drive_pipeline")
    assert '"enable_exploit_phase": False' in body, (
        "a hands-off driver must launch with exploit_phase OFF (impactful "
        "findings stay queued for human approval)")
    assert '"enable_exploit_phase": True' not in body
    # auto-exploit / synthesis must not be silently enabled by the driver
    assert '"enable_auto_exploit": True' not in body
    assert '"enable_test_synthesis": True' not in body


def test_handoff_requires_coverage_complete_and_cooldown():
    src = SRC.read_text(encoding="utf-8")
    assert "coverage_complete" in src and "dispatched == 0" in src, (
        "hand-off must require a complete-coverage signal, not fire mid-recon")
    _, body = _fn("_maybe_drive_pipeline")
    assert "_DRIVE_COOLDOWN" in body and "_last_driven" in body, (
        "hand-off must be behind a cooldown so an idle loop does not relaunch")


def test_driver_respects_the_kill_switch():
    _, body = _fn("_maybe_drive_pipeline")
    assert "409" in body, (
        "the driver must honour the /pentest 409 (platform halted) and not "
        "relaunch while halted")
