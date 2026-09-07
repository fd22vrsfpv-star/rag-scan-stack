"""ZAP's session must be bounded, or ZAP goes selectively deaf.

Run on demand:

    pytest tests/test_zap_session_hygiene.py -v

WHY THIS EXISTS
---------------
Nothing ever reset ZAP's session, so it accumulated every request and response
from every scan for the container's lifetime. Measured: a single `untitled1`
session at **2.2 GB on disk**, with the container at **5.46 GiB of its 6 GiB
limit (91%)**.

At that point ZAP does not report an error. It goes *selectively* deaf:

    core/view/mode                 -> {"mode":"standard"}   ~1 ms
    context/view/contextList       -> {...}                  ~1 ms
    core/view/numberOfMessages     -> (timeout)
    context/action/newContext      -> (timeout, 20s)

Cheap cached views answer; anything touching the session store blocks. Combined
with a zapv2 client that passes no timeouts, that is what hung the pipeline's ZAP
stage — and `bounded_zap_http` only converts the hang into a scan that proceeds
WITHOUT scope, which the code's own "SCOPE FIRST" comment says silently guts the
active scan.

A restart took it from 5.46 GiB to 685 MiB and every one of those calls answered
instantly. The helper for this already existed — `clear_zap_session()` in
etl/parse_zap.py — reachable only from a CLI flag, and never called.

Static checks: no ZAP needed, so this runs in CI.

Sabotage check: remove the reset call from run_pipeline -> RED.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
PIPELINE = os.path.join(REPO, "web_scanner", "scan_pipeline.py")
ZAP_ROUTER = os.path.join(REPO, "dashboard", "bff", "routers", "zap_addons.py")


def _src(path=PIPELINE):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _func(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{name}() not found — this guard would pass vacuously")


def test_the_reset_helper_exists():
    body = _func(_src(), "_reset_zap_session_if_oversized")
    assert "newSession" in body, "the helper does not actually start a new session"
    assert "numberOfMessages" in body, "the helper does not measure the session"
    assert "timeout" in body, (
        "the size probe has no timeout — and a session too big to answer is "
        "exactly the case this exists for"
    )


def test_an_unreadable_message_count_counts_as_oversized():
    """A timeout on the probe IS the symptom. Treating it as 'unknown, carry on'
    would skip the reset precisely when it is needed most."""
    body = _func(_src(), "_reset_zap_session_if_oversized")
    exc = body[body.index("except Exception"):]
    assert "count = None" in exc, "the failure path does not record an unknown count"
    assert re.search(r"count is not None and count <", body), (
        "the limit check does not special-case an unknown count, so a probe "
        "timeout would fall through to 'within limit' and skip the reset"
    )


def test_the_reset_runs_at_pipeline_start():
    """Not before the ZAP stage: Playwright crawls THROUGH the ZAP proxy in stage
    2, so a later reset discards the traffic the active scan is meant to attack."""
    src = _src()
    body = _func(src, "_run_pipeline_slotted")
    call = body.find("_reset_zap_session_if_oversized")
    assert call != -1, "the pipeline never calls the reset"
    stage0 = body.find("Stage 0")
    assert stage0 != -1, "Stage 0 marker missing — guard would be unreliable"
    assert call < stage0, (
        "the reset runs after the first stage; it must precede any traffic that "
        "goes through the ZAP proxy"
    )


def test_the_threshold_is_configurable():
    src = _src()
    assert "ZAP_SESSION_MAX_MESSAGES" in src, "no configurable threshold"
    m = re.search(r'ZAP_SESSION_MAX_MESSAGES\s*=\s*int\(os\.environ\.get\(\s*"ZAP_SESSION_MAX_MESSAGES",\s*"(\d+)"\)\)', src)
    assert m, "the threshold is not read from the environment with a default"
    assert 1000 <= int(m.group(1)) <= 500000, f"default {m.group(1)} is outside a sane range"


def test_the_reset_never_raises():
    """Hygiene must not fail the scan it is protecting."""
    body = _func(_src(), "_reset_zap_session_if_oversized")
    assert body.count("except Exception") >= 2, (
        "both the probe and the reset must be guarded; an exception here would "
        "abort a scan for a housekeeping step"
    )


def test_status_endpoint_reports_session_size():
    """The operator needs the number that predicts the failure."""
    src = _src(ZAP_ROUTER)
    assert "numberOfMessages" in src, "/api/zap/status does not report session size"
    assert "session_warning" in src, (
        "a session too large to query must be reported as such, not as size 0"
    )
