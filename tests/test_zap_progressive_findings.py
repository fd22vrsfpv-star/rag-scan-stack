"""ZAP findings must be stored as they are found, not only at the end.

Run on demand:

    pytest tests/test_zap_progressive_findings.py -v

WHY THIS EXISTS
---------------
Alerts were collected only AFTER the active scan finished, so anything that
killed ZAP mid-scan lost every finding for that run.

Observed, not theorised: an active scan against demo.testfire.net drove the JVM
into GC thrash — `Tech Detection Passive Scanner took 44 seconds` across 30
passive threads, up from milliseconds — and the process died at 15:03:35,
restarting at 15:04:46. The pipeline still reported `completed`, with 96
gowitness findings, 6 playwright findings and **zero from ZAP**. A scan that
looks finished and silently dropped its most valuable stage is the failure this
prevents.

Draining periodically costs at most one interval. It is safe to repeat because
`parse_zap_alerts(dedupe=True)` is the SAME ETL the end-of-scan path uses and
dedupes on insert — there is no parallel write path to drift.

Static — no ZAP needed, runs in CI.

Sabotage check: remove the drain call from the active-scan loop -> RED.
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
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{name}() not found — this guard would pass vacuously")


def test_the_drain_helper_exists_and_reuses_the_etl():
    body = _func(_src(), "drain_zap_alerts")
    assert "parse_zap_alerts" in body, (
        "the progressive path does not use the same ETL as the end-of-scan path — "
        "a second write path will drift from it"
    )
    assert "dedupe=True" in body, (
        "without dedupe, repeated draining stores every alert many times"
    )


def test_the_drain_never_fails_the_scan():
    body = _func(_src(), "drain_zap_alerts")
    assert "except Exception" in body, "a progressive save must not abort the scan"
    assert "logger.warning" in body or "logger.error" in body, (
        "a failed drain is swallowed silently — which is exactly how storing "
        "nothing stayed invisible in the first place"
    )


def test_the_active_scan_loop_drains_periodically():
    """The active scan is the phase that killed ZAP."""
    body = _func(_src(), "_zap_scan_with_urls_inner")
    loop = body[body.index("ascan.scan("):]
    loop = loop[:loop.index("Active scan complete")] if "Active scan complete" in loop else loop
    assert "drain_zap_alerts" in loop, (
        "the active-scan wait loop never stores findings, so a ZAP death during "
        "it loses the whole scan"
    )


def test_the_drain_interval_is_configurable():
    src = _src()
    assert "ZAP_DRAIN_INTERVAL" in src, "the drain interval is not tunable"
    m = re.search(r'ZAP_DRAIN_INTERVAL",\s*"(\d+)"', src)
    assert m and 10 <= int(m.group(1)) <= 600, \
        f"drain interval default {m.group(1) if m else '?'} is outside a sane range"


def test_findings_are_also_drained_after_the_spiders():
    """The passive scanner produces findings throughout the crawl, long before
    the active scan begins."""
    body = _func(_src(), "_zap_scan_with_urls_inner")
    i = body.find("Spider(s) complete")
    assert i != -1, "spider completion marker missing — guard unreliable"
    assert "drain_zap_alerts" in body[i:i + 400], (
        "nothing is stored between the crawl and the active scan, so a death "
        "early in the active scan discards every passive finding"
    )
