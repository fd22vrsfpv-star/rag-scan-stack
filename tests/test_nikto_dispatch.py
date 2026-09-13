"""The web profile controls nikto like every other pipeline stage.

Run on demand:

    pytest tests/test_nikto_dispatch.py -v

WHY THIS EXISTS
---------------
The autogen `start_pipeline_scan` mapped the web profile's stage list onto
skip flags for gobuster/playwright/zap/nuclei/katana — but NOT nikto, and never
passed skip_nikto to the web-scanner. So the web-scanner's default (run) always
won: the profile could neither guarantee nikto for `deep` nor suppress it for
`quick`, and `deep` and `quick` behaved identically for nikto. The BFF path
(`dashboard/bff/routers/scans.py::_apply_web_profile`) already iterated every
stage including nikto; only the agent path was missing it.

This pins both: the stage→skip mapping includes nikto, and the payload sends it.

SABOTAGE PROOF
--------------
Delete the `skip_nikto = "nikto" not in stages` line and
test_profile_stage_map_includes_nikto fails; drop `"skip_nikto"` from the payload
and test_pipeline_payload_sends_skip_nikto fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCAN_TOOLS = os.path.join(REPO, "autogen_agents", "scan_tools.py")


def _src():
    if not os.path.exists(SCAN_TOOLS):
        pytest.skip("scan_tools.py not present")
    with open(SCAN_TOOLS, encoding="utf-8") as fh:
        return fh.read()


def test_scan_tools_parses():
    ast.parse(_src())  # a mangled edit here would break every tool, not just nikto


def test_profile_stage_map_includes_nikto():
    src = _src()
    assert 'skip_nikto = "nikto" not in stages' in src, (
        "the web profile's nikto stage is ignored — nikto runs regardless of the "
        "profile, so 'quick' and 'deep' behave the same for it")


def test_pipeline_payload_sends_skip_nikto():
    src = _src()
    assert '"skip_nikto": skip_nikto' in src, (
        "skip_nikto is computed but never sent, so the web-scanner default wins "
        "and the profile still cannot control nikto")


def test_every_pipeline_stage_is_controllable():
    """Every stage the pipeline runs must be expressible as a skip flag, or the
    profile silently loses control of it — which is exactly how nikto slipped."""
    src = _src()
    for stage in ("gobuster", "playwright", "zap", "nuclei", "katana", "nikto"):
        assert f'skip_{stage} = "{stage}" not in stages' in src, (
            f"stage {stage} has no profile→skip mapping in start_pipeline_scan")
