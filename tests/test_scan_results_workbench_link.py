"""A scan result that names a CVE must offer the Exploit Workbench.

`pocWorkbenchHref` existed but began `if (a.tool !== 'cve_poc_builder') return
null` — so the ONE artifact that already had a PoC was the only one that
offered to open the workbench. A nuclei hit, a vuln scan or an imported
finding is exactly the moment an operator wants it, and those rows linked
nowhere.

The workbench already reads `?cve=`, `?ip=` and `?port=` (ExploitManager
BuildPocSection), so this is a link, not a feature.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=.:tests \
      python -m pytest tests/test_scan_results_workbench_link.py -v'
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PAGE = REPO / "dashboard" / "frontend" / "src" / "pages" / "ScanResults.tsx"
WORKBENCH = REPO / "dashboard" / "frontend" / "src" / "pages" / "ExploitManager.tsx"


@pytest.fixture(scope="module")
def src():
    return PAGE.read_text(encoding="utf-8")


def _func_body(text: str, name: str) -> str:
    i = text.index(f"function {name}(")
    depth, j, started = 0, i, False
    while j < len(text):
        if text[j] == "{":
            depth += 1
            started = True
        elif text[j] == "}":
            depth -= 1
            if started and depth == 0:
                return text[i:j + 1]
        j += 1
    pytest.fail(f"could not bound {name}")


class TestTheLinkIsNotGatedToPocRows:
    def test_it_does_not_require_the_poc_builder_tool(self, src):
        body = _func_body(src, "pocWorkbenchHref")
        gated = re.search(r"tool\s*!==\s*.cve_poc_builder.", body)
        assert not gated, (
            "the workbench link is gated to cve_poc_builder rows again — a "
            "nuclei or vuln-scan result naming a CVE would link nowhere, "
            "which is the row an operator most wants to act on")

    def test_it_still_needs_a_cve_and_a_target(self, src):
        """A link to nowhere is worse than plain text."""
        body = _func_body(src, "pocWorkbenchHref")
        guards = re.search(r"if\s*\(\s*!\s*cve\s*&&\s*!\s*ip\s*\)\s*return\s+null", body)
        assert guards, (
            "without a CVE or a target the function must return null")

    def test_non_poc_rows_get_a_label(self, src):
        """A link with nothing to click is not a link."""
        assert re.search(r"function\s+workbenchLabel\s*\(", src), (
            "pocLabel only speaks for cve_poc_builder rows; another label is "
            "needed or the widened link renders empty")
        body = _func_body(src, "workbenchLabel")
        assert re.search(r"CVE-", body), "the label must name the CVE it builds"

    def test_the_params_match_what_the_workbench_reads(self, src):
        """The link is only useful if the target page consumes these names."""
        body = _func_body(src, "pocWorkbenchHref")
        sent = set(re.findall(r"q\.set\('([a-z_]+)'", body))
        assert {"ip", "port", "cve"} <= sent, f"link params: {sent}"
        wb = WORKBENCH.read_text(encoding="utf-8")
        for p in ("ip", "port", "cve"):
            assert f"urlParams.get('{p}')" in wb, (
                f"the workbench does not read ?{p}= — the link would seed "
                "nothing")
