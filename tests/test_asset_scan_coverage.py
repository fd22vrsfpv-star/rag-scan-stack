"""An asset view must distinguish "scanned, nothing found" from "never scanned".

Everywhere else in the UI those render identically — both show no open ports —
and they are completely different facts: one is a measured result, the other is
a gap in the work. `discovered_by` does not settle it either; it names the
source that first created the asset row, not what has been run against it since.

`/assets/{ip}/scan-coverage` answers it from `scope_coverage`, the per-target
scan record, and returns an explicit `verdict`:

    never_scanned | scanned_nothing_listening | scanned_ports_open

This is the same three-outcome rule the repo applies to every probe (see
Docs/Memories.md, "unreachable is not absent"): an answer that could not be
obtained is its own outcome, never folded into the negative one.

Pinned here:
  1. the endpoint exists, reads scope_coverage, and returns a verdict;
  2. `never_scanned` is reachable — the verdict is not hardcoded to a finding;
  3. the panel renders all three states AND handles the query erroring, so an
     unreadable record never displays as "never scanned";
  4. the BFF declares the route the frontend calls.

Static (`ast` + regex). No DB, no node, no running stack.

Sabotage check: collapse the verdict to two states and
`test_never_scanned_is_its_own_verdict` fails; drop the `isError` branch from
the panel and `test_panel_separates_unreadable_from_unscanned` fails.

    pytest tests/test_asset_scan_coverage.py -q
"""

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
BFF = REPO / "dashboard" / "bff" / "routers" / "agents.py"
PAGE = REPO / "dashboard" / "frontend" / "src" / "pages" / "AssetBrowser.tsx"

VERDICTS = ("never_scanned", "scanned_nothing_listening", "scanned_ports_open")


def _read(p: Path) -> str:
    if not p.exists():
        pytest.skip(f"{p} not found")
    return p.read_text(encoding="utf-8")


def _handler() -> ast.FunctionDef:
    fn = next((n for n in ast.walk(ast.parse(_read(API)))
               if isinstance(n, ast.FunctionDef) and n.name == "asset_scan_coverage"), None)
    assert fn, "asset_scan_coverage not found in app/rag-api/api.py"
    return fn


def test_endpoint_reads_the_scan_record():
    fn = _handler()
    sqls = [n.value for n in ast.walk(fn)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert any("scope_coverage" in q for q in sqls), (
        "the endpoint does not read scope_coverage — it has no record of what "
        "was run and can only report what was found")


@pytest.mark.parametrize("verdict", VERDICTS)
def test_never_scanned_is_its_own_verdict(verdict):
    """Two states would collapse the distinction the endpoint exists for."""
    fn = _handler()
    consts = {n.value for n in ast.walk(fn)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert verdict in consts, (
        f"{verdict!r} is no longer produced; with fewer than three outcomes, "
        "'nobody looked' and 'nothing was listening' are the same answer again")


def test_endpoint_is_engagement_scoped():
    """A listing of collected data honours the active engagement."""
    fn = _handler()
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_resolve_engagement_id" in calls, (
        "the endpoint ignores X-Engagement-Id, so it would report scans from "
        "other engagements under this one")


def test_bff_declares_the_route():
    src = _read(BFF)
    assert re.search(r'@router\.get\(\s*["\']/api/assets/\{ip\}/scan-coverage["\']', src), (
        "the BFF does not declare /api/assets/{ip}/scan-coverage — the panel "
        "would 404 and render as an empty result")


def _panel() -> str:
    page = _read(PAGE)
    m = re.search(r"function ScanCoveragePanel\b.*?\n}\n", page, re.S)
    assert m, "ScanCoveragePanel not found in AssetBrowser.tsx"
    return m.group(0)


@pytest.mark.parametrize("verdict", VERDICTS)
def test_panel_renders_every_verdict(verdict):
    assert verdict in _panel(), (
        f"the panel has no branch for {verdict!r}, so that state renders as "
        "nothing at all")


def test_panel_separates_unreadable_from_unscanned():
    """A failed query is not evidence that no scan ran."""
    panel = _panel()
    assert re.search(r"\bisError\b", panel), (
        "the panel ignores the error case, so a failed lookup would render as "
        "'never scanned' — asserting a gap in the work that was never measured")
