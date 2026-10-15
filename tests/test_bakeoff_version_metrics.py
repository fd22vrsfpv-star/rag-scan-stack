"""A bake-off's per-model verdict and cost must survive to the compare view.

`_bakeoff_one` runs each model's payload against the target and records the
outcome on the version it saves — `canary_hit`, `gen_seconds`, `prompt_tokens`,
`completion_tokens`, `total_tokens`, `llm_latency_ms`. Its own comment says why:
"Capture LLM token/latency metrics so the diff view can show cost + speed per
model."

`GET /exploit-store/{id}/versions` did not select `metadata`, so every one of
those values was dropped on the way out. The side-by-side comparison — the
entire point of a bake-off, "which model's output really works?" — could show
only `verified`, which is the snapshot's flag rather than the run's verdict, and
nothing at all about cost or speed.

Three links in the chain, pinned here because breaking any one makes the
comparison silently blank again:

  1. the bake-off records the metrics on the version it saves;
  2. the list endpoint returns `metadata`;
  3. the frontend row type carries it through to the compare columns.

Static (`ast` for Python, regex for TypeScript — the precedent is
tests/test_severity_scale.py). No DB, no node.

Sabotage check: drop `metadata` from the versions SELECT and
`test_versions_list_returns_metadata` fails; remove it from `ExploitVersionRow`
and `test_frontend_row_carries_metadata` fails.

    pytest tests/test_bakeoff_version_metrics.py -q
"""

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
EXPLOITS_TS = REPO / "dashboard" / "frontend" / "src" / "api" / "exploits.ts"
PAGE_TSX = REPO / "dashboard" / "frontend" / "src" / "pages" / "ExploitManager.tsx"

# What a bake-off records and the comparison needs.
METRICS = ("canary_hit", "gen_seconds", "total_tokens", "llm_latency_ms")


def _read(p: Path) -> str:
    if not p.exists():
        pytest.skip(f"{p} not found")
    return p.read_text(encoding="utf-8")


def _func(name: str) -> ast.FunctionDef:
    fn = next((n for n in ast.walk(ast.parse(_read(API)))
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn, f"{name} not found in app/rag-api/api.py"
    return fn


@pytest.mark.parametrize("metric", METRICS)
def test_bakeoff_records_the_metric(metric):
    """Link 1 — the data has to exist before anything can show it."""
    fn = _func("_bakeoff_one")
    keys = {n.value for n in ast.walk(fn)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert metric in keys, (
        f"_bakeoff_one no longer records {metric!r}; the comparison cannot "
        "report what the run never measured")


def test_versions_list_returns_metadata():
    """Link 2 — the endpoint the compare view actually calls."""
    fn = _func("list_exploit_versions")
    sqls = [n.value for n in ast.walk(fn)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and "exploit_store_versions" in n.value]
    assert sqls, "list_exploit_versions has no query against exploit_store_versions"
    for sql in sqls:
        flat = " ".join(sql.split())
        assert re.search(r"\bmetadata\b", flat), (
            "the versions list does not select `metadata`, so the bake-off's "
            "per-model verdict and cost never reach the compare view")


def test_frontend_row_carries_metadata():
    """Link 3 — the type the columns are rendered from."""
    src = _read(EXPLOITS_TS)
    m = re.search(r"export interface ExploitVersionRow\b.*?\n}", src, re.S)
    assert m, "ExploitVersionRow not found in api/exploits.ts"
    assert re.search(r"\bmetadata\??\s*:", m.group(0)), (
        "ExploitVersionRow has no `metadata` field, so the list response's "
        "bake-off metrics are discarded before the compare view sees them")


def test_compare_column_renders_the_recorded_verdict():
    """`verified` is the snapshot flag; canary_hit is what the run decided."""
    page = _read(PAGE_TSX)
    m = re.search(r"function BakeoffColumn\b.*?\n}\n", page, re.S)
    assert m, "BakeoffColumn not found in ExploitManager.tsx"
    col = m.group(0)
    assert re.search(r"\bcanary_hit\b", col), (
        "BakeoffColumn never reads canary_hit — it can only show the snapshot "
        "flag, not whether that model's payload actually landed")
