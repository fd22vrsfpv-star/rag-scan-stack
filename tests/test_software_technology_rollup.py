"""2026-10-22: a technology could fall off the bottom of the software inventory.

Operator: "in the redteam engagement I do not see php flagged as a technology",
then "this should show up in the technology".

`/software` ends `ORDER BY ip, product, source LIMIT %s` (default 2000) against
**3516** deduplicated rows for that engagement — 43% dropped, with nothing in
the response saying so, and WHICH technologies survived decided by host IP sort
order. PHP is on 49 host/port pairs there and the UI received 34 of them.
Meanwhile the summary block above the table counted the FULL set, so the header
and the table disagreed by design.

"Is PHP present?" is a question about products, not hosts, so it now gets a
product-shaped answer: a complete rollup (274 products in that engagement),
unbounded by the row limit, plus an explicit `truncated` flag for the rows.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_software_technology_rollup.py -v'
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
UI = REPO / "dashboard" / "frontend" / "src" / "pages" / "AssetBrowser.tsx"
APISRC = REPO / "dashboard" / "frontend" / "src" / "api" / "assets.ts"


@pytest.fixture(scope="module")
def handler() -> str:
    src = API.read_text()
    fn = next(n for n in _ast.parse(src).body
              if isinstance(n, _ast.FunctionDef) and n.name == "get_detected_software")
    return _ast.get_source_segment(src, fn)


def test_the_rollup_is_not_subject_to_the_row_limit(handler):
    """The whole point: a GROUP BY product query with the same filters and no
    LIMIT. Passing `params` (which ends with the limit) would break it."""
    m = re.search(r"GROUP BY product(.{0,200}?)\"\"\",\s*(params[^\)]*)\)", handler, re.S)
    assert m, "no product rollup query found"
    assert "LIMIT" not in m.group(1).upper(), "the rollup is limited"
    assert "params[:-1]" in m.group(2), \
        f"the rollup must reuse the filters WITHOUT the limit, got {m.group(2)!r}"


def test_the_rollup_counts_hosts_not_rows(handler):
    """One product on 24 hosts is the useful number; 260 detection rows is not."""
    m = re.search(r"GROUP BY product", handler)
    assert m
    block = handler[max(0, m.start() - 900):m.start()]
    assert re.search(r"COUNT\(DISTINCT ip\)", block), "host_count is not distinct by ip"


def test_truncation_is_reported(handler):
    """The header counted the full set while the table was capped, and nothing
    said which was which."""
    assert re.search(r"[\"']truncated[\"']\s*:", handler), "no truncated flag"
    assert re.search(r"[\"']total_rows[\"']\s*:", handler), "no total_rows"
    assert re.search(r"[\"']limit[\"']\s*:", handler), "the active limit is not returned"


def test_a_failed_rollup_is_distinguishable_from_no_products(handler):
    """An empty list must not be able to mean 'the query blew up' — that is the
    repo's unreachable-is-not-absent rule."""
    assert re.search(r"[\"']products_available[\"']\s*:", handler), \
        "no flag separating a failed rollup from an empty one"
    m = re.search(r"except Exception as _pe(.{0,400})", handler, re.S)
    assert m and "products = None" in m.group(1), \
        "a failed rollup returns [] rather than None"


def test_the_rollup_is_engagement_filtered_like_the_rows(handler):
    """Same `where_sql`, so the rollup cannot leak another engagement's stack."""
    m = re.search(r"GROUP BY product", handler)
    block = handler[max(0, m.start() - 900):m.start()]
    assert "{where_sql}" in block, "the rollup does not apply the row filters"


# --- the UI has to render it, or the fix is invisible -----------------------

def test_the_api_layer_exposes_the_rollup():
    src = APISRC.read_text()
    assert "SoftwareProduct" in src, "no product type"
    assert re.search(r"products\s*:\s*SoftwareProduct\[\]\s*\|\s*null", src), \
        "products is not typed as nullable — a failed rollup would read as empty"
    assert "products_available" in src and "truncated" in src


def test_the_page_renders_a_technologies_list():
    src = UI.read_text()
    assert "Technologies" in src, "no technologies panel"
    assert "products_available" in src, \
        "the panel does not check whether the rollup actually ran"
    assert re.search(r"softwareData\.products!?\.map\(", src), \
        "the product rollup is never rendered"


def test_the_page_warns_when_the_rows_are_truncated():
    """Otherwise the operator reads a 2000-row table as the whole estate."""
    src = UI.read_text()
    assert re.search(r"softwareData\.truncated", src), \
        "truncation is not surfaced in the UI"
    m = re.search(r"softwareData\.truncated\s*&&(.{0,600})", src, re.S)
    assert m and "total_rows" in m.group(1), \
        "the warning does not say how many rows exist"
