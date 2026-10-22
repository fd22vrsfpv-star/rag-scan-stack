"""2026-10-22: the PoC Store can group by target or by CVE.

Operator: "in the poc store lets have the option to group by ip or cve name."

A store with four attempts on one CVE across three hosts reads as twelve
unrelated rows. Grouping answers "what do we hold for this box" and "every
attempt at this vuln, across hosts" without scanning the flat list.

Structural guard over the TSX — the repo has no frontend test runner, so this
checks the source the way the other workbench guards do. It pins the things
that silently rot: the state, the persistence, the shared row component, and
that grouping does not re-order rows behind the sort chips.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_poc_store_grouping.py -v'
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
UI = REPO / "dashboard" / "frontend" / "src" / "pages" / "ExploitManager.tsx"

pytestmark = pytest.mark.skipif(not UI.exists(), reason="ExploitManager.tsx not present")


@pytest.fixture(scope="module")
def src() -> str:
    return UI.read_text(encoding="utf-8")


def test_both_groupings_the_operator_asked_for_exist(src):
    m = re.search(r"useState<'none' \| 'ip' \| 'cve'>", src)
    assert m, "groupBy state does not offer none/ip/cve"


def test_the_choice_survives_a_refresh(src):
    """Same fail-soft localStorage pattern as the sort chips and the tab bar:
    a blocked or cleared store must not break the panel."""
    assert "poc-store-group" in src, "the grouping is not persisted"
    m = re.search(r"localStorage\.getItem\('poc-store-group'\)(.{0,200})", src, re.S)
    assert m and "catch" in m.group(1), "the read is not wrapped in try/catch"
    m2 = re.search(r"localStorage\.setItem\('poc-store-group'[^\n]*\)(.{0,60})", src, re.S)
    assert m2 and "catch" in m2.group(1), "the write is not wrapped in try/catch"


def test_an_unrecognised_stored_value_falls_back(src):
    """A stale or hand-edited value must not select a mode that renders nothing."""
    m = re.search(r"localStorage\.getItem\('poc-store-group'\)(.{0,220})", src, re.S)
    assert m and re.search(r"===\s*'ip'.*?===\s*'cve'", m.group(1), re.S), \
        "the stored value is not validated against the known modes"


def test_rows_with_no_host_or_cve_are_not_dropped(src):
    """A PoC with no target is exactly the row worth seeing; silently omitting
    it would make the grouped total disagree with the header count."""
    m = re.search(r"const storeGroups = useMemo\((.{0,1400}?)\n  \}, \[", src, re.S)
    assert m, "storeGroups memo not found"
    body = m.group(1)
    assert "(no target)" in body and "(no CVE)" in body, \
        "ungrouped rows have no explicit bucket"


def test_grouping_does_not_reorder_behind_the_sort_chips(src):
    """The sort chips decide row order. A group list that re-sorted itself
    would make those chips look broken."""
    m = re.search(r"const storeGroups = useMemo\((.{0,1400}?)\n  \}, \[", src, re.S)
    assert m, "storeGroups memo not found"
    body = m.group(1)
    assert ".sort(" not in body, "the grouping re-sorts rows"
    assert "order.push(" in body, "insertion order is not preserved"


def test_the_memo_depends_on_both_inputs(src):
    """A stale memo would keep showing the previous grouping after a filter
    change — the kind of bug that reads as 'the toggle does nothing'."""
    m = re.search(r"const storeGroups = useMemo\(.{0,1400}?\n  \}, \[([^\]]*)\]", src, re.S)
    assert m, "storeGroups memo deps not found"
    deps = m.group(1)
    assert "storeRows" in deps and "groupBy" in deps, f"deps are {deps!r}"


def test_both_views_render_the_same_row_component(src):
    """The row carries the bulk-select checkbox and the rebuild action. Two
    copies would drift; the flat list and the grouped list must share one."""
    assert src.count("function StoreRowItem(") == 1, "StoreRowItem is not a single component"
    uses = len(re.findall(r"<StoreRowItem\b", src))
    assert uses >= 2, f"only {uses} call site(s); flat and grouped must both use it"


def test_each_group_shows_its_size(src):
    """A collapsed group with no count is a drawer the operator must open to
    learn whether it is worth opening."""
    m = re.search(r"storeGroups\.map\(grp => \((.{0,2500}?)</details>", src, re.S)
    assert m, "grouped rendering not found"
    assert "grp.rows.length" in m.group(1), "a group does not show how many rows it holds"
