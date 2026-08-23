"""The scope placeholder sentinel is not a target.

Run on demand:

    pytest tests/test_scope_placeholder_filtering.py -v

WHY THIS EXISTS
---------------
`scope_targets` can hold a row with an EMPTY target and source
'__placeholder__', so a named scope can exist before it has any targets. That is
deliberate — but every consumer has to remember it is not a target, and one did
not: `gap_agent._get_targets` returned it, so the gap analysis reported coverage
for '' as though it were a host the operator should chase.

The 'msf' scope on this deployment carries one such row alongside its real IP,
so the case is live rather than hypothetical.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SENTINEL = "__placeholder__"

# Modules that SELECT scope targets and must therefore exclude the sentinel.
# health_router.py is excluded on purpose: its only mentions are a table-name
# list and CREATE TABLE DDL, not a target query.
TARGET_READERS = (
    "app/rag-api/gap_agent.py",
    "dashboard/bff/services/recon_agent.py",
)


@pytest.mark.unit
@pytest.mark.parametrize("rel", TARGET_READERS)
def test_target_readers_exclude_the_sentinel(rel):
    src = open(os.path.join(REPO, rel), encoding="utf-8").read()
    assert SENTINEL in src or "btrim(COALESCE(target" in src or "target <> ''" in src, (
        f"{rel} reads scope targets without excluding the placeholder sentinel — "
        "an empty target will be treated as a host")


@pytest.mark.unit
def test_gap_agent_filters_both_ways():
    """Either predicate alone leaves a hole: a hand-added empty row has no
    sentinel source, and a sentinel row could in principle carry text."""
    src = open(os.path.join(REPO, "app", "rag-api", "gap_agent.py"),
               encoding="utf-8").read()
    q = src.split("FROM scope_targets", 1)[1][:500]
    assert "btrim(COALESCE(target" in q, "gap_agent does not exclude empty targets"
    assert SENTINEL in q, "gap_agent does not exclude the sentinel source"


@pytest.mark.unit
def test_the_global_scope_names_endpoint_still_excludes_it_from_counts():
    """A scope holding only a placeholder must not report target_count=1."""
    src = open(os.path.join(REPO, "app", "rag-api", "api.py"), encoding="utf-8").read()
    blk = src.split('def list_scope_names(', 1)[1][:1200]
    assert "COUNT(*) FILTER" in blk and "target <> ''" in blk, \
        "scope/names counts placeholder rows as targets again"


@pytest.mark.unit
def test_the_frontend_matcher_drops_empty_targets():
    """'' as a scope target would behave as a wildcard in suffix matching."""
    src = open(os.path.join(REPO, "dashboard", "frontend", "src", "hooks",
                            "useScopeFilter.ts"), encoding="utf-8").read()
    assert ".filter(Boolean)" in src, \
        "empty scope targets are no longer dropped in the frontend matcher"
