"""Queued scans must run in the order the operator set.

Run on demand:

    pytest tests/test_recommendation_order.py -v

WHY THIS EXISTS
---------------
`priority` was written by the recommender and by the artifact rules, and read by
nobody at dispatch: `selected` was built from the caller's id list in arrival
order. Once concurrency was bounded that stopped being cosmetic — the first N
dispatched were whichever the UI happened to list first, out of a queue that had
already been ranked.

Worse, the column carried TWO conventions at once. scan_recommender documents
"lower int = runs first" and assigns 5 to a curated Metasploit module; the
artifact rules were written the other way up, so credentials (90) and SMBv1 (85)
— the most urgent items — sorted LAST. These tests pin the direction so the two
sources cannot drift apart again.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
RULES = os.path.join(REPO, "knowledge", "artifact_rules", "builtin.yaml")

yaml = pytest.importorskip("yaml")


@pytest.fixture(scope="module")
def rules():
    if not os.path.exists(RULES):                # pragma: no cover
        pytest.skip("builtin.yaml not present")
    with open(RULES) as fh:
        return yaml.safe_load(fh)["rules"]


def test_lower_priority_means_runs_first(rules):
    """The urgent rules must sort BEFORE the routine ones.

    Expressed as an ordering assertion rather than exact numbers so retuning a
    value does not fail the test, while inverting the convention does.
    """
    by_id = {r["id"]: r.get("priority", 50) for r in rules}
    urgent = ("credentials_found", "smbv1_enabled", "cve_referenced")
    routine = ("ssh_version", "tls_present", "http_service")
    for u in urgent:
        for r in routine:
            if u in by_id and r in by_id:
                assert by_id[u] < by_id[r], (
                    f"{u} (P{by_id[u]}) must run before {r} (P{by_id[r]}) — lower "
                    f"runs first, per scan_recommender.py")


def test_no_rule_uses_the_inverted_convention(rules):
    """A rule above 60 is almost certainly written 'higher = urgent'.

    The default is 50 and the recommender's most urgent band is 5-10, so a high
    number signals the wrong direction rather than a deliberately low priority.
    """
    suspicious = [(r["id"], r["priority"]) for r in rules if r.get("priority", 50) > 60]
    assert not suspicious, (
        f"these look inverted (lower runs first): {suspicious}")


def test_dispatch_sorts_by_priority():
    """The dispatcher must ORDER the selection, not take arrival order.

    Asserted on source because the failure is silent: an unsorted dispatch still
    works, it just runs the wrong scans first when capacity is limited.
    """
    src = open(os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")).read()
    m = re.search(r"selected = sorted\((.*?)\n\s*\)", src, re.S)
    assert m, "dispatch no longer sorts `selected` — priority would be ignored"
    assert "priority" in m.group(1), "dispatch sorts, but not by priority"


def test_reorder_endpoint_exists_and_guards_history():
    src = open(os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")).read()
    assert "/api/scan-recommendations/reorder" in src, "no reorder endpoint"
    # Reordering something that already ran would rewrite history without
    # changing what happens next.
    m = re.search(r"UPDATE scan_recommendations.*?RETURNING id, priority", src, re.S)
    assert m, "reorder UPDATE not found"
    assert "status IN ('pending','queued','skipped','failed')" in m.group(0), (
        "reorder does not restrict itself to work that has not run yet")


def test_reorder_rejects_duplicate_ids():
    src = open(os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")).read()
    assert "contains duplicates" in src, (
        "duplicate ids must be rejected — the resulting order would be ambiguous")


def test_reorder_starts_below_the_curated_band():
    """A manual reorder must not silently outrank a curated Metasploit module.

    scan_recommender assigns 5 (msf) and 10 (other) to high-value ports. A
    reorder starting at or below that would jump the queue for reasons the
    operator did not express.
    """
    src = open(os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")).read()
    # Match to the next class/def rather than a blank line: the field is
    # separated from the class line by an explanatory comment block, so a
    # blank-line delimiter captured nothing and the test failed on its own
    # regex rather than on the code.
    m = re.search(r"class ReorderRequest\(BaseModel\):(.*?)(?=\n@|\nclass |\nasync def |\ndef )",
                  src, re.S)
    assert m, "ReorderRequest not found"
    start = re.search(r"start: int = (\d+)", m.group(1))
    assert start and int(start.group(1)) > 10, (
        f"reorder start must sit above the recommender's 5/10 high-value band, "
        f"got {start.group(1) if start else 'none'}")
