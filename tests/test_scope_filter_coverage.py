"""The scope selector must apply on every panel that shows it.

Run on demand:

    pytest tests/test_scope_filter_coverage.py -v

WHY THIS EXISTS
---------------
Two separate defects, both reported as "changing the scope line doesn't
refresh".

1. **A control that filtered nothing.** On AssetBrowser the `ScopeFilter` sits
   in the SHARED page header, so it is on screen for all four tabs, and the count
   line appends "in <scope>" whatever tab is open. Only Assets and Subdomains
   honoured it. Software and Credentials ignored the scope completely *while the
   label claimed they were filtered*.

2. **A cache that never refetched.** The active engagement reaches the backend as
   the `X-Engagement-Id` HEADER, not as part of the URL or the React Query key.
   Switching engagement therefore changes what the server would return while the
   key stays identical, so React Query correctly served the PREVIOUS
   engagement's rows and never refetched. 492 of 534 `queryKey` declarations in
   src/api have no engagement term, so this was fixed once at the root rather
   than 492 times — see `useEngagementCacheReset`.

`clear()` and not `invalidateQueries()` on an engagement switch: invalidate keeps
showing stale data until the new response lands, and here that stale data is
another engagement's hosts and credentials. Showing one client's estate under
another client's name, even briefly, is not cosmetic.

WHY FOLLOW-UPS AND RECOMMENDATIONS GOT THE CONTROL TOO
------------------------------------------------------
An engagement holds several scope lists (the scanned scope, customer_scope,
unknown_scope). Triage and dispatch that can wander onto the wrong list is a
host we are not authorised to touch. The recommendations table DISPATCHES, so an
out-of-scope row there is one click from traffic — the server-side dispatch gate
still refuses it and always will, but it should not be selectable.

SABOTAGE PROOF
--------------
Delete `<EngagementCacheReset />` from App.tsx and
`test_engagement_switch_resets_the_cache` fails. Remove the `matchesAnyScope`
call from the follow-ups item memo and `test_followups_filters_by_scope` fails.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO, "dashboard", "frontend", "src")
APP = os.path.join(SRC, "App.tsx")
RESET = os.path.join(SRC, "hooks", "useEngagementCacheReset.ts")
AB = os.path.join(SRC, "pages", "AssetBrowser.tsx")
FU = os.path.join(SRC, "pages", "FollowUps.tsx")
RECS = os.path.join(SRC, "components", "recommendations", "ScanRecommendationsTable.tsx")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ── The central cache reset ────────────────────────────────────────────────

def test_engagement_switch_resets_the_cache():
    app = _read(APP)
    assert "<EngagementCacheReset />" in app, (
        "the cache reset is not mounted; switching engagement will serve the "
        "previous engagement's rows from cache and never refetch")
    assert "QueryClientProvider" in app
    # It must be INSIDE the provider or useQueryClient throws.
    prov = app.index("<QueryClientProvider")
    reset = app.index("<EngagementCacheReset />")
    assert prov < reset, "EngagementCacheReset must render inside QueryClientProvider"


def test_reset_clears_rather_than_invalidates_on_engagement_change():
    """invalidate keeps showing the old engagement's data while refetching."""
    src = _read(RESET)
    assert "qc.clear()" in src, (
        "an engagement switch must CLEAR the cache — invalidateQueries keeps "
        "the previous engagement's hosts on screen until the refetch lands")
    assert "prev.eid !== engagementId" in src


def test_reset_does_not_fire_on_first_render():
    src = _read(RESET)
    assert "prev === null" in src, (
        "without an initial-mount guard the reset wipes the cache the app has "
        "only just populated, on every page load")


# ── Every tab that shows the control must honour it ────────────────────────

@pytest.mark.parametrize("needle,what", [
    ("matchesAnyScope(a.hostname, a.ip)", "assets"),
    ("matchesScope(s.subdomain", "subdomains"),
    ("matchesAnyScope(sw.hostname, sw.ip)", "software"),
    ("softwareItems", "software list is the scoped one"),
])
def test_assetbrowser_tabs_filter_by_scope(needle, what):
    src = _read(AB)
    assert needle in src, (
        f"the {what} tab no longer applies the scope filter, but the ScopeFilter "
        "control is in the shared header and the count says 'in <scope>' — it "
        "would claim to filter and not")


def test_assetbrowser_credentials_filter_by_scope():
    src = _read(AB)
    i = src.index("const allCredentials = useMemo(")
    body = src[i:i + 700]
    assert "matchesAnyScope" in body, "the credentials tab ignores the scope filter"


def test_software_count_reports_the_filtered_list():
    """The count said `softwareData?.count` — the SERVER total — while the table
    showed a filtered list, so the number never matched the rows."""
    src = _read(AB)
    assert "`${softwareItems.length} detections`" in src, (
        "the software count is not taken from the filtered list")


# ── Follow-ups and recommendations ─────────────────────────────────────────

def test_followups_filters_by_scope():
    src = _read(FU)
    assert "<ScopeFilter" in src, "the follow-ups panel has no scope control"
    assert "matchesAnyScope(item.target)" in src, (
        "follow-ups do not filter by scope; triage could act on a host outside "
        "the chosen list")


def test_followups_scope_is_not_bypassed_by_search():
    """A search that can pull in an out-of-scope host defeats the point."""
    src = _read(FU)
    i = src.index("const items = useMemo(")
    body = src[i:i + 1400]
    assert "isScopeFiltering ? allItems.filter" in body, (
        "the no-search path returns allItems unfiltered, so clearing the search "
        "box shows out-of-scope follow-ups")
    assert body.index("matchesAnyScope(item.target)") < body.index("const text ="), (
        "the scope check must run before the text match, not after it")


def test_recommendations_filter_by_scope():
    src = _read(RECS)
    assert "<ScopeFilter" in src, "the recommendations table has no scope control"
    assert "matchesAnyScope(r.ip" in src, (
        "recommendations do not filter by scope. This table DISPATCHES scans, so "
        "an out-of-scope row is one click from traffic")


def test_recommendations_scope_runs_before_the_other_filters():
    src = _read(RECS)
    i = src.index("const recs = allRecs.filter(")
    body = src[i:i + 600]
    assert body.index("matchesAnyScope") < body.index("filters?.status"), (
        "the scope check must be the first thing applied")


def test_scope_selector_syncs_with_the_global_picker():
    """Each panel seeds from the global scope and re-seeds when the engagement
    changes — a scope name from one engagement is meaningless in another."""
    for path, name in ((FU, "follow-ups"), (RECS, "recommendations")):
        src = _read(path)
        assert re.search(r"useEffect\(\(\) => \{ setScopeFilter\(globalScope \|\| ''\) \},"
                         r" \[globalScope, engagementId\]\)", src), (
            f"{name} does not re-seed its scope from the global picker on an "
            "engagement switch")
