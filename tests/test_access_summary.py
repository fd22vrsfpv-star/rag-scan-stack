"""The per-host access summary must execute and agree with the detail endpoint.

Run on demand:

    pytest tests/test_access_summary.py -v
    TEST_BFF=https://localhost:3002 ACCESS_SUMMARY_URL=https://localhost:3002/api/assets/access/summary \
        pytest tests/test_access_summary.py

WHY THIS EXISTS
---------------
The asset list grew a shell badge and a "held access" filter, both fed by
`GET /assets/access/summary` — a grouped query that no unit test exercises. A bad
column, a broken FILTER clause or a NameError in the f-string-free query would
pass import and `ast.parse`, report a healthy container, and surface only as an
empty badge column that reads as "we hold nothing" rather than "the query
broke". This runs the query.

The badge count must also mean the same thing the host's Current Access tab
means. Both are defined here as status='live' AND score>0; if the summary drifts
from the detail endpoint, a host shows "3 live" in the list and something else
when opened. So where a host appears in the summary, this cross-checks its
`live` against the detail endpoint's own `live` for the same target.

Skips cleanly when the stack is not running, so a laptop unit run stays green.

SABOTAGE PROOF
--------------
Change the summary's FILTER to `status <> 'dead'` for the live count and
`test_summary_live_agrees_with_detail` fails where any host holds an unverified
access. Drop the HAVING clause and hosts with only dead access appear, failing
`test_summary_only_lists_hosts_with_access`.
"""
import os

import pytest
from conftest import BFF_API  # shared service endpoints (see tests/conftest.py)

requests = pytest.importorskip("requests")

BASE = os.environ.get("BFF_BASE") or BFF_API
SUMMARY_URL = os.environ.get("ACCESS_SUMMARY_URL", f"{BASE}/assets/access/summary")


def _get(url):
    try:
        r = requests.get(url, timeout=20, verify=False)
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"endpoint unreachable at {url}: {type(e).__name__}")
    if r.status_code == 404:                     # pragma: no cover
        pytest.skip(f"route not present at {url} (stack not rebuilt?)")
    if r.status_code >= 500:                     # pragma: no cover
        pytest.fail(f"{url} returned HTTP {r.status_code}: {r.text[:300]}")
    if r.status_code >= 400:                     # pragma: no cover
        pytest.skip(f"{url} returned HTTP {r.status_code} (auth/config)")
    return r.json()


def test_summary_executes_and_has_the_expected_shape():
    """The query runs and returns {summary: {target: {live,total}}, hosts:int}."""
    body = _get(SUMMARY_URL)
    assert isinstance(body, dict), body
    assert "summary" in body and isinstance(body["summary"], dict), body
    assert body.get("hosts") == len(body["summary"]), body
    for target, counts in body["summary"].items():
        assert isinstance(target, str) and target, target
        assert set(counts) >= {"live", "total"}, counts
        assert isinstance(counts["live"], int) and isinstance(counts["total"], int)
        # A host is only listed if it holds a non-dead access.
        assert counts["total"] > 0, (target, counts)
        assert 0 <= counts["live"] <= counts["total"], (target, counts)


def test_summary_only_lists_hosts_with_access():
    """No host appears with zero non-dead access — that is the HAVING clause."""
    body = _get(SUMMARY_URL)
    for target, counts in body["summary"].items():
        assert counts["total"] >= 1, (target, counts)


def test_summary_live_agrees_with_detail():
    """The badge's `live` must equal the host's Current Access `live`.

    Both are status='live' AND score>0. If they disagree, the list and the
    detail panel tell the operator two different things about the same host.
    """
    body = _get(SUMMARY_URL)
    if not body["summary"]:
        pytest.skip("no host currently holds access; nothing to cross-check")
    for target, counts in list(body["summary"].items())[:10]:
        detail = _get(f"{BASE}/assets/{target}/access")
        assert detail["live"] == counts["live"], (
            f"{target}: summary live={counts['live']} but detail "
            f"live={detail['live']} — badge disagrees with the tab")
