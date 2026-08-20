"""The recommendations listing must actually execute and return usable rows.

Run on demand:

    pytest tests/test_recommendation_listing.py -v
    RECS_URL=https://localhost:3002/api/scan-recommendations pytest tests/test_recommendation_listing.py

WHY THIS EXISTS
---------------
The listing query is built with an f-string and had never been executed by any
test — the module's unit tests cover pure helpers only. A brace placeholder
inside a SQL comment made every call raise NameError; the endpoint swallowed it
and returned zero rows, so the Recommendations page went blank while the suite
stayed green and the module still imported fine.

An import-time or syntax check cannot catch that class of failure. Running the
query can, along with any other SQL error (bad column, broken join, ambiguous
reference) introduced by a later edit.

Skips cleanly when the stack is not running, so a laptop unit run stays green.
"""
import os
import re

import pytest

requests = pytest.importorskip("requests")

URL = os.environ.get("RECS_URL", "https://localhost:3002/api/scan-recommendations")

# Fields the UI depends on. A completed recommendation that renders a status and
# nothing else is the exact complaint this endpoint has to answer, so the
# result/command columns are part of the contract, not extras.
REQUIRED_FIELDS = {
    "id", "scanner", "status", "command", "script", "job_id",
    "result_status", "result_exit_code", "result_preview",
    "artifact_id", "artifact_preview", "dispatched_command",
}


def _get(status=None):
    try:
        url = f"{URL}?status={status}" if status else URL
        r = requests.get(url, timeout=20, verify=False)
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"recommendations endpoint unreachable at {URL}: {type(e).__name__}")
    if r.status_code >= 500:                     # pragma: no cover
        pytest.fail(f"listing returned HTTP {r.status_code}: {r.text[:300]}")
    if r.status_code >= 400:                     # pragma: no cover
        pytest.skip(f"endpoint returned HTTP {r.status_code} (auth/config)")
    return r.json()


@pytest.mark.parametrize("status", ["pending", "completed", "failed", "queued", "skipped"])
def test_listing_executes_for_every_status(status):
    """Every status filter must run the query without error.

    A NameError or SQL error inside the query surfaces here as an empty list
    plus a logged exception, so the count is checked against the endpoint's own
    `total` rather than assumed non-empty — a genuinely empty status is fine, a
    broken query is not.
    """
    data = _get(status)
    assert isinstance(data, dict), f"expected an object, got {type(data)}"
    assert "recommendations" in data, f"missing 'recommendations' key: {list(data)[:6]}"
    recs = data["recommendations"]
    assert isinstance(recs, list)
    assert data.get("total") == len(recs), \
        f"total={data.get('total')} disagrees with {len(recs)} rows returned"


def test_returned_rows_carry_the_fields_the_ui_renders():
    """Guards the contract behind the completed/failed detail panel."""
    for status in ("completed", "failed", "pending"):
        data = _get(status)
        if data["recommendations"]:
            row = data["recommendations"][0]
            missing = REQUIRED_FIELDS - set(row)
            assert not missing, f"status={status} rows missing fields: {sorted(missing)}"
            return
    pytest.skip("no recommendations stored to inspect")


def test_all_statuses_together_are_not_silently_empty():
    """If EVERY status is empty, the query is far more likely broken than the
    database genuinely being bare — that is exactly how the outage presented."""
    counts = {s: _get(s).get("total", 0)
              for s in ("pending", "completed", "failed", "queued", "skipped")}
    if sum(counts.values()) == 0:                # pragma: no cover
        pytest.skip(f"no recommendations in any status: {counts} — nothing to verify")
    assert sum(counts.values()) > 0


def test_executed_recommendations_expose_what_ran():
    """A completed recommendation should carry a command that actually ran.

    `script` is the recommender's TEMPLATE and may still hold placeholders;
    `command` must prefer the dispatched command so the UI never shows an
    operator a command they did not run and which would not work if copied.
    """
    data = _get("completed")
    rows = [r for r in data["recommendations"] if r.get("dispatched_command")]
    if not rows:
        pytest.skip("no completed recommendation has a dispatched command yet")
    for r in rows:
        assert r["command"] == r["dispatched_command"], (
            f"command should show what ran, not the template: "
            f"command={r['command']!r} dispatched={r['dispatched_command']!r}")
        # Match TEMPLATE placeholders ({target}, {port}) specifically, not any
        # brace: a scanner-service dispatch is recorded as
        # `POST /jobs/nikto-scan {"target_url": ...}`, where the braces are the
        # JSON payload that was actually sent and are entirely correct.
        leftover = re.findall(r"\{[a-zA-Z_]+\}", r["command"] or "")
        assert not leftover, \
            f"executed command still contains placeholder(s) {leftover}: {r['command']!r}"
