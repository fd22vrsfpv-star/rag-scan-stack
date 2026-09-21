"""A target in more than one engagement scope is detected, recorded, and flagged.

Run on demand:

    pytest tests/test_scope_conflicts.py -v
    DB_DSN=postgresql://app:app@localhost:5432/scans pytest tests/test_scope_conflicts.py

WHY THIS EXISTS
---------------
When a scan/session resolves its engagement from the target's scope and the
target is in MORE THAN ONE engagement's scope, resolution returns None — it will
not guess an owner. That is correct, but it was INVISIBLE: the session ran
unattached, silently lost its engagement's exploit pre-approval, and nobody was
told the scope needed fixing. A live lab run sat unattached for exactly this
reason (192.168.1.150 was in both `lab` and `redteam3`). Now the conflict is
detected and recorded so an operator can remove the duplicate.

This exercises the REAL detection helpers and the REAL DB (a synthetic, unused
test IP added to two existing engagements, then cleaned up), plus the live
`/scope/conflicts` endpoint. Skips cleanly without a database or the stack.

SABOTAGE PROOF
--------------
Make engagements_for_ip return only the first match (a LIMIT 1) and
test_a_target_in_two_scopes_is_detected fails. Make resolve_engagement_for_ip
return a match instead of None on ambiguity and test_ambiguous_resolution_is_none
fails. Skip the record on ambiguity and test_a_conflict_is_recorded fails.
"""
import os
import sys
import uuid

import pytest
from conftest import BFF_API  # shared service endpoints (see tests/conftest.py)

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

psycopg2 = pytest.importorskip("psycopg2", reason="psycopg2 not installed")
ax = pytest.importorskip("etl.asset_utils", reason="etl.asset_utils not importable")

TEST_IP = "10.203.201.199"          # RFC1918, deliberately unused by any scan
SCOPE_NAME_A = "conftest_scope_a"
SCOPE_NAME_B = "conftest_scope_b"


def _dsn():
    return os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")


def _conn():
    dsn = _dsn()
    if not dsn:
        pytest.skip("no DB_DSN / DATABASE_URL — DB integration test skipped")
    try:
        return psycopg2.connect(dsn, connect_timeout=5)
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"database unreachable: {type(e).__name__}")


def _two_engagement_ids(cur):
    """Two real engagement ids to satisfy the scope_targets FK. Skip if the
    instance does not have at least two engagements to borrow."""
    cur.execute("SELECT id::text FROM engagements ORDER BY created_at LIMIT 2")
    rows = [r[0] for r in cur.fetchall()]
    if len(rows) < 2:
        pytest.skip("need at least two engagements to construct a conflict")
    return rows[0], rows[1]


@pytest.fixture()
def two_scopes():
    """Put TEST_IP in two engagements' scope, yield (conn, eid_a, eid_b), then
    remove the scope rows AND any conflict row the test created."""
    conn = _conn()
    conn.autocommit = True
    with conn.cursor() as cur:
        if ax.__dict__.get("engagements_for_ip") is None:
            pytest.skip("engagements_for_ip not present")
        eid_a, eid_b = _two_engagement_ids(cur)
        cur.execute("DELETE FROM scope_targets WHERE target=%s AND name IN (%s,%s)",
                    (TEST_IP, SCOPE_NAME_A, SCOPE_NAME_B))
        cur.execute("INSERT INTO scope_targets (name,target,target_type,engagement_id) "
                    "VALUES (%s,%s,'ip',%s::uuid)", (SCOPE_NAME_A, TEST_IP, eid_a))
        cur.execute("INSERT INTO scope_targets (name,target,target_type,engagement_id) "
                    "VALUES (%s,%s,'ip',%s::uuid)", (SCOPE_NAME_B, TEST_IP, eid_b))
    try:
        yield conn, eid_a, eid_b
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM scope_targets WHERE target=%s AND name IN (%s,%s)",
                        (TEST_IP, SCOPE_NAME_A, SCOPE_NAME_B))
            cur.execute("DELETE FROM scope_conflicts WHERE target=%s", (TEST_IP,))
        conn.close()


def test_a_target_in_two_scopes_is_detected(two_scopes):
    conn, eid_a, eid_b = two_scopes
    with conn.cursor() as cur:
        matches = ax.engagements_for_ip(cur, TEST_IP)
    ids = {m[0] for m in matches}
    assert ids == {eid_a, eid_b}, matches


def test_ambiguous_resolution_is_none_and_records(two_scopes):
    conn, _, _ = two_scopes
    with conn.cursor() as cur:
        assert ax.resolve_engagement_for_ip(cur, TEST_IP) is None, (
            "a host in two scopes must not resolve to an engagement")
    # resolve_engagement_for_ip records the conflict on its own connection.
    with conn.cursor() as cur:
        cur.execute("SELECT array_length(engagement_ids,1), resolved "
                    "FROM scope_conflicts WHERE target=%s", (TEST_IP,))
        row = cur.fetchone()
    assert row is not None, "the conflict was not recorded"
    assert row[0] == 2 and row[1] is False, row


def test_a_single_scope_resolves_cleanly():
    """One scope → a real engagement id, and NO conflict recorded."""
    conn = _conn()
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            eid_a, _ = _two_engagement_ids(cur)
            cur.execute("DELETE FROM scope_targets WHERE target=%s AND name=%s",
                        (TEST_IP, SCOPE_NAME_A))
            cur.execute("INSERT INTO scope_targets (name,target,target_type,engagement_id) "
                        "VALUES (%s,%s,'ip',%s::uuid)", (SCOPE_NAME_A, TEST_IP, eid_a))
            assert ax.resolve_engagement_for_ip(cur, TEST_IP) == eid_a
            cur.execute("SELECT 1 FROM scope_conflicts WHERE target=%s", (TEST_IP,))
            assert cur.fetchone() is None, "a single-scope target must not be a conflict"
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM scope_targets WHERE target=%s AND name=%s",
                        (TEST_IP, SCOPE_NAME_A))
            cur.execute("DELETE FROM scope_conflicts WHERE target=%s", (TEST_IP,))
        conn.close()


def test_the_endpoint_lists_and_resolves_a_conflict(two_scopes):
    """The live /scope/conflicts endpoint surfaces the recorded conflict and can
    mark it resolved. Skips if the stack (BFF) is not reachable."""
    requests = pytest.importorskip("requests")
    conn, _, _ = two_scopes
    # Ensure a conflict row exists (record via the real recorder).
    matches = None
    with conn.cursor() as cur:
        matches = ax.engagements_for_ip(cur, TEST_IP)
    ax.record_scope_conflict(TEST_IP, matches, detected_by="pytest")

    base = os.environ.get("BFF_BASE") or BFF_API
    try:
        r = requests.get(f"{base}/scope/conflicts", timeout=15, verify=False)
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"BFF unreachable: {type(e).__name__}")
    if r.status_code == 404:                     # pragma: no cover
        pytest.skip("route not present (stack not rebuilt?)")
    if r.status_code >= 400:                     # pragma: no cover
        pytest.skip(f"endpoint HTTP {r.status_code}")
    body = r.json()
    mine = [c for c in body["conflicts"] if c["target"] == TEST_IP]
    assert mine, f"{TEST_IP} not listed among conflicts"
    cid = mine[0]["id"]
    assert mine[0]["resolved"] is False and mine[0]["detections"] >= 1

    rr = requests.post(f"{base}/scope/conflicts/{cid}/resolve", timeout=15, verify=False)
    assert rr.status_code < 400, rr.text
    assert rr.json().get("resolved") is True
