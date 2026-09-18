"""The assets engagement trigger attributes an asset whose hostname matches a
URL-typed scope entry (target='http://demo.testfire.net'). Previously the trigger
compared the hostname to the raw scope target INCLUDING the scheme, so a
url-typed scope never matched and the asset (and its ports/web_findings) were
orphaned — the "scan mixes scope with another target's" bug.

Runs against the live DB in a rolled-back transaction; skips without one.
SABOTAGE PROOF: revert the trigger to compare lower(st.target) (with scheme) and
test_url_scope_attributes_asset fails.
"""
import os
import pytest
psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _conn():
    try:
        c = psycopg2.connect(DSN, connect_timeout=5)
        return c
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")


def test_url_scope_attributes_asset():
    c = _conn()
    try:
        cur = c.cursor()
        cur.execute("SELECT to_regclass('public.scope_targets'), to_regclass('public.engagements')")
        if not all(cur.fetchone()):
            pytest.skip("schema not present")
        cur.execute("BEGIN")
        cur.execute("INSERT INTO engagements (id, name) VALUES (gen_random_uuid(),'t_url_scope') RETURNING id")
        eng = cur.fetchone()[0]
        # a URL-typed scope entry (scheme + host), like the real testfire row
        cur.execute("INSERT INTO scope_targets (id,name,target,target_type,engagement_id) "
                    "VALUES (gen_random_uuid(),'t','http://portal.t-url-scope.example','url',%s)", (eng,))
        # an asset with the bare hostname + a resolved IP, NO engagement supplied
        cur.execute("INSERT INTO assets (id, ip, hostname) VALUES "
                    "(gen_random_uuid(),'203.0.113.9'::inet,'portal.t-url-scope.example') RETURNING engagement_id")
        got = cur.fetchone()[0]
        assert str(got) == str(eng), f"trigger did not attribute url-scoped asset: {got}"
    finally:
        try:
            c.rollback()
        finally:
            c.close()


def test_no_orphan_testfire_asset():
    """Regression: the demo.testfire.net asset is attributed (not NULL)."""
    c = _conn()
    try:
        cur = c.cursor()
        cur.execute("SELECT to_regclass('public.assets')")
        if not cur.fetchone()[0]:
            pytest.skip("no assets")
        cur.execute("SELECT engagement_id FROM assets WHERE hostname='demo.testfire.net'")
        row = cur.fetchone()
        if not row:
            pytest.skip("no testfire asset in this DB")
        assert row[0] is not None, "demo.testfire.net asset is orphaned (engagement_id NULL)"
    finally:
        c.close()
