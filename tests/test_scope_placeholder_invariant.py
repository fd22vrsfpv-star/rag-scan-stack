"""A scope with a real target must not also keep the blank '' placeholder.

Run on demand:

    pytest tests/test_scope_placeholder_invariant.py -v
    # the live-DB check runs only inside a container with DB_DSN (e.g. rag-api)

WHY THIS EXISTS
---------------
An empty scope carries a sentinel placeholder row (target='',
source='__placeholder__') so it stays visible in the UI. But
add_engagement_scope_targets ALWAYS inserted that placeholder and never removed
it once real targets were added — so a scope like 'testfire'
(http://demo.testfire.net) also kept a blank-target row. Blank targets are an
ILIKE '%%' wildcard trap in scope-intelligence (matched every engagement's recon
findings). The invariant "a scope with any real target has no placeholder" is
enforced by the AFTER INSERT trigger trg_scope_targets_drop_placeholder so it
holds at EVERY insert path, not just that one endpoint.

SABOTAGE PROOF
--------------
Remove the trigger from ensure_all_tables.sql and test_trigger_declared fails;
drop the trigger in the DB and the live test fails.
"""
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCHEMA = os.path.join(REPO, "db_init", "ensure_all_tables.sql")


def test_trigger_declared_in_schema():
    if not os.path.exists(SCHEMA):
        pytest.skip("ensure_all_tables.sql not present")
    sql = open(SCHEMA, encoding="utf-8").read()
    assert "scope_targets_drop_placeholder" in sql, (
        "the placeholder-drop trigger function must be declared in "
        "ensure_all_tables.sql so a clean build / schema repair carries it")
    assert "trg_scope_targets_drop_placeholder" in sql and \
        "AFTER INSERT ON public.scope_targets" in sql, (
        "the AFTER INSERT trigger on scope_targets must be declared")


def _connect():
    dsn = os.environ.get("DB_DSN")
    if not dsn:
        pytest.skip("DB_DSN not set — live trigger check runs inside rag-api")
    try:
        import psycopg2
    except ImportError:
        pytest.skip("psycopg2 not installed in this tier")
    try:
        return psycopg2.connect(dsn)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"cannot reach DB: {e}")


def test_placeholder_dropped_when_real_target_added():
    conn = _connect()
    conn.autocommit = True
    name = "__pytest_placeholder_invariant__"
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM scope_targets WHERE name=%s", (name,))
        # Empty scope: placeholder survives.
        cur.execute("INSERT INTO scope_targets (name,target,target_type,source) "
                    "VALUES (%s,'','domain','__placeholder__')", (name,))
        cur.execute("SELECT count(*) FROM scope_targets WHERE name=%s", (name,))
        assert cur.fetchone()[0] == 1, "placeholder should persist on an empty scope"
        # Real target: placeholder must be dropped.
        cur.execute("INSERT INTO scope_targets (name,target,target_type,source) "
                    "VALUES (%s,'example.com','domain','manual')", (name,))
        cur.execute("SELECT target FROM scope_targets WHERE name=%s", (name,))
        rows = [r[0] for r in cur.fetchall()]
        assert rows == ["example.com"], (
            f"placeholder should be gone once a real target exists; got {rows}")
        # And no blank target remains.
        cur.execute("SELECT count(*) FROM scope_targets "
                    "WHERE name=%s AND COALESCE(btrim(target),'')=''", (name,))
        assert cur.fetchone()[0] == 0
    finally:
        cur.execute("DELETE FROM scope_targets WHERE name=%s", (name,))
        conn.close()
