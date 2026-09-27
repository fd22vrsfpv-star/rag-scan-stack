"""The `scratch_schema` fixture must keep test writes out of the LIVE tables.

WHY THIS EXISTS
---------------
A pytest run once persisted 16 `phase='__pytest_phase'` rows into the live
`tool_selection_learned` table and left an APPROVED
`exploit/unix/misc/pytest_release` row in the live `pending_exploits` queue —
tests writing straight into production tables (OPEN_ITEMS: "pytest runs write
into production tables"). `tests/conftest.py` now offers a `scratch_schema`
fixture: a uniquely-named throwaway schema that unqualified CREATE/INSERT
statements resolve into, so a self-contained direct-DB test cannot reach the
`public` tables the running stack reads.

This test proves the fixture actually isolates writes, and that its create/drop
helpers create and then remove the schema.

Runs on demand (needs a reachable DB):

    TEST_DB_DSN=postgresql://app:app@localhost:5432/scans pytest \
        tests/test_scratch_schema_isolation.py -v

Skips cleanly with no database.

SABOTAGE PROOF
--------------
  * Delete the `SET search_path TO "<schema>", public` line in
    `conftest.create_scratch_schema` and
    `test_unqualified_writes_land_in_scratch_not_public` fails: the unqualified
    CREATE TABLE lands in `public`, so `to_regclass('public.<probe>')` is no
    longer NULL.
  * Make `create_scratch_schema` return a fixed name (drop the uuid) and
    `test_create_and_drop_helpers` starts failing on the second run because the
    schema already exists.
"""
import os
import uuid

import pytest

import conftest  # the module under test (create/drop helpers + ScratchSchema)

psycopg2 = pytest.importorskip("psycopg2")


def _plain_conn():
    """A separate connection with the DEFAULT search_path (public), so it sees
    only what genuinely reached the live schema."""
    dsn = os.environ.get("TEST_DB_DSN") or os.environ.get("DB_DSN")
    if not dsn:
        pytest.skip("no TEST_DB_DSN/DB_DSN — cannot verify isolation")
    try:
        c = psycopg2.connect(dsn, connect_timeout=3)
        c.autocommit = True
        return c
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"database unreachable: {type(e).__name__}")


def _regclass(conn, qualified):
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (qualified,))
        return cur.fetchone()[0]


def _schema_exists(conn, name):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
            (name,),
        )
        return cur.fetchone() is not None


def test_unqualified_writes_land_in_scratch_not_public(scratch_schema):
    """An UNQUALIFIED CREATE/INSERT through the fixture resolves to the scratch
    schema and is invisible to a plain connection reading `public`."""
    probe = f"iso_probe_{uuid.uuid4().hex[:10]}"
    scratch_schema.execute(f'CREATE TABLE {probe} (id text)')
    scratch_schema.execute(f"INSERT INTO {probe} (id) VALUES ('x')")

    # It exists in the scratch schema and holds the row.
    assert _regclass(scratch_schema.conn, f'"{scratch_schema.name}".{probe}') is not None
    got = scratch_schema.execute(f'SELECT count(*) FROM {probe}')
    assert got[0][0] == 1

    # It never reached public (checked from a separate, default-search_path conn).
    other = _plain_conn()
    try:
        assert _regclass(other, f'public.{probe}') is None, (
            "an unqualified CREATE TABLE reached the public schema — the scratch "
            "search_path is not redirecting writes")
    finally:
        other.close()


def test_writes_to_a_real_live_table_name_do_not_touch_public(scratch_schema):
    """Mirror the OPEN_ITEM directly: a test writing `pending_exploits` must not
    add rows to the LIVE `pending_exploits`. A scratch table shadowing the real
    name catches an escaped write as a changed live row count."""
    other = _plain_conn()
    try:
        if _regclass(other, 'public.pending_exploits') is None:
            pytest.skip("public.pending_exploits not present in this database")
        with other.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.pending_exploits")
            before = cur.fetchone()[0]

        marker = f"exploit/unix/misc/pytest_scratch_{uuid.uuid4().hex[:8]}"
        # Unqualified -> the scratch schema, shadowing the live table name.
        scratch_schema.execute(
            "CREATE TABLE pending_exploits (id serial PRIMARY KEY, exploit_id text)")
        scratch_schema.execute(
            "INSERT INTO pending_exploits (exploit_id) VALUES (%s)", (marker,))

        # The row is in the scratch copy...
        got = scratch_schema.execute(
            "SELECT count(*) FROM pending_exploits WHERE exploit_id = %s", (marker,))
        assert got[0][0] == 1

        # ...and the LIVE table is untouched: same count, no marker row.
        with other.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.pending_exploits")
            after = cur.fetchone()[0]
            cur.execute(
                "SELECT count(*) FROM public.pending_exploits WHERE exploit_id = %s",
                (marker,))
            leaked = cur.fetchone()[0]
        assert leaked == 0, "the write reached the LIVE pending_exploits table"
        assert after == before, "the live pending_exploits row count changed"
    finally:
        other.close()


def test_create_and_drop_helpers():
    """The helpers create a schema and then remove it (no leaked schemas)."""
    conn = _plain_conn()
    try:
        name = conftest.create_scratch_schema(conn)
        try:
            assert _schema_exists(conn, name), "schema was not created"
        finally:
            conftest.drop_scratch_schema(conn, name)
        assert not _schema_exists(conn, name), "schema was not dropped at teardown"
    finally:
        conn.close()
