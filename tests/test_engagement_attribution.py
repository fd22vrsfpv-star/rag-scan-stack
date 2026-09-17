"""ENFORCED: every table that holds target data must be attributable to an
engagement — either directly (an `engagement_id` column) or via its asset
(`asset_id` -> assets.engagement_id).

Why: data written with no engagement link (e.g. hashcat-cracked credentials keyed
only by `ip`) is not attributed to the engagement and an engagement purge/delete
misses it, so it keeps showing after the engagement is cleared. Requiring every
target-scoped table to be engagement-attributable keeps "delete an engagement's
data" complete and keeps a re-scan clean.

This RATCHETS: a target-scoped table with neither `engagement_id` nor `asset_id`
must be listed in ENG_ATTR_DEBT with a reason. A NEW one fails by name; a resolved
one must be removed from the list (a table that gains attribution should drop out).

Skips cleanly without a DB (reads information_schema).

    DB_DSN=... pytest tests/test_engagement_attribution.py
"""
import os

import pytest

psycopg2 = pytest.importorskip("psycopg2")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# Target-scoped base tables that today carry NEITHER engagement_id NOR asset_id, so
# they can only be tied to an engagement by IP/target. Each needs a reason; shrink
# this list by adding engagement_id (or asset_id) to the table. Do NOT grow it
# without a stated reason.
ENG_ATTR_DEBT = {
    "scan_runs": "delta run rows keyed by target; engagement inferred at query time",
    "tool_executions": "kali-dispatched tool log keyed by target/scan_id",
    "scan_pipeline_jobs": "transient pipeline job rows keyed by host",
    "burp_followup_queue": "export queue keyed by target",
    "port_access_advice": "advisory rows keyed by target",
    "scope_conflicts": "scope-overlap rows spanning engagements by design",
    "target_tool_settings": "operator per-target tool config (kept across purges)",
}

_TARGET_COLS = ("ip", "target", "target_ip", "host")


def _conn():
    try:
        c = psycopg2.connect(DB_DSN, connect_timeout=5); c.autocommit = True
        return c
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")


def _target_scoped_tables(cur):
    cur.execute(
        "SELECT t.table_name, "
        "  bool_or(c.column_name='engagement_id') AS has_eng, "
        "  bool_or(c.column_name='asset_id') AS has_asset "
        "FROM information_schema.tables t "
        "JOIN information_schema.columns c "
        "  ON c.table_name=t.table_name AND c.table_schema=t.table_schema "
        "WHERE t.table_schema='public' AND t.table_type='BASE TABLE' "
        "  AND t.table_name IN (SELECT table_name FROM information_schema.columns "
        "     WHERE table_schema='public' AND column_name IN %s) "
        "GROUP BY t.table_name", (_TARGET_COLS,))
    return {r[0]: (r[1], r[2]) for r in cur.fetchall()}


def test_every_target_table_is_engagement_attributable():
    c = _conn()
    try:
        tables = _target_scoped_tables(c.cursor())
    finally:
        c.close()
    if not tables:
        pytest.skip("no target-scoped tables found")
    # A table is attributable if it has engagement_id OR asset_id.
    unattributable = {t for t, (eng, asset) in tables.items() if not (eng or asset)}
    undeclared = sorted(unattributable - set(ENG_ATTR_DEBT))
    assert not undeclared, (
        "target-scoped tables with NO engagement attribution (no engagement_id, no "
        "asset_id) and not in ENG_ATTR_DEBT:\n  " + "\n  ".join(undeclared) +
        "\nAdd engagement_id (or asset_id) to the table, or declare it in "
        "ENG_ATTR_DEBT with a reason.")


def test_debt_list_does_not_rot():
    """A table listed as debt that has GAINED attribution must be removed."""
    c = _conn()
    try:
        tables = _target_scoped_tables(c.cursor())
    finally:
        c.close()
    if not tables:
        pytest.skip("no target-scoped tables found")
    resolved = sorted(t for t in ENG_ATTR_DEBT
                      if t in tables and any(tables[t]))   # now has eng or asset
    assert not resolved, ("these are in ENG_ATTR_DEBT but are now attributable — "
                          "remove them from the list:\n  " + "\n  ".join(resolved))
