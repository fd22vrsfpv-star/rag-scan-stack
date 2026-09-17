"""ENFORCED: every table that holds COLLECTED TARGET DATA must be attributable to
an engagement — either directly (an `engagement_id` column) or via its asset
(`asset_id` -> assets.engagement_id).

Collected target data = scans, assets, ports, findings, vulns, web/recon findings,
credentials, exploits, sessions/held access, observations — anything gathered
*about a specific target during an engagement*.

NOT required (exempt by design): techniques / methodology, follow-up queues, and
anything inherently shared ACROSS engagements or operator config. Those legitimately
have no single engagement and are listed in ENG_ATTR_EXEMPT.

Why: collected data written with no engagement link (e.g. hashcat-cracked credentials
keyed only by `ip`) is not attributed and an engagement purge/delete misses it, so it
keeps showing after the engagement is cleared. Requiring collected-data tables to be
engagement-attributable keeps "delete an engagement's data" complete and a re-scan clean.

This RATCHETS: a collected-data table with neither `engagement_id` nor `asset_id`
must be listed in ENG_ATTR_DEBT with a reason. A NEW one fails by name; a resolved one
must be removed. Exempt-by-design tables go in ENG_ATTR_EXEMPT (permanent, with a reason).

Skips cleanly without a DB (reads information_schema).

    DB_DSN=... pytest tests/test_engagement_attribution.py
"""
import os

import pytest

psycopg2 = pytest.importorskip("psycopg2")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# EXEMPT BY DESIGN — techniques, follow-ups, cross-engagement, or operator config.
# These are NOT collected-per-engagement data, so they need no engagement_id and are
# intentionally kept across a data purge.
ENG_ATTR_EXEMPT = {
    "burp_followup_queue": "follow-up export queue — an action item, not collected data",
    "port_access_advice": "technique/advice ('what to try on this service') — reusable across engagements",
    "scope_conflicts": "scope-overlap rows that SPAN engagements by design",
    "target_tool_settings": "operator per-target tool config — reused, kept across purges",
}

# DEBT — COLLECTED DATA that SHOULD be engagement-attributed but is not yet. Each
# needs a reason; shrink by adding engagement_id (or asset_id). Do NOT grow without one.
ENG_ATTR_DEBT = {
    "scan_runs": "delta scan-run rows keyed by target; should carry engagement_id",
    "tool_executions": "kali-dispatched tool-run log keyed by target/scan_id; should carry engagement_id",
    "scan_pipeline_jobs": "pipeline job rows keyed by host; should carry engagement_id",
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
    # A table is OK if it has engagement_id OR asset_id, or is exempt-by-design,
    # or is declared debt.
    known = set(ENG_ATTR_EXEMPT) | set(ENG_ATTR_DEBT)
    unattributable = {t for t, (eng, asset) in tables.items() if not (eng or asset)}
    undeclared = sorted(unattributable - known)
    assert not undeclared, (
        "collected-data tables with NO engagement attribution (no engagement_id, no "
        "asset_id) and not classified:\n  " + "\n  ".join(undeclared) +
        "\nIf this is collected target data, add engagement_id (or asset_id) or put "
        "it in ENG_ATTR_DEBT with a reason. If it is a technique / follow-up / "
        "cross-engagement / config table, put it in ENG_ATTR_EXEMPT with a reason.")


def test_debt_does_not_rot():
    """A DEBT table that has GAINED attribution must be moved out of the list."""
    c = _conn()
    try:
        tables = _target_scoped_tables(c.cursor())
    finally:
        c.close()
    if not tables:
        pytest.skip("no target-scoped tables found")
    resolved = sorted(t for t in ENG_ATTR_DEBT if t in tables and any(tables[t]))
    assert not resolved, ("these are in ENG_ATTR_DEBT but are now attributable — "
                          "remove them from the list:\n  " + "\n  ".join(resolved))


def test_exempt_and_debt_are_disjoint():
    both = sorted(set(ENG_ATTR_EXEMPT) & set(ENG_ATTR_DEBT))
    assert not both, f"a table is both exempt and debt — pick one: {both}"


# ---------------------------------------------------------------------------
# scope_targets is a COLLECTED-DATA table (it has both engagement_id and target),
# so it passes the schema check above. But that check only proves the COLUMN
# exists — not that it is filled. Scope entries define what an engagement may
# touch, so a NULL engagement_id makes a scope row unattributable and an
# engagement purge cannot claim it. The ONLY scope name allowed to be
# engagement-less is the global cross-engagement deny-list (`not_in_scope`),
# which the dispatch gate reads and both writers insert with `engagement_id IS
# NULL` on purpose (app/rag-api/api.py). This is a DATA check on live rows
# (separate from the schema check) and it RATCHETS: a new NULL-engagement scope
# name fails by name.
SCOPE_NULL_ALLOWED = {
    "not_in_scope": "global cross-engagement deny-list — read by the dispatch "
                    "gate and inserted with engagement_id IS NULL by design "
                    "(app/rag-api/api.py: 'the global not_in_scope list')",
}


def test_scope_targets_are_engagement_tied():
    c = _conn()
    try:
        cur = c.cursor()
        cur.execute("SELECT 1 FROM information_schema.tables WHERE "
                    "table_schema='public' AND table_name='scope_targets'")
        if not cur.fetchone():
            pytest.skip("scope_targets table absent")
        cur.execute("SELECT name, count(*) FROM scope_targets "
                    "WHERE engagement_id IS NULL GROUP BY name ORDER BY name")
        rows = cur.fetchall()
    finally:
        c.close()
    offending = {name: n for (name, n) in rows if name not in SCOPE_NULL_ALLOWED}
    assert not offending, (
        "scope_targets rows with NULL engagement_id for non-global scope names "
        "(per-engagement scope entries MUST carry engagement_id):\n  "
        + "\n  ".join(f"{k}: {v} rows" for k, v in sorted(offending.items()))
        + "\nBackfill them to their owning engagement. If a name is a genuine "
          "global cross-engagement list, add it to SCOPE_NULL_ALLOWED with a reason.")
