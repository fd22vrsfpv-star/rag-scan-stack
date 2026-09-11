"""assets.engagement_id — filled from scope, or not at all.

Run on demand:

    pytest tests/test_asset_engagement_attribution.py -v

WHY THIS EXISTS
---------------
`assets` had NO engagement propagation whatsoever. Every other table that needs
an engagement has a `propagate_engagement_to_*` trigger; assets got one only if
the inserting code happened to pass one, and most paths did not. Measured on the
live DB 2026-09-11: **137 of 1831 assets carried no engagement**.

That was not a cosmetic gap. Those 137 rows were the reason 897 unattributed
`follow_up_items` could not be repaired by resolving their hostname to an asset —
the asset itself knew nothing, so the lookup succeeded and returned NULL. Any
view that groups by engagement silently lost those hosts.

The fix resolves a host against `scope_targets`, which is the authority on which
engagement a host belongs to. On the live data 135 of the 137 resolved, and
every single one via an **exact** scope entry rather than a suffix guess; one
more resolved by address, leaving a single hostname-less private IP that is in
no scope and correctly stays NULL.

ATTRIBUTION IS NOT AUTHORIZATION
--------------------------------
The scope gate reads `scope_targets`, never `assets.engagement_id`. Stamping a
row here can never make a host scannable — it decides which engagement's reports
and views the host shows up in. `test_attribution_does_not_touch_scope_tables`
pins that the trigger only ever writes `NEW.engagement_id`.

WHAT IS PINNED
--------------
  * the trigger exists and fires on INSERT **and** UPDATE (a hostname often
    arrives after the row — nmap finds the address, reverse DNS names it later);
  * it only ever fills a NULL, never rewrites an existing engagement;
  * a blank `scope_targets.target` is not a wildcard;
  * suffix matching is domain-only, never IP octets;
  * a host in no scope stays NULL rather than being guessed at.

SABOTAGE PROOF
--------------
Drop `btrim(st.target) <> ''` from `propagate_engagement_to_assets()` in
db_init/ensure_all_tables.sql, re-run scripts/ensure_db_schema.sh, and
`test_host_in_no_scope_stays_null` fails — the orphan gets attributed to
whichever engagement owns a blank target. Remove `OR UPDATE` from the trigger and
`test_hostname_arriving_later_is_attributed` fails. Restore and both pass.
"""
import os
import re

import pytest

from _container import container_exec

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCHEMA = os.path.join(REPO, "db_init", "ensure_all_tables.sql")


@pytest.fixture(scope="module")
def schema_sql():
    if not os.path.exists(SCHEMA):
        pytest.skip(f"{SCHEMA} not present")
    with open(SCHEMA, encoding="utf-8") as fh:
        return fh.read()


def _assets_trigger_body(sql: str) -> str:
    m = re.search(
        r"CREATE OR REPLACE FUNCTION propagate_engagement_to_assets\(\)(.*?)\n\$\$;",
        sql, re.S)
    return m.group(1) if m else ""


# ── Static ratchet: runs anywhere, no DB needed ────────────────────────────

def test_assets_attribution_trigger_exists(schema_sql):
    assert _assets_trigger_body(schema_sql), (
        "propagate_engagement_to_assets() is gone — assets go back to being "
        "attributed only when an insert happens to supply an engagement")
    assert "CREATE TRIGGER trg_assets_engagement" in schema_sql, (
        "the trigger is defined but never attached to the table")


def test_trigger_fires_on_update_too(schema_sql):
    """A hostname commonly arrives after the row does; INSERT-only would miss it."""
    m = re.search(r"CREATE TRIGGER trg_assets_engagement\s+(.*?)ON assets",
                  schema_sql, re.S)
    assert m and "INSERT OR UPDATE" in m.group(1), (
        "trg_assets_engagement must fire BEFORE INSERT OR UPDATE — an address "
        "discovered before its hostname would never be attributed")


def test_trigger_only_fills_nulls(schema_sql):
    body = _assets_trigger_body(schema_sql)
    assert "IF NEW.engagement_id IS NULL THEN" in body, (
        "the trigger must only fill a NULL; rewriting an existing engagement "
        "would silently move hosts between engagements on every update")


def test_blank_scope_target_is_guarded(schema_sql):
    """Four live scope_targets rows have target='' — a blank is not a wildcard."""
    body = _assets_trigger_body(schema_sql)
    assert body.count("btrim(st.target) <> ''") >= 2, (
        "the blank-scope-target guard is missing from a lookup; every host "
        "would match the empty target and be attributed at random")


def test_suffix_match_excludes_ip_hosts(schema_sql):
    body = _assets_trigger_body(schema_sql)
    assert "!~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'" in body, (
        "an IP host could suffix-match a domain scope rule on trailing octets")


def test_attribution_does_not_touch_scope_tables(schema_sql):
    """Attribution must never write scope. Scope is the operator's authorization
    and the one thing this trigger reads but must not change."""
    body = _assets_trigger_body(schema_sql)
    for forbidden in ("INSERT INTO", "UPDATE ", "DELETE FROM"):
        assert forbidden not in body.upper(), (
            f"propagate_engagement_to_assets() performs a {forbidden.strip()} — "
            "it must only read scope_targets and set NEW.engagement_id")


# ── Live DB: skips cleanly when the stack is down ──────────────────────────

_LIVE = r"""
import json, os, psycopg2
c = psycopg2.connect(os.environ["DB_DSN"]); c.autocommit = True
cur = c.cursor()
DOM    = "pytest-asset-scope.example-test.invalid"
INDOM  = "deep.sub." + DOM              # in scope by suffix
ORPHAN = "pytest-asset-orphan.example-test.invalid"
eid = None
res = {}

def asset_engagement(host):
    cur.execute("SELECT engagement_id FROM assets WHERE hostname=%s", (host,))
    r = cur.fetchone()
    return str(r[0]) if r and r[0] else None

try:
    cur.execute("INSERT INTO engagements (name, status) VALUES "
                "('pytest-asset-attribution','planning') RETURNING id")
    eid = cur.fetchone()[0]
    res["expected"] = str(eid)
    cur.execute("INSERT INTO scope_targets (engagement_id,name,target,target_type,source) "
                "VALUES (%s,'pytest_asset_scope',%s,'domain','manual')", (eid, DOM))
    # The trap: a blank target in this very engagement.
    cur.execute("INSERT INTO scope_targets (engagement_id,name,target,target_type,source) "
                "VALUES (%s,'pytest_asset_scope','','domain','manual')", (eid,))

    # 1. INSERT with a hostname covered by scope -> attributed
    cur.execute("INSERT INTO assets (ip, hostname) VALUES ('198.51.100.11'::inet, %s)", (INDOM,))
    res["insert_attributed"] = asset_engagement(INDOM)

    # 2. INSERT with no hostname, then UPDATE to add one -> attributed on UPDATE
    cur.execute("INSERT INTO assets (ip, hostname) VALUES ('198.51.100.12'::inet, NULL)")
    cur.execute("UPDATE assets SET hostname=%s WHERE ip='198.51.100.12'::inet",
                ("late." + DOM,))
    res["update_attributed"] = asset_engagement("late." + DOM)

    # 3. A host in no scope must stay NULL despite the blank target existing
    cur.execute("INSERT INTO assets (ip, hostname) VALUES ('198.51.100.13'::inet, %s)", (ORPHAN,))
    res["orphan"] = asset_engagement(ORPHAN)

    # 4. An existing engagement is never rewritten
    cur.execute("INSERT INTO engagements (name, status) VALUES "
                "('pytest-asset-other','planning') RETURNING id")
    other = cur.fetchone()[0]
    cur.execute("INSERT INTO assets (ip, hostname, engagement_id) "
                "VALUES ('198.51.100.14'::inet, %s, %s)", ("keep." + DOM, other))
    cur.execute("UPDATE assets SET os='linux' WHERE ip='198.51.100.14'::inet")
    res["preserved"] = asset_engagement("keep." + DOM)
    res["other_engagement"] = str(other)
finally:
    cur.execute("DELETE FROM assets WHERE ip << '198.51.100.0/24'::inet")
    cur.execute("DELETE FROM scope_targets WHERE name='pytest_asset_scope'")
    cur.execute("DELETE FROM engagements WHERE name IN "
                "('pytest-asset-attribution','pytest-asset-other')")
print(json.dumps(res))
"""


@pytest.fixture(scope="module")
def live():
    res = container_exec(_LIVE, timeout=180)
    if res is None:
        pytest.skip("rag-api container unreachable — cannot exercise the trigger")
    if res.startswith("__ERR__"):
        pytest.fail(f"asset attribution round-trip failed: {res}")
    import json
    return json.loads(res.strip().splitlines()[-1])


def test_scoped_hostname_is_attributed_on_insert(live):
    assert live["insert_attributed"] == live["expected"], (
        "an asset whose hostname is covered by the engagement's scope was not "
        "attributed on INSERT")


def test_hostname_arriving_later_is_attributed(live):
    """nmap finds the address; reverse DNS names it later. INSERT-only misses it."""
    assert live["update_attributed"] == live["expected"], (
        "a hostname added by a later UPDATE did not attribute the asset — the "
        "trigger is probably INSERT-only again")


def test_host_in_no_scope_stays_null(live):
    """Fail closed, and prove the blank scope target is not a wildcard."""
    assert live["orphan"] is None, (
        "an asset matching no scope rule was attributed anyway — a blank "
        "scope_targets.target is being treated as a wildcard")


def test_existing_engagement_is_never_rewritten(live):
    assert live["preserved"] == live["other_engagement"], (
        "an UPDATE moved an asset to a different engagement; the trigger must "
        "only ever fill a NULL")
