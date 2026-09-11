"""The Follow-Ups "Engagement Only" filter, end to end.

Run on demand:

    pytest tests/test_followup_engagement_filter.py -v

WHY THIS EXISTS
---------------
The filter chain was correct at every layer and the feature still did nothing:

    FollowUps.tsx  -> engagement_id=<uuid>          (sent when the toggle is on)
    BFF   /api/follow-ups                           (forwards it verbatim)
    rag-api /follow-ups -> WHERE engagement_id = %s::uuid

The bug was one layer lower, in the data. `propagate_engagement_to_followups()`
stamped `engagement_id` only when it could pull an IPv4 literal out of `target`,
so every hostname/URL follow-up kept `engagement_id NULL` — and `NULL = <uuid>`
is never true. Measured on the live DB: 915 of 2528 follow-ups (36%) were NULL.

The first fix — resolve the hostname against `assets.hostname` — turned out to
be COSMETIC, and only measuring showed it. Of those 915 rows, 897 DO have an
asset row; it is the ASSET that carries no engagement (137 such assets), and 18
have no asset at all. Legs 1 and 2 together recovered **0** rows.

What actually works is asking scope, which is the authority on which engagement a
host belongs to: 915 of 915 resolved, verified with the real backfill statement
in a rolled-back transaction before it was applied. That is why leg 3 exists and
why it must not be "simplified" back out.

Two traps leg 3 has to dodge, both live in the real data:
  * `scope_targets` contains rows with `target = ''` (blackbaud, customer,
    customer_scope, msf). Suffix-matching against a blank target makes EVERY host
    match, so a blank is not a wildcard — same class of bug as
    tests/test_scope_placeholder_filtering.py.
  * Suffix matching is for domains only. An IP host must never match a scope row
    because its trailing octets happen to align.

WHAT IS PINNED
--------------
  * the schema still carries the hostname leg and the backfill (static, always
    runs — this is the ratchet that stops a revert going unnoticed);
  * `followup_target_host()` strips scheme/userinfo/port/path/query/trailing dot;
  * a follow-up inserted with a URL target inherits an engagement (via the
    asset when it has one, otherwise via scope membership);
  * a blank scope target does NOT behave as a wildcard;
  * that row is actually returned by `GET /follow-ups?engagement_id=...`;
  * a follow-up whose host matches nothing stays NULL rather than being
    attributed to an arbitrary engagement.

SABOTAGE PROOF
--------------
Delete the `-- 3. Scope membership` branch from
`propagate_engagement_to_followups()` in db_init/ensure_all_tables.sql, re-run
scripts/ensure_db_schema.sh, and `test_scope_membership_attributes_followup`
fails with engagement_id None. Drop the `btrim(s.target) <> ''` guard and
`test_blank_scope_target_is_not_a_wildcard` fails. Restore and both pass. The
static tests fail on the edit alone, without the DB.
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


def _followups_trigger_body(sql: str) -> str:
    """The body of propagate_engagement_to_followups(), or '' if absent."""
    m = re.search(
        r"CREATE OR REPLACE FUNCTION propagate_engagement_to_followups\(\)(.*?)\n\$\$;",
        sql, re.S)
    return m.group(1) if m else ""


# ── Static ratchet: runs anywhere, no DB needed ────────────────────────────

def test_schema_defines_the_shared_host_extractor(schema_sql):
    """The trigger and the backfill must agree on what 'the host' is, which they
    can only do by calling the same function rather than re-typing the regex."""
    assert "CREATE OR REPLACE FUNCTION followup_target_host(" in schema_sql, (
        "followup_target_host() is gone; the trigger and backfill will drift")


def test_followups_trigger_has_a_hostname_leg(schema_sql):
    body = _followups_trigger_body(schema_sql)
    assert body, "propagate_engagement_to_followups() not found in the schema"
    assert "followup_target_host" in body, (
        "the trigger no longer resolves hostnames — every URL/FQDN follow-up "
        "will keep engagement_id NULL and vanish from the Engagement Only view")
    assert "lower(hostname)" in body, "the hostname lookup against assets is gone"


def test_followups_trigger_ignores_assets_with_no_engagement(schema_sql):
    """assets allows many rows per IP; an unordered LIMIT 1 can stamp NULL."""
    body = _followups_trigger_body(schema_sql)
    assert body.count("engagement_id IS NOT NULL") >= 2, (
        "both the IP and hostname lookups must skip assets rows that carry no "
        "engagement, or a virtual-host sibling can stamp NULL over a known value")


def test_followups_trigger_asks_scope(schema_sql):
    """Leg 3 is the one that actually recovers rows — legs 1+2 recovered 0 of 915
    on the live database, because the assets themselves were unattributed."""
    body = _followups_trigger_body(schema_sql)
    assert "scope_targets" in body, (
        "the trigger no longer consults scope membership; hostname follow-ups "
        "whose asset carries no engagement will go back to being unattributed")


def test_blank_scope_target_is_guarded_everywhere(schema_sql):
    """`scope_targets` really does hold rows with target='' (four of them, in
    blackbaud/customer/customer_scope/msf). A blank suffix matches every host."""
    body = _followups_trigger_body(schema_sql)
    assert "btrim(s.target) <> ''" in body, (
        "the trigger lost its blank-scope-target guard — every host would "
        "suffix-match the empty target and be attributed at random")
    # The backfill runs the same match and needs the same guard.
    assert schema_sql.count("btrim(st.target) <> ''") >= 2, (
        "the backfill lost its blank-scope-target guard")


def test_scope_suffix_match_excludes_ip_hosts(schema_sql):
    """An IP host must not suffix-match a domain scope rule on trailing octets."""
    body = _followups_trigger_body(schema_sql)
    assert "!~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'" in body, (
        "the IP-literal exclusion on suffix matching is gone")


def test_schema_backfills_existing_rows(schema_sql):
    """BEFORE INSERT triggers do not fire retroactively. Without the backfill
    the fix only helps follow-ups created after the next deploy, and the
    operator's existing several-thousand-row list stays broken."""
    assert "UPDATE follow_up_items f" in schema_sql, (
        "the one-time engagement backfill for existing follow_up_items is gone")


# ── Live DB: skips cleanly when the stack is down ──────────────────────────

_HOST_CASES = r"""
import json, os, psycopg2
c = psycopg2.connect(os.environ["DB_DSN"]); cur = c.cursor()
cases = [
    ("https://shop.example.com:8443/admin?x=1", "shop.example.com"),
    ("http://Host.Example.COM/path",            "host.example.com"),
    ("user@host.example.com.",                  "host.example.com"),
    ("10.0.0.5:8080",                           "10.0.0.5"),
    ("plain.example.com",                       "plain.example.com"),
    ("",                                        None),
    (None,                                      None),
]
out = []
for target, expected in cases:
    cur.execute("SELECT followup_target_host(%s)", (target,))
    out.append({"target": target, "expected": expected, "got": cur.fetchone()[0]})
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def host_cases():
    res = container_exec(_HOST_CASES)
    if res is None:
        pytest.skip("rag-api container unreachable — cannot exercise the DB")
    if res.startswith("__ERR__"):
        pytest.fail(f"followup_target_host() could not be called: {res}")
    return res


def test_target_host_extraction(host_cases):
    import json
    for row in json.loads(host_cases):
        assert row["got"] == row["expected"], (
            f"followup_target_host({row['target']!r}) -> {row['got']!r}, "
            f"expected {row['expected']!r}")


_ROUNDTRIP = r"""
import json, os, urllib3, requests, psycopg2
urllib3.disable_warnings()
c = psycopg2.connect(os.environ["DB_DSN"]); c.autocommit = True
cur = c.cursor()
KEY = os.environ.get("API_KEY", "changeme")
HOST      = "pytest-fu-filter.example-test.invalid"      # has an attributed asset
SCOPEDOM  = "pytest-fu-scope.example-test.invalid"       # in scope, NO asset row
SCOPEHOST = "deep.sub." + SCOPEDOM                       # must match by suffix
ORPHAN    = "pytest-fu-orphan.example-test.invalid"      # in nothing at all
eid = None
res = {}

def insert(title, target):
    cur.execute("INSERT INTO follow_up_items (id,title,target,severity,rule_id,status) "
                "VALUES (gen_random_uuid(),%s,%s,'info','pytest_fu_filter','open') "
                "RETURNING id, engagement_id", (title, target))
    row = cur.fetchone()
    return str(row[0]), (str(row[1]) if row[1] else None)

try:
    cur.execute("INSERT INTO engagements (name, status) VALUES "
                "('pytest-fu-engagement-filter','planning') RETURNING id")
    eid = cur.fetchone()[0]
    res["expected_engagement"] = str(eid)

    # (a) asset leg: an asset that knows its engagement, reachable by hostname
    cur.execute("INSERT INTO assets (ip, hostname, engagement_id) "
                "VALUES ('203.0.113.77'::inet, %s, %s) ON CONFLICT DO NOTHING",
                (HOST, eid))
    # (b) scope leg: a scope rule with NO matching asset anywhere
    cur.execute("INSERT INTO scope_targets (engagement_id,name,target,target_type,source) "
                "VALUES (%s,'pytest_fu_scope',%s,'domain','manual')", (eid, SCOPEDOM))
    # (c) the trap: a BLANK scope target. If the guard is missing this makes
    #     every host on earth match this engagement.
    cur.execute("INSERT INTO scope_targets (engagement_id,name,target,target_type,source) "
                "VALUES (%s,'pytest_fu_scope','','domain','manual')", (eid,))

    res["url_row_id"],    res["url_engagement"]    = insert(
        "pytest url follow-up", "https://" + HOST + ":8443/admin?a=1")
    res["scope_row_id"],  res["scope_engagement"]  = insert(
        "pytest scope follow-up", "https://" + SCOPEHOST + "/login")
    res["orphan_row_id"], res["orphan_engagement"] = insert(
        "pytest orphan follow-up", "https://" + ORPHAN + "/x")

    r = requests.get("https://localhost:8000/follow-ups",
                     params={"engagement_id": str(eid), "rule_id": "pytest_fu_filter",
                             "limit": 10000},
                     headers={"x-api-key": KEY}, verify=False, timeout=60)
    res["list_status"] = r.status_code
    res["listed_ids"] = [f["id"] for f in (r.json().get("follow_ups") or [])] if r.ok else []
finally:
    cur.execute("DELETE FROM follow_up_items WHERE rule_id = 'pytest_fu_filter'")
    cur.execute("DELETE FROM scope_targets WHERE name = 'pytest_fu_scope'")
    cur.execute("DELETE FROM assets WHERE hostname = %s", (HOST,))
    if eid:
        cur.execute("DELETE FROM engagements WHERE id = %s", (eid,))
print(json.dumps(res))
"""


@pytest.fixture(scope="module")
def roundtrip():
    res = container_exec(_ROUNDTRIP, timeout=180)
    if res is None:
        pytest.skip("rag-api container unreachable — cannot exercise the filter")
    if res.startswith("__ERR__"):
        pytest.fail(f"follow-up engagement round-trip failed: {res}")
    import json
    return json.loads(res.strip().splitlines()[-1])


def test_url_target_inherits_engagement(roundtrip):
    """Leg 2: a hostname/URL follow-up whose asset IS attributed."""
    assert roundtrip["url_engagement"] == roundtrip["expected_engagement"], (
        "a follow-up targeting https://<host> did not inherit its asset's "
        "engagement — the Engagement Only filter will hide it")


def test_scope_membership_attributes_followup(roundtrip):
    """Leg 3, the one that actually mattered: no asset row exists for this host
    at all, and the engagement still has to be worked out from scope. On the
    live data this leg is the difference between 0 and 915 rows recovered."""
    assert roundtrip["scope_engagement"] == roundtrip["expected_engagement"], (
        "a follow-up on a host covered by the engagement's scope was not "
        "attributed — legs 1 and 2 alone recovered 0 of 915 real rows")


def test_blank_scope_target_is_not_a_wildcard(roundtrip):
    """A `scope_targets` row with target='' must select NOTHING. Four such rows
    exist in the live database; treating one as a wildcard would attribute every
    follow-up to whichever engagement happened to own it."""
    assert roundtrip["orphan_engagement"] is None, (
        "a follow-up matching no scope rule was attributed anyway — the blank "
        "scope target is being treated as a wildcard")


def test_filtered_list_returns_the_rows(roundtrip):
    assert roundtrip["list_status"] == 200, (
        f"GET /follow-ups?engagement_id=... returned {roundtrip['list_status']}")
    for key in ("url_row_id", "scope_row_id"):
        assert roundtrip[key] in roundtrip["listed_ids"], (
            f"{key} is missing from the engagement-filtered list")
    assert roundtrip["orphan_row_id"] not in roundtrip["listed_ids"], (
        "an unattributed follow-up leaked into an engagement-filtered list")
