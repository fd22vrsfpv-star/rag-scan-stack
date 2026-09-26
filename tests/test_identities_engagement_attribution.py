"""Enumerated / MSF-dumped accounts MUST carry engagement_id.

Run standalone:

    pytest tests/test_identities_engagement_attribution.py -v

WHY THIS EXISTS
---------------
`import_enumerated_identities` inserted every account with NO engagement_id, so
the Users page (which filters by engagement only when one resolves) listed those
NULL rows under every engagement — MSF-host accounts showed under an unrelated
scope like `testfire`. CLAUDE.md "Engagement attribution is mandatory" requires
collected target data to carry its engagement. These guards fail if the writer
regresses to omitting engagement_id, and pin the shared resolver's precedence.

SABOTAGE PROOF
--------------
Remove `engagement_id` from the INSERT column list in target_wordlists.py and
test_enumerated_insert_sets_engagement_id fails; break the asset-first order in
resolve_engagement_for_host and test_resolver_prefers_asset_then_scope fails.
"""
import os
import re

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

try:
    from etl.identity_upsert import resolve_engagement_for_host
    from etl.backfill_identities_engagement import _host_for_identity
except Exception as e:  # noqa: BLE001
    pytest.skip(f"identity modules not importable here: {e}",
                allow_module_level=True)


# ── the writer statically includes engagement_id ────────────────────────────
def test_enumerated_insert_sets_engagement_id():
    src = open(os.path.join(REPO, "app", "rag-api", "target_wordlists.py"),
               encoding="utf-8").read()
    # Isolate the identities INSERT inside import_enumerated_identities.
    m = re.search(r"INSERT INTO identities\s*\((.*?)\)\s*VALUES", src, re.S)
    assert m, "could not find the identities INSERT column list"
    cols = m.group(1)
    assert "engagement_id" in cols, (
        "the enumerated identities INSERT must list engagement_id — without it "
        "every enumerated/MSF account is written with a NULL engagement and "
        "leaks across engagements on the Users page")
    assert "resolve_engagement_for_host" in src, (
        "the writer must resolve each host to its engagement via the shared "
        "resolve_engagement_for_host, not invent or omit an engagement")
    assert "COALESCE(identities.engagement_id" in src, (
        "ON CONFLICT must fill a NULL engagement without overwriting a good one")


# ── the shared resolver's precedence: asset first, then IP scope, else None ──
class _FakeCursor:
    """Minimal cursor: scripted fetchone results, records executed SQL."""
    def __init__(self, results):
        self._results = list(results)
        self.sql = []

    def execute(self, sql, params=None):
        self.sql.append(sql)

    def fetchone(self):
        return self._results.pop(0) if self._results else None


def test_resolver_prefers_asset_then_scope():
    # asset hit → returned without consulting scope
    cur = _FakeCursor([("eng-from-asset",)])
    assert resolve_engagement_for_host(cur, "10.0.0.5") == "eng-from-asset"
    assert len(cur.sql) == 1, "a resolved asset must not also query scope"

    # asset miss, scope hit
    cur = _FakeCursor([None, ("eng-from-scope",)])
    assert resolve_engagement_for_host(cur, "10.0.0.5") == "eng-from-scope"
    assert len(cur.sql) == 2

    # both miss → None (never guess an engagement)
    cur = _FakeCursor([None, None])
    assert resolve_engagement_for_host(cur, "10.0.0.5") is None

    # no host → None, no queries
    cur = _FakeCursor([("x",)])
    assert resolve_engagement_for_host(cur, "") is None
    assert cur.sql == []


def test_resolver_reads_dict_rows():
    cur = _FakeCursor([{"engagement_id": "eng-dict"}])
    assert resolve_engagement_for_host(cur, "10.0.0.5") == "eng-dict"


# ── the backfill derives a host from every shape a row can carry ─────────────
def test_backfill_host_derivation():
    # domain column (what the enumerated writer stores) wins
    assert _host_for_identity({"domain": "10.0.0.5",
                               "identifier": "bob@other"}) == "10.0.0.5"
    # host:<h> tag
    assert _host_for_identity({"domain": "", "tags": ["service:smb", "host:h1"],
                               "identifier": "bob"}) == "h1"
    # raw json host
    assert _host_for_identity({"domain": None, "tags": [],
                               "raw": {"host": "h2"},
                               "identifier": "bob"}) == "h2"
    # name@host identifier
    assert _host_for_identity({"domain": None, "tags": [], "raw": {},
                               "identifier": "svc@10.0.0.9"}) == "10.0.0.9"
    # nothing derivable → empty (row stays NULL, reported as unresolved)
    assert _host_for_identity({"domain": None, "tags": [], "raw": {},
                               "identifier": "bareuser"}) == ""


# ── live DB (skips cleanly without one): no host-resolvable NULL rows remain ─
def test_no_host_resolvable_null_rows_remain_live():
    dsn = os.environ.get("DB_DSN")
    if not dsn:
        pytest.skip("DB_DSN not set — live check runs inside rag-api")
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
    except ImportError:
        pytest.skip("psycopg2 not installed in this tier")
    try:
        conn = psycopg2.connect(dsn, connect_timeout=5)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"cannot reach DB: {e}")
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, identifier, domain, tags, raw "
                    "FROM identities WHERE engagement_id IS NULL")
        wcur = conn.cursor()
        leaked = []
        for row in cur.fetchall():
            host = _host_for_identity(row)
            if host and resolve_engagement_for_host(wcur, host):
                leaked.append(row["identifier"])
        assert not leaked, (
            f"{len(leaked)} identities have a resolvable host but NULL "
            f"engagement — run etl/backfill_identities_engagement.py --apply: "
            f"{leaked[:10]}")
    finally:
        conn.close()


# ── azurehound threads engagement_id into findings AND identities ────────────
def test_azurehound_writer_threads_engagement_id():
    src = open(os.path.join(REPO, "etl", "parse_azurehound.py"),
               encoding="utf-8").read()
    sig = src.split("def parse_azurehound", 1)[1].split("):", 1)[0]
    assert "engagement_id" in sig, (
        "parse_azurehound must accept an engagement_id parameter so its caller "
        "can pass the active engagement")
    m = re.search(r"INSERT INTO recon_findings\s*\((.*?)\)\s*VALUES", src, re.S)
    assert m and "engagement_id" in m.group(1), (
        "the azurehound recon_findings INSERT must list engagement_id")
    assert src.count("engagement_id=engagement_id") >= 3, (
        "every azurehound identity kind (user / service_principal / role) must "
        "thread engagement_id into its upsert_identity call")
