"""One address, two asset rows — the same machine recorded twice.

Run on demand:

    pytest tests/test_asset_merge.py -v

WHY THIS EXISTS
---------------
`ix_assets_ip_hostname` is UNIQUE(ip, COALESCE(hostname, '')), so
(192.168.1.150, '') and (192.168.1.150, 'metasploitable') are two perfectly legal
rows. That is intentional — virtual hosts on shared hosting are real. But a row
with NO hostname is not a virtual host; it is the same machine before its name
was known, and this deployment had exactly that split:

    nameless row      57 ports,  6 vulns,   1 web,  0 creds,   39 recon
    'metasploitable'   0 ports,  2 vulns, 758 web,  7 creds,  110 recon

The pre-existing normalization prefers the NULL-hostname row when it consolidates
ports, so the host's ports lived on one row and its findings on the other.
Anything joining ports to findings through `asset_id` returned nothing, and
`credential_findings.port_id` was NULL on all seven rows because `parse_brutus`
resolves the port under the finding's own `asset_id`.

`public.merge_duplicate_assets()` merges these; a two-DIFFERENT-hostname address
is left alone, because choosing a survivor there would be arbitrary.

The DB-backed tests skip cleanly without a database. The synthetic ones run
inside a transaction that is always rolled back, so they never touch engagement
data.
"""
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))

INSTALL_SCRIPTS = ("db_init/ensure_all_tables.sql", "db_init/setup_alldb.sql")


def _psql(sql):
    """One-shot query; returns the scalar text or None when unreachable."""
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def _psql_script(sql):
    """Run a multi-statement script on stdin. `docker exec` needs -i for that."""
    try:
        out = subprocess.run(
            ["docker", "exec", "-i", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tA"],
            input=sql, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


@pytest.fixture(scope="module")
def db():
    if _psql("SELECT 1") != "1":
        pytest.skip("no reachable rag-postgres; DB assertions cannot run here")
    if _psql("SELECT count(*) FROM pg_proc WHERE proname='merge_duplicate_assets'") == "0":
        pytest.skip("merge_duplicate_assets() not installed; run ensure_db_schema.sh")
    return True


# ── source-level (always run) ───────────────────────────────────────────────

@pytest.mark.unit
def test_migration_is_in_both_install_scripts():
    """A clean install and an upgrade must end up in the same place."""
    for rel in INSTALL_SCRIPTS:
        src = open(os.path.join(REPO, rel), encoding="utf-8").read()
        assert "FUNCTION public.merge_duplicate_assets()" in src, \
            f"{rel} does not define merge_duplicate_assets()"
        assert "merge_duplicate_assets()" in src.split(
            "FUNCTION public.merge_duplicate_assets()", 1)[1], \
            f"{rel} defines the function but never calls it"
        assert "UPDATE public.credential_findings cf" in src and "port_id = p.id" in src, \
            f"{rel} is missing the credential_findings.port_id backfill"


@pytest.mark.unit
def test_child_tables_come_from_the_catalog_not_the_fk_list():
    """pending_exploits.asset_id has NO foreign key.

    An FK-driven merge would silently orphan it, and the older hand-written
    remap in the same file lists 16 tables and omits it for exactly that reason.
    Reading information_schema means a table that grows an asset_id later is
    covered without editing the function.
    """
    src = open(os.path.join(REPO, INSTALL_SCRIPTS[0]), encoding="utf-8").read()
    fn = src.split("FUNCTION public.merge_duplicate_assets()", 1)[1].split("$MDA$;", 1)[0]
    assert "information_schema.columns" in fn and "'asset_id'" in fn, \
        "the child-table list is no longer discovered from the catalog"
    assert "pg_constraint" not in fn, \
        "the function derives its tables from foreign keys, which misses pending_exploits"


@pytest.mark.unit
def test_both_asset_helpers_adopt_the_nameless_row():
    """The migration repairs history; these two stop it recurring."""
    for rel in ("etl/asset_utils.py", "playwright_scanner/db_utils.py"):
        src = open(os.path.join(REPO, rel), encoding="utf-8").read()
        assert "SET hostname = %s" in src, \
            f"{rel} no longer names an existing nameless asset row"
        assert "COALESCE(NULLIF(btrim(b.hostname), ''), '') <> ''" in src, \
            (f"{rel} adopts without excluding addresses that already have a named "
             "row — that would attach one host's data to an unrelated vhost")


@pytest.mark.unit
def test_health_checks_assert_the_merge():
    src = open(os.path.join(REPO, "scripts", "ensure_db_schema.sh"), encoding="utf-8").read()
    assert "merge_duplicate_assets" in src, \
        "ensure_db_schema.sh does not check the merge function exists"
    assert "nameless duplicate asset row" in src, \
        "ensure_db_schema.sh does not report a surviving split asset"


@pytest.mark.unit
def test_savepoints_are_conditional_on_a_transaction():
    """SAVEPOINT raises NoActiveSqlTransaction on an autocommit connection.

    The bridge's commit phase wraps each row in one, and the endpoint originally
    used get_db(autocommit=True) — so every row failed and it reported
    "4 accounts, 0 upserted, 4 errors" while the dry run looked perfect.
    """
    src = open(os.path.join(REPO, "etl", "credential_bridge.py"), encoding="utf-8").read()
    assert "use_savepoint" in src, "savepoints are issued unconditionally again"
    api = open(os.path.join(REPO, "app", "rag-api", "api.py"), encoding="utf-8").read()
    for fn in ("bridge_credential_findings(", "vault_import_agent.import_secrets_from_recon("):
        # the `with get_db(...)` line preceding each call must not be autocommit
        for chunk in api.split(fn)[:-1]:
            ctx = [l for l in chunk.splitlines() if "with get_db(" in l]
            if ctx:
                assert "autocommit=True" not in ctx[-1], (
                    f"{fn} is called on an autocommit connection; its SAVEPOINTs "
                    "will raise on every row")


# ── the live database ───────────────────────────────────────────────────────

def test_no_split_assets_remain(db):
    n = _psql("""SELECT count(*) FROM (
                   SELECT ip FROM assets GROUP BY ip
                    HAVING count(*) > 1
                       AND count(DISTINCT NULLIF(btrim(hostname), '')) <= 1) d""")
    assert n == "0", f"{n} address(es) still hold a nameless duplicate asset row"


def test_merge_is_idempotent(db):
    """Nothing left to do means the function returns no rows."""
    assert _psql("SELECT count(*) FROM public.merge_duplicate_assets()") == "0"


def test_verified_credentials_link_to_a_real_port(db):
    """port_id was NULL on every row while the host was split in two."""
    unlinked = _psql("SELECT count(*) FROM credential_findings WHERE port_id IS NULL")
    assert unlinked == "0", f"{unlinked} credential finding(s) have no port_id"
    bad = _psql("""SELECT count(*) FROM credential_findings cf
                    LEFT JOIN ports p ON p.id = cf.port_id
                   WHERE p.id IS NULL
                      OR p.asset_id <> cf.asset_id
                      OR p.port <> cf.port""")
    assert bad == "0", f"{bad} credential finding(s) point at the wrong port row"


def test_a_synthetic_split_merges_without_losing_children(db):
    """The whole point: children move, nothing is dropped, nothing is orphaned.

    Runs inside BEGIN ... ROLLBACK, so engagement data is never touched.
    pending_exploits is included deliberately — it is the FK-less table an
    FK-driven merge would orphan.
    """
    out = _psql_script("""
BEGIN;
INSERT INTO assets (id, ip, hostname) VALUES
  ('11111111-1111-4111-8111-111111111111', '198.51.100.11', NULL),
  ('22222222-2222-4222-8222-222222222222', '198.51.100.11', 'merge-probe.test');
INSERT INTO ports (asset_id, proto, port) VALUES
  ('11111111-1111-4111-8111-111111111111', 'tcp', 21),
  ('11111111-1111-4111-8111-111111111111', 'tcp', 22);
-- pending_exploits carries several NOT NULL columns and a CHECK restricting
-- source to exploitdb|metasploit, so the probe row has to satisfy both. It is
-- here ONLY because its asset_id has no FK, which is what an FK-driven merge
-- would miss.
INSERT INTO pending_exploits
  (asset_id, source, exploit_id, exploit_title, target_ip, customized_command)
VALUES
  ('11111111-1111-4111-8111-111111111111', 'exploitdb', 'probe-1',
   'merge probe', '198.51.100.11', 'true');
SELECT 'MERGED', count(*) FROM public.merge_duplicate_assets()
 WHERE address = '198.51.100.11'::inet;
SELECT 'ROWS', count(*) FROM assets WHERE ip = '198.51.100.11';
SELECT 'HOST', COALESCE(hostname, '(none)') FROM assets WHERE ip = '198.51.100.11';
SELECT 'PORTS', count(*) FROM ports p JOIN assets a ON a.id = p.asset_id
 WHERE a.ip = '198.51.100.11';
SELECT 'PENDING', count(*) FROM pending_exploits pe JOIN assets a ON a.id = pe.asset_id
 WHERE a.ip = '198.51.100.11';
SELECT 'ORPHANPORTS', count(*) FROM ports p
 LEFT JOIN assets a ON a.id = p.asset_id WHERE a.id IS NULL;
ROLLBACK;
""")
    assert out, "synthetic merge script failed to run"
    got = dict(l.split("|", 1) for l in out.splitlines() if "|" in l)
    assert got.get("MERGED") == "1", f"the split was not merged: {got}"
    assert got.get("ROWS") == "1", f"{got.get('ROWS')} asset rows survived, expected 1"
    assert got.get("HOST") == "merge-probe.test", (
        f"survivor hostname is {got.get('HOST')!r} — the name was lost in the merge")
    assert got.get("PORTS") == "2", (
        f"{got.get('PORTS')} ports after the merge, expected 2 — children were dropped")
    assert got.get("PENDING") == "1", (
        "pending_exploits was not repointed; it has no FK, so an FK-driven merge "
        "orphans it silently")
    assert got.get("ORPHANPORTS") == "0", "the merge orphaned port rows"


def test_two_different_hostnames_are_left_alone(db):
    """Virtual hosts. Picking a survivor between two real names is arbitrary."""
    out = _psql_script("""
BEGIN;
INSERT INTO assets (ip, hostname) VALUES
  ('198.51.100.12', 'vhost-a.test'), ('198.51.100.12', 'vhost-b.test');
SELECT 'MERGED', count(*) FROM public.merge_duplicate_assets()
 WHERE address = '198.51.100.12'::inet;
SELECT 'ROWS', count(*) FROM assets WHERE ip = '198.51.100.12';
ROLLBACK;
""")
    assert out, "vhost script failed to run"
    got = dict(l.split("|", 1) for l in out.splitlines() if "|" in l)
    assert got.get("MERGED") == "0", "a genuine vhost pair was merged"
    assert got.get("ROWS") == "2", f"{got.get('ROWS')} vhost rows survived, expected 2"


def test_ports_collision_keeps_one_row_rather_than_failing(db):
    """ux_ports_asset_proto_port_scans is the only unique index naming asset_id.

    When both rows have the same port the repoint collides; the merge must drop
    the duplicate rather than abort, or one collision blocks the whole merge.
    """
    out = _psql_script("""
BEGIN;
INSERT INTO assets (id, ip, hostname) VALUES
  ('33333333-3333-4333-8333-333333333333', '198.51.100.13', NULL),
  ('44444444-4444-4444-8444-444444444444', '198.51.100.13', 'collide.test');
INSERT INTO ports (asset_id, proto, port) VALUES
  ('33333333-3333-4333-8333-333333333333', 'tcp', 80),
  ('44444444-4444-4444-8444-444444444444', 'tcp', 80);
SELECT 'MERGED', count(*) FROM public.merge_duplicate_assets()
 WHERE address = '198.51.100.13'::inet;
SELECT 'PORTS', count(*) FROM ports p JOIN assets a ON a.id = p.asset_id
 WHERE a.ip = '198.51.100.13';
ROLLBACK;
""")
    assert out, "collision script failed to run"
    got = dict(l.split("|", 1) for l in out.splitlines() if "|" in l)
    assert got.get("MERGED") == "1", "the merge aborted on a colliding port"
    assert got.get("PORTS") == "1", (
        f"{got.get('PORTS')} rows for one (asset, tcp, 80) — the duplicate survived")
