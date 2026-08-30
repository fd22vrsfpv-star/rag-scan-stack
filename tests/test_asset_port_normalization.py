"""A hostname equal to the IP must never create a second asset for one host.

Run on demand:

    pytest tests/test_asset_port_normalization.py -v

WHY THIS EXISTS
---------------
ix_assets_ip_hostname is UNIQUE(ip, COALESCE(hostname, '')) deliberately, so an
IP may hold several asset rows — virtual hosts on shared hosting are real. But a
hostname that is merely the IP string is NOT a vhost. It is "hostname unknown"
written the wrong way, and the index counts it as a different row from
hostname=NULL.

Ports hang off asset_id, so every asset row for an IP carried its own copy of
that host's ports. This deployment held 99 port rows for 59 real
(ip, proto, port) tuples — a 1.68x inflation of every port count an agent,
export or report reads. The agent context listed `22/tcp — ssh` twice.

Root cause was one call:

    hostname = parsed_url.netloc                       # keeps ":8080" too
    asset_id = get_or_create_asset(hostname, hostname=hostname)

Both asset helpers now drop a hostname that equals the IP, CHECK
assets_hostname_not_ip enforces it in the schema, and ensure_all_tables.sql
normalizes existing rows.

The DB-backed tests skip cleanly without a database; the source-level tests
always run.
"""
import os
import re
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))


def _psql(sql):
    """One scalar out of the live DB, or None when no DB is reachable."""
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-tAc", sql],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


@pytest.fixture(scope="module")
def db():
    if _psql("SELECT 1") != "1":
        pytest.skip("no reachable rag-postgres; DB assertions cannot run here")
    return True


# ── source-level guards (always run) ─────────────────────────────────────────

def test_both_asset_helpers_drop_hostname_equal_to_ip():
    """Both helpers must null a hostname that is just the IP.

    Two implementations exist (playwright_scanner has its own), so both need the
    guard or the one without it re-creates the duplicates.
    """
    for rel in ("etl/asset_utils.py", "playwright_scanner/db_utils.py"):
        path = os.path.join(REPO, rel)
        assert os.path.exists(path), rel
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        # Tolerant of .strip()/normalisation on either side — asset_utils.py
        # compares hostname.strip() == ip.strip().
        compares = re.search(r"hostname[^\n]*==[^\n]*\b(resolved_ip|ip)\b", src)
        nulls = re.search(r"hostname\s*=\s*None", src)
        assert compares and nulls, \
            f"{rel} does not drop a hostname equal to the ip"


def test_playwright_uses_url_hostname_not_netloc():
    """netloc keeps the port, so an IP target became "ip:8080" and fell through
    to the 0.0.0.0 placeholder asset."""
    path = os.path.join(REPO, "playwright_scanner", "playwright_scanner.py")
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    assert "get_or_create_asset(hostname, hostname=hostname)" not in src, \
        "the netloc-as-both-ip-and-hostname call is back"
    assert "parsed_url.hostname" in src, "should use .hostname, not .netloc"


def test_migration_is_in_both_install_scripts():
    """A migration in only one script means clean builds and upgrades diverge."""
    for rel in ("db_init/ensure_all_tables.sql", "db_init/setup_alldb.sql"):
        with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
            src = fh.read()
        assert "assets_hostname_not_ip" in src, f"{rel} missing the CHECK"
        assert "canonical_asset" in src, f"{rel} missing the normalization block"
        # ON COMMIT DROP only behaves inside an explicit transaction.
        assert "ON COMMIT DROP" in src and "BEGIN;" in src and "COMMIT;" in src, \
            f"{rel}: scratch tables need an explicit transaction"


def test_health_checks_assert_the_new_schema():
    """CLAUDE.md: new DB elements go into the health check scripts too."""
    with open(os.path.join(REPO, "scripts", "ensure_db_schema.sh"), encoding="utf-8") as fh:
        ensure = fh.read()
    assert "assets_hostname_not_ip" in ensure
    assert "duplicate (ip, proto, port)" in ensure
    with open(os.path.join(REPO, "scripts", "post-install-check.sh"), encoding="utf-8") as fh:
        post = fh.read()
    assert "assets_hostname_not_ip" in post


def test_cwe_is_passed_as_an_array():
    """web_findings.cwe is text[]; psycopg2 cannot adapt a bare string to it."""
    path = os.path.join(REPO, "playwright_scanner", "playwright_scanner.py")
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    assert "cwe_array" in src, "cwe is not normalized to a list"
    assert "zap_finding.get('cwe'), Json(" not in src, \
        "the raw scalar is still being passed for a text[] column"


# ── DB-backed guards (skip without a database) ────────────────────────────────

def test_check_constraint_exists(db):
    assert _psql(
        "SELECT count(*) FROM pg_constraint WHERE conname='assets_hostname_not_ip'"
    ) == "1", "CHECK assets_hostname_not_ip is missing"


def test_no_asset_stores_the_ip_as_hostname(db):
    assert _psql("SELECT count(*) FROM assets WHERE hostname = host(ip)") == "0"


def test_ports_have_no_ip_level_duplicates(db):
    """The invariant the normalization exists to establish."""
    total = _psql("SELECT count(*) FROM ports")
    distinct = _psql(
        "SELECT count(*) FROM (SELECT DISTINCT a.ip, p.proto, p.port "
        "FROM ports p JOIN assets a ON p.asset_id = a.id) d"
    )
    assert total is not None and distinct is not None
    assert int(total) == int(distinct), (
        f"{int(total) - int(distinct)} duplicate (ip, proto, port) port row(s); "
        "re-run scripts/ensure_db_schema.sh"
    )


def test_check_constraint_actually_rejects(db):
    """Sabotage the invariant against the live schema, inside a rollback."""
    out = subprocess.run(
        ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans", "-c",
         "BEGIN; INSERT INTO assets (ip, hostname) "
         "VALUES ('10.99.99.99'::inet, '10.99.99.99'); ROLLBACK;"],
        capture_output=True, text=True, timeout=30,
    )
    combined = out.stdout + out.stderr
    assert "assets_hostname_not_ip" in combined, (
        "inserting hostname == ip was NOT rejected; the CHECK is not enforcing.\n"
        f"{combined[:400]}"
    )


def test_no_orphaned_children_after_remap(db):
    """The migration repoints 16 child tables; none may be left dangling."""
    for table in ("ports", "vulns", "web_findings", "recon_findings",
                  "scan_recommendations", "port_observation"):
        orphans = _psql(
            f"SELECT count(*) FROM {table} t WHERE t.asset_id IS NOT NULL "
            f"AND NOT EXISTS (SELECT 1 FROM assets a WHERE a.id = t.asset_id)"
        )
        assert orphans == "0", f"{table} has {orphans} orphaned asset_id row(s)"
