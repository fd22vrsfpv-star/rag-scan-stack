"""The software inventory must list a product once per host, not once per scan.

`detected_software` is a UNION ALL over `ports`, `recon_findings` and
`web_findings`. The latter two get a NEW ROW PER SCAN — httpx, gowitness, ZAP
and whatweb each append on every run against the same host — so the view
repeated the same software once per run. Measured 2026-10-14:

    detected_software rows: 15407   distinct software: 11268
    redundant copies:        4139   (27% of the view)

    n=778  Apache         zap    server_header   172.18.0.36
    n=709  Apache-Coyote  zap    server_header   65.61.137.117
    n=207  Amazon CloudFront / HSTS / AWS  httpx tech_detection 20.49.104.29

Every consumer inherited it. The operator reported it as "the asset software
CVEs are not deduplicated — they show copies from each test run": each listed
product drives its own CVE lookup, so a product listed 778 times rendered its
CVE block 778 times. The CVE tables themselves were clean — `vulns` had 0
duplicate (asset_id, port_id, cve) groups and 0 NULL fingerprints. The
INVENTORY feeding the lookup was 27% copies.

The fix wraps the UNION ALL in a GROUP BY with `min(first_seen)` /
`max(last_seen)`, so the per-run rows become the evidence for a first/last-seen
RANGE instead of N listings. `DISTINCT` would have collapsed them too, but by
keeping an arbitrary row's timestamps.

Three definitions of this view existed. `scripts/optional/create_software_view.py`
carried a stale copy — 10 source branches against the schema file's 15, and no
dedup — so running it would have reverted the fix AND dropped five sources of
detection. It now extracts the statement from `db_init/ensure_all_tables.sql`
and holds no SQL of its own. (`app/rag-api/health_router.py` is guarded by
`IF NOT EXISTS` and only builds a minimal nmap-only view on a fresh install.)

Sabotage check: delete the GROUP BY from the schema file and
`test_the_view_deduplicates` fails; paste a `CREATE OR REPLACE VIEW` back into
the optional script and `test_only_one_definition_carries_sql` fails by path.

    pytest tests/test_detected_software_dedup.py -q
"""

import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCHEMA = REPO / "db_init" / "ensure_all_tables.sql"
OPTIONAL = REPO / "scripts" / "optional" / "create_software_view.py"
HEAD = "CREATE OR REPLACE VIEW public.detected_software AS"

GROUP_KEY = ["asset_id", "ip", "hostname", "port", "protocol",
             "product", "version", "source", "detection_type"]


def _view_sql() -> str:
    if not SCHEMA.exists():
        pytest.skip("ensure_all_tables.sql not found")
    text = SCHEMA.read_text(encoding="utf-8")
    start = text.find(HEAD)
    if start < 0:
        pytest.fail(f"{SCHEMA.name} no longer declares detected_software")
    rest = text[start:]
    depth = 0
    for m in re.finditer(r"\$\$|;", rest):
        if m.group(0) == "$$":
            depth ^= 1
        elif depth == 0:
            return rest[:m.end()]
    pytest.fail("the view statement is not terminated")


def _sql_no_comments() -> str:
    """The statement with `--` comments stripped.

    The wrapper's own explanatory comment contains the words "GROUP BY", so a
    naive search passes while the real clause is gone — the guard would be
    mistaken for coverage, which CLAUDE.md calls worse than having none.
    """
    body = "\n".join(re.sub(r"--.*$", "", l) for l in _view_sql().splitlines())
    return " ".join(body.split())


def test_the_view_deduplicates():
    sql = _sql_no_comments()
    assert re.search(r"\bGROUP\s+BY\b", sql, re.I), (
        "detected_software has no GROUP BY. Its UNION ALL branches read "
        "recon_findings and web_findings, which gain a row per scan run, so "
        "the same software is listed once per run — 15,407 rows for 11,268 "
        "distinct products when this was measured")


def test_the_group_key_is_the_whole_identity():
    """A key missing a column silently merges different software."""
    sql = _sql_no_comments()
    m = re.search(r"GROUP\s+BY\s+(.+?);\s*$", sql, re.I)
    assert m, "GROUP BY clause not found at the end of the statement"
    key = {c.strip() for c in m.group(1).split(",")}
    missing = [c for c in GROUP_KEY if c not in key]
    assert not missing, (
        f"the GROUP BY key omits {missing}. Dropping a column from the key "
        "merges rows that are genuinely different software — `version` in "
        "particular: 172.18.0.36 legitimately carries Apache 2.4.68 (Debian) "
        "and 2.4.52 (Ubuntu) on different asset rows")
    extra = key - set(GROUP_KEY)
    assert not extra, f"unexpected columns in the GROUP BY key: {sorted(extra)}"


def test_timestamps_are_aggregated_as_a_range():
    """min/max, not an arbitrary row's values."""
    sql = _sql_no_comments()
    assert re.search(r"min\(\s*first_seen\s*\)", sql, re.I), (
        "first_seen is not min()-aggregated, so the EARLIEST sighting is lost")
    assert re.search(r"max\(\s*last_seen\s*\)", sql, re.I), (
        "last_seen is not max()-aggregated, so the LATEST sighting is lost")


def test_the_union_branches_survived_the_wrapper():
    """A dedup that also drops sources is not a fix."""
    sql = _view_sql()
    branches = sql.count("UNION ALL") + 1
    assert branches >= 15, (
        f"the view has {branches} source branches; it had 15+ before the "
        "dedup wrapper. Wrapping must not drop detection sources")
    for src in ("ports", "recon_findings", "web_findings"):
        assert src in sql, f"the {src} branch is gone"


def test_only_one_definition_carries_sql():
    """The stale second copy is how the fix would get reverted."""
    if not OPTIONAL.exists():
        pytest.skip("optional script not present")
    src = OPTIONAL.read_text(encoding="utf-8")
    # An embedded DEFINITION, not a mention. The script legitimately counts
    # "UNION ALL" in the SQL it extracts, so a substring search over the file
    # flags its own bookkeeping — look for a string literal that is itself a
    # view definition.
    import ast as _ast
    for node in _ast.walk(_ast.parse(src)):
        if isinstance(node, _ast.Constant) and isinstance(node.value, str):
            v = node.value
            if "VIEW public.detected_software" in v and "UNION ALL" in v:
                pytest.fail(
                    f"{OPTIONAL.relative_to(REPO)}:{node.lineno} carries its "
                    "own copy of the view SQL again. The last one had 10 "
                    "source branches against the schema file's 15 and no "
                    "dedup, so running it would have reverted the fix and "
                    "dropped five sources. Extract from db_init instead")
    assert "ensure_all_tables.sql" in src, (
        f"{OPTIONAL.relative_to(REPO)} does not read the canonical schema file")


def test_health_router_cannot_overwrite_the_real_view():
    """Its fresh-install fallback must stay guarded."""
    hr = REPO / "app" / "rag-api" / "health_router.py"
    if not hr.exists():
        pytest.skip("health_router.py not found")
    src = hr.read_text(encoding="utf-8")
    i = src.find("CREATE VIEW public.detected_software")
    if i < 0:
        return  # the fallback was removed entirely — also fine
    window = src[max(0, i - 400):i]
    assert "IF NOT EXISTS" in window and "pg_views" in window, (
        "health_router.py creates detected_software without the "
        "`IF NOT EXISTS (SELECT 1 FROM pg_views ...)` guard, so a schema "
        "repair would replace the full 15-source deduplicated view with its "
        "minimal nmap-only fallback")


def test_no_duplicates_live():
    """Executes against the database. Skips when there is none."""
    dsn = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("DB_DSN not set — no database to query")
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        conn = psycopg2.connect(dsn, connect_timeout=5)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_views WHERE viewname='detected_software'")
            if not cur.fetchone():
                pytest.skip("detected_software view not present")
            cur.execute(
                "SELECT count(*) FROM (SELECT " + ", ".join(GROUP_KEY) +
                " FROM detected_software GROUP BY " +
                ", ".join(str(i + 1) for i in range(len(GROUP_KEY))) +
                " HAVING count(*) > 1) x")
            dupes = cur.fetchone()[0]
        assert dupes == 0, (
            f"{dupes} duplicate groups in detected_software — the view is "
            "listing the same software once per scan run again")
    finally:
        conn.close()
