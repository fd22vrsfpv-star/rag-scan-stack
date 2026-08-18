"""Dedup enforcement in the database — indexes, triggers and upserts.

Everything here was originally verified with one-off psql probes that were
thrown away. These are the same checks, saved so they can be re-run on demand:

    pytest tests/test_db_dedup_integration.py

They need a live rag-postgres. When one is not reachable the whole module skips
rather than failing, so a laptop run of the unit suite stays green.

Why these matter: the fingerprint columns and helpers existed for a long time
while nothing enforced them — vulns held 369 rows for 34 distinct findings and
katana wrote 32,218 rows for 630. Every guard below is the thing that stops that
returning.
"""
import os
import uuid

import pytest

psycopg2 = pytest.importorskip("psycopg2")

DSN = os.environ.get(
    "TEST_DB_DSN",
    os.environ.get("DB_DSN", "postgresql://app:app@localhost:5433/scans"),
)


@pytest.fixture(scope="module")
def conn():
    try:
        c = psycopg2.connect(DSN, connect_timeout=3)
    except Exception as e:                      # pragma: no cover
        pytest.skip(f"no database at {DSN}: {type(e).__name__}")
    c.autocommit = True
    yield c
    c.close()


@pytest.fixture
def cur(conn):
    with conn.cursor() as c:
        yield c


# ------------------------------------------------------------- schema guards

@pytest.mark.database
@pytest.mark.parametrize("index", [
    "uq_session_scan_metrics_session_job",   # persist_to_db upsert depends on it
    "uq_web_findings_fingerprint",
    "uq_vulns_fingerprint",
    "uq_credential_findings_identity",
    "uq_recon_findings_fingerprint",
])
def test_required_unique_index_exists(cur, index):
    """The parsers issue ON CONFLICT against these. Without the index the
    statement does not silently no-op — it RAISES, which is how
    parse_tool_output was failing on every insert before the index existed."""
    cur.execute("SELECT 1 FROM pg_indexes WHERE indexname = %s", (index,))
    assert cur.fetchone(), f"missing unique index {index}"


@pytest.mark.database
@pytest.mark.parametrize("trigger", [
    "trg_web_findings_dedup", "trg_vulns_dedup", "trg_recon_findings_dedup",
])
def test_dedup_trigger_installed(cur, trigger):
    cur.execute(
        "SELECT 1 FROM pg_trigger WHERE tgname = %s AND NOT tgisinternal",
        (trigger,),
    )
    assert cur.fetchone(), f"missing trigger {trigger}"


# ------------------------------------------------------------ actual dedup

@pytest.mark.database
def test_web_findings_insert_is_idempotent_without_a_fingerprint(cur):
    """~26 insert sites across 6 services write this table and only ZAP computed
    a fingerprint. The trigger fills it, so a writer that omits one still
    deduplicates instead of inserting a fresh row per scan."""
    url = f"http://192.168.1.150/probe-{uuid.uuid4().hex[:8]}"
    try:
        for i in range(3):
            cur.execute(
                """INSERT INTO web_findings (id, url, source, issue_type, name,
                                             severity, evidence)
                   VALUES (gen_random_uuid(), %s, 'pytest', 'probe', 'probe',
                           'info', %s)""",
                (url, f"run-{i}"),
            )
        cur.execute(
            "SELECT count(*), max(evidence), bool_and(fingerprint IS NOT NULL)"
            "  FROM web_findings WHERE url = %s", (url,))
        rows, evidence, fp_set = cur.fetchone()
        assert rows == 1, f"3 inserts produced {rows} rows"
        assert evidence == "run-2", "the newest observation should win"
        assert fp_set, "trigger did not populate the fingerprint"
    finally:
        cur.execute("DELETE FROM web_findings WHERE url = %s", (url,))


@pytest.mark.database
def test_recon_findings_dedup_keys_on_data_not_only_target(cur):
    """gowitness writes one row per screenshot but puts the HOST in `target`, so
    563 of its rows shared a target and differed only in `data`. Keying on
    (source, finding_type, target) would have collapsed 575 rows to 5."""
    tag = uuid.uuid4().hex[:8]
    try:
        for payload in ('{"u":"/a"}', '{"u":"/a"}', '{"u":"/b"}'):
            cur.execute(
                """INSERT INTO recon_findings (id, source, finding_type, target,
                                               data, severity)
                   VALUES (gen_random_uuid(), %s, 'probe', '192.168.1.150',
                           %s::jsonb, 'info')""",
                (f"pytest-{tag}", payload),
            )
        cur.execute("SELECT count(*) FROM recon_findings WHERE source = %s",
                    (f"pytest-{tag}",))
        assert cur.fetchone()[0] == 2, "distinct `data` must stay distinct"
    finally:
        cur.execute("DELETE FROM recon_findings WHERE source = %s",
                    (f"pytest-{tag}",))


@pytest.mark.database
def test_vulns_dedup_updates_instead_of_duplicating(cur):
    fp = f"pytest-{uuid.uuid4().hex}"
    try:
        for sev in ("low", "high"):
            cur.execute(
                """INSERT INTO vulns (id, script, output, severity, fingerprint)
                   VALUES (gen_random_uuid(), 'pytest', 'out', %s, %s)""",
                (sev, fp),
            )
        cur.execute("SELECT count(*), max(severity) FROM vulns WHERE fingerprint = %s",
                    (fp,))
        rows, sev = cur.fetchone()
        assert rows == 1 and sev == "high"
    finally:
        cur.execute("DELETE FROM vulns WHERE fingerprint = %s", (fp,))


@pytest.mark.database
def test_session_scan_metrics_upsert_corrects_a_running_scan(cur):
    """ON CONFLICT DO NOTHING against a table keyed only on id never fired, so a
    scan persisted while `running` could never be corrected once it finished —
    104 rows for 75 jobs, some stuck mid-flight."""
    sid, job = str(uuid.uuid4()), f"pytest-{uuid.uuid4().hex[:8]}"
    # target_description is NOT NULL on agent_sessions.
    cur.execute("INSERT INTO agent_sessions (id, session_name, target_description, status) "
                "VALUES (%s::uuid, 'pytest', 'pytest-probe', 'completed')", (sid,))
    try:
        cur.execute(
            """INSERT INTO session_scan_metrics (session_id, scan_type, job_id, status)
               VALUES (%s::uuid, 'pytest', %s, 'running')
               ON CONFLICT (session_id, job_id) DO UPDATE SET status = EXCLUDED.status""",
            (sid, job))
        cur.execute(
            """INSERT INTO session_scan_metrics (session_id, scan_type, job_id, status,
                                                 duration_seconds)
               VALUES (%s::uuid, 'pytest', %s, 'completed', 9.5)
               ON CONFLICT (session_id, job_id) DO UPDATE SET
                   status = EXCLUDED.status,
                   duration_seconds = COALESCE(EXCLUDED.duration_seconds,
                                               session_scan_metrics.duration_seconds)""",
            (sid, job))
        cur.execute("SELECT count(*), max(status) FROM session_scan_metrics "
                    " WHERE job_id = %s", (job,))
        rows, status = cur.fetchone()
        assert rows == 1 and status == "completed"
    finally:
        cur.execute("DELETE FROM session_scan_metrics WHERE job_id = %s", (job,))
        cur.execute("DELETE FROM agent_sessions WHERE id = %s::uuid", (sid,))


# ------------------------------- python/SQL fingerprint agreement

@pytest.mark.database
def test_trigger_fingerprint_matches_the_python_helper(cur):
    """The trigger fills fingerprints in SQL while parsers compute them in
    Python. If the two disagree, the same finding written by each path becomes
    two rows — the exact bug the dedup work exists to remove."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from etl.fingerprint import web_fingerprint

    url = f"http://192.168.1.150/agree-{uuid.uuid4().hex[:8]}"
    try:
        cur.execute(
            """INSERT INTO web_findings (id, url, source, issue_type, name, severity)
               VALUES (gen_random_uuid(), %s, 'pytest', 'probe', 'probe', 'info')""",
            (url,))
        cur.execute("SELECT fingerprint FROM web_findings WHERE url = %s", (url,))
        from_sql = cur.fetchone()[0]
        assert from_sql == web_fingerprint(url, "pytest", "probe", "probe")
    finally:
        cur.execute("DELETE FROM web_findings WHERE url = %s", (url,))
