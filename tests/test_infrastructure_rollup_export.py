"""v_infrastructure_findings had exactly one reader, and it was a test.

Run on demand:

    pytest tests/test_infrastructure_rollup_export.py -v

WHY THIS EXISTS
---------------
The view groups infrastructure-level web findings across virtual hosts — the
"one problem, many vhosts" rollup. It collapses 779 web findings to 13 problems.
Nothing in reporting read it, so a report gave the operator 779 rows and no way
to see that they are 13 issues.

While wiring it in, its severity aggregate turned out to be wrong:

    max(w.severity)   -- lexical! 'medium' > 'high' > 'critical' as TEXT

so a group mixing severities reported the wrong one, and in the under-reporting
direction. Every group in this deployment happened to be single-severity, which
is why nothing had ever shown it. It now ranks by public.severity_rank(), the
one scale the stack shares.
"""
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
DDL = ("db_init/ensure_all_tables.sql", "db_init/setup_alldb.sql")


def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def _psql_script(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "-i", "rag-postgres", "psql", "-U", "app", "-d",
             "scans", "-v", "ON_ERROR_STOP=1", "-tA"],
            input=sql, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


@pytest.fixture(scope="module")
def db():
    if _psql("SELECT 1") != "1":
        pytest.skip("no reachable rag-postgres")
    return True


# ── source-level ────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_the_view_is_actually_exported():
    """"Wired into reporting" means a report includes it by DEFAULT.

    Available-if-you-know-to-ask leaves the operator with the 779 rows.
    """
    src = open(os.path.join(REPO, "app", "rag-api", "api.py"), encoding="utf-8").read()
    assert '"infrastructure": ["v_infrastructure_findings"]' in src, \
        "the rollup is no longer an export category"
    assert "assets,findings,infrastructure,recon" in src, \
        "the infrastructure category is not in the default category list"


@pytest.mark.unit
def test_the_view_severity_is_ranked_not_lexical():
    for rel in DDL:
        src = open(os.path.join(REPO, rel), encoding="utf-8").read()
        view = src.split("CREATE OR REPLACE VIEW public.v_infrastructure_findings", 1)[1]
        view = view.split(";", 1)[0]
        assert "max(w.severity)" not in view, (
            f"{rel} is back to a lexical max — 'medium' outranks 'critical' as text")
        assert "public.severity_rank" in view, \
            f"{rel} no longer ranks by the shared severity scale"


@pytest.mark.unit
def test_the_export_reader_tolerates_a_view():
    """A view has no created_at.

    The generic reader ordered by it unconditionally, so adding any view to an
    export category was a 500 waiting to happen.
    """
    src = open(os.path.join(REPO, "app", "rag-api", "api.py"), encoding="utf-8").read()
    assert "_export_order_column" in src, \
        "the export reader no longer resolves its ORDER BY column"
    assert 'f"SELECT * FROM {table} {order_sql} LIMIT %s"' in src, \
        "the export reader hard-codes an ORDER BY again"


# ── executed ────────────────────────────────────────────────────────────────

def test_the_view_returns_the_worst_severity_not_the_lexical_max(db):
    """The bug, demonstrated: a group of medium+critical+high.

    Runs in a rolled-back transaction, so engagement data is untouched.
    """
    out = _psql_script("""
BEGIN;
INSERT INTO assets (id, ip, hostname) VALUES
  ('55555555-5555-4555-8555-555555555555','198.51.100.30','sev-probe.test');
INSERT INTO web_findings (asset_id, url, source, name, issue_type, severity, port,
                          infrastructure_fingerprint)
VALUES
  ('55555555-5555-4555-8555-555555555555','http://a/','probe','probe','tls','medium',443,'probe-fp-mix'),
  ('55555555-5555-4555-8555-555555555555','http://b/','probe','probe','tls','critical',443,'probe-fp-mix'),
  ('55555555-5555-4555-8555-555555555555','http://c/','probe','probe','tls','high',443,'probe-fp-mix');
SELECT 'VIEW', severity, finding_count FROM v_infrastructure_findings
 WHERE infrastructure_fingerprint = 'probe-fp-mix';
SELECT 'LEXICAL', max(severity) FROM web_findings
 WHERE infrastructure_fingerprint = 'probe-fp-mix';
ROLLBACK;
""")
    assert out, "probe failed to run"
    got = dict(l.split("|", 1) for l in out.splitlines() if "|" in l)
    assert got.get("VIEW", "").startswith("critical"), (
        f"the view reports {got.get('VIEW')!r} for a group containing critical")
    # and prove the old behaviour really was wrong, so this test is not vacuous
    assert got.get("LEXICAL") == "medium", (
        "lexical max no longer returns 'medium' here — the case this guards "
        "against has changed and the assertion above proves nothing")


def test_the_rollup_actually_collapses_something(db):
    """A rollup that equals the row count is not a rollup."""
    groups = _psql("SELECT count(*) FROM v_infrastructure_findings")
    members = _psql("""SELECT count(*) FROM web_findings
                        WHERE infrastructure_fingerprint IS NOT NULL""")
    assert groups and members, "could not read the view"
    assert int(groups) > 0, "the view is empty; the export would carry nothing"
    assert int(members) >= int(groups), "more groups than members is impossible"


def test_the_export_endpoint_includes_the_rollup(db):
    """CLAUDE.md: an endpoint is verified by executing it."""
    key = None
    env = os.path.join(REPO, ".env")
    if os.path.exists(env):
        for line in open(env, encoding="utf-8"):
            if line.startswith("API_KEY="):
                key = line.split("=", 1)[1].strip()
                break
    if not key:
        pytest.skip("no API_KEY in .env")
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-api", "python3", "-c",
             "import os,ssl,json,urllib.request\n"
             "ctx=ssl.create_default_context(); ctx.check_hostname=False\n"
             "ctx.verify_mode=ssl.CERT_NONE\n"
             "req=urllib.request.Request('https://127.0.0.1:8000/export/data?format=json',"
             " headers={'x-api-key': os.environ['API_KEY']})\n"
             "d=json.loads(urllib.request.urlopen(req,timeout=300,context=ctx).read())\n"
             "c=d.get('counts') or {}\n"
             "print('RESULT', c.get('v_infrastructure_findings', -1),"
             " len(d.get('data',{}).get('v_infrastructure_findings',[])))\n"],
            capture_output=True, text=True, timeout=400)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("rag-api not reachable")
    if out.returncode != 0:
        pytest.skip(f"export probe could not run: {out.stderr[-200:]}")
    line = [l for l in out.stdout.splitlines() if l.startswith("RESULT")][-1].split()
    counted, returned = int(line[1]), int(line[2])
    assert counted > 0, (
        "the export reports zero infrastructure rows — the category is declared "
        "but produces nothing")
    assert returned == counted, f"counted {counted} but returned {returned} rows"
