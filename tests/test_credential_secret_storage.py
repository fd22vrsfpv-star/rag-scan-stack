"""The recovered password is stored, so follow-on attacks can use it.

Run on demand:

    pytest tests/test_credential_secret_storage.py -v

WHY THIS EXISTS
---------------
`credential_findings` recorded WHICH accounts were valid and threw the password
away — `parse_brutus` carried the comment "Insert - do NOT store password" and
only masked copies survived, in `metadata.audit`. An account name with no secret
is not usable for the lateral movement the credential-testing phase exists to
enable, so the operator chose to store it in plaintext.

THREE THINGS HAD TO CHANGE, and any one of them alone stores nothing:

  1. `nmap_scanner/nmap-api.py` built the ingest JSONL WITHOUT the password —
     it logged the plaintext one screen earlier and then dropped it. A parser
     fix alone would have had nothing to read.
  2. `parse_brutus` needed somewhere to put it (`secret_value`).
  3. `trg_credential_findings_dedup` is a BEFORE INSERT trigger that updates the
     existing row and RETURNs NULL, cancelling the statement — so the parser's
     own `ON CONFLICT DO UPDATE` is UNREACHABLE and an INSERT of a known
     credential reports "INSERT 0 0". Re-ingesting a credential you already know
     could therefore never attach a newly recovered password. The trigger had to
     learn the column.

An empty password is a REAL finding (anonymous FTP), so '' and NULL mean
different things throughout: '' is "no password required", NULL is "not
captured". Nothing may collapse them.
"""
import json
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))


def _in_container(script):
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


@pytest.fixture(scope="module")
def db():
    if _psql("SELECT 1") != "1":
        pytest.skip("no reachable rag-postgres")
    return True


# ── source-level ────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_the_parser_stores_the_password():
    src = open(os.path.join(REPO, "etl", "parse_brutus.py"), encoding="utf-8").read()
    assert 'secret_value = rec.get("password")' in src, \
        "parse_brutus no longer reads the password off the record"
    insert = src.split("INSERT INTO credential_findings", 1)[1].split('"""', 1)[0]
    assert "secret_value" in insert, "secret_value is not in the insert column list"


@pytest.mark.unit
def test_the_producer_emits_the_password():
    """The JSONL writer dropped it, so a parser fix alone stored nothing."""
    src = open(os.path.join(REPO, "nmap_scanner", "nmap-api.py"), encoding="utf-8").read()
    block = src.split('"protocol": service,', 1)[1][:600]
    assert '"password"' in block, (
        "the credential-check JSONL no longer carries the password; parse_brutus "
        "will store NULL no matter what it does")


@pytest.mark.unit
def test_the_dedup_trigger_carries_a_newly_recovered_secret():
    """The trigger RETURNs NULL, so it is the ONLY path onto an existing row."""
    for rel in ("db_init/ensure_all_tables.sql", "db_init/setup_alldb.sql"):
        src = open(os.path.join(REPO, rel), encoding="utf-8").read()
        fn = src.split("FUNCTION public.credential_findings_dedup()", 1)[1]
        fn = fn.split("$fn$", 2)[1] if "$fn$" in fn else fn[:3000]
        assert "secret_value" in fn, (
            f"{rel}: the dedup trigger does not carry secret_value, so "
            "re-ingesting a known credential discards the recovered password")
        assert "COALESCE(NEW.secret_value, secret_value)" in fn, (
            f"{rel}: secret_value is assigned rather than COALESCEd — a run that "
            "did not recover the password would erase one already stored")


@pytest.mark.unit
def test_an_empty_password_is_not_treated_as_absent():
    """anonymous FTP has a real, empty password. '' != NULL."""
    src = open(os.path.join(REPO, "etl", "parse_brutus.py"), encoding="utf-8").read()
    blk = src.split('secret_value = rec.get("password")', 1)[1][:500]
    assert "is not None" in blk, (
        "the parser tests truthiness rather than None, which turns an empty "
        "password into 'not captured'")


@pytest.mark.unit
def test_the_plaintext_caution_is_recorded_at_the_schema():
    """The operator accepted plaintext; the consequence belongs next to it."""
    src = open(os.path.join(REPO, "db_init", "ensure_all_tables.sql"),
               encoding="utf-8").read()
    blk = src.split("secret_value", 1)[0][-2000:]
    assert "CAUTION" in blk and "PLAINTEXT" in blk.upper(), \
        "the plaintext caution next to secret_value is gone"
    assert "/export/data" in blk, (
        "the caution no longer states that exports carry these passwords — that "
        "is the surprising part")


@pytest.mark.unit
def test_the_masked_audit_stays_masked():
    """metadata.audit lists every password TRIED, most belonging to no account.

    Unmasking a wordlist buys nothing and widens what a shipped log leaks.
    """
    src = open(os.path.join(REPO, "nmap_scanner", "cred_checker.py"),
               encoding="utf-8").read()
    assert "_mask_password" in src, "the audit masking helper is gone"
    assert "password_masked" in src, "the audit no longer stores masked passwords"


# ── executed ────────────────────────────────────────────────────────────────

def test_a_recovered_password_reaches_the_row_and_the_vault(db):
    """The whole point, end to end, on a documentation-range host."""
    out = _in_container(
        "import sys, os, json, tempfile, psycopg2\n"
        "sys.path.insert(0, '/app')\n"
        "from etl.parse_brutus import parse_brutus\n"
        "from etl.credential_bridge import bridge_credential_findings\n"
        "from psycopg2.extras import RealDictCursor\n"
        "IP = '203.0.113.90'\n"
        "conn = psycopg2.connect(os.environ['DB_DSN'])\n"
        "cur = conn.cursor(cursor_factory=RealDictCursor)\n"
        "def clean():\n"
        "    cur.execute('DELETE FROM credential_findings WHERE host(ip)=%s', (IP,))\n"
        "    cur.execute('DELETE FROM credential_vault WHERE domain=%s', (IP,))\n"
        "    cur.execute(\"DELETE FROM identities WHERE domain=%s AND provider='local'\", (IP,))\n"
        "    conn.commit()\n"
        "clean()\n"
        "recs = [{'host': IP, 'port': 21, 'protocol': 'ftp',\n"
        "         'username': 'secret-probe', 'password': 'hunter2', 'success': True},\n"
        "        {'host': IP, 'port': 23, 'protocol': 'telnet',\n"
        "         'username': 'empty-probe', 'password': '', 'success': True}]\n"
        "fh = tempfile.NamedTemporaryFile('w', suffix='.jsonl', delete=False)\n"
        "fh.write('\\n'.join(json.dumps(r) for r in recs) + '\\n'); fh.close()\n"
        "parse_brutus(fh.name, profile='test')\n"
        "# and AGAIN with no password, to prove a re-verification cannot erase it\n"
        "fh2 = tempfile.NamedTemporaryFile('w', suffix='.jsonl', delete=False)\n"
        "fh2.write(json.dumps({'host': IP, 'port': 21, 'protocol': 'ftp',\n"
        "                      'username': 'secret-probe', 'success': True}) + '\\n')\n"
        "fh2.close()\n"
        "parse_brutus(fh2.name, profile='test')\n"
        "bridge_credential_findings(cur, dry_run=False, sources=['brutus'])\n"
        "conn.commit()\n"
        "cur.execute('SELECT username, secret_value FROM credential_findings '\n"
        "            'WHERE host(ip)=%s ORDER BY username', (IP,))\n"
        "rows = {r['username']: r['secret_value'] for r in cur.fetchall()}\n"
        "cur.execute('SELECT username, credential_value FROM credential_vault '\n"
        "            'WHERE domain=%s ORDER BY username', (IP,))\n"
        "vault = {r['username']: r['credential_value'] for r in cur.fetchall()}\n"
        "clean(); os.unlink(fh.name); os.unlink(fh2.name)\n"
        "print('RESULT', json.dumps({'rows': rows, 'vault': vault}))\n")
    assert out, "probe failed to run"
    payload = json.loads([l for l in out.splitlines()
                          if l.startswith("RESULT")][-1][len("RESULT "):])
    rows, vault = payload["rows"], payload["vault"]
    assert rows.get("secret-probe") == "hunter2", (
        f"the recovered password did not reach the row: {rows!r} — note the "
        "second ingest carried no password and must not have erased it")
    assert rows.get("empty-probe") == "", (
        f"an empty password was not preserved as '': {rows!r} — anonymous FTP "
        "is a real finding, and '' must not collapse to NULL")
    assert vault.get("secret-probe") == "hunter2", (
        f"the secret did not reach credential_vault.credential_value: {vault!r}")


def test_the_real_engagement_credential_is_usable(db):
    """Not a mechanism check: msfadmin's actual password must be readable."""
    got = _psql("""SELECT secret_value FROM credential_findings
                    WHERE username = 'msfadmin' AND port = 21""")
    assert got, "no msfadmin credential on port 21 to check"
    assert got.strip(), (
        "msfadmin's password is still empty — the credential is recorded but "
        "cannot be used for anything")
