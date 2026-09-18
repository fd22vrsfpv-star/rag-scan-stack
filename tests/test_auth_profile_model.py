"""Auth Profile: web_auth_configs generalized into one portable, tool-agnostic
auth model — credential_id (resolve secret at scan time, no plaintext) + session
(reusable cookies/headers), engagement-scoped resolution.

Guards the model without importing the heavy playwright-scanner service:
source-level checks on the resolver/endpoint, plus a live-DB check that the new
schema admits credential-only and session-only profiles (rolled back).

SABOTAGE PROOF
--------------
Drop the engagement filter from _resolve_web_auth and
test_resolver_is_engagement_scoped fails; let /web-auth store a plaintext
password alongside a credential_id and test_no_plaintext_with_credential_id fails.

Run:  DB_DSN=... pytest tests/test_auth_profile_model.py -v
"""
import os
import re

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PS = os.path.join(REPO, "playwright_scanner", "playwright_scanner.py")
SQL = os.path.join(REPO, "db_init", "ensure_all_tables.sql")


def _read(p):
    if not os.path.exists(p):
        pytest.skip(f"{p} missing")
    return open(p, encoding="utf-8").read()


def test_schema_adds_credential_id_and_session():
    sql = _read(SQL)
    assert "ADD COLUMN IF NOT EXISTS credential_id uuid" in sql
    assert "ADD COLUMN IF NOT EXISTS session jsonb" in sql
    assert "ux_web_auth_configs_eng_host" in sql
    # per-(engagement,host) uniqueness must COALESCE the nullable engagement_id
    assert re.search(r"ux_web_auth_configs_eng_host[\s\S]*COALESCE\(engagement_id", sql)


def test_resolver_is_engagement_scoped():
    src = _read(PS)
    m = re.search(r"def _resolve_web_auth\(url: str, engagement_id[\s\S]*?(?=\n@app|\ndef |\Z)", src)
    assert m, "_resolve_web_auth not found / signature changed"
    body = m.group(0)
    # never applies another engagement's profile
    assert "engagement_id IS NULL" in body and "engagement_id = %s::uuid" in body
    # resolves the secret from credential_findings at scan time
    assert "FROM credential_findings" in body and "secret_value" in body
    assert "session" in body


def test_no_plaintext_with_credential_id():
    src = _read(PS)
    m = re.search(r"async def set_web_auth\([\s\S]*?\n@app\.", src)
    assert m, "set_web_auth endpoint not found"
    body = m.group(0)
    # requires host + one-of macro/credential/session
    assert "at least one of" in body
    # a credential_id means no plaintext password is stored
    assert "None if has_cred else body.get(\"password\")" in body


def test_live_schema_admits_credential_and_session_only_profiles():
    psycopg2 = pytest.importorskip("psycopg2")
    dsn = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
    try:
        conn = psycopg2.connect(dsn, connect_timeout=5)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")
    try:
        cur = conn.cursor()
        cur.execute("SELECT to_regclass('public.web_auth_configs')")
        if not cur.fetchone()[0]:
            pytest.skip("web_auth_configs absent")
        # apply the migration + insert profiles with NO login macro, then roll back
        cur.execute("""
            ALTER TABLE web_auth_configs ADD COLUMN IF NOT EXISTS credential_id uuid;
            ALTER TABLE web_auth_configs ADD COLUMN IF NOT EXISTS session jsonb DEFAULT '{}'::jsonb;
            ALTER TABLE web_auth_configs ALTER COLUMN login_url DROP NOT NULL;
            ALTER TABLE web_auth_configs ALTER COLUMN login_data DROP NOT NULL;
            ALTER TABLE web_auth_configs ALTER COLUMN username DROP NOT NULL;
            INSERT INTO web_auth_configs (host, session) VALUES ('t.example', '{"cookies":[]}'::jsonb);
        """)
        conn.rollback()
    finally:
        conn.close()
