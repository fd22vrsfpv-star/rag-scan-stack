"""Web-session credential types are first-class in the vault, so a portable web
Auth Profile's session material (cookie / bearer / token / api_key) can be stored
and read back by /export/proxy-replay and the ZAP/Burp auth bridge.

WHY THIS EXISTS
---------------
/export/proxy-replay Phase 3 injects Cookie/Authorization/X-API-Key headers by
selecting `credential_vault WHERE status='valid' AND credential_type IN
('cookie','token','api_key','bearer')`. That matched ZERO rows on two counts:
credential_vault has no 'valid' status (its lifecycle is active/cracking/...),
and those web-session types were never in the credential_type CHECK. This locks
in both fixes plus the bridge mapping, so the injection path can actually work.

SABOTAGE PROOF
--------------
Drop a web-session type from the CHECK migration and
test_vault_check_admits_web_session_types fails. Put 'valid' back in the
proxy-replay query and test_proxy_replay_uses_active_status fails. Remove a
bridge mapping and test_bridge_maps_web_session_types fails.

Run on demand:

    pytest tests/test_web_session_vault_types.py -v
"""
import os
import re
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

WEB_SESSION_TYPES = ("cookie", "bearer", "token", "api_key")


def _read(rel):
    p = os.path.join(REPO, rel)
    if not os.path.exists(p):
        pytest.skip(f"{rel} not present")
    return open(p, encoding="utf-8").read()


def test_bridge_maps_web_session_types():
    from etl import credential_bridge as cb
    for t in WEB_SESSION_TYPES:
        assert cb._SECRET_TYPE_TO_VAULT.get(t) == t, (
            f"credential_bridge must map web-session type {t!r} to itself")


def test_vault_check_admits_web_session_types():
    sql = _read("db_init/ensure_all_tables.sql")
    # find the authoritative migration (DROP then ADD credential_type CHECK)
    m = re.search(r"ADD CONSTRAINT credential_vault_credential_type_check\s+CHECK \([^;]*\)",
                  sql, re.S)
    assert m, "credential_vault credential_type CHECK migration not found"
    block = m.group(0)
    for t in WEB_SESSION_TYPES:
        assert f"'{t}'" in block, f"CHECK migration missing web-session type {t!r}"


def test_proxy_replay_uses_active_status():
    src = _read("app/rag-api/api.py")
    # the Phase-3 query that reads web-session creds must use status='active'
    m = re.search(r"FROM credential_vault\s+WHERE status = '(\w+)' AND credential_type IN "
                  r"\('cookie', 'token', 'api_key', 'bearer'\)", src)
    assert m, "proxy-replay web-session credential query not found (shape changed?)"
    assert m.group(1) == "active", (
        f"proxy-replay must select status='active', not {m.group(1)!r} "
        "(credential_vault has no 'valid' status)")


def test_live_vault_admits_cookie_type():
    """If a DB is reachable, prove the live CHECK admits a 'cookie' row (rolled back)."""
    psycopg2 = pytest.importorskip("psycopg2")
    dsn = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
    try:
        conn = psycopg2.connect(dsn, connect_timeout=5)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")
    try:
        cur = conn.cursor()
        cur.execute("SELECT to_regclass('public.credential_vault')")
        if not cur.fetchone()[0]:
            pytest.skip("credential_vault absent")
        # insert then roll back — proves the CHECK admits it without persisting
        cur.execute(
            "INSERT INTO public.credential_vault (username, credential_type, "
            "credential_value, source, status) VALUES "
            "('__test__','cookie','sid=abc','test','active')")
        conn.rollback()
    finally:
        conn.close()
