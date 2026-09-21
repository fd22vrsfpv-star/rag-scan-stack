"""POST /credentials/spray-release runs the small default-cred spray, scope-gated.

The spray is the acceptable first credential step (knowledge/credential_spray_policy.yaml):
username-as-password + documented defaults against a host's open login services,
lockout-safe. This proves it previews the host's login services, and fails closed
without scope. Skips cleanly without a live rag-api + DB.

    TEST_RAG_API=https://localhost:8000 DB_DSN=... pytest tests/test_spray_release.py
"""
import os
import re
import uuid
import pathlib

import pytest
from conftest import RAG_API  # shared service endpoints (see tests/conftest.py)

requests = pytest.importorskip("requests")
psycopg2 = pytest.importorskip("psycopg2")

BASE = os.environ.get("RAG_API_URL") or RAG_API
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _key():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _conn():
    try:
        c = psycopg2.connect(DB_DSN, connect_timeout=5)
        c.autocommit = True
        return c
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")


def _post(body):
    try:
        return requests.post(f"{BASE}/credentials/spray-release", json=body,
                             headers={"x-api-key": _key()}, timeout=30, verify=False)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


@pytest.fixture
def scoped_login_host():
    conn = _conn()
    cur = conn.cursor()
    ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    name = f"pytest-spray-{uuid.uuid4().hex[:8]}"
    eid, aid = None, None
    try:
        r = requests.post(f"{BASE}/engagements",
                          json={"name": name, "engagement_type": "internal_pentest",
                                "methodology": "OWASP"},
                          headers={"x-api-key": _key()}, timeout=30, verify=False)
        if r.status_code in (401, 403):
            pytest.skip("auth required")
        assert r.status_code in (200, 201), f"create engagement: {r.status_code} {r.text[:200]}"
        eid = r.json()["id"]
        cur.execute("INSERT INTO scope_targets (engagement_id, name, target, target_type, source) "
                    "VALUES (%s::uuid,'default',%s,'ip','manual')", (eid, ip))
        cur.execute("INSERT INTO assets (ip, engagement_id) VALUES (%s::inet,%s::uuid) RETURNING id",
                    (ip, eid))
        aid = cur.fetchone()[0]
        # An open SSH port -> a login service to spray.
        cur.execute("INSERT INTO ports (asset_id, proto, port, service, is_open) "
                    "VALUES (%s,'tcp',22,'ssh',true)", (aid,))
        yield {"eid": eid, "ip": ip}
    finally:
        try:
            if aid:
                cur.execute("DELETE FROM assets WHERE id = %s", (aid,))
            if eid:
                cur.execute("DELETE FROM scope_targets WHERE engagement_id = %s::uuid", (eid,))
                cur.execute("DELETE FROM engagements WHERE id = %s::uuid", (eid,))
        except Exception:
            pass
        cur.close(); conn.close()


def test_dry_run_lists_the_login_services(scoped_login_host):
    r = _post({"target": scoped_login_host["ip"], "engagement_id": scoped_login_host["eid"],
               "dry_run": True})
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, f"{r.status_code}: {r.text[:200]}"
    d = r.json()
    assert d.get("would_spray", 0) >= 1, f"login service not seen: {d}"
    assert 22 in (d.get("ports") or []), "the open ssh port should be a spray target"


def test_fails_closed_without_scope(scoped_login_host):
    conn = _conn()
    conn.cursor().execute("DELETE FROM scope_targets WHERE engagement_id = %s::uuid",
                          (scoped_login_host["eid"],))
    conn.close()
    r = _post({"target": scoped_login_host["ip"], "engagement_id": scoped_login_host["eid"],
               "dry_run": True})
    if r.status_code in (401, 403) and "scope" not in r.text.lower():
        pytest.skip("auth required")
    # No scope -> 409 fail-closed (or 403 refused). Never a 200 spray.
    assert r.status_code in (403, 409), f"expected fail-closed, got {r.status_code}: {r.text[:200]}"
