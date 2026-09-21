"""Engagement data-purge and delete endpoints actually remove asset data.

The bug: deleting an engagement only archived it and nulled engagement_id on
assets, so a "deleted" engagement's hosts kept showing in the Assets browser.
These endpoints fix that:
  - POST /engagements/{id}/purge-data  -> wipe assets + their data, KEEP the engagement
  - DELETE /engagements/{id}?purge=true -> wipe data AND remove the engagement

This test creates a throwaway engagement + asset + port, then proves the asset is
gone after purge-data while the engagement survives, and that the full purge
removes the engagement. Skips cleanly without a live rag-api + DB.

    TEST_RAG_API=https://localhost:8000 DB_DSN=... pytest tests/test_engagement_purge.py
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
        return psycopg2.connect(DB_DSN, connect_timeout=5)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")


def _req(method, path, **kw):
    try:
        return requests.request(method, f"{BASE}{path}",
                                headers={"x-api-key": _key()}, timeout=30, verify=False, **kw)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


@pytest.fixture
def engagement_with_asset():
    """Create engagement + asset + port; yield ids; clean up whatever survives."""
    conn = _conn()
    conn.autocommit = True
    cur = conn.cursor()
    name = f"pytest-purge-{uuid.uuid4().hex[:8]}"
    eid = None
    ip = f"203.0.113.{uuid.uuid4().int % 250 + 1}"     # TEST-NET-3, never a real target
    try:
        r = _req("POST", "/engagements",
                 json={"name": name, "engagement_type": "web_app", "methodology": "OWASP"})
        if r.status_code in (401, 403):
            pytest.skip("auth required")
        assert r.status_code in (200, 201), f"create engagement: {r.status_code} {r.text[:200]}"
        eid = r.json()["id"]
        cur.execute("INSERT INTO assets (ip, engagement_id) VALUES (%s, %s::uuid) RETURNING id",
                    (ip, eid))
        aid = cur.fetchone()[0]
        cur.execute("INSERT INTO ports (asset_id, proto, port, service) VALUES (%s,'tcp',9,'discard')",
                    (aid,))
        yield {"eid": eid, "aid": aid, "ip": ip}
    finally:
        # Best-effort cleanup in case the test failed before its own deletes.
        try:
            cur.execute("DELETE FROM assets WHERE ip = %s", (ip,))
            if eid:
                cur.execute("DELETE FROM engagements WHERE id = %s::uuid", (eid,))
        except Exception:
            pass
        cur.close(); conn.close()


def _asset_count(eid):
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM assets WHERE engagement_id = %s::uuid", (eid,))
        return cur.fetchone()[0]
    finally:
        conn.close()


def _engagement_exists(eid):
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM engagements WHERE id = %s::uuid", (eid,))
        return cur.fetchone() is not None
    finally:
        conn.close()


def test_purge_data_removes_assets_but_keeps_engagement(engagement_with_asset):
    eid = engagement_with_asset["eid"]
    assert _asset_count(eid) == 1, "setup asset not present"

    dr = _req("POST", f"/engagements/{eid}/purge-data", params={"dry_run": "true"})
    assert dr.status_code == 200, f"dry run: {dr.status_code} {dr.text[:200]}"
    assert dr.json().get("assets", 0) >= 1, "dry run did not count the asset"
    assert _asset_count(eid) == 1, "dry run must not delete anything"

    res = _req("POST", f"/engagements/{eid}/purge-data")
    assert res.status_code == 200, f"purge: {res.status_code} {res.text[:200]}"
    body = res.json()
    assert body.get("kept_engagement") is True
    assert body.get("deleted", {}).get("assets", 0) >= 1

    assert _asset_count(eid) == 0, "asset survived purge-data"
    assert _engagement_exists(eid), "purge-data must KEEP the engagement"


def test_delete_purge_removes_the_engagement(engagement_with_asset):
    eid = engagement_with_asset["eid"]
    res = _req("DELETE", f"/engagements/{eid}", params={"purge": "true"})
    assert res.status_code == 200, f"delete purge: {res.status_code} {res.text[:200]}"
    assert res.json().get("action") == "purged"
    assert _asset_count(eid) == 0, "asset survived full purge"
    assert not _engagement_exists(eid), "full purge must remove the engagement"


def test_default_delete_only_archives(engagement_with_asset):
    eid = engagement_with_asset["eid"]
    res = _req("DELETE", f"/engagements/{eid}")
    assert res.status_code == 200, f"archive: {res.status_code} {res.text[:200]}"
    assert res.json().get("action") == "archived"
    assert _engagement_exists(eid), "archive must not delete the engagement"
    assert _asset_count(eid) == 1, "archive must not delete assets"


def test_purge_deletes_ip_keyed_findings_with_null_engagement():
    """The reported bug: cracked creds (credential_findings src=hashcat_crack) have a
    NULL engagement_id/asset_id — keyed only by ip — so an engagement-scoped purge
    missed them and they kept showing. purge-data must delete them by target IP."""
    conn = _conn(); conn.autocommit = True; cur = conn.cursor()
    name = f"pytest-purge-ip-{uuid.uuid4().hex[:8]}"
    ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"     # TEST-NET-2
    eid = aid = None
    try:
        cur.execute("INSERT INTO engagements (name, status) VALUES (%s,'active') RETURNING id", (name,))
        eid = cur.fetchone()[0]
        cur.execute("INSERT INTO assets (ip, engagement_id) VALUES (%s::inet,%s) RETURNING id", (ip, eid))
        aid = cur.fetchone()[0]
        cur.execute("INSERT INTO scope_targets (name, target, target_type, engagement_id) "
                    "VALUES (%s,%s,'ip',%s)", (name, ip, eid))
        # NULL engagement_id + NULL asset_id, keyed only by ip — like a real cracked cred.
        cur.execute("INSERT INTO credential_findings (ip, port, protocol, username, source, auth_type, valid_cred) "
                    "VALUES (%s::inet,22,'tcp','msfadmin','hashcat_crack','password',true)", (ip,))
        cur.execute("SELECT count(*) FROM credential_findings WHERE host(ip)=%s", (ip,))
        assert cur.fetchone()[0] == 1
        # A web finding keyed only by URL (contains the IP), NULL engagement_id — the
        # class that survived a purge and kept showing after an engagement delete.
        cur.execute("INSERT INTO web_findings (url, issue_type, name, severity, source) "
                    "VALUES (%s,'info','pytest web','low','nuclei')", (f"http://{ip}:80/x",))

        r = _req("POST", f"/engagements/{eid}/purge-data", headers={"x-api-key": _key()})
        if r.status_code in (401, 403):
            pytest.skip("auth required")
        assert r.status_code == 200, r.text[:200]

        cur.execute("SELECT count(*) FROM credential_findings WHERE host(ip)=%s", (ip,))
        assert cur.fetchone()[0] == 0, "cracked creds survived the purge (the bug)"
        cur.execute("SELECT count(*) FROM web_findings WHERE url LIKE %s", (f"%{ip}%",))
        assert cur.fetchone()[0] == 0, "web_findings survived the purge (url-keyed bug)"
        # engagement kept (keep_engagement); scope preserved for re-run.
        cur.execute("SELECT count(*) FROM engagements WHERE id=%s", (eid,))
        assert cur.fetchone()[0] == 1
    finally:
        cur.execute("DELETE FROM credential_findings WHERE host(ip)=%s", (ip,))
        cur.execute("DELETE FROM web_findings WHERE url LIKE %s", (f"%{ip}%",))
        if aid:
            cur.execute("DELETE FROM assets WHERE id=%s", (aid,))
        if eid:
            cur.execute("DELETE FROM scope_targets WHERE engagement_id=%s", (eid,))
            cur.execute("DELETE FROM engagements WHERE id=%s", (eid,))
        cur.close(); conn.close()
