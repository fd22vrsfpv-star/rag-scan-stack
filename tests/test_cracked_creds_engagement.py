"""Cracked credentials (hashcat) are tied to the target's engagement.

Cracked creds were stored with a NULL engagement_id (keyed only by ip), so they
weren't attributed to the engagement and an engagement purge missed them. This
proves cred_cracker._store_credentials now stamps engagement_id (+ asset_id) from
the target's asset/scope. Skips without a DB / the module.
"""
import os
import sys
import uuid
import pathlib

import pytest

psycopg2 = pytest.importorskip("psycopg2")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "exploit_runner"))
cc = pytest.importorskip("cred_cracker")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _conn():
    try:
        c = psycopg2.connect(DB_DSN, connect_timeout=5); c.autocommit = True
        return c
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")


def test_stored_cracked_cred_carries_engagement():
    if getattr(cc, "DB_DSN", None) in (None, ""):
        cc.DB_DSN = DB_DSN
    c = _conn(); cur = c.cursor()
    name = f"pytest-crack-{uuid.uuid4().hex[:6]}"
    ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    eid = aid = None
    try:
        cur.execute("INSERT INTO engagements (name,status) VALUES (%s,'active') RETURNING id", (name,))
        eid = cur.fetchone()[0]
        cur.execute("INSERT INTO assets (ip,engagement_id) VALUES (%s::inet,%s) RETURNING id", (ip, eid))
        aid = cur.fetchone()[0]
        n = cc._store_credentials(ip, {"msfadmin": "msfadmin"},
                                  [{"username": "msfadmin", "port": 22, "protocol": "ssh"}])
        assert n == 1
        cur.execute("SELECT engagement_id, asset_id FROM credential_findings "
                    "WHERE host(ip)=%s AND source='hashcat_crack'", (ip,))
        row = cur.fetchone()
        assert row and str(row[0]) == str(eid), f"engagement not set: {row}"
        assert str(row[1]) == str(aid), f"asset not set: {row}"
    finally:
        cur.execute("DELETE FROM credential_findings WHERE host(ip)=%s", (ip,))
        if aid:
            cur.execute("DELETE FROM assets WHERE id=%s", (aid,))
        if eid:
            cur.execute("DELETE FROM engagements WHERE id=%s", (eid,))
        cur.close(); c.close()
