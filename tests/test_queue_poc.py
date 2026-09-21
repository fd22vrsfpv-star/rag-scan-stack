"""POST /findings/web/{id}/queue-poc queues a web PoC without a CheckViolation.

Regression for the bug class where code writes a value a CHECK constraint rejects
and the endpoint 500s silently: this endpoint hardcoded source='web_poc' (not an
allowed pending_exploits.source) and mapped 'open-redirect' -> 'open_redirect'
(not an allowed exploit_type), so EVERY call raised a CheckViolation. Now
'web_poc' is an allowed source and 'open-redirect' maps to 'webapp_other'.

Skips cleanly without a live rag-api + DB.
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
        c = psycopg2.connect(DB_DSN, connect_timeout=5); c.autocommit = True
        return c
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")


def test_queue_poc_open_redirect_does_not_violate_constraints():
    conn = _conn(); cur = conn.cursor()
    url = f"http://pytest-{uuid.uuid4().hex[:8]}.example/redirect"
    fid = None
    queued = []
    try:
        cur.execute(
            """INSERT INTO web_findings (url, issue_type, name, severity, source)
               VALUES (%s, 'open-redirect', 'pytest open redirect', 'medium', 'nuclei')
               RETURNING id::text""", (url,))
        fid = cur.fetchone()[0]
        try:
            r = requests.post(f"{BASE}/findings/web/{fid}/queue-poc",
                              json={"payloads": [{"payload": "//evil.example",
                                                  "description": "redirect PoC",
                                                  "confidence": 0.7}]},
                              headers={"x-api-key": _key()}, timeout=30, verify=False)
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"{BASE} unreachable: {type(e).__name__}")
        if r.status_code in (401, 403):
            pytest.skip("auth required")
        assert r.status_code == 200, f"queue-poc 500'd again: {r.status_code} {r.text[:200]}"
        queued = r.json().get("queued", [])
        assert len(queued) == 1, f"nothing queued: {r.text[:200]}"

        cur.execute("SELECT source, exploit_type FROM pending_exploits WHERE id = %s::uuid",
                    (queued[0],))
        src, etype = cur.fetchone()
        assert src == "web_poc", f"unexpected source {src!r}"
        assert etype == "webapp_other", f"open-redirect should map to webapp_other, got {etype!r}"
    finally:
        if queued:
            cur.execute("DELETE FROM pending_exploits WHERE id = ANY(%s::uuid[])", (queued,))
        if fid:
            cur.execute("DELETE FROM web_findings WHERE id = %s::uuid", (fid,))
        cur.close(); conn.close()
