"""Learned MSF options round-trip: learn on success -> fetch for prefill -> export.

A winning Metasploit option set is learned into rag_documents
(source=knowledge_msf_learned_options), fetched deterministically for queue-time
prefill, and exportable as knowledge/msf_learned_options.yaml text for check-in.
Per-target/run keys (RHOSTS/RPORT/LHOST/...) are never learned.

Hits live rag-api; skips cleanly without it (or its DB / embedder).

    RAG_API_URL=https://localhost:8000 pytest tests/test_msf_learned_options.py
"""
import os
import re
import uuid
import pathlib

import pytest

requests = pytest.importorskip("requests")
psycopg2 = pytest.importorskip("psycopg2")

BASE = os.environ.get("RAG_API_URL", "https://localhost:8000")
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _key():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _post(path, body):
    try:
        return requests.post(f"{BASE}{path}", json=body,
                             headers={"x-api-key": _key()}, timeout=30, verify=False)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def _get(path, params):
    try:
        return requests.get(f"{BASE}{path}", params=params,
                            headers={"x-api-key": _key()}, timeout=30, verify=False)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def test_learn_fetch_export_roundtrip():
    module = f"exploit/multi/pytest/opt_{uuid.uuid4().hex[:8]}"
    try:
        r = _post("/rag/knowledge/msf-options",
                  {"module": module, "service": "http",
                   "options": {"TARGETURI": "/cgi-bin/x", "SSL": True,
                               "RHOSTS": "10.0.0.9", "RPORT": 8080}})
        if r.status_code in (401, 403):
            pytest.skip("auth required")
        if r.status_code == 500 and "embed" in r.text.lower():
            pytest.skip("embedder unavailable")
        assert r.status_code == 200, f"{r.status_code} {r.text[:200]}"
        learned = r.json().get("learned") or {}
        opts = learned.get("options") or {}
        # Tuning options learned; per-target/run keys dropped.
        assert opts.get("TARGETURI") == "/cgi-bin/x"
        assert opts.get("SSL") is True
        assert "RHOSTS" not in opts and "RPORT" not in opts, f"unlearnable key kept: {opts}"

        # Deterministic fetch for prefill.
        g = _get("/rag/knowledge/msf-options", {"module": module})
        assert g.status_code == 200, g.text[:200]
        fetched = (g.json().get("learned") or {}).get("options") or {}
        assert fetched.get("TARGETURI") == "/cgi-bin/x"

        # Export renders YAML that includes the module.
        e = _get("/rag/knowledge/msf-options/export", {})
        assert e.status_code == 200
        assert module in e.json().get("yaml", "")
    finally:
        try:
            c = psycopg2.connect(DB_DSN, connect_timeout=5); c.autocommit = True
            cur = c.cursor()
            cur.execute("DELETE FROM rag_documents WHERE metadata->>'module' = %s", (module,))
            cur.close(); c.close()
        except Exception:
            pass


def test_second_success_merges_and_counts():
    module = f"exploit/multi/pytest/opt_{uuid.uuid4().hex[:8]}"
    try:
        r1 = _post("/rag/knowledge/msf-options", {"module": module, "options": {"A": "1"}})
        if r1.status_code in (401, 403):
            pytest.skip("auth required")
        if r1.status_code == 500 and "embed" in r1.text.lower():
            pytest.skip("embedder unavailable")
        assert r1.status_code == 200, r1.text[:200]
        r2 = _post("/rag/knowledge/msf-options", {"module": module, "options": {"B": "2"}})
        assert r2.status_code == 200
        rec = r2.json().get("learned") or {}
        assert rec.get("options") == {"A": "1", "B": "2"}, rec
        assert rec.get("learned_from") == 2, rec
    finally:
        try:
            c = psycopg2.connect(DB_DSN, connect_timeout=5); c.autocommit = True
            cur = c.cursor()
            cur.execute("DELETE FROM rag_documents WHERE metadata->>'module' = %s", (module,))
            cur.close(); c.close()
        except Exception:
            pass
