"""POST /extractors/learned/sync-rag — (re)embed active learned extractors into
rag_documents so planner LLMs can retrieve the shapes the platform recognizes.

Executes the endpoint (CLAUDE.md: every endpoint has a test that runs it) and
asserts the response shape. Idempotent and safe (re-embeds active rules only).
Skips cleanly when rag-api is unreachable.

    RAG_API_URL=https://localhost:8000 pytest tests/test_learned_extractor_rag_sync.py
"""
import os
import re
import pathlib

import pytest

requests = pytest.importorskip("requests")

BASE = os.environ.get("RAG_API_URL", "https://rag-api:8000")


def _key():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def test_sync_rag_executes_and_reports_counts():
    try:
        r = requests.post(f"{BASE}/extractors/learned/sync-rag",
                          headers={"x-api-key": _key()}, timeout=60, verify=False)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")
    if r.status_code in (401, 403):
        pytest.skip(f"auth not accepted here ({r.status_code})")
    assert r.status_code == 200, f"{r.status_code}: {r.text[:200]}"
    body = r.json()
    assert body.get("ok") is True
    # counts are present and consistent
    for k in ("active", "embedded", "failed"):
        assert isinstance(body.get(k), int), f"missing/int field {k}: {body}"
    assert body["embedded"] + body["failed"] == body["active"]
