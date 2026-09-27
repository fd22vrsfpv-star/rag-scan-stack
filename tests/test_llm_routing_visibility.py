"""Status surfaces must answer "which model actually runs" per task, and a
non-router OLLAMA base must be logged loudly instead of silently bypassing the
router (Docs/OPEN_ITEMS.md, LLM routing).

- test_routes_endpoint: /ollama/routes resolves every task through get_route and
  labels the global as a fallback, without leaking api keys. Runs via TestClient
  inside the llm_query container (has common + fastapi); skips elsewhere.
- the loud-log guards are source checks over the four resolution sites.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
LLM_QUERY_DIR = Path(os.environ.get("LLM_QUERY_DIR", str(ROOT / "llm_query")))


def _load_app():
    sys.path.insert(0, str(LLM_QUERY_DIR))
    try:
        mod = importlib.import_module("llm_query")
        from fastapi.testclient import TestClient
    except Exception as e:
        pytest.skip(f"llm_query not importable here: {e}")
    return mod, TestClient(mod.app)


def test_routes_endpoint_reports_resolved_routes():
    mod, client = _load_app()
    r = client.get("/ollama/routes")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "global_fallback" in body
    if not body.get("ok"):
        pytest.skip(f"routing table unavailable in this env: {body.get('error')}")
    routes = body["routes"]
    # Every known task has a resolved entry.
    from common.llm_settings import LLM_TASK_NAMES
    for t in LLM_TASK_NAMES:
        assert t in routes, f"task {t} missing from resolved routes"
    # The note makes clear the global is only a fallback.
    assert "fallback" in body["note"].lower()
    # No secret ever leaves through this endpoint.
    assert "api_key" not in r.text and "api-key" not in r.text.lower()


# ── the OLLAMA base must not silently bypass the router ──────────────────────

FALLBACK_SITES = [
    ROOT / "app" / "rag-api" / "api.py",
    ROOT / "app" / "rag-api" / "vault_import_agent.py",
    ROOT / "app" / "rag-api" / "artifact_consumer.py",
    ROOT / "app" / "rag-api" / "cloud_triage_agent.py",
]


@pytest.mark.parametrize("path", FALLBACK_SITES, ids=lambda p: p.name)
def test_non_router_ollama_base_is_logged(path):
    if not path.exists():
        pytest.skip(f"{path} not present")
    src = path.read_text()
    assert 'if "llm_query" not in OLLAMA_BASE:' in src, (
        f"{path.name} does not warn when OLLAMA_BASE bypasses the router")
    assert "logging.warning" in src
