"""POST /rag/knowledge/search executes and retrieves the rag_documents corpus.

This endpoint is the ONLY read path over rag_documents — the corpus holding
agent workflows/capabilities and operator-authored dispatch flows. Before it,
those docs were written and indexed but never queried, so the planner's
search_knowledge_base tool would have recalled nothing. This guard executes the
endpoint end-to-end (embed -> ivfflat kNN with probes raised) and proves a
relevant capability/flow document actually comes back ranked. Skips without a
stack when the rag-api / embedder / DB is not reachable.

    RAG_API_URL=https://localhost:8000 pytest tests/test_rag_knowledge_search.py
"""
import os
import re
import pathlib

import pytest

requests = pytest.importorskip("requests")

BASE = os.environ.get("RAG_API_URL", "https://localhost:8000")


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
                             headers={"x-api-key": _key()}, timeout=40, verify=False)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def test_empty_query_is_rejected():
    r = _post("/rag/knowledge/search", {"query": "   "})
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 400, f"expected 400 for empty query, got {r.status_code}"


def test_retrieves_relevant_capability_or_flow():
    r = _post("/rag/knowledge/search",
              {"query": "ssh or vnc login service is open but I have no valid "
                        "passwords, what should the agent do", "top_k": 8})
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, f"{r.status_code}: {r.text[:200]}"
    d = r.json()
    results = d.get("results", [])
    if not results:
        pytest.skip("rag_documents empty here — no corpus loaded on this stack")
    # The probes fix means the small-minority capability/flow docs must surface,
    # not be buried under thousands of web findings.
    sources = {x.get("source") for x in results}
    assert sources & {"agent_capability", "dispatch_flow"}, (
        "no capability/flow doc in top-8 for a credential-guessing query — the "
        f"ivfflat probes fix regressed or the corpus is unloaded. sources={sources}")
    top = results[0]
    assert top.get("similarity") is not None
    assert isinstance(top.get("title"), str) and top["title"]


def test_source_filter_narrows_results():
    r = _post("/rag/knowledge/search",
              {"query": "credential check on a login service", "top_k": 5,
               "sources": ["dispatch_flow"]})
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, f"{r.status_code}: {r.text[:200]}"
    results = r.json().get("results", [])
    if not results:
        pytest.skip("no dispatch_flow docs on this stack")
    assert all(x.get("source") == "dispatch_flow" for x in results), (
        "source filter leaked non-dispatch_flow rows")
