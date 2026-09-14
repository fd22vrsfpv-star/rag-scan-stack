"""llm_query's /api/* surface must be a complete drop-in Ollama API.

Run on demand:

    pytest tests/test_llm_query_api_router.py -v
    LLM_QUERY_URL=http://localhost:8002 pytest tests/test_llm_query_api_router.py

WHY THIS EXISTS
---------------
llm_query is a drop-in Ollama replacement: rag-api agents point OLLAMA_BASE_URL at
it and call /api/generate, /api/chat, /api/show, etc. The endpoints were declared
under the /ollama prefix but only a SUBSET was re-exposed under /api/, so a client
hitting /api/show (which Ollama clients call to read a model's params) got a 404 —
indistinguishable from "model not found". This pins the /api surface to the full
native set so a dropped route fails here, not at a caller.

SABOTAGE PROOF
--------------
Delete the `api_router.add_api_route("/show", ...)` line and
test_api_router_exposes_the_native_ollama_surface fails.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
LLM_QUERY = os.path.join(REPO, "llm_query", "llm_query.py")

#: The Ollama-native paths a drop-in replacement must answer under /api/.
NATIVE = {"generate", "chat", "embeddings", "embed", "tags", "ps", "version",
          "show", "pull", "delete"}


def _api_paths():
    if not os.path.exists(LLM_QUERY):
        pytest.skip("llm_query.py not present")
    src = open(LLM_QUERY, encoding="utf-8").read()
    # everything registered on the /api router
    return set(re.findall(r'api_router\.add_api_route\(\s*"/([a-z]+)"', src))


def test_api_router_exposes_the_native_ollama_surface():
    exposed = _api_paths()
    missing = NATIVE - exposed
    assert not missing, (
        f"/api/* is missing Ollama-native routes {sorted(missing)} — a client "
        f"hitting them gets a 404 that reads like 'model/endpoint not found'. "
        f"Add api_router.add_api_route for each.")


# ── Live (skips cleanly without the service) ─────────────────────────────────

def test_api_show_is_not_404_live():
    base = os.environ.get("LLM_QUERY_URL")
    if not base:
        pytest.skip("LLM_QUERY_URL not set")
    requests = pytest.importorskip("requests")
    try:
        r = requests.post(f"{base.rstrip('/')}/api/show",
                          json={"name": "x", "model": "x"}, timeout=10)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"llm_query unreachable: {type(e).__name__}")
    assert r.status_code != 404, (
        f"/api/show 404s — it is not registered on the /api router ({r.text[:120]})")
