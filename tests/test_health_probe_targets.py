"""rag-api's /health must probe the LLM backend it actually uses.

WHY THIS EXISTS
---------------
The health check dialled a hard-coded `http://ollama:11434/api/tags`. There is no
ollama container in this stack and never has been — the same nonexistent daemon
that meant news enrichment had never once run. Two measured consequences:

  * 4.00s of the endpoint's 4.2s was this single probe. `timeout=3` does not
    bound it, because requests retries the connection. That is why the
    dashboard's aggregate /api/health took 8.6s and reported
    `rag_api: ConnectTimeout (timeout=8s)` under load, and it is the reason the
    ~107 service-tier tests could not run against a live stack in useful time.
  * it set `response["ok"] = False`, so rag-api reported UNHEALTHY permanently
    (`docker ps`: "Up 15 hours (unhealthy)"). A health check that is always red
    says nothing when something is actually wrong.

OLLAMA_BASE is the variable the rag-api agents already dial; it resolves to
llm_query, which serves an ollama-compatible /api/tags. Measured from inside the
container: 0.00s vs 4.00s.

SABOTAGE PROOF
--------------
* Restore the literal "http://ollama:11434" -> test_no_hardcoded_llm_host fails.
* Re-add `response["ok"] = False` to that except -> test_an_optional_backend_does_not_flip_ok fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")


def _health_src():
    if not os.path.exists(API):
        pytest.skip("app/rag-api/api.py not present")
    src = open(API, encoding="utf-8").read()
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "health":
            return ast.get_source_segment(src, n)
    pytest.fail("the health() handler is gone")


def test_no_hardcoded_llm_host():
    """Asked of the CODE, not the text: the comment above the probe names the
    old host to explain why it is wrong, and a substring check would match it."""
    fn = _health_src()
    consts = {n.value for n in ast.walk(ast.parse(fn.lstrip()))
              if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    bad = [c for c in consts if "ollama:11434" in c or "host.docker.internal:11434" in c]
    assert not bad, (
        f"/health still probes a hard-coded LLM host {bad}; it must use the "
        f"configured OLLAMA_BASE, which points at the llm_query router")


def test_the_probe_uses_the_configured_base():
    fn = _health_src()
    names = {n.id for n in ast.walk(ast.parse(fn.lstrip())) if isinstance(n, ast.Name)}
    assert "OLLAMA_BASE" in names, (
        "the LLM probe does not read OLLAMA_BASE — the same variable the rag-api "
        "agents dial, so health can disagree with what actually runs")


def test_an_optional_backend_does_not_flip_ok():
    """`ok` is about whether rag-api can serve. A missing optional backend made
    it permanently false, which is how a health check stops carrying signal."""
    fn = _health_src()
    tree = ast.parse(fn.lstrip())
    # find handlers that assign ok=False, and check none of them is the LLM one
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler):
            continue
        body = ast.dump(handler)
        sets_ok_false = any(
            isinstance(n, ast.Subscript)
            and isinstance(n.slice, ast.Constant) and n.slice.value == "ok"
            for stmt in handler.body for n in ast.walk(stmt)
            if isinstance(stmt, ast.Assign))
        mentions_llm = "ollama" in body.lower()
        assert not (sets_ok_false and mentions_llm), (
            "the LLM-backend probe flips response['ok'] to False, so rag-api "
            "reports unhealthy whenever an OPTIONAL backend is unreachable")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
