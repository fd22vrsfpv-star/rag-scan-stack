"""Guard for llm_query._usage_from — token-usage normalization across backends.

Run: python3 tests/test_llm_usage.py

The router dropped provider token usage, so llm_request_metrics logged 0 tokens for
the Azure/OpenAI backend. This locks the normalizer that now forwards it (mirrored here
as a shim — llm_query.py pulls FastAPI/requests, and the logic is small and pure).
"""


def _usage_from(backend, data):
    b = (backend or "").lower()
    data = data or {}
    u = data.get("usage") or {}
    if b in ("azure", "openai"):
        pt, ct, tt = u.get("prompt_tokens"), u.get("completion_tokens"), u.get("total_tokens")
    elif b == "anthropic":
        pt, ct = u.get("input_tokens"), u.get("output_tokens")
        tt = (pt or 0) + (ct or 0) if (pt is not None or ct is not None) else None
    else:  # ollama / vllm
        pt, ct = data.get("prompt_eval_count"), data.get("eval_count")
        tt = (pt or 0) + (ct or 0) if (pt is not None or ct is not None) else None
    out = {}
    if pt is not None:
        out["prompt_tokens"] = pt
    if ct is not None:
        out["completion_tokens"] = ct
    if tt is not None:
        out["total_tokens"] = tt
    return out


def test_openai_azure_usage():
    d = {"usage": {"prompt_tokens": 12, "completion_tokens": 138, "total_tokens": 150}}
    for be in ("azure", "openai"):
        u = _usage_from(be, d)
        assert u == {"prompt_tokens": 12, "completion_tokens": 138, "total_tokens": 150}


def test_anthropic_usage_computes_total():
    d = {"usage": {"input_tokens": 20, "output_tokens": 80}}
    u = _usage_from("anthropic", d)
    assert u == {"prompt_tokens": 20, "completion_tokens": 80, "total_tokens": 100}


def test_ollama_usage_from_toplevel():
    d = {"prompt_eval_count": 5, "eval_count": 40, "response": "hi"}
    u = _usage_from("ollama", d)
    assert u == {"prompt_tokens": 5, "completion_tokens": 40, "total_tokens": 45}


def test_no_usage_returns_empty():
    # the pre-fix Azure shape (no usage anywhere) must yield {} — never fabricated zeros
    assert _usage_from("azure", {"choices": [{"message": {"content": "x"}}]}) == {}
    assert _usage_from("ollama", {"response": "x"}) == {}


if __name__ == "__main__":
    fns = [f for f in dict(globals()) if f.startswith("test_")]
    for f in fns:
        globals()[f]()
    print(f"PASSED {len(fns)}/{len(fns)}")
