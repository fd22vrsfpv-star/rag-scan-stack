"""PR 1 of the LiteLLM migration — agreement tests for the Router factory.

Pins that `litellm_router.entry_for_provider()` turns each provider
shape from `common.llm_settings.get_providers()` into exactly the
`model_list` entry LiteLLM's `Router` expects. These are PURE
translation tests — no network calls, no LiteLLM Router construction
(which pulls provider SDKs at import time), no agent paths exercised.

What this test proves BEFORE PR 2's dispatch swap:
    - Azure OpenAI deployments map to `azure/<deployment>`
    - Azure Foundry Anthropic deployments map to `azure_ai/anthropic/<deployment>`
      (empirical rule: deployment name starts with `claude-`)
    - Ollama providers map to `ollama/<model>` + api_base
    - Anthropic native providers map to `anthropic/<model>` + api_key
    - OpenAI providers map to `openai/<model>` + api_base + api_key
    - vLLM providers map to `openai/<model>` + api_base (vLLM speaks OpenAI
      chat completions)
    - A provider with no `default_model` is skipped (returns None)
    - An unknown provider type is skipped (returns None, warning logged)
    - The alias is `<provider_id>:<default_model>` so caller-override
      with that same string resolves 1:1

If any of these drifts, the test flags it BEFORE PR 2 wires the router
into `_generate_text` — because once that swap happens, a translation
bug reaches live traffic as a 404 or wrong-provider dispatch.

Runs standalone (`pytest tests/test_litellm_router.py`); skips cleanly
when `litellm_router` isn't on the path (e.g. the test is invoked
outside the llm_query image). The llm_query service's bind mount for
`common/` + the Dockerfile's COPY of `litellm_router.py` are the two
things this test ultimately asserts the shape of.
"""

from __future__ import annotations

import os
import sys
import pytest


_HERE = os.path.dirname(os.path.abspath(__file__))
# litellm_router lives in the repo at ../llm_query/ and in the image at /app/.
# Try both so the test runs identically from the host checkout and inside the
# llm_query container (the only place litellm itself is installed).
for _cand in (os.path.join(os.path.dirname(_HERE), "llm_query"), "/app"):
    if os.path.isfile(os.path.join(_cand, "litellm_router.py")) and _cand not in sys.path:
        sys.path.insert(0, _cand)

try:
    import litellm_router as lr
except Exception as e:  # pragma: no cover
    pytest.skip(f"litellm_router unimportable (looked in ../llm_query and /app): {e}",
                allow_module_level=True)


# --- Per-provider agreement tests -----------------------------------------

def test_azure_classic_openai_entry_shape():
    """CLASSIC Azure OpenAI endpoint (…/.openai.azure.com) → `azure/<deployment>`.
    This is the historical shape pre-Foundry; Foundry OpenAI deploys use a
    different prefix (see test_azure_foundry_openai_entry_shape)."""
    entry = lr.entry_for_provider({
        "id": "azure-classic",
        "type": "azure",
        "endpoint": "https://my-aoai.openai.azure.com",
        "api_key": "sk-abc123",
        "api_version": "2024-08-01-preview",
        "default_model": "gpt-4o",
        "enabled": True,
    })
    assert entry is not None
    assert entry["model_name"] == "azure-classic:gpt-4o"
    p = entry["litellm_params"]
    assert p["model"] == "azure/gpt-4o"
    assert p["api_base"] == "https://my-aoai.openai.azure.com"
    assert p["api_key"] == "sk-abc123"
    assert p["api_version"] == "2024-08-01-preview"


def test_azure_foundry_openai_entry_shape():
    """Foundry OpenAI deployment (gpt-5-mini / gpt-4o / o1 / o3) on
    *.services.ai.azure.com → `azure_ai/<deployment>`. This is the
    OpenAI-compat path through Foundry; `azure/<deployment>` would
    hit the classic REST shape which Foundry rejects. Caught after the
    first focused-10 CVE run: 1.56.4 sent `max_tokens` and 1.104.2
    (even after that bug was fixed upstream) was sent to `azure/` by
    the router, 400ing on "API version not supported" at the wrong
    endpoint shape."""
    entry = lr.entry_for_provider({
        "id": "azure-gpt5",
        "type": "azure",
        "endpoint": "https://rt3ai2-resource.services.ai.azure.com/api/projects/rt3ai2",
        "api_key": "sk-xyz",
        "api_version": "",
        "default_model": "gpt-5-mini",
        "enabled": True,
    })
    assert entry is not None
    assert entry["model_name"] == "azure-gpt5:gpt-5-mini"
    p = entry["litellm_params"]
    assert p["model"] == "azure_ai/gpt-5-mini"
    # /api/projects/<name> suffix stripped — LiteLLM wants the resource root
    # as api_base, same as the hand-rolled dispatcher's _azure_foundry_root.
    assert p["api_base"] == "https://rt3ai2-resource.services.ai.azure.com"
    assert p["api_key"] == "sk-xyz"
    # Blank api_version → default. The default itself is covered by
    # test_azure_api_version_defaults_when_blank.


def test_azure_foundry_anthropic_entry_shape():
    """Deployment name starting with `claude-` on *.services.ai.azure.com
    → `azure_ai/anthropic/<deployment>` AND api_base MUST have the
    `/anthropic` suffix (LiteLLM 1.104 appends `/v1/messages` to
    api_base; without the suffix Azure gets a request for a deployment
    literally named `anthropic/<model>` and returns DeploymentNotFound —
    this was the live `sonnet-4-5` failure that uncovered the bug)."""
    entry = lr.entry_for_provider({
        "id": "sonnet-4-5",
        "type": "azure",
        "endpoint": "https://my-foundry.services.ai.azure.com",
        "api_key": "sk-def456",
        "api_version": "2024-05-01-preview",
        "default_model": "claude-sonnet-4-5",
        "enabled": True,
    })
    assert entry is not None
    assert entry["model_name"] == "sonnet-4-5:claude-sonnet-4-5"
    p = entry["litellm_params"]
    assert p["model"] == "azure_ai/anthropic/claude-sonnet-4-5"
    # /anthropic suffix REQUIRED — see docstring.
    assert p["api_base"] == "https://my-foundry.services.ai.azure.com/anthropic"
    assert p["api_key"] == "sk-def456"


def test_azure_foundry_anthropic_api_base_not_doubled():
    """If the operator already included `/anthropic` in the endpoint
    (some docs show it that way), we shouldn't append it again."""
    entry = lr.entry_for_provider({
        "id": "sonnet-4-5",
        "type": "azure",
        "endpoint": "https://my-foundry.services.ai.azure.com/anthropic",
        "api_key": "k",
        "default_model": "claude-sonnet-4-5",
        "enabled": True,
    })
    assert entry["litellm_params"]["api_base"] == "https://my-foundry.services.ai.azure.com/anthropic"
    # NOT /anthropic/anthropic.


def test_azure_api_version_defaults_when_blank():
    """A provider row with no api_version falls back to `_AZURE_API_VERSION_DEFAULT`
    — LiteLLM REQUIRES api_version for Azure, so a blank one is a 400 at
    first call. The default is 2024-10-21 (bumped from 2024-05-01-preview
    after Foundry rejected the older version on gpt-5 deployments)."""
    entry = lr.entry_for_provider({
        "id": "azure-x", "type": "azure",
        "endpoint": "https://x.openai.azure.com", "api_key": "k",
        "api_version": "", "default_model": "gpt-4o",
        "enabled": True,
    })
    assert entry["litellm_params"]["api_version"] == lr._AZURE_API_VERSION_DEFAULT
    assert lr._AZURE_API_VERSION_DEFAULT == "2024-10-21"


def test_ollama_entry_shape():
    """Ollama → `ollama/<model>` + api_base. No api_key (local, trust the LAN)."""
    entry = lr.entry_for_provider({
        "id": "ollama", "type": "ollama",
        "endpoint": "http://ollama:11434",
        "api_key": "",
        "default_model": "qwen2.5:14b",
        "enabled": True,
    })
    assert entry is not None
    assert entry["model_name"] == "ollama:qwen2.5:14b"
    p = entry["litellm_params"]
    assert p["model"] == "ollama/qwen2.5:14b"
    assert p["api_base"] == "http://ollama:11434"
    assert "api_key" not in p


def test_anthropic_native_entry_shape():
    """Anthropic native (console api_key, not Foundry) → `anthropic/<model>` + api_key."""
    entry = lr.entry_for_provider({
        "id": "anthropic", "type": "anthropic",
        "endpoint": "https://api.anthropic.com",
        "api_key": "sk-ant-xxx",
        "default_model": "claude-sonnet-4-20250514",
        "enabled": True,
    })
    assert entry is not None
    assert entry["model_name"] == "anthropic:claude-sonnet-4-20250514"
    p = entry["litellm_params"]
    assert p["model"] == "anthropic/claude-sonnet-4-20250514"
    assert p["api_key"] == "sk-ant-xxx"


def test_openai_direct_entry_shape():
    """Direct OpenAI → `openai/<model>` + api_base + api_key."""
    entry = lr.entry_for_provider({
        "id": "openai", "type": "openai",
        "endpoint": "https://api.openai.com",
        "api_key": "sk-xxx",
        "default_model": "gpt-4o",
        "enabled": True,
    })
    assert entry is not None
    assert entry["model_name"] == "openai:gpt-4o"
    p = entry["litellm_params"]
    assert p["model"] == "openai/gpt-4o"
    assert p["api_base"] == "https://api.openai.com"
    assert p["api_key"] == "sk-xxx"


def test_vllm_entry_shape():
    """vLLM speaks OpenAI chat-completions — LiteLLM routes it as
    `openai/<model>` with an api_base pointed at the vLLM server."""
    entry = lr.entry_for_provider({
        "id": "vllm", "type": "vllm",
        "endpoint": "http://vllm:8000",
        "api_key": "",
        "default_model": "mistralai/Mistral-7B-Instruct-v0.3",
        "enabled": True,
    })
    assert entry is not None
    assert entry["litellm_params"]["model"] == "openai/mistralai/Mistral-7B-Instruct-v0.3"
    assert entry["litellm_params"]["api_base"] == "http://vllm:8000"


# --- Negative cases --------------------------------------------------------

def test_provider_without_default_model_is_skipped():
    """No default_model → no alias we can register. Skipped (not raised);
    PR 2 adds a wildcard path for one-shot explicit `prov_id:model` calls
    that aren't in the alias table."""
    assert lr.entry_for_provider({
        "id": "ollama", "type": "ollama",
        "endpoint": "http://ollama:11434",
        "default_model": "",
        "enabled": True,
    }) is None


def test_unknown_provider_type_is_skipped_not_raised(caplog):
    """An unknown type logs a WARNING and returns None — operator-added
    'bedrock' or 'vertex' should not take the router build down; the
    hand-rolled dispatcher continues to serve those while we add
    first-class support."""
    import logging as _logging
    caplog.set_level(_logging.WARNING)
    assert lr.entry_for_provider({
        "id": "bedrock-x", "type": "bedrock",
        "default_model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "enabled": True,
    }) is None
    assert any("unknown provider type" in r.message for r in caplog.records)


def test_missing_id_or_type_is_skipped():
    """Guards: an empty id or type shouldn't produce a half-valid entry
    LiteLLM will refuse at Router construction time."""
    assert lr.entry_for_provider({"id": "", "type": "openai", "default_model": "gpt-4o"}) is None
    assert lr.entry_for_provider({"id": "x", "type": "", "default_model": "gpt-4o"}) is None


# --- Model-list assembly ---------------------------------------------------

def test_build_model_list_filters_disabled_providers(monkeypatch):
    """`enabled: False` providers never reach LiteLLM. The settings resolver
    hides them from the DB-loaded list already, but a stray dict passed in
    directly must still be filtered — belt-and-braces, since the operator-
    facing toggle in Settings → LLM reads 'enabled' as the authoritative
    switch."""
    sample = [
        {"id": "a", "type": "openai", "endpoint": "https://x", "api_key": "k",
         "default_model": "gpt-4o", "enabled": True},
        {"id": "b", "type": "openai", "endpoint": "https://y", "api_key": "k",
         "default_model": "gpt-4o-mini", "enabled": False},
    ]
    monkeypatch.setattr(lr, "get_providers", lambda _s: sample)
    out = lr._build_model_list({})
    assert [e["model_name"] for e in out] == ["a:gpt-4o"]


def test_build_model_list_empty_when_no_providers(monkeypatch):
    """No providers → empty list → build_router_from_settings returns None.
    PR 2 reads that None as 'fall back to hand-rolled dispatch'."""
    monkeypatch.setattr(lr, "get_providers", lambda _s: [])
    assert lr._build_model_list({}) == []


# --- Fallbacks -------------------------------------------------------------

def test_build_fallbacks_registers_task_fallbacks(monkeypatch):
    """`fallbacks[<task>]` → `fallbacks=[{prim_alias: [backup_alias]}]`.
    The alias strings match the ones `_build_model_list` emits, so the
    Router correctly resolves the fallback target."""
    def fake_route(task, _s):
        if task == "extract":
            return {"task": "extract", "provider": "ollama", "model": "qwen2.5:14b",
                    "fallback": {"provider": "openai", "model": "gpt-4o-mini"}}
        return None
    monkeypatch.setattr(lr, "get_route", fake_route)
    monkeypatch.setattr(lr, "LLM_TASK_NAMES", ("extract", "recon"))
    out = lr._build_fallbacks({})
    assert out == [{"ollama:qwen2.5:14b": ["openai:gpt-4o-mini"]}]


def test_build_fallbacks_dedupe_self_fallback(monkeypatch):
    """A fallback pointing at the same provider+model as the primary buys
    nothing but a second 429. Skipped. (The hand-rolled resolver already
    does this; the router agreement test pins the behaviour.)"""
    def fake_route(task, _s):
        return {"task": task, "provider": "ollama", "model": "qwen2.5:14b",
                "fallback": {"provider": "ollama", "model": "qwen2.5:14b"}}
    monkeypatch.setattr(lr, "get_route", fake_route)
    monkeypatch.setattr(lr, "LLM_TASK_NAMES", ("recon",))
    assert lr._build_fallbacks({}) == []


# --- Public API guards ----------------------------------------------------

def test_build_router_returns_none_without_providers(monkeypatch):
    """build_router_from_settings() returns None when no providers are
    configured. PR 2's dispatch gate reads this and keeps the hand-rolled
    path serving everything."""
    monkeypatch.setattr(lr, "get_providers", lambda _s: [])
    assert lr.build_router_from_settings({}) is None


def test_router_available_flag_type():
    """Smoke: router_available() returns a bool, never raises on a
    missing dependency / unimportable settings — PR 2 will branch on
    its return value, so a crash here would take every dispatch out."""
    assert isinstance(lr.router_available(), bool)


def test_litellm_router_enabled_default_is_on_from_pr2():
    """Kill switch defaults ON from PR 2 onwards. PR 1 shipped default-OFF
    because nothing was wired in; PR 2 wires LiteLLM into `_generate_text`
    with a hand-rolled fallback on error, so default-ON is safe: a bad
    LiteLLM response falls back and logs the failure. The env var
    `LITELLM_ROUTER_ENABLED=false` still disables the path for operators
    who want to force hand-rolled dispatch during an incident."""
    # Re-read without the env var to assert the default. os.environ.pop
    # removes a per-session override (e.g. a dev who exports =false).
    import importlib
    import os as _os
    _prev = _os.environ.pop("LITELLM_ROUTER_ENABLED", None)
    try:
        importlib.reload(lr)
        assert lr.LITELLM_ROUTER_ENABLED is True
    finally:
        if _prev is not None:
            _os.environ["LITELLM_ROUTER_ENABLED"] = _prev
            importlib.reload(lr)


def test_litellm_completion_for_builds_azure_classic_openai_call(monkeypatch):
    """CLASSIC Azure OpenAI (…/.openai.azure.com) → `azure/<deployment>`.
    api_base, api_key, api_version plumbed through. Patches litellm.completion
    to capture kwargs so the test runs without a real endpoint."""
    import litellm
    captured = {}
    class _FakeMsg: content = "ok"
    class _FakeChoice: message = _FakeMsg()
    class _FakeUsage: prompt_tokens, completion_tokens, total_tokens = 11, 22, 33
    class _FakeResp: choices = [_FakeChoice()]; usage = _FakeUsage()
    def _fake(**kw):
        captured.update(kw); return _FakeResp()
    monkeypatch.setattr(litellm, "completion", _fake)
    text, usage = lr.litellm_completion_for(
        "azure", "gpt-4o", "hello", options={"temperature": 0.3},
        endpoint="https://x.openai.azure.com", api_key="sk-k",
        max_tokens=256, api_version="2024-08-01-preview")
    assert text == "ok"
    assert usage == {"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33}
    assert captured["model"] == "azure/gpt-4o"
    assert captured["api_base"] == "https://x.openai.azure.com"
    assert captured["api_key"] == "sk-k"
    assert captured["api_version"] == "2024-08-01-preview"
    assert captured["max_tokens"] == 256
    assert captured["temperature"] == 0.3


def test_litellm_completion_for_builds_azure_foundry_openai_call(monkeypatch):
    """Foundry OpenAI (gpt-5-mini / o1 / o3 on *.services.ai.azure.com) →
    `azure_ai/<deployment>`. Caught in the first focused-10 run — the
    router was sending `azure/gpt-5-mini` which 400'd on "API version
    not supported" because the hand-rolled dispatcher's `_azure_is_foundry`
    rule wasn't applied here. Also strips the `/api/projects/<name>`
    suffix from api_base — LiteLLM wants the resource root."""
    import litellm
    captured = {}
    class _R:
        choices = [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]
        usage = None
    monkeypatch.setattr(litellm, "completion", lambda **kw: (captured.update(kw), _R())[1])
    lr.litellm_completion_for("azure", "gpt-5-mini", "hi", None,
                              endpoint="https://rt3ai2-resource.services.ai.azure.com/api/projects/rt3ai2",
                              api_key="sk-xyz")
    assert captured["model"] == "azure_ai/gpt-5-mini"
    assert captured["api_base"] == "https://rt3ai2-resource.services.ai.azure.com"
    assert captured["api_version"] == lr._AZURE_API_VERSION_DEFAULT


def test_litellm_completion_for_builds_azure_foundry_anthropic_call(monkeypatch):
    """Deployment starting with `claude-` → `azure_ai/anthropic/<deployment>`.
    Same empirical rule the alias factory uses, enforced on the completion
    call too so the kill-switch-ON path routes to Foundry Anthropic exactly
    like the hand-rolled adapter does today."""
    import litellm
    captured = {}
    class _R:
        choices = [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]
        usage = None
    monkeypatch.setattr(litellm, "completion", lambda **kw: (captured.update(kw), _R())[1])
    # Realistic Foundry endpoint — the foundry-detection rule keys off
    # *.services.ai.azure.com (same rule the hand-rolled _azure_is_foundry
    # uses). An endpoint that doesn't match that pattern would be treated
    # as a CLASSIC Azure OpenAI resource, which is correct — Foundry
    # Anthropic deploys only live on Foundry endpoints.
    lr.litellm_completion_for("azure", "claude-sonnet-4-5", "hi", None,
                              endpoint="https://my-foundry.services.ai.azure.com",
                              api_key="k")
    assert captured["model"] == "azure_ai/anthropic/claude-sonnet-4-5"


def test_litellm_completion_for_ollama_no_api_key(monkeypatch):
    """Ollama path doesn't send api_key (local LAN). api_base is passed."""
    import litellm
    captured = {}
    class _R:
        choices = [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]
        usage = None
    monkeypatch.setattr(litellm, "completion", lambda **kw: (captured.update(kw), _R())[1])
    lr.litellm_completion_for("ollama", "qwen2.5:14b", "hi", None,
                              endpoint="http://ollama:11434", api_key=None)
    assert captured["model"] == "ollama/qwen2.5:14b"
    assert captured["api_base"] == "http://ollama:11434"
    assert "api_key" not in captured


def test_litellm_completion_for_unknown_backend_returns_none():
    """Unknown backend → None; the caller falls back to the hand-rolled
    dispatch instead of raising. Operator-added `bedrock` or `vertex`
    should not take the dispatch down."""
    assert lr.litellm_completion_for("bedrock", "claude-x", "hi", None) is None


def test_litellm_chat_completion_for_preserves_messages(monkeypatch):
    """Chat variant takes `messages` directly and preserves turn roles
    (the single-prompt wrapper would flatten them into one user turn).
    This is what makes `chat()`'s non-routed cutover safe — multi-turn
    semantics survive."""
    import litellm
    captured = {}
    class _R:
        choices = [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]
        usage = None
    monkeypatch.setattr(litellm, "completion", lambda **kw: (captured.update(kw), _R())[1])
    msgs = [{"role": "system", "content": "you are a tool"},
            {"role": "user", "content": "what time is it"},
            {"role": "assistant", "content": "noon"},
            {"role": "user", "content": "and now"}]
    text, _ = lr.litellm_chat_completion_for(
        "ollama", "qwen2.5:14b", msgs, options=None,
        endpoint="http://ollama:11434")
    assert text == "ok"
    assert captured["model"] == "ollama/qwen2.5:14b"
    # The messages array is passed through unchanged — no flattening,
    # no system-message extraction, no role-tag prefixing.
    assert captured["messages"] == msgs


def test_litellm_chat_completion_for_builds_azure_foundry_call(monkeypatch):
    """Chat on Foundry OpenAI still hits `azure_ai/<deployment>` with the
    stripped api_base — same translation table as the completion wrapper.
    Catches the easy mistake of forgetting to add a branch to one but not
    the other."""
    import litellm
    captured = {}
    class _R:
        choices = [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]
        usage = None
    monkeypatch.setattr(litellm, "completion", lambda **kw: (captured.update(kw), _R())[1])
    lr.litellm_chat_completion_for(
        "azure", "gpt-5-mini",
        [{"role": "user", "content": "hi"}], None,
        endpoint="https://rt3ai2-resource.services.ai.azure.com/api/projects/rt3ai2",
        api_key="k")
    assert captured["model"] == "azure_ai/gpt-5-mini"
    assert captured["api_base"] == "https://rt3ai2-resource.services.ai.azure.com"


def test_litellm_chat_completion_for_unknown_backend_returns_none():
    """Same fallback contract as the single-prompt wrapper."""
    assert lr.litellm_chat_completion_for("bedrock", "claude-x",
                                          [{"role": "user", "content": "hi"}],
                                          None) is None


def test_azure_shape_retry_falls_through_on_azure_ai_404(monkeypatch):
    """`_litellm_completion_with_azure_shape_retry` catches a 404 on the
    `azure_ai/` path and retries as `openai/<model>` with the
    `/openai/v1` api_base — the shape Foundry OpenAI-compat deployments
    (DeepSeek, Mistral, Phi, Llama) actually answer on. Verifies both the
    retry fires AND the pin lands so subsequent calls skip the first
    attempt."""
    lr._AZURE_SHAPE_CACHE.clear()
    calls = []
    class _R: choices=[type('C',(),{'message':type('M',(),{'content':'ok'})()})()]; usage=None
    class FakeLitellm:
        @staticmethod
        def completion(**kw):
            calls.append(kw["model"])
            if kw["model"].startswith("azure_ai/"):
                raise Exception("404 Resource not found")
            return _R()
    resp = lr._litellm_completion_with_azure_shape_retry(
        FakeLitellm, "azure", "DeepSeek-V4-Flash", "azure_ai/DeepSeek-V4-Flash",
        {"api_base": "https://rt3ai.services.ai.azure.com",
         "api_key": "k", "api_version": "2024-10-21",
         "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8})
    assert calls == ["azure_ai/DeepSeek-V4-Flash", "openai/DeepSeek-V4-Flash"]
    # Pin recorded — a second call should skip the azure_ai/ attempt.
    assert lr._AZURE_SHAPE_CACHE[("https://rt3ai.services.ai.azure.com",
                                  "DeepSeek-V4-Flash")] == "openai_compat"


def test_azure_shape_retry_pin_short_circuits_subsequent_calls(monkeypatch):
    """After the pin is set, the azure_ai/ attempt is skipped and the
    openai-compat shape is used directly — one call, not two."""
    lr._AZURE_SHAPE_CACHE[("https://rt3ai.services.ai.azure.com",
                           "DeepSeek-V4-Flash")] = "openai_compat"
    calls = []
    class _R: choices=[type('C',(),{'message':type('M',(),{'content':'ok'})()})()]; usage=None
    class FakeLitellm:
        @staticmethod
        def completion(**kw): calls.append(kw["model"]); return _R()
    lr._litellm_completion_with_azure_shape_retry(
        FakeLitellm, "azure", "DeepSeek-V4-Flash", "azure_ai/DeepSeek-V4-Flash",
        {"api_base": "https://rt3ai.services.ai.azure.com",
         "api_version": "2024-10-21",
         "messages": [{"role": "user", "content": "hi"}]})
    assert calls == ["openai/DeepSeek-V4-Flash"]
    lr._AZURE_SHAPE_CACHE.clear()


def test_azure_shape_retry_skips_anthropic_foundry(monkeypatch):
    """Foundry Anthropic (`azure_ai/anthropic/<deployment>`) does NOT get
    the openai-compat retry — those deployments really ARE Anthropic
    Messages API and the retry would route them to the wrong shape."""
    lr._AZURE_SHAPE_CACHE.clear()
    class FakeLitellm:
        @staticmethod
        def completion(**kw):
            raise Exception("404 something")
    with pytest.raises(Exception) as exc_info:
        lr._litellm_completion_with_azure_shape_retry(
            FakeLitellm, "azure", "claude-sonnet-4-5",
            "azure_ai/anthropic/claude-sonnet-4-5",
            {"api_base": "https://rt3ai.services.ai.azure.com",
             "messages": [{"role": "user", "content": "hi"}]})
    # Original error propagates, not the retry wrapper's "both failed".
    assert "404" in str(exc_info.value)


def test_azure_shape_retry_only_fires_on_404(monkeypatch):
    """A 429 or 500 on the azure_ai/ attempt is a real provider failure,
    not a shape mismatch — raise it immediately, don't retry."""
    lr._AZURE_SHAPE_CACHE.clear()
    class FakeLitellm:
        @staticmethod
        def completion(**kw):
            raise Exception("429 rate limited")
    with pytest.raises(Exception) as exc_info:
        lr._litellm_completion_with_azure_shape_retry(
            FakeLitellm, "azure", "DeepSeek-V4-Flash",
            "azure_ai/DeepSeek-V4-Flash",
            {"api_base": "https://rt3ai.services.ai.azure.com",
             "messages": [{"role": "user", "content": "hi"}]})
    assert "429" in str(exc_info.value)


def test_call_litellm_openai_compat_strips_api_version(monkeypatch):
    """`_call_litellm_openai_compat` strips the `api_version` kwarg
    (Azure-only — LiteLLM's openai provider rejects it) and appends
    `/openai/v1` to the api_base if not already there."""
    captured = {}
    class _R: choices=[type('C',(),{'message':type('M',(),{'content':'ok'})()})()]; usage=None
    class FakeLitellm:
        @staticmethod
        def completion(**kw): captured.update(kw); return _R()
    lr._call_litellm_openai_compat(FakeLitellm, "DeepSeek-V4-Flash", {
        "api_base": "https://rt3ai.services.ai.azure.com",
        "api_key": "k", "api_version": "2024-10-21",
        "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8,
    })
    assert captured["model"] == "openai/DeepSeek-V4-Flash"
    assert captured["api_base"] == "https://rt3ai.services.ai.azure.com/openai/v1"
    assert captured["api_key"] == "k"
    assert "api_version" not in captured  # stripped


def test_build_litellm_kwargs_is_shared(monkeypatch):
    """`_build_litellm_kwargs()` is the single source of truth for the
    backend→kwargs mapping. Both wrappers delegate to it, so a change in
    one lands in both. This test pins the shape: Foundry OpenAI with
    custom api_version → azure_ai/<deployment> + stripped api_base +
    the given api_version."""
    lmodel, kwargs = lr._build_litellm_kwargs(
        "azure", "gpt-5-mini", {"temperature": 0.2},
        "https://foundry.services.ai.azure.com/api/projects/p",
        "k", 1024, "2025-01-01-preview")
    assert lmodel == "azure_ai/gpt-5-mini"
    assert kwargs["api_base"] == "https://foundry.services.ai.azure.com"
    assert kwargs["api_version"] == "2025-01-01-preview"
    assert kwargs["temperature"] == 0.2
    assert kwargs["max_tokens"] == 1024
    # `messages` is intentionally NOT set — the caller plugs in its own
    # (single-prompt or multi-turn shape).
    assert "messages" not in kwargs
