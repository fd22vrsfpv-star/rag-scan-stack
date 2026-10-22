"""Settings -> LLM Backend -> "Ollama (network)": PUT /api/settings/llm stores
llm.ollama_url, normalised, and llm_query re-reads it per request.

Executes the real BFF handler against a fake rag-api. Skips when the BFF's
dependencies (fastapi/httpx/pydantic) are not importable here — run it in the
pentest-dashboard container or a venv with dashboard/bff/requirements.txt.
"""
import asyncio
import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BFF = os.path.join(REPO, "dashboard", "bff")


def _settings_mod():
    if BFF not in sys.path:
        sys.path.insert(0, BFF)
    try:
        import routers.settings as m  # noqa: E402
    except Exception as e:  # missing optional deps -> cannot run here
        pytest.skip(f"BFF not importable here: {e}")
    return m


@pytest.mark.parametrize("raw,expected", [
    ("", ""),
    ("   ", ""),
    ("http://192.168.1.50:11434", "http://192.168.1.50:11434"),
    ("192.168.1.50", "http://192.168.1.50:11434"),
    ("gpu-box.lan:8080/", "http://gpu-box.lan:8080"),
    ("https://ollama.example.com", "https://ollama.example.com:11434"),
    # localhost is dialled from inside llm_query, so it means the host machine
    ("localhost", "http://host.docker.internal:11434"),
    ("http://127.0.0.1:11434", "http://host.docker.internal:11434"),
])
def test_normalise_ollama_url(raw, expected):
    assert _settings_mod()._normalise_ollama_url(raw) == expected


@pytest.mark.parametrize("bad", [
    "ftp://host:11434", "http://host:11434/api", "http://host:99999", "http://",
])
def test_normalise_ollama_url_rejects(bad):
    m = _settings_mod()
    with pytest.raises(m.HTTPException) as ei:
        m._normalise_ollama_url(bad)
    assert ei.value.status_code == 400


class _Resp:
    status_code = 200

    def json(self):
        return {"ok": True}


class _FakeClient:
    puts = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def put(self, url, headers=None, json=None):
        _FakeClient.puts.append((url.rsplit("/", 1)[-1], json["value"]))
        return _Resp()


def _save(m, monkeypatch, **body):
    _FakeClient.puts = []
    monkeypatch.setattr(m.httpx, "AsyncClient", _FakeClient)
    out = asyncio.run(m.save_llm_settings(m.LlmSettingsBody(**body)))
    return out, dict(_FakeClient.puts)


def test_save_network_ollama_stores_normalised_url(monkeypatch):
    m = _settings_mod()
    out, puts = _save(m, monkeypatch, backend="ollama",
                      ollama_url="localhost:11434", ollama_model="qwen2.5:14b")
    assert out["updated"]["ollama_url"] is True
    assert puts["llm.ollama_url"] == "http://host.docker.internal:11434"
    assert puts["llm.ollama_model"] == "qwen2.5:14b"
    assert puts["llm.backend"] == "ollama"


def test_save_local_ollama_clears_url(monkeypatch):
    """Blank is written (not skipped) so switching back to local takes effect."""
    m = _settings_mod()
    out, puts = _save(m, monkeypatch, backend="ollama", ollama_url="")
    assert puts["llm.ollama_url"] == ""
    assert out["updated"]["ollama_url"] is True


def test_save_rejects_bad_url_before_writing(monkeypatch):
    m = _settings_mod()
    with pytest.raises(m.HTTPException):
        _save(m, monkeypatch, backend="ollama", ollama_url="http://x:11434/api/tags")
    assert _FakeClient.puts == []


def test_get_lists_ollama_keys():
    m = _settings_mod()
    assert "llm.ollama_url" in m._LLM_KEYS and "llm.ollama_model" in m._LLM_KEYS


def test_llm_query_refreshes_ollama_url():
    """Without this the hand-rolled path and /api/* proxy kept the env host."""
    # Asserted STRUCTURALLY, not as source text: the guard-style ratchet counts
    # an asserted string that looks like code, and a literal
    # `OLLAMA_URL = s.get("ollama_url")` breaks on any reformat while proving
    # nothing a reader could not have assumed. tests/_ast_assert.py exists for
    # this; here the shape is specific enough to read the AST directly.
    import ast as _ast
    src = open(os.path.join(REPO, "llm_query", "llm_query.py"), encoding="utf-8").read()
    fn = next((n for n in _ast.walk(_ast.parse(src))
               if isinstance(n, _ast.FunctionDef) and n.name == "_refresh_llm_globals"),
              None)
    assert fn is not None, "_refresh_llm_globals is gone"

    # Declared global, or the assignment below binds a LOCAL and the refresh
    # silently does nothing — the exact failure this test exists to catch.
    declared = {nm for g in _ast.walk(fn) if isinstance(g, _ast.Global) for nm in g.names}
    assert "OLLAMA_URL" in declared, "OLLAMA_URL not declared global"

    assigns = [a for a in _ast.walk(fn) if isinstance(a, _ast.Assign)
               and any(getattr(t, "id", "") == "OLLAMA_URL" for t in a.targets)]
    assert assigns, "OLLAMA_URL is never refreshed from the saved settings"
    value = _ast.unparse(assigns[0].value)
    assert "ollama_url" in value, (
        "OLLAMA_URL is not read from the saved setting: %s" % value)
    # A blank saved URL must fall back to the env value rather than blanking
    # the global — that fallback is what keeps this machine working when the
    # operator has not set a network Ollama.
    assert "OLLAMA_URL" in value, (
        "a blank saved URL would blank the global instead of falling back: %s" % value)
