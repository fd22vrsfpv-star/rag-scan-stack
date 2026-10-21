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
    src = open(os.path.join(REPO, "llm_query", "llm_query.py"), encoding="utf-8").read()
    body = src.split("def _refresh_llm_globals", 1)[1].split("\ndef ", 1)[0]
    assert "OLLAMA_URL" in body.split("try:", 1)[0], "OLLAMA_URL not declared global"
    assert 'OLLAMA_URL = s.get("ollama_url")' in body
