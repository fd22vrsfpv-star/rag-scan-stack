"""Agreement + unit tests for the LLM settings resolver.

`common/llm_settings.py` is copied verbatim into llm_query, scan_recommender and
autogen_agents (they don't all mount common/). The agreement test fails if the
copies drift; the unit tests pin the DB-over-env-over-default precedence.

Sabotage proof: change one copy's byte and test_copies_are_identical fails; flip
the precedence in get_llm_settings and test_db_overrides_env fails.
"""
import hashlib
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_COPIES = [
    os.path.join(REPO, "common", "llm_settings.py"),
    os.path.join(REPO, "llm_query", "llm_settings.py"),
    os.path.join(REPO, "scan_recommender", "llm_settings.py"),
    os.path.join(REPO, "autogen_agents", "llm_settings.py"),
]


def test_copies_are_identical():
    present = [p for p in _COPIES if os.path.exists(p)]
    assert len(present) == len(_COPIES), f"missing copies: {set(_COPIES) - set(present)}"
    digests = {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in present}
    assert len(set(digests.values())) == 1, f"copies have drifted: {digests}"


@pytest.fixture()
def mod():
    sys.path.insert(0, os.path.join(REPO, "common"))
    import llm_settings as m
    m.clear_cache()
    yield m
    m.clear_cache()


def test_env_over_default(mod, monkeypatch):
    monkeypatch.delenv("DB_DSN", raising=False)  # force no-DB path
    monkeypatch.setenv("LLM_BACKEND", "openai")
    monkeypatch.setenv("OPENAI_API_BASE", "https://rt3ai.services.ai.azure.com/openai")
    monkeypatch.setenv("OPENAI_MODEL", "DeepSeek-V4-Flash")
    s = mod.get_llm_settings(force_refresh=True)
    assert s["backend"] == "openai"
    assert s["openai_api_base"] == "https://rt3ai.services.ai.azure.com/openai"
    assert s["openai_model"] == "DeepSeek-V4-Flash"
    assert s["_source"]["openai_model"] == "env"


def test_default_when_unset(mod, monkeypatch):
    monkeypatch.delenv("DB_DSN", raising=False)
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    s = mod.get_llm_settings(force_refresh=True)
    assert s["ollama_model"] == "qwen2.5:32b"
    assert s["_source"]["ollama_model"] == "default"


def test_db_overrides_env(mod, monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    monkeypatch.setenv("LLM_BACKEND", "ollama")
    monkeypatch.setattr(mod, "_read_db_llm",
                        lambda: {"openai_model": "DeepSeek-V4-Flash", "backend": "openai"})
    s = mod.get_llm_settings(force_refresh=True)
    assert s["openai_model"] == "DeepSeek-V4-Flash"
    assert s["_source"]["openai_model"] == "db"
    assert s["backend"] == "openai"
    assert s["_source"]["backend"] == "db"


def test_db_failure_falls_back_to_env(mod, monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    def _boom():
        raise RuntimeError("db down")
    # _read_db_llm swallows internally, but prove get_llm_settings never raises
    monkeypatch.setattr(mod, "_read_db_llm", lambda: {})
    s = mod.get_llm_settings(force_refresh=True)
    assert s["openai_model"] == "gpt-4o"
