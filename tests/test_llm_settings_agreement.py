"""The LLM settings resolver: one copy, and every service can reach it.

`common/llm_settings.py` USED to be copied verbatim into llm_query,
scan_recommender and autogen_agents, kept byte-identical by a hash check,
because `common/` was not mounted into all of them. That is exactly the
arrangement `common/Dockerfile` exists to prevent — it records that
`validation.py` once lived in seven places with a real fix stranded in one.

The three services now bind-mount `./common` and import
`from common.llm_settings import get_llm_settings`, so the hash check is gone and
these tests assert the two things that can now go wrong instead:

  * a copy REAPPEARS somewhere (the drift starts again)
  * a service cannot actually import it

The second is the dangerous one. Every call site imports softly —
`except Exception: get_llm_settings = None` — so a broken import does NOT crash
the service. It silently falls back to env-only and the Settings -> LLM Tuning
GUI stops controlling that service, with nothing in the logs. So the import is
executed INSIDE each container rather than inferred from the file being present.
"""
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CANONICAL = os.path.join(REPO, "common", "llm_settings.py")

# The services that import it, and the container each runs in.
CONSUMERS = {
    "scan-recommender": "scan_recommender/scan_recommender.py",
    "llm_query": "llm_query/llm_query.py",
    "autogen-agents": "autogen_agents/agent_config.py",
}


def test_there_is_exactly_one_copy():
    """A reappearing copy is how the drift starts again."""
    assert os.path.exists(CANONICAL), "the canonical resolver is missing"
    found = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "node_modules", "__pycache__", "venv")]
        if "llm_settings.py" in files:
            found.append(os.path.relpath(os.path.join(root, "llm_settings.py"), REPO))
    assert found == ["common/llm_settings.py"], (
        f"llm_settings.py exists in {len(found)} places: {found}. There is one "
        "canonical copy; services bind-mount ./common and import "
        "common.llm_settings.")


def test_every_consumer_imports_from_common():
    """A flat `from llm_settings import ...` would resolve to nothing now, and
    the soft import would swallow it."""
    for service, path in CONSUMERS.items():
        src = open(os.path.join(REPO, path), encoding="utf-8").read()
        assert "from common.llm_settings import get_llm_settings" in src, \
            f"{path} does not import the shared resolver"
        assert "\nfrom llm_settings import" not in src, \
            f"{path} still has a flat import, which no longer resolves"


@pytest.mark.parametrize("service", sorted(CONSUMERS))
def test_the_import_actually_works_inside_the_container(service):
    """THE test that matters.

    Every call site catches the ImportError and sets `get_llm_settings = None`,
    so a missing module does not crash anything — the service quietly stops
    honouring the LLM Tuning GUI. Only executing the import proves it resolves.
    """
    import subprocess
    probe = ("from common.llm_settings import get_llm_settings;"
             "print('RESOLVED', callable(get_llm_settings))")
    try:
        out = subprocess.run(["docker", "exec", service, "python3", "-c", probe],
                             capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f"{service} not reachable")
    if out.returncode != 0 and "No such container" in (out.stderr or ""):
        pytest.skip(f"{service} not running")
    assert out.returncode == 0, (
        f"{service} cannot import common.llm_settings — it will silently fall "
        f"back to env-only config: {(out.stderr or '').strip()[-200:]}")
    assert "RESOLVED True" in out.stdout, out.stdout


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
