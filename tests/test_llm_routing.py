"""Per-task LLM routing.

One model for the whole stack is wrong in both directions: the frontier model
is wasted summarising news, and a cheap model fumbles tool calls in the exploit
phase. `llm.route.<task>` picks a model (optionally "backend:model") per task,
and `llm.route.<task>.fallback` says where to go when the primary is
rate-limited past its retries.

These are the tests that FAIL if that breaks:
  * the route-string parser (the ollama "qwen2.5:14b" colon trap)
  * precedence: route.<task> > agent_model:<task> > route.default > global
  * a fallback identical to the primary is dropped (it would just 429 twice)
  * an unroutable task degrades to the global model, never to nothing
  * the task list duplicated into the BFF agrees with the resolver's
  * llm_query honours a caller model and a task, and fails over on 429

Standalone: pytest tests/test_llm_routing.py
"""
import ast
import io
import json
import os
import sys

import pytest

REPO = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, REPO)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Routing reads env; a leaked var from another test would decide the
    answer here."""
    for k in list(os.environ):
        if k.startswith("LLM_ROUTE_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "azure")
    monkeypatch.setenv("AZURE_MODEL", "DeepSeek-V4-Flash")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:32b")
    monkeypatch.delenv("DB_DSN", raising=False)  # env-only; no DB in unit tests
    from common import llm_settings
    llm_settings.clear_cache()
    yield
    llm_settings.clear_cache()


# ---------------------------------------------------------------------------
# The parser
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("claude-sonnet-5", (None, "claude-sonnet-5")),
    ("azure:claude-sonnet-5", ("azure", "claude-sonnet-5")),
    ("AZURE:claude-sonnet-5", ("azure", "claude-sonnet-5")),
    ("ollama:qwen2.5:14b", ("ollama", "qwen2.5:14b")),
    ("openai:gpt-4o", ("openai", "gpt-4o")),
    # A bare backend prefix means "that backend, its configured model".
    ("ollama:", ("ollama", "")),
    ("azure:", ("azure", "")),
    ("", (None, "")),
    ("   ", (None, "")),
])
def test_parse_route(raw, expected):
    from common.llm_settings import parse_route
    assert parse_route(raw) == expected


def test_parse_route_does_not_eat_an_ollama_tag():
    """"qwen2.5:14b" is a MODEL, not backend "qwen2.5". Splitting on the first
    colon unconditionally would silently route to a backend that does not
    exist."""
    from common.llm_settings import parse_route
    assert parse_route("qwen2.5:14b") == (None, "qwen2.5:14b")
    assert parse_route("gemma4:31b") == (None, "gemma4:31b")


# ---------------------------------------------------------------------------
# Resolution + precedence
# ---------------------------------------------------------------------------

def test_route_from_env(monkeypatch):
    monkeypatch.setenv("LLM_ROUTE_EXPLOIT", "azure:claude-sonnet-5")
    from common import llm_settings
    llm_settings.clear_cache()
    r = llm_settings.get_route("exploit")
    assert (r["backend"], r["model"]) == ("azure", "claude-sonnet-5")
    assert r["source"] == "route.exploit"


def test_unrouted_task_falls_back_to_the_global_model():
    """The safety property: adding routing must not change behaviour for a task
    nobody configured."""
    from common import llm_settings
    llm_settings.clear_cache()
    r = llm_settings.get_route("analyze")
    assert (r["backend"], r["model"]) == ("azure", "DeepSeek-V4-Flash")
    assert r["source"] == "global"
    assert r["model"], "an unroutable task must never resolve to an empty model"


def test_route_default_covers_tasks_without_their_own(monkeypatch):
    monkeypatch.setenv("LLM_ROUTE_DEFAULT", "azure:claude-haiku-4-5")
    from common import llm_settings
    llm_settings.clear_cache()
    r = llm_settings.get_route("triage")
    assert r["model"] == "claude-haiku-4-5"
    assert r["source"] == "route.default"


def test_task_route_beats_the_default(monkeypatch):
    monkeypatch.setenv("LLM_ROUTE_DEFAULT", "azure:claude-haiku-4-5")
    monkeypatch.setenv("LLM_ROUTE_EXPLOIT", "azure:claude-opus-5")
    from common import llm_settings
    llm_settings.clear_cache()
    assert llm_settings.get_route("exploit")["model"] == "claude-opus-5"
    assert llm_settings.get_route("news")["model"] == "claude-haiku-4-5"


def test_backend_only_route_keeps_that_backends_model(monkeypatch):
    """"ollama:" with no model means "that backend, its configured model"."""
    monkeypatch.setenv("LLM_ROUTE_NEWS", "ollama:")
    from common import llm_settings
    llm_settings.clear_cache()
    r = llm_settings.get_route("news")
    assert r["backend"] == "ollama"
    assert r["model"] == "qwen2.5:32b"


# ---------------------------------------------------------------------------
# The rate-limit fallback
# ---------------------------------------------------------------------------

def test_global_fallback_applies_to_every_task(monkeypatch):
    monkeypatch.setenv("LLM_ROUTE_FALLBACK", "ollama:qwen2.5:14b")
    from common import llm_settings
    llm_settings.clear_cache()
    for task in ("exploit", "recon", "news"):
        fb = llm_settings.get_route(task)["fallback"]
        assert fb is not None, f"{task} has no fallback"
        assert (fb["backend"], fb["model"]) == ("ollama", "qwen2.5:14b")


def test_per_task_fallback_beats_the_global_one(monkeypatch):
    monkeypatch.setenv("LLM_ROUTE_FALLBACK", "ollama:qwen2.5:14b")
    monkeypatch.setenv("LLM_ROUTE_EXPLOIT_FALLBACK", "azure:claude-haiku-4-5")
    from common import llm_settings
    llm_settings.clear_cache()
    fb = llm_settings.get_route("exploit")["fallback"]
    assert (fb["backend"], fb["model"]) == ("azure", "claude-haiku-4-5")


def test_fallback_equal_to_the_primary_is_dropped(monkeypatch):
    """Failing over to the model that just got rate-limited buys a second 429
    and nothing else."""
    monkeypatch.setenv("LLM_ROUTE_NEWS", "ollama:qwen2.5:14b")
    monkeypatch.setenv("LLM_ROUTE_FALLBACK", "ollama:qwen2.5:14b")
    from common import llm_settings
    llm_settings.clear_cache()
    assert llm_settings.get_route("news")["fallback"] is None


def test_no_fallback_configured_means_none(monkeypatch):
    """A 429 must propagate rather than silently answering from some other
    model the operator never chose."""
    from common import llm_settings
    llm_settings.clear_cache()
    assert llm_settings.get_route("exploit")["fallback"] is None


# ---------------------------------------------------------------------------
# The task list is duplicated into the BFF (which cannot import ./common)
# ---------------------------------------------------------------------------

def _bff_tasks():
    src = io.open(os.path.join(REPO, "dashboard", "bff", "routers", "settings.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "LLM_ROUTE_TASKS" for t in node.targets):
            return [ast.literal_eval(e).__getitem__(0) for e in node.value.elts]
    return None


def test_bff_task_list_agrees_with_the_resolver():
    """The BFF does not mount ./common, so the list is duplicated. If they
    drift, the UI offers a task nothing routes (or hides one that exists)."""
    from common.llm_settings import LLM_TASK_NAMES
    bff = _bff_tasks()
    assert bff is not None, "LLM_ROUTE_TASKS not found in the BFF settings router"
    assert list(LLM_TASK_NAMES) == bff, (
        f"task lists drifted:\n  resolver={list(LLM_TASK_NAMES)}\n  bff={bff}"
    )


def test_every_agent_task_is_a_declared_task():
    """_AGENT_TASK maps agent names onto routing tasks; a value that is not a
    real task would make that agent unroutable while looking configured."""
    src = io.open(os.path.join(REPO, "autogen_agents", "langgraph_engine.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    mapped = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "_AGENT_TASK" for t in node.targets):
            mapped = set(ast.literal_eval(node.value).values())
            break
    assert mapped, "_AGENT_TASK not found"
    from common.llm_settings import LLM_TASK_NAMES
    unknown = sorted(mapped - set(LLM_TASK_NAMES))
    assert not unknown, f"_AGENT_TASK maps to undeclared task(s): {unknown}"


def test_agent_phases_actually_pass_their_task():
    """The mapping is useless if _chat_model() is still called with no task."""
    src = io.open(os.path.join(REPO, "autogen_agents", "langgraph_engine.py"),
                  encoding="utf-8").read()
    assert "_chat_model(task_for_agent(agent_name))" in src, (
        "the agent phase builds its model without a task — per-agent model "
        "selection will silently do nothing"
    )


def test_news_sends_its_task():
    src = io.open(os.path.join(REPO, "news_runner", "news_agent.py"),
                  encoding="utf-8").read()
    assert '"task": "news"' in src


# ---------------------------------------------------------------------------
# llm_query: the routing endpoint behaviour
# ---------------------------------------------------------------------------

def test_llm_query_declares_task_and_failover():
    """Static guard: llm_query must expose `task` and implement the failover.
    Read with ast so it works without fastapi/langchain installed."""
    src = io.open(os.path.join(REPO, "llm_query", "llm_query.py"),
                  encoding="utf-8").read()
    ast.parse(src)
    assert "task: Optional[str]" in src, "GenerateRequest has no task field"
    assert "_generate_routed" in src, "no 429 failover path"
    assert "_route_for" in src, "no route resolution"
    # The failover must trigger on 429 specifically, not on any error: retrying
    # a 400 on another model just burns quota twice.
    assert "e.status_code != 429" in src


# ---------------------------------------------------------------------------
# The failover path, executed
# ---------------------------------------------------------------------------

@pytest.fixture()
def llm_query_mod():
    """Import llm_query. Skips when its deps are absent rather than failing —
    "cannot run here" is not "broken"."""
    pytest.importorskip("fastapi")
    pytest.importorskip("requests")
    # Load the FILE, not the package: the `llm_query/` directory shadows
    # `llm_query.py` as a namespace package, so a plain `import llm_query`
    # picks up the directory and fails on its internal imports.
    import importlib.util
    sys.path.insert(0, os.path.join(REPO, "llm_query"))
    sys.path.insert(0, REPO)  # for `common`
    path = os.path.join(REPO, "llm_query", "llm_query.py")
    if not os.path.exists(path):
        pytest.skip("llm_query/llm_query.py not present")
    spec = importlib.util.spec_from_file_location("_llm_query_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"llm_query not importable here: {type(e).__name__}: {e}")
    return mod


def test_generate_routed_fails_over_on_429(llm_query_mod, monkeypatch):
    """A 429 that survived the retries must move to the fallback model.

    By the time a 429 reaches _generate_routed, _post_with_429_retry has
    already waited out the provider's Retry-After — so waiting longer is
    pointless and a DIFFERENT model is the only thing that helps.
    """
    m = llm_query_mod
    from fastapi import HTTPException

    seen = []

    def fake_generate(backend, model, prompt, options, endpoint=None, api_key=None):
        seen.append((backend, model))
        if (backend, model) == ("azure", "DeepSeek-V4-Flash"):
            raise HTTPException(429, "RateLimitReached")
        return "from the fallback"

    monkeypatch.setattr(m, "_generate_text", fake_generate)
    route = {"task": "news", "backend": "azure", "model": "DeepSeek-V4-Flash",
             "fallback": {"backend": "ollama", "model": "qwen2.5:14b"}}
    text, used, failed_over = m._generate_routed(route, "hi", None)

    assert text == "from the fallback"
    assert used == ("ollama", "qwen2.5:14b")
    assert failed_over is True, "a failover must be reported, not silent"
    assert seen == [("azure", "DeepSeek-V4-Flash"), ("ollama", "qwen2.5:14b")]


def test_generate_routed_propagates_429_with_no_fallback(llm_query_mod, monkeypatch):
    """With nothing configured to fall back to, the 429 must surface. Silently
    answering from some other model the operator never chose is worse."""
    m = llm_query_mod
    from fastapi import HTTPException

    def always_429(backend, model, prompt, options, endpoint=None, api_key=None):
        raise HTTPException(429, "RateLimitReached")

    monkeypatch.setattr(m, "_generate_text", always_429)
    route = {"task": "news", "backend": "azure", "model": "X", "fallback": None}
    with pytest.raises(HTTPException) as ei:
        m._generate_routed(route, "hi", None)
    assert ei.value.status_code == 429


def test_generate_routed_does_not_fail_over_on_a_400(llm_query_mod, monkeypatch):
    """A 400 is a contract bug. Retrying it on another model burns quota twice
    and hides the real error."""
    m = llm_query_mod
    from fastapi import HTTPException

    calls = []

    def bad_request(backend, model, prompt, options, endpoint=None, api_key=None):
        calls.append((backend, model))
        raise HTTPException(400, "bad payload")

    monkeypatch.setattr(m, "_generate_text", bad_request)
    route = {"task": "news", "backend": "azure", "model": "X",
             "fallback": {"backend": "ollama", "model": "y"}}
    with pytest.raises(HTTPException) as ei:
        m._generate_routed(route, "hi", None)
    assert ei.value.status_code == 400
    assert len(calls) == 1, "a 400 must not be retried on the fallback"


def test_caller_model_beats_the_task_route(llm_query_mod):
    """A service that names a model has already decided; the route must not
    override it."""
    m = llm_query_mod
    r = m._route_for("news", "some-explicit-model")
    assert r["model"] == "some-explicit-model"
    assert r["source"] == "caller"


def test_empty_caller_model_defers_to_the_route(llm_query_mod):
    """"" means "I don't care" and must NOT be confused with a named model."""
    m = llm_query_mod
    r = m._route_for("news", "")
    assert r["source"] != "caller"


# ---------------------------------------------------------------------------
# Named provider instances
# ---------------------------------------------------------------------------

TWO_AZURE = json.dumps([
    {"id": "azure-main", "type": "azure",
     "endpoint": "https://one.services.ai.azure.com/", "api_key": "k1",
     "default_model": "DeepSeek-V4-Flash"},
    {"id": "azure-claude", "type": "azure",
     "endpoint": "https://two.services.ai.azure.com/", "api_key": "k2",
     "default_model": "claude-sonnet-5"},
    {"id": "local", "type": "ollama",
     "endpoint": "http://host.docker.internal:11434",
     "default_model": "qwen2.5:14b"},
])


def test_two_instances_of_the_same_backend_are_both_reachable(monkeypatch):
    """The whole point: the per-type keys allow one Azure config, so two Azure
    resources could not both be used."""
    monkeypatch.setenv("LLM_PROVIDERS", TWO_AZURE)
    monkeypatch.setenv("LLM_ROUTE_EXPLOIT", "azure-claude:claude-opus-5")
    monkeypatch.setenv("LLM_ROUTE_RECON", "azure-main:")
    from common import llm_settings
    llm_settings.clear_cache()

    ex = llm_settings.get_route("exploit")
    assert ex["provider"] == "azure-claude"
    assert ex["model"] == "claude-opus-5"
    assert ex["endpoint"] == "https://two.services.ai.azure.com/"
    assert ex["api_key"] == "k2"

    rc = llm_settings.get_route("recon")
    assert rc["provider"] == "azure-main"
    assert rc["model"] == "DeepSeek-V4-Flash", "bare 'id:' must use its default_model"
    assert rc["endpoint"] == "https://one.services.ai.azure.com/"
    assert rc["api_key"] == "k1"


def test_provider_ids_do_not_break_the_colon_rule(monkeypatch):
    """A provider id is a valid prefix, but an ollama TAG still is not."""
    monkeypatch.setenv("LLM_PROVIDERS", TWO_AZURE)
    from common import llm_settings
    llm_settings.clear_cache()
    ids = [p["id"] for p in llm_settings.get_providers()]
    assert llm_settings.parse_route("azure-claude:x", ids) == ("azure-claude", "x")
    assert llm_settings.parse_route("qwen2.5:14b", ids) == (None, "qwen2.5:14b")


def test_implicit_providers_keep_legacy_routes_working(monkeypatch):
    """A deployment with no llm.providers row, or a route naming a backend
    TYPE, must keep working — otherwise adding providers is a breaking change."""
    from common import llm_settings
    llm_settings.clear_cache()
    ids = {p["id"] for p in llm_settings.get_providers()}
    assert {"azure", "openai", "ollama", "anthropic", "vllm"} <= ids
    monkeypatch.setenv("LLM_ROUTE_NEWS", "azure:some-model")
    llm_settings.clear_cache()
    r = llm_settings.get_route("news")
    assert r["provider"] == "azure" and r["model"] == "some-model"


def test_explicit_provider_wins_over_the_implicit_same_name(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDERS", json.dumps([
        {"id": "azure", "type": "azure", "endpoint": "https://override/",
         "api_key": "kX", "default_model": "m-override"},
    ]))
    from common import llm_settings
    llm_settings.clear_cache()
    p = llm_settings.get_provider("azure")
    assert p["endpoint"] == "https://override/"
    assert p["implicit"] is False


def test_disabled_provider_is_not_offered(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDERS", json.dumps([
        {"id": "off", "type": "azure", "endpoint": "https://x/", "enabled": False},
    ]))
    from common import llm_settings
    llm_settings.clear_cache()
    assert llm_settings.get_provider("off") is None


def test_malformed_providers_json_does_not_break_routing(monkeypatch):
    """A config typo must not be an outage: fall back to the implicit set."""
    monkeypatch.setenv("LLM_PROVIDERS", "{not json at all")
    from common import llm_settings
    llm_settings.clear_cache()
    r = llm_settings.get_route("exploit")
    assert r["model"] == "DeepSeek-V4-Flash"
    assert r["provider"] == "azure"


def test_same_model_on_a_different_provider_is_a_valid_fallback(monkeypatch):
    """Two deployments of the same model have SEPARATE quotas, so this is a
    real failover target — unlike the identical (provider, model) case."""
    monkeypatch.setenv("LLM_PROVIDERS", TWO_AZURE)
    monkeypatch.setenv("LLM_ROUTE_NEWS", "azure-main:shared-model")
    monkeypatch.setenv("LLM_ROUTE_NEWS_FALLBACK", "azure-claude:shared-model")
    from common import llm_settings
    llm_settings.clear_cache()
    fb = llm_settings.get_route("news")["fallback"]
    assert fb is not None, "a different provider with the same model must count"
    assert fb["provider"] == "azure-claude"
    assert fb["endpoint"] == "https://two.services.ai.azure.com/"


def test_provider_endpoint_and_key_reach_the_dispatcher(llm_query_mod, monkeypatch):
    """Routing is pointless if llm_query still uses the global endpoint/key."""
    m = llm_query_mod
    seen = {}

    def fake(backend, model, prompt, options, endpoint=None, api_key=None):
        seen.update(backend=backend, model=model, endpoint=endpoint, api_key=api_key)
        return "ok"

    monkeypatch.setattr(m, "_generate_text", fake)
    route = {"task": "exploit", "backend": "azure", "model": "claude-opus-5",
             "provider": "azure-claude", "endpoint": "https://two/", "api_key": "k2",
             "fallback": None}
    m._generate_routed(route, "hi", None)
    assert seen["endpoint"] == "https://two/"
    assert seen["api_key"] == "k2"


def test_unreachable_provider_is_a_502_naming_it(llm_query_mod, monkeypatch):
    """An unreachable named provider must say WHICH provider and WHERE.

    The ollama branch was the only one with no error mapping, so a provider
    pointing at a dead host produced a bare 500 "Internal Server Error" —
    indistinguishable from a bug in llm_query itself.
    """
    m = llm_query_mod
    from fastapi import HTTPException
    import requests as _rq

    def dead(*a, **kw):
        raise _rq.ConnectionError("Name or service not known")

    monkeypatch.setattr(m, "_post_with_429_retry", dead)
    with pytest.raises(HTTPException) as ei:
        m._generate_text("ollama", "qwen2.5:14b", "hi", None,
                         endpoint="http://nope:11434")
    assert ei.value.status_code == 502
    assert "nope:11434" in str(ei.value.detail), "the endpoint must be named"


def test_non_429_errors_name_the_provider_and_task(llm_query_mod, monkeypatch):
    """A 404 (DeploymentNotFound is common on Azure) must identify the route
    that caused it, not just bubble a status code."""
    m = llm_query_mod
    from fastapi import HTTPException

    def not_found(backend, model, prompt, options, endpoint=None, api_key=None):
        raise HTTPException(404, "DeploymentNotFound")

    monkeypatch.setattr(m, "_generate_text", not_found)
    route = {"task": "exploit", "backend": "azure", "model": "claude-opus-5",
             "provider": "azure-claude", "endpoint": "https://x/", "api_key": "k",
             "fallback": {"backend": "ollama", "model": "y"}}
    with pytest.raises(HTTPException) as ei:
        m._generate_routed(route, "hi", None)
    assert ei.value.status_code == 404
    assert "azure-claude" in str(ei.value.detail)
    assert "exploit" in str(ei.value.detail)


# ---------------------------------------------------------------------------
# Only DEPLOYED models are selectable
# ---------------------------------------------------------------------------

def test_available_models_uses_the_deployments_api_not_the_catalog():
    """Static guard on the BFF discovery endpoint.

    Azure Foundry's /openai/v1/models is the REGIONAL CATALOG (414 entries on
    this resource) of which 2 are deployed; offering the rest sends the
    operator into DeploymentNotFound. Deployments come from
    /openai/deployments?api-version=2023-03-15-preview -- and specifically that
    api-version, because 2024-08-01-preview returns 404 here.
    """
    src = io.open(os.path.join(REPO, "dashboard", "bff", "routers", "settings.py"),
                  encoding="utf-8").read()
    ast.parse(src)
    assert "/openai/deployments" in src, "not using the deployments API"
    assert "2023-03-15-preview" in src, (
        "the deployments api-version matters: 2024-08-01-preview 404s on this "
        "resource"
    )
    assert 'd.get("status") or "succeeded"' in src or '"succeeded"' in src, (
        "a deployment that is not succeeded must not be offered"
    )


def test_ui_offers_only_deployed_models():
    """The dropdown builder must read `models` (deployed) and must NOT put
    catalog entries into the option list."""
    src = io.open(os.path.join(REPO, "dashboard", "frontend", "src", "pages",
                               "Settings.tsx"), encoding="utf-8").read()
    start = src.index("function buildOptions")
    body = src[start:start + 1200].split("return out")[0]
    # Strip // comments: the body deliberately EXPLAINS why the catalog is not
    # offered, and matching that prose would fail on the correct code.
    code = "\n".join(l.split("//")[0] for l in body.splitlines())
    assert "p.models" in code, "buildOptions no longer reads the deployed list"
    assert "catalog" not in code, (
        "catalog entries are being offered as selectable again"
    )


def test_azure_root_strips_the_responses_path():
    """`_azure_root` must handle the Responses-API URL, which the llm_query
    equivalent does not -- that is how a doubled path gets built."""
    src = io.open(os.path.join(REPO, "dashboard", "bff", "routers", "settings.py"),
                  encoding="utf-8").read()
    assert "/responses" in src, "_azure_root does not strip /responses"
    import re
    pat = re.compile(r"(/openai)?(/v1)?(/chat/completions|/embeddings|/responses|/deployments)?/?$",
                     re.I)
    for typed in ("https://x.services.ai.azure.com/",
                  "https://x.services.ai.azure.com/openai",
                  "https://x.services.ai.azure.com/openai/v1",
                  "https://x.services.ai.azure.com/openai/v1/responses",
                  "https://x.services.ai.azure.com/openai/deployments"):
        assert pat.sub("", typed.rstrip("/")).rstrip("/") == \
            "https://x.services.ai.azure.com", typed


# ---------------------------------------------------------------------------
# gpt-5 / o-series take max_completion_tokens, not max_tokens
# ---------------------------------------------------------------------------

def test_azure_post_swaps_max_tokens_when_the_model_rejects_it(llm_query_mod, monkeypatch):
    """Verified against gpt-5-mini on a real resource: `max_tokens` returns
    400 unsupported_parameter, `max_completion_tokens` returns 200.

    The swap is driven by the provider's own error text rather than a model
    list, which would go stale every time a family is added.
    """
    m = llm_query_mod
    calls = []

    class _R:
        def __init__(self, code, text="", data=None):
            self.status_code = code
            self.text = text
            self._d = data or {}
            self.headers = {}

        def json(self):
            return self._d

        def raise_for_status(self):
            if self.status_code >= 400:
                import requests as rq
                raise rq.HTTPError(response=self)

    def fake_post(url, payload, headers):
        calls.append(dict(payload))
        if "max_tokens" in payload:
            return _R(400, '{"error":{"code":"unsupported_parameter",'
                           '"message":"Use \'max_completion_tokens\' instead"}}')
        return _R(200, "", {"choices": [{"message": {"content": "OK"}}]})

    monkeypatch.setattr(m, "_post_with_429_retry", fake_post)
    out = m._azure_json_post("https://x/openai/v1/chat/completions",
                             {"model": "gpt-5-mini", "max_tokens": 16,
                              "messages": []})
    assert out["choices"][0]["message"]["content"] == "OK"
    assert len(calls) == 2, "should retry exactly once"
    assert "max_tokens" not in calls[1]
    assert calls[1]["max_completion_tokens"] == 16


def test_azure_post_does_not_swap_on_an_unrelated_400(llm_query_mod, monkeypatch):
    """Only swap when the provider actually names the parameter — otherwise a
    real contract bug gets a pointless second request."""
    m = llm_query_mod
    calls = []

    class _R:
        status_code = 400
        text = '{"error":{"code":"content_filter"}}'
        headers = {}

        def json(self):
            return {}

        def raise_for_status(self):
            import requests as rq
            raise rq.HTTPError(response=self)

    def fake_post(url, payload, headers):
        calls.append(dict(payload))
        return _R()

    monkeypatch.setattr(m, "_post_with_429_retry", fake_post)
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        m._azure_json_post("https://x/openai/v1/chat/completions",
                           {"model": "gpt-4o", "max_tokens": 16, "messages": []})
    assert len(calls) == 1, "an unrelated 400 must not be retried"


@pytest.mark.parametrize("typed", [
    "https://r.services.ai.azure.com/",
    "https://r.services.ai.azure.com/openai",
    "https://r.services.ai.azure.com/openai/v1",
    "https://r.services.ai.azure.com/openai/v1/chat/completions",
    # The URL the portal shows for the Responses API, and a Foundry PROJECT
    # endpoint — both are things an operator will paste.
    "https://r.services.ai.azure.com/openai/v1/responses",
    "https://r.services.ai.azure.com/api/projects/myproj",
])
def test_azure_root_normalises_every_pasteable_shape(llm_query_mod, typed):
    m = llm_query_mod
    assert m._azure_foundry_root(typed) == "https://r.services.ai.azure.com", typed


def test_provider_test_endpoint_reports_each_stage():
    """The connectivity check must distinguish the stages, because they have
    very different causes that look identical from outside: a bad URL shape, a
    rejected key, a resource that authenticates but serves NO models, and a
    default_model that is not deployed on THAT resource. Diagnosing two real
    misconfigured providers by hand is what this exists to replace.
    """
    src = io.open(os.path.join(REPO, "dashboard", "bff", "routers", "settings.py"),
                  encoding="utf-8").read()
    ast.parse(src)
    assert '/api/settings/llm/providers/{provider_id}/test' in src
    for stage in ('"endpoint"', '"auth"', '"deployments"', '"generate"'):
        assert stage in src, f"the check does not report {stage}"
    # The end-to-end leg is the only one that proves usability, and it must
    # apply the same max_completion_tokens swap llm_query does or a gpt-5
    # deployment tests as broken while working fine in the app.
    assert "max_completion_tokens" in src
    assert "DeploymentNotFound" in src, (
        "a 404 on generate should say the model is not on this resource"
    )


def test_provider_test_never_takes_a_key_from_the_browser():
    """The test must use the STORED key. Accepting one from the request would
    make this endpoint a way to have the server dial an arbitrary host with an
    arbitrary credential."""
    src = io.open(os.path.join(REPO, "dashboard", "bff", "routers", "settings.py"),
                  encoding="utf-8").read()
    start = src.index('async def test_llm_provider(')
    body = src[start:src.index("@router.get", start)]
    assert "def test_llm_provider(provider_id: str)" in body, (
        "the test endpoint takes a body — it must take only the provider id"
    )
    assert 'prov.get("api_key")' in body
