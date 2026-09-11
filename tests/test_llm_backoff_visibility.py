"""The 429 backoff knobs are visible in Settings → LLM Tuning.

Run on demand:

    pytest tests/test_llm_backoff_visibility.py -v

WHY THIS EXISTS
---------------
There are TWO independent 429 mechanisms, because there are two paths to the
provider:

  * `llm_query`      — retry-on-429 at the shared HTTP chokepoint (news,
                       scan-recommender, anything routed through the service).
                       Knobs: LLM_429_MAX_RETRIES / _BASE_WAIT / _MAX_WAIT.
  * `autogen-agents` — an adaptive AIMD governor on the direct langchain path.
                       Knobs: LLM_RATELIMIT_MAX_RETRIES / _BASE_WAIT / _MAX_WAIT
                       / _ADAPTIVE.

Neither was visible anywhere in the UI, so "why are the agents slow?" had no
answer short of reading source. Worse, `.env.example` referenced the
LLM_RATELIMIT_* group in a comment ("the AGENTS have a separate governor
(LLM_RATELIMIT_* below)") and then never declared it, so a clean install gave no
hint the knobs existed.

THE TWO TRAPS THIS PINS
-----------------------
1. **Report the PROCESS, not .env on disk.** They diverge the moment someone
   edits .env without recreating the container, and a panel showing the file
   would confirm a setting that is not in force.
2. **Unreachable is not absent.** Each source reports ok / error / unreachable.
   Collapsing "could not ask" into "nothing configured" renders as "no
   throttling" on a stack that is throttling hard — the recurring bug in this
   repo. Found for real while building this: the aggregator first used
   `https://llm_query:8002` and got `[SSL: WRONG_VERSION_NUMBER]`, because
   llm_query serves plain HTTP. The panel said "unreachable", which is how the
   bug was caught rather than silently showing one source.

SABOTAGE PROOF
--------------
Change LLM_QUERY_URL back to https:// and
`test_llm_query_is_addressed_over_http` fails. Delete a knob from
`get_ratelimit_config()` and `test_agent_governor_reports_every_knob` fails.
"""
import ast
import os
import re

import pytest

from _container import container_exec

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
LLMQ = os.path.join(REPO, "llm_query", "llm_query.py")
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")
SERVICE = os.path.join(REPO, "autogen_agents", "autogen_service.py")
BFF = os.path.join(REPO, "dashboard", "bff", "routers", "settings.py")
UI = os.path.join(REPO, "dashboard", "frontend", "src", "pages", "Settings.tsx")
ENV_EXAMPLE = os.path.join(REPO, ".env.example")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func_source(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


# ── Each service exposes what it actually applies ──────────────────────────

def test_llm_query_exposes_its_backoff():
    src = _read(LLMQ)
    fn = _func_source(src, "backoff_config")
    assert fn, "llm_query no longer exposes GET /config/backoff"
    for knob in ("LLM_429_MAX_RETRIES", "LLM_429_BASE_WAIT", "LLM_429_MAX_WAIT"):
        assert knob in fn, f"{knob} is missing from the reported config"


def test_agent_governor_reports_every_knob():
    src = _read(ENGINE)
    fn = _func_source(src, "get_ratelimit_config")
    assert fn, "get_ratelimit_config() is gone"
    for knob in ("LLM_RATELIMIT_MAX_RETRIES", "LLM_RATELIMIT_BASE_WAIT",
                 "LLM_RATELIMIT_MAX_WAIT", "LLM_RATELIMIT_ADAPTIVE"):
        assert knob in fn, f"{knob} is missing from the reported config"
    assert "snapshot()" in fn, (
        "the live governor state is no longer reported; the static knobs are "
        "only the ceiling, and what an operator needs when agents feel slow is "
        "the interval the governor has actually backed off to")


def _method_source(src, cls_name, meth_name):
    """Source of one METHOD. Slicing on a blank line truncates inside the
    docstring, which is how the first version of this test failed on correct
    code — a guard that cannot tell right from wrong is worse than none."""
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ClassDef) and node.name == cls_name:
            for sub in node.body:
                if isinstance(sub, ast.FunctionDef) and sub.name == meth_name:
                    return ast.get_source_segment(src, sub) or ""
    return ""


def test_governor_snapshot_is_lock_guarded():
    """It is read from an HTTP handler while agent threads mutate it."""
    snap = _method_source(_read(ENGINE), "_RateLimitGovernor", "snapshot")
    assert snap, "_RateLimitGovernor.snapshot() is gone"
    assert "with self._lock:" in snap, "snapshot() reads shared state without the lock"


def test_agent_endpoint_surfaces_an_unavailable_engine():
    """A missing langgraph must be an error, not a silent 'no governor'."""
    src = _read(SERVICE)
    fn = _func_source(src, "llm_ratelimit_config")
    assert fn, "GET /llm/ratelimit is gone"
    assert "503" in fn, (
        "an unimportable engine must surface as 503, not be swallowed into a "
        "response that reads as 'no throttling configured'")


# ── The aggregator ─────────────────────────────────────────────────────────

def test_llm_query_is_addressed_over_http():
    """llm_query runs `uvicorn --port 8002` with no ssl_keyfile/ssl_certfile.
    An https:// URL fails with SSL WRONG_VERSION_NUMBER — which is exactly what
    happened, and also silently broke the ollama backend test for however long
    it had been written that way."""
    src = _read(BFF)
    assert 'LLM_QUERY_URL = os.environ.get("LLM_QUERY_URL", "http://llm_query:8002")' in src, (
        "llm_query must be addressed over http:// — it does not terminate TLS")
    assert "https://llm_query:8002" not in src, (
        "an https:// llm_query URL is back; it cannot connect")


def test_aggregator_distinguishes_unreachable_from_configured():
    src = _read(BFF)
    fn = _func_source(src, "get_llm_backoff")
    assert fn, "GET /api/settings/llm-backoff is gone"
    for state in ('"unreachable"', '"error"', '"ok"'):
        assert state in fn, (
            f"the aggregator no longer reports {state}; collapsing 'could not "
            "ask' into 'nothing configured' renders as 'no throttling'")


def test_ui_renders_the_panel():
    src = _read(UI)
    assert "function RateLimitBackoffSection()" in src, "the panel component is gone"
    assert "<RateLimitBackoffSection />" in src, "the panel is defined but never rendered"
    assert "/settings/llm-backoff" in src, "the panel no longer calls the endpoint"


def test_ui_says_the_values_are_env_not_editable_here():
    """A field that saved to a table nothing reads would be worse than none."""
    src = _read(UI)
    panel = src[src.index("function RateLimitBackoffSection()"):]
    panel = panel[:panel.index("\nfunction ")]
    assert "onChange" not in panel, (
        "the backoff panel grew an editable field, but these are environment "
        "variables read at process start — saving one here would do nothing")


# ── The gap that started this ──────────────────────────────────────────────

def test_env_example_declares_both_groups():
    """.env.example referenced LLM_RATELIMIT_* in a comment and never declared
    it, so a clean install gave no hint the agents' knobs existed."""
    src = _read(ENV_EXAMPLE)
    for knob in ("LLM_429_MAX_RETRIES", "LLM_429_BASE_WAIT", "LLM_429_MAX_WAIT",
                 "LLM_RATELIMIT_MAX_RETRIES", "LLM_RATELIMIT_BASE_WAIT",
                 "LLM_RATELIMIT_MAX_WAIT", "LLM_RATELIMIT_ADAPTIVE"):
        assert re.search(rf"^{knob}=", src, re.M), (
            f"{knob} is not declared in .env.example")


# ── Live ───────────────────────────────────────────────────────────────────

_LIVE = r"""
import json, os, urllib3, requests
urllib3.disable_warnings()
H = {"x-api-key": os.environ.get("API_KEY", "changeme")}
out = {}
r = requests.get("http://llm_query:8002/config/backoff", headers=H, timeout=20)
out["llm_query_status"] = r.status_code
out["llm_query"] = r.json() if r.ok else None
r = requests.get("https://autogen-agents:8015/llm/ratelimit", headers=H,
                 verify=False, timeout=20)
out["agents_status"] = r.status_code
out["agents"] = r.json() if r.ok else None
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def live():
    out = container_exec(_LIVE, timeout=120)
    if out is None:
        pytest.skip("rag-api container unreachable")
    if out.startswith("__ERR__"):
        pytest.fail(f"backoff endpoints could not be reached: {out}")
    import json
    return json.loads(out.strip().splitlines()[-1])


def test_llm_query_endpoint_executes(live):
    assert live["llm_query_status"] == 200
    env = live["llm_query"]["env"]
    assert set(env) == {"LLM_429_MAX_RETRIES", "LLM_429_BASE_WAIT", "LLM_429_MAX_WAIT"}
    assert all(isinstance(v, (int, float)) for v in env.values()), (
        f"knobs must be reported as numbers, got {env}")


def test_agent_endpoint_executes_and_reports_live_state(live):
    assert live["agents_status"] == 200
    data = live["agents"]
    assert set(data["env"]) == {
        "LLM_RATELIMIT_MAX_RETRIES", "LLM_RATELIMIT_BASE_WAIT",
        "LLM_RATELIMIT_MAX_WAIT", "LLM_RATELIMIT_ADAPTIVE"}
    for field in ("current_interval_sec", "learned_base_wait_sec",
                  "interval_cap_sec", "throttling"):
        assert field in data["live"], f"governor state is missing {field}"
    assert data["live"]["interval_cap_sec"] == data["env"]["LLM_RATELIMIT_MAX_WAIT"], (
        "the adaptive ceiling must come from the operator's configured MAX_WAIT")
