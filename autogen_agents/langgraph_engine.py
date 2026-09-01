"""LangGraph pentest engine — the AutoGen → LangGraph migration (Phase 1→4).

Runs a pentest session behind the SAME `/pentest` API. `AGENT_ENGINE`
(`langgraph` default as of Phase 4 | `autogen` fallback) selects the engine, and
a per-request `engine` field overrides it for one session. Design invariants
from Docs/LANGGRAPH_MIGRATION_PLAN.md:

  * Reuses the existing `scan_tools` bodies unchanged — so the scope gate,
    MAX_CONCURRENT_SCANS and webhook contracts are exactly the same. A node that
    dispatches is NOT a new dispatcher; it calls the same gated function.
  * Persists to the SAME `agent_sessions` / `agent_messages` tables via db_utils,
    sets the SAME `scan_tracker` session context (so `/scans`, port_profile and
    web_profile behave identically) and writes the SAME `llm_request_metrics`
    rows (via a LangChain callback instead of AutoGen's monkeypatch).
  * Deterministic supervisor edges (recon → scan → analyze → [exploit] → report)
    — this is what removes the GroupChat speaker-selection stall class.
  * Checkpoints to Postgres (thread_id = session_id) via PostgresSaver, the
    native replacement for manual message persistence + parent_session_id resume.

Phase 3 made **recon** a real LLM agent. Phase 4 adds:
  * **scan** and **analyze** as LLM agents (same pattern, per-phase toolsets),
  * an opt-in **exploit** phase whose approval is a native `interrupt()` —
    the graph parks in Postgres and the operator resumes it via
    `POST /pentest/{id}/approve` (`Command(resume=...)`), which is the durable
    replacement for `/nudge` + UserProxy input,
  * LLM metrics + scan-tracker parity so flipping the default loses nothing.

Nodes execute inline on the calling thread (single-task steps), which is why the
thread-local `scan_tracker` / `LLMMetricsContext` context set in
`run_langgraph_session_sync` is visible inside every node. Keep the graph
sequential: a parallel fan-out would run in worker threads and lose it.
"""
from __future__ import annotations

import json
import operator
import os
import time
import uuid
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langgraph.graph import StateGraph, START, END

import logging

import scan_tools
from db_utils import add_agent_message, get_agent_session, update_agent_session
from scan_tools import scan_tracker

_log = logging.getLogger("langgraph_engine")

ENGINE_NAME = "langgraph"
_MSG_CAP = 4000

# ── per-phase tool surfaces ──────────────────────────────────────────────────
# Every name below must exist in the AutoGen roster; the same bodies are called,
# so nothing here creates a new dispatch path. tests/test_langgraph_phases.py
# pins these sets against langgraph_tools.TOOL_NAMES so a rename fails the build
# instead of silently shrinking a phase's toolset to nothing.

# Read-only queries against data we already hold. No traffic leaves the platform.
_READ_ONLY = {
    "query_assets", "query_open_ports", "query_vulnerabilities",
    "get_web_findings", "search_all_findings", "get_attack_vectors",
    "query_credential_findings", "query_exploitdb",
    "get_session_scan_status", "get_all_active_jobs",
}

RECON_TOOLS = _READ_ONLY | {"get_passive_recon_plan"}

# Scan planning is read-only; dispatch is added ONLY when auto_execute is on.
SCAN_TOOLS_READONLY = {
    # get_tool_recommendations is the actionable one: structured tools +
    # command templates + the ingested methodology for the service, which is
    # what turns "there is an https port" into "run these specific tests".
    "get_tool_recommendations",
    "get_scan_recommendations", "get_passive_recon_plan", "query_assets",
    "query_open_ports", "get_session_scan_status", "get_all_active_jobs",
}
# Discovery / enumeration dispatchers. Deliberately EXCLUDES the credential
# brute-force tools (start_brutus, start_credential_check) and everything
# exploit-adjacent: those stay behind the human-approved exploit phase, so the
# blast radius of an autonomous scan phase is enumeration only.
SCAN_TOOLS_DISPATCH = {
    "start_nmap_scan", "start_naabu", "start_masscan", "start_deep_port_scan",
    "start_udp_scan", "start_httpx_probe", "start_nuclei_scan", "start_web_scan",
    "start_pipeline_scan", "start_playwright_scan", "start_katana",
    "start_subfinder", "start_dnsx", "start_asnmap", "start_uncover",
    "start_cloudlist", "start_passive_recon", "start_subdomain_takeover",
    "start_smb_vuln_scan", "start_full_scan",
}

ANALYZE_TOOLS = _READ_ONLY | {"match_vuln_to_exploits", "search_msf_modules",
                              "get_tool_recommendations"}

# Exploit PLANNING is read-only + the queue-for-approval call, which only writes
# a pending_exploits row. Execution is a separate node, reached only after the
# operator approves through the interrupt.
EXPLOIT_PLAN_TOOLS = {
    "query_vulnerabilities", "query_open_ports", "query_assets",
    "match_vuln_to_exploits", "query_exploitdb", "search_msf_modules",
    "customize_exploit", "list_pending_exploits", "get_exploit_approval_status",
    "queue_exploit_for_approval",
}

_RECON_SYSTEM = (
    "You are the Reconnaissance agent in a penetration-testing platform. Use ONLY "
    "the read-only tools provided to enumerate what is already known about the "
    "target: discovered assets, open ports, existing vulnerabilities and web "
    "findings. Do NOT attempt to launch scans. When you have gathered enough, "
    "reply with a concise reconnaissance summary (assets, notable ports/services, "
    "and the most important existing findings)."
)
_SCAN_SYSTEM_PLAN = (
    "You are the Scanner agent in a penetration-testing platform. auto_execute is "
    "OFF for this session, so you must NOT launch anything — you have no dispatch "
    "tools. Use the read-only tools to work out what SHOULD be scanned next and "
    "reply with a prioritised, concrete scan plan (tool, target, ports/scope, and "
    "why) that the operator can run manually. For each open service worth "
    "testing, call get_tool_recommendations(service, port) — it returns the "
    "specific tools, command templates, nuclei tags and methodology for that "
    "service, so your plan can name real commands instead of generalities."
)
_SCAN_SYSTEM_DISPATCH = (
    "You are the Scanner agent in a penetration-testing platform. auto_execute is "
    "ON, so you may launch discovery and enumeration scans with the start_* tools. "
    "Before choosing, call get_tool_recommendations(service, port) for the "
    "services you found — it returns the specific tools, command templates and "
    "methodology for each, which is how you pick the right scan rather than a "
    "generic one. "
    "Rules: launch only against the session's target; prefer one or two scans that "
    "add the most information over a broad sweep; never launch the same scan twice; "
    "a tool that answers 'not in the configured scope' is REFUSED — do not retry it "
    "or try a variant of the target, report it. Do not wait for jobs to finish. "
    "Finish by replying with what you dispatched (tool, target, job id) and what "
    "you deliberately did not."
)
_ANALYZE_SYSTEM = (
    "You are the Analyzer agent in a penetration-testing platform. Use the "
    "read-only tools to review the findings held for this target and reply with an "
    "analysis: the highest-value findings by exploitability (not just severity), "
    "which services they sit on, any credible attack chains, and which findings "
    "have known public exploits. Do NOT launch scans or exploits."
)
_EXPLOIT_SYSTEM = (
    "You are the Exploit agent in a penetration-testing platform. Identify the "
    "single best-evidenced exploitation candidate for this target from existing "
    "findings, then call queue_exploit_for_approval EXACTLY ONCE for it — a human "
    "operator reviews and approves before anything executes, and you must never "
    "execute anything yourself. If no candidate is well-evidenced enough to be "
    "worth an operator's time, queue nothing and say so. Reply with the candidate, "
    "the pending exploit id you queued (if any), and your reasoning."
)


# ── operator-editable prompts ────────────────────────────────────────────────
# The phase prompts above are DEFAULTS. `agent_config.SYSTEM_MESSAGES` plus the
# active `prompt_configs` row is what the Prompt Config UI edits, and AutoGen's
# PentestTeam overlaid it per key. Reading it here keeps that UI live: without
# this, retiring AutoGen would have turned every saved prompt customisation into
# a store-only setting that silently changed nothing.
#
# Per-key overlay, not replacement, so a config defining only "coordinator"
# leaves the other phases on their defaults.
_PHASE_PROMPT_KEY = {
    "Reconnaissance": "reconnaissance",
    "Scanner": "scanner",
    "Analyzer": "analyzer",
    "Exploit": "exploit",
    "Reporter": "reporter",
}


def _prompt_for(agent_name: str, default: str) -> str:
    """The active operator prompt for a phase, else the engine default.

    Appended to the phase default rather than replacing it: the defaults carry
    the LangGraph-specific contract (which tools exist, that dispatch is
    forbidden in a read-only phase, that the agent must not execute an exploit).
    An operator prompt that replaced them outright could talk an agent out of a
    safety property, which is not something a prompt field should be able to do.
    """
    key = _PHASE_PROMPT_KEY.get(agent_name)
    if not key:
        return default
    try:
        from db_utils import get_active_prompt_config
        active = get_active_prompt_config()
        prompts = (active or {}).get("prompts") or {}
        extra = prompts.get(key)
        if isinstance(extra, str) and extra.strip():
            return (f"{default}\n\n[operator prompt: "
                    f"{(active or {}).get('name') or 'active config'}]\n{extra.strip()}")
    except Exception as e:  # noqa: BLE001
        _log.warning("could not read the active prompt config: %s", e)
    return default


# ── LLM client + metrics parity ──────────────────────────────────────────────
def _chat_model():
    """A LangChain chat model targeting the SAME active backend AutoGen uses
    (get_llm_config resolves dashboard-DB over env: Azure DeepSeek here)."""
    from agent_config import get_llm_config
    cfg = (get_llm_config() or [{}])[0]
    at = (cfg.get("api_type") or "openai").lower()
    model, base_url, api_key = cfg.get("model"), cfg.get("base_url"), cfg.get("api_key")
    temperature = cfg.get("temperature", 0.1)
    timeout = cfg.get("timeout", 120)
    if at == "azure":
        from langchain_openai import AzureChatOpenAI
        return AzureChatOpenAI(azure_endpoint=base_url, api_key=api_key,
                               api_version=cfg.get("api_version"),
                               azure_deployment=model, temperature=temperature,
                               timeout=timeout, max_retries=1)
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(model=model, base_url=base_url, api_key=api_key,
                      temperature=temperature, timeout=timeout, max_retries=1)


def metrics_callback(session_id: str, agent_name: str):
    """A LangChain callback handler writing the SAME `llm_request_metrics` rows
    AutoGen's `llm_metrics` monkeypatch writes.

    Without this, flipping AGENT_ENGINE to langgraph would silently empty the LLM
    cost/latency dashboards — the metrics table is fed by an AutoGen-specific
    patch on OpenAIWrapper.create that a LangChain client never goes through.
    The row keys must stay identical to `llm_metrics._patched_create`'s.
    """
    from langchain_core.callbacks import BaseCallbackHandler
    from llm_metrics import LLMMetricsContext

    class _Handler(BaseCallbackHandler):
        def __init__(self):
            self._started: Dict[str, float] = {}
            self._model: Dict[str, str] = {}

        # on_chat_model_start fires for chat models; on_llm_start for completions.
        def _start(self, serialized, run_id, invocation_params=None):
            self._started[str(run_id)] = time.time()
            params = invocation_params or {}
            self._model[str(run_id)] = (params.get("model")
                                        or params.get("azure_deployment")
                                        or params.get("model_name") or "unknown")

        def on_chat_model_start(self, serialized, messages, *, run_id=None, **kw):
            self._start(serialized, run_id, kw.get("invocation_params"))

        def on_llm_start(self, serialized, prompts, *, run_id=None, **kw):
            self._start(serialized, run_id, kw.get("invocation_params"))

        def _record(self, run_id, *, usage=None, tool_names=None,
                    is_error=False, error_message=None):
            key = str(run_id)
            started = self._started.pop(key, None)
            model = self._model.pop(key, "unknown")
            latency_ms = round((time.time() - started) * 1000, 2) if started else 0.0
            usage = usage or {}
            names = [n for n in (tool_names or []) if n]
            try:
                LLMMetricsContext.record_request({
                    "session_id": session_id,
                    "agent_name": agent_name,
                    "model_name": model,
                    "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens"),
                    "latency_ms": latency_ms,
                    "has_tool_calls": bool(names),
                    "tool_call_count": len(names),
                    "tool_names": names or None,
                    "is_error": is_error,
                    "error_message": error_message,
                    "request_params": json.dumps({"model": model, "engine": ENGINE_NAME}),
                })
            except Exception:
                pass

        def on_llm_end(self, response, *, run_id=None, **kw):
            usage, names = {}, []
            try:
                out = getattr(response, "llm_output", None) or {}
                tu = out.get("token_usage") or out.get("usage") or {}
                usage = {
                    "prompt_tokens": tu.get("prompt_tokens") or tu.get("input_tokens"),
                    "completion_tokens": tu.get("completion_tokens") or tu.get("output_tokens"),
                    "total_tokens": tu.get("total_tokens"),
                }
                for gen_list in (getattr(response, "generations", None) or []):
                    for gen in gen_list:
                        msg = getattr(gen, "message", None)
                        # langchain-core 1.x puts usage on the message when the
                        # provider does not populate llm_output.
                        um = getattr(msg, "usage_metadata", None) or {}
                        if um and not usage.get("total_tokens"):
                            usage = {
                                "prompt_tokens": um.get("input_tokens"),
                                "completion_tokens": um.get("output_tokens"),
                                "total_tokens": um.get("total_tokens"),
                            }
                        for tc in (getattr(msg, "tool_calls", None) or []):
                            names.append(tc.get("name") if isinstance(tc, dict) else None)
            except Exception:
                pass
            self._record(run_id, usage=usage, tool_names=names)

        def on_llm_error(self, error, *, run_id=None, **kw):
            self._record(run_id, is_error=True,
                         error_message=f"{type(error).__name__}: {str(error)[:500]}")

    return _Handler()


def _tools_for(names) -> List[Any]:
    """The LangChain-wrapped registry tools whose names are in `names`."""
    import langgraph_tools as lt
    return lt.tools_named(names)


# ── state ────────────────────────────────────────────────────────────────────
class PentestState(TypedDict):
    session_id: str
    target: str
    task: str
    auto_execute: bool
    exploit_phase: bool
    phase: str
    findings: Annotated[List[str], operator.add]
    log: Annotated[List[str], operator.add]
    exploit_candidate: Optional[str]
    exploit_decision: Optional[dict]
    # Surface-test phase (opt-in, independent of exploit_phase).
    surface_test_phase: bool
    surface_synthesize: Optional[bool]
    surface_auto_exploit: Optional[bool]
    surface_target_request: Optional[str]
    surface_target: Optional[str]
    surface_tests: Optional[list]
    surface_safe_results: Optional[list]
    pending_surface_tests: Optional[list]
    surface_decision: Optional[dict]
    report: Optional[str]


# ── side effects (same sinks AutoGen writes to) ──────────────────────────────
def _sid(session_id) -> uuid.UUID:
    return session_id if isinstance(session_id, uuid.UUID) else uuid.UUID(str(session_id))


# The session transcript, in the shape session_collector expects
# ({"name", "content"}). Kept alongside the DB writes because
# collect_session_outputs takes the conversation as a list — the AutoGen path
# handed it `groupchat.messages`, and without an equivalent here every LangGraph
# session silently wrote no session directory to disk.
_transcript: List[dict] = []


def _msg(session_id, agent: str, content: str, role: str = "assistant") -> None:
    """Persist a session message (same table + shape the UI reads)."""
    body = (content or "")[:_MSG_CAP]
    _transcript.append({"name": agent, "role": role, "content": body})
    try:
        add_agent_message(_sid(session_id), agent, role, body)
    except Exception:
        pass


def _emit(event_type: str, session_id, data: dict) -> None:
    """Every node action emits a webhook event — visible in the Agent Activity
    timeline, tagged with the engine so AutoGen vs LangGraph runs are comparable."""
    try:
        import httpx
        rag = os.environ.get("RAG_API_URL", "https://rag-api:8000")
        key = os.environ.get("API_KEY", "changeme")
        httpx.post(f"{rag}/webhooks/emit",
                   json={"event_type": event_type, "source": "langgraph-agent",
                         "data": {"session_id": str(session_id), "engine": ENGINE_NAME, **data}},
                   headers={"x-api-key": key}, verify=False, timeout=10)
    except Exception:
        pass


def _tool(fn, *args, **kwargs) -> str:
    """Call a scan_tools body defensively — a tool error becomes a logged line,
    never a crashed graph."""
    try:
        return str(fn(*args, **kwargs))
    except Exception as e:  # noqa: BLE001
        return f"[tool {getattr(fn, '__name__', 'fn')} error: {e}]"


# ── the generic LLM phase ────────────────────────────────────────────────────
# `recursion_limit` counts graph super-steps, and one tool-using turn costs TWO
# (LLM, then ToolNode) — so a budget of 14 is only ~7 tool rounds. The analyze
# phase hit that ceiling on its first live run and returned LangGraph's
# "Sorry, need more steps to process this request." in place of an analysis,
# which reads like a model refusal rather than a budget. Sized per phase from
# observed tool use: analyze made 10 calls.
PHASE_STEP_BUDGET = {
    "Reconnaissance": 20,
    "Scanner": 16,          # 24 with dispatch tools, see scan()
    "Analyzer": 26,
    "Exploit": 22,
}
# LangGraph's own message when the step budget runs out. Surfaced explicitly
# rather than persisted as if it were the agent's answer.
_STEP_LIMIT_MARKER = "need more steps"


# Rate-limit backoff knobs. A 429 is a "come back later", not a failure — waiting
# it out keeps the LLM phase (recon/analyze) alive instead of silently degrading
# to the deterministic summary. Waits are exponential with a ceiling and honour a
# server-supplied Retry-After when present. Tunable via env so an operator can
# match their provider's quota without a code change (defined in .env and the
# autogen-agents service env in docker-compose.yml). `or` guards the empty-string
# trap: a set-but-blank env var must fall through to the default, not parse to 0.
def _env_num(name: str, default: float, cast=float):
    try:
        return cast(os.environ.get(name) or default)
    except (TypeError, ValueError):
        logger.warning("bad %s=%r; using default %s", name,
                       os.environ.get(name), default)
        return cast(default)


_LLM_RATELIMIT_MAX_RETRIES = _env_num("LLM_RATELIMIT_MAX_RETRIES", 4, int)
_LLM_RATELIMIT_BASE_WAIT = _env_num("LLM_RATELIMIT_BASE_WAIT", 5.0)   # sec; 5,10,20,40…
_LLM_RATELIMIT_MAX_WAIT = _env_num("LLM_RATELIMIT_MAX_WAIT", 60.0)
# Self-tuning: watch observed 429s and adapt. On by default; costs nothing when
# the provider is healthy because the pacing interval decays back to zero.
_LLM_RATELIMIT_ADAPTIVE = (os.environ.get("LLM_RATELIMIT_ADAPTIVE") or "true").lower() \
    not in ("0", "false", "no", "off")


class _RateLimitGovernor:
    """Process-wide adaptive throttle (AIMD) shared across concurrent sessions.

    - `pace()` sleeps just enough to honour the current min-interval before a
      call, so a spike of 429s spaces subsequent calls out proactively.
    - `on_rate_limit()` multiplicatively *raises* the interval and remembers the
      server's Retry-After as the effective backoff base — the provider telling
      us its real rate beats any hard-coded guess.
    - `on_success()` additively *lowers* the interval, so once the provider is
      happy the added latency bleeds off and steady-state overhead returns to 0.
    This adapts to the quota actually in force without a redeploy; the static
    env knobs remain the ceiling.
    """

    def __init__(self):
        import threading
        self._lock = threading.Lock()
        self._interval = 0.0           # current min seconds between calls
        self._last_call = 0.0          # monotonic ts of the last paced call
        self._base_wait = _LLM_RATELIMIT_BASE_WAIT  # learned backoff base
        # Bounds derived from the static knobs so self-tuning can never exceed
        # what the operator declared as the ceiling.
        self._interval_cap = _LLM_RATELIMIT_MAX_WAIT
        self._decay = 1.0              # subtract per healthy call
        self._grow = 2.0               # multiply on a 429

    def pace(self):
        if not _LLM_RATELIMIT_ADAPTIVE:
            return
        with self._lock:
            interval = self._interval
            last = self._last_call
        if interval > 0:
            wait = last + interval - time.monotonic()
            if wait > 0:
                time.sleep(min(wait, self._interval_cap))
        with self._lock:
            self._last_call = time.monotonic()

    def on_success(self):
        if not _LLM_RATELIMIT_ADAPTIVE:
            return
        with self._lock:
            if self._interval > 0:
                self._interval = max(0.0, self._interval - self._decay)

    def on_rate_limit(self, server_wait: Optional[float]):
        """Record a 429. Returns the effective wait to use for THIS retry."""
        if not _LLM_RATELIMIT_ADAPTIVE:
            return server_wait
        with self._lock:
            if server_wait and server_wait > 0:
                # Trust the server's stated cool-down as the new backoff base.
                self._base_wait = min(server_wait, self._interval_cap)
            # Grow the proactive spacing (additive floor so the first 429 from a
            # zero interval still moves it off the floor).
            self._interval = min(self._interval_cap,
                                 max(self._base_wait, self._interval * self._grow
                                     if self._interval > 0 else self._base_wait))
            return self._base_wait

    def base_wait(self) -> float:
        with self._lock:
            return self._base_wait


_rl_governor = _RateLimitGovernor()


def _is_rate_limit_error(exc: Exception) -> Optional[float]:
    """If `exc` looks like a rate-limit (429), return the seconds to wait
    (server Retry-After if we can read one, else None). Otherwise return -1."""
    # openai/azure raise RateLimitError with .status_code == 429; other stacks
    # bury it in the message. Match on both so we don't depend on one client.
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    text = str(exc).lower()
    looks_ratelimited = (
        status == 429
        or "429" in text
        or "rate limit" in text
        or "ratelimit" in text
        or "too many requests" in text
    )
    if not looks_ratelimited:
        return -1.0
    # Try to read Retry-After from an attached response/headers.
    retry_after = None
    resp = getattr(exc, "response", None)
    hdrs = getattr(resp, "headers", None) if resp is not None else None
    if hdrs:
        try:
            ra = hdrs.get("retry-after") or hdrs.get("Retry-After")
            if ra is not None:
                retry_after = float(ra)
        except (TypeError, ValueError):
            retry_after = None
    return retry_after  # None → caller uses exponential backoff


def _invoke_with_backoff(agent, payload, config, *, session_id=None,
                         agent_name: str = "") -> Any:
    """Call `agent.invoke`, retrying on rate-limit (429) with exponential
    backoff (honouring Retry-After). Re-raises non-rate-limit errors immediately
    and re-raises the last 429 once retries are exhausted so the caller can fall
    back deterministically."""
    attempt = 0
    while True:
        _rl_governor.pace()   # proactive spacing (no-op once the provider is healthy)
        try:
            out = agent.invoke(payload, config)
            _rl_governor.on_success()
            return out
        except Exception as exc:  # noqa: BLE001
            server_wait = _is_rate_limit_error(exc)
            if server_wait == -1.0 or attempt >= _LLM_RATELIMIT_MAX_RETRIES:
                raise
            # Let the governor learn from this 429 and hand back the base wait it
            # now trusts (the server's Retry-After if it gave one).
            learned = _rl_governor.on_rate_limit(server_wait)
            if server_wait is not None:
                wait = server_wait
            else:
                base = learned if learned and learned > 0 else _LLM_RATELIMIT_BASE_WAIT
                wait = min(base * (2 ** attempt), _LLM_RATELIMIT_MAX_WAIT)
            attempt += 1
            logger.warning(
                "%s rate-limited (429); backing off %.0fs before retry %d/%d",
                agent_name or "LLM", wait, attempt, _LLM_RATELIMIT_MAX_RETRIES)
            if session_id is not None:
                try:
                    _msg(session_id, agent_name or "LLM",
                         f"[rate-limited: waiting {wait:.0f}s before retry "
                         f"{attempt}/{_LLM_RATELIMIT_MAX_RETRIES}]")
                except Exception:  # noqa: BLE001
                    pass
            time.sleep(wait)


def _llm_phase(session_id, *, agent_name: str, system: str, tool_names,
               task: str, recursion_limit: int = 20):
    """Run one phase as an LLM agent (LLM ↔ ToolNode) over `tool_names`.

    Returns (final_text, tools_used). Raises on LLM/tool-binding failure so the
    caller can fall back to its deterministic path — a session must never hard-
    fail because a model was rate-limited.
    """
    # create_react_agent moves to langchain.agents.create_agent in langgraph v2;
    # requirements pin langgraph<2 so this stays valid. Swap when we add the
    # langchain meta-package.
    from langgraph.prebuilt import create_react_agent
    tools = _tools_for(tool_names)
    agent = create_react_agent(_chat_model(), tools,
                               prompt=_prompt_for(agent_name, system))
    out = _invoke_with_backoff(
        agent,
        {"messages": [("user", task)]},
        {"recursion_limit": recursion_limit,
         "callbacks": [metrics_callback(str(session_id), agent_name)]},
        session_id=session_id, agent_name=agent_name,
    )
    msgs = out.get("messages", [])
    tools_used, final = [], ""
    for m in msgs:
        for c in (getattr(m, "tool_calls", None) or []):
            tools_used.append(c.get("name"))
    for m in reversed(msgs):
        if getattr(m, "type", None) == "ai" and (getattr(m, "content", "") or "").strip():
            final = m.content
            break
    if _STEP_LIMIT_MARKER in (final or "").lower():
        final = (f"[TRUNCATED — the {agent_name} agent used its whole step budget "
                 f"({recursion_limit} super-steps, {len(tools_used)} tool calls) "
                 f"before summarising. The tool results above are real; this "
                 f"phase has no written conclusion.]\n{final}")
    return final, [t for t in tools_used if t]


def _phase_result(session_id, agent_name: str, phase: str, next_phase: str,
                  final: str, used: List[str], header: str = "") -> dict:
    distinct = sorted(set(used))
    _msg(session_id, agent_name,
         f"{header}[LLM {phase}] tools used: {', '.join(distinct) or 'none'}\n\n{final[:1800]}")
    _emit("langgraph_phase_completed", session_id,
          {"phase": phase, "mode": "llm", "tools_used": distinct})
    return {"phase": next_phase,
            "findings": [f"{phase}(llm): {len(used)} tool call(s), {len(distinct)} distinct"],
            "log": [f"{phase}(llm): {distinct}"]}


# ── nodes ────────────────────────────────────────────────────────────────────
def recon(state: PentestState) -> dict:
    """LLM recon over read-only tools (Phase 3 cutover)."""
    sid = state["session_id"]
    try:
        task = (f"Target: {state['target'][:300]}\nTask: {state['task'][:300]}\n"
                "Enumerate the known assets, open ports and existing findings, "
                "then summarize.")
        final, used = _llm_phase(sid, agent_name="Reconnaissance",
                                 system=_RECON_SYSTEM, tool_names=RECON_TOOLS,
                                 task=task,
                                 recursion_limit=PHASE_STEP_BUDGET["Reconnaissance"])
        return _phase_result(sid, "Reconnaissance", "recon", "scan", final, used)
    except Exception as e:  # noqa: BLE001
        _emit("langgraph_phase_completed", sid,
              {"phase": "recon", "mode": "fallback", "error": str(e)[:200]})
        return _recon_deterministic(state, note=f"[LLM recon unavailable: {e}] ")


def _recon_deterministic(state: PentestState, note: str = "") -> dict:
    """Read-only recon without an LLM — the fallback so a session never hard-fails."""
    sid = state["session_id"]
    assets = _tool(scan_tools.query_assets, limit=25)
    ports = _tool(scan_tools.query_open_ports, limit=50)
    _msg(sid, "Reconnaissance",
         f"{note}Assets:\n{assets[:1400]}\n\nOpen ports:\n{ports[:1400]}")
    return {"phase": "scan",
            "findings": ["recon(deterministic)"],
            "log": [f"recon deterministic{' — ' + note if note else ''}"]}


def scan(state: PentestState) -> dict:
    """LLM scan phase (Phase 4 cutover).

    The toolset — not the prompt — is what enforces the auto_execute contract:
    with auto_execute off the agent is given NO start_* tool, so it cannot
    dispatch even if it decides to. With it on, every start_* body is the same
    scope-gated, MAX_CONCURRENT_SCANS-bounded function AutoGen calls.
    """
    sid = state["session_id"]
    auto = bool(state.get("auto_execute"))
    names = SCAN_TOOLS_READONLY | (SCAN_TOOLS_DISPATCH if auto else set())
    system = _SCAN_SYSTEM_DISPATCH if auto else _SCAN_SYSTEM_PLAN
    try:
        task = (f"Target: {state['target'][:300]}\nTask: {state['task'][:300]}\n"
                f"auto_execute={'ON' if auto else 'OFF'}. Decide what to scan next"
                f"{' and launch it' if auto else ''}.")
        final, used = _llm_phase(sid, agent_name="Scanner", system=system,
                                 tool_names=names, task=task,
                                 recursion_limit=(24 if auto
                                                  else PHASE_STEP_BUDGET["Scanner"]))
        dispatched = sorted({t for t in used if t.startswith("start_")})
        # Append the deterministic plan regardless of what the model produced.
        # Observed twice on one afternoon: the scan agent was rate-limited (429)
        # and fell back, then on the retry it ran fine, never called
        # get_tool_recommendations, and answered "No results yet for redteam3
        # specifically". Concrete tests should not depend on the model choosing
        # to ask for them — the open services are already known, so the plan is
        # cheap and always groundable.
        plan_text, planned = _build_test_plan()
        if planned:
            final = (f"{final}\n\n---\nConcrete tests for the "
                     f"{planned} discovered service(s):\n\n{plan_text}")
        res = _phase_result(sid, "Scanner", "scan", "analyze", final, used)
        res["log"] = [f"scan(llm): dispatched={dispatched} tools={sorted(set(used))}"]
        _emit("langgraph_scan_dispatched", sid,
              {"phase": "scan", "auto_execute": auto, "dispatched": dispatched})
        return res
    except Exception as e:  # noqa: BLE001
        _emit("langgraph_phase_completed", sid,
              {"phase": "scan", "mode": "fallback", "error": str(e)[:200]})
        return _scan_deterministic(state, note=f"[LLM scan unavailable: {e}] ")


# Services that ARE TLS by definition. Note what is absent: port numbers.
# Transport is a property of the connection, not of the port — TLS turns up on
# 8443, 9443, 10443 and arbitrary ports, and plaintext turns up on 443.
# Web-ish service names, for deciding whether "probe both schemes" advice makes
# sense. Mirrors the http family in scan_recommender/exploits_rag.py.
_SERVICE_FAMILIES_WEB = {
    "http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http", "www",
    "http-mgmt", "webcache",
}

_TLS_SERVICE_NAMES = {
    "https", "https-alt", "imaps", "smtps", "ldaps", "ftps", "pop3s", "nntps",
    "ircs", "dot", "sips", "telnets", "rdps", "ssl/http",
}


def _tls_state(service: str, product: str = "", banner: str = "") -> str:
    """'yes' or 'unknown' — never inferred from the port number.

    Deliberately has no port heuristic. This dataset holds 260 rows recorded as
    `http` on port 443 (Apache, Azure Application Gateway, Cloudflare) with NO
    tunnel or TLS field captured anywhere in the row, and 0 rows whose banner
    mentions tls/ssl. So the port would be the only "evidence" available, and it
    is exactly the assumption that produces `nikto -h http://host:443` against a
    TLS listener — a command that fails and tells the operator nothing.

    'unknown' is an honest answer that the plan can act on (probe both), where a
    guess is not.
    """
    svc = (service or "").strip().lower()
    if "ssl" in svc or "tls" in svc:
        return "yes"
    if svc in _TLS_SERVICE_NAMES:
        return "yes"
    blob = f"{product or ''} {banner or ''}".lower()
    if "ssl" in blob or "tls" in blob:
        return "yes"
    return "unknown"


# How many distinct (service, port) pairs the deterministic planner will build
# tests for. Bounded because each one is an HTTP call to the recommender.
_DETERMINISTIC_PLAN_LIMIT = 8


def _build_test_plan(_unused_target: str = "") -> "tuple[str, int]":
    """Concrete, runnable tests for the services already discovered.

    Returns (plan_text, service_count). No LLM: the platform already knows the
    open services, and get_tool_recommendations returns the tools, command
    templates, nuclei tags and ingested methodology for each. That is enough to
    write the plan.

    The `{target}` placeholder is filled from the PORT ROW's ip, never from the
    session's target_description. The description is a human label — filling it
    in produced `sslscan redteam3 web hosts:443`, which reads like a command and
    cannot be run. Each row already carries the host the service was found on.
    """
    hosts: dict = {}
    plan = []
    try:
        ports = json.loads(_tool(scan_tools.query_open_ports, limit=100))
        items = ports.get("items") or []
    except Exception:  # noqa: BLE001
        items = []
    _plat = _infer_target_platform(items)

    # Group by (service, port), remembering one real host and how many share it.
    for row in items:
        svc = (row.get("service") or "").strip().lower()
        port, ip = row.get("port"), row.get("ip")
        if not svc or not ip:
            continue
        entry = hosts.setdefault((svc, port), {"ip": ip, "count": 0, "tls": "unknown"})
        entry["count"] += 1
        # Any row in the group proving TLS proves it for the group.
        if _tls_state(svc, row.get("product"), row.get("banner")) == "yes":
            entry["tls"] = "yes"

    for (svc, port), info in list(hosts.items())[:_DETERMINISTIC_PLAN_LIMIT]:
        target = info["ip"]
        tls = info["tls"]
        try:
            rec = json.loads(_tool(scan_tools.get_tool_recommendations,
                                   service=svc, port=port))
        except Exception:  # noqa: BLE001
            continue
        tools = rec.get("tools") or []
        if not tools and not rec.get("nuclei_tags"):
            continue
        extra = (f" ({info['count']} hosts; example {target})"
                 if info["count"] > 1 else f" ({target})")
        lines = [f"### {svc}/{port} — {rec.get('description') or svc}{extra}"]
        for t in tools[:4]:
            cmd = (t.get("command") or "").replace("{target}", target)
            lines.append(f"  - {t.get('name')}: {t.get('purpose')}\n    $ {cmd}")
        if rec.get("nuclei_tags"):
            lines.append(f"  - nuclei tags: {', '.join(rec['nuclei_tags'][:8])}")
        for m in _rank_msf(rec.get("metasploit"), platform=_plat):
            lines.append(f"  - msf: {m.get('module')} — {m.get('purpose')}")
        if rec.get("common_vulns"):
            lines.append(f"  - watch for: {'; '.join(rec['common_vulns'][:4])}")

        # Transport is its own axis. The commands above came from the service
        # name, which does not say whether the connection is wrapped in TLS —
        # and the port does not say it either. Where TLS is confirmed or merely
        # possible, name the TLS tooling explicitly rather than letting a plan
        # go out that only probes one scheme.
        web = svc in _SERVICE_FAMILIES_WEB
        if tls == "yes":
            lines.append(
                f"  - transport: TLS (from the service name/banner). Use "
                f"https:// for web tooling and run the TLS checks: "
                f"sslscan {target}:{port} / testssl.sh {target}:{port} / "
                f"sslyze {target}:{port}")
        elif web:
            lines.append(
                f"  - transport: UNCONFIRMED — nothing in the record says "
                f"whether this is TLS, and the port is not evidence. Probe both "
                f"before committing: "
                f"curl -sI http://{target}:{port}/ and "
                f"curl -skI https://{target}:{port}/ ; if TLS answers, redo the "
                f"web commands above with https:// and add "
                f"sslscan {target}:{port} / testssl.sh {target}:{port}")
        else:
            lines.append(
                f"  - transport: not established as TLS. If this service can be "
                f"TLS-wrapped (many are, on any port), confirm with "
                f"`openssl s_client -connect {target}:{port}` and add "
                f"testssl.sh {target}:{port} when it negotiates")
        plan.append("\n".join(lines))

    return "\n\n".join(plan), len(plan)


def _scan_deterministic(state: PentestState, note: str = "") -> dict:
    """Build a concrete test plan WITHOUT an LLM. Never dispatches.

    This used to ask get_scan_recommendations (free text -> a paragraph) and
    paste the paragraph. When the model is rate-limited — which is exactly when
    this path runs — that paragraph was often "I cannot determine the specific
    services", i.e. the fallback produced nothing usable at the moment it
    mattered most.

    The platform already knows the open services; it does not need a model to
    list them. So walk the discovered (service, port) pairs and ask
    get_tool_recommendations for each: that returns the tools, ready command
    templates, nuclei tags and the ingested methodology for that service. The
    result is an actionable test plan an operator (or the next agent phase) can
    run, produced deterministically and with no LLM involved.
    """
    sid = state["session_id"]
    plan_text, planned = _build_test_plan()

    if planned:
        body = (f"{note}Test plan built from {planned} discovered service(s) "
                f"— no LLM required.\n\n" + plan_text)
        summary = f"scan(deterministic): {planned} service(s) planned"
    else:
        # Nothing discovered yet, so fall back to the free-text recommender.
        ctx = f"target={state['target'][:200]} task={state['task'][:200]}"
        body = (f"{note}No open services on record to plan against yet.\n\n"
                f"{_tool(scan_tools.get_scan_recommendations, ctx)[:1500]}")
        summary = "scan(deterministic): no services, asked the recommender"

    _msg(sid, "Scanner", body[:_MSG_CAP] +
         "\n\nDispatch: skipped (deterministic planner recommends only).")
    _emit("langgraph_phase_completed", sid,
          {"phase": "scan", "mode": "fallback", "services_planned": planned})
    return {"phase": "analyze",
            "findings": [summary],
            "log": [f"scan deterministic: planned {planned} service(s)"]}


def analyze(state: PentestState) -> dict:
    """LLM analysis over the findings we hold (Phase 4 cutover)."""
    sid = state["session_id"]
    try:
        task = (f"Target: {state['target'][:300]}\nTask: {state['task'][:300]}\n"
                "Review the findings held for this target and give the analysis.")
        final, used = _llm_phase(sid, agent_name="Analyzer", system=_ANALYZE_SYSTEM,
                                 tool_names=ANALYZE_TOOLS, task=task,
                                 recursion_limit=PHASE_STEP_BUDGET["Analyzer"])
        return _phase_result(sid, "Analyzer", "analyze", "exploit", final, used)
    except Exception as e:  # noqa: BLE001
        _emit("langgraph_phase_completed", sid,
              {"phase": "analyze", "mode": "fallback", "error": str(e)[:200]})
        return _analyze_deterministic(state, note=f"[LLM analyze unavailable: {e}] ")


def _analyze_deterministic(state: PentestState, note: str = "") -> dict:
    sid = state["session_id"]
    vulns = _tool(scan_tools.query_vulnerabilities, limit=50)
    web = _tool(scan_tools.get_web_findings, limit=50)
    _msg(sid, "Analyzer", f"{note}Vulnerabilities:\n{vulns[:1500]}\n\nWeb findings:\n{web[:1500]}")
    _emit("langgraph_phase_completed", sid, {"phase": "analyze", "mode": "fallback"})
    return {"phase": "exploit",
            "findings": ["analyze(deterministic): vulns + web findings reviewed"],
            "log": ["analyze deterministic: query_vulnerabilities + get_web_findings"]}


def exploit_plan(state: PentestState) -> dict:
    """Pick a candidate and queue it for approval. Read-only + a pending_exploits
    row; nothing is executed here.

    This is deliberately a SEPARATE node from the interrupt: a node containing
    interrupt() re-runs from its start when the graph resumes, so any side effect
    in front of the interrupt would happen twice (a duplicate queued exploit, a
    second LLM bill). Side effects live here; the interrupt node has none before
    it pauses.
    """
    sid = state["session_id"]
    try:
        task = (f"Target: {state['target'][:300]}\nTask: {state['task'][:300]}\n"
                f"Session id (pass as session_id when queueing): {sid}\n"
                "Identify the best exploitation candidate and queue it for "
                "operator approval.")
        final, used = _llm_phase(sid, agent_name="Exploit", system=_EXPLOIT_SYSTEM,
                                 tool_names=EXPLOIT_PLAN_TOOLS, task=task,
                                 recursion_limit=PHASE_STEP_BUDGET["Exploit"])
        queued = "queue_exploit_for_approval" in used
        distinct = sorted(set(used))
        _msg(sid, "Exploit",
             f"[LLM exploit planning] tools used: {', '.join(distinct) or 'none'}\n\n"
             f"{final[:1800]}")
        _emit("langgraph_phase_completed", sid,
              {"phase": "exploit_plan", "mode": "llm", "queued": queued,
               "tools_used": distinct})
        return {"phase": "exploit_approval" if queued else "report",
                "exploit_candidate": final[:2000] if queued else None,
                "findings": [f"exploit_plan(llm): queued={queued}"],
                "log": [f"exploit_plan(llm): queued={queued} tools={distinct}"]}
    except Exception as e:  # noqa: BLE001
        # No candidate, no interrupt — an LLM outage must not park a session
        # waiting for approval of something that was never queued.
        _emit("langgraph_phase_completed", sid,
              {"phase": "exploit_plan", "mode": "fallback", "error": str(e)[:200]})
        _msg(sid, "Exploit", f"[LLM exploit planning unavailable: {e}] "
                             "No candidate queued; skipping the approval gate.")
        return {"phase": "report", "exploit_candidate": None,
                "findings": ["exploit_plan: skipped (LLM unavailable)"],
                "log": [f"exploit_plan skipped: {e}"]}


def exploit_approval(state: PentestState) -> dict:
    """The human-in-the-loop gate: `interrupt()` parks the graph in Postgres until
    the operator answers via POST /pentest/{id}/approve.

    Override flags do NOT apply here — this gate is the operator's authorization,
    and there is no 'run anyway'. Everything before the pause lives in
    exploit_plan, so a resume re-entering this node repeats nothing.
    """
    from langgraph.types import interrupt
    decision = interrupt({
        "kind": "exploit_approval",
        "session_id": str(state["session_id"]),
        "target": state.get("target", "")[:300],
        "candidate": (state.get("exploit_candidate") or "")[:2000],
        "prompt": ("Approve execution of the queued exploit? Reply via "
                   "POST /pentest/{session_id}/approve with "
                   '{"approved": true|false, "pending_exploit_id": "<uuid>"}'),
    })
    if isinstance(decision, dict):
        approved = bool(decision.get("approved"))
        note = str(decision.get("note") or "")
        pending_id = decision.get("pending_exploit_id")
    else:
        approved, note, pending_id = bool(decision), "", None
    sid = state["session_id"]
    _msg(sid, "Exploit",
         f"[operator decision] approved={approved}"
         f"{' pending_exploit_id=' + str(pending_id) if pending_id else ''}"
         f"{chr(10) + 'note: ' + note[:500] if note else ''}",
         role="user")
    _emit("langgraph_exploit_decision", sid,
          {"approved": approved, "pending_exploit_id": str(pending_id or "")})
    return {"phase": "exploit_exec" if approved else "report",
            "exploit_decision": {"approved": approved, "note": note[:500],
                                 "pending_exploit_id": str(pending_id or "") or None},
            "findings": [f"exploit_approval: approved={approved}"],
            "log": [f"exploit_approval: approved={approved}"]}


def _mark_approved(pending_id, who: str, note: str = None) -> None:
    """Transition a pending_exploit to status='approved' so the downstream
    execute_approved_exploit (which REQUIRES that status and otherwise refuses
    "not approved") will run it. The operator's decision at the approval
    interrupt — or the auto-exploit opt-in — IS the authorization; this records
    it. execute_approved_exploit still fails closed on scope, so this can never
    turn an out-of-scope target runnable."""
    try:
        import db_utils as _du
        _du.approve_exploit(pending_id, reviewed_by=who, notes=note)
    except Exception as _e:  # noqa: BLE001
        logger.warning("approve_exploit(%s) failed: %s", pending_id, _e)


def exploit_exec(state: PentestState) -> dict:
    """Execute the operator-approved exploit through the SAME gated tool body."""
    sid = state["session_id"]
    decision = state.get("exploit_decision") or {}
    pending_id = decision.get("pending_exploit_id")
    if not pending_id:
        _msg(sid, "Exploit",
             "[approved but no pending_exploit_id supplied] Nothing executed. "
             "Re-approve with the id from list_pending_exploits.")
        _emit("langgraph_exploit_executed", sid, {"executed": False,
                                                 "reason": "no pending_exploit_id"})
        return {"phase": "report",
                "findings": ["exploit_exec: skipped (no id)"],
                "log": ["exploit_exec skipped: no pending_exploit_id"]}
    _mark_approved(pending_id, "operator (exploit approval)",
                   (state.get("exploit_decision") or {}).get("note"))
    result = _tool(scan_tools.execute_approved_exploit, pending_id)
    _msg(sid, "Exploit", f"[execute_approved_exploit {pending_id}]\n{result[:2000]}")
    _emit("langgraph_exploit_executed", sid,
          {"executed": True, "pending_exploit_id": str(pending_id)})
    return {"phase": "report",
            "findings": [f"exploit_exec: executed {pending_id}"],
            "log": [f"exploit_exec: execute_approved_exploit({pending_id})"]}


def report(state: PentestState) -> dict:
    sid = state["session_id"]
    lines = "\n".join(f"  - {f}" for f in state.get("findings", []))
    decision = state.get("exploit_decision") or {}
    rpt = (f"LangGraph pentest session summary\n"
           f"Target: {state['target'][:200]}\n"
           f"Task: {state['task'][:200]}\n"
           f"auto_execute: {bool(state.get('auto_execute'))}   "
           f"exploit phase: {bool(state.get('exploit_phase'))}\n"
           + (f"operator exploit decision: approved={decision.get('approved')}\n"
              if decision else "")
           + f"Steps:\n{lines}")
    # Phase 3: attach the FULL engagement report (findings, evidence, severity)
    # from the real generator, not just this step list. Best-effort — the step
    # summary is the fallback so a generator hiccup never fails the session.
    full = None
    try:
        import report_generator
        r = report_generator.generate_full_report(target=state.get("target"),
                                                  format="markdown")
        if isinstance(r, str):
            full = r
        elif isinstance(r, dict):
            full = r.get("markdown") or r.get("report") or r.get("content")
    except Exception as e:  # noqa: BLE001
        _msg(sid, "Reporter", f"[full report unavailable, using summary: {e}]")
    final = full if (isinstance(full, str) and full.strip()) else rpt
    if full and final is not rpt:
        final = rpt + "\n\n" + "=" * 60 + "\n\n" + final   # summary header + full report
    _msg(sid, "Reporter", final[:6000])
    _emit("langgraph_phase_completed", sid, {"phase": "report",
                                             "full_report": bool(full)})
    return {"phase": "done", "report": final, "log": ["report: composed"]}


# ── surface-test phase ───────────────────────────────────────────────────────
# Analyze ONE operator-selected host's attack surface, generate custom tests,
# and prove which are exploitable. Two lanes: SAFE tests run autonomously (via
# the scope-gated /tools/execute), IMPACTFUL tests queue for the SAME human
# approval interrupt the exploit phase uses. Every test is persisted as a
# re-runnable security_tests row with pass/fail history.

# Classification: a test is SAFE iff its category is read-only AND its tool is a
# known non-destructive tool AND it is not sourced from an exploit. Anything else
# is IMPACTFUL. The sets are ast-readable so tests/test_langgraph_phases.py pins
# them. IMPACTFUL is the safe default — a category we do not recognise is gated.
_SAFE_CATEGORIES = {
    "version_probe", "nuclei_detect", "tls_check", "lfi_read", "sqli_detect",
    "dir_enum", "banner", "http_probe", "cert_check",
    # WSTG finding-driven SAFE detection probes (curl/nuclei/sslscan only). Each
    # confirms a specific web finding without changing data or running code;
    # anything that does is IMPACTFUL (rce/sqli_dump/cred_bruteforce/upload/…).
    "xss_detect", "ssti_detect", "ssrf_detect", "xxe_detect", "redirect_check",
    "header_check", "cookie_check", "cors_check", "error_check", "method_check",
}
_IMPACTFUL_CATEGORIES = {
    "rce", "shell", "msf_exploit", "file_write", "upload", "cred_bruteforce",
    "dos", "sqli_dump", "deserialization", "webshell_upload", "edb_exploit", "idor",
}
# ExploitDB scripts to try per (product, version). Non-MSF exploit coverage.
_EDB_PER_SERVICE = int(os.environ.get("SURFACE_EDB_LIMIT", "3"))
# Read-only tools the safe lane may dispatch. The /tools/execute endpoint is the
# real authority (Metasploit excluded there); this is a conservative agent-side
# snapshot so a tool we do not list is treated as impactful (fails safe).
_SAFE_TOOL_HINTS = {
    "curl", "wget", "httpx", "nuclei", "nikto", "whatweb", "sslscan",
    "testssl.sh", "testssl", "sslyze", "gobuster", "feroxbuster", "dirb",
    "dirsearch", "ffuf", "sqlmap", "nmap", "dig", "host", "nslookup",
    "enum4linux", "enum4linux-ng", "smbmap", "smbclient", "snmpwalk",
    "onesixtyone", "ldapsearch", "dnsrecon", "dnsenum", "wafw00f", "ssh-audit",
    "nbtscan", "showmount", "rpcclient",
}
# Cap per host — this is a single-host exhaustive sweep, not the cross-host
# _DETERMINISTIC_PLAN_LIMIT that bounds recommender calls across many hosts.
# Max surface tests generated for ONE host. Deliberately high: the operator asked
# to test EVERY recommendation, so this is a runaway backstop, not a curation cap.
# Candidates are priority-sorted (real exploits + webshell first) before it bites,
# so on a pathological host the highest-value tests are the ones that survive.
_SURFACE_TEST_LIMIT = int(os.environ.get("SURFACE_TEST_LIMIT", "300"))
# How many MSF modules per service become impactful tests. Was an inline [:2]
# that truncated real exploits; high now so all recommended modules get through.
_MSF_MODULE_LIMIT = int(os.environ.get("SURFACE_MSF_LIMIT", "12"))


def _exploitdb_tests(items: list) -> list:
    """Non-MSF exploit tests: search ExploitDB by (product, version) and emit an
    IMPACTFUL test per real EDB script found. These execute via the exploit-runner
    `source=exploitdb` path (the script is LLM-customised for the target, then
    run), complementing the MSF modules — so a service with a raw PoC but no MSF
    module still gets a proof attempt. The '(Metasploit)' EDB duplicates are
    skipped (the MSF path already covers those)."""
    import httpx as _hx
    base = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")
    key = os.environ.get("API_KEY", "changeme")
    out, seen_q, seen_edb = [], set(), set()
    for row in items:
        product = (row.get("product") or "").strip()
        version = (row.get("version") or "").strip()
        port, ip = row.get("port"), row.get("ip")
        svc = (row.get("service") or "").strip().lower()
        if not product or not ip:
            continue
        # The nmap version field is often junk (UnrealIRCd's is an admin email,
        # Samba's is "3.X - 4.X"), so search by product + a CLEAN version token
        # (e.g. 2.3.4) only when one is present, else product alone.
        import re as _re
        vm = _re.search(r"\d+\.\d+(?:\.\d+)?", version or "")
        q = f"{product} {vm.group(0)}".strip() if vm else product.strip()
        if q.lower() in seen_q:
            continue
        seen_q.add(q.lower())
        try:
            r = _hx.get(f"{base}/exploitdb/search",
                        params={"q": q, "limit": 8},
                        headers={"x-api-key": key}, verify=False, timeout=15)
            results = (r.json().get("results") or []) if r.status_code < 400 else []
        except Exception:  # noqa: BLE001
            results = []
        added = 0
        for it in results:
            if added >= _EDB_PER_SERVICE:
                break
            edb = str(it.get("edb_id") or it.get("id") or "").strip()
            title = str(it.get("title") or it.get("description") or "")
            if not edb or edb in seen_edb:
                continue
            # Skip the '(Metasploit)' EDB mirrors — the MSF path already runs those.
            if "metasploit" in title.lower():
                continue
            seen_edb.add(edb)
            added += 1
            out.append({
                "name": f"exploitdb EDB-{edb}: {title[:50]} @ {ip}:{port}",
                "host": ip, "service": svc or "?", "port": port, "tool": "exploitdb",
                "command": None, "category": "edb_exploit", "tier": "impactful",
                "assertion": {"expect_regex": "(?i)(uid=[0-9]|gid=[0-9]|shell|success|root@)"},
                "exploit_ref": {"source": "exploitdb", "dispatch_source": "exploitdb",
                                "exploit_type": "rce", "module": edb, "edb_id": edb,
                                "purpose": title[:120]},
            })
    return out


def _test_priority(t: dict) -> int:
    """Lower = kept first when capping. Real exploits and the webshell rank above
    active safe probes, which rank above passive version/banner probes, which
    rank above MSF auxiliary SCANNERS (version/login/enum — lowest value)."""
    cat = t.get("category")
    ref = t.get("exploit_ref") or {}
    mod = str(ref.get("module") or "")
    if cat == "webshell_upload":
        return 0
    if cat == "msf_exploit" and mod.startswith("exploit/"):
        return 1                                   # a shell — the whole point
    if cat == "edb_exploit":
        return 1                                   # non-MSF ExploitDB script — same value
    if t.get("tier") == "impactful":
        return 2                                   # wstg/synth impactful (rce, sqli_dump…)
    if cat in ("nuclei_detect", "dir_enum", "sqli_detect", "xss_detect", "lfi_read", "cmd_injection"):
        return 3                                   # active safe detection
    if cat == "msf_exploit":
        return 6                                   # auxiliary/ scanner — lowest
    return 4                                        # version_probe / banner / tls


# Platform inference from banners (nmap rarely fills assets.os on this lab).
# Strong, low-false-positive tokens only — "microsoft" is excluded because nmap
# labels a LINUX Samba port "microsoft-ds".
_LINUX_HINTS = ("linux", "ubuntu", "debian", "unix", "smbd", "telnetd",
                "openssh", "vsftpd", "proftpd", "distcc", "postfix",
                "centos", "redhat", "fedora", ".el")
_WINDOWS_HINTS = ("windows", "win32", "win64", "microsoft iis", "microsoft-iis")
# Which MSF module platforms are INCOMPATIBLE with a given target family. The
# module platform is the 2nd path segment: exploit/<platform>/<cat>/<name>.
_PLATFORM_MISMATCH = {
    "unix": {"windows", "osx", "apple_ios", "android", "mainframe"},
    "windows": {"linux", "unix", "osx", "apple_ios", "android", "bsd", "solaris"},
}


def _infer_target_platform(items) -> Optional[str]:
    """'unix' | 'windows' | None from the host's service banners/products/os.
    None (unknown) means DON'T filter — never drop a module on a guess."""
    blob = " ".join(
        f"{r.get('product') or ''} {r.get('banner') or ''} "
        f"{r.get('version') or ''} {r.get('os') or ''}"
        for r in (items or [])).lower()
    lin = sum(blob.count(h) for h in _LINUX_HINTS)
    win = sum(blob.count(h) for h in _WINDOWS_HINTS)
    if lin > win and lin:
        return "unix"
    if win > lin and win:
        return "windows"
    return None


def _module_platform(module) -> str:
    parts = str(module or "").lower().split("/")
    return parts[1] if len(parts) >= 2 else ""


def _platform_mismatch(module, target) -> bool:
    """True when this module's platform contradicts the target family — e.g. a
    windows/smb exploit against a Linux Samba host. Unknown target or platform
    never mismatches (fail-open: we only drop a PROVEN wrong-OS module)."""
    if not target:
        return False
    return _module_platform(module) in _PLATFORM_MISMATCH.get(target, set())


def _rank_msf(mods, limit=None, platform=None):
    """Filter platform mismatches, then order real `exploit/` modules (which land
    a shell) ABOVE `auxiliary/` scanners (version/login/enum), then cap.

    The recommender lists scanners first, so a naive `[:2]` kept ftp_version +
    ftp_login and TRUNCATED OUT exploit/unix/ftp/vsftpd_234_backdoor — the actual
    RCE — at index 3. It also returns generic Windows SMB modules (ms17_010,
    ms08_067) for a Linux Samba port; `platform` drops those wrong-OS modules so
    the approval queue holds only what can actually land here."""
    def _mod(m):
        return str((m or {}).get("module") or (m or {}).get("name") or "")

    kept = [m for m in (mods or []) if not _platform_mismatch(_mod(m), platform)]

    def _rank(m):
        mod = _mod(m).lower()
        if mod.startswith("exploit/"):
            return 0
        if mod.startswith("auxiliary/"):
            return 2
        return 1
    return sorted(kept, key=_rank)[:(limit or _MSF_MODULE_LIMIT)]
# How long surface_safe_exec polls one safe test for its terminal result. Must
# exceed run_custom_test's tool timeout (300s) so slow scanners (nuclei/gobuster)
# are captured instead of recorded as empty errors. Env-tunable.
_SAFE_TEST_POLL_SECONDS = int(os.environ.get("SAFE_TEST_POLL_SECONDS", "330"))
# Opt-in LLM synthesis in the surface phase: author a custom test per web finding
# instead of the fixed WSTG-map command. Bounded (one LLM call each) and it falls
# back to the deterministic map on any failure, so it never blocks the phase.
_SYNTH_TESTS_DEFAULT = os.environ.get("LANGGRAPH_SYNTH_TESTS", "").lower() in ("1", "true", "yes")
_SURFACE_SYNTH_LIMIT = int(os.environ.get("SURFACE_SYNTH_LIMIT", "8"))


def _synthesize_finding_test(finding: dict, guidance: str, ip, port):
    """Opt-in: LLM-author a custom test for one web finding, FAIL-SAFE classified
    (test_synth.synthesize re-classifies the synthesized command). Pulls an
    ExploitDB writeup too when the finding carries a CVE. Returns a candidate test
    dict, or None on ANY failure so the caller falls back to the fixed map.

    test_synth is imported lazily (it imports this module) — safe at call time,
    a cycle at module load."""
    try:
        import test_synth
        cwe = finding.get("cwe")
        cve = None
        if isinstance(cwe, list):
            cve = next((c for c in cwe if str(c).upper().startswith("CVE-")), None)
        elif str(cwe or "").upper().startswith("CVE-"):
            cve = cwe
        g = guidance or ""
        if cve:
            try:
                ed = json.loads(scan_tools.get_exploitdb_guidance(cve=cve))
                if ed.get("matched"):
                    g = (g + "\n\n=== ExploitDB ===\n" + (ed.get("guidance") or ""))[:8000]
            except Exception:  # noqa: BLE001
                pass
        out = test_synth.synthesize(finding, g)
        if not out.get("ok"):
            return None
        spec = out["spec"]
        cmd = spec.get("command")
        if not cmd:
            return None
        tier, cat = spec.get("tier"), spec.get("category")
        return {
            "name": f"AI:{cat} @ {finding.get('url') or finding.get('target')}",
            "host": ip, "service": "http", "port": port, "tool": _tool_head(cmd),
            "command": cmd, "category": cat, "tier": tier,
            "assertion": spec.get("assertion") or {},
            "exploit_ref": ({"source": "synth", "module": (spec.get("name") or "ai-test"),
                             "purpose": spec.get("rationale")} if tier == "impactful" else None),
        }
    except Exception:  # noqa: BLE001
        return None


def _host_of(raw) -> "str | None":
    """Normalize an attack-vector `target` (host, url, or 'svc on host') to a
    host/IP suitable for query_open_ports(target=)."""
    import re as _re
    raw = str(raw or "").strip()
    if not raw:
        return None
    m = _re.search(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", raw)
    if m:
        return m.group(0)
    host = raw.split("//")[-1].split("/")[0].split(":")[0].strip()
    return host or None


def _tool_head(command: str) -> str:
    return (command or "").strip().split(" ", 1)[0].split("/")[-1].lower()


def _classify(category: str, command: str, has_exploit_ref: bool) -> str:
    """safe|impactful. SAFE requires all three: read-only category, allowlisted
    tool, no exploit source. Everything else is impactful (fails safe)."""
    if has_exploit_ref:
        return "impactful"
    if (category in _SAFE_CATEGORIES
            and _tool_head(command) in _SAFE_TOOL_HINTS):
        return "safe"
    return "impactful"


def _assertion_for(category: str, tls: str) -> dict:
    """A deterministic structured assertion per test category — the observable
    that proves the finding. Kept simple so record_test_run can evaluate it."""
    if category == "tls_check":
        return {"expect_exit_code": 0, "min_output_bytes": 40}
    if category == "lfi_read":
        return {"expect_substring": ["root:x:0:0"]}
    if category == "sqli_detect":
        return {"expect_regex": "(?i)injectable|parameter .* is vulnerable|syntax error"}
    if category == "nuclei_detect":
        return {"expect_regex": r"\[[a-z0-9-]+\]"}   # nuclei prints [template-id]
    if category in ("version_probe", "http_probe", "banner", "cert_check"):
        # A detection probe PASSES when it produced identifying output — the exit
        # code is not the signal. ssh-audit exits 3 when it FINDS weak crypto
        # (a successful probe, not a failure); testssl/sslscan and whatweb behave
        # similarly. Requiring exit 0 mislabelled a good 9.5 KB banner as "fail".
        return {"min_output_bytes": 20}
    if category == "dir_enum":
        return {"expect_regex": r"(?i)status: ?200|/[a-z0-9]"}
    return {"expect_exit_code": 0}


def _surface_categories_for(svc: str, tls: str) -> "list[tuple[str,str]]":
    """(category, tool) safe probes appropriate to a service. Deterministic; the
    concrete command comes from get_tool_recommendations where possible, else a
    sensible default here."""
    web = svc in _SERVICE_FAMILIES_WEB
    out = []
    if web:
        # whatweb, not ProjectDiscovery httpx: the kali image ships Python's
        # httpx at /usr/bin/httpx (different CLI, and not on the allowlist), so
        # an `httpx -title -tech-detect …` probe both 400s at the gate and would
        # not parse. whatweb is present, allowlisted, and gives title / server /
        # tech — exactly what http_probe asserts on.
        out += [("http_probe", "whatweb"), ("nuclei_detect", "nuclei"),
                ("dir_enum", "gobuster")]
        if tls == "yes":
            out += [("tls_check", "sslscan")]
    if svc in ("smb", "microsoft-ds", "netbios-ssn", "cifs"):
        out += [("version_probe", "enum4linux-ng")]
    if svc in ("ssh",):
        out += [("version_probe", "ssh-audit")]
    if svc in ("snmp",):
        out += [("version_probe", "snmpwalk")]
    if not out:
        out = [("banner", "nmap")]
    return out


# NSE script categories that are read-only/version-detection and safe to keep on
# a safe-lane nmap probe. Anything else (exploit, brute, dos, intrusive, or a
# service glob like `ftp-*` that pulls in ftp-vsftpd-backdoor) is stripped.
_SAFE_NSE_SCRIPTS = {"banner", "ssl-cert", "ssl-enum-ciphers", "http-title",
                     "http-headers", "http-server-header"}


def _bound_safe_command(cmd: str, ip, port) -> str:
    """Make a recommender-supplied command safe and bounded for the safe lane.

    The recommender emits aggressive nmap probes like
    `nmap -sV -sC -p 21 --script=ftp-*` for a "banner" test. `--script=ftp-*`
    pulls in exploit/brute NSE (ftp-vsftpd-backdoor et al.) — that both HANGS
    (seen: a 5-minute defunct nmap blocking the whole sequential safe lane) and
    crosses the safe/impactful line a safe test must not cross. Reduce any nmap
    command carrying `-sC`/`--script=` (unless the scripts are all in the safe
    allow-set) to a bounded version scan, and give every nmap probe a
    `--host-timeout` so one slow host cannot stall the lane.
    """
    head = _tool_head(cmd)
    if head != "nmap":
        return cmd
    import re as _re
    scripts = _re.findall(r"--script[= ]([^\s]+)", cmd)
    flat = ",".join(scripts)
    aggressive = ("-sC" in cmd.split()) or (
        flat and any(tok.strip() not in _SAFE_NSE_SCRIPTS
                     for tok in flat.split(",") if tok.strip()))
    if aggressive:
        # Rebuild as a plain, bounded version scan on the same port.
        return f"nmap -sV -Pn --host-timeout 120s -p {port} {ip}"
    if "--host-timeout" not in cmd:
        cmd = cmd.replace("nmap", "nmap --host-timeout 120s", 1)
    return cmd


# WSTG-CONF-06 — collections a PUT webshell is commonly accepted into. Kept
# permissive: a server that accepts PUT WITHOUT advertising it (Tomcat with
# readonly=false, a misconfigured upload dir, no DAV header at all) should still
# be attempted, because the gated PUT at execution is the real proof. Ordered
# roughly by how often each is writable; the deploy tries them in turn.
_DAV_CANDIDATE_PATHS = ("/dav/", "/webdav/", "/uploads/", "/upload/", "/files/",
                        "/data/", "/media/", "/images/", "/tmp/", "/")


def _webshell_ref(ip, port, scheme, paths, wid_s="WSTG-CONF-06") -> dict:
    """Build the webshell dispatch ref. `paths` is the ORDERED list of collections
    the deploy will try (permissive: it walks them until one accepts a webshell).
    `path` is kept as the first entry for back-compat with older readers."""
    paths = [p if str(p).endswith("/") else str(p) + "/" for p in (paths or ["/dav/"])]
    # exploit_type must satisfy the pending_exploits CHECK constraint; a webshell
    # upload IS a file_upload (leading to RCE). dispatch_source='webshell' is what
    # execute-by-id branches on — the exploit_type is metadata.
    return {"source": "wstg", "dispatch_source": "webshell",
            "exploit_type": "file_upload", "module": wid_s,
            "parameters": {"vector": "webdav_put", "path": paths[0],
                           "paths": paths, "scheme": scheme},
            "purpose": "WSTG-CONF-06 writable PUT/WebDAV -> webshell RCE"}


def _webshell_ref_from_url(url, ip, port, wid_s="WSTG-CONF-06") -> dict:
    """Ref for a webshell test derived from a finding URL (the WSTG map path).
    Tries the finding's own collection first, then the common candidate list."""
    scheme, path = "http", "/dav/"
    try:
        if url:
            import urllib.parse as _up
            u = _up.urlparse(url if "://" in str(url) else f"http://{url}")
            scheme = u.scheme or "http"
            p = u.path or "/dav/"
            if not p.endswith("/"):
                p = p.rsplit("/", 1)[0] + "/"
            path = p or "/dav/"
    except Exception:  # noqa: BLE001
        pass
    norm = [pp if pp.endswith("/") else pp + "/" for pp in _DAV_CANDIDATE_PATHS]
    paths = [path] + [pp for pp in norm if pp != path]
    return _webshell_ref(ip, port, scheme, paths, wid_s)


def _host_in_scope(host: str) -> bool:
    """Fail-closed scope check for a planner-time recon probe. The OPTIONS method
    test below sends real traffic, so it passes the same gate as any dispatch —
    if the scope cannot be read, refuse (return False). Uses the canonical
    one-line enforcer (connect + load + check) so this path can never drift from
    every other dispatcher's gate."""
    try:
        from etl.scope_gate import enforce_target_scope
        return enforce_target_scope(host) is None
    except Exception:  # noqa: BLE001
        return False


def _detect_webdav(scheme: str, ip, port, path: str):
    """WSTG-CONF-06 OPTIONS probe. Returns the collection path when it advertises
    WebDAV (a `DAV:` header, `MS-Author-Via`, or PUT in Allow), else None.
    Read-only — writability is proven later by the gated PUT in the exploit-runner."""
    try:
        import httpx as _hx
        url = f"{scheme}://{ip}:{port}{path}"
        with _hx.Client(verify=False, timeout=10, follow_redirects=True) as c:
            r = c.request("OPTIONS", url)
        hdr = {k.lower(): v for k, v in r.headers.items()}
        allow = (hdr.get("allow") or "").upper()
        if hdr.get("dav") or "ms-author-via" in hdr or "PUT" in allow:
            return path if path.endswith("/") else path + "/"
    except Exception:  # noqa: BLE001
        return None
    return None


def _wstg_conf06_webshell_tests(items: list) -> list:
    """WSTG-CONF-06 (Test HTTP Methods): the OWASP way this vector is found.

    The deterministic recommender is service+port-keyed (http/80 -> canned MSF
    aux modules) and never inspects the banner, so a writable WebDAV collection
    was invisible to it. This runs the actual WSTG-CONF-06 method test — a
    scope-gated OPTIONS probe on candidate collections — and, when a WebDAV
    collection answers, emits an IMPACTFUL `webshell_upload` test carrying the
    WSTG map's assertion. The PUT itself is gated: it runs only after the human
    approval interrupt, in the exploit-runner's `source=webshell` branch."""
    out, seen = [], set()
    # Assertion is fixed here rather than via get_wstg_guidance: the map's SAFE
    # `http_methods` (method_check) entry shares CWE-650 and shadows the match,
    # so a lookup would return the wrong (detection) assertion. This is the
    # impactful ESCALATION — a passing run must show command output.
    assertion = {"expect_regex": "(?i)(uid=[0-9]|gid=[0-9]|PXWEBSHELL_OK)"}
    wid_s = "WSTG-CONF-06"
    for row in items:
        svc = (row.get("service") or "").strip().lower()
        if svc not in _SERVICE_FAMILIES_WEB:
            continue
        port, ip = row.get("port"), row.get("ip")
        if not ip or (ip, port) in seen:
            continue
        seen.add((ip, port))
        if not _host_in_scope(ip):
            continue
        scheme = "https" if _tls_state(svc, row.get("product"), row.get("banner")) == "yes" else "http"
        # PERMISSIVE: emit ONE webshell candidate for EVERY in-scope web service.
        # The OPTIONS probe below only PRIORITISES which collection to try first —
        # it does not gate. A server that accepts PUT without advertising DAV/PUT
        # (Tomcat readonly=false, a stray upload dir) is still attempted; the
        # gated PUT at execution is the proof, and the deploy walks the whole
        # candidate list until one lands (or all fail cleanly).
        detected = [p if p.endswith("/") else p + "/"
                    for p in _DAV_CANDIDATE_PATHS
                    if _detect_webdav(scheme, ip, port, p)]
        norm = [p if p.endswith("/") else p + "/" for p in _DAV_CANDIDATE_PATHS]
        paths = detected + [p for p in norm if p not in detected]
        url = f"{scheme}://{ip}:{port}{paths[0]}"
        ref = _webshell_ref(ip, port, scheme, paths, wid_s)
        label = "WebDAV advertised" if detected else "PUT unadvertised — trying anyway"
        out.append({
            "name": f"WSTG-CONF-06 webshell_upload ({label}) @ {scheme}://{ip}:{port}",
            "host": ip, "service": "http", "port": port, "tool": "webshell",
            "command": None, "category": "webshell_upload", "tier": "impactful",
            "assertion": assertion,
            "exploit_ref": ref,
        })
    return out


# Parameter-name heuristics → the OWASP class each implies. Object references get
# an IDOR test; path-like params get an LFI test; EVERY param gets SQLi + XSS.
_IDOR_PARAM_NAMES = {"id", "uid", "userid", "user_id", "user", "username", "account",
                     "acct", "pid", "cid", "doc", "docid", "document_id", "file_id",
                     "fileid", "order", "order_id", "orderid", "item", "itemid",
                     "record", "rid", "object", "oid", "customer", "invoice",
                     "message", "msgid", "note", "profile", "aid", "gid", "author",
                     "blogger", "owner", "email", "member", "group", "role", "level"}
_PATH_PARAM_NAMES = {"file", "page", "path", "include", "inc", "template", "tpl",
                     "doc", "document", "dir", "folder", "load", "read", "view",
                     "download", "filename", "url", "site", "conf", "config",
                     "textfile", "text_file", "pg", "action", "cat", "lang", "style"}


# Curated list of intentionally-vulnerable / high-value web apps that generic
# wordlists (common.txt, even 43k-line raft) do NOT contain. Shipped in
# wordlists/ (bind-mounted into kali-listener at /wordlists).
_KNOWN_APPS_WORDLIST = os.environ.get(
    "KNOWN_APPS_WORDLIST", "/wordlists/known-web-apps.txt")


_WEB_PIPELINE_MAX_PORTS = int(os.environ.get("WEB_PIPELINE_MAX_PORTS", "3"))


def _ensure_web_pipeline(host: str, sid, engagement_id=None) -> dict:
    """Hands-off: auto-trigger the comprehensive web pipeline
    (Gobuster→Nikto→Playwright→Katana→ZAP→Nuclei, ZAP pre-seeded + in-scope) for a
    host's web services, so the app-layer surface (DVWA/Mutillidae params, ZAP
    alerts) is populated WITHOUT a manual step. Scope-gated; deduped (skips if a
    ZAP/katana scan produced findings for this host in the last 6h); fire-and-
    forget — the pipeline is long-running, so its findings drive the NEXT surface
    cycle (the coverage loop re-drives). Bounded to _WEB_PIPELINE_MAX_PORTS."""
    if not _host_in_scope(host):
        return {"skipped": "out-of-scope"}
    try:
        ports = json.loads(_tool(scan_tools.query_open_ports, target=host, limit=100))
        items = ports.get("items") or []
    except Exception:  # noqa: BLE001
        return {"skipped": "no ports"}
    web = [(r.get("port"), _tls_state(r.get("service"), r.get("product"), r.get("banner")))
           for r in items
           if (r.get("service") or "").strip().lower() in _SERVICE_FAMILIES_WEB and r.get("port")]
    if not web:
        return {"skipped": "no web services"}
    # Dedup: don't re-run a heavy pipeline if one recently produced findings.
    try:
        import psycopg2
        from db_utils import get_db_dsn
        with psycopg2.connect(get_db_dsn()) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT count(*) FROM web_findings wf JOIN assets a ON wf.asset_id = a.id
                    WHERE regexp_replace(a.ip::text,'/[0-9]+$','') = %s
                      AND wf.source IN ('zap','katana','nuclei','nikto')
                      AND wf.last_seen > now() - interval '6 hours'""",
                (host,))
            recent = cur.fetchone()[0]
        if recent:
            return {"skipped": f"recent web scan ({recent} findings <6h)"}
    except Exception:  # noqa: BLE001
        pass
    dispatched = []
    for port, tls in web[:_WEB_PIPELINE_MAX_PORTS]:
        scheme = "https" if tls == "yes" else "http"
        url = f"{scheme}://{host}:{port}"
        try:
            res = json.loads(_tool(scan_tools.start_pipeline_scan, target_url=url))
            dispatched.append({"url": url, "job_id": res.get("job_id")})
        except Exception as e:  # noqa: BLE001
            _msg(sid, "SurfaceTester", f"[web pipeline dispatch failed for {url}: {e}]")
    if dispatched:
        _msg(sid, "SurfaceTester",
             f"[web pipeline] dispatched {len(dispatched)} comprehensive web scan(s) "
             f"(Gobuster→…→ZAP→Nuclei) — the app-layer findings they produce (SQLi/"
             f"XSS/IDOR surface) will drive the next surface cycle.")
        _emit("langgraph_web_pipeline_dispatched", sid,
              {"host": host, "dispatched": len(dispatched),
               "urls": [d["url"] for d in dispatched]})
    return {"dispatched": dispatched}


def _known_app_discovery_tests(items: list) -> list:
    """One safe gobuster probe per web port against the curated vulnerable-app
    list — so DVWA / Mutillidae / tikiwiki are DISCOVERED (they answer 301/200),
    which is the prerequisite for crawling their app-layer surface and generating
    the OWASP param tests. Safe lane; gobuster is allow-listed."""
    out, seen = [], set()
    for row in items:
        svc = (row.get("service") or "").strip().lower()
        if svc not in _SERVICE_FAMILIES_WEB:
            continue
        port, ip = row.get("port"), row.get("ip")
        if not ip or (ip, port) in seen:
            continue
        seen.add((ip, port))
        scheme = "https" if _tls_state(svc, row.get("product"), row.get("banner")) == "yes" else "http"
        out.append({
            "name": f"app_discovery known-vuln-apps @ {scheme}://{ip}:{port}",
            "host": ip, "service": "http", "port": port, "tool": "gobuster",
            "command": f"gobuster dir -u {scheme}://{ip}:{port}/ -w {_KNOWN_APPS_WORDLIST} -q -t 10",
            "category": "dir_enum", "tier": "safe",
            "assertion": {"expect_regex": r"(?i)status: ?(200|301|302)"},
            "exploit_ref": None,
            "source_finding_id": None, "source_finding_source": None,
        })
    return out


def _owasp_param_tests(host: str, limit: int = 16) -> list:
    """Turn CRAWLED parameterized endpoints into OWASP WSTG app-layer tests —
    the IDOR / SQLi / XSS / LFI coverage a service+port-keyed recommender never
    produces. For a target like Metasploitable's DVWA/Mutillidae this is where
    the real application bugs live. Reads the host's crawled URLs (any source)
    that carry a query string, classifies each parameter, and emits the tests.
    Scope-gated (the URLs are for one in-scope host); execution is still gated
    per-tier (SQLi/XSS/LFI safe, IDOR human-approved)."""
    import re as _re
    import urllib.parse as _up
    try:
        import psycopg2
        from db_utils import get_db_dsn
        with psycopg2.connect(get_db_dsn()) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT DISTINCT wf.url
                     FROM web_findings wf JOIN assets a ON wf.asset_id = a.id
                    WHERE regexp_replace(a.ip::text,'/[0-9]+$','') = %s
                      AND wf.url LIKE '%%?%%'
                    LIMIT 400""",
                (host,))
            urls = [r[0] for r in cur.fetchall() if r[0]]
    except Exception:  # noqa: BLE001
        return []
    if not _host_in_scope(host):
        return []

    out, seen = [], set()
    for raw in urls:
        u = _up.urlparse(raw if "://" in str(raw) else f"http://{raw}")
        if not u.query:
            continue
        base = f"{u.scheme or 'http'}://{u.netloc}{u.path}"
        port = u.port or (443 if u.scheme == "https" else 80)
        for pname, pvals in _up.parse_qs(u.query).items():
            low = pname.lower()
            pval = (pvals or [""])[0]
            key = (base, low)
            if key in seen or len(out) >= limit:
                continue
            seen.add(key)
            # Rebuild the query with a placeholder we can substitute per test.
            def _with(val):
                q = _up.parse_qs(u.query); q[pname] = [val]
                return f"{base}?{_up.urlencode(q, doseq=True)}"

            # SQLi — safe detection via sqlmap (allow-listed), scoped to this param.
            out.append(_param_test("sqli_detect", "sqlmap", base, pname, port,
                f"sqlmap -u \"{raw}\" -p {pname} --batch --smart --level 1 --risk 1 --flush-session",
                {"expect_regex": "(?i)(is vulnerable|injectable|parameter .* is|payload)"}))
            # XSS — safe reflection probe: does a marker payload come back verbatim?
            xurl = _with("pxXSS<svg/onload=1>")
            out.append(_param_test("xss_detect", "curl", base, pname, port,
                f"curl -sk \"{xurl}\"",
                {"expect_substring": ["pxXSS<svg/onload=1>"]}))
            # LFI — path-like params only.
            if low in _PATH_PARAM_NAMES:
                lurl = _with("../../../../../../etc/passwd")
                out.append(_param_test("lfi_read", "curl", base, pname, port,
                    f"curl -sk \"{lurl}\"", {"expect_substring": ["root:x:0:0"]}))
            # IDOR — object-ref params. Impactful + gated: confirming needs a
            # second identity, so this ENUMERATES the reference for the operator.
            if low in _IDOR_PARAM_NAMES:
                out.append(_param_test("idor", "curl", base, pname, port,
                    f"curl -sk \"{raw}\"", {"expect_status": 200},
                    impactful=True, wid="WSTG-ATHZ-04"))
            if len(out) >= limit:
                break
    return out


def _param_test(category, tool, base, pname, port, command, assertion,
                impactful=False, wid=None) -> dict:
    wmap = {"sqli_detect": "WSTG-INPV-05", "xss_detect": "WSTG-INPV-01,WSTG-INPV-02",
            "lfi_read": "WSTG-ATHZ-01", "idor": "WSTG-ATHZ-04"}
    wid = wid or wmap.get(category, "WSTG")
    ip = base.split("://", 1)[-1].split("/")[0].split(":")[0]
    tier = "impactful" if impactful else "safe"
    ref = ({"source": "wstg", "module": wid, "purpose": f"{wid} {category} on {pname}"}
           if impactful else None)
    return {"name": f"WSTG {wid} {category} @ {base}?{pname}=",
            "host": ip, "service": "http", "port": port, "tool": tool,
            "command": command, "category": category, "tier": tier,
            "assertion": assertion, "exploit_ref": ref,
            "source_finding_id": None, "source_finding_source": "crawl-param"}


def _build_surface_tests(host: str, synthesize: bool = None) -> list:
    """Deterministic (no LLM) custom tests for ONE host's surface.

    Reuses query_open_ports(target=host) + get_tool_recommendations per service.
    Each element becomes a candidate test dict with a structured assertion and a
    safe|impactful tier. Impactful candidates carry an exploit_ref (from the
    recommender's metasploit[] or match_vuln_to_exploits) so they route to the
    approval lane; nothing here executes.
    """
    tests: list = []
    try:
        ports = json.loads(_tool(scan_tools.query_open_ports, target=host, limit=100))
        items = ports.get("items") or []
    except Exception:  # noqa: BLE001
        items = []

    # WSTG-CONF-06 (Test HTTP Methods) FIRST: a writable WebDAV collection is a
    # direct RCE (upload a webshell), the highest-value vector on the host — it
    # must never be crowded out of the _SURFACE_TEST_LIMIT budget by lower-value
    # probes. Detected up front and prepended.
    tests.extend(_wstg_conf06_webshell_tests(items))

    # Non-MSF exploit coverage: ExploitDB scripts matched by (product, version).
    tests.extend(_exploitdb_tests(items))

    # Discover known vulnerable web apps (DVWA/Mutillidae/etc.) that generic
    # wordlists miss — so their app-layer surface can then be crawled + tested.
    tests.extend(_known_app_discovery_tests(items))

    # OWASP app-layer coverage: IDOR / SQLi / XSS / LFI from crawled parameters.
    tests.extend(_owasp_param_tests(host))

    # Infer the target OS family once, to drop platform-mismatched MSF modules.
    _plat = _infer_target_platform(items)

    seen = set()
    for row in items:
        svc = (row.get("service") or "").strip().lower()
        port, ip = row.get("port"), row.get("ip") or host
        if not svc or (svc, port) in seen:
            continue
        seen.add((svc, port))
        if len(tests) >= _SURFACE_TEST_LIMIT:
            break
        tls = _tls_state(svc, row.get("product"), row.get("banner"))
        try:
            rec = json.loads(_tool(scan_tools.get_tool_recommendations,
                                   service=svc, port=port))
        except Exception:  # noqa: BLE001
            rec = {}
        rec_tools = {(_tool_head(t.get("command") or t.get("name") or "")): t
                     for t in (rec.get("tools") or [])}

        # SAFE candidates from the service's read-only probe set.
        for category, default_tool in _surface_categories_for(svc, tls):
            rt = rec_tools.get(default_tool)
            cmd = (rt.get("command") if rt else None)
            if cmd:
                cmd = cmd.replace("{target}", str(ip))
                cmd = _bound_safe_command(cmd, ip, port)
            else:
                scheme = "https" if tls == "yes" else "http"
                cmd = {
                    # Present + allowlisted in the kali image (see _surface_categories_for).
                    "whatweb": f"whatweb -a 3 --color=never {scheme}://{ip}:{port}",
                    "nuclei": f"nuclei -u {scheme}://{ip}:{port} -silent",
                    # seclists is installed; /usr/share/wordlists/dirb/ is not.
                    "gobuster": f"gobuster dir -u {scheme}://{ip}:{port} -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -q",
                    "sslscan": f"sslscan {ip}:{port}",
                    "enum4linux-ng": f"enum4linux-ng -A {ip}",
                    "ssh-audit": f"ssh-audit {ip}:{port}",
                    "snmpwalk": f"snmpwalk -v2c -c public {ip}",
                    "nmap": f"nmap -sV -Pn --host-timeout 120s -p {port} {ip}",
                }.get(default_tool, f"nmap -sV -Pn --host-timeout 120s -p {port} {ip}")
            tier = _classify(category, cmd, has_exploit_ref=False)
            tests.append({
                "name": f"{category} {svc}/{port} @ {ip}",
                "host": ip, "service": svc, "port": port, "tool": _tool_head(cmd),
                "command": cmd, "category": category, "tier": tier,
                "assertion": _assertion_for(category, tls),
                "exploit_ref": None,
            })

        # IMPACTFUL candidates: metasploit modules the recommender named.
        for m in _rank_msf(rec.get("metasploit"), platform=_plat):
            module = m.get("module") or m.get("name")
            if not module:
                continue
            tests.append({
                "name": f"msf_exploit {module} @ {ip}",
                "host": ip, "service": svc, "port": port, "tool": "metasploit",
                "command": None, "category": "msf_exploit", "tier": "impactful",
                "assertion": {"expect_shell": True},
                "exploit_ref": {"source": "metasploit", "module": module,
                                "purpose": m.get("purpose")},
            })

    # WSTG finding-driven tests: turn each of the host's WEB findings into the
    # OWASP-WSTG-guided test that proves it. The map (rag-api /rag/wstg) keys a
    # finding by issue_type / CWE / nuclei tag / name to a tier+category+command+
    # assertion. Safe probes run in the autonomous lane; impactful ones carry a
    # 'wstg' exploit_ref so surface_plan queues them for the SAME human approval
    # as any other impactful test. `_classify` still fails safe on top of this.
    try:
        web = json.loads(_tool(scan_tools.get_web_findings, target=host, limit=100))
        findings = (web.get("findings") or web.get("web_findings")
                    or web.get("items") or [])
    except Exception:  # noqa: BLE001
        findings = []

    # Web ports (and their scheme) for THIS host — used to (a) skip web
    # finding-driven tests on non-web ports (a header_check on :22/SSH would
    # just hang) and (b) give a bare host:port URL a proper http(s):// scheme.
    _web_ports, _port_scheme = {}, {}
    for row in items:
        svc = (row.get("service") or "").strip().lower()
        p = row.get("port")
        if svc in _SERVICE_FAMILIES_WEB and p is not None:
            _web_ports[p] = svc
            _port_scheme[p] = "https" if _tls_state(
                svc, row.get("product"), row.get("banner")) == "yes" else "http"

    def _web_url(url, ip, port):
        """Ensure a web test URL carries an http(s):// scheme."""
        if url and str(url).startswith(("http://", "https://")):
            return url
        scheme = _port_scheme.get(port, "https" if str(port) in ("443", "8443") else "http")
        return f"{scheme}://{ip}:{port}" if port else f"{scheme}://{ip}"

    synth_on = _SYNTH_TESTS_DEFAULT if synthesize is None else bool(synthesize)
    seen_wstg = set()
    synth_count = 0
    for f in findings:
        if len(tests) >= _SURFACE_TEST_LIMIT:
            break
        issue = f.get("issue_type") or f.get("finding_type") or f.get("name")
        fname = f.get("name") or f.get("title")
        cwe = f.get("cwe")
        cwe_s = ",".join(cwe) if isinstance(cwe, list) else (str(cwe) if cwe else None)
        tags = f.get("tags")
        nuc = ",".join(t for t in tags if isinstance(t, str)) if isinstance(tags, list) else None
        furl = f.get("url")
        fip = f.get("ip") or f.get("host") or host
        fport = f.get("port")
        # Skip web finding-driven tests on a NON-web port: a finding on :22 (SSH)
        # etc. must not spawn an HTTP test that just hangs. Allow it only when the
        # port is a known web port, or the finding already carries an http URL.
        if fport is not None and fport not in _web_ports and not str(furl or "").startswith("http"):
            continue
        # Give the URL a real scheme (the endpoint returns bare host:port).
        furl = _web_url(furl, fip, fport)
        tgt = f"{fip}:{fport}" if fport else str(fip)
        try:
            g = json.loads(scan_tools.get_wstg_guidance(
                issue_type=issue, cwe=cwe_s, name=fname, nuclei_tags=nuc,
                target=tgt, url=furl))
        except Exception:  # noqa: BLE001
            g = {}
        ent = g.get("entry") if g.get("matched") else None
        # One test per (class, target) — a scan reports the same class many
        # times; prove it once. Keyed by the WSTG class when matched, else the
        # finding type (so synthesis for unmatched findings still de-dups).
        key = ((ent.get("id") if ent else None) or str(issue or "").lower(), fip, fport)
        if key in seen_wstg:
            continue
        seen_wstg.add(key)

        # OPT-IN synthesis: author a CUSTOM test for this finding instead of the
        # fixed map command. Bounded by _SURFACE_SYNTH_LIMIT; on any failure we
        # fall through to the deterministic map test below. The synthesized tier
        # is already fail-safe (test_synth), and impactful synth tests carry a
        # 'synth' exploit_ref so surface_plan queues them for human approval.
        if synth_on and synth_count < _SURFACE_SYNTH_LIMIT:
            fd = {"issue_type": issue, "name": fname, "cwe": cwe,
                  "url": furl, "target": tgt}
            st = _synthesize_finding_test(fd, g.get("guidance") or "", fip, fport)
            if st:
                tests.append(st)
                synth_count += 1
                continue

        if not ent:
            continue
        cmd = ent.get("command_rendered") or ent.get("command")
        cat = ent.get("category")
        wid = ent.get("wstg_id")
        wid_s = ",".join(wid) if isinstance(wid, list) else str(wid or "")
        impactful_ref = (ent.get("tier") == "impactful"
                         or cat in _IMPACTFUL_CATEGORIES)
        tier = _classify(cat, cmd or "", has_exploit_ref=impactful_ref)
        # webshell_upload can't dispatch as a plain wstg command — it needs the
        # webshell branch (PUT + RCE). Derive the collection path/scheme from the
        # finding URL and give it a webshell dispatch ref, same as the active
        # WSTG-CONF-06 probe below.
        if cat == "webshell_upload" and tier == "impactful":
            e_ref = _webshell_ref_from_url(furl, fip, fport, wid_s or "WSTG-CONF-06")
            e_tool = "webshell"
        else:
            e_ref = ({"source": "wstg", "module": wid_s,
                      "purpose": ent.get("wstg_note")} if tier == "impactful" else None)
            e_tool = _tool_head(cmd or "")
        tests.append({
            "name": f"WSTG {wid_s} {cat} @ {furl or tgt}",
            "host": fip, "service": "http", "port": fport,
            "tool": e_tool,
            "command": cmd, "category": cat, "tier": tier,
            "assertion": ent.get("assertion") or {},
            "exploit_ref": e_ref,
            # Link back to the scanner finding this test proves, so a PASS marks
            # THAT finding confirmed (not just "something passed on the host").
            "source_finding_id": f.get("id"),
            "source_finding_source": f.get("source"),
        })

    # Go through ALL recommendations: keep every candidate, only ORDER them so
    # the high-value ones (real exploits, webshell) come first — that ordering
    # is what the operator sees in the approval queue, and what survives if the
    # runaway backstop ever trims.
    return sorted(tests, key=_test_priority)


def surface_plan(state: PentestState) -> dict:
    """Deterministic: pick+bound the target, build+classify tests, persist each,
    queue impactful ones. NO execution here — safe execution is the next node so
    the checkpointed interrupt never re-runs a real scan."""
    sid = state["session_id"]
    host = _host_of(state.get("surface_target_request"))
    if not host:
        try:
            av = json.loads(_tool(scan_tools.get_attack_vectors, limit=1, min_risk=40.0))
            vs = av.get("vectors") or []
            host = _host_of(vs[0].get("target")) if vs else None
        except Exception:  # noqa: BLE001
            host = None
    if not host:
        _msg(sid, "SurfaceTester",
             "No target host given and no ranked attack vector to fall back on — "
             "skipping surface tests.")
        _emit("langgraph_surface_analyzed", sid, {"mode": "no_target"})
        return {"phase": "surface_onward", "surface_target": None,
                "surface_tests": [], "pending_surface_tests": [],
                "findings": ["surface: no target"], "log": ["surface: no target"]}

    import db_utils
    eng = (get_agent_session(_sid(sid)) or {}).get("configuration", {})
    engagement_id = eng.get("engagement_id") if isinstance(eng, dict) else None

    # Hands-off web coverage: when scan dispatch is allowed, auto-trigger the
    # comprehensive web pipeline (→ZAP) for the target's web services so the
    # app-layer surface is enumerated without a manual step. Scope+dedup guarded;
    # fire-and-forget (its findings drive the next cycle).
    if bool(state.get("auto_execute")):
        try:
            _ensure_web_pipeline(host, sid, engagement_id)
        except Exception as e:  # noqa: BLE001
            _msg(sid, "SurfaceTester", f"[web pipeline autotrigger skipped: {e}]")

    candidates = _build_surface_tests(host, synthesize=state.get("surface_synthesize"))

    persisted, pending = [], []
    for c in candidates:
        pending_exploit_id = None
        if c["tier"] == "impactful":
            # Queue the exploit for approval FIRST (side effect lives here, before
            # the interrupt) so the security_tests row can reference it.
            ref = c.get("exploit_ref") or {}
            # The dispatch source is what execute-by-id branches on. Most refs
            # dispatch under their own source (metasploit); a webshell test names
            # a `dispatch_source` ("webshell") distinct from its provenance
            # `source` ("wstg"), and carries structured `parameters` (the DAV
            # path/scheme) the exploit-runner needs. Fall back to the old
            # metasploit/rce defaults so nothing else changes.
            dispatch_source = ref.get("dispatch_source") or ref.get("source") or "metasploit"
            exploit_type = ref.get("exploit_type") or "rce"
            try:
                res = json.loads(_tool(
                    scan_tools.queue_exploit_for_approval,
                    exploit_id=ref.get("module") or c["name"],
                    source=dispatch_source,
                    exploit_title=c["name"],
                    customized_command=(c.get("command") or ref.get("module") or c["name"]),
                    target_ip=c["host"], target_port=c.get("port"),
                    target_service=c.get("service"), exploit_type=exploit_type,
                    parameters=ref.get("parameters"),
                    session_id=sid))
                pending_exploit_id = (res.get("pending_exploit_id")
                                      or res.get("id") if isinstance(res, dict) else None)
            except Exception as e:  # noqa: BLE001
                _msg(sid, "SurfaceTester", f"[queue failed for {c['name']}: {e}]")
                continue
            if not pending_exploit_id:
                continue
        try:
            test_id = db_utils.create_security_test(
                name=c["name"], tier=c["tier"], category=c["category"],
                target_ip=c["host"], target_port=c.get("port"),
                target_service=c.get("service"), command=c.get("command"),
                tool=c.get("tool"), assertion=c.get("assertion"),
                pending_exploit_id=pending_exploit_id,
                source_finding_source=c.get("source_finding_source"),
                source_finding_id=c.get("source_finding_id"),
                created_by_session=sid, engagement_id=engagement_id)
        except Exception as e:  # noqa: BLE001
            _msg(sid, "SurfaceTester", f"[persist failed for {c['name']}: {e}]")
            continue
        rec = {**c, "test_id": test_id, "pending_exploit_id": pending_exploit_id}
        persisted.append(rec)
        if c["tier"] == "impactful":
            pending.append(rec)
            try:
                db_utils.record_test_run(test_id, "impactful",
                                         status_override="skipped",
                                         command_run=c.get("command"),
                                         triggered_by="agent",
                                         triggered_by_session=sid,
                                         engagement_id=engagement_id)
            except Exception:  # noqa: BLE001
                pass

    safe_n = sum(1 for t in persisted if t["tier"] == "safe")
    _msg(sid, "SurfaceTester",
         f"Attack surface of {host}: {len(persisted)} custom test(s) — "
         f"{safe_n} safe (run now), {len(pending)} impactful (need approval).")
    _emit("langgraph_surface_analyzed", sid,
          {"target": host, "tests": len(persisted), "safe": safe_n,
           "impactful": len(pending)})
    _emit("langgraph_surface_test_planned", sid,
          {"target": host, "safe": safe_n, "impactful": len(pending)})
    return {"phase": "surface_safe_exec", "surface_target": host,
            "surface_tests": persisted, "pending_surface_tests": pending,
            "findings": [f"surface: {len(persisted)} tests planned for {host}"],
            "log": [f"surface_plan: {host} safe={safe_n} impactful={len(pending)}"]}


def surface_safe_exec(state: PentestState) -> dict:
    """Run the SAFE tests autonomously. SIDE EFFECTS (real scans) live here,
    BEFORE the checkpointed interrupt, so a resume never re-runs them."""
    sid = state["session_id"]
    import db_utils, time as _time
    tests = state.get("surface_tests") or []
    safe = [t for t in tests if t["tier"] == "safe"]
    results = []
    for t in safe:
        t0 = _time.time()
        out = {}
        try:
            out = json.loads(_tool(scan_tools.run_custom_test,
                                   tool=t["tool"], command=t["command"],
                                   target=t["host"], port=t.get("port"),
                                   service=t.get("service"), timeout=300))
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "status_code": 0, "error": str(e)}
        code = out.get("status_code")
        if code in (400, 403, 429):
            # Refused by the gate (out-of-scope / not allowlisted / at capacity).
            # Record and move on — never retried, never escalated to impactful.
            try:
                db_utils.record_test_run(t["test_id"], "safe",
                    command_run=t["command"], status_override="skipped",
                    output=f"[{code}] {out.get('detail') or out.get('error')}",
                    triggered_by="agent", triggered_by_session=sid)
            except Exception:  # noqa: BLE001
                pass
            continue
        exec_id = out.get("exec_id")
        exit_code, body, http_status = None, "", None
        if exec_id:
            # Poll to a wall-clock deadline that covers the tool's own timeout —
            # nuclei (6k templates) and gobuster (thousands of paths on a slow
            # host) take minutes, and a fixed 60s cap recorded them as empty
            # errors even though they completed. +30s margin over the 300s tool
            # timeout, then we give up and record what we have.
            deadline = _time.time() + _SAFE_TEST_POLL_SECONDS
            while _time.time() < deadline:
                _time.sleep(3)
                try:
                    st = json.loads(_tool(scan_tools.get_execution_status, exec_id=exec_id)) \
                        if hasattr(scan_tools, "get_execution_status") else {}
                except Exception:  # noqa: BLE001
                    st = {}
                # A transient read miss ({} or {"ok": false}) is not terminal —
                # keep polling rather than breaking out with empty output.
                if st.get("status") in ("completed", "failed", "timeout"):
                    exit_code = st.get("exit_code")
                    body = st.get("output") or ""
                    pr = st.get("parsed_results") or {}
                    http_status = pr.get("status_code") if isinstance(pr, dict) else None
                    break
        try:
            r = db_utils.record_test_run(
                t["test_id"], "safe", command_run=t["command"], exit_code=exit_code,
                output=body, duration_ms=int((_time.time() - t0) * 1000),
                tool_execution_id=exec_id, http_status=http_status,
                triggered_by="agent", triggered_by_session=sid)
            results.append({"test": t["name"], "status": r["status"]})
            _emit("langgraph_surface_test_executed", sid,
                  {"test": t["name"], "status": r["status"], "lane": "safe"})
        except Exception as e:  # noqa: BLE001
            _msg(sid, "SurfaceTester", f"[record failed for {t['name']}: {e}]")

    passed = sum(1 for r in results if r["status"] == "pass")
    _msg(sid, "SurfaceTester",
         f"Ran {len(results)} safe test(s): {passed} proved (pass), "
         f"{len(results) - passed} not proven.")
    return {"phase": "surface_safe_done", "surface_safe_results": results,
            "findings": [f"surface: {passed}/{len(results)} safe tests proved"],
            "log": [f"surface_safe_exec: {passed}/{len(results)} pass"]}


def surface_approval(state: PentestState) -> dict:
    """Human gate for impactful surface tests. ONLY interrupt() — no side effect
    before the pause, so a resume re-entering this node repeats nothing (mirror
    of exploit_approval)."""
    from langgraph.types import interrupt
    pending = state.get("pending_surface_tests") or []
    decision = interrupt({
        "kind": "surface_test_approval",
        "session_id": str(state["session_id"]),
        "target": state.get("surface_target", "")[:300],
        "candidate": "\n".join(f"- {t['name']} (pending_exploit_id={t.get('pending_exploit_id')})"
                               for t in pending)[:2000],
        "prompt": ("Approve execution of the queued impactful test(s)? Reply via "
                   "POST /pentest/{session_id}/approve with "
                   '{"approved": true|false, "pending_exploit_id": "<uuid>"}'),
    })
    if isinstance(decision, dict):
        approved = bool(decision.get("approved"))
        note = str(decision.get("note") or "")
        pending_id = decision.get("pending_exploit_id")
    else:
        approved, note, pending_id = bool(decision), "", None
    sid = state["session_id"]
    _msg(sid, "SurfaceTester",
         f"[operator decision] approved={approved}"
         f"{' pending_exploit_id=' + str(pending_id) if pending_id else ''}",
         role="user")
    _emit("langgraph_surface_decision", sid,
          {"approved": approved, "pending_exploit_id": str(pending_id or "")})
    return {"phase": "surface_exec" if approved else "surface_onward",
            "surface_decision": {"approved": approved, "note": note[:500],
                                 "pending_exploit_id": str(pending_id or "") or None},
            "findings": [f"surface_approval: approved={approved}"],
            "log": [f"surface_approval: approved={approved}"]}


def surface_exec(state: PentestState) -> dict:
    """Execute the operator-approved impactful test via the SAME gated body, and
    record the run against its security_tests row."""
    sid = state["session_id"]
    import db_utils
    decision = state.get("surface_decision") or {}
    pending_id = decision.get("pending_exploit_id")
    if not pending_id:
        _msg(sid, "SurfaceTester",
             "[approved but no pending_exploit_id] Nothing executed.")
        return {"phase": "surface_onward",
                "findings": ["surface_exec: skipped (no id)"],
                "log": ["surface_exec skipped: no id"]}
    _mark_approved(pending_id, "operator (surface approval)",
                   (state.get("surface_decision") or {}).get("note"))
    result = _tool(scan_tools.execute_approved_exploit, pending_id)
    # Find the security_test that referenced this pending exploit.
    test = next((t for t in (state.get("pending_surface_tests") or [])
                 if str(t.get("pending_exploit_id")) == str(pending_id)), None)
    if test:
        # Read the exploit_results row id + success for the run record.
        try:
            import psycopg2
            from db_utils import get_db_dsn
            with psycopg2.connect(get_db_dsn()) as conn, conn.cursor() as cur:
                cur.execute("SELECT id, success, output, session_type, session_id "
                            "FROM public.exploit_results "
                            "WHERE pending_exploit_id=%s::uuid ORDER BY executed_at DESC LIMIT 1",
                            (pending_id,))
                r = cur.fetchone()
            er_id, success, out = (str(r[0]), r[1], r[2]) if r else (None, False, result)
            session_type, session_id = (r[3], r[4]) if r else (None, None)
            db_utils.record_test_run(
                test["test_id"], "impactful", command_run=test.get("command"),
                output=(out or "")[:20000], exploit_result_id=er_id,
                has_shell=bool(success),
                status_override=("pass" if success else "fail"),
                triggered_by="agent", triggered_by_session=sid)
            if success:
                _postex_enumerate(test.get("host"), session_type, session_id, sid)
        except Exception as e:  # noqa: BLE001
            _msg(sid, "SurfaceTester", f"[record impactful failed: {e}]")
    _msg(sid, "SurfaceTester", f"[execute_approved_exploit {pending_id}]\n{result[:1500]}")
    _emit("langgraph_surface_test_completed", sid,
          {"executed": True, "pending_exploit_id": str(pending_id)})
    return {"phase": "surface_onward",
            "findings": [f"surface_exec: executed {pending_id}"],
            "log": [f"surface_exec: {pending_id}"]}


def _postex_enumerate(host, session_type, session_id, sid):
    """A shell of ANY kind -> run bounded post-ex enumeration through it and
    harvest credentials (exploit-runner /postex/enumerate dispatches per shell
    type). Best-effort; never blocks or fails the run. Enumeration only."""
    if not session_type or str(session_type).lower() in ("none", "web_poc", ""):
        return
    if not session_id:
        _msg(sid, "SurfaceTester",
             f"[post-ex] shell on {host} ({session_type}) but no session id recorded — skipped")
        return
    try:
        import requests as _rq
        base = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")
        payload = {"session_type": session_type, "session_id": str(session_id),
                   "host": host, "platform": "linux",
                   # chain into a scope-gated lateral spray PLAN (no dispatch —
                   # the plan still goes through approval).
                   "lateral": True}
        # A webshell drives commands through its invocation URL (with a {cmd}
        # slot), stored as session_id. The post-ex webshell provider reads
        # webshell_url, so pass it or enumeration has no channel.
        if str(session_type).lower() == "webshell":
            payload["webshell_url"] = str(session_id)
        r = _rq.post(f"{base}/postex/enumerate", json=payload,
                     headers={"x-api-key": os.environ.get("API_KEY", "changeme")},
                     timeout=120, verify=False)
        d = r.json() if r.status_code < 400 else {}
        lat = d.get("lateral") or {}
        _msg(sid, "SurfaceTester",
             f"[post-ex] {host} ({session_type}): priv={d.get('privileged')}, "
             f"users={len(d.get('local_users') or [])}, "
             f"creds_harvested={d.get('credentials_harvested', 0)}"
             + (f" → lateral plan: {lat.get('planned', 0)} target(s), "
                f"{lat.get('held_needs_approval', 0)} need approval" if lat else ""))
        _emit("langgraph_postex_enumerated", sid,
              {"host": host, "session_type": session_type,
               "privileged": d.get("privileged"),
               "credentials_harvested": d.get("credentials_harvested", 0)})
    except Exception as e:  # noqa: BLE001
        _msg(sid, "SurfaceTester", f"[post-ex enumerate failed: {e}]")


def _exec_one_impactful(sid, pending_id, test):
    """Execute ONE queued impactful test through the SAME scope-gated runner
    (execute_approved_exploit -> exploit-runner, which fails CLOSED on an
    out-of-scope target — so auto-firing can never reach a host outside scope),
    then record PROOF: the run's assertion is evaluated against the exploit
    output, so a test passes only when it actually demonstrated impact. When the
    exploit yields a SHELL, post-ex enumeration fires automatically. Returns the
    run status ('pass'|'fail'|'error') or None."""
    import db_utils
    _mark_approved(pending_id, "auto-exploit (operator opt-in)")
    result = _tool(scan_tools.execute_approved_exploit, pending_id)
    if not test:
        return None
    try:
        import psycopg2
        from db_utils import get_db_dsn
        with psycopg2.connect(get_db_dsn()) as conn, conn.cursor() as cur:
            cur.execute("SELECT id, success, output, session_type, session_id "
                        "FROM public.exploit_results "
                        "WHERE pending_exploit_id=%s::uuid ORDER BY executed_at DESC LIMIT 1",
                        (pending_id,))
            r = cur.fetchone()
        er_id, success, out = (str(r[0]), r[1], r[2]) if r else (None, False, result)
        session_type, session_id = (r[3], r[4]) if r else (None, None)
        rec = db_utils.record_test_run(
            test["test_id"], "impactful", command_run=test.get("command"),
            output=(out or "")[:20000], exploit_result_id=er_id,
            has_shell=bool(success), triggered_by="agent",
            triggered_by_session=sid)
        if success:
            _postex_enumerate(test.get("host"), session_type, session_id, sid)
        return rec.get("status")
    except Exception as e:  # noqa: BLE001
        _msg(sid, "SurfaceTester", f"[auto-exploit record failed for {pending_id}: {e}]")
        return None


def surface_auto_exec(state: PentestState) -> dict:
    """AUTO-EXPLOIT (opt-in): fire every queued impactful test WITHOUT the human
    approval interrupt, capturing proof. The scope gate is NOT bypassed — each
    dispatch still goes through execute_approved_exploit -> the exploit-runner's
    scope gate, which refuses any out-of-scope target; those are recorded as
    blocked, never executed. This node has side effects and NO interrupt, so it
    replaces surface_approval only when auto-exploit is enabled."""
    sid = state["session_id"]
    pending = state.get("pending_surface_tests") or []
    _msg(sid, "SurfaceTester",
         f"[AUTO-EXPLOIT] firing {len(pending)} queued impactful test(s) "
         "through the scope gate (out-of-scope is refused, not run).")
    proved, results = 0, []
    for t in pending:
        pid = t.get("pending_exploit_id")
        if not pid:
            continue
        status = _exec_one_impactful(sid, pid, t)
        results.append({"test": t["name"], "status": status})
        if status == "pass":
            proved += 1
        _emit("langgraph_surface_test_completed", sid,
              {"executed": True, "auto": True, "pending_exploit_id": str(pid),
               "status": status})
    _msg(sid, "SurfaceTester",
         f"[AUTO-EXPLOIT] {proved}/{len(results)} impactful test(s) PROVED "
         "(assertion held on the exploit output).")
    _emit("langgraph_surface_decision", sid,
          {"approved": True, "auto_exploit": True, "proved": proved,
           "total": len(results)})
    return {"phase": "surface_onward",
            "surface_decision": {"approved": True, "auto_exploit": True,
                                 "proved": proved, "total": len(results)},
            "findings": [f"surface_auto_exec: {proved}/{len(results)} proved"],
            "log": [f"surface_auto_exec: {proved}/{len(results)} proved"]}


# ── graph ────────────────────────────────────────────────────────────────────
def _surface_onward(state: PentestState) -> str:
    """After the surface phase, chain into the exploit phase if it too is opted
    in, else the report."""
    return "exploit_plan" if state.get("exploit_phase") else "report"


def _after_analyze(state: PentestState) -> str:
    """Both extra phases are opt-in and independent. Surface runs first (it can
    generate impactful candidates the exploit phase would otherwise duplicate)."""
    if state.get("surface_test_phase"):
        return "surface_plan"
    return "exploit_plan" if state.get("exploit_phase") else "report"


def _after_surface_plan(state: PentestState) -> str:
    # Always run the safe lane (it no-ops with zero safe tests) before any gate.
    if state.get("surface_target"):
        return "surface_safe_exec"
    return _surface_onward(state)


def _after_surface_safe(state: PentestState) -> str:
    # No impactful tests -> chain onward. Otherwise: auto-exploit (fire through
    # the scope gate, no human pause) when opted in, else the human approval gate.
    if state.get("pending_surface_tests"):
        if state.get("surface_auto_exploit"):
            return "surface_auto_exec"
        return "surface_approval"
    return _surface_onward(state)


def _after_surface_approval(state: PentestState) -> str:
    decision = state.get("surface_decision") or {}
    return "surface_exec" if decision.get("approved") else _surface_onward(state)


def _after_exploit_plan(state: PentestState) -> str:
    return "exploit_approval" if state.get("exploit_candidate") else "report"


def _after_exploit_approval(state: PentestState) -> str:
    decision = state.get("exploit_decision") or {}
    return "exploit_exec" if decision.get("approved") else "report"


def build_graph(checkpointer=None):
    g = StateGraph(PentestState)
    g.add_node("recon", recon)
    g.add_node("scan", scan)
    g.add_node("analyze", analyze)
    g.add_node("exploit_plan", exploit_plan)
    g.add_node("exploit_approval", exploit_approval)
    g.add_node("exploit_exec", exploit_exec)
    g.add_node("surface_plan", surface_plan)
    g.add_node("surface_safe_exec", surface_safe_exec)
    g.add_node("surface_approval", surface_approval)
    g.add_node("surface_exec", surface_exec)
    g.add_node("surface_auto_exec", surface_auto_exec)
    g.add_node("report", report)
    g.add_edge(START, "recon")
    g.add_edge("recon", "scan")
    g.add_edge("scan", "analyze")
    g.add_conditional_edges("analyze", _after_analyze,
                            {"surface_plan": "surface_plan",
                             "exploit_plan": "exploit_plan", "report": "report"})
    # Surface-test phase: plan -> safe-exec (side effects here, before the
    # checkpointed interrupt) -> approval -> exec, then chain onward.
    g.add_conditional_edges("surface_plan", _after_surface_plan,
                            {"surface_safe_exec": "surface_safe_exec",
                             "exploit_plan": "exploit_plan", "report": "report"})
    g.add_conditional_edges("surface_safe_exec", _after_surface_safe,
                            {"surface_approval": "surface_approval",
                             "surface_auto_exec": "surface_auto_exec",
                             "exploit_plan": "exploit_plan", "report": "report"})
    g.add_conditional_edges("surface_auto_exec", _surface_onward,
                            {"exploit_plan": "exploit_plan", "report": "report"})
    g.add_conditional_edges("surface_approval", _after_surface_approval,
                            {"surface_exec": "surface_exec",
                             "exploit_plan": "exploit_plan", "report": "report"})
    g.add_conditional_edges("surface_exec", _surface_onward,
                            {"exploit_plan": "exploit_plan", "report": "report"})
    g.add_conditional_edges("exploit_plan", _after_exploit_plan,
                            {"exploit_approval": "exploit_approval", "report": "report"})
    g.add_conditional_edges("exploit_approval", _after_exploit_approval,
                            {"exploit_exec": "exploit_exec", "report": "report"})
    g.add_edge("exploit_exec", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer)


_build = build_graph  # back-compat alias (Phase 1 name)


# ── run / resume ─────────────────────────────────────────────────────────────
def _interrupt_payload(result: dict, graph=None, cfg=None) -> Optional[dict]:
    """The interrupt value if the graph paused, else None.

    `invoke` puts it under `__interrupt__`; get_state is the fallback so a
    version change in that key does not silently turn a paused session into a
    'completed' one."""
    ints = (result or {}).get("__interrupt__")
    if ints:
        first = ints[0] if isinstance(ints, (list, tuple)) else ints
        val = getattr(first, "value", None)
        return val if isinstance(val, dict) else {"value": val}
    if graph is not None and cfg is not None:
        try:
            snap = graph.get_state(cfg)
            for task in (getattr(snap, "tasks", None) or []):
                for itr in (getattr(task, "interrupts", None) or []):
                    val = getattr(itr, "value", None)
                    return val if isinstance(val, dict) else {"value": val}
        except Exception:
            pass
    return None


def _saver_cm():
    from langgraph.checkpoint.postgres import PostgresSaver
    return PostgresSaver.from_conn_string(os.environ.get("DB_DSN"))


def _park_for_approval(sid: str, payload: dict) -> dict:
    """Record the pause so it is visible everywhere the operator looks: session
    status, a session message, session metadata and a webhook event. A blocked /
    waiting item that looks identical to a running one reads as a hang."""
    _msg(sid, "Exploit",
         "⏸ AWAITING OPERATOR APPROVAL — the graph is checkpointed in Postgres "
         "and will resume from this exact point.\n\n"
         f"Candidate:\n{(payload.get('candidate') or '')[:1500]}\n\n"
         f"Approve with: POST /pentest/{sid}/approve "
         '{"approved": true, "pending_exploit_id": "<uuid>"}',
         role="system")
    try:
        update_agent_session(_sid(sid), status="awaiting_approval",
                             metadata={"engine": ENGINE_NAME,
                                       "awaiting_approval": payload})
    except Exception:
        pass
    _emit("langgraph_awaiting_approval", sid,
          {"kind": payload.get("kind"), "target": payload.get("target")})
    return {"session_id": sid, "status": "awaiting_approval",
            "awaiting_approval": payload}


def _finish(sid: str, final: dict, session_name: str = "unnamed") -> dict:
    """Close the session out with the SAME lifecycle the AutoGen path had.

    Three things used to happen only on the AutoGen path, so they were about to
    be lost when it was retired:
      * `metadata.scans` / `scan_summary` from the scan tracker — the dashboard's
        per-session scan panel reads these,
      * `collect_session_outputs`, which writes the run's scans + transcript +
        report to a session directory on disk,
      * `_finalize_session`, which produces the flow summary, claim validation
        and the KB recommendation drain.
    """
    summary = (final.get("report") or "session complete")[:4000]

    scans_metadata: List[dict] = []
    scan_summary = None
    try:
        status = scan_tracker.get_session_status(sid)
        if isinstance(status, dict):
            scans_metadata = status.get("scans") or []
            scan_summary = status.get("summary")
    except Exception:
        pass

    update_agent_session(
        _sid(sid), status="completed", summary=summary,
        metadata={"engine": ENGINE_NAME,
                  "total_messages": len(_transcript),
                  "phase": final.get("phase"),
                  "steps": len(final.get("log", [])),
                  "scans": scans_metadata,
                  "scan_summary": scan_summary},
    )

    try:
        from session_collector import collect_session_outputs
        started_at = getattr(scan_tracker._local, "started_at", "") or ""
        out_dir = collect_session_outputs(
            session_id=sid, session_name=session_name,
            scans_metadata=scans_metadata, session_started_at=started_at,
            conversation_messages=list(_transcript),
            final_report=final.get("report"),
        )
        if out_dir:
            _emit("langgraph_session_outputs_collected", sid, {"output_dir": str(out_dir)})
    except Exception as e:  # noqa: BLE001
        # Warned, not silent: "no session directory" is otherwise
        # indistinguishable from "the feature does not exist for this engine".
        _log.warning("[%s] session output collection failed: %s", sid, e)

    _emit("langgraph_session_completed", sid,
          {"phase": final.get("phase"), "steps": len(final.get("log", [])),
           "scans": len(scans_metadata)})
    return {"session_id": sid, "status": "completed"}


def _teardown(sid: str, auto_run_recommendations) -> None:
    """Run the shared end-of-session work (flow summary, claim validation, KB
    drain, scan persistence, tracker cleanup).

    Imported lazily because `autogen_service` imports THIS module — a top-level
    import would be circular. By the time a session runs, that module is loaded.

    `auto_run_recommendations` was accepted by this engine's entry point and then
    ignored, so a session launched with it on left its KB recommendations at
    status='pending' forever. This is where it gets honoured.
    """
    try:
        from autogen_service import _finalize_session
    except Exception as e:  # noqa: BLE001
        _log.warning("[%s] teardown unavailable: %s", sid, e)
        return
    try:
        _finalize_session(_sid(sid), auto_run_recommendations)
    except Exception as e:  # noqa: BLE001
        _log.warning("[%s] teardown failed: %s", sid, e)


def run_langgraph_session_sync(
    session_id,
    target_description: str,
    initial_task: str,
    max_rounds: int = 200,
    resume_context: Optional[str] = None,
    session_name: str = "unnamed",
    auto_execute_scans: bool = True,
    proxy: Optional[str] = None,
    port_profile: Optional[str] = None,
    web_profile: Optional[str] = None,
    auto_run_recommendations: Optional[bool] = None,
    exploit_phase: Optional[bool] = None,
    surface_test_phase: Optional[bool] = None,
    surface_target: Optional[str] = None,
    synthesize_tests: Optional[bool] = None,
    auto_exploit: Optional[bool] = None,
):
    """Drop-in LangGraph replacement for the AutoGen session runner."""
    from llm_metrics import LLMMetricsContext
    sid = str(session_id)
    if exploit_phase is None:
        exploit_phase = os.environ.get("LANGGRAPH_EXPLOIT_PHASE", "").strip().lower() in ("1", "true", "yes")
    if surface_test_phase is None:
        surface_test_phase = os.environ.get("LANGGRAPH_SURFACE_TEST_PHASE", "").strip().lower() in ("1", "true", "yes")
    if proxy:
        try:
            scan_tools.set_session_proxy(proxy)
        except Exception:
            pass

    task = initial_task
    if resume_context:
        task = f"{initial_task}\n\n[resumed context]\n{resume_context[:1000]}"

    # Same thread-local context AutoGen sets: without it /scans is empty for the
    # session, port_profile/web_profile are silently ignored, and no
    # llm_request_metrics row can be attributed.
    scan_tracker.set_session(sid, port_profile=port_profile, web_profile=web_profile)
    LLMMetricsContext.set_session(sid)
    _transcript.clear()

    update_agent_session(_sid(sid), status="active",
                         metadata={"engine": ENGINE_NAME,
                                   "exploit_phase": bool(exploit_phase),
                                   "surface_test_phase": bool(surface_test_phase)})
    _msg(sid, "Coordinator",
         f"LangGraph engine starting.\nTarget: {target_description[:300]}\nTask: {task[:300]}\n"
         f"auto_execute={bool(auto_execute_scans)} exploit_phase={bool(exploit_phase)}",
         role="system")
    _emit("langgraph_session_started", sid,
          {"target": target_description[:200],
           "auto_execute": bool(auto_execute_scans),
           "exploit_phase": bool(exploit_phase)})

    try:
        with _saver_cm() as saver:
            saver.setup()  # idempotent; creates the checkpoint tables
            graph = build_graph(saver)
            cfg = {"configurable": {"thread_id": sid}}
            final = graph.invoke({
                "session_id": sid, "target": target_description, "task": task,
                "auto_execute": bool(auto_execute_scans),
                "exploit_phase": bool(exploit_phase),
                "surface_test_phase": bool(surface_test_phase),
                "surface_synthesize": synthesize_tests,
                "surface_auto_exploit": auto_exploit,
                "surface_target_request": surface_target,
                "surface_target": None, "surface_tests": None,
                "surface_safe_results": None, "pending_surface_tests": None,
                "surface_decision": None, "phase": "recon",
                "findings": [], "log": [], "exploit_candidate": None,
                "exploit_decision": None, "report": None,
            }, cfg)
            payload = _interrupt_payload(final, graph, cfg)
        if payload is not None:
            # Parked, NOT finished: the tracker context and the transcript must
            # survive for the resume, so no teardown here.
            return _park_for_approval(sid, payload)
        result = _finish(sid, final, session_name)
        _teardown(sid, auto_run_recommendations)
        return result
    except Exception as e:  # noqa: BLE001
        update_agent_session(_sid(sid), status="failed",
                             summary=f"LangGraph engine error: {e}")
        _emit("langgraph_session_failed", sid, {"error": str(e)[:300]})
        # A failed run is exactly when the flow summary and claim validation
        # matter most — same reasoning as _finalize_session's own docstring.
        _teardown(sid, auto_run_recommendations)
        raise
    finally:
        try:
            LLMMetricsContext.flush_buffer()
            LLMMetricsContext.clear_session()
        except Exception:
            pass


def get_pending_approval(session_id) -> Optional[dict]:
    """The interrupt a session is parked on, read from the Postgres checkpoint.

    Reads the checkpoint rather than the session row so it is true even if this
    process never ran the session — that durability is the point of the
    checkpointer."""
    sid = str(session_id)
    try:
        with _saver_cm() as saver:
            graph = build_graph(saver)
            cfg = {"configurable": {"thread_id": sid}}
            snap = graph.get_state(cfg)
            for task in (getattr(snap, "tasks", None) or []):
                for itr in (getattr(task, "interrupts", None) or []):
                    val = getattr(itr, "value", None)
                    return val if isinstance(val, dict) else {"value": val}
    except Exception:
        return None
    return None


def resume_langgraph_session_sync(session_id, approved: bool,
                                  pending_exploit_id: Optional[str] = None,
                                  note: Optional[str] = None):
    """Resume a session parked on an approval interrupt.

    `Command(resume=...)` continues the graph from the Postgres checkpoint — no
    new session row, no parent_session_id, no replay of the phases already done.
    That is the native replacement for the AutoGen resume-as-a-new-session hack.
    """
    from langgraph.types import Command
    from llm_metrics import LLMMetricsContext
    sid = str(session_id)

    row = get_agent_session(_sid(sid)) or {}
    config = row.get("configuration") or {}
    scan_tracker.set_session(sid, port_profile=config.get("port_profile"),
                             web_profile=config.get("web_profile"))
    LLMMetricsContext.set_session(sid)
    if config.get("proxy"):
        try:
            scan_tools.set_session_proxy(config["proxy"])
        except Exception:
            pass

    update_agent_session(_sid(sid), status="active")
    _emit("langgraph_session_resumed", sid,
          {"approved": bool(approved),
           "pending_exploit_id": str(pending_exploit_id or "")})
    try:
        with _saver_cm() as saver:
            saver.setup()
            graph = build_graph(saver)
            cfg = {"configurable": {"thread_id": sid}}
            final = graph.invoke(
                Command(resume={"approved": bool(approved),
                                "pending_exploit_id": pending_exploit_id,
                                "note": note or ""}), cfg)
            payload = _interrupt_payload(final, graph, cfg)
        if payload is not None:
            return _park_for_approval(sid, payload)
        result = _finish(sid, final, row.get("session_name") or "resumed")
        _teardown(sid, config.get("auto_run_recommendations"))
        return result
    except Exception as e:  # noqa: BLE001
        update_agent_session(_sid(sid), status="failed",
                             summary=f"LangGraph resume error: {e}")
        _emit("langgraph_session_failed", sid, {"error": str(e)[:300], "on": "resume"})
        _teardown(sid, config.get("auto_run_recommendations"))
        raise
    finally:
        try:
            LLMMetricsContext.flush_buffer()
            LLMMetricsContext.clear_session()
        except Exception:
            pass
