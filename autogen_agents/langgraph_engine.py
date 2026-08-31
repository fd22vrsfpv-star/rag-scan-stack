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
    out = agent.invoke(
        {"messages": [("user", task)]},
        {"recursion_limit": recursion_limit,
         "callbacks": [metrics_callback(str(session_id), agent_name)]},
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
        for m in (rec.get("metasploit") or [])[:2]:
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
    _msg(sid, "Reporter", rpt)
    _emit("langgraph_phase_completed", sid, {"phase": "report"})
    return {"phase": "done", "report": rpt, "log": ["report: composed"]}


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
    "dos", "sqli_dump", "deserialization",
}
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
_SURFACE_TEST_LIMIT = int(os.environ.get("SURFACE_TEST_LIMIT", "24"))
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
        return {"expect_exit_code": 0, "min_output_bytes": 1}
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
        out += [("http_probe", "httpx"), ("nuclei_detect", "nuclei"),
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
            else:
                scheme = "https" if tls == "yes" else "http"
                cmd = {
                    "httpx": f"httpx -u {scheme}://{ip}:{port} -title -tech-detect -status-code",
                    "nuclei": f"nuclei -u {scheme}://{ip}:{port} -silent",
                    "gobuster": f"gobuster dir -u {scheme}://{ip}:{port} -w /usr/share/wordlists/dirb/common.txt -q",
                    "sslscan": f"sslscan {ip}:{port}",
                    "enum4linux-ng": f"enum4linux-ng -A {ip}",
                    "ssh-audit": f"ssh-audit {ip}:{port}",
                    "snmpwalk": f"snmpwalk -v2c -c public {ip}",
                    "nmap": f"nmap -sV -Pn -p {port} {ip}",
                }.get(default_tool, f"nmap -sV -Pn -p {port} {ip}")
            tier = _classify(category, cmd, has_exploit_ref=False)
            tests.append({
                "name": f"{category} {svc}/{port} @ {ip}",
                "host": ip, "service": svc, "port": port, "tool": _tool_head(cmd),
                "command": cmd, "category": category, "tier": tier,
                "assertion": _assertion_for(category, tls),
                "exploit_ref": None,
            })

        # IMPACTFUL candidates: metasploit modules the recommender named.
        for m in (rec.get("metasploit") or [])[:2]:
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
        tests.append({
            "name": f"WSTG {wid_s} {cat} @ {furl or tgt}",
            "host": fip, "service": "http", "port": fport,
            "tool": _tool_head(cmd or ""),
            "command": cmd, "category": cat, "tier": tier,
            "assertion": ent.get("assertion") or {},
            "exploit_ref": ({"source": "wstg", "module": wid_s,
                             "purpose": ent.get("wstg_note")}
                            if tier == "impactful" else None),
        })

    return tests


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

    candidates = _build_surface_tests(host, synthesize=state.get("surface_synthesize"))
    import db_utils
    eng = (get_agent_session(_sid(sid)) or {}).get("configuration", {})
    engagement_id = eng.get("engagement_id") if isinstance(eng, dict) else None

    persisted, pending = [], []
    for c in candidates:
        pending_exploit_id = None
        if c["tier"] == "impactful":
            # Queue the exploit for approval FIRST (side effect lives here, before
            # the interrupt) so the security_tests row can reference it.
            ref = c.get("exploit_ref") or {}
            try:
                res = json.loads(_tool(
                    scan_tools.queue_exploit_for_approval,
                    exploit_id=ref.get("module") or c["name"],
                    source=ref.get("source") or "metasploit",
                    exploit_title=c["name"],
                    customized_command=(c.get("command") or ref.get("module") or c["name"]),
                    target_ip=c["host"], target_port=c.get("port"),
                    target_service=c.get("service"), exploit_type="rce",
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
            for _ in range(20):
                _time.sleep(3)
                try:
                    st = json.loads(_tool(scan_tools.get_execution_status, exec_id=exec_id))                         if hasattr(scan_tools, "get_execution_status") else {}
                except Exception:  # noqa: BLE001
                    st = {}
                if not st:
                    break
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
        r = _rq.post(f"{base}/postex/enumerate",
                     json={"session_type": session_type, "session_id": str(session_id),
                           "host": host, "platform": "linux",
                           # chain into a scope-gated lateral spray PLAN (no
                           # dispatch — the plan still goes through approval).
                           "lateral": True},
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
