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

ANALYZE_TOOLS = _READ_ONLY | {"match_vuln_to_exploits", "search_msf_modules"}

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
    "why) that the operator can run manually."
)
_SCAN_SYSTEM_DISPATCH = (
    "You are the Scanner agent in a penetration-testing platform. auto_execute is "
    "ON, so you may launch discovery and enumeration scans with the start_* tools. "
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
        res = _phase_result(sid, "Scanner", "scan", "analyze", final, used)
        res["log"] = [f"scan(llm): dispatched={dispatched} tools={sorted(set(used))}"]
        _emit("langgraph_scan_dispatched", sid,
              {"phase": "scan", "auto_execute": auto, "dispatched": dispatched})
        return res
    except Exception as e:  # noqa: BLE001
        _emit("langgraph_phase_completed", sid,
              {"phase": "scan", "mode": "fallback", "error": str(e)[:200]})
        return _scan_deterministic(state, note=f"[LLM scan unavailable: {e}] ")


def _scan_deterministic(state: PentestState, note: str = "") -> dict:
    """Recommendations-only scan fallback. Never dispatches: an LLM outage is not
    a reason to fire scans nobody chose."""
    sid = state["session_id"]
    ctx = f"target={state['target'][:200]} task={state['task'][:200]}"
    recs = _tool(scan_tools.get_scan_recommendations, ctx)
    _msg(sid, "Scanner", f"{note}Recommendations:\n{recs[:2000]}\n\n"
                         "Dispatch: skipped (deterministic fallback recommends only).")
    _emit("langgraph_phase_completed", sid, {"phase": "scan", "mode": "fallback"})
    return {"phase": "analyze",
            "findings": ["scan(deterministic): recommendations only"],
            "log": ["scan deterministic: get_scan_recommendations"]}


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


# ── graph ────────────────────────────────────────────────────────────────────
def _after_analyze(state: PentestState) -> str:
    """The exploit phase is opt-in per session. Skipping straight to report keeps
    a default session from parking on an approval nobody asked for."""
    return "exploit_plan" if state.get("exploit_phase") else "report"


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
    g.add_node("report", report)
    g.add_edge(START, "recon")
    g.add_edge("recon", "scan")
    g.add_edge("scan", "analyze")
    g.add_conditional_edges("analyze", _after_analyze,
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
):
    """Drop-in LangGraph replacement for the AutoGen session runner."""
    from llm_metrics import LLMMetricsContext
    sid = str(session_id)
    if exploit_phase is None:
        exploit_phase = os.environ.get("LANGGRAPH_EXPLOIT_PHASE", "").strip().lower() in ("1", "true", "yes")
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
                                   "exploit_phase": bool(exploit_phase)})
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
                "exploit_phase": bool(exploit_phase), "phase": "recon",
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
