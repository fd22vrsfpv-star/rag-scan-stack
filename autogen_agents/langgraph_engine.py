"""LangGraph pentest engine — Phase 1 of the AutoGen → LangGraph migration.

Runs a pentest session behind the SAME `/pentest` API when `AGENT_ENGINE=langgraph`
(default stays `autogen`). Design invariants from Docs/LANGGRAPH_MIGRATION_PLAN.md:

  * Reuses the existing `scan_tools` bodies unchanged — so the scope gate,
    MAX_CONCURRENT_SCANS and webhook contracts are exactly the same. A node that
    dispatches is NOT a new dispatcher; it calls the same gated function.
  * Persists to the SAME `agent_sessions` / `agent_messages` tables via db_utils,
    so `/sessions`, `/pentest/{id}`, `/messages` and the dashboard render a
    LangGraph session identically to an AutoGen one.
  * Deterministic supervisor edges (recon → scan → analyze → report) — this is
    what removes the GroupChat speaker-selection stall class.
  * Checkpoints to Postgres (thread_id = session_id) via PostgresSaver, the native
    replacement for manual message persistence + parent_session_id resume.

This engine is intentionally modest for Phase 1: it proves the lifecycle and the
invariants end-to-end behind the real API. Richer agent reasoning is Phase 3.
"""
from __future__ import annotations

import operator
import os
import uuid
from typing import Annotated, List, Optional, TypedDict

from langgraph.graph import StateGraph, START, END

import scan_tools
from db_utils import add_agent_message, update_agent_session

ENGINE_NAME = "langgraph"
_MSG_CAP = 4000

# Phase 3: the recon phase is a real LLM agent (LLM ↔ ToolNode) over a READ-ONLY
# tool subset — no start_* dispatch, so the cutover contacts nothing new. The
# other phases stay deterministic until their own cutover.
_RECON_TOOL_NAMES = {
    "query_assets", "query_open_ports", "query_vulnerabilities",
    "get_web_findings", "search_all_findings", "get_attack_vectors",
    "check_system_status", "get_session_scan_status", "get_all_active_jobs",
    "query_credential_findings", "query_exploitdb",
}
_RECON_SYSTEM = (
    "You are the Reconnaissance agent in a penetration-testing platform. Use ONLY "
    "the read-only tools provided to enumerate what is already known about the "
    "target: discovered assets, open ports, existing vulnerabilities and web "
    "findings. Do NOT attempt to launch scans. When you have gathered enough, "
    "reply with a concise reconnaissance summary (assets, notable ports/services, "
    "and the most important existing findings)."
)


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


def _recon_tools():
    import langgraph_tools as lt
    return [t for t in lt.LANGGRAPH_TOOLS if getattr(t, "name", None) in _RECON_TOOL_NAMES]


# ── state ────────────────────────────────────────────────────────────────────
class PentestState(TypedDict):
    session_id: str
    target: str
    task: str
    auto_execute: bool
    phase: str
    findings: Annotated[List[str], operator.add]
    log: Annotated[List[str], operator.add]
    report: Optional[str]


# ── side effects (same sinks AutoGen writes to) ──────────────────────────────
def _sid(session_id) -> uuid.UUID:
    return session_id if isinstance(session_id, uuid.UUID) else uuid.UUID(str(session_id))


def _msg(session_id, agent: str, content: str, role: str = "assistant") -> None:
    """Persist a session message (same table + shape the UI reads)."""
    try:
        add_agent_message(_sid(session_id), agent, role, (content or "")[:_MSG_CAP])
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


# ── nodes ────────────────────────────────────────────────────────────────────
def _recon_deterministic(state: PentestState, note: str = "") -> dict:
    """Phase-1 read-only recon — the fallback if the LLM agent is unavailable, so
    a session never hard-fails on an LLM/tool error."""
    sid = state["session_id"]
    assets = _tool(scan_tools.query_assets, limit=25)
    ports = _tool(scan_tools.query_open_ports, limit=50)
    _msg(sid, "Reconnaissance",
         f"{note}Assets:\n{assets[:1400]}\n\nOpen ports:\n{ports[:1400]}")
    return {"phase": "scan",
            "findings": ["recon(deterministic)"],
            "log": [f"recon deterministic{' — ' + note if note else ''}"]}


def recon(state: PentestState) -> dict:
    """Phase 3 cutover: a real LLM agent (LLM ↔ ToolNode) over read-only tools."""
    sid = state["session_id"]
    try:
        # create_react_agent moves to langchain.agents.create_agent in langgraph
        # v2; requirements pin langgraph<2 so this stays valid. Swap when we add
        # the langchain meta-package.
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(_chat_model(), _recon_tools(), prompt=_RECON_SYSTEM)
        task = (f"Target: {state['target'][:300]}\nTask: {state['task'][:300]}\n"
                "Enumerate the known assets, open ports and existing findings, "
                "then summarize.")
        out = agent.invoke({"messages": [("user", task)]},
                           {"recursion_limit": 14})
        msgs = out.get("messages", [])
        tools_used, final = [], ""
        for m in msgs:
            for c in (getattr(m, "tool_calls", None) or []):
                tools_used.append(c.get("name"))
        for m in reversed(msgs):
            if getattr(m, "type", None) == "ai" and (getattr(m, "content", "") or "").strip():
                final = m.content
                break
        used = sorted({t for t in tools_used if t})
        _msg(sid, "Reconnaissance",
             f"[LLM recon] tools used: {', '.join(used) or 'none'}\n\n{final[:1800]}")
        _emit("langgraph_phase_completed", sid,
              {"phase": "recon", "mode": "llm", "tools_used": used})
        return {"phase": "scan",
                "findings": [f"recon(llm): {len(tools_used)} tool call(s), {len(used)} distinct"],
                "log": [f"recon(llm): {used}"]}
    except Exception as e:  # noqa: BLE001
        _emit("langgraph_phase_completed", sid,
              {"phase": "recon", "mode": "fallback", "error": str(e)[:200]})
        return _recon_deterministic(state, note=f"[LLM recon unavailable: {e}] ")


def scan(state: PentestState) -> dict:
    sid = state["session_id"]
    ctx = f"target={state['target'][:200]} task={state['task'][:200]}"
    recs = _tool(scan_tools.get_scan_recommendations, ctx)
    dispatched = "auto_execute is off — recommendations only"
    if state.get("auto_execute"):
        # Scope-gated dispatch through the SAME tool body. Out-of-scope targets
        # are refused inside scan_tools; nothing new bypasses the gate here.
        dispatched = _tool(scan_tools.start_pipeline_scan)
    _msg(sid, "Scanner", f"Recommendations:\n{recs[:1500]}\n\nDispatch:\n{dispatched[:1200]}")
    _emit("langgraph_phase_completed", sid, {"phase": "scan",
                                             "auto_execute": bool(state.get("auto_execute"))})
    return {"phase": "analyze",
            "findings": ["scan: recommendations gathered"],
            "log": [f"scan: get_scan_recommendations (auto_execute={state.get('auto_execute')})"]}


def analyze(state: PentestState) -> dict:
    sid = state["session_id"]
    vulns = _tool(scan_tools.query_vulnerabilities, limit=50)
    web = _tool(scan_tools.get_web_findings, limit=50)
    _msg(sid, "Analyzer", f"Vulnerabilities:\n{vulns[:1500]}\n\nWeb findings:\n{web[:1500]}")
    _emit("langgraph_phase_completed", sid, {"phase": "analyze"})
    return {"phase": "report",
            "findings": ["analyze: vulns + web findings reviewed"],
            "log": ["analyze: query_vulnerabilities + get_web_findings"]}


def report(state: PentestState) -> dict:
    sid = state["session_id"]
    lines = "\n".join(f"  - {f}" for f in state.get("findings", []))
    rpt = (f"LangGraph pentest session summary\n"
           f"Target: {state['target'][:200]}\n"
           f"Task: {state['task'][:200]}\n"
           f"Phases completed: recon → scan → analyze → report\n"
           f"Steps:\n{lines}")
    _msg(sid, "Reporter", rpt)
    _emit("langgraph_phase_completed", sid, {"phase": "report"})
    return {"phase": "done", "report": rpt, "log": ["report: composed"]}


def _build(checkpointer):
    g = StateGraph(PentestState)
    g.add_node("recon", recon)
    g.add_node("scan", scan)
    g.add_node("analyze", analyze)
    g.add_node("report", report)
    g.add_edge(START, "recon")
    g.add_edge("recon", "scan")
    g.add_edge("scan", "analyze")
    g.add_edge("analyze", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer)


# ── entry point (same signature as autogen_service.run_pentest_session_sync) ──
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
):
    """Drop-in LangGraph replacement for the AutoGen session runner."""
    sid = str(session_id)
    if proxy:
        try:
            scan_tools.set_session_proxy(proxy)
        except Exception:
            pass

    task = initial_task
    if resume_context:
        task = f"{initial_task}\n\n[resumed context]\n{resume_context[:1000]}"

    update_agent_session(_sid(sid), status="active")
    _msg(sid, "Coordinator",
         f"LangGraph engine starting.\nTarget: {target_description[:300]}\nTask: {task[:300]}",
         role="system")
    _emit("langgraph_session_started", sid,
          {"target": target_description[:200], "auto_execute": bool(auto_execute_scans)})

    dsn = os.environ.get("DB_DSN")
    try:
        from langgraph.checkpoint.postgres import PostgresSaver
        with PostgresSaver.from_conn_string(dsn) as saver:
            saver.setup()  # idempotent
            graph = _build(saver)
            cfg = {"configurable": {"thread_id": sid}}
            final = graph.invoke({
                "session_id": sid, "target": target_description, "task": task,
                "auto_execute": bool(auto_execute_scans), "phase": "recon",
                "findings": [], "log": [], "report": None,
            }, cfg)
        summary = (final.get("report") or "session complete")[:4000]
        update_agent_session(_sid(sid), status="completed", summary=summary)
        _emit("langgraph_session_completed", sid,
              {"phase": final.get("phase"), "steps": len(final.get("log", []))})
        return {"session_id": sid, "status": "completed"}
    except Exception as e:  # noqa: BLE001
        update_agent_session(_sid(sid), status="failed",
                             summary=f"LangGraph engine error: {e}")
        _emit("langgraph_session_failed", sid, {"error": str(e)[:300]})
        raise
