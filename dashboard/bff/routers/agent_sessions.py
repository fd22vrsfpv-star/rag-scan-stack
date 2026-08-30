from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

# TLS verification is ON for every call in this router.
#
# pentest-dashboard now mounts /certs and sets REQUESTS_CA_BUNDLE /
# SSL_CERT_FILE to the stack's CA bundle (public roots + the self-signed server
# cert), so httpx verifies internal peers without `verify=False`. Before that
# mount existed the flag was load-bearing - there was nothing to verify against -
# which is why ~554 of them accumulated across the BFF.
#
# If a call here starts failing with CERTIFICATE_VERIFY_FAILED, regenerate the
# bundle with scripts/generate-ca-bundle.sh rather than reinstating verify=False.

router = APIRouter()


class StartSessionRequest(BaseModel):
    target_description: str
    session_name: str
    initial_task: str
    max_rounds: int = 200
    auto_execute_scans: bool = True
    proxy: Optional[str] = None
    # Named port scope from knowledge/port_profiles.yaml. Forwarded to the
    # autogen service, which resolves it once per session (see SessionTracker).
    port_profile: Optional[str] = None
    # Named web scan depth from knowledge/web_profiles.yaml.
    web_profile: Optional[str] = None
    # Launch options. model_dump() is what gets forwarded, so a field missing
    # here is silently dropped no matter what the autogen service accepts.
    #
    # Turn on the continuous recon agent for this session's engagement. It was
    # never enabled for ANY engagement (recon_agent_state was empty), which is why
    # the KB recommendation queue had never been drained even once.
    enable_recon_agent: Optional[bool] = None
    # Dispatch still-pending KB recommendations when the session ends.
    auto_run_recommendations: Optional[bool] = None
    # Orchestration engine for this session: 'langgraph' (default) or 'autogen'
    # (legacy GroupChat, kept one release). This is the canary control — pin one
    # session to either engine without restarting anything. Omit for the
    # service-wide AGENT_ENGINE default.
    engine: Optional[str] = None
    # LangGraph only: add the exploit phase, which PAUSES the session on a
    # durable interrupt until an operator answers /approve.
    enable_exploit_phase: Optional[bool] = None
    # LangGraph only: add the attack-surface test phase — enumerate ONE host,
    # generate custom security tests, run SAFE ones autonomously and PAUSE for
    # approval on any IMPACTFUL one.
    enable_surface_test_phase: Optional[bool] = None
    # The ONE host/IP the surface-test phase enumerates. Omit to auto-pick the
    # highest-risk host. Must be in scope.
    surface_target_host: Optional[str] = None
    # Surface-test phase: LLM-author a custom test per web finding instead of the
    # fixed WSTG-map command (falls back to the map; impactful still gated).
    enable_test_synthesis: Optional[bool] = None


class ResumeRequest(BaseModel):
    max_rounds: int = 200
    additional_instructions: Optional[str] = None
    proxy: Optional[str] = None  # SOCKS proxy URL — switch or keep proxy


class ApprovalRequest(BaseModel):
    """Operator answer to a paused LangGraph approval interrupt."""
    approved: bool
    pending_exploit_id: Optional[str] = None
    note: Optional[str] = None


@router.get("/api/agent-sessions")
async def list_sessions():
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/pentest/sessions",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/agent-sessions")
async def start_session(req: StartSessionRequest):
    s = get_settings()
    async with httpx.AsyncClient(timeout=60) as c:
        resp = await c.post(
            f"{s.autogen_url}/pentest",
            json=req.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-sessions/engine")
async def get_agent_engine():
    """Which orchestration engine new sessions use (LangGraph vs legacy AutoGen).

    Declared BEFORE /api/agent-sessions/{session_id}: FastAPI matches in
    declaration order, so after the parameterised route "engine" would be read
    as a session id and 400 on the uuid parse.
    """
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/pentest/engine",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-sessions/{session_id}/pending-approval")
async def get_pending_approval(session_id: str):
    """What a paused LangGraph session is waiting for (read from its checkpoint)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/pentest/{session_id}/pending-approval",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/agent-sessions/{session_id}/approve")
async def approve_session_step(session_id: str, req: ApprovalRequest):
    """Answer the approval interrupt; the session continues from its checkpoint."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=60) as c:
        resp = await c.post(
            f"{s.autogen_url}/pentest/{session_id}/approve",
            json=req.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-sessions/{session_id}")
async def get_session(session_id: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/pentest/{session_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-sessions/{session_id}/messages")
async def get_messages(session_id: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/pentest/{session_id}/messages",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/agent-sessions/{session_id}/stop")
async def stop_session(session_id: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.autogen_url}/pentest/{session_id}/stop",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/agent-sessions/{session_id}/resume")
async def resume_session(session_id: str, req: ResumeRequest):
    s = get_settings()
    async with httpx.AsyncClient(timeout=60) as c:
        resp = await c.post(
            f"{s.autogen_url}/pentest/{session_id}/resume",
            json=req.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-sessions/{session_id}/scans")
async def get_session_scans(session_id: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/pentest/{session_id}/scans",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-sessions/{session_id}/flow-summary")
async def get_session_flow_summary(session_id: str):
    """Per-scan-type summary of what the session actually ran.

    The upstream endpoint serves this LIVE from the in-memory tracker while a
    session is active, and from the persisted copy on agent_sessions.metadata
    once it has ended. It existed for some time with no BFF route in front of
    it, so the UI could not reach it at all (404) and had to read the frozen
    metadata blob instead — which is taken at teardown, while scans are often
    still running.
    """
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/pentest/{session_id}/flow-summary",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/model/performance-warning")
async def get_model_performance_warning():
    """Warn when the configured model is a poor fit for agent tool-calling.

    The frontend has always called this (`api/agents.ts`), but no BFF route
    existed, so every request 404'd and the warning modal could never fire.
    """
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/model/performance-warning",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/agent-sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a single agent session (proxies to autogen service)"""
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.delete(
            f"{s.autogen_url}/pentest/{session_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/agent-sessions")
async def clear_session_history():
    """Clear all agent session history (proxies to rag-api cleanup)"""
    s = get_settings()
    async with httpx.AsyncClient(timeout=60) as c:
        resp = await c.post(
            f"{s.rag_api_url}/cleanup/sessions",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-mcp-tools")
async def list_agent_mcp_tools():
    """List MCP tools available to the autogen agents."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.get(
                f"{s.autogen_url}/pentest/mcp-tools",
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
            if resp.status_code >= 400:
                return {"error": resp.text, "total_discovered": 0}
            return safe_json(resp)
    except Exception as e:
        return {"error": str(e), "total_discovered": 0}


class SynthesizeTestRequest(BaseModel):
    issue_type: Optional[str] = None
    cwe: Optional[str] = None
    name: Optional[str] = None
    url: Optional[str] = None
    target: Optional[str] = None
    cve: Optional[str] = None
    edb_id: Optional[str] = None
    session_id: Optional[str] = None
    persist: bool = True


@router.post("/api/synthesize-test")
async def synthesize_test(req: SynthesizeTestRequest):
    """LLM-author a custom security test for one web finding (upstream: autogen,
    which holds the resolved LLM backend). Safe candidates are persisted and
    re-runnable; impactful ones come back requires_approval and are not run."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=120) as c:
        resp = await c.post(
            f"{s.autogen_url}/synthesize-test",
            json=req.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
