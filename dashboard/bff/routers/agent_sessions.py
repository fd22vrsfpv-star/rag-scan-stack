from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


class StartSessionRequest(BaseModel):
    target_description: str
    session_name: str
    initial_task: str
    max_rounds: int = 200
    auto_execute_scans: bool = True
    proxy: Optional[str] = None  # SOCKS proxy URL from a remote node


class ResumeRequest(BaseModel):
    max_rounds: int = 200
    additional_instructions: Optional[str] = None
    proxy: Optional[str] = None  # SOCKS proxy URL — switch or keep proxy


@router.get("/api/agent-sessions")
async def list_sessions():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
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
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(
            f"{s.autogen_url}/pentest",
            json=req.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-sessions/{session_id}")
async def get_session(session_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
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
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
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
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
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
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
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
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.autogen_url}/pentest/{session_id}/scans",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/agent-sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a single agent session (proxies to autogen service)"""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
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
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
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
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            resp = await c.get(
                f"{s.autogen_url}/pentest/mcp-tools",
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
            if resp.status_code >= 400:
                return {"error": resp.text, "total_discovered": 0}
            return safe_json(resp)
    except Exception as e:
        return {"error": str(e), "total_discovered": 0}
