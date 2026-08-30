"""BFF proxies for the attack-surface security-test store.

Thin pass-throughs to rag-api, which owns `security_tests` / `security_test_runs`.
Every upstream path here is declared by app/rag-api/api.py — enforced by
tests/test_proxy_contracts.py::test_upstream_paths_exist.

TLS verification is ON for every call (see agent_sessions.py for why the old
verify=False is gone).
"""
from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


@router.get("/api/security-tests")
async def list_security_tests(
    session_id: Optional[str] = Query(default=None),
    engagement_id: Optional[str] = Query(default=None),
    tier: Optional[str] = Query(default=None),
    target_ip: Optional[str] = Query(default=None),
    enabled: Optional[bool] = Query(default=None),
    limit: int = Query(default=200),
):
    s = get_settings()
    params = {k: v for k, v in {
        "session_id": session_id, "engagement_id": engagement_id, "tier": tier,
        "target_ip": target_ip, "enabled": enabled, "limit": limit,
    }.items() if v is not None}
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/security-tests",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent-sessions/{session_id}/security-tests")
async def session_security_tests(session_id: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/agent-sessions/{session_id}/security-tests",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/security-tests/{test_id}")
async def get_security_test(test_id: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/security-tests/{test_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/security-tests/{test_id}/runs")
async def get_security_test_runs(test_id: str, limit: int = Query(default=50)):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/security-tests/{test_id}/runs",
            params={"limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


class SecurityTestCreate(BaseModel):
    name: str
    tier: str
    category: Optional[str] = None
    description: Optional[str] = None
    target_ip: Optional[str] = None
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    target_service: Optional[str] = None
    command: Optional[str] = None
    tool: Optional[str] = None
    assertion: Optional[dict] = None
    pending_exploit_id: Optional[str] = None
    created_by_session: Optional[str] = None
    engagement_id: Optional[str] = None


@router.post("/api/security-tests")
async def create_security_test(body: SecurityTestCreate):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/security-tests",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


class SecurityTestPatch(BaseModel):
    # Mirrors rag-api's SecurityTestPatch — only these are honoured upstream.
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    assertion: Optional[dict] = None


@router.patch("/api/security-tests/{test_id}")
async def patch_security_test(test_id: str, body: SecurityTestPatch):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/security-tests/{test_id}",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


class SecurityTestRunReq(BaseModel):
    proxy: Optional[str] = None
    triggered_by_session: Optional[str] = None


@router.post("/api/security-tests/{test_id}/run")
async def run_security_test(test_id: str, body: SecurityTestRunReq):
    """Re-run a stored test. A SAFE test dispatches to /tools/execute and records
    a run; an IMPACTFUL test returns 202 {requires_approval:true} and executes
    NOTHING until the operator approves through the exploit-approval banner —
    the re-run cannot bypass the human gate (rag-api enforces this structurally).
    """
    s = get_settings()
    async with httpx.AsyncClient(timeout=330) as c:
        resp = await c.post(
            f"{s.rag_api_url}/security-tests/{test_id}/run",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        # Preserve the upstream status code: an IMPACTFUL re-run answers 202
        # (requires_approval) rather than 200, and the UI/tests key on that.
        return JSONResponse(status_code=resp.status_code, content=safe_json(resp))


class BurpExportReq(BaseModel):
    format: Optional[str] = "har"  # "har" (Burp Import) | "request" (Repeater)


@router.post("/api/security-tests/{test_id}/export-burp")
async def export_test_burp(test_id: str, body: BurpExportReq):
    """Export one custom test/payload as Burp-ingestible HAR or raw request."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/security-tests/{test_id}/export-burp",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/agent-sessions/{session_id}/security-tests/export-burp")
async def export_session_tests_burp(session_id: str, body: BurpExportReq):
    """Export ALL of a session's custom tests as one Burp-ingestible HAR."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/agent-sessions/{session_id}/security-tests/export-burp",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/security-tests/{test_id}/send-to-burp")
async def send_test_to_burp(test_id: str):
    """Push a custom test into the live Burp import queue (same queue the operator
    already imports follow-ups from)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/security-tests/{test_id}/send-to-burp",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
