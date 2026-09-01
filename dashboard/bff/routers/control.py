"""Kill-switch / blast-radius control proxies (upstream: rag-api).

The enforcement lives at the scope gate (a halt empties the dispatch scope, so
every gated dispatcher refuses). These routes just flip and report the flag.
Upstream paths are inlined as literals so tests/test_proxy_contracts can verify
each far end exists.
"""
from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from utils import safe_json


router = APIRouter()


class HaltReq(BaseModel):
    reason: Optional[str] = None
    scope: Optional[str] = "global"
    actor: Optional[str] = None


class BudgetReq(BaseModel):
    scope: Optional[str] = "global"
    scan_budget: Optional[int] = None
    host_cap: Optional[int] = None


def _hdrs():
    s = get_settings()
    return {"x-api-key": s.api_key, **engagement_headers()}


@router.post("/api/control/halt")
async def halt(req: HaltReq):
    """Emergency stop: refuse all gated dispatch for a scope."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/control/halt",
                            json=req.model_dump(exclude_none=True), headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/control/resume")
async def resume(req: HaltReq):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/control/resume",
                            json=req.model_dump(exclude_none=True), headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/control/budget")
async def budget(req: BudgetReq):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/control/budget",
                            json=req.model_dump(), headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/control/status")
async def status(engagement_id: Optional[str] = Query(default=None)):
    s = get_settings()
    params = {"engagement_id": engagement_id} if engagement_id else {}
    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/control/status", params=params, headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/coverage/{engagement_id}")
async def coverage(engagement_id: str):
    """Service-level coverage for an engagement (enumerated / tested / proven)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=20) as c:
        resp = await c.get(f"{s.rag_api_url}/coverage/{engagement_id}", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/coverage/wstg/{engagement_id}")
async def wstg_coverage(engagement_id: str):
    """Live OWASP WSTG coverage (98 tests) for an engagement."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=25) as c:
        resp = await c.get(f"{s.rag_api_url}/coverage/wstg/{engagement_id}", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/wstg/checklist/{engagement_id}")
async def wstg_checklist(engagement_id: str):
    """Tier-4 manual WSTG checklist (guidance + review status) for an engagement."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=25) as c:
        resp = await c.get(f"{s.rag_api_url}/wstg/checklist/{engagement_id}", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


class WstgReviewBody(BaseModel):
    wstg_id: str
    status: Optional[str] = "reviewed"
    notes: Optional[str] = None
    reviewer: Optional[str] = None


@router.post("/api/wstg/checklist/{engagement_id}/review")
async def wstg_checklist_review(engagement_id: str, body: WstgReviewBody):
    """Record an operator sign-off on one manual WSTG test."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/wstg/checklist/{engagement_id}/review",
                            json=body.model_dump(exclude_none=True), headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/coverage/{engagement_id}/complete")
async def coverage_complete(engagement_id: str):
    """Engagement stop condition: is every in-scope service tested?"""
    s = get_settings()
    async with httpx.AsyncClient(timeout=20) as c:
        resp = await c.get(f"{s.rag_api_url}/coverage/{engagement_id}/complete", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/findings/verification/{engagement_id}")
async def findings_verification(engagement_id: str):
    """Which scanner findings are backed by a passing proof test (Phase 3)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=20) as c:
        resp = await c.get(f"{s.rag_api_url}/findings/verification/{engagement_id}", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/learning/status")
async def learning_status():
    """Learning-loop health metrics (Phase 4)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/learning/status", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
