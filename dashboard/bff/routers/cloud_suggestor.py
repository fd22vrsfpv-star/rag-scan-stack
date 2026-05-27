from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from config import get_settings
from utils import safe_json

router = APIRouter()


@router.get("/api/cloud/posture")
async def cloud_posture():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/cloud/posture",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/cloud/recommendations")
async def cloud_recommendations(
    provider: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    status: Optional[str] = Query("open"),
    limit: int = Query(100),
    offset: int = Query(0),
):
    s = get_settings()
    params = {"limit": limit, "offset": offset}
    if provider:
        params["provider"] = provider
    if priority:
        params["priority"] = priority
    if status:
        params["status"] = status
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/cloud/recommendations",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/cloud/recommendations/refresh")
async def cloud_refresh():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/cloud/recommendations/refresh",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class RecStatusUpdate(BaseModel):
    status: str


@router.patch("/api/cloud/recommendations/{rec_id}")
async def cloud_recommendation_update(rec_id: str, body: RecStatusUpdate):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/cloud/recommendations/{rec_id}",
            params={"status": body.status},
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── AI Triage agent proxies ─────────────────────────────────────────────


@router.post("/api/cloud/triage/run")
async def cloud_triage_run(
    engagement_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    force: bool = Query(False),
    model: Optional[str] = Query(None),
):
    """Kick off the cloud triage agent. LLM call can take 30-60s, hence the
    longer timeout. Use force=true to bypass the debounce window. Pass
    `model` to override the triage LLM for a single run."""
    s = get_settings()
    params = {"force": "true" if force else "false"}
    if engagement_id:
        params["engagement_id"] = engagement_id
    if provider:
        params["provider"] = provider
    if model:
        params["model"] = model
    async with httpx.AsyncClient(verify=False, timeout=300) as c:
        resp = await c.post(
            f"{s.rag_api_url}/cloud/triage/run",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/cloud/triage/latest")
async def cloud_triage_latest(
    engagement_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
):
    s = get_settings()
    params = {}
    if engagement_id:
        params["engagement_id"] = engagement_id
    if provider:
        params["provider"] = provider
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/cloud/triage/latest",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/cloud/tenants")
async def cloud_tenants(
    domain: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    engagement_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    s = get_settings()
    params: dict = {"limit": limit, "offset": offset}
    for k, v in (("domain", domain), ("provider", provider),
                 ("engagement_id", engagement_id)):
        if v:
            params[k] = v
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/cloud-tenants",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
