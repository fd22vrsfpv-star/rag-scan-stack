"""BFF proxy endpoints for the AI Agents page and gap analysis."""
import httpx
from fastapi import APIRouter, Query, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
from config import get_settings
from engagement import engagement_headers
from timeouts import TIMEOUT_NORMAL, TIMEOUT_LONG
from utils import safe_json

router = APIRouter()


# ── Agents Status ──────────────────────────────────────────────────────

@router.get("/api/agents/status")
async def agents_status():
    """Aggregate status of all AI agents."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agents/status",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


# ── Gap Analysis ───────────────────────────────────────────────────────

@router.post("/api/gap-analysis/{eid}")
async def trigger_gap_analysis(eid: str):
    """Trigger recon gap analysis for an engagement."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/gap-analysis/{eid}",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/gap-analysis/{eid}")
async def get_gap_report(eid: str, all: bool = Query(False)):
    """Get latest (or all) gap analysis report(s)."""
    s = get_settings()
    params = {"all": str(all).lower()} if all else {}
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/gap-analysis/{eid}",
                           params=params, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/gap-analysis/{eid}/auto-fill")
async def auto_fill_gaps(eid: str, report_id: Optional[str] = Query(None)):
    """Dispatch passive scans to fill gaps."""
    s = get_settings()
    params = {}
    if report_id:
        params["report_id"] = report_id
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/gap-analysis/{eid}/auto-fill",
                            params=params, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/gap-analysis/{eid}/schedule")
async def get_gap_schedule(eid: str):
    """Get gap analysis auto-schedule config."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/gap-analysis/{eid}/schedule",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/gap-analysis/{eid}/schedule")
async def set_gap_schedule(eid: str, request: Request):
    """Set gap analysis auto-schedule config."""
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/gap-analysis/{eid}/schedule",
                            json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


# ── Subdomain Takeover Hunter ──────────────────────────────────────────

class TakeoverRunBody(BaseModel):
    engagement_ids: Optional[list[str]] = None
    dry_run: bool = False
    limit: int = 5000
    concurrency: int = 50
    force: bool = False


@router.post("/api/agents/takeover-hunter/run")
async def takeover_hunter_run(body: TakeoverRunBody):
    """Run the subdomain takeover hunter. Active engagements only by default;
    routes through the configured proxy. Supports dry_run for preview, force
    to bypass the agent-side 10-min debounce."""
    s = get_settings()
    # Long timeout: 5,000 candidates × 50 concurrency × 6s timeout could take
    # several minutes worst-case. Use TIMEOUT_LONG so the BFF doesn't 504.
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/agents/takeover-hunter/run",
                            json=body.model_dump(exclude_none=True),
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()
