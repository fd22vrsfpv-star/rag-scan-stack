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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agents/status",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


# ── Agent Feedback channel (agent_flags) ───────────────────────────────

@router.get("/api/agent-flags")
async def list_agent_flags(status: Optional[str] = None, engagement_id: Optional[str] = None):
    s = get_settings()
    params = {k: v for k, v in (("status", status), ("engagement_id", engagement_id)) if v}
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent-flags", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


# The actions /api/agent-flags/{flag_id}/{action} forwards. A module-level
# constant rather than an inline tuple so tests/test_proxy_contracts.py can
# enumerate them and prove each one resolves to a declared rag-api route
# (DYNAMIC_SEGMENT_SOURCES). Before this the guard could not read the second
# path segment and reported the call as an upstream that no service declares.
AGENT_FLAG_ACTIONS = ("approve", "dismiss")


@router.post("/api/agent-flags/{flag_id}/{action}")
async def act_agent_flag(flag_id: str, action: str):
    if action not in AGENT_FLAG_ACTIONS:
        raise HTTPException(400, f"action must be one of {AGENT_FLAG_ACTIONS}")
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/agent-flags/{flag_id}/{action}",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── Self-adapting extractors (extractor_learned) ────────────────────────

@router.get("/api/extractors/learned")
async def list_extractors_learned(status: Optional[str] = None, tool: Optional[str] = None):
    s = get_settings()
    params = {k: v for k, v in (("status", status), ("tool", tool)) if v}
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/extractors/learned", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/extractors/learned/{rule_id}/{action}")
async def review_extractor_learned(rule_id: str, action: str):
    if action not in ("approve", "reject"):
        raise HTTPException(400, "action must be approve or reject")
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/extractors/learned/{rule_id}/{action}",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/extractors/export")
async def export_extractors(tool: Optional[str] = None):
    s = get_settings()
    params = {"tool": tool} if tool else {}
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/extractors/export", params=params,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/agent-activity")
async def agent_activity(limit: int = 120, event_type: Optional[str] = None,
                         status: Optional[str] = None):
    """Cross-agent action timeline: proxy the webhook event-log (every agent
    action emits an event via /webhooks/emit), newest first."""
    s = get_settings()
    params: dict = {"limit": max(1, min(limit, 200))}
    if event_type:
        params["event_type"] = event_type
    if status:
        params["status"] = status
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/webhooks/events", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/extractors/analyze")
async def analyze_extractor(body: dict):
    """Preview what a profile extracts from an artifact, and optionally send it to
    the LLM to distil new rules (learn=true, may take a while → long timeout)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/extractors/analyze", json=body,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── Gap Analysis ───────────────────────────────────────────────────────

@router.post("/api/gap-analysis/{eid}")
async def trigger_gap_analysis(eid: str):
    """Trigger recon gap analysis for an engagement."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/gap-analysis/{eid}",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/gap-analysis/{eid}")
async def get_gap_report(eid: str, all: bool = Query(False)):
    """Get latest (or all) gap analysis report(s)."""
    s = get_settings()
    params = {"all": str(all).lower()} if all else {}
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/gap-analysis/{eid}/auto-fill",
                            params=params, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/gap-analysis/{eid}/schedule")
async def get_gap_schedule(eid: str):
    """Get gap analysis auto-schedule config."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/gap-analysis/{eid}/schedule",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/gap-analysis/{eid}/schedule")
async def set_gap_schedule(eid: str, request: Request):
    """Set gap analysis auto-schedule config."""
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/agents/takeover-hunter/run",
                            json=body.model_dump(exclude_none=True),
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()
