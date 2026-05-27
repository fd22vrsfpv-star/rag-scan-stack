from typing import Optional
import httpx
from fastapi import APIRouter, Query
from pydantic import BaseModel
from config import get_settings
from utils import safe_json

router = APIRouter()


# ── Engagements CRUD ──

@router.get("/api/engagements")
async def list_engagements(status: Optional[str] = Query(None)):
    s = get_settings()
    params = {}
    if status:
        params["status"] = status
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/engagements",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/engagements/{eid}")
async def get_engagement(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/engagements/{eid}",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class EngagementBody(BaseModel):
    name: str
    client: Optional[str] = None
    engagement_type: str = "external_pentest"
    methodology: str = "custom"
    status: str = "planning"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    scope_name: Optional[str] = None
    rules_of_engagement: Optional[str] = None
    metadata: Optional[dict] = None


@router.post("/api/engagements")
async def create_engagement(body: EngagementBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/engagements",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class EngagementUpdateBody(BaseModel):
    name: Optional[str] = None
    client: Optional[str] = None
    engagement_type: Optional[str] = None
    methodology: Optional[str] = None
    status: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    scope_name: Optional[str] = None
    rules_of_engagement: Optional[str] = None
    metadata: Optional[dict] = None


@router.put("/api/engagements/{eid}")
async def update_engagement(eid: str, body: EngagementUpdateBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.put(
            f"{s.rag_api_url}/engagements/{eid}",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.delete("/api/engagements/{eid}")
async def delete_engagement(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/engagements/{eid}",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


# ── Campaign Events (H1) ──

class CampaignEventBody(BaseModel):
    kill_chain_phase: str
    title: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    description: Optional[str] = None
    target_asset_id: Optional[str] = None
    exploit_result_id: Optional[str] = None
    node_id: Optional[str] = None
    timestamp: Optional[str] = None
    detected: bool = False
    detection_time: Optional[str] = None
    operator: Optional[str] = None
    metadata: Optional[dict] = None


@router.post("/api/engagements/{eid}/campaign-events")
async def create_campaign_event(eid: str, body: CampaignEventBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/engagements/{eid}/campaign-events",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/engagements/{eid}/campaign-events")
async def list_campaign_events(eid: str, kill_chain_phase: Optional[str] = Query(None)):
    s = get_settings()
    params = {}
    if kill_chain_phase:
        params["kill_chain_phase"] = kill_chain_phase
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/engagements/{eid}/campaign-events",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class CampaignEventUpdateBody(BaseModel):
    kill_chain_phase: Optional[str] = None
    title: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    description: Optional[str] = None
    detected: Optional[bool] = None
    detection_time: Optional[str] = None
    operator: Optional[str] = None
    metadata: Optional[dict] = None


@router.put("/api/campaign-events/{event_id}")
async def update_campaign_event(event_id: str, body: CampaignEventUpdateBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.put(
            f"{s.rag_api_url}/campaign-events/{event_id}",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.delete("/api/campaign-events/{event_id}")
async def delete_campaign_event(event_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/campaign-events/{event_id}",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/engagements/{eid}/campaign-summary")
async def campaign_summary(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/engagements/{eid}/campaign-summary",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


# ── Engagement-Scoped Scopes ────────────────────────────────────────────

@router.get("/api/engagements/{eid}/scopes")
async def list_engagement_scopes(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/engagements/{eid}/scopes",
                           headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.get("/api/engagements/{eid}/scopes/{scope_name}")
async def get_engagement_scope(eid: str, scope_name: str, limit: int = Query(500)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/engagements/{eid}/scopes/{scope_name}",
                           params={"limit": limit},
                           headers={"x-api-key": s.api_key})
        return safe_json(resp)


class ScopeTargetsBody(BaseModel):
    targets: list
    source: str = "manual"


@router.post("/api/engagements/{eid}/scopes/{scope_name}/targets")
async def add_scope_targets(eid: str, scope_name: str, body: ScopeTargetsBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/engagements/{eid}/scopes/{scope_name}/targets",
                            json=body.dict(),
                            headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.delete("/api/engagements/{eid}/scopes/{scope_name}")
async def delete_scope(eid: str, scope_name: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.delete(f"{s.rag_api_url}/engagements/{eid}/scopes/{scope_name}",
                              headers={"x-api-key": s.api_key})
        return safe_json(resp)


class ScopeRenameBody(BaseModel):
    new_name: str


@router.put("/api/engagements/{eid}/scopes/{scope_name}")
async def rename_scope(eid: str, scope_name: str, body: ScopeRenameBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.put(f"{s.rag_api_url}/engagements/{eid}/scopes/{scope_name}",
                           json=body.dict(),
                           headers={"x-api-key": s.api_key})
        return safe_json(resp)


class MoveTargetsBody(BaseModel):
    targets: list
    to_engagement_id: str
    to_scope_name: str


@router.post("/api/engagements/{eid}/scopes/{scope_name}/move")
async def move_scope_targets(eid: str, scope_name: str, body: MoveTargetsBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/engagements/{eid}/scopes/{scope_name}/move",
                            json=body.dict(),
                            headers={"x-api-key": s.api_key})
        return safe_json(resp)


class MoveScopeBody(BaseModel):
    to_engagement_id: str


@router.post("/api/engagements/{eid}/scopes/{scope_name}/move-all")
async def move_entire_scope(eid: str, scope_name: str, body: MoveScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/engagements/{eid}/scopes/{scope_name}/move-all",
                            json=body.dict(),
                            headers={"x-api-key": s.api_key})
        return safe_json(resp)
