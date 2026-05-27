from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from config import get_settings
from utils import safe_json

router = APIRouter()


# --- Models ---

class FollowUpCreate(BaseModel):
    title: str
    target: Optional[str] = None
    severity: Optional[str] = "info"
    reason: Optional[str] = None
    priority: Optional[str] = "medium"
    assigned_to: Optional[str] = None
    flagged_by: Optional[str] = "manual"
    tags: Optional[list[str]] = None
    notes: Optional[str] = None
    engagement_id: Optional[str] = None
    finding_source: Optional[str] = None
    finding_id: Optional[str] = None


class FollowUpUpdate(BaseModel):
    title: Optional[str] = None
    target: Optional[str] = None
    severity: Optional[str] = None
    reason: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[list[str]] = None
    notes: Optional[str] = None
    engagement_id: Optional[str] = None


class FeedbackBody(BaseModel):
    action: str
    notes: Optional[str] = None


# --- Endpoints ---

@router.get("/api/follow-ups/stats")
async def follow_up_stats(engagement_id: Optional[str] = Query(None)):
    s = get_settings()
    params = {}
    if engagement_id:
        params["engagement_id"] = engagement_id
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/follow-ups/stats",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/follow-ups/group-ids")
async def follow_up_group_ids(
    group_key: str = Query(...),
    group_by: str = Query("title"),
    status: Optional[str] = Query(None),
    exclude_status: Optional[str] = Query(None),
    engagement_id: Optional[str] = Query(None),
):
    """Get all follow-up IDs matching a group key (for bulk select)."""
    s = get_settings()
    params: dict = {"group_key": group_key, "group_by": group_by}
    if status: params["status"] = status
    if exclude_status: params["exclude_status"] = exclude_status
    if engagement_id: params["engagement_id"] = engagement_id
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/follow-ups/group-ids", params=params,
                           headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.get("/api/follow-ups/grouped")
async def follow_ups_grouped(
    group_by: str = Query("title"),
    status: Optional[str] = Query(None),
    exclude_status: Optional[str] = Query(None),
    engagement_id: Optional[str] = Query(None),
):
    s = get_settings()
    params: dict = {"group_by": group_by}
    if status:
        params["status"] = status
    if exclude_status:
        params["exclude_status"] = exclude_status
    if engagement_id:
        params["engagement_id"] = engagement_id
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/follow-ups/grouped",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/follow-ups")
async def list_follow_ups(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    flagged_by: Optional[str] = Query(None),
    engagement_id: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    exclude_status: Optional[str] = Query(None),
    limit: int = Query(10000),
    offset: int = Query(0),
):
    s = get_settings()
    params = {"limit": limit, "offset": offset}
    if exclude_status:
        params["exclude_status"] = exclude_status
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    if priority:
        params["priority"] = priority
    if flagged_by:
        params["flagged_by"] = flagged_by
    if engagement_id:
        params["engagement_id"] = engagement_id
    if rule_id:
        params["rule_id"] = rule_id
    if search:
        params["search"] = search
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/follow-ups",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/follow-ups")
async def create_follow_up(body: FollowUpCreate):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/follow-ups",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.patch("/api/follow-ups/{item_id}")
async def update_follow_up(item_id: str, body: FollowUpUpdate):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/follow-ups/{item_id}",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/follow-ups/{item_id}")
async def delete_follow_up(item_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/follow-ups/{item_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/follow-ups/{item_id}/feedback")
async def submit_feedback(item_id: str, body: FeedbackBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/follow-ups/{item_id}/feedback",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- Bulk operations ---

@router.post("/api/followups/bulk-update")
async def bulk_update_followups(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/followups/bulk-update",
            json=body,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- Agent control ---

class AgentScanBody(BaseModel):
    since_minutes: int = 0


@router.post("/api/agent/scan")
async def trigger_agent_scan(body: AgentScanBody = AgentScanBody()):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/agent/scan",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/agent/rules")
async def list_agent_rules():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/agent/rules",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/agent/rules/{rule_id}")
async def get_agent_rule(rule_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/agent/rules/{rule_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.patch("/api/agent/rules/{rule_id}")
async def toggle_agent_rule(rule_id: str, enabled: bool = Query(True)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/agent/rules/{rule_id}",
            params={"enabled": enabled},
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/agent/rules/reload")
async def reload_agent_rules():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/agent/rules/reload",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class RuleTestBody(BaseModel):
    rule_id: Optional[str] = None
    rule_yaml: Optional[str] = None
    since_minutes: int = 60
    limit: int = 50

@router.post("/api/agent/rules/test")
async def test_agent_rule(body: RuleTestBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/agent/rules/test",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


class AdhocRuleBody(BaseModel):
    rule_yaml: str

@router.post("/api/agent/rules/adhoc")
async def create_adhoc_rule(body: AdhocRuleBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/agent/rules/adhoc",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/agent/rules/{rule_id}")
async def delete_agent_rule(rule_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/agent/rules/{rule_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent/stats")
async def agent_stats():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/agent/stats",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)
