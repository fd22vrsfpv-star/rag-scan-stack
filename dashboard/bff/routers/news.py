"""BFF proxy for the rag-api /news endpoints — News Intelligence feature."""
from typing import Optional, Any

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()

_TIMEOUT = httpx.Timeout(60.0, connect=10.0)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=False, timeout=_TIMEOUT)


# --- Models ---

class NewsItemPatch(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[list[str]] = None
    acknowledged_by: Optional[str] = None


class NewsBulkBody(BaseModel):
    ids: list[str]
    action: str
    value: Optional[str] = None


class NewsSourcePatch(BaseModel):
    enabled: Optional[bool] = None
    url: Optional[str] = None
    name: Optional[str] = None


class NewsDeepSearchBody(BaseModel):
    topic: str
    include_deleted: Optional[bool] = False
    refresh_llm: Optional[bool] = False
    max_items: Optional[int] = 50


def _h() -> dict:
    s = get_settings()
    return {"x-api-key": s.api_key, **engagement_headers()}


def _u(path: str) -> str:
    return f"{get_settings().rag_api_url}{path}"


# --- Routes ---

@router.post("/api/news/ingest")
async def news_ingest(source_id: Optional[str] = Query(None)):
    params = {"source_id": source_id} if source_id else {}
    async with _client() as c:
        resp = await c.post(_u("/news/ingest"), params=params, headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/news/runs/{run_id}")
async def news_run_status(run_id: str):
    async with _client() as c:
        resp = await c.get(_u(f"/news/runs/{run_id}"), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/news/runs")
async def news_runs_list(limit: int = Query(20, ge=1, le=200)):
    async with _client() as c:
        resp = await c.get(_u("/news/runs"), params={"limit": limit}, headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/news/items")
async def news_items_list(
    status: Optional[str] = Query(None),
    hide_statuses: Optional[str] = Query(None),
    cve: Optional[str] = Query(None),
    kev_listed: Optional[bool] = Query(None),
    rce: Optional[bool] = Query(None),
    red_team_only: bool = Query(False),
    q: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
    include_deleted: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    params: dict[str, Any] = {
        "limit": limit, "offset": offset,
        "include_deleted": include_deleted, "red_team_only": red_team_only,
    }
    for k, v in (("status", status), ("hide_statuses", hide_statuses),
                 ("cve", cve), ("q", q), ("since", since)):
        if v is not None:
            params[k] = v
    if kev_listed is not None:
        params["kev_listed"] = kev_listed
    if rce is not None:
        params["rce"] = rce
    async with _client() as c:
        resp = await c.get(_u("/news/items"), params=params, headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/news/items/{item_id}")
async def news_item_detail(item_id: str):
    async with _client() as c:
        resp = await c.get(_u(f"/news/items/{item_id}"), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.patch("/api/news/items/{item_id}")
async def news_item_patch(item_id: str, body: NewsItemPatch):
    async with _client() as c:
        resp = await c.patch(_u(f"/news/items/{item_id}"),
                             json=body.model_dump(exclude_none=True), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/news/items/bulk")
async def news_items_bulk(body: NewsBulkBody):
    async with _client() as c:
        resp = await c.post(_u("/news/items/bulk"),
                            json=body.model_dump(), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/news/items/{item_id}/match-assets")
async def news_item_match_assets(item_id: str):
    async with _client() as c:
        resp = await c.post(_u(f"/news/items/{item_id}/match-assets"), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/news/items/{item_id}/github-search")
async def news_item_github_search(item_id: str):
    async with _client() as c:
        resp = await c.post(_u(f"/news/items/{item_id}/github-search"), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/news/items/{item_id}/enrich")
async def news_item_enrich(item_id: str):
    async with _client() as c:
        resp = await c.post(_u(f"/news/items/{item_id}/enrich"), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/news/deep-search")
async def news_deep_search(body: NewsDeepSearchBody):
    async with _client() as c:
        resp = await c.post(_u("/news/deep-search"),
                            json=body.model_dump(), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/news/sources")
async def news_sources_list():
    async with _client() as c:
        resp = await c.get(_u("/news/sources"), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.patch("/api/news/sources/{source_id}")
async def news_source_patch(source_id: str, body: NewsSourcePatch):
    async with _client() as c:
        resp = await c.patch(_u(f"/news/sources/{source_id}"),
                             json=body.model_dump(exclude_none=True), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/news/sources/{source_id}/refetch")
async def news_source_refetch(source_id: str):
    async with _client() as c:
        resp = await c.post(_u(f"/news/sources/{source_id}/refetch"), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/news/stats")
async def news_stats():
    async with _client() as c:
        resp = await c.get(_u("/news/stats"), headers=_h())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
