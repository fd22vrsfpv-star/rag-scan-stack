"""BFF proxy for the rag-api /chat-presets endpoints.

Saved operator prompts for the dashboard chat panel — picker UI on the
frontend hits these routes; this proxy adds the API-key header and forwards
to rag-api.
"""
from typing import Optional, Any

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_settings
from utils import safe_json

router = APIRouter()

_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=False, timeout=_TIMEOUT)


class PresetIn(BaseModel):
    title: str
    prompt_template: str
    engagement_id: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    placeholders: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    created_by: Optional[str] = None


class PresetPatch(BaseModel):
    title: Optional[str] = None
    prompt_template: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    placeholders: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class RenderBody(BaseModel):
    vars: dict[str, Any] = {}


def _headers() -> dict:
    s = get_settings()
    return {"x-api-key": s.api_key} if s.api_key else {}


@router.get("/api/chat-presets")
async def list_presets(
    engagement_id: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    s = get_settings()
    params = {k: v for k, v in {
        "engagement_id": engagement_id, "category": category, "search": search,
    }.items() if v is not None}
    async with _client() as c:
        r = await c.get(f"{s.rag_api_url}/chat-presets",
                        headers=_headers(), params=params)
    if r.status_code != 200:
        raise HTTPException(r.status_code, safe_json(r))
    return r.json()


@router.get("/api/chat-presets/{preset_id}")
async def get_preset(preset_id: str):
    s = get_settings()
    async with _client() as c:
        r = await c.get(f"{s.rag_api_url}/chat-presets/{preset_id}",
                        headers=_headers())
    if r.status_code != 200:
        raise HTTPException(r.status_code, safe_json(r))
    return r.json()


@router.post("/api/chat-presets")
async def create_preset(body: PresetIn):
    s = get_settings()
    async with _client() as c:
        r = await c.post(f"{s.rag_api_url}/chat-presets",
                         headers=_headers(), json=body.model_dump(exclude_none=True))
    if r.status_code not in (200, 201):
        raise HTTPException(r.status_code, safe_json(r))
    return r.json()


@router.patch("/api/chat-presets/{preset_id}")
async def update_preset(preset_id: str, body: PresetPatch):
    s = get_settings()
    async with _client() as c:
        r = await c.patch(f"{s.rag_api_url}/chat-presets/{preset_id}",
                          headers=_headers(), json=body.model_dump(exclude_none=True))
    if r.status_code != 200:
        raise HTTPException(r.status_code, safe_json(r))
    return r.json()


@router.delete("/api/chat-presets/{preset_id}")
async def delete_preset(preset_id: str):
    s = get_settings()
    async with _client() as c:
        r = await c.delete(f"{s.rag_api_url}/chat-presets/{preset_id}",
                           headers=_headers())
    if r.status_code != 200:
        raise HTTPException(r.status_code, safe_json(r))
    return r.json()


@router.post("/api/chat-presets/{preset_id}/render")
async def render_preset(preset_id: str, body: RenderBody):
    s = get_settings()
    async with _client() as c:
        r = await c.post(f"{s.rag_api_url}/chat-presets/{preset_id}/render",
                         headers=_headers(), json=body.model_dump())
    if r.status_code != 200:
        raise HTTPException(r.status_code, safe_json(r))
    return r.json()


@router.post("/api/chat-presets/{preset_id}/use")
async def bump_preset_use(preset_id: str):
    s = get_settings()
    async with _client() as c:
        r = await c.post(f"{s.rag_api_url}/chat-presets/{preset_id}/use",
                         headers=_headers())
    if r.status_code != 200:
        raise HTTPException(r.status_code, safe_json(r))
    return r.json()
