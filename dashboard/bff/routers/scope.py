from typing import Optional
import httpx
from fastapi import APIRouter, Query, Request
from pydantic import BaseModel
from config import get_settings
from utils import safe_json

router = APIRouter()


@router.get("/api/scope/names")
async def list_scope_names():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/names",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/scope")
async def get_scope(
    name: str = Query("default"),
    limit: int = Query(500, le=5000),
):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope",
            params={"name": name, "limit": limit},
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class AddToScopeBody(BaseModel):
    name: str = "default"
    targets: list[dict]


@router.post("/api/scope/add")
async def add_to_scope(body: AddToScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/add",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class RemoveFromScopeBody(BaseModel):
    name: str = "default"
    targets: list[str]


@router.delete("/api/scope/targets")
async def remove_from_scope(body: RemoveFromScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/scope/targets",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/scope/move")
async def move_scope_targets(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/move",
            json=body,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/scope/cleanup-unknown")
async def cleanup_unknown_scope():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/cleanup-unknown",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/scope/auto-assign-unknown")
async def auto_assign_unknown():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/auto-assign-unknown",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


class ExcludeBody(BaseModel):
    targets: list[str]
    source: str = "manual"


@router.post("/api/scope/exclude")
async def exclude_from_scope(body: ExcludeBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/exclude",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.delete("/api/scope/exclude")
async def remove_exclusion(body: RemoveFromScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/scope/exclude",
            json={"targets": body.targets},
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/scope/excluded")
async def list_excluded():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/excluded",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)
