from typing import Optional
import httpx
from fastapi import APIRouter, Query, Request
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


@router.get("/api/scope/names")
async def list_scope_names():
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/names",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/scope")
async def get_scope(
    name: str = Query("default"),
    limit: int = Query(500, le=5000),
):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope",
            params={"name": name, "limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class AddToScopeBody(BaseModel):
    name: str = "default"
    targets: list[dict]


@router.post("/api/scope/add")
async def add_to_scope(body: AddToScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/add",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope/{name}/purge-data")
async def purge_scope_data(name: str, body: dict = None, dry_run: bool = Query(False)):
    """Delete all findings, follow-ups, and recommendations for a named scope's
    targets (dry_run previews counts). Keeps assets/ports/scope so a rerun is
    authorised and regenerates fresh data."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=60) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/{name}/purge-data",
            params={"dry_run": str(dry_run).lower()},
            json=body or {},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class RemoveFromScopeBody(BaseModel):
    name: str = "default"
    targets: list[str]


@router.delete("/api/scope/targets")
async def remove_from_scope(body: RemoveFromScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/scope/targets",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope/move")
async def move_scope_targets(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/move",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope/cleanup-unknown")
async def cleanup_unknown_scope():
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/cleanup-unknown",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope/auto-assign-unknown")
async def auto_assign_unknown():
    s = get_settings()
    async with httpx.AsyncClient(timeout=120) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/auto-assign-unknown",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class ExcludeBody(BaseModel):
    targets: list[str]
    source: str = "manual"


@router.post("/api/scope/exclude")
async def exclude_from_scope(body: ExcludeBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/exclude",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/scope/exclude")
async def remove_exclusion(body: RemoveFromScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/scope/exclude",
            json={"targets": body.targets},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/scope/excluded")
async def list_excluded():
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/excluded",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ─── OSINT scope-pivot (typosquats + cert / ASN pivots) ─────────────────────
# The rag-api endpoints land at /scope-pivot/*; these are thin BFF proxies so
# the dashboard's apiFetch -> /api/scope-pivot/* reaches them.

@router.post("/api/scope-pivot/typosquat/{engagement_id}")
async def run_typosquat_pivot(
    engagement_id: str,
    check_resolution: bool = Query(False),
    auto_block_at: float = Query(0.85),
):
    s = get_settings()
    async with httpx.AsyncClient(timeout=120) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope-pivot/typosquat/{engagement_id}",
            params={
                "check_resolution": str(check_resolution).lower(),
                "auto_block_at": auto_block_at,
            },
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/scope-pivot/suggestions")
async def list_pivot_suggestions(
    status: Optional[str] = Query(None),
    method: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
):
    s = get_settings()
    params = {"limit": limit}
    if status: params["status"] = status
    if method: params["method"] = method
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope-pivot/suggestions",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class ReviewPivotBody(BaseModel):
    action: str  # "accept" | "reject"


@router.post("/api/scope-pivot/suggestions/{suggestion_id}/review")
async def review_pivot_suggestion(suggestion_id: int, body: ReviewPivotBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope-pivot/suggestions/{suggestion_id}/review",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)
