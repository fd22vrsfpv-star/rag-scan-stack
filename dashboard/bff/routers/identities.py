"""BFF proxy for the rag-api /identities endpoints."""
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Query

from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


@router.get("/api/identities")
async def list_identities(
    provider: Optional[str] = Query(None),
    principal_type: Optional[str] = Query(None),
    is_admin: Optional[bool] = Query(None),
    is_guest: Optional[bool] = Query(None),
    is_dirsync: Optional[bool] = Query(None),
    has_credential: Optional[bool] = Query(None),
    source: Optional[str] = Query(None),
    member_of: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    s = get_settings()
    params = {"limit": limit, "offset": offset}
    for k, v in (
        ("provider", provider), ("principal_type", principal_type),
        ("is_admin", is_admin), ("is_guest", is_guest), ("is_dirsync", is_dirsync),
        ("has_credential", has_credential), ("source", source),
        ("member_of", member_of), ("search", search),
    ):
        if v is not None:
            params[k] = v
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/identities",
            params=params, headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/identities/groups")
async def identities_groups(
    search: Optional[str] = Query(None),
    min_members: Optional[int] = Query(None, ge=1),
    limit: Optional[int] = Query(None, ge=1, le=20000),
    offset: Optional[int] = Query(None, ge=0),
):
    s = get_settings()
    params: dict = {}
    for k, v in (("search", search), ("min_members", min_members),
                 ("limit", limit), ("offset", offset)):
        if v is not None:
            params[k] = v
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/identities/groups",
            params=params, headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/identities/summary")
async def identities_summary():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/identities/stats/summary",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/identities/{identity_id}")
async def get_identity(identity_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/identities/{identity_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
