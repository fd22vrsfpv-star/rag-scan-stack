from typing import Optional
import httpx
from fastapi import APIRouter, Query
from config import get_settings
from utils import safe_json

router = APIRouter()


@router.get("/api/opsec/timeline")
async def opsec_timeline(hours: int = Query(24)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/opsec/timeline",
            params={"hours": hours},
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/opsec/alerts")
async def opsec_alerts(threshold: int = Query(20)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/opsec/alerts",
            params={"threshold": threshold},
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/scheduled-scans")
async def list_scheduled_scans(status: Optional[str] = Query(None)):
    s = get_settings()
    params = {}
    if status:
        params["status"] = status
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scheduled-scans",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/scheduled-scans")
async def create_scheduled_scan(body: dict):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scheduled-scans",
            json=body,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.delete("/api/scheduled-scans/{sid}")
async def cancel_scheduled_scan(sid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/scheduled-scans/{sid}",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)
