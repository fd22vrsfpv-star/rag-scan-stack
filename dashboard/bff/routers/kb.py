from typing import Any, Dict
import httpx
from fastapi import APIRouter, HTTPException, Body
from utils import safe_json

from config import get_settings

router = APIRouter()


@router.get("/api/kb/services")
async def list_kb_services():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.scan_recommender_url}/kb/services")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/kb/services/{name}")
async def get_kb_service(name: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.scan_recommender_url}/kb/services/{name}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.put("/api/kb/services/{name}")
async def upsert_kb_service(name: str, body: Dict[str, Any] = Body(...)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.put(
            f"{s.scan_recommender_url}/kb/services/{name}",
            json=body,
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/kb/services/{name}")
async def delete_kb_service(name: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(f"{s.scan_recommender_url}/kb/services/{name}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
