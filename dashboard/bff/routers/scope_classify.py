"""BFF proxy routes for scope auto-classification."""

from typing import Optional
from fastapi import APIRouter, Request, Query
import httpx
from config import get_settings
from utils import safe_json

router = APIRouter()


@router.get("/api/scope/classify/{target}")
async def classify_target(target: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(f"{s.rag_api_url}/scope/classify/{target}", headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.post("/api/scope/classify-unknown")
async def classify_unknown(request: Request):
    s = get_settings()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(f"{s.rag_api_url}/scope/classify-unknown", json=body, headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.get("/api/scope/suggestions")
async def list_suggestions(status: str = Query("pending"), limit: int = Query(100)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/scope/suggestions", params={"status": status, "limit": limit}, headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.post("/api/scope/suggestions/{suggestion_id}/accept")
async def accept_suggestion(suggestion_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/scope/suggestions/{suggestion_id}/accept", headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.post("/api/scope/suggestions/{suggestion_id}/reject")
async def reject_suggestion(suggestion_id: str, request: Request):
    s = get_settings()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/scope/suggestions/{suggestion_id}/reject", json=body, headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.post("/api/scope/suggestions/bulk-accept")
async def bulk_accept(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(f"{s.rag_api_url}/scope/suggestions/bulk-accept", json=body, headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.get("/api/scope/classification-rules")
async def list_rules():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/scope/classification-rules", headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.post("/api/scope/classification-rules")
async def create_rule(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/scope/classification-rules", json=body, headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.delete("/api/scope/classification-rules/{rule_id}")
async def delete_rule(rule_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.request("DELETE", f"{s.rag_api_url}/scope/classification-rules/{rule_id}", headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.post("/api/scope/rules/learn")
async def learn_rules():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(f"{s.rag_api_url}/scope/rules/learn", headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.get("/api/scope/decisions")
async def list_decisions(limit: int = Query(50)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/scope/decisions", params={"limit": limit}, headers={"x-api-key": s.api_key})
        return safe_json(resp)
