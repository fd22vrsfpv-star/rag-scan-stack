"""BFF proxy routes for operator-expandable vuln-class skills (rag-api /skills)."""

from fastapi import APIRouter, Request, Header
import httpx
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


@router.get("/api/skills")
async def list_skills():
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/skills",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/skills/test")
async def test_skill(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/skills/test", json=body,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/skills")
async def add_skill(request: Request,
                    x_operator: str = Header("dashboard", alias="X-Operator")):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(f"{s.rag_api_url}/skills", json=body,
                            headers={"x-api-key": s.api_key, "X-Operator": x_operator,
                                     **engagement_headers()})
        return safe_json(resp)


@router.delete("/api/skills/{skill_id}")
async def delete_skill(skill_id: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.request("DELETE", f"{s.rag_api_url}/skills/{skill_id}",
                               headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)
