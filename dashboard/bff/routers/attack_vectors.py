import logging
from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query
from utils import safe_json
from config import get_settings
from engagement import engagement_headers

router = APIRouter()
log = logging.getLogger("bff.attack_vectors")


@router.get("/api/attack-vectors")
async def list_attack_vectors(
    engagement_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    min_risk: float = Query(0.0, ge=0, le=100),
):
    """Ranked attack vectors (findings → MITRE ATT&CK + risk), highest first."""
    s = get_settings()
    params = {"limit": limit, "min_risk": min_risk}
    if engagement_id:
        params["engagement_id"] = engagement_id
    async with httpx.AsyncClient(verify=False, timeout=20) as c:
        resp = await c.get(f"{s.rag_api_url}/attack-vectors", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:300])
        return safe_json(resp)


@router.get("/api/attack-vectors/graph")
async def attack_vectors_graph(engagement_id: Optional[str] = None):
    """Graph (target → technique → tactic) for the Attack Map view."""
    s = get_settings()
    params = {"engagement_id": engagement_id} if engagement_id else None
    async with httpx.AsyncClient(verify=False, timeout=20) as c:
        resp = await c.get(f"{s.rag_api_url}/attack-vectors/graph", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:300])
        return safe_json(resp)


@router.post("/api/attack-vectors/compute")
async def compute_attack_vectors(engagement_id: Optional[str] = None):
    """Recompute the attack vector map from current findings."""
    s = get_settings()
    params = {"engagement_id": engagement_id} if engagement_id else None
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(f"{s.rag_api_url}/attack-vectors/compute", params=params,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:300])
        return safe_json(resp)
