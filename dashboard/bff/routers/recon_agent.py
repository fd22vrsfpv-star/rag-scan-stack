"""BFF proxy endpoints for the autonomous recon agent."""
import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from config import get_settings
from timeouts import TIMEOUT_NORMAL
from utils import safe_json

router = APIRouter()


@router.get("/api/recon-agent/{eid}")
async def get_agent_state(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/recon-agent/{eid}",
                           headers={"x-api-key": s.api_key})
    return safe_json(resp)


class EnableBody(BaseModel):
    interval_sec: int = 300
    config: Optional[dict] = None


@router.post("/api/recon-agent/{eid}/enable")
async def enable_agent(eid: str, body: EnableBody = EnableBody()):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(
            f"{s.rag_api_url}/recon-agent/{eid}/enable",
            json=body.dict(),
            headers={"x-api-key": s.api_key},
        )
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.post("/api/recon-agent/{eid}/disable")
async def disable_agent(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/recon-agent/{eid}/disable",
                            headers={"x-api-key": s.api_key})
    return safe_json(resp)


@router.post("/api/recon-agent/{eid}/pause")
async def pause_agent(eid: str, minutes: int = Query(60)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/recon-agent/{eid}/pause",
                            params={"minutes": minutes},
                            headers={"x-api-key": s.api_key})
    return safe_json(resp)


@router.get("/api/recon-agent/{eid}/coverage")
async def get_coverage(eid: str, target: Optional[str] = None):
    s = get_settings()
    params = {"target": target} if target else {}
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/recon-agent/{eid}/coverage",
                           params=params, headers={"x-api-key": s.api_key})
    return safe_json(resp)


@router.get("/api/recon-agent/{eid}/log")
async def get_agent_log(eid: str, limit: int = Query(20)):
    """Recent campaign events from the recon agent for this engagement."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(
            f"{s.rag_api_url}/engagements/{eid}/campaign-events",
            params={"operator": "recon_agent", "limit": limit},
            headers={"x-api-key": s.api_key},
        )
    if resp.status_code >= 400:
        return {"events": []}
    return safe_json(resp)


@router.post("/api/recon-agent/{eid}/run-now")
async def run_now(eid: str):
    """Trigger an immediate recon agent cycle for this engagement."""
    from services.recon_agent import get_agent
    agent = get_agent()
    if not agent:
        raise HTTPException(503, "Recon agent not running")
    # Reset last_run_at to force immediate execution on next tick
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        await c.patch(
            f"{s.rag_api_url}/recon-agent/{eid}",
            json={"last_run_at": "2000-01-01T00:00:00Z"},
            headers={"x-api-key": s.api_key},
        )
    return {"ok": True, "message": f"Next cycle will run within {int(30)}s"}


@router.get("/api/software/github-search")
async def github_search(product: str, version: str = "", cve: str = "", force: bool = False):
    s = get_settings()
    params = {"product": product, "version": version, "cve": cve, "force": str(force).lower()}
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(f"{s.rag_api_url}/software/github-search",
                           params=params, headers={"x-api-key": s.api_key})
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)
