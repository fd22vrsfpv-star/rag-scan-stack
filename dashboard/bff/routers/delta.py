"""BFF proxy routes for scan runs and delta comparison."""
import httpx
from fastapi import APIRouter, Query
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter(prefix="/api/delta", tags=["delta"])
TIMEOUT = 30.0


def _api(path: str) -> str:
    return f"{get_settings().rag_api_url}{path}"


def _headers() -> dict:
    return {"x-api-key": get_settings().api_key, **engagement_headers()}


@router.get("/scan-runs")
async def list_scan_runs(tool: str = None, limit: int = Query(50, le=200)):
    params = {"limit": limit}
    if tool:
        params["tool"] = tool
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.get(_api("/scan-runs"), params=params, headers=_headers())
    return r.json()


@router.post("/scan-runs/backfill")
async def backfill_scan_runs():
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.post(_api("/scan-runs/backfill"), headers=_headers())
    return r.json()


@router.post("/scan-runs")
async def create_scan_run(
    tool: str = Query(...),
    target: str = Query(None),
    job_id: str = Query(None),
    profile: str = Query(None),
):
    params = {"tool": tool}
    if target:
        params["target"] = target
    if job_id:
        params["job_id"] = job_id
    if profile:
        params["profile"] = profile
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.post(_api("/scan-runs"), params=params, headers=_headers())
    return r.json()


@router.patch("/scan-runs/{run_id}")
async def finish_scan_run(run_id: str):
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.patch(_api(f"/scan-runs/{run_id}"), headers=_headers())
    return r.json()


@router.post("/scan-runs/{run_id}/link")
async def link_findings(run_id: str, finding_type: str = Query(...)):
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.post(
            _api(f"/scan-runs/{run_id}/link"),
            params={"finding_type": finding_type},
            headers=_headers(),
        )
    return r.json()


@router.get("/compare")
async def compare_runs(
    run_a: str = Query(...),
    run_b: str = Query(...),
):
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.get(
            _api("/scan-runs/compare"),
            params={"run_a": run_a, "run_b": run_b},
            headers=_headers(),
        )
    return r.json()


@router.post("/backfill-fingerprints")
async def backfill_fingerprints():
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.post(_api("/findings/backfill-fingerprints"), headers=_headers())
    return r.json()


@router.get("/dedup-report")
async def dedup_report():
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.get(_api("/findings/dedup-report"), headers=_headers())
    return r.json()
