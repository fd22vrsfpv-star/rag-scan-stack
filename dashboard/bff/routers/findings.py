from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


@router.get("/api/findings")
async def search_findings(
    severity: Optional[list[str]] = Query(None),
    source: Optional[list[str]] = Query(None),
    ip: Optional[str] = None,
    cve: Optional[str] = None,
    cwe: Optional[str] = None,
    search: Optional[str] = None,
    port: Optional[int] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    workflow_status: Optional[list[str]] = Query(None),
    engagement_id: Optional[str] = None,
    tags: Optional[list[str]] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = 0,
):
    s = get_settings()
    params: dict = {"limit": limit, "offset": offset}
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    if ip:
        params["ip"] = ip
    if cve:
        params["cve"] = cve
    if cwe:
        params["cwe"] = cwe
    if search:
        params["search"] = search
    if port is not None:
        params["port"] = port
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    if workflow_status:
        params["workflow_status"] = workflow_status
    if engagement_id:
        params["engagement_id"] = engagement_id
    if tags:
        params["tags"] = tags

    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/findings/search",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/findings/bulk")
async def delete_findings_bulk(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.request("DELETE", f"{s.rag_api_url}/findings/bulk",
                               json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.delete("/api/recon/findings/bulk")
async def delete_recon_findings_bulk(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.request("DELETE", f"{s.rag_api_url}/recon/findings/bulk",
                               json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/recon")
async def search_recon(
    source: Optional[list[str]] = Query(None),
    finding_type: Optional[list[str]] = Query(None),
    target: Optional[str] = None,
    search: Optional[str] = None,
    severity: Optional[list[str]] = Query(None),
    asset_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = Query(200, le=2000),
    offset: int = 0,
):
    s = get_settings()
    params: dict = {"limit": limit, "offset": offset}
    if source:
        params["source"] = source
    if finding_type:
        params["finding_type"] = finding_type
    if target:
        params["target"] = target
    if search:
        params["search"] = search
    if severity:
        params["severity"] = severity
    if asset_id:
        params["asset_id"] = asset_id
    if engagement_id:
        params["engagement_id"] = engagement_id
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to

    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/recon/search",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ── Domain Overview ──

@router.get("/api/recon/domains")
async def list_recon_domains(
    search: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    include_excluded: bool = False,
):
    s = get_settings()
    params: dict = {"limit": limit, "offset": offset}
    if search:
        params["search"] = search
    if include_excluded:
        params["include_excluded"] = "true"

    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/recon/domains",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/recon/domains/{domain}/overview")
async def get_domain_overview(domain: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/recon/domains/{domain}/overview",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/ports/summary")
async def ports_summary():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/ports/summary", headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/recon/domains/{domain}/sitemap")
async def get_domain_sitemap(domain: str, limit: int = 2000):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/recon/domains/{domain}/sitemap",
            params={"limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/params")
async def search_params(
    url_pattern: Optional[str] = None,
    param_name: Optional[str] = None,
    param_type: Optional[str] = None,
    min_occurrences: int = Query(1, ge=1),
    limit: int = Query(200, le=2000),
    offset: int = 0,
):
    s = get_settings()
    params: dict = {"limit": limit, "offset": offset}
    if url_pattern:
        params["url_pattern"] = url_pattern
    if param_name:
        params["param_name"] = param_name
    if param_type:
        params["param_type"] = param_type
    if min_occurrences > 1:
        params["min_occurrences"] = min_occurrences

    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/params",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/params/summary")
async def params_summary(
    min_occurrences: int = Query(1, ge=1),
    limit: int = Query(100, le=1000),
):
    s = get_settings()
    params: dict = {"limit": limit}
    if min_occurrences > 1:
        params["min_occurrences"] = min_occurrences

    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/params/summary",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/vulns")
async def list_vulns(
    ip: Optional[str] = None,
    limit: int = Query(200, le=5000),
):
    s = get_settings()
    params: dict = {"limit": limit}
    if ip:
        params["ip"] = ip
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/vulns",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/recommendations")
async def get_recommendations():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.scan_recommender_url}/get_next_recommendations",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ── Finding Workflow (C1) ──

class WorkflowBody(BaseModel):
    workflow_status: Optional[str] = None
    assigned_to: Optional[str] = None
    verified_by: Optional[str] = None
    tester_notes: Optional[str] = None
    original_severity: Optional[str] = None
    report_ready: Optional[bool] = None


@router.patch("/api/findings/{source}/{fid}/workflow")
async def update_finding_workflow(source: str, fid: str, body: WorkflowBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/findings/{source}/{fid}/workflow",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ── Finding Comments & Activity (C2) ──

class CommentBody(BaseModel):
    comment: str
    actor: Optional[str] = None


@router.post("/api/findings/{source}/{fid}/comments")
async def add_comment(source: str, fid: str, body: CommentBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/findings/{source}/{fid}/comments",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/findings/{source}/{fid}/activity")
async def get_activity(source: str, fid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/findings/{source}/{fid}/activity",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ── Exploit Matching (J2) ──

@router.get("/api/findings/{source}/{fid}/exploit-matches")
async def get_exploit_matches(source: str, fid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/findings/{source}/{fid}/exploit-matches",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ── Scope Intelligence (E1) ──

@router.get("/api/scope/{scope_name}/intelligence")
async def scope_intelligence(scope_name: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/{scope_name}/intelligence",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/scope/{scope_name}/analysis")
async def scope_analysis(scope_name: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/{scope_name}/analysis",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ── Screenshot Proxy (GoWitness) ──

@router.get("/api/screenshots/list")
async def list_screenshots(search: Optional[str] = None):
    """List available screenshots from osint-runner."""
    s = get_settings()
    params = {}
    if search:
        params["search"] = search
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.get(f"{s.osint_runner_url}/screenshots/list", params=params)
        return r.json()


@router.get("/api/screenshots/{path:path}")
async def proxy_screenshot(path: str):
    """Proxy screenshot files from osint-runner."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.get(f"{s.osint_runner_url}/screenshots/{path}")
        if r.status_code != 200:
            raise HTTPException(r.status_code, "Screenshot not found")
        return Response(content=r.content, media_type="image/png")


# ── Finding Tags (TIER 8) ──

class TagBody(BaseModel):
    tags: list[str]
    action: str = "set"


@router.patch("/api/findings/{source}/{fid}/tags")
async def update_finding_tags(source: str, fid: str, body: TagBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/findings/{source}/{fid}/tags",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/tags/suggestions")
async def get_tag_suggestions():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/tags/suggestions",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ── Screenshot Metadata (TIER 8) ──

class ScreenshotMetaBody(BaseModel):
    path: str
    filename: str
    directory: Optional[str] = None
    tags: Optional[list[str]] = None
    notes: Optional[str] = None
    added_to_scope: Optional[str] = None


@router.get("/api/screenshots/metadata")
async def get_screenshot_metadata(
    path: Optional[str] = None,
    tag: Optional[str] = None,
):
    s = get_settings()
    params: dict = {}
    if path:
        params["path"] = path
    if tag:
        params["tag"] = tag
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/screenshots/metadata",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.patch("/api/screenshots/metadata")
async def upsert_screenshot_metadata(body: ScreenshotMetaBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/screenshots/metadata",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)
