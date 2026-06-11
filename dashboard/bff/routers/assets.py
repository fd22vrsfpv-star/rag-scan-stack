import asyncio
import logging
import httpx
from typing import List, Optional
from fastapi import APIRouter, Query, Request, HTTPException
from pydantic import BaseModel
from psycopg2.extras import Json
from config import get_settings
from engagement import engagement_headers
from polling import register_job
from utils import safe_json

log = logging.getLogger("assets")

router = APIRouter()


@router.post("/api/credentials")
async def create_credential(request: Request):
    s = get_settings()
    params = dict(request.query_params)
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/credentials",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/credentials/{cid}")
async def delete_credential(cid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/credentials/{cid}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/credentials")
async def list_all_credentials(
    status: str = Query(None),
    protocol: str = Query(None),
    source: str = Query(None),
    limit: int = Query(500, le=5000),
):
    s = get_settings()
    params = {"limit": limit}
    if status: params["status"] = status
    if protocol: params["protocol"] = protocol
    if source: params["source"] = source
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/credentials",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/assets")
async def list_assets(limit: int = Query(100, le=5000)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/assets",
            params={"limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/purge/pattern")
async def purge_by_pattern(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/purge/pattern",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/assets")
async def delete_assets(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/assets",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/targets/{domain}")
async def purge_target_domain(domain: str, dry_run: bool = Query(False)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/targets/{domain}",
            params={"dry_run": str(dry_run).lower()},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            from fastapi import HTTPException
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/assets/{ip}/ports")
async def asset_ports(ip: str, limit: int = Query(200, le=5000)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/ports/open",
            params={"ip": ip, "limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/assets/{ip}/vulns")
async def asset_vulns(ip: str, limit: int = Query(200, le=5000)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/vulns",
            params={"ip": ip, "limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/recon/subdomains")
async def recon_subdomains(domain: str = Query(None), limit: int = Query(500, le=5000)):
    s = get_settings()
    params = {"limit": limit}
    if domain:
        params["domain"] = domain
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/recon/subdomains",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/recon/subdomains")
async def delete_subdomains(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/recon/subdomains",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/assets/{ip}/credentials")
async def asset_credentials(ip: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/assets/{ip}/credentials",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.patch("/api/credential-findings/{cid}/status")
async def update_credential_status(cid: str, request: Request):
    s = get_settings()
    params = dict(request.query_params)
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/credential-findings/{cid}/status",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/software")
async def detected_software(
    ip: str = Query(None),
    product: str = Query(None),
    search: str = Query(None),
    source: str = Query(None),
    limit: int = Query(2000, le=10000),
):
    s = get_settings()
    params = {"limit": limit}
    if search: params["search"] = search
    elif ip: params["ip"] = ip
    if product and not search: params["product"] = product
    if source: params["source"] = source
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/software",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/software/cve-tuning")
async def get_cve_tuning():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/cve-tuning", headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.put("/api/software/cve-tuning")
async def update_cve_tuning(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.put(f"{s.rag_api_url}/software/cve-tuning", json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/software/bulk-dismiss")
async def bulk_dismiss_software(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/software/bulk-dismiss",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            from fastapi import HTTPException
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/software/searchsploit")
async def software_searchsploit(product: str, version: str = "", target_version: str = "", analyze: bool = False, limit: int = 20):
    s = get_settings()
    timeout = 120 if analyze else 15
    async with httpx.AsyncClient(verify=False, timeout=timeout) as c:
        resp = await c.get(
            f"{s.rag_api_url}/software/searchsploit",
            params={"product": product, "version": version, "target_version": target_version, "analyze": str(analyze).lower(), "limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/software/research-cache")
async def software_research_cache(product: str, version: str = ""):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(
            f"{s.rag_api_url}/software/research-cache",
            params={"product": product, "version": version},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/software/bulk-check")
async def software_bulk_check(request: Request):
    s = get_settings()
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(f"{s.rag_api_url}/software/bulk-check",
                            json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:500])
        try:
            result = resp.json()
        except Exception:
            raise HTTPException(502, f"Invalid JSON from rag-api: {resp.text[:200]}")

    # Register as a BFF job so it shows in scan monitor history
    if result.get("ok"):
        from polling import register_job, active_jobs
        import uuid as _uuid
        job_id = str(_uuid.uuid4())
        selected = body.get("selected", [])
        target_desc = f"{len(selected)} selected" if selected else f"{result.get('total', '?')} products"
        register_job(
            job_id=job_id,
            service_url=f"{s.rag_api_url}",
            scan_type="ai-software-check",
            target=f"AI Exploit Check: {target_desc}",
        )
        active_jobs[job_id]["status"] = "running"
        active_jobs[job_id]["_bulk_check"] = True
        result["bff_job_id"] = job_id

    return result


@router.get("/api/software/bulk-check/status")
async def software_bulk_check_status():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/bulk-check/status",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        data = resp.json()

    # Sync BFF job status with rag-api bulk check status
    from polling import active_jobs, _persist
    from datetime import datetime, timezone
    for jid, job in list(active_jobs.items()):
        if job.get("_bulk_check") and job.get("status") == "running":
            p = data.get("progress", {})
            job["last_data"] = {"progress": p, "type": "ai-software-check"}
            if not data.get("running"):
                job["status"] = "completed"
                job["completed_at"] = datetime.now(timezone.utc).isoformat()
                job["last_data"]["status"] = "completed"
                job["last_data"]["summary"] = f"{p.get('completed',0)}/{p.get('total',0)} checked, {p.get('flagged',0)} flagged"
                _persist(jid)

    return data


@router.post("/api/software/bulk-check/cancel")
async def software_bulk_check_cancel():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.post(f"{s.rag_api_url}/software/bulk-check/cancel",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/software/cve-decision")
async def software_cve_decision(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(f"{s.rag_api_url}/software/cve-decision",
                            json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/software/cve-decisions")
async def get_cve_decisions(product: str, version: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/cve-decisions",
                           params={"product": product, "version": version},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.delete("/api/software/research-cache")
async def clear_research_cache(product: str, version: str = ""):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.delete(f"{s.rag_api_url}/software/research-cache",
                              params={"product": product, "version": version},
                              headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/software/backfill-refs")
async def backfill_followup_refs():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(f"{s.rag_api_url}/software/backfill-refs",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/nuclei/templates/search")
async def search_nuclei_templates(q: str, limit: int = 20):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.nuclei_url}/templates/search",
                           params={"q": q, "limit": limit})
        return safe_json(resp)


@router.get("/api/software/llm-debug")
async def software_llm_debug(product: str, version: str = ""):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/llm-debug",
                           params={"product": product, "version": version},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/software/release-date")
async def get_release_date(product: str, version: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/release-date",
                           params={"product": product, "version": version},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.put("/api/software/release-date")
async def set_release_date(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.put(f"{s.rag_api_url}/software/release-date",
                           json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/software/ddg-jobs")
async def list_ddg_jobs():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/ddg-jobs",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/software/vendor-pages")
async def list_vendor_pages():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/vendor-pages", headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.put("/api/software/vendor-pages")
async def save_vendor_page(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.put(f"{s.rag_api_url}/software/vendor-pages", json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.delete("/api/software/vendor-pages/{keyword}")
async def delete_vendor_page(keyword: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.delete(f"{s.rag_api_url}/software/vendor-pages/{keyword}", headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/software/scan-urls")
async def scan_manual_urls(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(f"{s.rag_api_url}/software/scan-urls",
                            json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/software/deep-search-cache")
async def get_deep_search_cache(product: str, version: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/deep-search-cache",
                           params={"product": product, "version": version},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/software/cve-deep-search")
async def cve_deep_search(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(f"{s.rag_api_url}/software/cve-deep-search",
                            json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/software/cve-prompt")
async def get_cve_prompt():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(f"{s.rag_api_url}/software/cve-prompt",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.put("/api/software/cve-prompt")
async def update_cve_prompt(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.put(f"{s.rag_api_url}/software/cve-prompt",
                           json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/software/ddg-search-raw")
async def software_ddg_search_raw(query: str = Query(...), max_results: int = Query(20)):
    """Generic DDG search — returns raw results (for GitHub PoC tab)."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/software/ddg-search-raw",
            params={"query": query, "max_results": max_results},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/software/ddg-search")
async def software_ddg_search(product: str, version: str = "", force: bool = False):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.get(
            f"{s.rag_api_url}/software/ddg-search",
            params={"product": product, "version": version, "force": str(force).lower()},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:500])
        try:
            return safe_json(resp)
        except Exception:
            raise HTTPException(502, f"Invalid JSON from rag-api: {resp.text[:200]}")


@router.get("/api/software/ddg-search/{job_id}")
async def software_ddg_search_status(job_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/software/ddg-search/{job_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:500])
        try:
            return safe_json(resp)
        except Exception:
            raise HTTPException(502, f"Invalid JSON from rag-api: {resp.text[:200]}")


@router.get("/api/scan-recommendations")
async def list_scan_recommendations(
    status: str = Query("pending", description="Filter by status: pending, completed, all"),
    limit: int = Query(100, ge=1, le=500),
):
    """List all scan recommendations from the DB, optionally filtered by status."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            params = {"limit": str(limit)}
            if status != "all":
                params["status"] = status
            resp = await c.get(
                f"{s.rag_api_url}/scan-recommendations",
                params=params,
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
            if resp.status_code == 200:
                return safe_json(resp)
            # Fallback: query DB directly if rag-api doesn't have the endpoint
            resp2 = await c.get(
                f"{s.scan_recommender_url}/recommendations",
                params=params,
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
            if resp2.status_code == 200:
                return resp2.json()
            return {"recommendations": [], "error": f"No endpoint available (rag-api: {resp.status_code}, recommender: {resp2.status_code})"}
    except Exception as e:
        return {"recommendations": [], "error": str(e)}


class AddScanRecommendationRequest(BaseModel):
    """Payload for POST /api/scan-recommendations.

    Used by the per-port "Suggest from KB" modal: operator picks a tool
    from the KB suggestions list, we materialize it as a scan_recommendations
    row with source='kb_manual' so it flows through the same dispatch +
    status-loop machinery as auto-generated recs.
    """
    ip: str
    port: Optional[int] = None
    service: Optional[str] = None
    scanner: str
    action: Optional[str] = None
    script: Optional[str] = None
    template: Optional[str] = None
    priority: int = 50
    extra: Optional[dict] = None


@router.post("/api/scan-recommendations")
async def add_scan_recommendation(body: AddScanRecommendationRequest):
    """Insert a manual KB-driven scan recommendation.

    Dedupes against the table's generated `fingerprint` column
    (md5 of ip|service|scanner|action|script|template) so adding the
    same KB tool twice for the same port returns the existing row
    instead of creating a duplicate.
    """
    extra = dict(body.extra or {})
    if body.port is not None:
        extra.setdefault("port", body.port)

    def _do_insert():
        from db import get_db
        with get_db() as conn, conn.cursor() as cur:
            # INSERT ... ON CONFLICT DO NOTHING ... RETURNING returns no rows
            # on a conflict, so we fall back to SELECT-by-fingerprint for the
            # existing row.  Fingerprint is a generated column, so we let PG
            # compute it -- this matches scan_recommender's persist path.
            cur.execute(
                """
                INSERT INTO scan_recommendations (
                    ip, service, scanner, action, script, template,
                    source, priority, extra, status
                )
                VALUES (
                    %s::inet, %s, %s, %s, %s, %s,
                    'kb_manual', %s, %s::jsonb, 'pending'
                )
                ON CONFLICT (fingerprint) DO NOTHING
                RETURNING id, status, created_at
                """,
                (
                    body.ip,
                    body.service,
                    body.scanner,
                    body.action,
                    body.script,
                    body.template,
                    body.priority,
                    Json(extra),
                ),
            )
            row = cur.fetchone()
            if row is None:
                # Conflict on fingerprint -- find the existing row.
                cur.execute(
                    """
                    SELECT id, status, created_at
                      FROM scan_recommendations
                     WHERE ip = %s::inet
                       AND COALESCE(service,'') = COALESCE(%s,'')
                       AND scanner = %s
                       AND COALESCE(action,'') = COALESCE(%s,'')
                       AND COALESCE(script,'') = COALESCE(%s,'')
                       AND COALESCE(template,'') = COALESCE(%s,'')
                     LIMIT 1
                    """,
                    (body.ip, body.service, body.scanner,
                     body.action, body.script, body.template),
                )
                row = cur.fetchone()
                conn.commit()
                return {"created": False, "row": row}
            conn.commit()
            return {"created": True, "row": row}

    try:
        result = await asyncio.to_thread(_do_insert)
    except Exception as e:
        log.warning("manual rec insert failed: %s", e)
        raise HTTPException(500, f"insert failed: {e}")

    row = result["row"]
    if row is None:
        # Theoretical race: conflict happened but the row also vanished.
        raise HTTPException(500, "insert raced with concurrent delete")
    rec_id, status, created_at = row

    # Best-effort webhook so external subscribers see operator-driven adds
    # alongside the auto-generated rule firings.
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            await c.post(
                f"{s.rag_api_url}/webhooks/emit",
                json={
                    "event_type": "scan_recommendation_manual_added",
                    "source": "bff",
                    "data": {
                        "rec_id": str(rec_id),
                        "ip": body.ip,
                        "port": body.port,
                        "service": body.service,
                        "scanner": body.scanner,
                        "action": body.action,
                        "deduplicated": not result["created"],
                    },
                },
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        log.debug(f"scan_recommendation_manual_added webhook failed: {e}")

    return {
        "ok": True,
        "created": result["created"],
        "id": str(rec_id),
        "status": status,
        "created_at": created_at.isoformat() if created_at else None,
    }


class RunRecommendationsRequest(BaseModel):
    ids: List[str]
    proxy: Optional[str] = None  # SOCKS proxy URL, e.g. socks5://node-manager:10001
    use_kali: bool = False       # Route manual tools to the internal Kali container
    node_id: Optional[str] = None  # Remote node for SSH-based tool execution


@router.post("/api/scan-recommendations/run")
async def run_scan_recommendations(body: RunRecommendationsRequest):
    """
    Run selected scan recommendations by dispatching them to the appropriate scanner services.
    Updates recommendation status to 'running' then 'completed' or 'failed'.
    """
    s = get_settings()
    headers = {"x-api-key": s.api_key, "Content-Type": "application/json", **engagement_headers()}
    results = []

    # Fetch the full recommendation details
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(
            f"{s.scan_recommender_url}/recommendations",
            params={"status": "all", "limit": 500},
            headers=headers,
        )
        all_recs = resp.json().get("recommendations", []) if resp.status_code == 200 else []

    recs_by_id = {r["id"]: r for r in all_recs}
    selected = [recs_by_id[rid] for rid in body.ids if rid in recs_by_id]

    if not selected:
        return {"ok": False, "error": "No matching recommendations found", "results": []}

    # Idempotency guard: a rec that's already 'queued' / 'running' / 'completed'
    # MUST NOT be re-dispatched -- doing so spawns a second runner job for the
    # same target and leaves the old job_id orphaned in the rec's extra.jsonb.
    # We split selected[] into dispatchable + already_active and emit a
    # 'skipped' result for the latter so the UI surfaces "already running".
    _ACTIVE_REC_STATES = {"queued", "running", "completed"}
    dispatchable = []
    already_active_results = []
    for rec in selected:
        cur_status = (rec.get("status") or "pending").lower()
        if cur_status in _ACTIVE_REC_STATES:
            already_active_results.append({
                "id": rec["id"],
                "scanner": rec.get("scanner"),
                "ip": rec.get("ip"),
                "status": "skipped",
                "detail": f"already {cur_status} -- skipped to prevent double-dispatch",
            })
        else:
            dispatchable.append(rec)
    selected = dispatchable

    # Map scanner → service URL
    SCANNER_URLS = {
        "nmap": s.nmap_scanner_url,
        "nuclei": s.nuclei_url,
        "nikto": s.web_scanner_url,
        "gobuster": s.web_scanner_url,
        "feroxbuster": s.web_scanner_url,
        "dirsearch": s.web_scanner_url,
        "ffuf": s.pd_runner_url,
        "whatweb": s.pd_runner_url,
        "httpx": s.pd_runner_url,
        "sqlmap": s.web_scanner_url,
        "metasploit": s.exploit_runner_url,
        "wfuzz": s.pd_runner_url,
        "wappalyzer": s.pd_runner_url,
        "subfinder": s.osint_runner_url,
        "dnsx": s.osint_runner_url,
        "alterx": s.osint_runner_url,
        "hydra": s.brutus_runner_url,
        "medusa": s.brutus_runner_url,
        "ncrack": s.brutus_runner_url,
        "vulnx": s.osint_runner_url,
    }

    # Tools that are manual/CLI-only — skip with explanation
    MANUAL_TOOLS = {
        "curl", "telnet", "netcat", "vncviewer", "irssi", "lftp", "ftp",
        "psql", "mysql", "rpcinfo", "showmount", "smtp-user-enum",
        "ssh-audit", "swaks", "mysqltuner", "rmg", "ajpycat",
    }

    proxy_url = body.proxy
    use_kali = body.use_kali
    node_id = body.node_id

    # Map scanner → endpoint and payload builder
    async def dispatch_rec(rec):
        scanner = rec.get("scanner", "").lower()
        ip = (rec.get("ip") or "").replace("/32", "")
        service_url = SCANNER_URLS.get(scanner)
        result = {"id": rec["id"], "scanner": scanner, "ip": ip}

        if not service_url:
            # Try Kali container for manual/CLI tools — preflight first.
            if use_kali and scanner not in ("metasploit",):
                pf = await _preflight_tool("kali", scanner, None)
                if not pf["ok"]:
                    result["status"] = "skipped"
                    result["detail"] = pf["detail"]
                    await _emit_tool_webhook("tool_unavailable",
                        {"tool": scanner, "executor": "kali", "ip": ip, "detail": pf["detail"]})
                    return result
                return await _dispatch_via_kali(rec, scanner, ip, result)
            # Try remote node via SSH — preflight first.
            if node_id and scanner not in ("metasploit",):
                pf = await _preflight_tool("node", scanner, node_id)
                if not pf["ok"]:
                    result["status"] = "skipped"
                    result["detail"] = pf["detail"]
                    await _emit_tool_webhook("tool_unavailable",
                        {"tool": scanner, "executor": f"node:{node_id}", "ip": ip, "detail": pf["detail"]})
                    return result
                return await _dispatch_via_node(rec, scanner, ip, node_id, result)
            if scanner in MANUAL_TOOLS:
                result["status"] = "skipped"
                result["detail"] = f"Manual tool — enable 'Use Kali' to run via internal Kali container"
            else:
                result["status"] = "skipped"
                result["detail"] = f"No automated handler for '{scanner}'"
            return result

        try:
            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                if scanner == "nmap":
                    script = rec.get("script", "")
                    action = rec.get("action", "")
                    # Nmap script recommendations (banner, http-title, etc.) are already covered
                    # by service detection — only dispatch actual port scans
                    if script and not any(kw in action.lower() for kw in ("port scan", "discovery", "full scan")):
                        result["status"] = "skipped"
                        result["detail"] = f"Nmap script '{script.split(' ')[0]}' — already run during service detection"
                        return result
                    payload = {"targets": [ip], "ports": str(rec.get("port", "1-1000"))}
                    if proxy_url:
                        payload["proxy"] = proxy_url
                    r = await client.post(f"{service_url}/jobs/masscan-then-nmap", json=payload, headers=headers)
                elif scanner == "nuclei":
                    template = rec.get("template", "")
                    payload = {"targets": [f"http://{ip}"]}
                    if template:
                        tags = [t.strip() for t in template.split(",") if t.strip()]
                        payload["tags"] = ",".join(tags)
                    if proxy_url:
                        payload["proxy"] = proxy_url
                    r = await client.post(f"{service_url}/jobs/nuclei-scan", json=payload, headers=headers)
                elif scanner in ("nikto", "gobuster"):
                    # web_scanner has per-tool endpoints (/jobs/nikto-scan,
                    # /jobs/gobuster) that take target_url and run JUST that
                    # tool, with each tool inserting directly into the
                    # web_findings table (no separate ingest step needed --
                    # different pattern from nuclei).  The old code routed
                    # everything to /jobs/web-scan, which runs the multi-
                    # tool pipeline (gobuster+playwright+katana+zap) and
                    # crucially DOES NOT INCLUDE NIKTO -- so a recon-agent
                    # dispatch of "nikto" actually never ran nikto.
                    port = rec.get("port") or 80
                    target_url = f"http://{ip}:{port}"
                    endpoint = "/jobs/nikto-scan" if scanner == "nikto" else "/jobs/gobuster"
                    payload = {"target_url": target_url}
                    if proxy_url:
                        payload["proxy"] = proxy_url
                    r = await client.post(f"{service_url}{endpoint}", json=payload, headers=headers)
                elif scanner in ("feroxbuster", "dirsearch", "sqlmap"):
                    # web_scanner does not yet have endpoints for these
                    # tools.  Mark as 'skipped' so the recon agent's Phase
                    # 4 (PR #33) updates the rec's DB status and stops
                    # re-picking it every cycle.  Operators can run these
                    # tools via the Kali container ("Use Kali" flag) until
                    # web_scanner exposes them natively.
                    result["status"] = "skipped"
                    result["detail"] = (
                        f"{scanner} not yet implemented in web_scanner -- "
                        "enable 'Use Kali' to run via internal Kali container"
                    )
                    return result
                elif scanner in ("whatweb", "httpx"):
                    payload = {"targets": [ip]}
                    if proxy_url:
                        payload["proxy"] = proxy_url
                    r = await client.post(f"{service_url}/jobs/{scanner}", json=payload, headers=headers)
                elif scanner in ("ffuf", "wfuzz"):
                    port = rec.get("port") or 80
                    payload = {"targets": [f"http://{ip}:{port}"]}
                    if proxy_url:
                        payload["proxy"] = proxy_url
                    r = await client.post(f"{service_url}/jobs/ffuf", json=payload, headers=headers)
                elif scanner in ("subfinder", "dnsx", "alterx"):
                    payload = {"domains": [ip]} if scanner == "subfinder" else {"targets": [ip]}
                    if isinstance(payload, dict) and "targets" in payload and proxy_url:
                        payload["proxy"] = proxy_url
                    r = await client.post(f"{service_url}/jobs/{scanner}", json=payload, headers=headers)
                elif scanner == "vulnx":
                    product = rec.get("banner", "").split(" ")[0] if rec.get("banner") else ip
                    r = await client.post(
                        f"{service_url}/jobs/vulnx",
                        json={"targets": [product]},
                        headers=headers,
                    )
                elif scanner in ("hydra", "medusa", "ncrack"):
                    port = rec.get("port") or 22
                    service_name = rec.get("service") or "ssh"
                    payload = {"targets": [ip], "protocols": [service_name]}
                    if proxy_url:
                        payload["proxy"] = proxy_url
                    r = await client.post(f"{service_url}/jobs/brutus", json=payload, headers=headers)
                elif scanner == "wappalyzer":
                    port = rec.get("port") or 80
                    r = await client.post(
                        f"{service_url}/jobs/whatweb",
                        json={"targets": [f"http://{ip}:{port}"]},
                        headers=headers,
                    )
                elif scanner == "metasploit":
                    module = rec.get("script", "")
                    if module:
                        result["status"] = "skipped"
                        result["detail"] = f"Metasploit module '{module}' — use Exploit Manager to execute"
                    else:
                        result["status"] = "skipped"
                        result["detail"] = "Metasploit — use Exploit Manager for module execution"
                    return result
                else:
                    result["status"] = "skipped"
                    result["detail"] = f"No dispatch handler for '{scanner}'"
                    return result

                if r.status_code in (200, 201, 202):
                    data = r.json()
                    job_id = data.get("job_id", "")
                    result["status"] = "dispatched"
                    result["job_id"] = job_id
                    result["detail"] = f"Scan started: {job_id[:8]}"
                    # Register with BFF job tracker so it shows in Scan Monitor.
                    # source_rec_id links the runner job back to the
                    # scan_recommendations row -- the polling loop uses this
                    # to backfill the rec's terminal status when the job
                    # finishes (see polling.py _backfill_recommendation_status).
                    if job_id and service_url:
                        try:
                            register_job(
                                job_id=job_id,
                                service_url=service_url,
                                scan_type=scanner,
                                target=ip,
                                proxy=proxy_url,
                                source_rec_id=rec["id"],
                            )
                        except Exception:
                            pass
                        # Close the first half of the rec lifecycle loop:
                        # mark queued + persist job_id + emit dispatched
                        # webhook.  Best-effort; the run itself has already
                        # been accepted by the scanner.
                        await _mark_rec_dispatched(
                            rec_id=rec["id"],
                            job_id=job_id,
                            ip=ip,
                            port=rec.get("port"),
                            service=rec.get("service"),
                            scanner=scanner,
                            node_id=node_id,
                        )
                else:
                    result["status"] = "failed"
                    result["detail"] = f"HTTP {r.status_code}: {r.text[:100]}"
        except Exception as e:
            result["status"] = "failed"
            result["detail"] = f"{type(e).__name__}: {str(e)[:80]}"
            log.warning(f"dispatch_rec {scanner} failed: {e}")

        return result

    async def _dispatch_via_kali(rec, scanner, ip, result):
        """Route tool execution to the internal Kali container."""
        command = rec.get("script", "")
        if not command:
            # Build a sensible default command
            port = rec.get("port") or ""
            service = rec.get("service") or ""
            if scanner in ("hydra", "medusa", "ncrack"):
                command = f"{scanner} -l admin -P /usr/share/wordlists/rockyou.txt {service}://{ip}:{port}" if port else f"{scanner} -l admin -P /usr/share/wordlists/rockyou.txt ssh://{ip}"
            elif scanner == "ssh-audit":
                command = f"ssh-audit {ip}"
            elif scanner in ("showmount",):
                command = f"showmount -e {ip}"
            elif scanner in ("rpcinfo",):
                command = f"rpcinfo -p {ip}"
            elif scanner in ("enum4linux",):
                command = f"enum4linux -a {ip}"
            elif scanner in ("smbclient", "smbmap"):
                command = f"{scanner} -L {ip} -N"
            elif scanner in ("snmpwalk",):
                command = f"snmpwalk -v2c -c public {ip}"
            elif scanner in ("nbtscan",):
                command = f"nbtscan {ip}"
            elif scanner in ("whatweb",):
                command = f"whatweb http://{ip}"
            else:
                command = f"{scanner} {ip}"
        # Replace placeholders
        command = command.replace("{target}", ip).replace("{ip}", ip)
        if rec.get("port"):
            command = command.replace("{port}", str(rec["port"]))

        try:
            async with httpx.AsyncClient(verify=False, timeout=60) as client:
                r = await client.post(
                    f"{s.kali_listener_url}/tools/execute",
                    json={"tool": scanner, "command": command, "target": ip},
                    headers=headers,
                )
                if r.status_code == 200:
                    data = r.json()
                    result["status"] = "dispatched"
                    result["detail"] = f"Kali: {command[:50]}"
                    exec_id = data.get("execution_id", data.get("id", ""))
                    result["exec_id"] = exec_id
                    result["via"] = "kali"
                    # Mark the rec dispatched so the idempotency guard stops it
                    # re-firing every agent cycle (kali exec is fire-and-forget,
                    # so without this the autonomous loop re-dispatches forever).
                    await _mark_rec_dispatched(
                        rec_id=rec["id"], job_id=exec_id or f"kali:{ip}",
                        ip=ip, port=rec.get("port"), service=rec.get("service"),
                        scanner=scanner, node_id=None,
                    )
                else:
                    result["status"] = "failed"
                    result["detail"] = f"Kali HTTP {r.status_code}: {r.text[:80]}"
        except Exception as e:
            result["status"] = "failed"
            result["detail"] = f"Kali: {type(e).__name__}: {str(e)[:60]}"
        return result

    async def _mark_rec_dispatched(
        rec_id: str, job_id: str, ip: str, port, service, scanner: str,
        node_id: Optional[str],
    ):
        """Close the first half of the rec → job lifecycle loop.

        Called immediately after a successful register_job().  Two side
        effects, both best-effort (a failure here must not roll back the
        scanner job that was already accepted):
          1. Direct UPDATE on scan_recommendations: status -> 'queued',
             executed_at = now(), and merge job_id (+ optional node_id)
             into the row's `extra` jsonb so the polling backfill can
             correlate completion events back to the rec.
          2. Emit a 'scan_recommendation_dispatched' webhook event so
             external subscribers (Slack, n8n) see the dispatch.

        psycopg2 is synchronous; we run the UPDATE in a worker thread via
        asyncio.to_thread so this coroutine doesn't block the event loop.
        """
        # Step 1: status writeback via direct DB (no HTTP hop -- the BFF
        # owns the trigger and has psycopg2 access via dashboard/bff/db.py).
        def _do_update():
            from db import get_db
            extra_merge = {"job_id": job_id}
            if node_id:
                extra_merge["node_id"] = node_id
            with get_db() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_recommendations
                       SET status = 'queued',
                           executed_at = COALESCE(executed_at, now()),
                           updated_at = now(),
                           extra = COALESCE(extra, '{}'::jsonb) || %s::jsonb
                     WHERE id = %s::uuid
                    """,
                    (Json(extra_merge), rec_id),
                )
                conn.commit()
                return cur.rowcount

        try:
            rows = await asyncio.to_thread(_do_update)
            if rows == 0:
                log.warning("rec dispatch writeback: rec_id=%s not found in DB", rec_id)
        except Exception as e:
            log.warning(f"failed to UPDATE rec {rec_id} to queued: {e}")

        # Step 2: fire-and-forget webhook.
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as c:
                await c.post(
                    f"{s.rag_api_url}/webhooks/emit",
                    json={
                        "event_type": "scan_recommendation_dispatched",
                        "source": "bff",
                        "data": {
                            "rec_id": rec_id,
                            "job_id": job_id,
                            "ip": ip,
                            "port": port,
                            "service": service,
                            "scanner": scanner,
                            "node_id": node_id,
                        },
                    },
                    headers={"x-api-key": s.api_key, **engagement_headers()},
                )
        except Exception as e:
            log.debug(f"scan_recommendation_dispatched webhook failed: {e}")

    async def _dispatch_via_node(rec, scanner, ip, nid, result):
        """Route tool execution to a remote node via SSH."""
        command = rec.get("script") or f"{scanner} {ip}"
        command = command.replace("{target}", ip).replace("{ip}", ip)
        try:
            async with httpx.AsyncClient(verify=False, timeout=60) as client:
                r = await client.post(
                    f"{s.tunnel_manager_url}/ssh/{nid}/exec",
                    json={"command": command, "timeout": 45},
                    headers=headers,
                )
                if r.status_code == 200:
                    data = r.json()
                    exit_code = data.get("exit_code", data.get("returncode", -1))
                    result["status"] = "dispatched" if exit_code == 0 else "failed"
                    result["detail"] = f"Node {nid}: exit={exit_code}"
                    result["output"] = (data.get("stdout", "") or "")[:200]
                    result["via"] = f"node:{nid}"
                    # Mark dispatched so the agent doesn't re-fire it each cycle.
                    if exit_code == 0:
                        await _mark_rec_dispatched(
                            rec_id=rec["id"], job_id=f"node:{nid}",
                            ip=ip, port=rec.get("port"), service=rec.get("service"),
                            scanner=scanner, node_id=nid,
                        )
                else:
                    result["status"] = "failed"
                    result["detail"] = f"Node SSH HTTP {r.status_code}"
        except Exception as e:
            result["status"] = "failed"
            result["detail"] = f"Node: {type(e).__name__}"
        return result

    async def _emit_tool_webhook(event_type, data, severity=None):
        """Fire-and-forget capability webhook (preflight install / unavailable)."""
        try:
            payload = {"event_type": event_type, "source": "bff", "data": data}
            if severity:
                payload["severity"] = severity
            async with httpx.AsyncClient(verify=False, timeout=5) as c:
                await c.post(f"{s.rag_api_url}/webhooks/emit", json=payload,
                             headers={"x-api-key": s.api_key, **engagement_headers()})
        except Exception as e:
            log.debug(f"{event_type} webhook failed: {e}")

    async def _preflight_tool(executor, scanner, nid):
        """Confirm `scanner` is callable on the chosen executor; auto-install if
        missing. Returns {"ok": bool, "detail": str}. Best-effort: on probe
        error we allow the dispatch through (don't block on a flaky check)."""
        try:
            if executor == "kali":
                async with httpx.AsyncClient(verify=False, timeout=10) as c:
                    chk = await c.get(f"{s.kali_listener_url}/tools/check",
                                      params={"tools": scanner}, headers=headers)
                    if chk.status_code == 200 and scanner in (chk.json().get("found") or []):
                        return {"ok": True, "detail": "present"}
                # Missing → attempt install
                async with httpx.AsyncClient(verify=False, timeout=600) as c:
                    inst = await c.post(f"{s.kali_listener_url}/tools/install",
                                        json={"tool": scanner}, headers=headers)
                ok = inst.status_code == 200 and (inst.json() or {}).get("installed")
                await _emit_tool_webhook("tool_preflight_install",
                    {"tool": scanner, "executor": "kali", "ok": bool(ok)})
                return {"ok": bool(ok),
                        "detail": "installed on kali" if ok else f"'{scanner}' missing on kali; install failed"}
            else:  # node
                async with httpx.AsyncClient(verify=False, timeout=30) as c:
                    chk = await c.post(f"{s.tunnel_manager_url}/ssh/{nid}/exec",
                                       json={"command": f"which {scanner}", "timeout": 15},
                                       headers=headers)
                    if chk.status_code == 200 and chk.json().get("exit_code") == 0:
                        return {"ok": True, "detail": "present"}
                    # Missing → install via apt on the node, then recheck.
                    await c.post(f"{s.tunnel_manager_url}/ssh/{nid}/exec",
                                 json={"command": f"DEBIAN_FRONTEND=noninteractive apt-get install -y {scanner}",
                                       "timeout": 300}, headers=headers)
                    recheck = await c.post(f"{s.tunnel_manager_url}/ssh/{nid}/exec",
                                           json={"command": f"which {scanner}", "timeout": 15},
                                           headers=headers)
                    ok = recheck.status_code == 200 and recheck.json().get("exit_code") == 0
                await _emit_tool_webhook("tool_preflight_install",
                    {"tool": scanner, "executor": f"node:{nid}", "ok": bool(ok)})
                return {"ok": bool(ok),
                        "detail": f"installed on node {nid}" if ok else f"'{scanner}' missing on node {nid}; install failed"}
        except Exception as e:
            # Don't block dispatch on a flaky preflight probe.
            log.debug(f"preflight {executor}/{scanner} error: {e}")
            return {"ok": True, "detail": f"preflight skipped ({type(e).__name__})"}

    dispatched_results = await asyncio.gather(*[dispatch_rec(r) for r in selected])
    # Combine fresh dispatches with the idempotency-guard skips so the UI
    # sees one consistent list -- "already queued" recs surface as skipped.
    results = list(dispatched_results) + already_active_results

    dispatched = sum(1 for r in results if r.get("status") == "dispatched")
    failed = sum(1 for r in results if r.get("status") == "failed")
    skipped = sum(1 for r in results if r.get("status") == "skipped")

    return {
        "ok": dispatched > 0,
        "total": len(results),
        "dispatched": dispatched,
        "failed": failed,
        "skipped": skipped,
        "results": results,
    }


# Tools the recommender routes to dedicated runner services (not Kali/nodes).
# "Covered" by their own container; listed so the coverage audit can tell
# native-runner tools apart from generic Kali/node tools.
_NATIVE_RUNNER_TOOLS = {
    "nmap", "nuclei", "nikto", "gobuster", "feroxbuster", "dirsearch", "ffuf",
    "whatweb", "httpx", "sqlmap", "metasploit", "wfuzz", "wappalyzer",
    "subfinder", "dnsx", "alterx", "hydra", "medusa", "ncrack", "vulnx",
}


@router.get("/api/recommender/tool-coverage")
async def recommender_tool_coverage(live: bool = Query(False)):
    """Capability matrix: every tool in the canonical registry × executors
    {native-runner, kali, each online node} → is it callable?

    Sources: node_manager /tools/registry (universe), kali /tools/check (real
    `which`), and per-node provision-status (cached unless live=true).  Lets an
    operator see, before dispatching, which recommended tools can actually run
    and where the gaps are.
    """
    s = get_settings()
    headers = {"x-api-key": s.api_key, **engagement_headers()}
    universe, kali_found, nodes_cov = [], set(), {}

    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        # 1. Universe from the canonical registry.
        try:
            r = await c.get(f"{s.tunnel_manager_url}/tools/registry", headers=headers)
            if r.status_code == 200:
                universe = sorted(set((r.json() or {}).get("names", [])) | _NATIVE_RUNNER_TOOLS)
        except Exception as e:
            log.warning(f"tool-coverage: registry fetch failed: {e}")
            universe = sorted(_NATIVE_RUNNER_TOOLS)

        # 2. Kali real presence.
        try:
            kr = await c.get(f"{s.kali_listener_url}/tools/check",
                             params={"tools": ",".join(universe)}, headers=headers)
            if kr.status_code == 200:
                kali_found = set(kr.json().get("found") or [])
        except Exception as e:
            log.debug(f"tool-coverage: kali check failed: {e}")

        # 3. Online nodes: cached provisioned tools (or live probe).
        try:
            nr = await c.get(f"{s.tunnel_manager_url}/nodes", headers=headers)
            online = [n for n in (nr.json().get("nodes") or [])
                      if n.get("status") == "online"] if nr.status_code == 200 else []
            for node in online:
                nid = node.get("id")
                try:
                    pr = await c.get(f"{s.tunnel_manager_url}/ssh/{nid}/provision-status",
                                     params={"live": str(live).lower()}, headers=headers,
                                     timeout=120 if live else 15)
                    prov = set((pr.json() or {}).get("provisioned_tools") or []) if pr.status_code == 200 else set()
                except Exception:
                    prov = set()
                nodes_cov[nid] = {"name": node.get("name"), "tools": sorted(prov)}
        except Exception as e:
            log.debug(f"tool-coverage: nodes fetch failed: {e}")

    matrix = {}
    for tool in universe:
        matrix[tool] = {
            "native_runner": tool in _NATIVE_RUNNER_TOOLS,
            "kali": tool in kali_found,
            "nodes": {nid: (tool in cov["tools"]) for nid, cov in nodes_cov.items()},
        }
    # A tool is "callable somewhere" if a native runner exists, kali has it, or any node does.
    uncovered = [t for t, m in matrix.items()
                 if not (m["native_runner"] or m["kali"] or any(m["nodes"].values()))]
    return {
        "ok": True,
        "universe_count": len(universe),
        "nodes": {nid: cov["name"] for nid, cov in nodes_cov.items()},
        "uncovered": uncovered,
        "matrix": matrix,
    }


class ToolCheckRequest(BaseModel):
    node_id: str
    tools: List[str]


class ToolInstallRequest(BaseModel):
    node_id: str
    tools: List[str]


# Package manager install commands for common pentest tools
TOOL_INSTALL_MAP = {
    "nmap": "apt-get install -y nmap",
    "nikto": "apt-get install -y nikto",
    "gobuster": "apt-get install -y gobuster",
    "feroxbuster": "apt-get install -y feroxbuster || cargo install feroxbuster",
    "dirsearch": "pip3 install dirsearch",
    "ffuf": "apt-get install -y ffuf || go install github.com/ffuf/ffuf/v2@latest",
    "wfuzz": "pip3 install wfuzz",
    "sqlmap": "apt-get install -y sqlmap",
    "whatweb": "apt-get install -y whatweb",
    "hydra": "apt-get install -y hydra",
    "medusa": "apt-get install -y medusa",
    "ncrack": "apt-get install -y ncrack",
    "netcat": "apt-get install -y netcat-openbsd",
    "curl": "apt-get install -y curl",
    "telnet": "apt-get install -y telnet",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || apt-get install -y nuclei",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "ssh-audit": "pip3 install ssh-audit",
    "smtp-user-enum": "apt-get install -y smtp-user-enum",
    "rpcinfo": "apt-get install -y rpcbind",
    "showmount": "apt-get install -y nfs-common",
    "vncviewer": "apt-get install -y tigervnc-viewer",
    "swaks": "apt-get install -y swaks",
    "vulnx": "pip3 install vulnx",
    "wappalyzer": "npm install -g wappalyzer",
    "ajpycat": "pip3 install ajpycat",
    "irssi": "apt-get install -y irssi",
    "psql": "apt-get install -y postgresql-client",
    "mysql": "apt-get install -y default-mysql-client",
}


@router.post("/api/tools/check")
async def check_tools_on_node(body: ToolCheckRequest):
    """Check which tools are installed on Kali container or remote node."""
    s = get_settings()
    headers = {"x-api-key": s.api_key, "Content-Type": "application/json", **engagement_headers()}

    # Internal Kali container — use /tools/allowed endpoint
    if body.node_id in ("kali-local", "kali", "internal"):
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                r = await client.get(
                    f"{s.kali_listener_url}/tools/allowed",
                    headers=headers,
                )
                if r.status_code == 200:
                    allowed = set(t.lower() for t in r.json().get("tools", []))
                    found = [t for t in body.tools if t.lower() in allowed]
                    missing = [
                        {"tool": t, "install": TOOL_INSTALL_MAP.get(t, f"apt-get install -y {t}")}
                        for t in body.tools if t.lower() not in allowed
                    ]
                    return {"ok": True, "node_id": "kali-local", "found": found, "missing": missing, "total": len(body.tools)}
                return {"ok": False, "error": f"Kali health: HTTP {r.status_code}"}
        except Exception as e:
            return {"ok": False, "error": f"Kali unreachable: {e}"}

    # Remote node — use SSH exec
    checks = " && ".join(f'(which {t} >/dev/null 2>&1 && echo "FOUND:{t}" || echo "MISSING:{t}")' for t in body.tools)
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            r = await client.post(
                f"{s.tunnel_manager_url}/ssh/{body.node_id}/exec",
                json={"command": checks, "timeout": 20},
                headers=headers,
            )
            if r.status_code != 200:
                return {"ok": False, "error": f"SSH exec failed: HTTP {r.status_code}"}

            output = r.json().get("stdout", "") or r.json().get("output", "")
            found = []
            missing = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if line.startswith("FOUND:"):
                    found.append(line.replace("FOUND:", ""))
                elif line.startswith("MISSING:"):
                    tool = line.replace("MISSING:", "")
                    install_cmd = TOOL_INSTALL_MAP.get(tool, f"apt-get install -y {tool}")
                    missing.append({"tool": tool, "install": install_cmd})

            return {"ok": True, "node_id": body.node_id, "found": found, "missing": missing, "total": len(body.tools)}
    except Exception as e:
        log.error(f"check_tools failed: {e}")
        return {"ok": False, "error": str(e)}


@router.post("/api/tools/install")
async def install_tools_on_node(body: ToolInstallRequest):
    """Install missing tools on the internal Kali container or a remote node.

    The Recommendations UI sends node_id='kali-local' (the same sentinel
    /api/tools/check accepts). Previously this handler ignored that and always
    tried to SSH to a node literally named 'kali-local', so every Kali-targeted
    install failed. Route the Kali sentinels to the Kali listener's own
    /tools/install (registry-driven), and only fall back to SSH for real nodes.
    """
    s = get_settings()
    headers = {"x-api-key": s.api_key, "Content-Type": "application/json", **engagement_headers()}
    results = []

    # Internal Kali container — use the listener's /tools/install endpoint.
    if body.node_id in ("kali-local", "kali", "internal"):
        async with httpx.AsyncClient(verify=False, timeout=300) as client:
            for tool in body.tools:
                try:
                    r = await client.post(
                        f"{s.kali_listener_url}/tools/install",
                        json={"tool": tool, "timeout": 180},
                        headers=headers,
                    )
                    if r.status_code == 200 and r.json().get("installed"):
                        results.append({"tool": tool, "status": "installed", "detail": "Success"})
                    else:
                        detail = (r.json().get("detail") if r.status_code == 200 else f"HTTP {r.status_code}")
                        results.append({"tool": tool, "status": "failed", "detail": (detail or "")[:200]})
                except Exception as e:
                    results.append({"tool": tool, "status": "failed", "detail": str(e)[:100]})
        installed = sum(1 for r in results if r["status"] == "installed")
        return {
            "ok": installed > 0,
            "node_id": "kali-local",
            "total": len(body.tools),
            "installed": installed,
            "failed": sum(1 for r in results if r["status"] == "failed"),
            "results": results,
        }

    # Remote node — install via SSH exec.
    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        for tool in body.tools:
            install_cmd = TOOL_INSTALL_MAP.get(tool)
            if not install_cmd:
                results.append({"tool": tool, "status": "skipped", "detail": "No install command known"})
                continue

            try:
                r = await client.post(
                    f"{s.tunnel_manager_url}/ssh/{body.node_id}/exec",
                    json={"command": f"DEBIAN_FRONTEND=noninteractive {install_cmd}", "timeout": 90},
                    headers=headers,
                )
                if r.status_code == 200:
                    data = r.json()
                    exit_code = data.get("exit_code", data.get("returncode", -1))
                    if exit_code == 0:
                        results.append({"tool": tool, "status": "installed", "detail": "Success"})
                    else:
                        stderr = (data.get("stderr", "") or "")[:200]
                        results.append({"tool": tool, "status": "failed", "detail": stderr or f"Exit code {exit_code}"})
                else:
                    results.append({"tool": tool, "status": "failed", "detail": f"HTTP {r.status_code}"})
            except Exception as e:
                results.append({"tool": tool, "status": "failed", "detail": str(e)[:100]})

    installed = sum(1 for r in results if r["status"] == "installed")
    return {
        "ok": installed > 0,
        "node_id": body.node_id,
        "total": len(body.tools),
        "installed": installed,
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "results": results,
    }


@router.get("/api/assets/{ip}/recommendations")
async def port_recommendations(
    ip: str,
    service: str = Query(None),
    banner: str = Query(None),
    port: int = Query(None),
):
    s = get_settings()
    params = {"ip": ip, "persist": "false"}
    if service:
        params["service"] = service
    if banner:
        params["banner"] = banner
    if port:
        params["port"] = str(port)
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.scan_recommender_url}/next_scan",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/software/vulnx-findings")
async def get_vulnx_findings(
    product: str = Query(...),
    version: str = Query(""),
    ip: str = Query(None),
):
    s = get_settings()
    params = {"product": product}
    if version:
        params["version"] = version
    if ip:
        params["ip"] = ip
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/software/vulnx-findings",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)
