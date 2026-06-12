import logging
from typing import Any, Dict
import httpx
from fastapi import APIRouter, HTTPException, Body
from utils import safe_json

from config import get_settings
from engagement import engagement_headers

router = APIRouter()
log = logging.getLogger("bff.kb")


async def _emit_kb_webhook(event_type: str, name: str, extra: Dict[str, Any] | None = None):
    """Fire-and-forget webhook so external subscribers see KB override
    edits.  Write to the rag-api's /webhooks/emit endpoint -- failure
    here must not roll back the override change that already succeeded.

    `kb_service_overrides` has no `engagement_id` column (overrides are
    global), so the engagement header passed through here is purely for
    audit trail context, not for filtering.
    """
    s = get_settings()
    data: Dict[str, Any] = {"service_name": name}
    if extra:
        data.update(extra)
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            await c.post(
                f"{s.rag_api_url}/webhooks/emit",
                json={"event_type": event_type, "source": "bff_kb", "data": data},
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        log.debug("%s webhook emit failed for %s: %s", event_type, name, e)


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
        result = safe_json(resp)
    # Webhook *after* the upstream write succeeds so a webhook delivery
    # failure doesn't make the override change look unsuccessful.
    await _emit_kb_webhook(
        "kb_override_updated",
        name,
        {
            "tool_count": len((body.get("tools") or [])),
            "msf_count": len((body.get("metasploit") or [])),
            "nuclei_tags": body.get("nuclei_tags") or [],
        },
    )
    return result


@router.delete("/api/kb/services/{name}")
async def delete_kb_service(name: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(f"{s.scan_recommender_url}/kb/services/{name}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        result = safe_json(resp)
    await _emit_kb_webhook("kb_override_deleted", name)
    return result


# ── Tool-selection feedback (durable loop that steers which tools get picked) ──

@router.get("/api/kb/feedback")
async def list_kb_feedback():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.scan_recommender_url}/kb/feedback")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/kb/feedback")
async def add_kb_feedback(body: Dict[str, Any] = Body(...)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(f"{s.scan_recommender_url}/kb/feedback", json=body)
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/kb/feedback/{feedback_id}")
async def delete_kb_feedback(feedback_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(f"{s.scan_recommender_url}/kb/feedback/{feedback_id}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
