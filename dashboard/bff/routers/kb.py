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


# ── Per-service / per-port operator prompts ──────────────────────────────────
# Straight proxies to scan-recommender's /kb/prompts endpoints, which own the
# service_prompts table and the RAG training-doc indexing. Webhooks are emitted
# upstream (service_prompt_saved / service_prompt_deleted), so unlike the KB
# override routes above these don't re-emit here.

@router.get("/api/kb/prompts")
async def list_service_prompts(
    service: str | None = None,
    port: int | None = None,
    engagement_id: str | None = None,
    enabled_only: bool = False,
):
    s = get_settings()
    params = {k: v for k, v in {
        "service": service, "port": port,
        "engagement_id": engagement_id,
        "enabled_only": str(enabled_only).lower(),
    }.items() if v not in (None, "")}
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.scan_recommender_url}/kb/prompts", params=params)
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/kb/prompts/resolve")
async def resolve_service_prompts(
    service: str | None = None,
    port: int | None = None,
    tech: str | None = None,
    engagement_id: str | None = None,
):
    """Preview what guidance + training context a (service, port, tech) would inject."""
    s = get_settings()
    params = {k: v for k, v in {
        "service": service, "port": port, "tech": tech,
        "engagement_id": engagement_id,
    }.items() if v not in (None, "")}
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(f"{s.scan_recommender_url}/kb/prompts/resolve", params=params)
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/kb/prompts")
async def create_service_prompt(body: Dict[str, Any] = Body(...)):
    s = get_settings()
    # Training-note indexing embeds the text, so allow more headroom than the
    # 15s used by the other KB proxies.
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(f"{s.scan_recommender_url}/kb/prompts", json=body)
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.put("/api/kb/prompts/{prompt_id}")
async def update_service_prompt(prompt_id: str, body: Dict[str, Any] = Body(...)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.put(f"{s.scan_recommender_url}/kb/prompts/{prompt_id}", json=body)
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/kb/prompts/{prompt_id}")
async def delete_service_prompt(prompt_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.delete(f"{s.scan_recommender_url}/kb/prompts/{prompt_id}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/kb/web-guidance")
async def web_scan_guidance(
    ip: str | None = None,
    service: str | None = "http",
    port: int | None = None,
    tech: str | None = None,
    engagement_id: str | None = None,
):
    """Operator training applicable to scanning one web target.

    Returns guidance text, retrieved training context, and suggested nuclei tags
    for whatever technology was detected. A web profile decides how deep to dig;
    this decides what to look for once the stack is known.
    """
    s = get_settings()
    params = {k: v for k, v in {
        "ip": ip, "service": service, "port": port, "tech": tech,
        "engagement_id": engagement_id,
    }.items() if v not in (None, "")}
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(f"{s.scan_recommender_url}/kb/web-guidance", params=params)
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
