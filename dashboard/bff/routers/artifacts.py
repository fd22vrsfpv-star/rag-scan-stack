"""Raw scan output — browsing, LLM processing state, and follow-on actions.

Thin proxy over rag-api's /artifacts endpoints. The only logic here is
parameter forwarding: the artifact store, the suggestion rules and the
already-run check all live in rag-api so the CLI and the UI see identical
behaviour.

TLS verification is ON for every call (pentest-dashboard mounts /certs and sets
REQUESTS_CA_BUNDLE). If a call starts failing with CERTIFICATE_VERIFY_FAILED,
regenerate the bundle with scripts/generate-ca-bundle.sh rather than
reinstating verify=False.
"""
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()

# Artifacts are whole tool outputs — a listing that inlined them would move
# megabytes per page — so `include_content` stays off unless asked for. The
# detail view fetches one artifact at a time.
LIST_TIMEOUT = 30
# Suggestion analysis reads the full artifact and runs every rule over it.
ACTIONS_TIMEOUT = 60


class CustomAction(BaseModel):
    title: str
    scanner: str
    script: str
    priority: int = 60
    rationale: Optional[str] = None
    category: str = "manual"


class QueueActionsRequest(BaseModel):
    action_ids: List[str] = []
    # action_id -> {"script": ..., "priority": ...}. Required to queue a
    # needs_input action, whose placeholders must be filled in first.
    overrides: Dict[str, Dict[str, Any]] = {}
    custom_actions: List[CustomAction] = []
    engagement_id: Optional[str] = None


class AutoQueueSetting(BaseModel):
    enabled: bool


class ProcessedRequest(BaseModel):
    llm_status: str = "done"
    llm_model: Optional[str] = None
    llm_result: Optional[dict] = None
    llm_error: Optional[str] = None


def _hdrs():
    s = get_settings()
    return {"x-api-key": s.api_key, **engagement_headers()}


@router.get("/api/artifacts")
async def list_artifacts(llm_status: Optional[str] = None, tool: Optional[str] = None,
                         target: Optional[str] = None, source: Optional[str] = None,
                         content_format: Optional[str] = None,
                         limit: int = 50, offset: int = 0):
    """Paginated list of stored raw outputs. Content deliberately omitted."""
    s = get_settings()
    params = {"limit": str(limit), "offset": str(offset)}
    for k, v in (("llm_status", llm_status), ("tool", tool), ("target", target),
                 ("source", source), ("content_format", content_format)):
        if v:
            params[k] = v
    async with httpx.AsyncClient(timeout=LIST_TIMEOUT) as c:
        resp = await c.get(f"{s.rag_api_url}/artifacts", params=params, headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/artifacts/stats")
async def artifact_stats():
    """Queue depth by processing state. Declared BEFORE /{artifact_id} —
    FastAPI matches in definition order, so the dynamic route would otherwise
    swallow 'stats' and 404 on a UUID lookup."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=LIST_TIMEOUT) as c:
        resp = await c.get(f"{s.rag_api_url}/artifacts/stats", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/artifacts/auto-queue")
async def get_auto_queue():
    """Whether high-confidence follow-ups queue themselves on store, which
    rules opt in, and any rule-file errors."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=LIST_TIMEOUT) as c:
        resp = await c.get(f"{s.rag_api_url}/artifacts/auto-queue", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/artifacts/auto-queue")
async def set_auto_queue(req: AutoQueueSetting):
    """Turn automatic queuing on or off. Never affects already-queued items."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=LIST_TIMEOUT) as c:
        resp = await c.post(f"{s.rag_api_url}/artifacts/auto-queue",
                            json=req.model_dump(), headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/artifacts/{artifact_id}")
async def get_artifact(artifact_id: str):
    """One artifact including its complete, untruncated content."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=LIST_TIMEOUT) as c:
        resp = await c.get(f"{s.rag_api_url}/artifacts/{artifact_id}", headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/artifacts/{artifact_id}/actions")
async def get_artifact_actions(artifact_id: str):
    """Follow-on actions derived from this artifact, each citing its evidence."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=ACTIONS_TIMEOUT) as c:
        resp = await c.get(f"{s.rag_api_url}/artifacts/{artifact_id}/actions",
                           headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/artifacts/{artifact_id}/actions/queue")
async def queue_artifact_actions(artifact_id: str, req: QueueActionsRequest):
    """Queue chosen actions as scan recommendations (existing dispatch path)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=ACTIONS_TIMEOUT) as c:
        resp = await c.post(f"{s.rag_api_url}/artifacts/{artifact_id}/actions/queue",
                            json=req.model_dump(), headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/artifacts/{artifact_id}/processed")
async def mark_processed(artifact_id: str, req: ProcessedRequest):
    """Record an LLM pass outcome, or requeue by posting llm_status='pending'."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=ACTIONS_TIMEOUT) as c:
        resp = await c.post(f"{s.rag_api_url}/artifacts/{artifact_id}/processed",
                            json=req.model_dump(), headers=_hdrs())
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
