"""
RAG proxy router.

Surfaces the scan_recommender's /rag/ask + /rag/feedback endpoints
through the BFF so the dashboard can:
  1. Ask the knowledge base questions (Layer 1 — every call gets logged).
  2. Rate the answers and mark individual retrieved chunks helpful or
     unhelpful (Layer 2 — closes the feedback loop, producing training
     data for embedding fine-tuning + reranker / GRPO training).

Engagement-scoped: ``apiFetch`` on the frontend already attaches an
``X-Engagement-Id`` header on every request, and ``engagement_headers()``
spreads it through to the scan_recommender so the rag_query_log and
rag_feedback rows are tagged to the active engagement.
"""

from typing import List, Optional
import logging
import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()
log = logging.getLogger("rag")


class RagAskRequest(BaseModel):
    q: str
    top_k: int = 6


class RagFeedbackRequest(BaseModel):
    query_log_id: str
    rating: int = 0
    helpful_chunk_ids: Optional[List[int]] = None
    unhelpful_chunk_ids: Optional[List[int]] = None
    comment: Optional[str] = None
    reviewer_id: Optional[str] = None


@router.post("/api/rag/ask")
async def rag_ask(req: RagAskRequest):
    """Forward an RAG question to the scan_recommender.

    The scan_recommender embeds the query, retrieves top-K chunks from
    exploit_chunks, generates an answer, logs the call into rag_query_log,
    and returns ``{answer, sources, retrieved, query_log_id, duration_ms}``.
    The frontend uses ``query_log_id`` to submit feedback referencing this
    specific call.
    """
    s = get_settings()
    params = {"q": req.q, "top_k": req.top_k}
    try:
        async with httpx.AsyncClient(verify=False, timeout=180) as c:
            resp = await c.get(
                f"{s.scan_recommender_url}/rag/ask",
                params=params,
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        raise HTTPException(502, f"scan_recommender unreachable: {e}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.post("/api/rag/feedback")
async def rag_feedback(req: RagFeedbackRequest):
    """Record operator feedback on a previously-logged /rag/ask call.

    -1 = thumbs down, 0 = neutral / unrated, 1 = thumbs up.  2-5 reserved
    for star-scale UIs.  ``unhelpful_chunk_ids`` carries the most valuable
    signal -- high-similarity chunks the operator confirms were NOT
    actually relevant ("hard negatives" for embedding fine-tuning).
    """
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            resp = await c.post(
                f"{s.scan_recommender_url}/rag/feedback",
                json=req.dict(),
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        raise HTTPException(502, f"scan_recommender unreachable: {e}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.get("/api/rag/feedback/stats")
async def rag_feedback_stats(days: int = Query(30, ge=1, le=365)):
    """Summary stats: total queries, fraction rated, rating distribution,
    and the top hard-negative chunks (the most-marked-unhelpful ids).
    Surfaced on the KnowledgeBase page so operators can see whether the
    feedback loop is producing useful training data."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            resp = await c.get(
                f"{s.scan_recommender_url}/rag/feedback/stats",
                params={"days": days},
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        raise HTTPException(502, f"scan_recommender unreachable: {e}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.get("/api/rag/training/preview")
async def rag_training_preview(
    days: int = Query(90, ge=1, le=365),
    min_rating: Optional[int] = Query(None, ge=-1, le=5),
):
    """Counts-only preview of what /rag/training/export would produce
    right now: how many embedding triplets, reranker rows, GRPO rows
    can we extract from the current rag_query_log + rag_feedback tables.
    Cheap to call; safe to poll from the dashboard."""
    s = get_settings()
    params: dict = {"days": days}
    if min_rating is not None:
        params["min_rating"] = min_rating
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            resp = await c.get(
                f"{s.scan_recommender_url}/rag/training/preview",
                params=params,
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        raise HTTPException(502, f"scan_recommender unreachable: {e}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


class RagTrainingExportRequest(BaseModel):
    days: int = 90
    min_rating: Optional[int] = None
    subdir_prefix: Optional[str] = None  # scan_recommender sanitises this


class RagEvalRunRequest(BaseModel):
    model_label: str = "baseline"
    top_k: int = 10
    days: int = 365
    notes: Optional[str] = None


@router.post("/api/rag/eval/run")
async def rag_eval_run(req: RagEvalRunRequest):
    """Run a retrieval evaluation pass against the current state of
    rag_query_log + rag_feedback.  Replays every rated query, computes
    NDCG@K / MRR / recall@K / precision@K against the operator-labeled
    helpful chunks, and persists the run into rag_eval_runs."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=300) as c:
            resp = await c.post(
                f"{s.scan_recommender_url}/rag/eval/run",
                json=req.dict(),
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        raise HTTPException(502, f"scan_recommender unreachable: {e}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.get("/api/rag/eval/history")
async def rag_eval_history(limit: int = Query(20, ge=1, le=200)):
    """Recent eval runs, most recent first.  Per-query details dropped --
    fetch /api/rag/eval/{id} for the full breakdown."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            resp = await c.get(
                f"{s.scan_recommender_url}/rag/eval/history",
                params={"limit": limit},
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        raise HTTPException(502, f"scan_recommender unreachable: {e}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.post("/api/rag/training/export")
async def rag_training_export(req: RagTrainingExportRequest):
    """Materialise the three RAG training datasets (embedding triplets,
    reranker rows, GRPO RLHF rows) as JSONL on the host filesystem.
    Returns the manifest of files written + counts.

    Files land in /datasets/rag-YYYYMMDD-HHMMSS/ on the host (bind-
    mounted from scan-recommender's /datasets).  The grpo_trainer
    service can pick them up directly when it's deployed."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=300) as c:
            resp = await c.post(
                f"{s.scan_recommender_url}/rag/training/export",
                json=req.dict(),
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except Exception as e:
        raise HTTPException(502, f"scan_recommender unreachable: {e}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)
