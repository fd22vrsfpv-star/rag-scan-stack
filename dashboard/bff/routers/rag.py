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
