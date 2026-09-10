"""News Runner — FastAPI service exposing news-cycle and deep-search jobs.

rag-api proxies its trigger endpoints (POST /news/ingest etc.) here; the BFF
and frontend never see this service directly. All endpoints respond
immediately with a job/run id; work happens in BackgroundTasks.

Read-only and CRUD endpoints (GET /news/items, PATCH /news/items/{id}, etc.)
stay in rag-api since they're pure DB queries.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel

import news_agent

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)-14s %(levelname)-5s %(message)s")
log = logging.getLogger("news_runner")

app = FastAPI(title="News Runner")

API_KEY = os.environ.get("API_KEY", "changeme")


def _check_key(x_api_key: Optional[str]) -> None:
    """Lightweight gate so rag-api can authenticate calls."""
    if x_api_key and x_api_key == API_KEY:
        return
    # Allow empty in dev; rag-api always sends one in compose.
    if x_api_key is None:
        return
    raise HTTPException(401, "bad api key")


class IngestBody(BaseModel):
    source_id: Optional[str] = None


class DeepSearchBody(BaseModel):
    topic: str
    include_deleted: Optional[bool] = False
    refresh_llm: Optional[bool] = False
    max_items: Optional[int] = 50


class ItemActionBody(BaseModel):
    """One item, or many. `item_id` is kept for the existing single-item
    callers (rag-api's /news/items/{id}/enrich); `item_ids` carries an
    operator's multi-select from the News page."""
    item_id: Optional[str] = None
    item_ids: Optional[list] = None


# Enrichment is an LLM call per item. A select-all over thousands of rows must
# not turn into thousands of LLM calls, so a batch beyond this is REFUSED
# (429) rather than accepted and abandoned half-way.
MAX_ENRICH_BATCH = int(os.environ.get("NEWS_MAX_ENRICH_BATCH", "100"))


def _ids_from(body: "ItemActionBody") -> list:
    """Collapse item_id + item_ids into one de-duplicated, order-stable list."""
    seen, out = set(), []
    for i in ([body.item_id] if body.item_id else []) + list(body.item_ids or []):
        i = str(i).strip()
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _require_one(body: "ItemActionBody") -> str:
    ids = _ids_from(body)
    if not ids:
        raise HTTPException(400, "item_id is required")
    return ids[0]


@app.on_event("startup")
def startup_event():
    """Pulls the CISA KEV catalog once on startup, then hands off to the
    daily scheduler thread."""
    try:
        news_agent.refresh_cisa_kev()
    except Exception:
        log.exception("initial CISA KEV refresh failed (continuing)")
    try:
        news_agent.start_scheduler()
    except Exception:
        log.exception("news_agent.start_scheduler failed (continuing)")


@app.get("/health")
def health():
    return {"ok": True, "service": "news-runner"}


@app.post("/jobs/ingest")
def jobs_ingest(body: IngestBody, background_tasks: BackgroundTasks,
                x_api_key: Optional[str] = None):
    _check_key(x_api_key)
    run_id = news_agent.start_run(triggered_by="manual")

    def _bg():
        try:
            stats = news_agent.fetch_all_sources(run_id=run_id, source_id=body.source_id)
            news_agent.finish_run(run_id, stats)
        except Exception as e:
            log.exception("ingest failed")
            news_agent.finish_run(run_id, {}, error=str(e))

    background_tasks.add_task(_bg)
    return {"ok": True, "run_id": run_id, "status": "running"}


@app.post("/jobs/deep-search")
def jobs_deep_search(body: DeepSearchBody, background_tasks: BackgroundTasks,
                     x_api_key: Optional[str] = None):
    _check_key(x_api_key)
    run_id = news_agent.start_run(triggered_by="deep_search", topic=body.topic)

    def _bg():
        try:
            summary = news_agent.deep_search(
                topic=body.topic, include_deleted=bool(body.include_deleted),
                refresh_llm=bool(body.refresh_llm), max_items=int(body.max_items or 50),
            )
            news_agent.finish_run(run_id, {
                "sources_fetched": 0, "articles_seen": 0,
                "items_new": 0, "items_updated": 0,
                "items_enriched": summary.get("matched_items", 0),
                "per_source": summary.get("items", []),
            })
        except Exception as e:
            log.exception("deep_search failed")
            news_agent.finish_run(run_id, {}, error=str(e))

    background_tasks.add_task(_bg)
    return {"ok": True, "run_id": run_id, "topic": body.topic}


@app.post("/jobs/match-assets")
def jobs_match_assets(body: ItemActionBody, x_api_key: Optional[str] = None):
    _check_key(x_api_key)
    import psycopg2
    item_id = _require_one(body)
    with psycopg2.connect(news_agent.DB_DSN) as conn:
        hits = news_agent._match_assets(conn, item_id)
    return {"ok": True, "asset_hits": hits}


@app.post("/jobs/github-search")
def jobs_github_search(body: ItemActionBody, x_api_key: Optional[str] = None):
    _check_key(x_api_key)
    import psycopg2
    item_id = _require_one(body)
    with psycopg2.connect(news_agent.DB_DSN) as conn:
        repos = news_agent._github_search(conn, item_id)
    return {"ok": True, "repos": repos}


@app.post("/jobs/enrich")
def jobs_enrich(body: ItemActionBody, background_tasks: BackgroundTasks,
                x_api_key: Optional[str] = None):
    """Enrich the items the operator selected — nothing else.

    Ingest no longer LLM-enriches anything, so this is the only path that
    spends an LLM call on a news item (plus deep-search's topic fan-out).

    One id runs inline so the row is updated by the time the UI refetches.
    Many run in the background: N LLM calls will outlive any sane HTTP
    timeout, and admitting a request we then abandon wastes the work twice.
    """
    _check_key(x_api_key)
    ids = _ids_from(body)
    if not ids:
        raise HTTPException(400, "item_id or item_ids is required")
    if len(ids) > MAX_ENRICH_BATCH:
        raise HTTPException(
            429,
            f"{len(ids)} items exceeds NEWS_MAX_ENRICH_BATCH={MAX_ENRICH_BATCH}; "
            f"narrow the selection and retry",
        )

    if len(ids) == 1:
        r = news_agent._enrich_pending(limit=1, item_ids=ids)
        news_agent._emit_webhook("news_items_enriched", "news_runner",
                                 {**r, "item_ids": ids, "mode": "inline"})
        # 429 upward: llm_query already retried with the provider's Retry-After,
        # so reaching here means the quota is genuinely gone. Saying so beats
        # returning enriched:0 and letting it read as "nothing to do".
        if r["rate_limited"] and not r["enriched"]:
            raise HTTPException(
                429,
                "LLM provider quota exhausted (rate limited after retries) — "
                "the item was not enriched; retry later or lower load",
            )
        return {"ok": True, "requested": 1, "enriched": r["enriched"],
                "rate_limited": r["rate_limited"], "failed": r["failed"],
                "queued": 0}

    def _bg():
        try:
            r = news_agent._enrich_pending(limit=len(ids), item_ids=ids)
            news_agent._emit_webhook("news_items_enriched", "news_runner",
                                     {**r, "item_ids": ids,
                                      "mode": "background"})
            if r["rate_limited"]:
                # The operator cannot see a background return value, so the
                # quota condition has to reach them another way.
                news_agent._emit_webhook(
                    "news_items_enrich_rate_limited", "news_runner",
                    {**r, "note": "provider quota exhausted; some items "
                                  "were not enriched"})
        except Exception as e:
            log.exception("bulk enrich failed")
            news_agent._emit_webhook("news_items_enrich_failed", "news_runner",
                                     {"requested": len(ids), "error": str(e)})

    background_tasks.add_task(_bg)
    news_agent._emit_webhook("news_items_enrich_dispatched", "news_runner",
                             {"requested": len(ids), "item_ids": ids})
    return {"ok": True, "requested": len(ids), "enriched": None,
            "queued": len(ids)}


@app.post("/jobs/stage2")
def jobs_stage2(background_tasks: BackgroundTasks, x_api_key: Optional[str] = None):
    """Asset-match + GitHub-PoC across items ALREADY flagged kev/rce.

    This used to fire automatically at the end of every ingest. It is now
    operator-triggered: the work is a GitHub API call plus an asset query per
    item, and it is only meaningful once enrichment has flagged something.
    """
    _check_key(x_api_key)

    def _bg():
        try:
            n = news_agent._stage2_for_flagged_items()
            news_agent._emit_webhook("news_stage2_completed", "news_runner",
                                     {"items_processed": n})
        except Exception as e:
            log.exception("stage2 failed")
            news_agent._emit_webhook("news_stage2_failed", "news_runner",
                                     {"error": str(e)})

    background_tasks.add_task(_bg)
    return {"ok": True, "queued": True}


@app.post("/jobs/refresh-kev")
def jobs_refresh_kev(x_api_key: Optional[str] = None):
    _check_key(x_api_key)
    return news_agent.refresh_cisa_kev()
