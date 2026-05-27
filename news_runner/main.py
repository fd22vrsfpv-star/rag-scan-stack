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
    item_id: str


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
    with psycopg2.connect(news_agent.DB_DSN) as conn:
        hits = news_agent._match_assets(conn, body.item_id)
    return {"ok": True, "asset_hits": hits}


@app.post("/jobs/github-search")
def jobs_github_search(body: ItemActionBody, x_api_key: Optional[str] = None):
    _check_key(x_api_key)
    import psycopg2
    with psycopg2.connect(news_agent.DB_DSN) as conn:
        repos = news_agent._github_search(conn, body.item_id)
    return {"ok": True, "repos": repos}


@app.post("/jobs/enrich")
def jobs_enrich(body: ItemActionBody, x_api_key: Optional[str] = None):
    _check_key(x_api_key)
    n = news_agent._enrich_pending(limit=1, item_ids=[body.item_id])
    return {"ok": True, "enriched": n}


@app.post("/jobs/refresh-kev")
def jobs_refresh_kev(x_api_key: Optional[str] = None):
    _check_key(x_api_key)
    return news_agent.refresh_cisa_kev()
