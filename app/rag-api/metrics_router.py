"""
Pipeline Performance Metrics Router for RAG Scan Stack API

Provides endpoints to query scan pipeline timing, per-session breakdowns,
and aggregate performance statistics across all scan types.
"""

import os
import psycopg2
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Depends, Header
from pydantic import BaseModel, Field
from datetime import datetime

router = APIRouter(prefix="/metrics", tags=["Metrics"])

API_KEY = os.environ.get("API_KEY", "changeme")
DB_DSN = os.environ.get("DB_DSN", "dbname=scans user=app password=app host=127.0.0.1 port=5432")


def auth(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid X-API-Key")
    return True


def get_db():
    return psycopg2.connect(DB_DSN)


# --- Response Models ---

class ScanStageMetric(BaseModel):
    metric_source: str = Field(..., description="Source table (jobs, tasks, session_scan_metrics, etc.)")
    entity_id: str = Field(..., description="Row ID from the source table")
    scan_type: str = Field(..., description="Scan type (masscan, nmap, playwright, etc.)")
    status: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None


class SessionMetricsResponse(BaseModel):
    session_id: str
    stages: List[ScanStageMetric]
    total_duration_seconds: Optional[float] = Field(None, description="Wall-clock time from first start to last finish")
    slowest_stage: Optional[Dict[str, Any]] = Field(None, description="Stage with longest duration")
    stage_gaps: List[Dict[str, Any]] = Field(default_factory=list, description="Idle gaps between consecutive stages")


class AggregateStatRow(BaseModel):
    scan_type: str
    count: int = 0
    avg_duration: Optional[float] = None
    min_duration: Optional[float] = None
    max_duration: Optional[float] = None
    p50_duration: Optional[float] = None
    p95_duration: Optional[float] = None
    success_count: int = 0
    failure_count: int = 0
    success_rate: Optional[float] = None


class AggregateMetricsResponse(BaseModel):
    days: int
    scan_type_filter: Optional[str] = None
    stats: List[AggregateStatRow]


class RecentScanMetric(BaseModel):
    metric_source: str
    entity_id: str
    session_id: Optional[str] = None
    scan_type: str
    status: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None


class RecentMetricsResponse(BaseModel):
    limit: int
    scan_type_filter: Optional[str] = None
    scans: List[RecentScanMetric]


class ModelComparisonRow(BaseModel):
    model_name: str
    total_requests: int = 0
    avg_latency_ms: Optional[float] = None
    p50_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    avg_total_tokens: Optional[float] = None
    avg_prompt_tokens: Optional[float] = None
    avg_completion_tokens: Optional[float] = None
    tool_call_rate_pct: Optional[float] = None
    error_rate_pct: Optional[float] = None
    session_count: int = 0


class ModelComparisonResponse(BaseModel):
    days: int
    session_id_filter: Optional[str] = None
    models: List[ModelComparisonRow]


class LLMRequestMetric(BaseModel):
    id: str
    session_id: Optional[str] = None
    agent_name: Optional[str] = None
    caller: Optional[str] = None
    model_name: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    tokens_per_sec: Optional[float] = None
    latency_ms: float
    has_tool_calls: bool = False
    tool_call_count: int = 0
    tool_names: Optional[List[str]] = None
    is_error: bool = False
    error_message: Optional[str] = None
    request_params: Optional[dict] = None
    created_at: Optional[datetime] = None


class LLMRequestsResponse(BaseModel):
    limit: int
    session_id_filter: Optional[str] = None
    model_filter: Optional[str] = None
    requests: List[LLMRequestMetric]


# --- Endpoints ---

@router.get("/session/{session_id}", response_model=SessionMetricsResponse,
            summary="Per-session timing breakdown")
def get_session_metrics(
    session_id: str,
    authorized: bool = Depends(auth),
):
    """
    Return per-stage timing breakdown for a specific session.
    Shows each scan phase, duration, the slowest stage, and inter-stage gaps.
    """
    from psycopg2.extras import RealDictCursor

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get all metrics for this session from the unified view
        cur.execute("""
            SELECT metric_source, entity_id, scan_type, status,
                   started_at, finished_at, duration_seconds
            FROM pipeline_performance
            WHERE session_id = %s::uuid
            ORDER BY started_at ASC NULLS LAST
        """, (session_id,))
        rows = cur.fetchall()

        # Also pull from session_scan_metrics directly if the view missed any
        # (the view already includes it, but let's also check agent_sessions for the session itself)
        if not rows:
            # Fallback: check if it's an agent session and get related data
            cur.execute("""
                SELECT metric_source, entity_id, scan_type, status,
                       started_at, finished_at, duration_seconds
                FROM pipeline_performance
                WHERE entity_id = %s
                ORDER BY started_at ASC NULLS LAST
            """, (session_id,))
            rows = cur.fetchall()

    stages = []
    for row in rows:
        stages.append(ScanStageMetric(
            metric_source=row["metric_source"],
            entity_id=row["entity_id"],
            scan_type=row["scan_type"],
            status=row["status"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            duration_seconds=float(row["duration_seconds"]) if row["duration_seconds"] is not None else None,
        ))

    # Compute total wall-clock duration
    started_times = [s.started_at for s in stages if s.started_at]
    finished_times = [s.finished_at for s in stages if s.finished_at]
    total_duration = None
    if started_times and finished_times:
        total_duration = (max(finished_times) - min(started_times)).total_seconds()

    # Find slowest stage
    slowest = None
    for s in stages:
        if s.duration_seconds is not None:
            if slowest is None or s.duration_seconds > slowest.duration_seconds:
                slowest = s
    slowest_dict = None
    if slowest:
        slowest_dict = {
            "scan_type": slowest.scan_type,
            "metric_source": slowest.metric_source,
            "duration_seconds": slowest.duration_seconds,
        }

    # Compute inter-stage gaps
    gaps = []
    sorted_stages = sorted(
        [s for s in stages if s.started_at and s.finished_at],
        key=lambda s: s.started_at,
    )
    for i in range(1, len(sorted_stages)):
        prev_end = sorted_stages[i - 1].finished_at
        curr_start = sorted_stages[i].started_at
        if prev_end and curr_start and curr_start > prev_end:
            gap_sec = (curr_start - prev_end).total_seconds()
            gaps.append({
                "after": sorted_stages[i - 1].scan_type,
                "before": sorted_stages[i].scan_type,
                "gap_seconds": gap_sec,
            })

    return SessionMetricsResponse(
        session_id=session_id,
        stages=stages,
        total_duration_seconds=total_duration,
        slowest_stage=slowest_dict,
        stage_gaps=gaps,
    )


@router.get("/aggregate", response_model=AggregateMetricsResponse,
            summary="Aggregate performance statistics")
def get_aggregate_metrics(
    days: int = Query(30, ge=1, le=365, description="Look-back window in days"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    authorized: bool = Depends(auth),
):
    """
    Return historical aggregate stats: avg/min/max/p50/p95 duration per scan type,
    plus success/failure rates.
    """
    from psycopg2.extras import RealDictCursor

    where_clauses = ["started_at >= now() - interval '%s days'"]
    params: list = [days]

    if scan_type:
        where_clauses.append("scan_type = %s")
        params.append(scan_type)

    where_sql = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
        SELECT
            scan_type,
            COUNT(*) AS count,
            AVG(duration_seconds) AS avg_duration,
            MIN(duration_seconds) AS min_duration,
            MAX(duration_seconds) AS max_duration,
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY duration_seconds) AS p50_duration,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_seconds) AS p95_duration,
            SUM(CASE WHEN status IN ('finished', 'completed') THEN 1 ELSE 0 END) AS success_count,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failure_count
        FROM pipeline_performance
        {where_sql}
          AND duration_seconds IS NOT NULL
        GROUP BY scan_type
        ORDER BY count DESC
    """

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    stats = []
    for row in rows:
        total = row["success_count"] + row["failure_count"]
        success_rate = (row["success_count"] / total * 100) if total > 0 else None
        stats.append(AggregateStatRow(
            scan_type=row["scan_type"],
            count=row["count"],
            avg_duration=round(float(row["avg_duration"]), 2) if row["avg_duration"] is not None else None,
            min_duration=round(float(row["min_duration"]), 2) if row["min_duration"] is not None else None,
            max_duration=round(float(row["max_duration"]), 2) if row["max_duration"] is not None else None,
            p50_duration=round(float(row["p50_duration"]), 2) if row["p50_duration"] is not None else None,
            p95_duration=round(float(row["p95_duration"]), 2) if row["p95_duration"] is not None else None,
            success_count=row["success_count"],
            failure_count=row["failure_count"],
            success_rate=round(success_rate, 1) if success_rate is not None else None,
        ))

    return AggregateMetricsResponse(
        days=days,
        scan_type_filter=scan_type,
        stats=stats,
    )


@router.get("/recent", response_model=RecentMetricsResponse,
            summary="Recent completed scans with timing")
def get_recent_metrics(
    limit: int = Query(20, ge=1, le=200, description="Max results"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    authorized: bool = Depends(auth),
):
    """
    Return the most recent completed scans with timing information.
    """
    from psycopg2.extras import RealDictCursor

    where_clauses = ["duration_seconds IS NOT NULL"]
    params: list = []

    if scan_type:
        where_clauses.append("scan_type = %s")
        params.append(scan_type)

    where_sql = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
        SELECT metric_source, entity_id, session_id,
               scan_type, status, started_at, finished_at, duration_seconds
        FROM pipeline_performance
        {where_sql}
        ORDER BY started_at DESC NULLS LAST
        LIMIT %s
    """
    params.append(limit)

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    scans = []
    for row in rows:
        scans.append(RecentScanMetric(
            metric_source=row["metric_source"],
            entity_id=row["entity_id"],
            session_id=str(row["session_id"]) if row["session_id"] else None,
            scan_type=row["scan_type"],
            status=row["status"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            duration_seconds=float(row["duration_seconds"]) if row["duration_seconds"] is not None else None,
        ))

    return RecentMetricsResponse(
        limit=limit,
        scan_type_filter=scan_type,
        scans=scans,
    )


@router.get("/models/compare", response_model=ModelComparisonResponse,
            summary="LLM model comparison dashboard")
def get_model_comparison(
    days: int = Query(7, ge=1, le=365, description="Look-back window in days"),
    session_id: Optional[str] = Query(None, description="Filter by session UUID"),
    authorized: bool = Depends(auth),
):
    """
    Compare LLM models by latency, token usage, tool call rate, and error rate.
    Groups metrics by model_name with aggregate statistics.
    """
    from psycopg2.extras import RealDictCursor

    where_clauses = ["created_at >= now() - interval '%s days'"]
    params: list = [days]

    if session_id:
        where_clauses.append("session_id = %s::uuid")
        params.append(session_id)

    where_sql = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
        SELECT
            model_name,
            COUNT(*) AS total_requests,
            ROUND(AVG(latency_ms)::numeric, 1) AS avg_latency_ms,
            ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p50_latency_ms,
            ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p95_latency_ms,
            ROUND(AVG(total_tokens)::numeric, 0) AS avg_total_tokens,
            ROUND(AVG(prompt_tokens)::numeric, 0) AS avg_prompt_tokens,
            ROUND(AVG(completion_tokens)::numeric, 0) AS avg_completion_tokens,
            ROUND(SUM(CASE WHEN has_tool_calls THEN 1 ELSE 0 END)::numeric / NULLIF(COUNT(*), 0) * 100, 1) AS tool_call_rate_pct,
            ROUND(SUM(CASE WHEN is_error THEN 1 ELSE 0 END)::numeric / NULLIF(COUNT(*), 0) * 100, 1) AS error_rate_pct,
            COUNT(DISTINCT session_id) AS session_count
        FROM llm_request_metrics
        {where_sql}
        GROUP BY model_name
        ORDER BY total_requests DESC
    """

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    models = []
    for row in rows:
        models.append(ModelComparisonRow(
            model_name=row["model_name"],
            total_requests=row["total_requests"],
            avg_latency_ms=float(row["avg_latency_ms"]) if row["avg_latency_ms"] is not None else None,
            p50_latency_ms=float(row["p50_latency_ms"]) if row["p50_latency_ms"] is not None else None,
            p95_latency_ms=float(row["p95_latency_ms"]) if row["p95_latency_ms"] is not None else None,
            avg_total_tokens=float(row["avg_total_tokens"]) if row["avg_total_tokens"] is not None else None,
            avg_prompt_tokens=float(row["avg_prompt_tokens"]) if row["avg_prompt_tokens"] is not None else None,
            avg_completion_tokens=float(row["avg_completion_tokens"]) if row["avg_completion_tokens"] is not None else None,
            tool_call_rate_pct=float(row["tool_call_rate_pct"]) if row["tool_call_rate_pct"] is not None else None,
            error_rate_pct=float(row["error_rate_pct"]) if row["error_rate_pct"] is not None else None,
            session_count=row["session_count"],
        ))

    return ModelComparisonResponse(
        days=days,
        session_id_filter=session_id,
        models=models,
    )


@router.get("/models/requests", response_model=LLMRequestsResponse,
            summary="Raw per-request LLM metrics")
def get_llm_requests(
    limit: int = Query(50, ge=1, le=500, description="Max results"),
    session_id: Optional[str] = Query(None, description="Filter by session UUID"),
    model: Optional[str] = Query(None, description="Filter by model name"),
    caller: Optional[str] = Query(None, description="Filter by caller (e.g. searchsploit_analyze, ddg_cve_search)"),
    authorized: bool = Depends(auth),
):
    """
    Return raw per-request LLM metrics for debugging and analysis.
    """
    from psycopg2.extras import RealDictCursor

    where_clauses = []
    params: list = []

    if session_id:
        where_clauses.append("session_id = %s::uuid")
        params.append(session_id)

    if model:
        where_clauses.append("model_name = %s")
        params.append(model)

    if caller:
        where_clauses.append("caller ILIKE %s")
        params.append(f"%{caller}%")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    sql = f"""
        SELECT id, session_id, agent_name, caller, model_name,
               prompt_tokens, completion_tokens, total_tokens, tokens_per_sec,
               latency_ms, has_tool_calls, tool_call_count, tool_names,
               is_error, error_message, request_params, created_at
        FROM llm_request_metrics
        {where_sql}
        ORDER BY created_at DESC
        LIMIT %s
    """
    params.append(limit)

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    requests_list = []
    for row in rows:
        requests_list.append(LLMRequestMetric(
            id=str(row["id"]),
            session_id=str(row["session_id"]) if row.get("session_id") else None,
            agent_name=row.get("agent_name"),
            caller=row.get("caller"),
            model_name=row["model_name"],
            prompt_tokens=row["prompt_tokens"],
            completion_tokens=row["completion_tokens"],
            total_tokens=row["total_tokens"],
            tokens_per_sec=float(row["tokens_per_sec"]) if row.get("tokens_per_sec") else None,
            latency_ms=float(row["latency_ms"]),
            has_tool_calls=row["has_tool_calls"],
            tool_call_count=row["tool_call_count"],
            tool_names=row["tool_names"],
            is_error=row["is_error"],
            error_message=row["error_message"],
            request_params=row.get("request_params"),
            created_at=row["created_at"],
        ))

    return LLMRequestsResponse(
        limit=limit,
        session_id_filter=session_id,
        model_filter=model,
        requests=requests_list,
    )


@router.get("/llm/summary", summary="LLM usage summary by caller")
def get_llm_summary(
    days: int = Query(7, ge=1, le=90),
    authorized: bool = Depends(auth),
):
    """Aggregated LLM usage stats grouped by caller."""
    from psycopg2.extras import RealDictCursor
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT COALESCE(caller, agent_name, 'unknown') as caller,
                   model_name,
                   COUNT(*) as total_calls,
                   SUM(CASE WHEN is_error THEN 1 ELSE 0 END) as error_count,
                   ROUND(AVG(latency_ms)) as avg_latency_ms,
                   ROUND(AVG(tokens_per_sec)::numeric, 1) as avg_tok_per_sec,
                   ROUND(AVG(total_tokens)::numeric) as avg_tokens,
                   SUM(total_tokens) as total_tokens_used,
                   MIN(created_at) as first_call,
                   MAX(created_at) as last_call
            FROM llm_request_metrics
            WHERE created_at > now() - interval '%s days'
            GROUP BY COALESCE(caller, agent_name, 'unknown'), model_name
            ORDER BY total_calls DESC
        """, (days,))
        rows = cur.fetchall()
    return {"days": days, "callers": [dict(r) for r in rows]}
