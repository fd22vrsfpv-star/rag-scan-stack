"""
FastAPI router for webhook management endpoints.
"""

import os
import json
import time
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Query, Header
from fastapi.responses import HTMLResponse
import psycopg2
from psycopg2.extras import RealDictCursor

from .models import (
    WebhookCreate,
    WebhookUpdate,
    WebhookResponse,
    WebhookEventResponse,
    WebhookListResponse,
    WebhookEventListResponse,
    WebhookTestRequest,
    WebhookTestResponse,
    WebhookEmitRequest,
)
from .dispatcher import deliver_webhook, emit_webhook
from .formatters import format_payload
from .ui import WEBHOOKS_UI_HTML

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

# Configuration
DB_DSN = os.environ.get("DB_DSN", "dbname=scans user=app password=app host=127.0.0.1 port=5432")
API_KEY = os.environ.get("API_KEY", "changeme")


def get_db():
    """Get database connection."""
    return psycopg2.connect(DB_DSN)


def auth(x_api_key: str = Header(...)):
    """API key authentication dependency."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid X-API-Key")
    return True


@router.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def webhooks_ui():
    """Webhook monitoring dashboard UI."""
    return HTMLResponse(content=WEBHOOKS_UI_HTML)


@router.get("/stats")
def get_webhook_stats(authorized: bool = Depends(auth)):
    """Get aggregated webhook statistics for dashboard."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get webhook counts
        cur.execute("SELECT COUNT(*) as total FROM webhooks")
        total_webhooks = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as enabled FROM webhooks WHERE enabled = true")
        enabled_webhooks = cur.fetchone()["enabled"]

        # Get event counts by status
        cur.execute("""
            SELECT status, COUNT(*) as cnt
            FROM webhook_events
            GROUP BY status
        """)
        status_counts = {row["status"]: row["cnt"] for row in cur.fetchall()}

        delivered = status_counts.get("delivered", 0)
        failed = status_counts.get("failed", 0)
        retrying = status_counts.get("retrying", 0)
        pending = status_counts.get("pending", 0)

        total_events = delivered + failed + retrying + pending
        success_rate = (delivered / total_events * 100) if total_events > 0 else 100.0

        # Get top failing webhooks
        cur.execute("""
            SELECT w.name, w.failure_count
            FROM webhooks w
            WHERE w.failure_count > 0
            ORDER BY w.failure_count DESC
            LIMIT 5
        """)
        top_failing = [{"name": row["name"], "failures": row["failure_count"]} for row in cur.fetchall()]

    return {
        "webhooks": {
            "total": total_webhooks,
            "enabled": enabled_webhooks,
            "disabled": total_webhooks - enabled_webhooks
        },
        "events": {
            "delivered": delivered,
            "failed": failed,
            "retrying": retrying,
            "pending": pending
        },
        "success_rate": round(success_rate, 1),
        "top_failing": top_failing
    }


@router.post("", response_model=WebhookResponse, status_code=201)
def create_webhook(webhook: WebhookCreate, authorized: bool = Depends(auth)):
    """Create a new webhook configuration."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO webhooks (name, url, secret, enabled, event_types, sources, severities, max_retries, timeout_ms)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, name, url, enabled, event_types, sources, severities, max_retries, timeout_ms,
                      created_at, updated_at, last_success, failure_count
        """, (
            webhook.name,
            webhook.url,
            webhook.secret,
            webhook.enabled,
            webhook.event_types,
            webhook.sources,
            webhook.severities,
            webhook.max_retries,
            webhook.timeout_ms
        ))
        row = cur.fetchone()
        conn.commit()

    return WebhookResponse(
        id=str(row["id"]),
        name=row["name"],
        url=row["url"],
        enabled=row["enabled"],
        event_types=row["event_types"] or [],
        sources=row["sources"],
        severities=row["severities"],
        max_retries=row["max_retries"],
        timeout_ms=row["timeout_ms"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_success=row["last_success"],
        failure_count=row["failure_count"]
    )


@router.get("", response_model=WebhookListResponse)
def list_webhooks(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    authorized: bool = Depends(auth)
):
    """List all webhook configurations."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        where_clauses = []
        params = []

        if enabled is not None:
            where_clauses.append("enabled = %s")
            params.append(enabled)

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        # Get total count
        cur.execute(f"SELECT COUNT(*) as total FROM webhooks {where_sql}", params)
        total = cur.fetchone()["total"]

        # Get webhooks
        cur.execute(f"""
            SELECT id, name, url, enabled, event_types, sources, severities, max_retries, timeout_ms,
                   created_at, updated_at, last_success, failure_count
            FROM webhooks
            {where_sql}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])
        rows = cur.fetchall()

    webhooks = [
        WebhookResponse(
            id=str(row["id"]),
            name=row["name"],
            url=row["url"],
            enabled=row["enabled"],
            event_types=row["event_types"] or [],
            sources=row["sources"],
            severities=row["severities"],
            max_retries=row["max_retries"],
            timeout_ms=row["timeout_ms"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_success=row["last_success"],
            failure_count=row["failure_count"]
        )
        for row in rows
    ]

    return WebhookListResponse(webhooks=webhooks, total=total)


# NOTE: /events and /emit MUST be defined BEFORE /{webhook_id} to avoid route conflicts
@router.delete("/events")
def delete_webhook_events(
    event_ids: Optional[List[str]] = Query(None, description="Specific event IDs to delete"),
    status: Optional[str] = Query(None, description="Delete all events with this status"),
    older_than_hours: Optional[int] = Query(None, description="Delete events older than N hours"),
    authorized: bool = Depends(auth)
):
    """
    Delete webhook events.

    Can delete by:
    - Specific event IDs (event_ids parameter)
    - All events with a given status (status parameter)
    - Events older than N hours (older_than_hours parameter)
    - All events (if no filters provided, deletes all)
    """
    with get_db() as conn, conn.cursor() as cur:
        if event_ids:
            # Delete specific events
            cur.execute(
                "DELETE FROM webhook_events WHERE id = ANY(%s) RETURNING id",
                (event_ids,)
            )
        elif status:
            cur.execute(
                "DELETE FROM webhook_events WHERE status = %s RETURNING id",
                (status,)
            )
        elif older_than_hours:
            cur.execute(
                "DELETE FROM webhook_events WHERE created_at < NOW() - INTERVAL '%s hours' RETURNING id",
                (older_than_hours,)
            )
        else:
            # Delete all events
            cur.execute("DELETE FROM webhook_events RETURNING id")

        deleted_count = cur.rowcount
        conn.commit()

    return {"deleted": deleted_count}


@router.delete("/events/{event_id}", status_code=204)
def delete_webhook_event(event_id: str, authorized: bool = Depends(auth)):
    """Delete a single webhook event by ID."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM webhook_events WHERE id = %s RETURNING id", (event_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Event not found")
        conn.commit()


@router.get("/events", response_model=WebhookEventListResponse)
def list_webhook_events(
    webhook_id: Optional[str] = Query(None, description="Filter by webhook ID"),
    status: Optional[str] = Query(None, description="Filter by status (pending, delivered, failed, retrying)"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    authorized: bool = Depends(auth)
):
    """List webhook delivery events."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        where_clauses = []
        params = []

        if webhook_id:
            where_clauses.append("webhook_id = %s")
            params.append(webhook_id)
        if status:
            where_clauses.append("status = %s")
            params.append(status)
        if event_type:
            where_clauses.append("event_type = %s")
            params.append(event_type)

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        # Get total count
        cur.execute(f"SELECT COUNT(*) as total FROM webhook_events {where_sql}", params)
        total = cur.fetchone()["total"]

        # Get events
        cur.execute(f"""
            SELECT id, webhook_id, event_type, payload, status, attempt, response_code,
                   error_message, created_at, delivered_at, next_retry
            FROM webhook_events
            {where_sql}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])
        rows = cur.fetchall()

    events = [
        WebhookEventResponse(
            id=str(row["id"]),
            webhook_id=str(row["webhook_id"]),
            event_type=row["event_type"],
            payload=row["payload"] if isinstance(row["payload"], dict) else json.loads(row["payload"]),
            status=row["status"],
            attempt=row["attempt"],
            response_code=row["response_code"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            delivered_at=row["delivered_at"],
            next_retry=row["next_retry"]
        )
        for row in rows
    ]

    return WebhookEventListResponse(events=events, total=total)


@router.post("/sink", include_in_schema=False)
def webhook_sink():
    """
    Internal log sink — always returns 200.

    The default 'event-log' webhook points here so every scanner event
    is recorded in webhook_events with status=delivered.
    """
    return {"ok": True}


@router.post("/emit")
def emit_webhook_event(req: WebhookEmitRequest, authorized: bool = Depends(auth)):
    """
    Internal endpoint for scanners to emit webhook events.

    This is called by scanner services when jobs complete or findings are detected.
    """
    count = emit_webhook(
        event_type=req.event_type,
        source=req.source,
        data=req.data,
        severity=req.severity
    )

    return {"ok": True, "webhooks_notified": count}


@router.get("/{webhook_id}", response_model=WebhookResponse)
def get_webhook(webhook_id: str, authorized: bool = Depends(auth)):
    """Get a webhook configuration by ID."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, name, url, enabled, event_types, sources, severities, max_retries, timeout_ms,
                   created_at, updated_at, last_success, failure_count
            FROM webhooks
            WHERE id = %s
        """, (webhook_id,))
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return WebhookResponse(
        id=str(row["id"]),
        name=row["name"],
        url=row["url"],
        enabled=row["enabled"],
        event_types=row["event_types"] or [],
        sources=row["sources"],
        severities=row["severities"],
        max_retries=row["max_retries"],
        timeout_ms=row["timeout_ms"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_success=row["last_success"],
        failure_count=row["failure_count"]
    )


@router.put("/{webhook_id}", response_model=WebhookResponse)
def update_webhook(webhook_id: str, webhook: WebhookUpdate, authorized: bool = Depends(auth)):
    """Update a webhook configuration."""
    # Build update query dynamically based on provided fields
    updates = []
    params = []

    if webhook.name is not None:
        updates.append("name = %s")
        params.append(webhook.name)
    if webhook.url is not None:
        updates.append("url = %s")
        params.append(webhook.url)
    if webhook.secret is not None:
        updates.append("secret = %s")
        params.append(webhook.secret)
    if webhook.enabled is not None:
        updates.append("enabled = %s")
        params.append(webhook.enabled)
    if webhook.event_types is not None:
        updates.append("event_types = %s")
        params.append(webhook.event_types)
    if webhook.sources is not None:
        updates.append("sources = %s")
        params.append(webhook.sources)
    if webhook.severities is not None:
        updates.append("severities = %s")
        params.append(webhook.severities)
    if webhook.max_retries is not None:
        updates.append("max_retries = %s")
        params.append(webhook.max_retries)
    if webhook.timeout_ms is not None:
        updates.append("timeout_ms = %s")
        params.append(webhook.timeout_ms)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    params.append(webhook_id)

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"""
            UPDATE webhooks
            SET {", ".join(updates)}, updated_at = now()
            WHERE id = %s
            RETURNING id, name, url, enabled, event_types, sources, severities, max_retries, timeout_ms,
                      created_at, updated_at, last_success, failure_count
        """, params)
        row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return WebhookResponse(
        id=str(row["id"]),
        name=row["name"],
        url=row["url"],
        enabled=row["enabled"],
        event_types=row["event_types"] or [],
        sources=row["sources"],
        severities=row["severities"],
        max_retries=row["max_retries"],
        timeout_ms=row["timeout_ms"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_success=row["last_success"],
        failure_count=row["failure_count"]
    )


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(webhook_id: str, authorized: bool = Depends(auth)):
    """Delete a webhook configuration."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM webhooks WHERE id = %s RETURNING id", (webhook_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Webhook not found")
        conn.commit()


@router.post("/{webhook_id}/test", response_model=WebhookTestResponse)
def test_webhook(webhook_id: str, req: WebhookTestRequest = None, authorized: bool = Depends(auth)):
    """Test a webhook with a sample payload."""
    if req is None:
        req = WebhookTestRequest()

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, url, secret, timeout_ms
            FROM webhooks
            WHERE id = %s
        """, (webhook_id,))
        webhook = cur.fetchone()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    # Build test payload
    if req.payload:
        payload = req.payload
    else:
        payload = format_payload(
            webhook["url"],
            req.event_type,
            "test",
            {
                "job_id": "test-123",
                "message": "This is a test webhook delivery",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )

    # Deliver test webhook
    success, response_code, error, response_time_ms = deliver_webhook(
        str(webhook["id"]),
        webhook["url"],
        payload,
        webhook["secret"],
        webhook["timeout_ms"] or 5000
    )

    return WebhookTestResponse(
        success=success,
        response_code=response_code,
        response_time_ms=response_time_ms,
        error=error
    )


# ---------------------------------------------------------------------------
# Auto-register default "event-log" webhook on startup
# ---------------------------------------------------------------------------
_DEFAULT_WEBHOOK_NAME = "event-log"

# The RAG API listens on port 8000 inside Docker
_SELF_SINK_URL = os.environ.get(
    "WEBHOOK_SINK_URL",
    "https://127.0.0.1:8000/webhooks/sink",
)

# Every event type emitted by any scanner
_ALL_EVENT_TYPES = [
    "scan_started", "scan_completed", "scan_failed", "scan_stopped",
    "scan_summary",
    "stage_started", "stage_completed", "stage_failed",
    "finding_high", "finding_critical", "finding_exploitable",
    "ingest_completed",
]


_BFF_WEBHOOK_NAME = "dashboard-bff"
_BFF_WEBHOOK_URL = os.environ.get(
    "BFF_WEBHOOK_URL",
    "https://pentest-dashboard:443/api/webhooks/receive",
)
_BFF_EVENT_TYPES = [
    "scan_completed", "scan_failed",
    "finding_high", "finding_critical",
    "ingest_completed",
]


def ensure_default_webhook():
    """
    Create the catch-all 'event-log' webhook and BFF dashboard webhook
    if they don't already exist.

    Called once at application startup so every scanner event is recorded
    in the webhook_events table automatically, and the dashboard BFF
    receives events for real-time WebSocket push to the frontend.
    """
    import logging
    log = logging.getLogger("webhooks.init")
    try:
        conn = get_db()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Default event-log webhook
            cur.execute(
                "SELECT id FROM webhooks WHERE name = %s",
                (_DEFAULT_WEBHOOK_NAME,),
            )
            if cur.fetchone():
                # Update event_types in case new ones were added
                cur.execute(
                    "UPDATE webhooks SET event_types = %s WHERE name = %s",
                    (_ALL_EVENT_TYPES, _DEFAULT_WEBHOOK_NAME),
                )
                log.info("Default '%s' webhook updated with current event types", _DEFAULT_WEBHOOK_NAME)
            else:
                cur.execute("""
                    INSERT INTO webhooks
                        (name, url, secret, enabled, event_types, sources, severities,
                         max_retries, timeout_ms)
                    VALUES (%s, %s, NULL, true, %s, NULL, NULL, 0, 3000)
                    RETURNING id
                """, (_DEFAULT_WEBHOOK_NAME, _SELF_SINK_URL, _ALL_EVENT_TYPES))
                wh_id = cur.fetchone()["id"]
                log.info("Registered default '%s' webhook (id=%s) → %s",
                         _DEFAULT_WEBHOOK_NAME, wh_id, _SELF_SINK_URL)

            # 2. BFF dashboard webhook (real-time push to frontend)
            cur.execute(
                "SELECT id FROM webhooks WHERE name = %s",
                (_BFF_WEBHOOK_NAME,),
            )
            if cur.fetchone():
                cur.execute(
                    "UPDATE webhooks SET event_types = %s, url = %s WHERE name = %s",
                    (_BFF_EVENT_TYPES, _BFF_WEBHOOK_URL, _BFF_WEBHOOK_NAME),
                )
                log.info("BFF webhook '%s' updated", _BFF_WEBHOOK_NAME)
            else:
                cur.execute("""
                    INSERT INTO webhooks
                        (name, url, secret, enabled, event_types, sources, severities,
                         max_retries, timeout_ms)
                    VALUES (%s, %s, NULL, true, %s, NULL, NULL, 1, 5000)
                    RETURNING id
                """, (_BFF_WEBHOOK_NAME, _BFF_WEBHOOK_URL, _BFF_EVENT_TYPES))
                wh_id = cur.fetchone()["id"]
                log.info("Registered BFF webhook '%s' (id=%s) → %s",
                         _BFF_WEBHOOK_NAME, wh_id, _BFF_WEBHOOK_URL)

            conn.commit()
        conn.close()
    except Exception as e:
        log.error("Failed to register default webhooks: %s", e)
