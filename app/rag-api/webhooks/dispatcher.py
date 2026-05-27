"""
Webhook dispatcher with retry support.

Handles:
- Immediate delivery attempts
- HMAC signature generation
- Background retry worker for failed deliveries
"""

import os
import hmac
import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

import requests
import psycopg2
from psycopg2.extras import RealDictCursor

from .formatters import format_payload

logger = logging.getLogger("webhooks.dispatcher")

# Configuration from environment
DB_DSN = os.environ.get("DB_DSN", "dbname=scans user=app password=app host=127.0.0.1 port=5432")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"
WEBHOOK_MAX_RETRIES = int(os.environ.get("WEBHOOK_MAX_RETRIES", "3"))
WEBHOOK_TIMEOUT_MS = int(os.environ.get("WEBHOOK_TIMEOUT_MS", "5000"))
RETRY_INTERVALS = [60, 300, 900, 3600]  # Retry after 1min, 5min, 15min, 1hr

# Global retry worker state
_retry_worker: Optional[threading.Thread] = None
_retry_worker_stop = threading.Event()


def get_db():
    """Get database connection."""
    return psycopg2.connect(DB_DSN)


def generate_signature(payload: str, secret: str) -> str:
    """
    Generate HMAC-SHA256 signature for webhook payload.

    Returns hex-encoded signature.
    """
    return hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def deliver_webhook(
    webhook_id: str,
    url: str,
    payload: Dict[str, Any],
    secret: Optional[str] = None,
    timeout_ms: int = 5000
) -> tuple[bool, Optional[int], Optional[str], int]:
    """
    Attempt to deliver a webhook payload.

    Args:
        webhook_id: Webhook configuration ID
        url: Destination URL
        payload: JSON payload to send
        secret: Optional HMAC secret for signing
        timeout_ms: Request timeout in milliseconds

    Returns:
        Tuple of (success, response_code, error_message, response_time_ms)
    """
    if not WEBHOOK_ENABLED:
        logger.debug("Webhooks disabled, skipping delivery")
        return False, None, "Webhooks disabled", 0

    payload_json = json.dumps(payload)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "RAG-Scan-Stack-Webhook/1.0",
        "X-Webhook-ID": webhook_id,
    }

    if secret:
        signature = generate_signature(payload_json, secret)
        headers["X-Webhook-Signature"] = f"sha256={signature}"

    start_time = time.time()
    try:
        response = requests.post(
            url,
            data=payload_json,
            headers=headers,
            timeout=timeout_ms / 1000.0,
            allow_redirects=False,
            verify=False
        )
        response_time_ms = int((time.time() - start_time) * 1000)

        if response.status_code < 300:
            logger.info(f"Webhook delivered successfully: {webhook_id} -> {url} ({response.status_code})")
            return True, response.status_code, None, response_time_ms
        else:
            error = f"HTTP {response.status_code}: {response.text[:200]}"
            logger.warning(f"Webhook delivery failed: {webhook_id} -> {url}: {error}")
            return False, response.status_code, error, response_time_ms

    except requests.Timeout:
        response_time_ms = int((time.time() - start_time) * 1000)
        logger.warning(f"Webhook timeout: {webhook_id} -> {url}")
        return False, None, "Request timeout", response_time_ms

    except requests.RequestException as e:
        response_time_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Webhook delivery error: {webhook_id} -> {url}: {e}")
        return False, None, str(e), response_time_ms


def emit_webhook(
    event_type: str,
    source: str,
    data: Dict[str, Any],
    severity: Optional[str] = None,
    db_conn=None
) -> int:
    """
    Emit a webhook event to all matching webhooks.

    This is the main entry point for scanner services to emit events.

    Args:
        event_type: Event type (scan_completed, finding_high, etc.)
        source: Source scanner (nmap, nuclei, zap, etc.)
        data: Event payload data
        severity: Optional severity level (for finding events)
        db_conn: Optional existing database connection

    Returns:
        Number of webhooks notified (including queued retries)
    """
    if not WEBHOOK_ENABLED:
        return 0

    close_conn = False
    if db_conn is None:
        try:
            db_conn = get_db()
            close_conn = True
        except Exception as e:
            logger.error(f"Failed to connect to database for webhook emission: {e}")
            return 0

    notified = 0
    try:
        with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Find matching webhooks
            cur.execute("""
                SELECT id, url, secret, event_types, sources, severities, max_retries, timeout_ms
                FROM webhooks
                WHERE enabled = true
            """)
            webhooks = cur.fetchall()

            for webhook in webhooks:
                # Check event type filter
                if webhook["event_types"] and event_type not in webhook["event_types"]:
                    continue

                # Check source filter
                if webhook["sources"] and source not in webhook["sources"]:
                    continue

                # Check severity filter (for finding events)
                if severity and webhook["severities"] and severity not in webhook["severities"]:
                    continue

                # Format payload for destination
                payload = format_payload(webhook["url"], event_type, source, data, severity)

                # Create event record with source-prefixed event type for clear identification
                source_event_type = f"{source}_{event_type}"
                cur.execute("""
                    INSERT INTO webhook_events (webhook_id, event_type, payload, status)
                    VALUES (%s, %s, %s, 'pending')
                    RETURNING id
                """, (str(webhook["id"]), source_event_type, json.dumps(payload)))
                event_id = str(cur.fetchone()["id"])
                db_conn.commit()

                # Attempt immediate delivery
                success, response_code, error, _ = deliver_webhook(
                    str(webhook["id"]),
                    webhook["url"],
                    payload,
                    webhook["secret"],
                    webhook["timeout_ms"] or WEBHOOK_TIMEOUT_MS
                )

                if success:
                    # Mark as delivered
                    cur.execute("""
                        UPDATE webhook_events
                        SET status = 'delivered', response_code = %s, delivered_at = now(), attempt = 1
                        WHERE id = %s
                    """, (response_code, event_id))
                    cur.execute("""
                        UPDATE webhooks
                        SET last_success = now(), failure_count = 0
                        WHERE id = %s
                    """, (str(webhook["id"]),))
                else:
                    # Schedule for retry
                    max_retries = webhook["max_retries"] or WEBHOOK_MAX_RETRIES
                    if max_retries > 0:
                        next_retry = datetime.now(timezone.utc) + timedelta(seconds=RETRY_INTERVALS[0])
                        cur.execute("""
                            UPDATE webhook_events
                            SET status = 'retrying', response_code = %s, error_message = %s,
                                attempt = 1, next_retry = %s
                            WHERE id = %s
                        """, (response_code, error, next_retry, event_id))
                    else:
                        cur.execute("""
                            UPDATE webhook_events
                            SET status = 'failed', response_code = %s, error_message = %s, attempt = 1
                            WHERE id = %s
                        """, (response_code, error, event_id))
                    cur.execute("""
                        UPDATE webhooks
                        SET failure_count = failure_count + 1
                        WHERE id = %s
                    """, (str(webhook["id"]),))

                db_conn.commit()
                notified += 1

    except Exception as e:
        logger.error(f"Error emitting webhook: {e}")
        if db_conn:
            db_conn.rollback()
    finally:
        if close_conn and db_conn:
            db_conn.close()

    return notified


def process_retries():
    """
    Process pending webhook retries.

    Called by the background retry worker.
    """
    try:
        conn = get_db()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get events due for retry
            cur.execute("""
                SELECT we.id, we.webhook_id, we.payload, we.attempt,
                       w.url, w.secret, w.max_retries, w.timeout_ms
                FROM webhook_events we
                JOIN webhooks w ON w.id = we.webhook_id
                WHERE we.status = 'retrying'
                  AND we.next_retry <= now()
                  AND w.enabled = true
                ORDER BY we.next_retry
                LIMIT 50
            """)
            events = cur.fetchall()

            for event in events:
                payload = event["payload"]
                if isinstance(payload, str):
                    payload = json.loads(payload)

                success, response_code, error, _ = deliver_webhook(
                    str(event["webhook_id"]),
                    event["url"],
                    payload,
                    event["secret"],
                    event["timeout_ms"] or WEBHOOK_TIMEOUT_MS
                )

                attempt = event["attempt"] + 1
                max_retries = event["max_retries"] or WEBHOOK_MAX_RETRIES

                if success:
                    cur.execute("""
                        UPDATE webhook_events
                        SET status = 'delivered', response_code = %s, delivered_at = now(), attempt = %s
                        WHERE id = %s
                    """, (response_code, attempt, str(event["id"])))
                    cur.execute("""
                        UPDATE webhooks
                        SET last_success = now(), failure_count = 0
                        WHERE id = %s
                    """, (str(event["webhook_id"]),))
                elif attempt >= max_retries:
                    cur.execute("""
                        UPDATE webhook_events
                        SET status = 'failed', response_code = %s, error_message = %s, attempt = %s
                        WHERE id = %s
                    """, (response_code, error, attempt, str(event["id"])))
                    cur.execute("""
                        UPDATE webhooks
                        SET failure_count = failure_count + 1
                        WHERE id = %s
                    """, (str(event["webhook_id"]),))
                else:
                    # Schedule next retry with exponential backoff
                    retry_idx = min(attempt, len(RETRY_INTERVALS) - 1)
                    next_retry = datetime.now(timezone.utc) + timedelta(seconds=RETRY_INTERVALS[retry_idx])
                    cur.execute("""
                        UPDATE webhook_events
                        SET response_code = %s, error_message = %s, attempt = %s, next_retry = %s
                        WHERE id = %s
                    """, (response_code, error, attempt, next_retry, str(event["id"])))

                conn.commit()

    except Exception as e:
        logger.error(f"Error processing webhook retries: {e}")
    finally:
        if conn:
            conn.close()


def _retry_worker_loop():
    """Background retry worker main loop."""
    logger.info("Webhook retry worker started")
    while not _retry_worker_stop.is_set():
        try:
            process_retries()
        except Exception as e:
            logger.error(f"Retry worker error: {e}")
        # Sleep for 30 seconds between retry checks
        _retry_worker_stop.wait(30)
    logger.info("Webhook retry worker stopped")


def start_retry_worker():
    """Start the background retry worker."""
    global _retry_worker
    if _retry_worker is not None and _retry_worker.is_alive():
        return

    _retry_worker_stop.clear()
    _retry_worker = threading.Thread(target=_retry_worker_loop, daemon=True)
    _retry_worker.start()
    logger.info("Webhook retry worker thread started")


def stop_retry_worker():
    """Stop the background retry worker."""
    global _retry_worker
    if _retry_worker is None:
        return

    _retry_worker_stop.set()
    _retry_worker.join(timeout=5)
    _retry_worker = None
    logger.info("Webhook retry worker thread stopped")
