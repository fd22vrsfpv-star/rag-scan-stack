"""
ETL script for ZAP (OWASP Zed Attack Proxy) findings.
Fetches alerts from ZAP API and ingests into database with full logging.
"""

import os
import re
import json
import logging
import threading
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse

import requests
import psycopg2
from psycopg2.extras import RealDictCursor

from etl.fingerprint import web_fingerprint

# Configure logging - integrate with log_manager if available
logger = logging.getLogger("parse_zap")
logger.setLevel(logging.INFO)

# Try to attach CircularLogHandler when running inside a container with log_manager
try:
    from log_manager import get_log_handler
    circular_handler = get_log_handler()
    if circular_handler not in logger.handlers:
        logger.addHandler(circular_handler)
        logger.info("[parse_zap] Attached to CircularLogHandler for web UI logging")
except ImportError:
    # Running standalone - add console handler if none exists
    if not logger.handlers and not logger.parent.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
        logger.addHandler(handler)

# Configuration
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
ZAP_ADDR = os.environ.get("ZAP_ADDR", "zap")
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8090"))
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "changeme")
ZAP_BASE_URL = f"http://{ZAP_ADDR}:{ZAP_PORT}"
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
SCAN_RECOMMENDER_URL = os.environ.get("SCAN_RECOMMENDER_URL",
                                      "https://scan-recommender:8013")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"


def emit_webhook_event(event_type: str, source: str, data: dict, severity: str = None):
    """Emit a webhook event via the RAG API."""
    if not WEBHOOK_ENABLED:
        return
    try:
        payload = {
            "event_type": event_type,
            "source": source,
            "data": data
        }
        if severity:
            payload["severity"] = severity
        requests.post(
            f"{API_BASE}/webhooks/emit",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json=payload,
            timeout=5
        )
    except Exception as e:
        logger.warning(f"Failed to emit webhook: {e}")

# Severity mapping (ZAP uses different names)
SEVERITY_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
    "False Positive": None,  # Skip false positives
}

# Cache for asset lookups to avoid repeated DB queries
_asset_cache: Dict[str, Optional[str]] = {}


def extract_ip_from_url(url: str) -> Optional[str]:
    """Extract IP address from a URL."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        # Check if host is an IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if host and re.match(ip_pattern, host):
            return host
    except Exception:
        pass
    return None


def get_asset_id_for_ip(cur, ip: str) -> Optional[str]:
    """Look up asset_id for an IP address, with caching."""
    if not ip:
        return None

    # Check cache first
    if ip in _asset_cache:
        return _asset_cache[ip]

    try:
        cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
        row = cur.fetchone()
        asset_id = str(row["id"]) if row else None
        _asset_cache[ip] = asset_id
        return asset_id
    except Exception as e:
        logger.warning(f"Failed to look up asset for IP {ip}: {e}")
        return None


def get_zap_alerts(base_url: Optional[str] = None, start: int = 0, count: int = -1) -> List[Dict]:
    """
    Fetch alerts from ZAP API.

    Args:
        base_url: Filter alerts by base URL (optional)
        start: Start index for pagination
        count: Number of alerts to fetch (-1 for all)

    Returns:
        List of alert dictionaries
    """
    params = {
        "apikey": ZAP_API_KEY,
        "start": start,
    }
    if count > 0:
        params["count"] = count
    if base_url:
        params["baseurl"] = base_url

    url = f"{ZAP_BASE_URL}/JSON/core/view/alerts/"

    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get("alerts", [])
    except Exception as e:
        logger.error(f"Failed to fetch ZAP alerts: {e}")
        return []


def get_zap_message(message_id: str) -> Dict:
    """Fetch full HTTP message (request + response) from ZAP by message ID."""
    if not message_id or message_id == "-1":
        return {}
    try:
        url = f"{ZAP_BASE_URL}/JSON/core/view/message/"
        resp = requests.get(url, params={"apikey": ZAP_API_KEY, "id": message_id}, timeout=10)
        if resp.status_code == 200:
            msg = resp.json().get("message", {})
            return {
                "request_header": msg.get("requestHeader", ""),
                "request_body": msg.get("requestBody", ""),
                "response_header": msg.get("responseHeader", ""),
                "response_body": msg.get("responseBody", ""),
            }
    except Exception as e:
        logger.debug(f"Could not fetch ZAP message {message_id}: {e}")
    return {}


def get_zap_alert_count(base_url: Optional[str] = None) -> int:
    """Get total number of alerts in ZAP (retries on timeout)."""
    params = {"apikey": ZAP_API_KEY}
    if base_url:
        params["baseurl"] = base_url

    url = f"{ZAP_BASE_URL}/JSON/core/view/numberOfAlerts/"

    for attempt in range(3):
        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            return int(data.get("numberOfAlerts", 0))
        except Exception as e:
            logger.warning(f"ZAP alert count attempt {attempt + 1}/3 failed: {e}")
            if attempt == 2:
                logger.error(f"Failed to get ZAP alert count after 3 attempts: {e}")
    return 0


def _trigger_recommendations_from_zap(
    unique_services: Set[Tuple[str, str, int]],
) -> None:
    """Fire-and-forget: call the local-LLM scan_recommender's /next_scan for
    each unique (ip, scheme, port) ZAP just touched, skipping any service
    that already has a recommendation persisted.

    Runs in a daemon thread so it never blocks parse_zap_alerts' return.
    Mirrors the central trigger in app/rag-api/api.py:_trigger_recommendations_for
    -- ZAP findings are parsed in-process by web_scanner (not via an
    /ingest/* endpoint), so this is the only point at which the recommender
    can be triggered reactively for ZAP."""
    if not unique_services:
        return

    def _worker() -> None:
        ips = list({ip for (ip, _, _) in unique_services})
        already_done: Set[Tuple[str, str]] = set()
        try:
            conn = psycopg2.connect(DB_DSN)
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT host(ip)::text AS ip,
                               COALESCE(service, '') AS service
                        FROM public.scan_recommendations
                        WHERE host(ip)::text = ANY(%s)
                    """, (ips,))
                    already_done = {
                        (row["ip"], row["service"]) for row in cur.fetchall()
                    }
            finally:
                conn.close()
        except Exception as e:
            # Non-fatal: worst case we make extra /next_scan calls and the
            # recommender's ON CONFLICT DO NOTHING absorbs the duplicate.
            logger.debug(f"[zap] dedup lookup failed, falling through: {e}")

        dispatched = 0
        for ip, scheme, port in unique_services:
            if (ip, scheme) in already_done:
                continue
            try:
                requests.get(
                    f"{SCAN_RECOMMENDER_URL}/next_scan",
                    params={
                        "ip": ip,
                        "service": scheme,
                        "port": str(port),
                        "persist": "true",
                    },
                    headers={"x-api-key": API_KEY},
                    timeout=60,
                    verify=False,
                )
                dispatched += 1
            except Exception as e:
                logger.debug(
                    f"[zap] recommender call failed for {ip}:{port}/{scheme}: {e}"
                )

        if dispatched:
            logger.info(
                f"[zap] scan_recommender dispatched: {dispatched} new probe "
                f"recommendation(s) from {len(unique_services)} unique service(s)"
            )
            # Surface this on the webhook bus so the OPSEC timeline and any
            # external listeners see the reactive trigger as part of ingest.
            try:
                emit_webhook_event("recommendations_generated", "zap", {
                    "source": "zap",
                    "dispatched": dispatched,
                    "unique_services_seen": len(unique_services),
                })
            except Exception:
                pass

    threading.Thread(
        target=_worker, daemon=True, name="zap-reco-trigger",
    ).start()


def parse_zap_alerts(
    base_url: Optional[str] = None,
    batch_size: int = 100,
    dedupe: bool = True
) -> Dict[str, Any]:
    """
    Parse ZAP alerts and insert into database.

    Args:
        base_url: Filter alerts by base URL (optional)
        batch_size: Number of alerts to fetch per batch
        dedupe: Skip alerts that already exist in database

    Returns:
        Stats about what was parsed and inserted
    """
    logger.info("=" * 60)
    logger.info("PARSING ZAP ALERTS")
    logger.info(f"ZAP Server: {ZAP_BASE_URL}")
    if base_url:
        logger.info(f"Base URL Filter: {base_url}")
    logger.info("=" * 60)

    stats = {
        "total_alerts": 0,
        "inserted": 0,
        "skipped_duplicate": 0,
        "skipped_false_positive": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "by_risk": {},
        "errors": []
    }
    # (ip, scheme, port) tuples for every service ZAP touched. Used after the
    # parse completes to trigger the local-LLM scan_recommender reactively.
    unique_services: Set[Tuple[str, str, int]] = set()

    # Get total count
    total_count = get_zap_alert_count(base_url)
    logger.info(f"Total alerts in ZAP: {total_count}")
    stats["total_alerts"] = total_count

    if total_count == 0:
        logger.info("No alerts to process")
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Process in batches
            processed = 0
            while processed < total_count:
                alerts = get_zap_alerts(base_url, start=processed, count=batch_size)
                if not alerts:
                    break

                logger.info(f"\n{'─' * 50}")
                logger.info(f"Processing batch: {processed} - {processed + len(alerts)}")
                logger.info(f"{'─' * 50}")

                for alert in alerts:
                    # Log raw alert data
                    raw_data = {
                        "alert": alert.get("alert"),
                        "risk": alert.get("risk"),
                        "confidence": alert.get("confidence"),
                        "url": alert.get("url"),
                        "method": alert.get("method"),
                        "param": alert.get("param"),
                        "attack": alert.get("attack"),
                        "evidence": alert.get("evidence", "")[:200] if alert.get("evidence") else None,
                        "cweid": alert.get("cweid"),
                        "wascid": alert.get("wascid"),
                    }
                    logger.info(f"[RAW ZAP ALERT] {json.dumps(raw_data, indent=2)}")

                    # Track by risk
                    risk = alert.get("risk", "Unknown")
                    stats["by_risk"][risk] = stats["by_risk"].get(risk, 0) + 1

                    # Map severity
                    severity = SEVERITY_MAP.get(risk)
                    if severity is None:
                        logger.debug(f"  [SKIP] False positive or unknown risk: {risk}")
                        stats["skipped_false_positive"] += 1
                        continue

                    # Check for duplicates if deduping
                    if dedupe:
                        cur.execute("""
                            SELECT id FROM web_findings
                            WHERE url = %s AND name = %s AND source = 'zap'
                            LIMIT 1
                        """, (alert.get("url"), alert.get("alert")))
                        if cur.fetchone():
                            logger.debug(f"  [SKIP] Duplicate: {alert.get('alert')[:50]}")
                            stats["skipped_duplicate"] += 1
                            continue

                    # Build CWE array
                    cwe_list = []
                    if alert.get("cweid") and alert.get("cweid") != "-1":
                        cwe_list.append(f"CWE-{alert.get('cweid')}")

                    # Build references (keep for backward compatibility)
                    refs = {}
                    if alert.get("reference"):
                        refs["reference"] = alert.get("reference")
                    if alert.get("solution"):
                        refs["solution"] = alert.get("solution")
                    if alert.get("wascid") and alert.get("wascid") != "-1":
                        refs["wasc"] = alert.get("wascid")

                    # Extract new fields
                    description = alert.get("description")
                    solution = alert.get("solution")
                    reference = alert.get("reference")
                    confidence = alert.get("confidence")
                    tags = alert.get("tags", {})

                    # Link to asset by extracting IP or hostname from URL
                    alert_url = alert.get("url", "")
                    ip = extract_ip_from_url(alert_url)

                    if ip:
                        # Try IP first
                        asset_id = get_asset_id_for_ip(cur, ip)
                        # Track the (ip, scheme, port) this alert touched so we
                        # can trigger the scan_recommender reactively at the
                        # end of the parse run.
                        try:
                            parsed = urlparse(alert_url)
                            scheme = (parsed.scheme or "http").lower()
                            port = parsed.port or (443 if scheme == "https" else 80)
                            unique_services.add((ip, scheme, port))
                        except Exception:
                            pass
                    else:
                        # Extract hostname if no IP found
                        from urllib.parse import urlparse
                        try:
                            parsed = urlparse(alert_url)
                            hostname = parsed.hostname
                            if hostname:
                                # Look up asset by hostname
                                cur.execute("SELECT id FROM assets WHERE hostname = %s", (hostname,))
                                row = cur.fetchone()
                                asset_id = str(row["id"]) if row else None
                            else:
                                asset_id = None
                        except Exception:
                            asset_id = None

                    # Generate fingerprint
                    fp = web_fingerprint(
                        url=alert_url,
                        source="zap",
                        name=alert.get("alert"),
                        issue_type="zap-alert",
                    )

                    # Fetch full HTTP message (request + response)
                    msg_id = alert.get("messageId")
                    msg_data = get_zap_message(msg_id) if msg_id else {}
                    request_raw = ""
                    response_raw = ""
                    if msg_data:
                        req_hdr = msg_data.get("request_header", "")
                        req_body = msg_data.get("request_body", "")
                        request_raw = req_hdr + ("\r\n" + req_body if req_body else "")
                        resp_hdr = msg_data.get("response_header", "")
                        resp_body = msg_data.get("response_body", "")
                        response_raw = resp_hdr + ("\r\n" + resp_body if resp_body else "")
                        # Cap response to prevent huge blobs
                        if len(response_raw) > 50000:
                            response_raw = response_raw[:50000] + "\n\n[TRUNCATED]"

                    # Insert finding
                    finding_id = str(uuid.uuid4())
                    try:
                        cur.execute("SAVEPOINT rec_sp")
                        cur.execute("""
                            INSERT INTO web_findings
                              (id, asset_id, url, source, issue_type, name, severity, evidence,
                               method, payload, cwe, refs, description, solution, reference,
                               confidence, tags, request_data, response_data,
                               first_seen, last_seen, fingerprint)
                            VALUES (%s, %s, %s, 'zap', 'zap-alert', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), now(), %s)
                        """, (
                            finding_id,
                            asset_id,
                            alert_url,
                            alert.get("alert"),
                            severity,
                            alert.get("evidence") or alert.get("param"),
                            alert.get("method"),
                            alert.get("attack"),
                            cwe_list if cwe_list else None,
                            json.dumps(refs) if refs else None,
                            description,
                            solution,
                            reference,
                            confidence,
                            json.dumps(tags) if tags else None,
                            request_raw or None,
                            response_raw or None,
                            fp,
                        ))

                        stats["inserted"] += 1
                        stats["by_severity"][severity] += 1
                        logger.info(f"  [DB] Inserted: {finding_id[:8]}... ({severity}) {alert.get('alert')[:50]}")

                        # Emit webhook for high severity findings
                        if severity == "high":
                            emit_webhook_event("finding_high", "zap", {
                                "title": alert.get("alert"),
                                "url": alert_url,
                                "ip": ip,
                                "method": alert.get("method"),
                                "cwe": f"CWE-{alert.get('cweid')}" if alert.get("cweid") and alert.get("cweid") != "-1" else None,
                                "description": description[:500] if description else None
                            }, severity="high")

                        cur.execute("RELEASE SAVEPOINT rec_sp")
                    except Exception as e:
                        cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                        logger.error(f"  [DB] Insert error: {e}")
                        stats["errors"].append(str(e))

                processed += len(alerts)
                conn.commit()
                logger.info(f"Batch committed. Progress: {processed}/{total_count}")

    except Exception as e:
        logger.error(f"Database error: {e}")
        stats["errors"].append(str(e))
        conn.rollback()
    finally:
        conn.close()

    # Final summary
    logger.info(f"\n{'=' * 60}")
    logger.info("ZAP PARSE COMPLETE")
    logger.info(f"  Total Alerts: {stats['total_alerts']}")
    logger.info(f"  Inserted: {stats['inserted']}")
    logger.info(f"  Skipped (duplicate): {stats['skipped_duplicate']}")
    logger.info(f"  Skipped (false positive): {stats['skipped_false_positive']}")
    logger.info(f"  By Severity: {stats['by_severity']}")
    logger.info(f"  Unique services touched: {len(unique_services)}")
    if stats["errors"]:
        logger.warning(f"  Errors: {len(stats['errors'])}")
    logger.info(f"{'=' * 60}\n")

    # Fire the scan_recommender reactively for each service ZAP just touched.
    # Fire-and-forget — does not block this function's return.
    try:
        _trigger_recommendations_from_zap(unique_services)
    except Exception as e:
        logger.warning(f"[zap] failed to spawn recommender trigger: {e}")

    return stats


def clear_zap_session():
    """Clear ZAP's current session (alerts, history, etc.)."""
    url = f"{ZAP_BASE_URL}/JSON/core/action/newSession/"
    params = {"apikey": ZAP_API_KEY}

    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        logger.info("ZAP session cleared")
        return True
    except Exception as e:
        logger.error(f"Failed to clear ZAP session: {e}")
        return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parse ZAP alerts into database")
    parser.add_argument("--url", help="Filter by base URL")
    parser.add_argument("--batch-size", type=int, default=100, help="Batch size for fetching")
    parser.add_argument("--no-dedupe", action="store_true", help="Don't skip duplicates")
    parser.add_argument("--clear-session", action="store_true", help="Clear ZAP session after parsing")

    args = parser.parse_args()

    stats = parse_zap_alerts(
        base_url=args.url,
        batch_size=args.batch_size,
        dedupe=not args.no_dedupe
    )

    if args.clear_session:
        clear_zap_session()

    print(json.dumps(stats, indent=2))
