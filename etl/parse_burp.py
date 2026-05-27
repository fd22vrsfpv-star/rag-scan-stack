"""
ETL script for Burp Suite XML exports.
Parses both Burp Scanner issue exports (<issues> root) and
Burp Sitemap exports (<items> root) into the web_findings table.
"""

import os
import re
import json
import logging
import uuid
import base64
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from xml.etree.ElementTree import iterparse

import psycopg2
from psycopg2.extras import RealDictCursor
import requests

from etl.fingerprint import web_fingerprint

# Configure logging
logger = logging.getLogger("parse_burp")
logger.setLevel(logging.INFO)

try:
    from log_manager import get_log_handler
    circular_handler = get_log_handler()
    if circular_handler not in logger.handlers:
        logger.addHandler(circular_handler)
        logger.info("[parse_burp] Attached to CircularLogHandler for web UI logging")
except ImportError:
    if not logger.handlers and not logger.parent.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
        logger.addHandler(handler)

# Configuration
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"

# Severity mapping (Burp → normalized)
SEVERITY_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Information": "info",
    "False positive": None,
}

# Cache for asset lookups
_asset_cache: Dict[str, Optional[str]] = {}


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


def extract_ip_from_url(url: str) -> Optional[str]:
    """Extract IP address from a URL."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
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


def _decode_base64_safe(text: Optional[str]) -> Optional[str]:
    """Decode base64-encoded text, returning None on failure."""
    if not text:
        return None
    try:
        return base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        return None


def _detect_format(filepath: str) -> str:
    """Detect Burp XML format by inspecting root element tag."""
    for event, elem in iterparse(filepath, events=("start",)):
        tag = elem.tag.lower()
        elem.clear()
        if tag == "issues":
            return "scanner"
        elif tag == "items":
            return "sitemap"
        else:
            return "unknown"
    return "unknown"


def _parse_scanner_issues(filepath: str, cur, stats: dict, dedupe: bool):
    """Parse Burp Scanner issue XML (<issues> root)."""
    for event, elem in iterparse(filepath, events=("end",)):
        if elem.tag != "issue":
            continue

        name = (elem.findtext("name") or "").strip()
        host_elem = elem.find("host")
        host_ip = host_elem.get("ip", "") if host_elem is not None else ""
        host_url = (host_elem.text or "") if host_elem is not None else ""
        path = (elem.findtext("path") or "").strip()
        location = (elem.findtext("location") or "").strip()

        url = host_url.rstrip("/") + path if path else host_url
        if not url and location:
            url = location

        severity_raw = (elem.findtext("severity") or "Information").strip()
        severity = SEVERITY_MAP.get(severity_raw)
        if severity is None:
            stats["skipped_false_positive"] += 1
            elem.clear()
            continue

        confidence = (elem.findtext("confidence") or "").strip()
        issue_type_id = (elem.findtext("type") or "").strip()
        issue_detail = (elem.findtext("issueDetail") or "").strip()
        issue_background = (elem.findtext("issueBackground") or "").strip()
        remediation_detail = (elem.findtext("remediationDetail") or "").strip()
        remediation_background = (elem.findtext("remediationBackground") or "").strip()

        # Build CWE from issueType if it looks like a CWE ID
        cwe_list = []
        if issue_type_id and issue_type_id.isdigit():
            cwe_list.append(f"CWE-{issue_type_id}")

        # Evidence from issueDetail or request/response snippets
        evidence = issue_detail[:2000] if issue_detail else None

        # Build references
        refs = {}
        if issue_background:
            refs["background"] = issue_background
        if remediation_detail:
            refs["remediation"] = remediation_detail
        if remediation_background:
            refs["remediation_background"] = remediation_background

        # Fingerprint for dedup
        fp = web_fingerprint(
            url=url,
            source="burp",
            name=name,
            issue_type="burp-scanner",
        )

        if dedupe:
            cur.execute("""
                SELECT id FROM web_findings
                WHERE fingerprint = %s
                LIMIT 1
            """, (fp,))
            if cur.fetchone():
                stats["skipped_duplicate"] += 1
                elem.clear()
                continue

        # Asset lookup
        ip = host_ip or extract_ip_from_url(url)
        asset_id = get_asset_id_for_ip(cur, ip) if ip else None

        finding_id = str(uuid.uuid4())
        try:
            cur.execute("SAVEPOINT rec_sp")
            cur.execute("""
                INSERT INTO web_findings
                  (id, asset_id, url, source, issue_type, name, severity, evidence,
                   method, payload, cwe, refs, description, solution, reference,
                   confidence, tags, first_seen, last_seen, fingerprint)
                VALUES (%s, %s, %s, 'burp', 'burp-scanner', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), now(), %s)
            """, (
                finding_id,
                asset_id,
                url,
                name,
                severity,
                evidence,
                None,  # method
                None,  # payload
                cwe_list if cwe_list else None,
                json.dumps(refs) if refs else None,
                issue_background,     # description
                remediation_detail,   # solution
                remediation_background,  # reference
                confidence,
                json.dumps({"burp_type": issue_type_id}) if issue_type_id else None,
                fp,
            ))
            stats["inserted"] += 1
            stats["by_severity"][severity] += 1
            logger.info(f"  [DB] Inserted: {finding_id[:8]}... ({severity}) {name[:50]}")

            if severity == "high":
                emit_webhook_event("finding_high", "burp", {
                    "title": name,
                    "url": url,
                    "ip": ip,
                    "confidence": confidence,
                    "description": issue_detail[:500] if issue_detail else None
                }, severity="high")

            cur.execute("RELEASE SAVEPOINT rec_sp")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
            logger.error(f"  [DB] Insert error: {e}")
            stats["errors"].append(str(e))

        elem.clear()


def _parse_sitemap_items(filepath: str, cur, stats: dict, dedupe: bool):
    """Parse Burp Sitemap XML (<items> root)."""
    for event, elem in iterparse(filepath, events=("end",)):
        if elem.tag != "item":
            continue

        url_text = (elem.findtext("url") or "").strip()
        host = (elem.findtext("host") or "").strip()
        port = (elem.findtext("port") or "").strip()
        protocol = (elem.findtext("protocol") or "").strip()
        method = (elem.findtext("method") or "GET").strip()
        path = (elem.findtext("path") or "").strip()
        status = (elem.findtext("status") or "").strip()
        mimetype = (elem.findtext("mimetype") or "").strip()
        comment = (elem.findtext("comment") or "").strip()

        url = url_text or f"{protocol}://{host}:{port}{path}"

        # Decode base64 request/response for evidence
        request_b64 = elem.findtext("request")
        response_b64 = elem.findtext("response")
        request_text = _decode_base64_safe(request_b64)
        response_text = _decode_base64_safe(response_b64)

        evidence_parts = []
        if request_text:
            evidence_parts.append(f"REQUEST:\n{request_text[:500]}")
        if response_text:
            evidence_parts.append(f"RESPONSE:\n{response_text[:500]}")
        evidence = "\n\n".join(evidence_parts) if evidence_parts else None

        name = f"{method} {path or url}" if path else f"{method} {url}"

        # Fingerprint for dedup
        fp = web_fingerprint(
            url=url,
            source="burp",
            name=name,
            issue_type="burp-sitemap",
        )

        if dedupe:
            cur.execute("""
                SELECT id FROM web_findings
                WHERE fingerprint = %s
                LIMIT 1
            """, (fp,))
            if cur.fetchone():
                stats["skipped_duplicate"] += 1
                elem.clear()
                continue

        # Asset lookup
        ip = extract_ip_from_url(url)
        asset_id = get_asset_id_for_ip(cur, ip) if ip else None

        # Build tags
        tags = {}
        if mimetype:
            tags["mimetype"] = mimetype
        if status:
            tags["status_code"] = status
        if comment:
            tags["comment"] = comment

        finding_id = str(uuid.uuid4())
        try:
            cur.execute("SAVEPOINT rec_sp")
            cur.execute("""
                INSERT INTO web_findings
                  (id, asset_id, url, source, issue_type, name, severity, evidence,
                   method, payload, cwe, refs, description, solution, reference,
                   confidence, tags, first_seen, last_seen, fingerprint)
                VALUES (%s, %s, %s, 'burp', 'burp-sitemap', %s, 'info', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), now(), %s)
            """, (
                finding_id,
                asset_id,
                url,
                name,
                evidence,
                method,
                None,  # payload
                None,  # cwe
                None,  # refs
                None,  # description
                None,  # solution
                None,  # reference
                None,  # confidence
                json.dumps(tags) if tags else None,
                fp,
            ))
            stats["inserted"] += 1
            stats["by_severity"]["info"] += 1
            logger.info(f"  [DB] Sitemap item: {finding_id[:8]}... {method} {url[:60]}")

            cur.execute("RELEASE SAVEPOINT rec_sp")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
            logger.error(f"  [DB] Insert error: {e}")
            stats["errors"].append(str(e))

        elem.clear()


def parse_burp(
    filepath: str,
    profile: str = "cli",
    dedupe: bool = True,
) -> Dict[str, Any]:
    """
    Parse a Burp Suite XML export and insert findings into the database.

    Handles two formats:
    - Scanner issues (<issues> root) — vulnerability findings
    - Sitemap export (<items> root) — request/response pairs

    Args:
        filepath: Path to the Burp XML file
        profile: Ingest profile label
        dedupe: Skip findings that already exist in database

    Returns:
        Stats about what was parsed and inserted
    """
    logger.info("=" * 60)
    logger.info("PARSING BURP SUITE XML EXPORT")
    logger.info(f"File: {filepath}")
    logger.info(f"Profile: {profile}")
    logger.info("=" * 60)

    stats = {
        "format": "unknown",
        "total_items": 0,
        "inserted": 0,
        "skipped_duplicate": 0,
        "skipped_false_positive": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "errors": []
    }

    # Detect format
    fmt = _detect_format(filepath)
    stats["format"] = fmt
    logger.info(f"Detected format: {fmt}")

    if fmt == "unknown":
        stats["errors"].append("Unrecognized Burp XML format (expected <issues> or <items> root)")
        logger.error(stats["errors"][-1])
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if fmt == "scanner":
                _parse_scanner_issues(filepath, cur, stats, dedupe)
            elif fmt == "sitemap":
                _parse_sitemap_items(filepath, cur, stats, dedupe)

            conn.commit()
    except Exception as e:
        logger.error(f"Database error: {e}")
        stats["errors"].append(str(e))
        conn.rollback()
    finally:
        conn.close()

    stats["total_items"] = stats["inserted"] + stats["skipped_duplicate"] + stats["skipped_false_positive"]

    # Final summary
    logger.info(f"\n{'=' * 60}")
    logger.info("BURP PARSE COMPLETE")
    logger.info(f"  Format: {stats['format']}")
    logger.info(f"  Total Items: {stats['total_items']}")
    logger.info(f"  Inserted: {stats['inserted']}")
    logger.info(f"  Skipped (duplicate): {stats['skipped_duplicate']}")
    logger.info(f"  Skipped (false positive): {stats['skipped_false_positive']}")
    logger.info(f"  By Severity: {stats['by_severity']}")
    if stats["errors"]:
        logger.warning(f"  Errors: {len(stats['errors'])}")
    logger.info(f"{'=' * 60}\n")

    return stats


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parse Burp Suite XML exports into database")
    parser.add_argument("file", help="Path to Burp XML export file")
    parser.add_argument("--profile", default="cli", help="Ingest profile label")
    parser.add_argument("--no-dedupe", action="store_true", help="Don't skip duplicates")

    args = parser.parse_args()

    result = parse_burp(
        filepath=args.file,
        profile=args.profile,
        dedupe=not args.no_dedupe
    )

    print(json.dumps(result, indent=2))
