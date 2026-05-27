"""
OSINT Flagging Agent — YAML-driven rule engine + RAG-enhanced classifier.

Scans new findings from recon_findings, web_findings, and credential tables,
applies detection rules loaded from YAML, and creates follow_up_items for
pentester triage. Learns from user feedback via embedding similarity (RAG).
"""

import os
import uuid
import logging

import psycopg2
from psycopg2.extras import RealDictCursor

from rule_engine import get_engine

log = logging.getLogger("osint_agent")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "https://embedder:8030")


def _get_conn():
    return psycopg2.connect(DB_DSN)


def _get_or_create_unknown_scope_engagement(cur):
    """Get or create the 'unknown_scope' engagement for out-of-scope discoveries."""
    # Check if unknown_scope engagement exists
    cur.execute("SELECT id FROM engagements WHERE name = 'unknown_scope' LIMIT 1")
    row = cur.fetchone()
    if row:
        return row[0] if isinstance(row, tuple) else row.get('id')

    # Create unknown_scope engagement
    cur.execute("""
        INSERT INTO engagements (id, name, description, status, scope, start_date, created_at, updated_at)
        VALUES (gen_random_uuid(), 'unknown_scope',
                'Auto-created engagement for out-of-scope discoveries during OSINT scanning',
                'active',
                'Out-of-scope domains and targets discovered during reconnaissance',
                now(), now(), now())
        RETURNING id
    """)
    engagement_id = cur.fetchone()[0]
    log.info("Created 'unknown_scope' engagement: %s", engagement_id)
    return engagement_id


def _is_out_of_scope_target(target, cur):
    """Check if a target appears to be out of scope based on domain patterns and asset associations."""
    if not target:
        return False

    from urllib.parse import urlparse
    try:
        # Extract domain from URL or use target directly
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.netloc.lower()
            # Remove port numbers if present
            if ':' in domain:
                domain = domain.split(':')[0]
        else:
            # Handle plain domain or IP
            domain = target.split('/')[0].split(':')[0].lower()

        # First check if this domain is already associated with in-scope assets
        # This is the key fix - check the domain against existing assets
        try:
            cur.execute("SAVEPOINT scope_check")
            # Check for exact hostname match
            cur.execute("SELECT COUNT(*) FROM assets WHERE LOWER(hostname) = %s", (domain,))
            exact_match = cur.fetchone()[0] > 0

            if exact_match:
                cur.execute("RELEASE SAVEPOINT scope_check")
                return False  # Domain is in scope

            # Check for domain suffix match (e.g., subdomain.example.com matches example.com)
            cur.execute("SELECT COUNT(*) FROM assets WHERE hostname IS NOT NULL AND (LOWER(hostname) = %s OR LOWER(hostname) LIKE %s)",
                       (domain, f"%.{domain}"))
            domain_match = cur.fetchone()[0] > 0

            if domain_match:
                cur.execute("RELEASE SAVEPOINT scope_check")
                return False  # Domain or parent domain is in scope

            # Check if the domain is a subdomain of an in-scope domain
            cur.execute("SELECT hostname FROM assets WHERE hostname IS NOT NULL")
            in_scope_domains = [row[0].lower() for row in cur.fetchall() if row[0]]

            for in_scope_domain in in_scope_domains:
                if domain.endswith(f".{in_scope_domain}") or domain == in_scope_domain:
                    cur.execute("RELEASE SAVEPOINT scope_check")
                    return False  # Subdomain of in-scope domain

            cur.execute("RELEASE SAVEPOINT scope_check")
        except Exception:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT scope_check")
            except:
                pass

        # Only flag as out-of-scope if domain is clearly external
        # Known out-of-scope external service domains
        external_service_patterns = [
            "demo.testfire.net",
            "addons.mozilla.org",
            "github.com",
            "stackoverflow.com",
            "w3.org",
            "mozilla.org",
            "google.com",
            "microsoft.com",
            "apple.com",
            "facebook.com",
            "twitter.com",
            "linkedin.com",
            "youtube.com",
            "cloudfront.net",
            "amazonaws.com",
            "googletagmanager.com",
            "googleapis.com",
            "gstatic.com",
            "googlesyndication.com",
            "doubleclick.net"
        ]

        for pattern in external_service_patterns:
            if domain == pattern or domain.endswith(f".{pattern}"):
                return True

        # Check if domain looks like internal/private (definitely in scope)
        if any(internal in domain for internal in ["localhost", "127.", "10.", "192.168.", "172.", "local", "test", "dev", "internal"]):
            return False

        # Be conservative - don't flag as out of scope unless we're very confident it's external
        # This prevents false positives on unknown but potentially in-scope domains
        return False

    except Exception:
        pass

    return False


def _create_follow_up(cur, *, rule_id, title, target, severity, reason,
                      finding_source, finding_id, confidence=0.9, tags=None,
                      metadata=None):
    """Insert a follow_up_item flagged by osint_agent. Auto-inherits engagement from asset or assigns to unknown_scope."""
    from psycopg2.extras import Json

    # Try to find engagement_id from the target's asset.
    # Wrap in SAVEPOINT so a failed inet cast or other SQL error
    # doesn't poison the surrounding transaction.
    engagement_id = None
    is_out_of_scope = False

    try:
        import re
        cur.execute("SAVEPOINT engagement_lookup")
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target or '')
        if ip_match:
            cur.execute("SELECT engagement_id FROM assets WHERE ip = %s::inet LIMIT 1", (ip_match.group(0),))
            row = cur.fetchone()
            if row:
                engagement_id = row[0] if isinstance(row, tuple) else row.get('engagement_id')
        if not engagement_id and target:
            # Enhanced hostname matching for subdomains
            target_domain = target.split('/')[0].split(':')[0].lower()

            # First try exact hostname match
            cur.execute("SELECT engagement_id FROM assets WHERE LOWER(hostname) = %s LIMIT 1", (target_domain,))
            row = cur.fetchone()
            if row:
                engagement_id = row[0] if isinstance(row, tuple) else row.get('engagement_id')

            # If no exact match, try parent domain matching for subdomains
            if not engagement_id:
                # Check if target is a subdomain of any existing asset hostname
                cur.execute("""
                    SELECT engagement_id FROM assets
                    WHERE hostname IS NOT NULL
                    AND (
                        %s LIKE CONCAT('%%', LOWER(hostname))
                        OR %s LIKE CONCAT('%%.', LOWER(hostname))
                    )
                    AND LENGTH(hostname) > 0
                    ORDER BY LENGTH(hostname) DESC
                    LIMIT 1
                """, (target_domain, target_domain))
                row = cur.fetchone()
                if row:
                    engagement_id = row[0] if isinstance(row, tuple) else row.get('engagement_id')
        cur.execute("RELEASE SAVEPOINT engagement_lookup")
    except Exception:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT engagement_lookup")
        except Exception:
            pass

    # If no engagement found and target appears out of scope, assign to unknown_scope
    if not engagement_id and _is_out_of_scope_target(target, cur):
        is_out_of_scope = True
        engagement_id = _get_or_create_unknown_scope_engagement(cur)

        # Modify title and reason to indicate out-of-scope
        title = f"[OUT-OF-SCOPE] {title}"
        reason = f"{reason} (Auto-assigned to unknown_scope - discovered during reconnaissance)"

        # Add out-of-scope tag
        if tags is None:
            tags = []
        tags = list(tags) + ['out-of-scope', 'unknown-scope']

        # Lower severity for out-of-scope items
        if severity in ['critical', 'high']:
            severity = 'medium'
        elif severity == 'medium':
            severity = 'low'

    cur.execute("""
        INSERT INTO follow_up_items
            (id, finding_source, finding_id, title, target, severity, reason,
             flagged_by, rule_id, confidence, tags, engagement_id, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 'osint_agent', %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """, (
        str(uuid.uuid4()), finding_source,
        finding_id, title, target, severity, reason,
        rule_id, confidence, tags or [], engagement_id,
        Json(metadata) if metadata else Json({}),
    ))

    if is_out_of_scope:
        log.info("Assigned out-of-scope follow-up to unknown_scope engagement: %s", target)


# ──────────────────────────────────────────────────────────────
# RAG feedback retrieval
# ──────────────────────────────────────────────────────────────

def _retrieve_similar_feedback(context_text: str, top_k: int = 5):
    """Retrieve the most similar past user feedback via embedding distance."""
    try:
        import requests as _req
        resp = _req.post(f"{EMBEDDER_URL}/embed", json={"texts": [context_text]}, timeout=30)
        resp.raise_for_status()
        vec = resp.json()["embeddings"][0]
    except Exception:
        return []

    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, user_action, user_notes, agent_suggestion,
                       finding_context, embedding <-> %s::vector AS distance
                FROM osint_agent_feedback
                WHERE embedding IS NOT NULL
                ORDER BY embedding <-> %s::vector
                LIMIT %s
            """, (vec, vec, top_k))
            rows = cur.fetchall()
            for r in rows:
                r["similarity"] = max(0, 1.0 - float(r.get("distance", 1.0)))
            return rows
    except Exception as e:
        log.warning("RAG feedback retrieval failed: %s", e)
        return []
    finally:
        conn.close()


def _should_skip_via_feedback(context_text: str) -> bool:
    """Check if similar past feedback suggests dismissal (skip flagging)."""
    similar = _retrieve_similar_feedback(context_text, top_k=3)
    if not similar:
        return False
    top = similar[0]
    if top.get("similarity", 0) > 0.85 and top.get("user_action") == "dismissed":
        log.info("Skipping flag — similar feedback was dismissed (sim=%.2f)", top["similarity"])
        return True
    return False


# ──────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────

_last_scan_time = 0.0
_MIN_SCAN_INTERVAL = 30  # seconds — don't run more often than this


def scan_new_findings(tool: str = None, since_minutes: int = 60):
    """
    Run all detection rules against recent findings.
    Called after ingest or manually via POST /agent/scan.
    Rate-limited to once per 30 seconds to prevent DB flooding.
    """
    global _last_scan_time
    import time
    now = time.time()
    if now - _last_scan_time < _MIN_SCAN_INTERVAL:
        log.info("OSINT agent skipped — last scan was %ds ago (min interval %ds)",
                 int(now - _last_scan_time), _MIN_SCAN_INTERVAL)
        return {"flagged": 0, "skipped": True}
    _last_scan_time = now

    log.info("OSINT agent scanning findings (last %d min, tool=%s)", since_minutes, tool)
    conn = _get_conn()
    total = 0

    engine = get_engine()

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Ensure rules are loaded (with DB state merge)
            if not engine._loaded:
                engine.load_rules(cur)

            # Execute all enabled rules
            matches = engine.execute_all(cur, since_minutes)

            # Create follow-up items for each match.
            # Each insert is wrapped in a SAVEPOINT so one failure
            # doesn't poison the transaction and cascade to all remaining items.
            for match in matches:
                try:
                    cur.execute("SAVEPOINT followup_insert")

                    # Check if VulnX has already flagged this software/CVE combination to avoid duplicates
                    if match["rule_id"] == "software_known_cve":
                        # Extract product name from metadata or title for VulnX deduplication check
                        product_name = ""
                        if match.get("metadata") and match["metadata"].get("product"):
                            product_name = match["metadata"]["product"]
                        else:
                            # Fallback: extract from title if metadata not available
                            import re
                            title_match = re.search(r"Vulnerable:\s*([^v\s]+)", match["title"])
                            if title_match:
                                product_name = title_match.group(1).strip()

                        if product_name:
                            cur.execute("""
                                SELECT 1 FROM follow_up_items
                                WHERE rule_id = 'software_known_cve'
                                AND finding_source = 'vulnx'
                                AND target = %s
                                AND metadata->>'product' ILIKE %s
                                LIMIT 1
                            """, (match["target"], f"%{product_name}%"))

                            if cur.fetchone():
                                # VulnX already flagged this asset/product combination - skip
                                cur.execute("RELEASE SAVEPOINT followup_insert")
                                continue

                    _create_follow_up(
                        cur,
                        rule_id=match["rule_id"],
                        title=match["title"],
                        target=match["target"],
                        severity=match["severity"],
                        reason=match["reason"],
                        finding_source=match["finding_source"],
                        finding_id=match["finding_id"],
                        confidence=match.get("confidence", 0.9),
                        tags=match.get("tags"),
                        metadata=match.get("metadata"),
                    )
                    cur.execute("RELEASE SAVEPOINT followup_insert")
                    total += 1
                except Exception as e:
                    log.warning("Failed to create follow-up for %s: %s", match.get("title"), e)
                    try:
                        cur.execute("ROLLBACK TO SAVEPOINT followup_insert")
                    except Exception:
                        pass

            conn.commit()
    except Exception as e:
        log.error("OSINT agent scan failed: %s", e)
        conn.rollback()
    finally:
        conn.close()

    log.info("OSINT agent created %d follow-up items", total)

    # Emit webhook for agent scan completion
    try:
        from webhooks import emit_webhook
        emit_webhook("agent_scan_completed", "osint_agent", {
            "follow_ups_created": total,
            "rules_evaluated": len(matches) if matches else 0,
            "since_minutes": since_minutes,
            "tool_filter": tool,
        })
    except Exception:
        pass

    return {"flagged": total}
