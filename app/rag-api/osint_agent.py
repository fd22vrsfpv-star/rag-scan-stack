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

from urllib.parse import urlparse

# The SAME fail-closed matcher the discovery ingests (parse_subfinder/parse_dnsx)
# use, so ip/cidr/domain/url scope behaves identically everywhere.
try:
    from etl.scope_gate import is_in_scope, load_engagement_scope
except ImportError:  # container layouts that mount etl/ flat
    from scope_gate import is_in_scope, load_engagement_scope

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

    # Create unknown_scope engagement.
    #
    # This INSERT named `description` and `scope`, NEITHER of which exists on
    # public.engagements (the columns are `notes` and `scope_name`). So the whole
    # quarantine path raised UndefinedColumn the first time it was reached —
    # which, given the scope check was default-allow and almost never fired, is
    # why nobody hit it. Fixing the check exposed this immediately.
    cur.execute("""
        INSERT INTO engagements (id, name, notes, status, scope_name, start_date, created_at, updated_at)
        VALUES (gen_random_uuid(), 'unknown_scope',
                'Auto-created engagement for out-of-scope discoveries during OSINT scanning',
                'active',
                'unknown_scope',
                now(), now(), now())
        RETURNING id
    """)
    # RealDictCursor returns a dict, so [0] raises KeyError. The SELECT above
    # already handled both cursor shapes; this path did not — the second latent
    # bug in this function, and like the column-name one, only reachable once the
    # scope check actually started firing.
    row = cur.fetchone()
    engagement_id = row[0] if isinstance(row, (tuple, list)) else row.get("id")
    log.info("Created 'unknown_scope' engagement: %s", engagement_id)
    return engagement_id


def _target_hostname(target):
    """Bare hostname from a target string, or "" when none can be parsed.

    Scope is decided by the URL's HOST and nothing else. Substring matching is
    what made the old check wrong in both directions: it would have called
    devblog.attacker.com in-scope (contains "dev"), and it cannot tell
    http://192.168.1.150/redir?url=https://www.owasp.org — an in-scope open
    redirect ON the target — apart from http://www.owasp.org/... , which is a
    different host entirely.
    """
    if not target:
        return ""
    t = str(target).strip()
    try:
        netloc = urlparse(t if "://" in t else "//" + t).netloc
    except Exception:
        netloc = t.split("/")[0]
    return (netloc.split("@")[-1].split(":")[0] or "").strip().lower().rstrip(".")


def _scanned_host_scope(cur):
    """Fallback scope: the hosts we actually SCANNED.

    Used only when no scope_targets rows exist. These come from nmap/masscan
    ingestion, i.e. hosts an operator pointed a scanner at — not hosts a crawler
    merely linked to. That distinction is the whole point: the old check consulted
    `assets` for in-scope-ness while discovery was writing into the same table, so
    anything crawled could authorize itself.
    """
    rows = []
    try:
        cur.execute("SAVEPOINT scanned_scope")
        cur.execute("SELECT DISTINCT host(ip)::text FROM assets WHERE ip IS NOT NULL")
        rows += [(r[0] if not isinstance(r, dict) else r.get("host"), "ip")
                 for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT LOWER(hostname) FROM assets WHERE hostname IS NOT NULL")
        for r in cur.fetchall():
            h = r[0] if not isinstance(r, dict) else r.get("lower")
            h = _target_hostname(h)
            if h:
                rows.append((h, "domain"))
        cur.execute("RELEASE SAVEPOINT scanned_scope")
    except Exception as e:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT scanned_scope")
        except Exception:
            pass
        log.warning("scanned-host scope lookup failed: %s", e)
    return [(t, tt) for t, tt in rows if t]


def _host_aliases(cur, host):
    """Every known identity of `host`: itself, its IPs, and its hostnames.

    A host can be in scope under a name the scope entry does not use. Scope may
    list 127.0.0.1 while the finding says "localhost"; or scope lists a hostname,
    the scan resolved it to an IP, and later findings are recorded against that
    IP. Matching the literal string alone rejects both, which reads to the
    operator as the gate refusing a host it demonstrably just scanned.

    Aliases come from `assets`, where nmap/masscan ingestion records the ip <->
    hostname pairing it actually observed. Only pairings we OBSERVED are used —
    this does not perform live DNS resolution, which an attacker-controlled
    record could otherwise use to talk its way into scope.
    """
    aliases = {host}
    # Loopback is the one pairing every system agrees on and that assets may not
    # carry explicitly.
    if host in ("localhost", "127.0.0.1", "::1"):
        aliases |= {"localhost", "127.0.0.1", "::1"}
    try:
        cur.execute("SAVEPOINT host_aliases")
        # hostname -> ip(s)
        cur.execute(
            "SELECT DISTINCT host(ip)::text AS ip FROM assets "
            "WHERE ip IS NOT NULL AND LOWER(hostname) = %s", (host,))
        for r in cur.fetchall():
            v = r[0] if not isinstance(r, dict) else r.get("ip")
            if v:
                aliases.add(str(v).lower())
        # ip -> hostname(s)
        cur.execute(
            "SELECT DISTINCT LOWER(hostname) AS hostname FROM assets "
            "WHERE hostname IS NOT NULL AND host(ip)::text = %s", (host,))
        for r in cur.fetchall():
            v = r[0] if not isinstance(r, dict) else r.get("hostname")
            v = _target_hostname(v)
            if v:
                aliases.add(v)
        cur.execute("RELEASE SAVEPOINT host_aliases")
    except Exception as e:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT host_aliases")
        except Exception:
            pass
        log.warning("alias lookup failed for %r: %s", host, e)
    return aliases


def _load_scope_rows(cur, engagement_id=None):
    """(scope_rows, source). Engagement scope first, then any scope, then scanned hosts."""
    rows = load_engagement_scope(cur, engagement_id) if engagement_id else []
    if rows:
        return rows, "engagement"
    try:
        cur.execute("SAVEPOINT any_scope")
        cur.execute("SELECT target, target_type FROM public.scope_targets")
        rows = [(r[0], r[1]) if not isinstance(r, dict) else (r.get("target"), r.get("target_type"))
                for r in cur.fetchall()]
        cur.execute("RELEASE SAVEPOINT any_scope")
    except Exception:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT any_scope")
        except Exception:
            pass
        rows = []
    if rows:
        return rows, "scope_targets"
    return _scanned_host_scope(cur), "scanned-hosts"


def _is_out_of_scope_target(target, cur, engagement_id=None):
    """True when `target` is NOT in scope. DEFAULT-DENY.

    The previous implementation was default-ALLOW behind a 20-entry hardcoded
    denylist (github.com, google.com, ...) and ended with:

        # Be conservative - don't flag as out of scope unless we're very confident
        return False

    So every unrecognised external host was treated as in-scope. www.owasp.org,
    irongeek.com, www.jcp.org, java.sun.com, www.jguru.com, en.wikipedia.org,
    samurai.inguardians.com and www.hackersforcharity.org — all linked from the
    target's own pages — became follow-up items on an engagement that never
    authorized them. For an authorization boundary the default must be deny.

    Scope resolution is delegated to etl.scope_gate.is_in_scope, the same
    fail-closed matcher the discovery ingests use, so ip/cidr/domain/url all
    behave identically across the system.
    """
    host = _target_hostname(target)
    if not host:
        # Nothing to authorize against. Fail closed — the caller quarantines
        # rather than deletes, so this is recoverable.
        return True
    scope_rows, source = _load_scope_rows(cur, engagement_id)
    if not scope_rows:
        log.warning(
            "no scope available (no scope_targets, no scanned assets) — cannot "
            "authorize %r; treating as out-of-scope", host,
        )
        return True
    # Check every known identity, not just the literal string — see _host_aliases.
    aliases = _host_aliases(cur, host)
    in_scope = any(is_in_scope(a, scope_rows) for a in aliases)
    if not in_scope:
        log.info("out-of-scope target %r (aliases: %s; scope source: %s)",
                 host, sorted(aliases), source)
    return not in_scope

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

    # Scope is checked ALWAYS, not only when no engagement matched. The old
    # `if not engagement_id and ...` meant an out-of-scope host that inherited an
    # engagement from surrounding context skipped the check completely — the
    # authorization boundary was conditional on a lookup that had nothing to do
    # with authorization.
    if _is_out_of_scope_target(target, cur, engagement_id):
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
