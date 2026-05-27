"""
Recon Gap Analysis Agent — identifies missing recon data per engagement.

Analyzes scope targets against collected recon_findings to find gaps
(missing DNS, TLS, ASN, etc.), generates recommendations for scans to
fill them, and can auto-dispatch passive scans.

No LLM dependency — purely structured SQL queries.
"""

import os
import uuid
import json
import logging
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

log = logging.getLogger("gap_agent")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _get_conn():
    return psycopg2.connect(DB_DSN)


# ── Recon categories: what "complete" recon looks like ─────────────────

RECON_CATEGORIES = {
    "subdomain_enumeration": {
        "label": "Subdomains",
        "description": "Subdomain discovery via passive DNS and certificate transparency",
        "sources": ["subfinder", "amass"],
        "finding_types": ["subdomain"],
        "passive_scans": ["subfinder"],
        "active_scans": [],
        "priority": 1,
        "target_types": ["domain"],
    },
    "dns_resolution": {
        "label": "DNS Records",
        "description": "DNS record resolution (A, AAAA, CNAME, MX, NS, TXT)",
        "sources": ["dnsx"],
        "finding_types": ["dns_a", "dns_aaaa", "dns_cname", "dns_mx", "dns_ns", "dns_txt"],
        "passive_scans": ["dnsx"],
        "active_scans": [],
        "priority": 2,
        "target_types": ["domain", "ip"],
    },
    "tls_certificates": {
        "label": "TLS Certs",
        "description": "TLS certificate chain and CT log enumeration",
        "sources": ["tlsx", "crtsh"],
        "finding_types": ["tls_cert", "ct_cert"],
        "passive_scans": ["crtsh"],
        "active_scans": ["tlsx"],
        "priority": 4,
        "target_types": ["domain", "ip"],
    },
    "http_probing": {
        "label": "HTTP Services",
        "description": "HTTP service detection, tech stack, web server fingerprinting",
        "sources": ["httpx", "whatweb"],
        "finding_types": ["web_service"],
        "passive_scans": [],
        "active_scans": ["httpx"],
        "priority": 3,
        "target_types": ["domain", "ip", "url"],
    },
    "asn_mapping": {
        "label": "ASN/IP Intel",
        "description": "IP to ASN, organization, and CIDR mapping",
        "sources": ["asnmap"],
        "finding_types": ["asn_mapping", "asn"],
        "passive_scans": ["asnmap"],
        "active_scans": [],
        "priority": 5,
        "target_types": ["ip", "domain"],
    },
    "waf_detection": {
        "label": "WAF",
        "description": "WAF/CDN/firewall identification",
        "sources": ["wafw00f"],
        "finding_types": ["waf_detection", "waf"],
        "passive_scans": [],
        "active_scans": ["wafw00f"],
        "priority": 6,
        "target_types": ["domain", "url"],
    },
    "whois": {
        "label": "WHOIS",
        "description": "Domain/IP registration, organization, netblock, ASN lookup",
        "sources": ["whois"],
        "finding_types": ["whois_record", "whois_ip"],
        "passive_scans": ["whois"],
        "active_scans": [],
        "priority": 5,
        "target_types": ["domain", "ip"],
    },
    "port_enumeration": {
        "label": "Ports",
        "description": "Open port discovery via network scanning",
        "sources": ["nmap", "masscan", "naabu"],
        "finding_types": [],
        "passive_scans": [],
        "active_scans": ["nmap"],
        "priority": 7,
        "target_types": ["ip", "cidr"],
        "check_ports_table": True,
    },
}


# ── Core analysis functions ────────────────────────────────────────────

def _get_targets(cur, engagement_id: str) -> list[dict]:
    """Fetch scope targets for the engagement."""
    cur.execute("""
        SELECT target, target_type, name
        FROM scope_targets
        WHERE engagement_id = %s
        ORDER BY target_type, target
    """, (engagement_id,))
    return [dict(r) for r in cur.fetchall()]


def _get_existing_data(cur, engagement_id: str, targets: list[dict]) -> dict:
    """Query recon_findings and ports grouped by target and source.

    Returns: {target_str: {source: finding_count, ...}, ...}
    """
    if not targets:
        return {}

    # Build LIKE patterns for target matching (same approach as scope intelligence)
    patterns = []
    for t in targets:
        target = t["target"]
        target_type = t.get("target_type", "domain")
        if target_type == "domain":
            patterns.append(f"%{target}%")
        elif target_type in ("ip", "cidr"):
            patterns.append(f"%{target}%")
        elif target_type == "url":
            patterns.append(f"%{target}%")
        else:
            patterns.append(f"%{target}%")

    # Query recon_findings
    result = {}
    for i, t in enumerate(targets):
        target_key = t["target"]
        pattern = patterns[i]

        cur.execute("""
            SELECT source, finding_type, count(*) as cnt
            FROM recon_findings
            WHERE target LIKE %s
            GROUP BY source, finding_type
        """, (pattern,))
        source_counts = {}
        for row in cur.fetchall():
            src = row["source"]
            ft = row["finding_type"]
            cnt = row["cnt"]
            source_counts[src] = source_counts.get(src, 0) + cnt
            source_counts[f"_type_{ft}"] = source_counts.get(f"_type_{ft}", 0) + cnt

        # Also check web_findings for httpx/whatweb
        cur.execute("""
            SELECT source, count(*) as cnt
            FROM web_findings
            WHERE url LIKE %s
            GROUP BY source
        """, (pattern,))
        for row in cur.fetchall():
            src = row["source"]
            source_counts[src] = source_counts.get(src, 0) + row["cnt"]

        # Check ports table for port_enumeration
        cur.execute("""
            SELECT count(*) as cnt FROM ports p
            JOIN assets a ON p.asset_id = a.id
            WHERE (host(a.ip)::text LIKE %s OR a.hostname LIKE %s)
              AND p.is_open = true
        """, (pattern, pattern))
        port_row = cur.fetchone()
        if port_row and port_row["cnt"] > 0:
            source_counts["_ports"] = port_row["cnt"]

        result[target_key] = source_counts

    return result


def _analyze_gaps(targets: list[dict], existing: dict) -> dict:
    """Compare actual data vs expected categories. Returns per-target gap analysis."""
    analysis = {}
    total_gaps = 0

    for t in targets:
        target_key = t["target"]
        target_type = t.get("target_type", "domain")
        data = existing.get(target_key, {})

        categories = {}
        present_count = 0
        applicable_count = 0

        for cat_id, cat in RECON_CATEGORIES.items():
            # Check if this category applies to this target type
            if target_type not in cat["target_types"]:
                continue

            applicable_count += 1
            has_data = False
            finding_count = 0

            # Check if any source for this category has data
            for src in cat["sources"]:
                if src in data:
                    has_data = True
                    finding_count += data[src]

            # Check finding types
            for ft in cat["finding_types"]:
                key = f"_type_{ft}"
                if key in data:
                    has_data = True
                    finding_count += data[key]

            # Special: port_enumeration checks ports table
            if cat.get("check_ports_table") and data.get("_ports", 0) > 0:
                has_data = True
                finding_count = data["_ports"]

            if has_data:
                present_count += 1

            categories[cat_id] = {
                "label": cat["label"],
                "has_data": has_data,
                "finding_count": finding_count,
                "sources_found": [s for s in cat["sources"] if s in data],
                "passive_scans": cat["passive_scans"],
                "active_scans": cat["active_scans"],
            }

            if not has_data:
                total_gaps += 1

        coverage_pct = round(present_count / applicable_count * 100) if applicable_count else 0

        analysis[target_key] = {
            "target_type": target_type,
            "categories": categories,
            "present": present_count,
            "applicable": applicable_count,
            "missing": applicable_count - present_count,
            "coverage_pct": coverage_pct,
        }

    return {"targets": analysis, "total_gaps": total_gaps}


def _generate_recommendations(gap_analysis: dict) -> list[dict]:
    """Produce actionable scan suggestions from gap analysis."""
    recs = []
    seen = set()

    for target, info in gap_analysis.get("targets", {}).items():
        for cat_id, cat_data in info.get("categories", {}).items():
            if cat_data["has_data"]:
                continue

            cat_def = RECON_CATEGORIES.get(cat_id, {})

            # Passive scans first
            for scan_type in cat_data.get("passive_scans", []):
                key = f"{scan_type}:{target}"
                if key in seen:
                    continue
                seen.add(key)
                recs.append({
                    "category": cat_id,
                    "category_label": cat_data["label"],
                    "target": target,
                    "scan_type": scan_type,
                    "passive": True,
                    "priority": cat_def.get("priority", 99),
                    "reason": f"No {cat_data['label'].lower()} data for {target}",
                })

            # Active scans
            for scan_type in cat_data.get("active_scans", []):
                key = f"{scan_type}:{target}"
                if key in seen:
                    continue
                seen.add(key)
                recs.append({
                    "category": cat_id,
                    "category_label": cat_data["label"],
                    "target": target,
                    "scan_type": scan_type,
                    "passive": False,
                    "priority": cat_def.get("priority", 99),
                    "reason": f"No {cat_data['label'].lower()} data for {target} (active scan required)",
                })

    recs.sort(key=lambda r: (r["priority"], 0 if r["passive"] else 1, r["target"]))
    return recs


# ── Main entry points ──────────────────────────────────────────────────

def run_gap_analysis(engagement_id: str, triggered_by: str = "manual") -> dict:
    """Run gap analysis for an engagement. Creates a report row in the DB."""
    log.info("Gap analysis starting for engagement %s (triggered_by=%s)", engagement_id, triggered_by)

    conn = _get_conn()
    report_id = str(uuid.uuid4())

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Create report row
            cur.execute("""
                INSERT INTO gap_analysis_reports (id, engagement_id, status, triggered_by)
                VALUES (%s, %s, 'running', %s)
            """, (report_id, engagement_id, triggered_by))
            conn.commit()

            # Emit webhook
            try:
                from webhooks import emit_webhook
                emit_webhook("gap_analysis_started", "gap_agent", {
                    "engagement_id": engagement_id,
                    "report_id": report_id,
                    "triggered_by": triggered_by,
                })
            except Exception:
                pass

            # Run analysis
            targets = _get_targets(cur, engagement_id)
            if not targets:
                cur.execute("""
                    UPDATE gap_analysis_reports
                    SET status = 'completed', report = %s, completed_at = now()
                    WHERE id = %s
                """, (json.dumps({"targets": {}, "total_gaps": 0, "message": "No scope targets defined"}), report_id))
                conn.commit()
                return {"ok": True, "report_id": report_id, "gaps_found": 0, "message": "No scope targets"}

            existing = _get_existing_data(cur, engagement_id, targets)
            gap_analysis = _analyze_gaps(targets, existing)
            recommendations = _generate_recommendations(gap_analysis)

            # Compute summary
            total_gaps = gap_analysis["total_gaps"]
            total_targets = len(targets)
            avg_coverage = 0
            if gap_analysis["targets"]:
                avg_coverage = round(
                    sum(t["coverage_pct"] for t in gap_analysis["targets"].values()) / len(gap_analysis["targets"])
                )

            report = {
                **gap_analysis,
                "summary": {
                    "total_targets": total_targets,
                    "total_gaps": total_gaps,
                    "avg_coverage_pct": avg_coverage,
                    "passive_recommendations": len([r for r in recommendations if r["passive"]]),
                    "active_recommendations": len([r for r in recommendations if not r["passive"]]),
                },
            }

            # Update report row
            cur.execute("""
                UPDATE gap_analysis_reports
                SET status = 'completed', report = %s, gaps_found = %s,
                    recommendations = %s, completed_at = now()
                WHERE id = %s
            """, (json.dumps(report), total_gaps, json.dumps(recommendations), report_id))
            conn.commit()

            log.info("Gap analysis completed: %d targets, %d gaps, %d recommendations",
                     total_targets, total_gaps, len(recommendations))

            # Emit webhook
            try:
                from webhooks import emit_webhook
                emit_webhook("gap_analysis_completed", "gap_agent", {
                    "engagement_id": engagement_id,
                    "report_id": report_id,
                    "gaps_found": total_gaps,
                    "coverage_pct": avg_coverage,
                    "recommendations": len(recommendations),
                })
            except Exception:
                pass

            return {
                "ok": True,
                "report_id": report_id,
                "gaps_found": total_gaps,
                "coverage_pct": avg_coverage,
                "recommendations_count": len(recommendations),
            }

    except Exception as e:
        log.error("Gap analysis failed: %s", e)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE gap_analysis_reports SET status = 'failed' WHERE id = %s
                """, (report_id,))
                conn.commit()
        except Exception:
            pass

        try:
            from webhooks import emit_webhook
            emit_webhook("gap_analysis_failed", "gap_agent", {
                "engagement_id": engagement_id,
                "error": str(e),
            })
        except Exception:
            pass

        return {"ok": False, "error": str(e)}
    finally:
        conn.close()


def auto_fill_gaps(engagement_id: str, report_id: str = None) -> dict:
    """Dispatch passive scans to fill gaps from a completed report."""
    import requests as _req

    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if not report_id:
                cur.execute("""
                    SELECT id, recommendations FROM gap_analysis_reports
                    WHERE engagement_id = %s AND status = 'completed'
                    ORDER BY created_at DESC LIMIT 1
                """, (engagement_id,))
                row = cur.fetchone()
                if not row:
                    return {"ok": False, "error": "No completed gap report found"}
                report_id = str(row["id"])
                recommendations = row["recommendations"]
            else:
                cur.execute("SELECT recommendations FROM gap_analysis_reports WHERE id = %s", (report_id,))
                row = cur.fetchone()
                if not row:
                    return {"ok": False, "error": "Report not found"}
                recommendations = row["recommendations"]

            if isinstance(recommendations, str):
                recommendations = json.loads(recommendations)

            # Filter to passive-only
            passive_recs = [r for r in recommendations if r.get("passive")]
            if not passive_recs:
                return {"ok": True, "scans_dispatched": 0, "message": "No passive scans to dispatch"}

            # Dispatch each via BFF scan endpoint
            bff_base = os.environ.get("BFF_URL", "https://pentest-dashboard")
            dispatched = 0
            scan_types = set()

            for rec in passive_recs:
                try:
                    payload = {
                        "targets": rec["target"],
                        "engagement_id": engagement_id,
                    }
                    _req.post(
                        f"{bff_base}/api/scans/{rec['scan_type']}",
                        json=payload, timeout=10, verify=False,
                    )
                    dispatched += 1
                    scan_types.add(rec["scan_type"])
                except Exception as e:
                    log.warning("Failed to dispatch %s for %s: %s", rec["scan_type"], rec["target"], e)

            # Update report
            cur.execute("""
                UPDATE gap_analysis_reports SET scans_dispatched = %s WHERE id = %s
            """, (dispatched, report_id))
            conn.commit()

            log.info("Auto-fill dispatched %d passive scans for engagement %s", dispatched, engagement_id)

            try:
                from webhooks import emit_webhook
                emit_webhook("gap_analysis_scans_dispatched", "gap_agent", {
                    "engagement_id": engagement_id,
                    "report_id": report_id,
                    "scans_dispatched": dispatched,
                    "scan_types": list(scan_types),
                })
            except Exception:
                pass

            return {"ok": True, "scans_dispatched": dispatched, "scan_types": list(scan_types)}

    except Exception as e:
        log.error("Auto-fill failed: %s", e)
        return {"ok": False, "error": str(e)}
    finally:
        conn.close()
