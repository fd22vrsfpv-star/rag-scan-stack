"""
Parse Nuclei JSONL output and insert into vulns table
"""
import os
import uuid
import json
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, Any

import requests

from etl.fingerprint import vuln_fingerprint

logger = logging.getLogger("parse_nuclei")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
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


def search_exploits_for_cve(cve: str) -> Dict[str, Any]:
    """
    Search for exploits matching a CVE ID.
    Returns exploit info from ExploitDB and Metasploit.
    """
    try:
        resp = requests.get(
            f"{API_BASE}/rag/search/enhanced",
            params={"cve": cve, "top_k": 10, "min_confidence": 0.3},
            headers={"x-api-key": API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            exploitdb = data.get("exploitdb", [])
            metasploit = data.get("metasploit", [])
            return {
                "found": len(exploitdb) > 0 or len(metasploit) > 0,
                "exploitdb_count": len(exploitdb),
                "metasploit_count": len(metasploit),
                "exploitdb": exploitdb[:5],  # Top 5 EDB exploits
                "metasploit": metasploit[:5]  # Top 5 MSF modules
            }
    except Exception as e:
        logger.warning(f"Failed to search exploits for {cve}: {e}")
    return {"found": False, "exploitdb_count": 0, "metasploit_count": 0, "exploitdb": [], "metasploit": []}


def parse_nuclei(path: str, profile: str = None, job_id: str = None, target: str = None) -> Dict[str, Any]:
    """
    Parse Nuclei JSONL output file and insert findings into vulns table

    Args:
        path: Path to the nuclei JSONL output file
        profile: Optional profile name (for compatibility with API)
        job_id: Optional job ID for webhook correlation
        target: Optional target description for webhook context

    Returns:
        Dict with parsing statistics
    """
    stats = {
        "total": 0,
        "inserted": 0,
        "errors": 0,
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "exploitable_count": 0,
        "exploitable_cves": [],
        "job_id": job_id,
        "target": target
    }

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    stats["total"] += 1

                    try:
                        cur.execute("SAVEPOINT rec_sp")
                        finding = json.loads(line)

                        # Extract key fields from nuclei output
                        template_id = finding.get("template-id", finding.get("templateID", "unknown"))
                        template_name = finding.get("info", {}).get("name", template_id)
                        severity = finding.get("info", {}).get("severity", "info")
                        host = finding.get("host", finding.get("matched-at", ""))
                        matched_at = finding.get("matched-at", host)

                        # Extract IP from host URL
                        ip = None
                        if host:
                            # Parse IP from URL like http://192.168.1.150:80
                            import re
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host)
                            if ip_match:
                                ip = ip_match.group(1)

                        # Get asset_id if IP found
                        asset_id = None
                        if ip:
                            cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
                            row = cur.fetchone()
                            if row:
                                asset_id = str(row["id"])

                        # Extract additional info
                        description = finding.get("info", {}).get("description", "")
                        reference = finding.get("info", {}).get("reference", [])
                        if isinstance(reference, list):
                            reference = ", ".join(reference[:5])  # Limit to 5 refs

                        tags = finding.get("info", {}).get("tags", [])
                        if isinstance(tags, list):
                            tags = ", ".join(tags)

                        cve_id = None
                        cve_list = finding.get("info", {}).get("classification", {}).get("cve-id", [])
                        if cve_list and isinstance(cve_list, list) and len(cve_list) > 0:
                            cve_id = cve_list[0]

                        matcher_name = finding.get("matcher-name", "")
                        extracted = finding.get("extracted-results", [])
                        if isinstance(extracted, list):
                            extracted = "\n".join(str(e) for e in extracted[:10])

                        # Build evidence string
                        evidence_parts = []
                        if matcher_name:
                            evidence_parts.append(f"Matcher: {matcher_name}")
                        if extracted:
                            evidence_parts.append(f"Extracted: {extracted}")
                        evidence = "\n".join(evidence_parts) if evidence_parts else None

                        # Insert into vulns table
                        # Build output with all relevant info
                        output_parts = []
                        if description:
                            output_parts.append(description[:1000])
                        if evidence:
                            output_parts.append(f"\n--- Evidence ---\n{evidence}")
                        if reference:
                            output_parts.append(f"\n--- References ---\n{reference}")
                        output_text = "\n".join(output_parts) if output_parts else f"Nuclei finding: {template_name}"

                        # Extract port from matched_at (could be "192.168.1.150:22" or "http://host:80/path")
                        port_num = None
                        matched_url = matched_at or ""
                        port_match = re.search(r':(\d+)', matched_url)
                        if port_match:
                            port_num = int(port_match.group(1))

                        # Only store URL if it's a proper HTTP URL (not bare ip:port)
                        metadata = {
                            "source": f"nuclei:{template_id}",
                            "tags": tags,
                            "template_id": template_id,
                            "port": port_num,
                        }
                        if matched_url.startswith("http"):
                            metadata["url"] = matched_url

                        fp = vuln_fingerprint(
                            ip=ip, port=port_num,
                            script=f"nuclei:{template_id}",
                            cves=[cve_id] if cve_id else None,
                        )

                        vuln_id = str(uuid.uuid4())
                        cur.execute("""
                            INSERT INTO vulns (id, asset_id, script, output, severity, cve, metadata, fingerprint)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                        """, (
                            vuln_id,
                            asset_id,
                            f"nuclei:{template_id}",
                            output_text[:4000],
                            severity,
                            [cve_id] if cve_id else None,
                            json.dumps(metadata),
                            fp,
                        ))

                        stats["inserted"] += 1

                        # Track severity counts
                        if severity in stats["by_severity"]:
                            stats["by_severity"][severity] += 1

                        # Check for exploits if CVE exists
                        exploit_info = None
                        if cve_id:
                            exploit_info = search_exploits_for_cve(cve_id)
                            if exploit_info.get("found"):
                                stats["exploitable_count"] += 1
                                stats["exploitable_cves"].append({
                                    "cve": cve_id,
                                    "severity": severity,
                                    "exploitdb_count": exploit_info["exploitdb_count"],
                                    "metasploit_count": exploit_info["metasploit_count"]
                                })

                                # Emit real-time webhook for exploitable finding
                                emit_webhook_event("finding_exploitable", "nuclei", {
                                    "job_id": job_id,
                                    "cve": cve_id,
                                    "severity": severity,
                                    "title": template_name,
                                    "url": matched_at,
                                    "ip": ip,
                                    "exploit_count": exploit_info["exploitdb_count"] + exploit_info["metasploit_count"],
                                    "exploitdb_count": exploit_info["exploitdb_count"],
                                    "metasploit_count": exploit_info["metasploit_count"],
                                    "top_exploits": {
                                        "exploitdb": [{"id": e.get("edb_id"), "title": e.get("title")} for e in exploit_info["exploitdb"][:3]],
                                        "metasploit": [{"module": m.get("module_path"), "rank": m.get("rank")} for m in exploit_info["metasploit"][:3]]
                                    }
                                }, severity=severity)

                        # Emit webhook for high/critical findings
                        if severity in ("high", "critical"):
                            event_type = f"finding_{severity}"
                            emit_webhook_event(event_type, "nuclei", {
                                "job_id": job_id,
                                "title": template_name,
                                "template_id": template_id,
                                "url": matched_at,
                                "ip": ip,
                                "cve": cve_id,
                                "has_exploit": exploit_info.get("found") if exploit_info else False,
                                "description": description[:500] if description else None
                            }, severity=severity)

                        cur.execute("RELEASE SAVEPOINT rec_sp")
                    except json.JSONDecodeError as e:
                        cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                        stats["errors"] += 1
                        print(f"[nuclei-parse] JSON error: {e}")
                    except Exception as e:
                        cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                        stats["errors"] += 1
                        print(f"[nuclei-parse] Error processing finding: {e}")

            conn.commit()

        # Emit scan summary webhook
        if stats["inserted"] > 0:
            emit_webhook_event("scan_summary", "nuclei", {
                "job_id": job_id,
                "target": target,
                "scan_type": "nuclei-scan",
                "total_findings": stats["inserted"],
                "by_severity": stats["by_severity"],
                "exploitable_count": stats["exploitable_count"],
                "exploitable_cves": stats["exploitable_cves"][:20],  # Top 20
                "critical_count": stats["by_severity"]["critical"],
                "high_count": stats["by_severity"]["high"]
            })

    finally:
        conn.close()

    return stats
