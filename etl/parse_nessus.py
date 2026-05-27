"""
Parse Nessus .nessus XML output and insert into vulns / ports / assets tables.

Nessus XML structure (NessusClientData_v2):
  <NessusClientData_v2>
    <Report name="...">
      <ReportHost name="192.168.1.1">
        <HostProperties>
          <tag name="host-ip">192.168.1.1</tag>
          <tag name="host-fqdn">example.com</tag>
          <tag name="operating-system">Linux</tag>
          ...
        </HostProperties>
        <ReportItem port="443" svc_name="www" protocol="tcp"
                    pluginID="12345" pluginName="SSL Cert Info"
                    pluginFamily="General" severity="0">
          <description>...</description>
          <solution>...</solution>
          <synopsis>...</synopsis>
          <plugin_output>...</plugin_output>
          <risk_factor>None|Low|Medium|High|Critical</risk_factor>
          <cvss3_base_score>7.5</cvss3_base_score>
          <cvss_base_score>5.0</cvss_base_score>
          <cve>CVE-2021-12345</cve>
          <cwe>79</cwe>
          <xref>...</xref>
          <see_also>https://...</see_also>
        </ReportItem>
      </ReportHost>
    </Report>
  </NessusClientData_v2>
"""
import os
import uuid
import json
import logging
import ipaddress
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor, Json

import requests

from etl.fingerprint import vuln_fingerprint

logger = logging.getLogger("parse_nessus")
logger.setLevel(logging.INFO)
if not logger.handlers and not logger.parent.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
    logger.addHandler(handler)

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"

# Nessus severity mapping: 0=info, 1=low, 2=medium, 3=high, 4=critical
NESSUS_SEVERITY_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}

# risk_factor text → normalized severity
RISK_FACTOR_MAP = {
    "none": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def emit_webhook_event(event_type: str, source: str, data: dict, severity: str = None):
    """Emit a webhook event via the RAG API."""
    if not WEBHOOK_ENABLED:
        return
    try:
        payload = {"event_type": event_type, "source": source, "data": data}
        if severity:
            payload["severity"] = severity
        requests.post(
            f"{API_BASE}/webhooks/emit",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json=payload,
            timeout=5,
        )
    except Exception as e:
        logger.warning(f"Failed to emit webhook: {e}")


def search_exploits_for_cve(cve: str) -> Dict[str, Any]:
    """Search for exploits matching a CVE ID."""
    try:
        resp = requests.get(
            f"{API_BASE}/rag/search/enhanced",
            params={"cve": cve, "top_k": 10, "min_confidence": 0.3},
            headers={"x-api-key": API_KEY},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            exploitdb = data.get("exploitdb", [])
            metasploit = data.get("metasploit", [])
            return {
                "found": len(exploitdb) > 0 or len(metasploit) > 0,
                "exploitdb_count": len(exploitdb),
                "metasploit_count": len(metasploit),
                "exploitdb": exploitdb[:5],
                "metasploit": metasploit[:5],
            }
    except Exception as e:
        logger.warning(f"Failed to search exploits for {cve}: {e}")
    return {"found": False, "exploitdb_count": 0, "metasploit_count": 0, "exploitdb": [], "metasploit": []}


def _get_text(item: ET.Element, tag: str) -> Optional[str]:
    """Get text content of a child element, or None."""
    el = item.find(tag)
    return el.text.strip() if el is not None and el.text else None


def _get_all_text(item: ET.Element, tag: str) -> List[str]:
    """Get text from all matching child elements."""
    return [el.text.strip() for el in item.findall(tag) if el.text]


def _get_host_property(host: ET.Element, name: str) -> Optional[str]:
    """Get a named property from HostProperties."""
    props = host.find("HostProperties")
    if props is None:
        return None
    for tag in props.findall("tag"):
        if tag.get("name") == name:
            return tag.text
    return None


def _map_severity(item: ET.Element) -> str:
    """Determine normalized severity from Nessus ReportItem."""
    # Prefer the numeric severity attribute
    sev_num = item.get("severity", "0")
    if sev_num in NESSUS_SEVERITY_MAP:
        return NESSUS_SEVERITY_MAP[sev_num]
    # Fallback to risk_factor element
    risk = _get_text(item, "risk_factor")
    if risk:
        return RISK_FACTOR_MAP.get(risk.lower(), "info")
    return "info"


def _is_ip(value: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _get_cvss(item: ET.Element) -> Optional[float]:
    """Get best CVSS score (prefer v3 over v2)."""
    for tag in ("cvss3_base_score", "cvss_base_score"):
        val = _get_text(item, tag)
        if val:
            try:
                return float(val)
            except ValueError:
                pass
    return None


def parse_nessus(path: str, profile: str = "upload", job_id: str = None, target: str = None) -> Dict[str, Any]:
    """
    Parse a .nessus XML file and insert findings into the database.

    Args:
        path: Path to the .nessus XML file
        profile: Profile name for metadata
        job_id: Job ID for webhook correlation
        target: Target description for webhooks

    Returns:
        Dict with parsing statistics
    """
    logger.info(f"{'=' * 60}")
    logger.info(f"PARSING NESSUS: {path}")
    logger.info(f"Profile: {profile}, Job: {job_id}, Target: {target}")
    logger.info(f"{'=' * 60}")

    stats = {
        "file": path,
        "profile": profile,
        "job_id": job_id,
        "target": target,
        "hosts": 0,
        "ports": 0,
        "vulns": 0,
        "info_plugins": 0,
        "skipped_zero_port": 0,
        "errors": [],
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "exploitable_count": 0,
        "exploitable_cves": [],
    }

    # Parse XML
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"Failed to parse Nessus XML: {e}")
        stats["errors"].append(f"XML parse error: {e}")
        return stats

    # Find all ReportHost elements
    report = root.find("Report")
    if report is None:
        # Some exports use Policy/Report nesting
        for child in root:
            if child.tag == "Report":
                report = child
                break
    if report is None:
        logger.error("No <Report> element found in .nessus file")
        stats["errors"].append("No <Report> element found")
        return stats

    logger.info(f"Report name: {report.get('name', 'unknown')}")

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for host_elem in report.findall("ReportHost"):
                host_name = host_elem.get("name", "")
                ip = _get_host_property(host_elem, "host-ip") or host_name
                fqdn = _get_host_property(host_elem, "host-fqdn")
                os_name = _get_host_property(host_elem, "operating-system")

                if not ip:
                    continue

                stats["hosts"] += 1
                logger.info(f"\n{'─' * 50}")
                logger.info(f"HOST: {ip} (fqdn={fqdn}, os={os_name})")
                logger.info(f"{'─' * 50}")

                # Get or create asset
                if _is_ip(ip):
                    cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
                else:
                    cur.execute("SELECT id FROM assets WHERE hostname = %s", (ip,))
                row = cur.fetchone()
                if row:
                    asset_id = str(row["id"])
                    updates = ["updated_at=now()"]
                    params = []
                    if fqdn:
                        updates.append("hostname=COALESCE(%s, hostname)")
                        params.append(fqdn)
                    if os_name:
                        updates.append("os=COALESCE(%s, os)")
                        params.append(os_name)
                    params.append(asset_id)
                    cur.execute(f"UPDATE assets SET {', '.join(updates)} WHERE id=%s", params)
                else:
                    asset_id = str(uuid.uuid4())
                    cur.execute(
                        "INSERT INTO assets (id, ip, hostname, os) VALUES (%s, %s, %s, %s)",
                        (asset_id, ip if _is_ip(ip) else None, fqdn or (ip if not _is_ip(ip) else None), os_name),
                    )

                # Process ReportItems
                for item in host_elem.findall("ReportItem"):
                    plugin_id = item.get("pluginID", "0")
                    plugin_name = item.get("pluginName", "Unknown Plugin")
                    plugin_family = item.get("pluginFamily", "")
                    port_num = int(item.get("port", "0"))
                    proto = item.get("protocol", "tcp")
                    svc_name = item.get("svc_name", "")

                    severity = _map_severity(item)
                    cvss = _get_cvss(item)

                    # Extract text fields
                    synopsis = _get_text(item, "synopsis")
                    description = _get_text(item, "description")
                    solution = _get_text(item, "solution")
                    plugin_output = _get_text(item, "plugin_output")

                    # CVEs and references
                    cves = _get_all_text(item, "cve")
                    cwes = _get_all_text(item, "cwe")
                    xrefs = _get_all_text(item, "xref")
                    see_also = _get_all_text(item, "see_also")

                    # Skip port 0 (host-level informational plugins) from port table
                    # but still record as findings
                    port_id = None
                    if port_num > 0:
                        # Upsert port
                        cur.execute(
                            "SELECT id FROM ports WHERE asset_id=%s AND proto=%s AND port=%s",
                            (asset_id, proto, port_num),
                        )
                        prow = cur.fetchone()
                        if prow:
                            port_id = str(prow["id"])
                            cur.execute(
                                """UPDATE ports SET is_open=true,
                                   service=COALESCE(%s, service),
                                   updated_at=now()
                                   WHERE id=%s""",
                                (svc_name if svc_name and svc_name != "general" else None, port_id),
                            )
                        else:
                            port_id = str(uuid.uuid4())
                            cur.execute(
                                """INSERT INTO ports (id, asset_id, proto, port, service, is_open)
                                   VALUES (%s, %s, %s, %s, %s, true)""",
                                (port_id, asset_id, proto, port_num,
                                 svc_name if svc_name and svc_name != "general" else None),
                            )
                            stats["ports"] += 1
                    else:
                        stats["skipped_zero_port"] += 1

                    # Build output text
                    output_parts = []
                    if synopsis:
                        output_parts.append(f"Synopsis: {synopsis}")
                    if description:
                        output_parts.append(f"\n{description[:2000]}")
                    if plugin_output:
                        output_parts.append(f"\n--- Plugin Output ---\n{plugin_output[:2000]}")
                    if solution and solution.lower() != "n/a":
                        output_parts.append(f"\n--- Solution ---\n{solution[:500]}")
                    output_text = "\n".join(output_parts) if output_parts else f"Nessus: {plugin_name}"

                    # Build refs
                    refs = {}
                    if cwes:
                        refs["cwe"] = cwes
                    if xrefs:
                        refs["xref"] = xrefs
                    if see_also:
                        refs["see_also"] = see_also

                    # Build metadata
                    metadata = {
                        "source": "nessus",
                        "plugin_id": plugin_id,
                        "plugin_family": plugin_family,
                        "profile": profile,
                        "port": port_num,
                    }
                    if svc_name:
                        metadata["svc_name"] = svc_name

                    # Generate fingerprint
                    fp = vuln_fingerprint(
                        ip=ip, port=port_num,
                        script=f"nessus:{plugin_id}",
                        cves=cves,
                    )

                    # Insert into vulns
                    vuln_id = str(uuid.uuid4())
                    try:
                        cur.execute("SAVEPOINT vuln_sp")
                        cur.execute(
                            """INSERT INTO vulns
                               (id, asset_id, port_id, script, output, severity, cve, cvss, refs, metadata, fingerprint)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                            (
                                vuln_id,
                                asset_id,
                                port_id,
                                f"nessus:{plugin_id}",
                                output_text[:4000],
                                severity,
                                cves if cves else None,
                                cvss,
                                Json(refs) if refs else Json({}),
                                Json(metadata),
                                fp,
                            ),
                        )

                        if severity == "info":
                            stats["info_plugins"] += 1
                        stats["vulns"] += 1
                        if severity in stats["by_severity"]:
                            stats["by_severity"][severity] += 1

                        # Exploit lookup for CVEs
                        for cve in cves:
                            exploit_info = search_exploits_for_cve(cve)
                            if exploit_info.get("found"):
                                stats["exploitable_count"] += 1
                                stats["exploitable_cves"].append({
                                    "cve": cve,
                                    "severity": severity,
                                    "plugin_id": plugin_id,
                                    "ip": ip,
                                    "port": port_num,
                                    "exploitdb_count": exploit_info["exploitdb_count"],
                                    "metasploit_count": exploit_info["metasploit_count"],
                                })
                                emit_webhook_event("finding_exploitable", "nessus", {
                                    "job_id": job_id,
                                    "cve": cve,
                                    "severity": severity,
                                    "plugin": plugin_name,
                                    "ip": ip,
                                    "port": port_num,
                                    "exploit_count": exploit_info["exploitdb_count"] + exploit_info["metasploit_count"],
                                }, severity=severity)

                        # Webhook for high/critical
                        if severity in ("high", "critical"):
                            emit_webhook_event(f"finding_{severity}", "nessus", {
                                "job_id": job_id,
                                "plugin_id": plugin_id,
                                "plugin_name": plugin_name,
                                "ip": ip,
                                "port": port_num,
                                "cves": cves,
                                "cvss": cvss,
                            }, severity=severity)

                        cur.execute("RELEASE SAVEPOINT vuln_sp")
                    except Exception as e:
                        cur.execute("ROLLBACK TO SAVEPOINT vuln_sp")
                        logger.error(f"  [DB] Failed to insert vuln {plugin_id}: {e}")
                        stats["errors"].append(f"Plugin {plugin_id}: {e}")

            conn.commit()

    except Exception as e:
        logger.error(f"Database error: {e}")
        stats["errors"].append(f"DB error: {e}")
        conn.rollback()
    finally:
        conn.close()

    # Summary
    logger.info(f"\n{'=' * 60}")
    logger.info(f"PARSE COMPLETE: {path}")
    logger.info(f"  Hosts: {stats['hosts']}")
    logger.info(f"  Ports: {stats['ports']}")
    logger.info(f"  Findings: {stats['vulns']} (info: {stats['info_plugins']})")
    logger.info(f"  By severity: {stats['by_severity']}")
    logger.info(f"  Exploitable: {stats['exploitable_count']}")
    logger.info(f"  Skipped port-0: {stats['skipped_zero_port']}")
    if stats["errors"]:
        logger.warning(f"  Errors: {len(stats['errors'])}")
    logger.info(f"{'=' * 60}\n")

    # Emit scan summary webhook
    if stats["vulns"] > 0 or stats["hosts"] > 0:
        emit_webhook_event("scan_summary", "nessus", {
            "job_id": job_id,
            "target": target,
            "scan_type": "nessus",
            "hosts": stats["hosts"],
            "ports": stats["ports"],
            "total_vulns": stats["vulns"],
            "by_severity": stats["by_severity"],
            "exploitable_count": stats["exploitable_count"],
            "exploitable_cves": stats["exploitable_cves"][:20],
            "critical_count": stats["by_severity"]["critical"],
            "high_count": stats["by_severity"]["high"],
        })

    return stats
