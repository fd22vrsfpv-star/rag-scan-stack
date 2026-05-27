import os
import re
import uuid
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Any

import psycopg2
import requests
from psycopg2.extras import RealDictCursor, Json

from etl.fingerprint import vuln_fingerprint

# Configure logging - integrate with nmap_scanner's log_manager if available
logger = logging.getLogger("parse_nmap")
logger.setLevel(logging.INFO)

# Try to get the CircularLogHandler from log_manager (when running inside nmap_scanner)
try:
    from log_manager import get_log_handler
    circular_handler = get_log_handler()
    if circular_handler not in logger.handlers:
        logger.addHandler(circular_handler)
        logger.info("[parse_nmap] Attached to CircularLogHandler for web UI logging")
except ImportError:
    # Running standalone - add console handler if none exists
    if not logger.handlers and not logger.parent.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
        logger.addHandler(handler)

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
    """Search for exploits matching a CVE ID."""
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
                "exploitdb": exploitdb[:5],
                "metasploit": metasploit[:5]
            }
    except Exception as e:
        logger.warning(f"Failed to search exploits for {cve}: {e}")
    return {"found": False, "exploitdb_count": 0, "metasploit_count": 0, "exploitdb": [], "metasploit": []}


# Vulnerability script patterns - scripts that produce vuln findings
VULN_SCRIPT_PATTERNS = [
    'vuln', 'vulscan', 'vulners', 'exploit', 'cve-',
    'ssl-heartbleed', 'ssl-poodle', 'ssl-drown', 'ssl-ccs-injection',
    'smb-vuln', 'http-vuln', 'ftp-vuln', 'rmi-vuln', 'rdp-vuln',
    'ms08-067', 'ms17-010', 'eternalblue'
]

def is_vuln_script(script_id: str) -> bool:
    """Check if a script is a vulnerability detection script"""
    script_lower = script_id.lower()
    return any(pattern in script_lower for pattern in VULN_SCRIPT_PATTERNS)

def extract_cves(text: str) -> List[str]:
    """Extract CVE IDs from text"""
    if not text:
        return []
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))

def extract_cvss(text: str) -> Optional[float]:
    """Extract CVSS score from text"""
    if not text:
        return None
    # Match patterns like "CVSS: 9.8" or "cvss=7.5" or "score: 8.1"
    patterns = [
        r'CVSS[:\s=]+(\d+\.?\d*)',
        r'score[:\s=]+(\d+\.?\d*)',
        r'\b(\d+\.\d)\s*/\s*10\b'
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            try:
                score = float(match.group(1))
                if 0 <= score <= 10:
                    return score
            except ValueError:
                pass
    return None

def determine_severity(cvss: Optional[float], output: str) -> str:
    """Determine severity from CVSS or keywords"""
    if cvss is not None:
        if cvss >= 9.0:
            return 'critical'
        elif cvss >= 7.0:
            return 'high'
        elif cvss >= 4.0:
            return 'medium'
        elif cvss > 0:
            return 'low'

    # Fallback to keyword detection — use word boundaries to avoid
    # matching URL fragments like "Exploit-DB" or header text
    output_lower = output.lower()
    if re.search(r'\b(critical|remote code execution|rce|unauthenticated)\b', output_lower):
        return 'critical'
    elif re.search(r'\b(high|vulnerable|backdoor)\b', output_lower):
        return 'high'
    elif re.search(r'\b(medium|moderate|warning)\b', output_lower):
        return 'medium'
    elif re.search(r'\b(low|informational)\b', output_lower):
        return 'low'
    return 'info'

def parse_nmap(path: str, profile: str = "upload", job_id: str = None, target: str = None) -> Dict[str, Any]:
    """
    Parse nmap XML output and insert into database.

    Args:
        path: Path to nmap XML file
        profile: Profile name (for logging)
        job_id: Job ID for webhook correlation
        target: Target description for webhook context

    Returns stats about what was parsed and inserted.
    """
    logger.info(f"=" * 60)
    logger.info(f"PARSING NMAP XML: {path}")
    logger.info(f"Profile: {profile}, Job: {job_id}, Target: {target}")
    logger.info(f"=" * 60)

    stats = {
        "file": path,
        "profile": profile,
        "job_id": job_id,
        "target": target,
        "hosts": 0,
        "ports": 0,
        "services": 0,
        "vulns": 0,
        "scripts": 0,
        "errors": [],
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "exploitable_count": 0,
        "exploitable_cves": []
    }

    # Log raw file contents first
    try:
        with open(path, 'r') as f:
            raw_content = f.read()
        file_size = len(raw_content)
        logger.info(f"\n{'━' * 60}")
        logger.info(f"RAW XML FILE ({file_size} bytes):")
        logger.info(f"{'━' * 60}")
        # Log first 5000 chars of raw XML
        if file_size > 5000:
            logger.info(raw_content[:5000])
            logger.info(f"... [{file_size - 5000} more bytes truncated]")
        else:
            logger.info(raw_content)
        logger.info(f"{'━' * 60}\n")
    except Exception as e:
        logger.warning(f"Could not read raw file: {e}")

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML: {e}")
        stats["errors"].append(f"XML parse error: {e}")
        return stats

    # Log scan info
    scan_info = root.find('scaninfo')
    if scan_info is not None:
        logger.info(f"Scan type: {scan_info.get('type')}, protocol: {scan_info.get('protocol')}")

    run_stats = root.find('runstats')
    if run_stats is not None:
        finished = run_stats.find('finished')
        hosts_elem = run_stats.find('hosts')
        if finished is not None:
            logger.info(f"Scan finished: {finished.get('timestr')}, elapsed: {finished.get('elapsed')}s")
        if hosts_elem is not None:
            logger.info(f"Hosts - up: {hosts_elem.get('up')}, down: {hosts_elem.get('down')}, total: {hosts_elem.get('total')}")

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for host in root.findall('host'):
                st = host.find('status')
                if st is not None and st.get('state') == 'down':
                    continue

                # Get IP address
                ip = None
                for addr in host.findall('address'):
                    if addr.get('addrtype') in ('ipv4', 'ipv6'):
                        ip = addr.get('addr')
                        break
                if not ip:
                    continue

                # Extract hostname from nmap XML
                hostname = None
                hostnames_node = host.find('hostnames')
                if hostnames_node is not None:
                    for hn in hostnames_node.findall('hostname'):
                        name = hn.get('name')
                        if name:
                            hostname = name
                            break  # Use first hostname

                stats["hosts"] += 1
                logger.info(f"\n{'─' * 50}")
                logger.info(f"HOST: {ip}" + (f" ({hostname})" if hostname else ""))
                logger.info(f"{'─' * 50}")

                # Get or create asset
                cur.execute("SELECT id FROM assets WHERE ip=%s", (ip,))
                row = cur.fetchone()
                if row:
                    asset_id = str(row["id"])
                    if hostname:
                        cur.execute("UPDATE assets SET hostname=COALESCE(hostname,%s), last_seen=now() WHERE id=%s", (hostname, asset_id))
                    else:
                        cur.execute("UPDATE assets SET last_seen=now() WHERE id=%s", (asset_id,))
                    logger.info(f"  [asset] Updated existing: {asset_id[:8]}...")
                else:
                    asset_id = str(uuid.uuid4())
                    cur.execute("INSERT INTO assets (id, ip, hostname) VALUES (%s,%s,%s)", (asset_id, ip, hostname))
                    logger.info(f"  [asset] Created new: {asset_id[:8]}...")

                # Process ports
                ports_node = host.find('ports')
                if ports_node is None:
                    logger.info(f"  [ports] No ports found")
                    continue

                for p in ports_node.findall('port'):
                    proto = p.get('protocol') or 'tcp'
                    port = int(p.get('portid'))
                    state = p.find('state')
                    state_str = state.get('state') if state is not None else 'unknown'
                    is_open = state_str in ('open', 'open|filtered')

                    # Service detection
                    svc = p.find('service')
                    svc_name = svc.get('name') if svc is not None else None
                    product = svc.get('product') if svc is not None else None
                    version = svc.get('version') if svc is not None else None
                    extrainfo = svc.get('extrainfo') if svc is not None else None

                    # Log port info
                    svc_str = f"{svc_name or 'unknown'}"
                    if product:
                        svc_str += f" ({product}"
                        if version:
                            svc_str += f" {version}"
                        svc_str += ")"

                    logger.info(f"  [{proto}/{port}] {state_str} - {svc_str}")
                    stats["ports"] += 1
                    if svc_name:
                        stats["services"] += 1

                    # Process all scripts
                    banner_text = None
                    port_vulns = []

                    for sc in p.findall('script'):
                        script_id = sc.get('id') or ''
                        script_output = sc.get('output') or ''
                        stats["scripts"] += 1

                        # Extract banner
                        if script_id in ('banner', 'http-title'):
                            banner_text = script_output
                            logger.info(f"    [script] {script_id}: {script_output[:100]}{'...' if len(script_output) > 100 else ''}")

                        # Check for vulnerability scripts
                        elif is_vuln_script(script_id):
                            # Skip vulscan results that found nothing across all databases
                            if script_id == 'vulscan':
                                # Strip out the database headers and check if anything remains
                                stripped = re.sub(r'(?i)(VulDB|MITRE CVE|SecurityFocus|IBM X-Force|Exploit-DB|OpenVAS|SecurityTracker|OSVDB)\s*-\s*https?://[^\n]*', '', script_output)
                                stripped = re.sub(r'(?i)no findings', '', stripped).strip()
                                if not stripped:
                                    logger.info(f"    [SKIP] {script_id}: no actual findings")
                                    stats["scripts"] += 0  # already counted
                                    continue

                            cves = extract_cves(script_output)
                            cvss = extract_cvss(script_output)
                            severity = determine_severity(cvss, script_output)

                            logger.info(f"    [VULN] {script_id}")
                            logger.info(f"           Severity: {severity}, CVSS: {cvss}, CVEs: {cves}")
                            logger.info(f"           Output: {script_output[:200]}{'...' if len(script_output) > 200 else ''}")

                            port_vulns.append({
                                "script": script_id,
                                "output": script_output,
                                "severity": severity,
                                "cves": cves,
                                "cvss": cvss
                            })
                        else:
                            # Log other scripts briefly
                            logger.debug(f"    [script] {script_id}: {script_output[:80]}...")

                    # Upsert port - log raw data first
                    port_data = {
                        "ip": ip,
                        "proto": proto,
                        "port": port,
                        "is_open": is_open,
                        "service": svc_name,
                        "product": product,
                        "version": version or extrainfo,
                        "banner": banner_text[:200] if banner_text else None
                    }
                    logger.info(f"    [RAW PORT DATA] {json.dumps(port_data, indent=6)}")

                    cur.execute("SELECT id FROM ports WHERE asset_id=%s AND proto=%s AND port=%s", (asset_id, proto, port))
                    prow = cur.fetchone()
                    if prow:
                        port_id = str(prow["id"])
                        cur.execute("""
                            UPDATE ports
                            SET is_open=%s,
                                service=COALESCE(%s, service),
                                product=COALESCE(%s, product),
                                version=COALESCE(%s, version),
                                banner=COALESCE(%s, banner),
                                updated_at=now()
                            WHERE id=%s
                        """, (is_open, svc_name, product, version or extrainfo, banner_text, port_id))
                        logger.info(f"    [DB] Updated port: {port_id[:8]}...")
                    else:
                        port_id = str(uuid.uuid4())
                        cur.execute("""
                            INSERT INTO ports
                              (id, asset_id, proto, port, service, product, version, banner, is_open)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """, (port_id, asset_id, proto, port, svc_name, product, version or extrainfo, banner_text, is_open))
                        logger.info(f"    [DB] Inserted port: {port_id[:8]}...")

                    # Insert vulnerabilities - log raw data first
                    for vuln in port_vulns:
                        vuln_id = str(uuid.uuid4())
                        vuln_data = {
                            "ip": ip,
                            "port": port,
                            "script": vuln["script"],
                            "severity": vuln["severity"],
                            "cvss": vuln["cvss"],
                            "cves": vuln["cves"],
                            "output_preview": vuln["output"][:500] if vuln["output"] else None
                        }
                        logger.info(f"    [RAW VULN DATA] {json.dumps(vuln_data, indent=6)}")

                        fp = vuln_fingerprint(
                            ip=ip, port=port,
                            script=vuln["script"],
                            cves=vuln["cves"],
                        )
                        try:
                            cur.execute("SAVEPOINT vuln_sp")
                            cur.execute("""
                                INSERT INTO vulns
                                  (id, asset_id, port_id, script, output, severity, cve, cvss, metadata, fingerprint)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """, (
                                vuln_id,
                                asset_id,
                                port_id,
                                vuln["script"],
                                vuln["output"],
                                vuln["severity"],
                                vuln["cves"] if vuln["cves"] else None,
                                vuln["cvss"],
                                Json({"source": "nmap", "profile": profile, "port": port}),
                                fp,
                            ))
                            stats["vulns"] += 1
                            logger.info(f"    [DB] Inserted vuln: {vuln_id[:8]}... ({vuln['script']})")

                            # Track severity
                            if vuln["severity"] in stats["by_severity"]:
                                stats["by_severity"][vuln["severity"]] += 1

                            # Check for exploits if CVEs exist
                            if vuln["cves"]:
                                for cve in vuln["cves"]:
                                    exploit_info = search_exploits_for_cve(cve)
                                    if exploit_info.get("found"):
                                        stats["exploitable_count"] += 1
                                        stats["exploitable_cves"].append({
                                            "cve": cve,
                                            "severity": vuln["severity"],
                                            "ip": ip,
                                            "port": port,
                                            "exploitdb_count": exploit_info["exploitdb_count"],
                                            "metasploit_count": exploit_info["metasploit_count"]
                                        })

                                        # Emit real-time webhook for exploitable finding
                                        emit_webhook_event("finding_exploitable", "nmap", {
                                            "job_id": job_id,
                                            "cve": cve,
                                            "severity": vuln["severity"],
                                            "script": vuln["script"],
                                            "ip": ip,
                                            "port": port,
                                            "exploit_count": exploit_info["exploitdb_count"] + exploit_info["metasploit_count"],
                                            "exploitdb_count": exploit_info["exploitdb_count"],
                                            "metasploit_count": exploit_info["metasploit_count"],
                                            "top_exploits": {
                                                "exploitdb": [{"id": e.get("edb_id"), "title": e.get("title")} for e in exploit_info["exploitdb"][:3]],
                                                "metasploit": [{"module": m.get("module_path"), "rank": m.get("rank")} for m in exploit_info["metasploit"][:3]]
                                            }
                                        }, severity=vuln["severity"])

                            # Emit webhook for high/critical findings
                            if vuln["severity"] in ("high", "critical"):
                                emit_webhook_event(f"finding_{vuln['severity']}", "nmap", {
                                    "job_id": job_id,
                                    "script": vuln["script"],
                                    "ip": ip,
                                    "port": port,
                                    "cves": vuln["cves"],
                                    "cvss": vuln["cvss"]
                                }, severity=vuln["severity"])

                            cur.execute("RELEASE SAVEPOINT vuln_sp")
                        except Exception as e:
                            cur.execute("ROLLBACK TO SAVEPOINT vuln_sp")
                            logger.error(f"    [DB] Failed to insert vuln: {e}")
                            stats["errors"].append(f"Vuln insert error: {e}")

            conn.commit()

    except Exception as e:
        logger.error(f"Database error: {e}")
        stats["errors"].append(f"DB error: {e}")
        conn.rollback()
    finally:
        conn.close()

    # Final summary
    logger.info(f"\n{'=' * 60}")
    logger.info(f"PARSE COMPLETE: {path}")
    logger.info(f"  Hosts: {stats['hosts']}")
    logger.info(f"  Ports: {stats['ports']}")
    logger.info(f"  Services: {stats['services']}")
    logger.info(f"  Scripts: {stats['scripts']}")
    logger.info(f"  Vulnerabilities: {stats['vulns']}")
    logger.info(f"  Exploitable: {stats['exploitable_count']}")
    if stats["errors"]:
        logger.warning(f"  Errors: {len(stats['errors'])}")
    logger.info(f"{'=' * 60}\n")

    # Emit scan summary webhook
    if stats["vulns"] > 0 or stats["hosts"] > 0:
        emit_webhook_event("scan_summary", "nmap", {
            "job_id": job_id,
            "target": target,
            "scan_type": "nmap",
            "hosts": stats["hosts"],
            "ports": stats["ports"],
            "services": stats["services"],
            "total_vulns": stats["vulns"],
            "by_severity": stats["by_severity"],
            "exploitable_count": stats["exploitable_count"],
            "exploitable_cves": stats["exploitable_cves"][:20],
            "critical_count": stats["by_severity"]["critical"],
            "high_count": stats["by_severity"]["high"]
        })

    return stats
