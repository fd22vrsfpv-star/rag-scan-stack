"""
parse_tool_output.py — Structure arbitrary tool stdout into findings.

Given raw stdout from a security tool execution, attempts to:
1. Detect JSON/JSONL output and parse structured data
2. Extract IPs, ports, URLs, CVEs, severity indicators
3. Route into the most appropriate findings table
4. Fall back to recon_findings with raw text in JSONB data
"""

import os
import re
import json
import uuid
import ipaddress
import logging
from typing import Optional

import psycopg2
from psycopg2.extras import RealDictCursor

log = logging.getLogger(__name__)

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r"\b(\d{1,5})/(tcp|udp)\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_SEVERITY_MAP = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "warning": "medium",
    "warn": "medium",
    "vulnerable": "high",
    "error": "info",
}
_SEVERITY_RE = re.compile(
    r"\b(" + "|".join(_SEVERITY_MAP.keys()) + r")\b", re.IGNORECASE
)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_KEY_VALUE_RE = re.compile(r"^([A-Za-z_][\w\s-]{0,30}):\s+(.+)$", re.MULTILINE)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("/")[0])
        return True
    except (ValueError, AttributeError):
        return False


def _resolve_asset_id(cur, target: str) -> Optional[str]:
    """Find asset_id by IP or hostname. Handles inet /32 storage."""
    if not target:
        return None
    if _is_ip(target):
        # Use host() to strip /32 mask for comparison
        cur.execute("SELECT id FROM assets WHERE host(ip)::text = %s", (target,))
    else:
        cur.execute("SELECT id FROM assets WHERE hostname = %s", (target,))
    row = cur.fetchone()
    if not row and _is_ip(target):
        # Create asset if it doesn't exist
        import uuid as _uuid
        asset_id = str(_uuid.uuid4())
        cur.execute(
            "INSERT INTO assets (id, ip) VALUES (%s, %s) ON CONFLICT (ip) DO UPDATE SET ip = EXCLUDED.ip RETURNING id",
            (asset_id, target),
        )
        row = cur.fetchone()
    return str(row["id"]) if row else None


def _detect_severity(text: str) -> str:
    """Extract the highest severity mentioned in text."""
    severity_order = ["critical", "high", "medium", "low", "info"]
    found = set()
    for m in _SEVERITY_RE.finditer(text):
        mapped = _SEVERITY_MAP.get(m.group(1).lower(), "info")
        found.add(mapped)
    for s in severity_order:
        if s in found:
            return s
    return "info"


def _try_parse_json(text: str):
    """Try to parse text as JSON object, JSON array, or JSONL."""
    text = text.strip()
    # Single JSON object or array
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
            return [data]
        except json.JSONDecodeError:
            pass
    # JSONL
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if records and len(records) >= len([l for l in text.splitlines() if l.strip()]) * 0.5:
        return records
    return None


def _extract_key_values(text: str) -> dict:
    """Extract key: value pairs from text output."""
    kv = {}
    for m in _KEY_VALUE_RE.finditer(text):
        key = m.group(1).strip().lower().replace(" ", "_").replace("-", "_")
        val = m.group(2).strip()
        if key and val and len(key) < 32:
            kv[key] = val
    return kv


def _extract_table_rows(text: str) -> list[dict]:
    """Try to parse tabular output (header + rows separated by whitespace)."""
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 3:
        return []
    # Look for a separator line (e.g. "----  -----  ------")
    sep_idx = None
    for i, line in enumerate(lines[:5]):
        if re.match(r"^[\s\-=+|]+$", line) and len(line) > 5:
            sep_idx = i
            break
    if sep_idx is not None and sep_idx > 0:
        header_line = lines[sep_idx - 1]
        data_lines = lines[sep_idx + 1:]
    else:
        # Try first line as header
        header_line = lines[0]
        data_lines = lines[1:]
    # Split header by 2+ spaces or tabs
    headers = re.split(r"\s{2,}|\t", header_line.strip())
    if len(headers) < 2 or len(headers) > 20:
        return []
    headers = [h.strip().lower().replace(" ", "_").replace("-", "_") for h in headers]
    rows = []
    for line in data_lines:
        cols = re.split(r"\s{2,}|\t", line.strip(), maxsplit=len(headers) - 1)
        if len(cols) >= len(headers) - 1:
            row = {}
            for i, h in enumerate(headers):
                row[h] = cols[i].strip() if i < len(cols) else ""
            rows.append(row)
    return rows if len(rows) >= 1 else []


# ---------------------------------------------------------------------------
# Tool-specific parsers — run before generic strategies
# ---------------------------------------------------------------------------
_SSH_AUDIT_LINE_RE = re.compile(
    r"^\((\w+)\)\s+(.+?)\s+--\s+\[(\w+)\]\s*(.*)$"
)
_SSH_AUDIT_GEN_RE = re.compile(
    r"^\(gen\)\s+(.+?):\s+(.+)$"
)
_SSH_AUDIT_SEVERITY = {"fail": "high", "warn": "medium", "info": "info"}
_SSH_AUDIT_CATEGORY = {
    "kex": "Key Exchange", "key": "Host Key", "enc": "Encryption",
    "mac": "MAC Algorithm", "gen": "General",
}


def _parse_ssh_audit(stdout: str, target: str, port: Optional[int],
                     asset_id: Optional[str], cur) -> Optional[dict]:
    """Parse ssh-audit output into individual findings per algorithm issue."""
    lines = stdout.strip().splitlines()
    # Detect ssh-audit output by looking for (gen) or (kex) markers
    markers = sum(1 for l in lines[:20] if l.strip().startswith("("))
    if markers < 3:
        return None

    findings = []
    banner = software = ""
    for line in lines:
        line = line.strip()
        # General info lines: (gen) banner: SSH-2.0-...
        gm = _SSH_AUDIT_GEN_RE.match(line)
        if gm:
            key, val = gm.group(1).strip(), gm.group(2).strip()
            if "banner" in key.lower():
                banner = val
            elif "software" in key.lower():
                software = val
            continue
        # Algorithm lines: (kex) name -- [severity] detail
        m = _SSH_AUDIT_LINE_RE.match(line)
        if m:
            category, algo, level, detail = m.groups()
            severity = _SSH_AUDIT_SEVERITY.get(level, "info")
            cat_label = _SSH_AUDIT_CATEGORY.get(category, category)
            findings.append({
                "category": cat_label,
                "algorithm": algo.strip(),
                "level": level,
                "severity": severity,
                "detail": detail.strip(),
            })

    if not findings:
        return None

    # Insert each warn/fail as a vuln finding, batch info as recon
    stats = {
        "records_seen": len(findings),
        "findings_inserted": 0,
        "vulns_inserted": 0,
        "web_findings_inserted": 0,
        "recon_findings_inserted": 0,
        "evidence_stored": 0,
        "parse_method": "ssh_audit",
        "finding_ids": [],
        "errors": [],
    }

    # Resolve or create port record
    port_id = None
    actual_port = port or 22
    if asset_id:
        try:
            cur.execute(
                "SELECT id FROM ports WHERE asset_id = %s AND port = %s AND proto = 'tcp'",
                (asset_id, actual_port))
            row = cur.fetchone()
            if row:
                port_id = str(row["id"])
            else:
                port_id = str(uuid.uuid4())
                cur.execute(
                    "INSERT INTO ports (id, asset_id, port, proto, is_open, service) "
                    "VALUES (%s, %s, %s, 'tcp', true, 'ssh') ON CONFLICT DO NOTHING",
                    (port_id, asset_id, actual_port))
        except Exception:
            pass

    # Group findings by severity for efficient storage
    issues = [f for f in findings if f["level"] in ("fail", "warn")]
    infos = [f for f in findings if f["level"] == "info"]

    for issue in issues:
        fid = str(uuid.uuid4())
        title = f"ssh-audit:{issue['category'].lower().replace(' ', '-')}-{issue['algorithm']}"
        evidence = f"{issue['category']}: {issue['algorithm']}\n{issue['detail']}"
        if banner:
            evidence += f"\nBanner: {banner}"
        if software:
            evidence += f"\nSoftware: {software}"
        try:
            cur.execute("SAVEPOINT ssh_audit_rec")
            cur.execute(
                """INSERT INTO vulns (id, asset_id, port_id, script, output, severity, metadata)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (fid, asset_id, port_id, title, evidence, issue["severity"],
                 json.dumps({
                     "source": title,
                     "tool": "ssh-audit",
                     "port": actual_port,
                     "category": issue["category"],
                     "algorithm": issue["algorithm"],
                     "level": issue["level"],
                     "software": software,
                     "banner": banner,
                 })),
            )
            cur.execute("RELEASE SAVEPOINT ssh_audit_rec")
            stats["finding_ids"].append(fid)
            stats["vulns_inserted"] += 1
            stats["findings_inserted"] += 1
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT ssh_audit_rec")
            if len(stats["errors"]) < 5:
                stats["errors"].append(str(e))

    # Store info-level as a single recon summary
    if infos:
        fid = str(uuid.uuid4())
        data = {
            "tool": "ssh-audit",
            "target": target,
            "port": port or 22,
            "banner": banner,
            "software": software,
            "algorithms": [{"category": f["category"], "algorithm": f["algorithm"],
                            "detail": f["detail"]} for f in infos],
            "issue_count": len(issues),
            "info_count": len(infos),
        }
        try:
            cur.execute("SAVEPOINT ssh_audit_info")
            cur.execute(
                """INSERT INTO recon_findings
                   (id, asset_id, source, finding_type, target, data, severity)
                   VALUES (%s, %s, 'ssh-audit', 'ssh_config', %s, %s, 'info')""",
                (fid, asset_id, target, json.dumps(data)),
            )
            cur.execute("RELEASE SAVEPOINT ssh_audit_info")
            stats["finding_ids"].append(fid)
            stats["recon_findings_inserted"] += 1
            stats["findings_inserted"] += 1
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT ssh_audit_info")

    return stats


def _parse_sslscan(stdout: str, target: str, port: Optional[int],
                    asset_id: Optional[str], cur) -> Optional[dict]:
    """Parse sslscan/testssl output into findings for weak ciphers/protocols."""
    lines = stdout.strip().splitlines()
    # Detect sslscan by characteristic markers
    is_sslscan = any("sslscan" in l.lower() or "SSL/TLS" in l for l in lines[:10])
    is_testssl = any("testssl" in l.lower() or "Testing protocols" in l for l in lines[:15])
    if not is_sslscan and not is_testssl:
        return None

    tool = "sslscan" if is_sslscan else "testssl"
    findings = []

    # Common patterns across sslscan/testssl
    weak_patterns = [
        (re.compile(r"(?i)(SSLv[23]|TLSv1\.0|TLSv1\.1)\s.*(enabled|accepted|offered)", re.I), "high", "Weak protocol"),
        (re.compile(r"(?i)(RC4|DES|3DES|NULL|EXPORT|anon)\s.*(accepted|enabled)", re.I), "high", "Weak cipher"),
        (re.compile(r"(?i)heartbleed.*vulnerable", re.I), "critical", "Heartbleed"),
        (re.compile(r"(?i)CRIME.*vulnerable", re.I), "high", "CRIME attack"),
        (re.compile(r"(?i)BEAST.*vulnerable", re.I), "medium", "BEAST attack"),
        (re.compile(r"(?i)POODLE.*vulnerable", re.I), "high", "POODLE attack"),
        (re.compile(r"(?i)LUCKY13.*vulnerable", re.I), "medium", "Lucky13"),
        (re.compile(r"(?i)certificate.*expired", re.I), "high", "Expired certificate"),
        (re.compile(r"(?i)self.signed", re.I), "medium", "Self-signed certificate"),
    ]

    for line in lines:
        for pattern, severity, label in weak_patterns:
            if pattern.search(line):
                findings.append({"title": f"{tool}:{label.lower().replace(' ', '-')}",
                                 "evidence": line.strip(), "severity": severity, "label": label})

    if not findings:
        return None

    stats = {
        "records_seen": len(findings),
        "findings_inserted": 0, "vulns_inserted": 0,
        "web_findings_inserted": 0, "recon_findings_inserted": 0,
        "evidence_stored": 0, "parse_method": tool,
        "finding_ids": [], "errors": [],
    }

    # Resolve or create port record for SSL
    ssl_port_id = None
    ssl_port = port or 443
    if asset_id:
        try:
            cur.execute(
                "SELECT id FROM ports WHERE asset_id = %s AND port = %s AND proto = 'tcp'",
                (asset_id, ssl_port))
            row = cur.fetchone()
            if row:
                ssl_port_id = str(row["id"])
            else:
                ssl_port_id = str(uuid.uuid4())
                cur.execute(
                    "INSERT INTO ports (id, asset_id, port, proto, is_open, service) "
                    "VALUES (%s, %s, %s, 'tcp', true, 'https') ON CONFLICT DO NOTHING",
                    (ssl_port_id, asset_id, ssl_port))
        except Exception:
            pass

    seen_titles = set()
    for f in findings:
        if f["title"] in seen_titles:
            continue
        seen_titles.add(f["title"])
        fid = str(uuid.uuid4())
        try:
            cur.execute("SAVEPOINT ssl_rec")
            cur.execute(
                """INSERT INTO vulns (id, asset_id, port_id, script, output, severity, metadata)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (fid, asset_id, ssl_port_id, f["title"], f["evidence"], f["severity"],
                 json.dumps({"source": f["title"], "tool": tool, "port": ssl_port})),
            )
            cur.execute("RELEASE SAVEPOINT ssl_rec")
            stats["finding_ids"].append(fid)
            stats["vulns_inserted"] += 1
            stats["findings_inserted"] += 1
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT ssl_rec")
    return stats


# Tool-specific parser dispatch — checked before generic strategies
_TOOL_PARSERS = {
    "ssh-audit": _parse_ssh_audit,
    "sslscan": _parse_sslscan,
    "testssl": _parse_sslscan,  # same format patterns
    "sslyze": _parse_sslscan,
}


# ---------------------------------------------------------------------------
# Main structuring function
# ---------------------------------------------------------------------------
def structure_tool_output(
    stdout: str,
    tool_name: str,
    target: str,
    port: Optional[int] = None,
    service: Optional[str] = None,
    job_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
) -> dict:
    """
    Parse raw stdout from a security tool and insert structured findings.

    Returns stats dict with counts + list of created finding IDs.
    """
    stats = {
        "records_seen": 0,
        "findings_inserted": 0,
        "vulns_inserted": 0,
        "web_findings_inserted": 0,
        "recon_findings_inserted": 0,
        "evidence_stored": 0,
        "parse_method": "unknown",
        "finding_ids": [],
        "errors": [],
    }

    if not stdout or not stdout.strip():
        stats["parse_method"] = "empty"
        return stats

    # Extract global indicators from full text
    all_cves = list(set(_CVE_RE.findall(stdout)))
    all_ips = list(set(_IP_RE.findall(stdout)))
    all_urls = list(set(_URL_RE.findall(stdout)))
    all_cwes = list(set(_CWE_RE.findall(stdout)))
    global_severity = _detect_severity(stdout)

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            asset_id = _resolve_asset_id(cur, target)

            # --- Strategy 0: Tool-specific parser ---
            parser = _TOOL_PARSERS.get(tool_name)
            if parser:
                result = parser(stdout, target, port, asset_id, cur)
                if result:
                    conn.commit()
                    return result

            # --- Strategy 1: JSON / JSONL output ---
            json_records = _try_parse_json(stdout)
            if json_records:
                stats["parse_method"] = "json"
                stats["records_seen"] = len(json_records)
                for rec in json_records:
                    try:
                        cur.execute("SAVEPOINT tool_rec")
                        fid = _insert_json_finding(
                            cur, rec, tool_name, target, port,
                            service, asset_id, job_id
                        )
                        cur.execute("RELEASE SAVEPOINT tool_rec")
                        if fid:
                            stats["finding_ids"].append(fid)
                            stats["findings_inserted"] += 1
                    except Exception as e:
                        cur.execute("ROLLBACK TO SAVEPOINT tool_rec")
                        if len(stats["errors"]) < 5:
                            stats["errors"].append(f"{type(e).__name__}: {e}")

                conn.commit()
                return stats

            # --- Strategy 2: Tabular output ---
            table_rows = _extract_table_rows(stdout)
            if table_rows and len(table_rows) >= 2:
                stats["parse_method"] = "table"
                stats["records_seen"] = len(table_rows)
                for row in table_rows:
                    try:
                        cur.execute("SAVEPOINT tool_rec")
                        fid = _insert_table_row_finding(
                            cur, row, tool_name, target, port,
                            service, asset_id, job_id
                        )
                        cur.execute("RELEASE SAVEPOINT tool_rec")
                        if fid:
                            stats["finding_ids"].append(fid)
                            stats["findings_inserted"] += 1
                    except Exception as e:
                        cur.execute("ROLLBACK TO SAVEPOINT tool_rec")
                        if len(stats["errors"]) < 5:
                            stats["errors"].append(f"{type(e).__name__}: {e}")
                conn.commit()
                return stats

            # --- Strategy 3: Key-value pairs ---
            kv_pairs = _extract_key_values(stdout)

            # --- Strategy 4: CVE-rich output → vulns table ---
            if all_cves:
                stats["parse_method"] = "cve_extraction"
                stats["records_seen"] = len(all_cves)
                fid = _insert_vuln_finding(
                    cur, tool_name, target, port, stdout,
                    all_cves, global_severity, asset_id, job_id
                )
                if fid:
                    stats["finding_ids"].append(fid)
                    stats["vulns_inserted"] += 1
                    stats["findings_inserted"] += 1
                conn.commit()
                return stats

            # --- Strategy 5: URL-rich output → web_findings ---
            if all_urls and len(all_urls) >= 2:
                stats["parse_method"] = "url_extraction"
                stats["records_seen"] = len(all_urls)
                for url in all_urls[:50]:  # cap at 50
                    try:
                        cur.execute("SAVEPOINT tool_rec")
                        fid = _insert_web_finding(
                            cur, tool_name, url, target,
                            global_severity, job_id
                        )
                        cur.execute("RELEASE SAVEPOINT tool_rec")
                        if fid:
                            stats["finding_ids"].append(fid)
                            stats["web_findings_inserted"] += 1
                            stats["findings_inserted"] += 1
                    except Exception as e:
                        cur.execute("ROLLBACK TO SAVEPOINT tool_rec")
                        if len(stats["errors"]) < 5:
                            stats["errors"].append(f"{type(e).__name__}: {e}")
                conn.commit()
                return stats

            # --- Strategy 6: Fallback → recon_findings with full text ---
            stats["parse_method"] = "raw_text"
            stats["records_seen"] = 1
            data = {
                "raw_output": stdout[:8000],
                "tool": tool_name,
                "target": target,
                "extracted_ips": all_ips[:20],
                "extracted_urls": all_urls[:20],
                "extracted_cves": all_cves[:20],
                "extracted_cwes": all_cwes[:10],
                "key_values": kv_pairs,
            }
            if port:
                data["port"] = port
            if service:
                data["service"] = service
            if job_id:
                data["job_id"] = job_id

            fid = str(uuid.uuid4())
            cur.execute(
                """INSERT INTO recon_findings
                   (id, asset_id, source, finding_type, target, data, severity)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (fid, asset_id, tool_name, "tool_output",
                 target, json.dumps(data), global_severity),
            )
            stats["finding_ids"].append(fid)
            stats["recon_findings_inserted"] += 1
            stats["findings_inserted"] += 1

            # Also store as evidence if engagement_id provided
            if engagement_id:
                eid = str(uuid.uuid4())
                cur.execute(
                    """INSERT INTO evidence_store
                       (id, engagement_id, evidence_type, title, content_text,
                        tags, uploaded_by, metadata)
                       VALUES (%s, %s, 'terminal_output', %s, %s, %s, %s, %s)""",
                    (eid, engagement_id,
                     f"{tool_name} output — {target}:{port or 'all'}",
                     stdout[:50000],
                     [tool_name, target],
                     "targeted-recon",
                     json.dumps({"tool": tool_name, "target": target,
                                 "port": port, "job_id": job_id})),
                )
                stats["evidence_stored"] += 1

            conn.commit()
            return stats

    except Exception as e:
        log.error("structure_tool_output failed: %s", e)
        stats["errors"].append(f"{type(e).__name__}: {e}")
        return stats
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Insertion helpers
# ---------------------------------------------------------------------------

def _insert_json_finding(cur, rec: dict, tool_name: str, target: str,
                         port: Optional[int], service: Optional[str],
                         asset_id: Optional[str], job_id: Optional[str]) -> Optional[str]:
    """Insert a single JSON record into the best-fit table."""
    # Try to detect the record type from common field patterns
    rec_target = (rec.get("host") or rec.get("ip") or rec.get("target")
                  or rec.get("hostname") or target)
    rec_url = rec.get("url") or rec.get("matched-at") or rec.get("endpoint")
    rec_cves = rec.get("cve") or rec.get("cves") or rec.get("vulnerabilities")
    rec_severity = rec.get("severity") or rec.get("risk") or rec.get("level")
    rec_name = (rec.get("name") or rec.get("title") or rec.get("template-id")
                or rec.get("info", {}).get("name") if isinstance(rec.get("info"), dict) else None
                or rec.get("check") or rec.get("plugin_name"))

    if isinstance(rec_severity, str):
        rec_severity = _SEVERITY_MAP.get(rec_severity.lower(), "info")
    else:
        rec_severity = "info"

    # CVE list normalization
    cve_list = []
    if isinstance(rec_cves, list):
        for c in rec_cves:
            if isinstance(c, str) and _CVE_RE.match(c):
                cve_list.append(c)
            elif isinstance(c, dict):
                cid = c.get("id") or c.get("cve_id") or c.get("cve")
                if cid and _CVE_RE.match(str(cid)):
                    cve_list.append(str(cid))
    elif isinstance(rec_cves, str):
        cve_list = _CVE_RE.findall(rec_cves)

    # Resolve asset
    if not asset_id and rec_target:
        asset_id = _resolve_asset_id(cur, rec_target)

    fid = str(uuid.uuid4())

    # Route: if has URL → web_findings; if has CVEs → vulns; else → recon_findings
    if rec_url:
        cur.execute(
            """INSERT INTO web_findings
               (id, asset_id, url, source, issue_type, name, severity, evidence,
                cwe, refs, fingerprint)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (fingerprint) DO UPDATE SET last_seen = now()
               RETURNING id""",
            (fid, asset_id, rec_url, tool_name, "tool_finding",
             rec_name or f"{tool_name} finding",
             rec_severity,
             json.dumps(rec, default=str)[:4000],
             _CWE_RE.findall(json.dumps(rec)) or None,
             json.dumps({"cves": cve_list}) if cve_list else "{}",
             _fingerprint(tool_name, rec_url, rec_name)),
        )
        row = cur.fetchone()
        return str(row["id"]) if row else fid

    if cve_list:
        # Need port_id for vulns table — try to find it
        port_id = None
        if asset_id and port:
            cur.execute(
                "SELECT id FROM ports WHERE asset_id = %s AND port_number = %s LIMIT 1",
                (asset_id, port),
            )
            prow = cur.fetchone()
            port_id = str(prow["id"]) if prow else None

        cur.execute(
            """INSERT INTO vulns
               (id, asset_id, port_id, script, output, severity, cve,
                metadata, fingerprint)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (fingerprint) DO UPDATE SET updated_at = now()
               RETURNING id""",
            (fid, asset_id, port_id,
             f"{tool_name}:{rec_name or 'finding'}",
             json.dumps(rec, default=str)[:4000],
             rec_severity, cve_list,
             json.dumps({"source": tool_name, "job_id": job_id, "port": port}),
             _fingerprint(tool_name, rec_target, str(cve_list))),
        )
        row = cur.fetchone()
        return str(row["id"]) if row else fid

    # Default: recon_findings
    data = dict(rec)
    if job_id:
        data["job_id"] = job_id
    cur.execute(
        """INSERT INTO recon_findings
           (id, asset_id, source, finding_type, target, data, severity, fingerprint)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (fingerprint) DO NOTHING""",
        (fid, asset_id, tool_name, "tool_finding",
         rec_target or target,
         json.dumps(data, default=str),
         rec_severity,
         _fingerprint(tool_name, rec_target, json.dumps(rec, default=str)[:200])),
    )
    return fid


def _insert_table_row_finding(cur, row: dict, tool_name: str, target: str,
                              port: Optional[int], service: Optional[str],
                              asset_id: Optional[str], job_id: Optional[str]) -> Optional[str]:
    """Insert a parsed table row as a recon_finding."""
    # Try to extract a target from the row
    row_target = (row.get("host") or row.get("ip") or row.get("target")
                  or row.get("address") or target)
    row_name = (row.get("name") or row.get("title") or row.get("service")
                or row.get("finding") or row.get("issue"))

    if not asset_id and row_target:
        asset_id = _resolve_asset_id(cur, row_target)

    severity = "info"
    for k, v in row.items():
        if isinstance(v, str):
            mapped = _SEVERITY_MAP.get(v.lower())
            if mapped:
                severity = mapped
                break

    data = dict(row)
    if job_id:
        data["job_id"] = job_id
    if port:
        data["port"] = port
    if service:
        data["service"] = service

    fid = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO recon_findings
           (id, asset_id, source, finding_type, target, data, severity, fingerprint)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (fingerprint) DO NOTHING""",
        (fid, asset_id, tool_name, "tool_table_row",
         row_target or target,
         json.dumps(data, default=str),
         severity,
         _fingerprint(tool_name, row_target, json.dumps(row, default=str)[:200])),
    )
    return fid


def _insert_vuln_finding(cur, tool_name: str, target: str, port: Optional[int],
                         stdout: str, cves: list, severity: str,
                         asset_id: Optional[str], job_id: Optional[str]) -> Optional[str]:
    """Insert CVE-bearing output as a vuln."""
    port_id = None
    if asset_id and port:
        cur.execute(
            "SELECT id FROM ports WHERE asset_id = %s AND port_number = %s LIMIT 1",
            (asset_id, port),
        )
        prow = cur.fetchone()
        port_id = str(prow["id"]) if prow else None

    fid = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO vulns
           (id, asset_id, port_id, script, output, severity, cve,
            metadata, fingerprint)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (fingerprint) DO UPDATE SET updated_at = now()
           RETURNING id""",
        (fid, asset_id, port_id,
         f"{tool_name}:targeted-recon",
         stdout[:4000],
         severity, cves[:10],
         json.dumps({"source": tool_name, "job_id": job_id, "port": port}),
         _fingerprint(tool_name, target, str(cves[:3]))),
    )
    row = cur.fetchone()
    return str(row["id"]) if row else fid


def _insert_web_finding(cur, tool_name: str, url: str, target: str,
                        severity: str, job_id: Optional[str]) -> Optional[str]:
    """Insert a discovered URL as a web_finding."""
    fid = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO web_findings
           (id, url, source, issue_type, name, severity, evidence, fingerprint)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (fingerprint) DO UPDATE SET last_seen = now()
           RETURNING id""",
        (fid, url, tool_name, "discovered_url",
         f"URL discovered by {tool_name}",
         "info",
         f"Found during targeted recon of {target}",
         _fingerprint(tool_name, url, "discovered_url")),
    )
    row = cur.fetchone()
    return str(row["id"]) if row else fid


def _fingerprint(*parts) -> str:
    import hashlib
    return hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()
