"""
Report Generator Module - Aggregates scan results into structured reports.

This module provides functions for:
- Aggregating tool execution statistics
- Extracting vulnerabilities by severity
- Generating full security scan reports
- Integrating with RAG for exploit correlation
"""

import os
import re
import json
import httpx
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

import psycopg2
from psycopg2.extras import RealDictCursor

# Configuration
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
RAG_SERVICE_URL = os.environ.get("RAG_SERVICE_URL", "https://scan-recommender:8013")

# Severity levels in order
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

# Keywords that indicate different severity levels in tool output
SEVERITY_KEYWORDS = {
    "critical": [
        "backdoor", "rce", "remote code execution", "unauthenticated",
        "root access", "CVE-2011-2523",  # vsftpd backdoor
        "ms08-067", "ms17-010", "eternalblue",
        "command injection", "arbitrary code"
    ],
    "high": [
        "authenticated", "arbitrary file", "sql injection", "sqli",
        "password disclosure", "credential", "weak password",
        "default password", "anonymous login", "CVE-",
        "vulnerable", "exploit"
    ],
    "medium": [
        "weak cipher", "weak algorithm", "outdated", "deprecated",
        "misconfiguration", "information disclosure", "directory listing",
        "version disclosure", "obsolete"
    ],
    "low": [
        "missing header", "cookie without", "clickjacking",
        "x-frame-options", "hsts", "content-type-options"
    ],
    "info": [
        "open port", "service", "version", "banner", "detected",
        "fingerprint", "enumeration"
    ]
}


def get_db_connection():
    """Get database connection."""
    return psycopg2.connect(DB_DSN)


def classify_severity(output: str, parsed_results: Optional[Dict]) -> str:
    """Classify the severity of a finding based on output content."""
    output_lower = output.lower() if output else ""

    # Check parsed results first for vulnerability indicators
    if parsed_results:
        vulns = parsed_results.get("vulnerabilities", [])
        creds = parsed_results.get("credentials_found", [])

        if creds:
            return "critical"

        for vuln in vulns:
            vuln_lower = str(vuln).lower()
            if any(kw in vuln_lower for kw in SEVERITY_KEYWORDS["critical"]):
                return "critical"
            if any(kw in vuln_lower for kw in SEVERITY_KEYWORDS["high"]):
                return "high"

    # Check output for severity keywords
    for severity in SEVERITY_LEVELS:
        for keyword in SEVERITY_KEYWORDS[severity]:
            if keyword.lower() in output_lower:
                return severity

    return "info"


def extract_cves(output: str) -> List[str]:
    """Extract CVE identifiers from output."""
    if not output:
        return []
    pattern = r'CVE-\d{4}-\d{4,7}'
    return list(set(re.findall(pattern, output, re.IGNORECASE)))


def extract_title_from_output(tool: str, output: str, parsed_results: Optional[Dict]) -> str:
    """Generate a descriptive title for a finding."""
    if not output:
        return f"{tool} scan result"

    # Check for specific vulnerability patterns
    output_lower = output.lower()

    if "vsftpd" in output_lower and "backdoor" in output_lower:
        return "vsftpd 2.3.4 Backdoor Vulnerability"

    if parsed_results:
        # Credentials found
        creds = parsed_results.get("credentials_found", [])
        if creds:
            return f"Credentials Found via {tool}"

        # Weak algorithms
        weak = parsed_results.get("weak_algorithms", [])
        if weak:
            return f"Weak Cryptographic Algorithms ({tool})"

        # Vulnerabilities
        vulns = parsed_results.get("vulnerabilities", [])
        if vulns:
            # Try to extract a meaningful name
            first_vuln = str(vulns[0])[:50]
            return f"Vulnerability: {first_vuln}"

    # Extract CVE if present
    cves = extract_cves(output)
    if cves:
        return f"{cves[0]} Vulnerability"

    # Generic titles based on tool
    tool_titles = {
        "nmap": "Port Scan Results",
        "nikto": "Web Vulnerability Scan",
        "hydra": "Brute Force Results",
        "enum4linux": "SMB Enumeration Results",
        "ssh-audit": "SSH Configuration Audit",
        "whatweb": "Web Technology Fingerprint"
    }

    return tool_titles.get(tool.lower(), f"{tool} Scan Results")


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from text."""
    if not text:
        return text
    # Standard ANSI escape sequences
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    # Handle partial/corrupted ANSI codes (e.g., leftover "0m", "32m", etc.)
    text = re.sub(r'(?<![a-zA-Z0-9])\d{1,3}m(?=[:\s]|$)', '', text)
    # Clean up any double colons or leading colons from the cleanup
    text = re.sub(r'^:\s*', '', text)
    text = re.sub(r'::\s*', ': ', text)
    return text.strip()


def summarize_tool_output(tool: str, output: str, parsed: Dict) -> List[str]:
    """Extract key findings from tool output as bullet points."""
    findings = []
    output_lower = output.lower() if output else ""

    if tool.lower() == "nmap":
        # Count open ports
        services = parsed.get("services", [])
        open_ports = parsed.get("open_ports", [])
        if services:
            findings.append(f"Found {len(services)} open port(s)")
            for svc in services[:5]:  # Show first 5
                ver = f" ({svc.get('version')})" if svc.get('version') else ""
                findings.append(f"  - {svc.get('port')}/{svc.get('protocol')}: {svc.get('service')}{ver}")
            if len(services) > 5:
                findings.append(f"  - ... and {len(services) - 5} more")
        if parsed.get("vulnerabilities"):
            findings.append(f"Vulnerabilities detected: {len(parsed['vulnerabilities'])}")
        if parsed.get("os_detection"):
            findings.append(f"OS: {parsed['os_detection']}")

    elif tool.lower() == "smbclient":
        if "anonymous login successful" in output_lower:
            findings.append("Anonymous login ALLOWED")
        # Extract shares
        shares = []
        for line in output.split('\n'):
            if 'Disk' in line and 'Sharename' not in line:
                parts = line.split()
                if parts:
                    shares.append(parts[0].strip())
        if shares:
            findings.append(f"Shares found: {', '.join(shares)}")

    elif tool.lower() == "whatweb":
        techs = parsed.get("technologies", [])
        if techs:
            findings.append(f"Technologies detected: {len(techs)}")
            for tech in techs[:5]:
                name = strip_ansi(str(tech.get('name', '')))
                version = strip_ansi(str(tech.get('version', 'unknown')))
                # Handle corrupted data where name is empty/ANSI remnant and version has real info
                if not name or name in ['0m', '1m', '32m', '31m', '33m']:
                    # Version field likely contains the actual info
                    if version and version != 'unknown':
                        findings.append(f"  - {version}")
                else:
                    findings.append(f"  - {name}: {version}")
        if parsed.get("server"):
            findings.append(f"Server: {strip_ansi(parsed['server'])}")
        if parsed.get("cms"):
            findings.append(f"CMS: {strip_ansi(parsed['cms'])}")

    elif tool.lower() == "hydra":
        creds = parsed.get("credentials_found", [])
        if creds:
            findings.append(f"CREDENTIALS FOUND: {len(creds)}")
            for cred in creds[:3]:
                findings.append(f"  - {cred.get('username')}:{cred.get('password')} ({cred.get('service')})")
        else:
            findings.append("No credentials found")

    elif tool.lower() == "nikto":
        vulns = parsed.get("vulnerabilities", [])
        items = parsed.get("findings", [])
        if vulns:
            findings.append(f"Vulnerabilities: {len(vulns)}")
        if items:
            findings.append(f"Findings: {len(items)}")
        if parsed.get("server"):
            findings.append(f"Server: {parsed['server']}")

    elif tool.lower() == "enum4linux":
        if parsed.get("domain"):
            findings.append(f"Domain: {parsed['domain']}")
        users = parsed.get("users", [])
        if users:
            findings.append(f"Users found: {', '.join(users[:5])}")
        shares = parsed.get("shares", [])
        if shares:
            findings.append(f"Shares: {', '.join(shares)}")

    elif tool.lower() == "ssh-audit":
        weak = parsed.get("weak_algorithms", [])
        vulns = parsed.get("vulnerabilities", [])
        if weak:
            findings.append(f"Weak algorithms: {len(weak)}")
        if vulns:
            findings.append(f"Vulnerabilities: {len(vulns)}")
        if parsed.get("ssh_version"):
            findings.append(f"SSH: {parsed['ssh_version']}")

    # Generic fallback - extract CVEs and key indicators
    if not findings:
        cves = extract_cves(output)
        if cves:
            findings.append(f"CVEs found: {', '.join(cves[:3])}")
        if "vulnerable" in output_lower:
            findings.append("Potential vulnerabilities detected")
        if "success" in output_lower:
            findings.append("Scan completed successfully")
        if not findings:
            findings.append("Scan completed - check raw output for details")

    return findings


def db_get_tool_results(
    target: Optional[str] = None,
    include_raw: bool = False,
    status_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Get detailed results for each tool execution.

    Args:
        target: Optional target IP/hostname to filter by
        include_raw: If True, include raw_output and error_output in results
        status_filter: Optional status to filter by (completed/failed/timeout)

    Returns:
        List of tool results with findings summaries.
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where_parts = []
            params = []

            if status_filter:
                where_parts.append("status = %s")
                params.append(status_filter)

            if target:
                where_parts.append("target = %s")
                params.append(target)

            where_clause = "WHERE " + " AND ".join(where_parts) if where_parts else ""

            cur.execute(f"""
                SELECT
                    id, tool, command, target, port, service,
                    status, exit_code, output, error, parsed_results,
                    started_at, completed_at,
                    EXTRACT(EPOCH FROM (completed_at - started_at)) as duration
                FROM tool_executions
                {where_clause}
                ORDER BY started_at DESC
            """, params)
            executions = cur.fetchall()

            results = []
            for ex in executions:
                parsed = ex.get("parsed_results") or {}
                output = ex.get("output") or ""
                severity = classify_severity(output, parsed)
                cves = extract_cves(output)

                # Generate findings summary
                findings = summarize_tool_output(ex["tool"], output, parsed)

                result = {
                    "id": str(ex["id"]),
                    "tool": ex["tool"],
                    "command": ex["command"],
                    "target": ex["target"],
                    "port": ex.get("port"),
                    "service": ex.get("service"),
                    "severity": severity,
                    "cves": cves,
                    "findings": findings,
                    "started_at": ex["started_at"].isoformat() if ex.get("started_at") else None,
                    "completed_at": ex["completed_at"].isoformat() if ex.get("completed_at") else None,
                    "duration": round(ex.get("duration") or 0, 2),
                    "status": ex.get("status") or "completed",
                    "exit_code": ex.get("exit_code"),
                }

                # Include raw output only when requested
                if include_raw:
                    result["raw_output"] = output
                    result["error_output"] = ex.get("error")

                results.append(result)

            return results
    finally:
        conn.close()


def db_get_report_summary(target: Optional[str] = None) -> Dict[str, Any]:
    """
    Aggregate tool executions and findings for a target.

    Returns:
        Dictionary with tools_summary, ports_discovered, findings_by_severity, etc.
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Build WHERE clause
            where_clause = "WHERE 1=1"
            params = []
            if target:
                where_clause += " AND target = %s"
                params.append(target)

            # Get tool execution summary with findings
            cur.execute(f"""
                SELECT
                    tool,
                    COUNT(*) as executions,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN status IN ('failed', 'timeout') THEN 1 ELSE 0 END) as failed,
                    AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) as avg_duration
                FROM tool_executions
                {where_clause}
                GROUP BY tool
                ORDER BY executions DESC
            """, params)
            tools_stats = cur.fetchall()

            # Get scan time range
            cur.execute(f"""
                SELECT
                    MIN(started_at) as scan_started,
                    MAX(completed_at) as scan_ended
                FROM tool_executions
                {where_clause}
            """, params)
            time_range = cur.fetchone()

            # Get all completed executions for detailed analysis
            cur.execute(f"""
                SELECT
                    id, tool, output, parsed_results, target, port
                FROM tool_executions
                {where_clause}
                AND status = 'completed'
                ORDER BY started_at DESC
            """, params)
            executions = cur.fetchall()

            # Aggregate ports discovered and per-tool findings
            ports_map = {}
            findings_by_severity = {s: 0 for s in SEVERITY_LEVELS}
            tool_findings = {}  # tool -> list of key findings

            for ex in executions:
                parsed = ex.get("parsed_results") or {}
                output = ex.get("output") or ""
                tool = ex.get("tool")

                # Extract ports from parsed results
                services = parsed.get("services", [])
                for svc in services:
                    port = svc.get("port")
                    if port:
                        if port not in ports_map:
                            ports_map[port] = {
                                "port": port,
                                "protocol": svc.get("protocol", "tcp"),
                                "service": svc.get("service", "unknown"),
                                "version": svc.get("version"),
                                "findings_count": 0
                            }

                # Classify severity and count findings
                severity = classify_severity(output, parsed)
                if severity != "info" or parsed.get("vulnerabilities") or parsed.get("credentials_found"):
                    findings_by_severity[severity] += 1

                    # Count finding against port if we can determine it
                    port = ex.get("port") or (services[0].get("port") if services else None)
                    if port and port in ports_map:
                        ports_map[port]["findings_count"] += 1

                # Collect per-tool findings
                if tool not in tool_findings:
                    tool_findings[tool] = []
                findings = summarize_tool_output(tool, output, parsed)
                tool_findings[tool].extend(findings)

            # Build enhanced tools_summary
            tools_summary = []
            for t in tools_stats:
                tool_name = t["tool"]
                # Get unique findings for this tool (deduplicate)
                unique_findings = list(dict.fromkeys(tool_findings.get(tool_name, [])))[:10]

                tools_summary.append({
                    "tool": tool_name,
                    "executions": t["executions"],
                    "successful": t["successful"] or 0,
                    "failed": t["failed"] or 0,
                    "avg_duration": round(t["avg_duration"] or 0, 2),
                    "findings": unique_findings
                })

            return {
                "target": target,
                "scan_period": {
                    "started": time_range["scan_started"].isoformat() if time_range.get("scan_started") else None,
                    "ended": time_range["scan_ended"].isoformat() if time_range.get("scan_ended") else None
                },
                "tools_summary": tools_summary,
                "ports_discovered": list(ports_map.values()),
                "findings_by_severity": findings_by_severity
            }
    finally:
        conn.close()


def db_get_vulnerabilities_by_severity(
    target: Optional[str] = None,
    severity_filter: Optional[str] = None,
    tool_filter: Optional[str] = None
) -> Dict[str, List[Dict]]:
    """
    Get all vulnerabilities grouped by severity.

    Returns:
        Dictionary with critical, high, medium, low, info lists
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Build WHERE clause
            where_parts = ["status = 'completed'"]
            params = []

            if target:
                where_parts.append("target = %s")
                params.append(target)
            if tool_filter:
                where_parts.append("tool = %s")
                params.append(tool_filter)

            where_clause = "WHERE " + " AND ".join(where_parts)

            cur.execute(f"""
                SELECT
                    id, tool, command, target, port, service,
                    output, parsed_results, started_at
                FROM tool_executions
                {where_clause}
                ORDER BY started_at DESC
            """, params)
            executions = cur.fetchall()

            # Group by severity
            vulnerabilities = {s: [] for s in SEVERITY_LEVELS}

            for ex in executions:
                parsed = ex.get("parsed_results") or {}
                output = ex.get("output") or ""

                # Determine severity
                severity = classify_severity(output, parsed)

                # Apply severity filter if specified
                if severity_filter and severity != severity_filter:
                    continue

                # Extract CVEs
                cves = extract_cves(output)

                # Generate title
                title = extract_title_from_output(ex["tool"], output, parsed)

                # Only include if it has actual findings (not just info scans with no results)
                has_findings = (
                    severity in ["critical", "high", "medium", "low"] or
                    cves or
                    parsed.get("vulnerabilities") or
                    parsed.get("credentials_found") or
                    parsed.get("weak_algorithms")
                )

                if has_findings or severity_filter == "info":
                    entry = {
                        "id": str(ex["id"]),
                        "title": title,
                        "tool": ex["tool"],
                        "target": ex["target"],
                        "port": ex.get("port"),
                        "service": ex.get("service"),
                        "cve": cves,
                        "detail_url": f"/reports/vulnerability/{ex['id']}"
                    }
                    vulnerabilities[severity].append(entry)

            return vulnerabilities
    finally:
        conn.close()


def db_get_vulnerability_detail(exec_id: str) -> Optional[Dict[str, Any]]:
    """
    Get full detail for one vulnerability/execution.

    Returns:
        Dictionary with raw_output, parsed_results, exploit_links, etc.
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    id, tool, command, target, port, service,
                    status, exit_code, output, error, parsed_results,
                    started_at, completed_at
                FROM tool_executions
                WHERE id = %s
            """, (exec_id,))
            ex = cur.fetchone()

            if not ex:
                return None

            parsed = ex.get("parsed_results") or {}
            output = ex.get("output") or ""

            # Determine severity
            severity = classify_severity(output, parsed)

            # Extract CVEs
            cves = extract_cves(output)

            # Generate title
            title = extract_title_from_output(ex["tool"], output, parsed)

            # Build reproduction command
            reproduction_command = ex["command"]

            # Generate reproduction steps
            reproduction_steps = [
                f"1. Run: {reproduction_command}"
            ]

            # Add tool-specific reproduction steps
            if ex["tool"].lower() == "nmap" and "vsftpd" in output.lower():
                reproduction_steps.extend([
                    "2. Or trigger manually: echo 'USER test:)' | nc {target} 21".format(target=ex["target"]),
                    "3. Connect to backdoor: nc {target} 6200".format(target=ex["target"])
                ])

            # Get remediation if available
            remediation = get_remediation(ex["tool"], output, parsed, cves)

            return {
                "id": str(ex["id"]),
                "severity": severity,
                "title": title,
                "tool": ex["tool"],
                "command": ex["command"],
                "target": ex["target"],
                "port": ex.get("port"),
                "service": ex.get("service"),
                "raw_output": output,
                "error_output": ex.get("error"),
                "parsed_results": parsed,
                "cve": cves,
                "exploit_links": [],  # Populated by get_exploit_links() async call
                "reproduction_steps": reproduction_steps,
                "reproduction_command": reproduction_command,
                "remediation": remediation,
                "started_at": ex["started_at"].isoformat() if ex.get("started_at") else None,
                "completed_at": ex["completed_at"].isoformat() if ex.get("completed_at") else None
            }
    finally:
        conn.close()


def get_remediation(tool: str, output: str, parsed: Dict, cves: List[str]) -> Optional[str]:
    """Get remediation advice based on the finding."""
    output_lower = output.lower() if output else ""

    # Known remediations
    if "vsftpd" in output_lower and "2.3.4" in output_lower:
        return "Upgrade vsftpd to version 2.3.5 or later. The backdoor was removed in the official release."

    if parsed.get("weak_algorithms"):
        return "Disable weak cryptographic algorithms. Update SSH configuration to use only strong ciphers (e.g., chacha20-poly1305, aes256-gcm)."

    if parsed.get("credentials_found"):
        return "Change compromised credentials immediately. Implement strong password policies and consider multi-factor authentication."

    if "anonymous" in output_lower and ("ftp" in output_lower or "login" in output_lower):
        return "Disable anonymous FTP access if not required. If required, ensure proper access controls are in place."

    if "default" in output_lower and "password" in output_lower:
        return "Change default credentials immediately. Implement strong password policies."

    if "CVE-" in output:
        return "Apply vendor patches for the identified CVE(s). Check vendor security advisories for available updates."

    return None


async def get_exploit_links(
    cve: Optional[str] = None,
    service: Optional[str] = None,
    version: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Query scan-recommender RAG for exploit information.

    Returns:
        List of exploit links with name, type, url, etc.
    """
    exploit_links = []

    # Build search query
    search_terms = []
    if cve:
        search_terms.append(cve)
    if service:
        search_terms.append(service)
    if version:
        search_terms.append(version)

    if not search_terms:
        return exploit_links

    query = " ".join(search_terms) + " exploit"

    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            # Try enhanced search endpoint
            resp = await client.get(
                f"{RAG_SERVICE_URL}/rag/search/enhanced",
                params={"query": query, "limit": 5}
            )

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])

                for result in results:
                    content = result.get("content", "").lower()
                    metadata = result.get("metadata", {})

                    # Determine exploit type
                    exploit_type = "reference"
                    if "metasploit" in content or "msf" in content:
                        exploit_type = "metasploit"
                    elif "exploit-db" in content or "exploitdb" in content:
                        exploit_type = "exploitdb"
                    elif "github" in content:
                        exploit_type = "github"

                    exploit_links.append({
                        "name": result.get("title", "Exploit Reference"),
                        "type": exploit_type,
                        "source": metadata.get("source", "unknown"),
                        "description": result.get("content", "")[:200]
                    })

            # Also try tools recommendation if service is provided
            if service:
                resp = await client.get(
                    f"{RAG_SERVICE_URL}/rag/tools/recommend",
                    params={"service": service}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for tool in data.get("tools", []):
                        if "exploit" in tool.get("description", "").lower():
                            exploit_links.append({
                                "name": tool.get("name", "Tool"),
                                "type": "tool",
                                "description": tool.get("description", "")
                            })

    except Exception as e:
        # Log but don't fail - exploit links are supplementary
        pass

    return exploit_links


def generate_markdown_report(target: str, summary: Dict, vulnerabilities: Dict) -> str:
    """Generate a markdown format report."""
    lines = [
        f"# Security Scan Report",
        f"",
        f"**Target:** {target}",
        f"**Scan Period:** {summary['scan_period']['started']} to {summary['scan_period']['ended']}",
        f"",
        f"## Executive Summary",
        f"",
        f"### Tools Executed",
        f"",
        f"| Tool | Executions | Successful | Failed | Avg Duration |",
        f"|------|------------|------------|--------|--------------|"
    ]

    for tool in summary.get("tools_summary", []):
        lines.append(
            f"| {tool['tool']} | {tool['executions']} | {tool['successful']} | "
            f"{tool['failed']} | {tool['avg_duration']:.1f}s |"
        )

    lines.extend([
        f"",
        f"### Findings by Severity",
        f"",
    ])

    for severity in SEVERITY_LEVELS:
        count = summary.get("findings_by_severity", {}).get(severity, 0)
        if count > 0:
            lines.append(f"- **{severity.upper()}:** {count}")

    lines.extend([
        f"",
        f"### Ports Discovered",
        f"",
        f"| Port | Protocol | Service | Version | Findings |",
        f"|------|----------|---------|---------|----------|"
    ])

    for port in summary.get("ports_discovered", []):
        lines.append(
            f"| {port['port']} | {port['protocol']} | {port['service']} | "
            f"{port.get('version', 'N/A')} | {port['findings_count']} |"
        )

    lines.extend([
        f"",
        f"## Vulnerabilities",
        f""
    ])

    for severity in SEVERITY_LEVELS:
        vulns = vulnerabilities.get(severity, [])
        if vulns:
            lines.extend([
                f"### {severity.upper()} ({len(vulns)})",
                f""
            ])
            for vuln in vulns:
                cves = ", ".join(vuln.get("cve", [])) or "N/A"
                lines.extend([
                    f"#### {vuln['title']}",
                    f"",
                    f"- **Tool:** {vuln['tool']}",
                    f"- **Target:** {vuln['target']}:{vuln.get('port', 'N/A')}",
                    f"- **CVE:** {cves}",
                    f"- **Details:** [{vuln['id']}]({vuln['detail_url']})",
                    f""
                ])

    lines.extend([
        f"---",
        f"*Report generated at {datetime.now().isoformat()}*"
    ])

    return "\n".join(lines)


def generate_full_report(target: str = None, format: str = "json") -> Dict[str, Any]:
    """
    Generate a complete report in the specified format.

    Args:
        target: Target IP/hostname (optional — if None, includes all findings)
        format: Output format - json, html, or markdown

    Returns:
        Dictionary with report data and optional rendered content
    """
    summary = db_get_report_summary(target)
    vulnerabilities = db_get_vulnerabilities_by_severity(target)

    report_target = target or "All Targets"
    report = {
        "target": report_target,
        "generated_at": datetime.now().isoformat(),
        "summary": summary,
        "vulnerabilities": vulnerabilities
    }

    if format == "markdown":
        report["rendered"] = generate_markdown_report(report_target, summary, vulnerabilities)

    return report


def generate_pentester_markdown_report(results: List[Dict], target: Optional[str] = None) -> str:
    """
    Generate a markdown report with raw tool output for manual pentester review.

    Args:
        results: List of tool results from db_get_tool_results(include_raw=True)
        target: Optional target description for report header

    Returns:
        Markdown formatted report string
    """
    lines = [
        "# Penetration Test Tool Execution Report",
        "",
        f"**Generated:** {datetime.now().isoformat()}",
    ]

    if target:
        lines.append(f"**Target:** {target}")

    lines.append(f"**Total Executions:** {len(results)}")
    lines.append("")

    # Count by status
    status_counts = {}
    for r in results:
        status = r.get("status", "completed")
        status_counts[status] = status_counts.get(status, 0) + 1

    if status_counts:
        lines.append("**Status Summary:** " + ", ".join(
            f"{status}: {count}" for status, count in sorted(status_counts.items())
        ))
        lines.append("")

    # Execution Summary Table
    lines.extend([
        "## Execution Summary",
        "",
        "| # | Tool | Target | Port | Status | Exit Code | Duration |",
        "|---|------|--------|------|--------|-----------|----------|"
    ])

    for i, r in enumerate(results, 1):
        port = str(r.get("port") or "-")
        status = r.get("status", "completed")
        exit_code = str(r.get("exit_code")) if r.get("exit_code") is not None else "-"
        duration = f"{r.get('duration', 0):.1f}s"
        lines.append(f"| {i} | {r['tool']} | {r['target']} | {port} | {status} | {exit_code} | {duration} |")

    lines.extend(["", "---", ""])

    # Tool Outputs Section
    lines.append("## Tool Outputs")
    lines.append("")

    for i, r in enumerate(results, 1):
        tool = r.get("tool", "unknown")
        target_str = r.get("target", "unknown")
        port = r.get("port")
        port_str = f":{port}" if port else ""

        lines.extend([
            f"### {i}. {tool} - {target_str}{port_str}",
            ""
        ])

        # Command
        if r.get("command"):
            lines.append(f"**Command:** `{r['command']}`")

        # Status info
        status = r.get("status", "completed")
        exit_code = r.get("exit_code")
        duration = r.get("duration", 0)
        exit_str = f" | **Exit Code:** {exit_code}" if exit_code is not None else ""
        lines.append(f"**Status:** {status}{exit_str} | **Duration:** {duration:.1f}s")

        # Findings summary
        findings = r.get("findings", [])
        if findings:
            lines.append("")
            lines.append("**Findings:**")
            for finding in findings:
                lines.append(f"- {finding}")

        # CVEs
        cves = r.get("cves", [])
        if cves:
            lines.append(f"**CVEs:** {', '.join(cves)}")

        lines.append("")

        # Raw output (strip ANSI color codes for clean display)
        raw_output = r.get("raw_output")
        if raw_output:
            lines.extend([
                "#### Output:",
                "```",
                strip_ansi(raw_output).strip(),
                "```",
                ""
            ])

        # Error output
        error_output = r.get("error_output")
        if error_output:
            lines.extend([
                "#### Errors:",
                "```",
                error_output.strip(),
                "```",
                ""
            ])

        lines.append("---")
        lines.append("")

    lines.extend([
        "",
        f"*Report generated at {datetime.now().isoformat()}*"
    ])

    return "\n".join(lines)


def generate_pentester_text_report(results: List[Dict], target: Optional[str] = None) -> str:
    """
    Generate a plain text report with raw tool output for manual pentester review.

    Args:
        results: List of tool results from db_get_tool_results(include_raw=True)
        target: Optional target description for report header

    Returns:
        Plain text formatted report string
    """
    lines = [
        "=" * 70,
        "PENETRATION TEST TOOL EXECUTION REPORT",
        "=" * 70,
        "",
        f"Generated: {datetime.now().isoformat()}",
    ]

    if target:
        lines.append(f"Target: {target}")

    lines.append(f"Total Executions: {len(results)}")
    lines.append("")

    # Count by status
    status_counts = {}
    for r in results:
        status = r.get("status", "completed")
        status_counts[status] = status_counts.get(status, 0) + 1

    if status_counts:
        lines.append("Status Summary: " + ", ".join(
            f"{status}: {count}" for status, count in sorted(status_counts.items())
        ))

    lines.extend([
        "",
        "-" * 70,
        "EXECUTION SUMMARY",
        "-" * 70,
        ""
    ])

    # Summary list
    for i, r in enumerate(results, 1):
        port = r.get("port") or "-"
        status = r.get("status", "completed")
        exit_code = r.get("exit_code")
        exit_str = f", exit={exit_code}" if exit_code is not None else ""
        duration = r.get("duration", 0)
        lines.append(f"  {i:3}. {r['tool']:15} {r['target']:20} port={port:<6} [{status}{exit_str}] {duration:.1f}s")

    lines.extend([
        "",
        "=" * 70,
        "TOOL OUTPUTS",
        "=" * 70,
    ])

    for i, r in enumerate(results, 1):
        tool = r.get("tool", "unknown")
        target_str = r.get("target", "unknown")
        port = r.get("port")
        port_str = f":{port}" if port else ""

        lines.extend([
            "",
            "-" * 70,
            f"[{i}] {tool.upper()} - {target_str}{port_str}",
            "-" * 70,
            ""
        ])

        # Command
        if r.get("command"):
            lines.append(f"Command: {r['command']}")

        # Status info
        status = r.get("status", "completed")
        exit_code = r.get("exit_code")
        duration = r.get("duration", 0)
        lines.append(f"Status: {status}")
        if exit_code is not None:
            lines.append(f"Exit Code: {exit_code}")
        lines.append(f"Duration: {duration:.1f}s")

        # Findings
        findings = r.get("findings", [])
        if findings:
            lines.append("")
            lines.append("Findings:")
            for finding in findings:
                lines.append(f"  * {finding}")

        # CVEs
        cves = r.get("cves", [])
        if cves:
            lines.append(f"CVEs: {', '.join(cves)}")

        # Raw output (strip ANSI color codes for clean display)
        raw_output = r.get("raw_output")
        if raw_output:
            lines.extend([
                "",
                "OUTPUT:",
                "~" * 50,
                strip_ansi(raw_output).strip(),
                "~" * 50
            ])

        # Error output
        error_output = r.get("error_output")
        if error_output:
            lines.extend([
                "",
                "ERRORS:",
                "~" * 50,
                error_output.strip(),
                "~" * 50
            ])

    lines.extend([
        "",
        "=" * 70,
        f"Report generated at {datetime.now().isoformat()}",
        "=" * 70
    ])

    return "\n".join(lines)
