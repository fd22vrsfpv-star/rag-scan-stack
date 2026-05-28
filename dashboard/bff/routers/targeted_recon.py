"""
Targeted Recon Router — KB lookup + remote execution + auto-ingest.

Connects the scan-recommender knowledge base with remote node execution
and structured result ingestion.
"""

import logging
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from utils import safe_json

from config import get_settings
from engagement import engagement_headers

log = logging.getLogger("targeted_recon")
router = APIRouter()

# Tools with known parsers that produce ingestible output formats.
# Maps tool name → (output flag to append, ingest endpoint type).
TOOL_OUTPUT_MAP = {
    "nmap":        {"flag": "-oX /tmp/tr_out.xml",   "ingest": "nmap",    "mime": "application/xml"},
    "nuclei":      {"flag": "-jsonl -o /tmp/tr_out.json", "ingest": "nuclei", "mime": "application/json"},
    "httpx":       {"flag": "-json -o /tmp/tr_out.json",  "ingest": "httpx",  "mime": "application/json"},
    "masscan":     {"flag": "-oJ /tmp/tr_out.json",  "ingest": "masscan", "mime": "application/json"},
    "nikto":       {"flag": "-o /tmp/tr_out.xml -Format xml", "ingest": None, "mime": None},
    "gobuster":    {"flag": "-o /tmp/tr_out.txt",    "ingest": None,      "mime": None},
    "feroxbuster": {"flag": "-o /tmp/tr_out.txt",    "ingest": None,      "mime": None},
    "whatweb":     {"flag": "--log-json=/tmp/tr_out.json", "ingest": "whatweb", "mime": "application/json"},
    "katana":      {"flag": "-json -o /tmp/tr_out.json",  "ingest": "katana", "mime": "application/json"},
    # Tools that use stdout-based parsing (no file output, parsed by tool-specific parsers)
    "ssh-audit":   {"flag": "",  "ingest": None, "mime": None, "stdout_parser": "ssh-audit"},
    "sslscan":     {"flag": "",  "ingest": None, "mime": None, "stdout_parser": "sslscan"},
    "testssl":     {"flag": "",  "ingest": None, "mime": None, "stdout_parser": "testssl"},
    "sslyze":      {"flag": "",  "ingest": None, "mime": None, "stdout_parser": "sslyze"},
    "enum4linux":  {"flag": "",  "ingest": None, "mime": None, "stdout_parser": "enum4linux"},
}

# Safe tools (reconnaissance-only, no exploitation)
SAFE_TOOLS = {
    "nmap", "nuclei", "whatweb", "ssh-audit", "enum4linux", "showmount",
    "rpcinfo", "smbclient", "smbmap", "snmpwalk", "dig", "dnsrecon",
    "curl", "ldapsearch", "redis-cli", "snmp-check", "sslscan",
    "testssl", "sslyze", "subfinder", "dnsx", "vulnx", "nikto",
    "gobuster", "feroxbuster", "httpx", "whatweb", "katana",
    "wafw00f", "wpscan",
}


# Default wordlist paths (must match service_tools.yaml defaults)
_WORDLIST_DEFAULTS = {
    "wordlist_usernames": "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
    "wordlist_passwords": "/usr/share/wordlists/rockyou.txt",
    "wordlist_dirs": "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "wordlist_subdomains": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
}

_wordlist_cache: dict = {"paths": {}, "ts": 0}


async def _load_wordlist_paths(s) -> dict[str, str]:
    """Load user-configured wordlist paths from settings. Cached 60s.
    Returns dict mapping default_path -> user_path for paths that differ."""
    import time
    now = time.time()
    if _wordlist_cache["paths"] and (now - _wordlist_cache["ts"]) < 60:
        return _wordlist_cache["paths"]
    overrides = {}
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            for key, default in _WORDLIST_DEFAULTS.items():
                try:
                    resp = await c.get(
                        f"{s.rag_api_url}/settings/config/{key}",
                        headers={"x-api-key": s.api_key, **engagement_headers()},
                    )
                    if resp.status_code == 200:
                        user_val = resp.json().get("value", "").strip()
                        if user_val and user_val != default:
                            overrides[default] = user_val
                except Exception:
                    pass
    except Exception:
        pass
    _wordlist_cache["paths"] = overrides
    _wordlist_cache["ts"] = now
    return overrides


class ReconLookupRequest(BaseModel):
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    banner: Optional[str] = None


class ReconExecuteRequest(BaseModel):
    node_id: str
    command: str
    tool_name: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    timeout: int = 300
    auto_ingest: bool = True
    engagement_id: Optional[str] = None


# --------------------------------------------------------------------------
# GET /api/targeted-recon — KB lookup for a target:port
# --------------------------------------------------------------------------

@router.post("/api/targeted-recon")
async def targeted_recon_lookup(req: ReconLookupRequest):
    """
    Query the knowledge base for recommended commands given a target and port.

    Returns tool recommendations with filled-in commands, risk level,
    and whether auto-ingest is supported.
    """
    s = get_settings()

    # 1) Query scan-recommender KB for service tools
    kb_result = {}
    try:
        params = {"ip": req.target}
        if req.port:
            params["port"] = req.port
        if req.service:
            params["service"] = req.service
        if req.banner:
            params["banner"] = req.banner
        params["persist"] = "false"  # don't persist recommendation, just lookup

        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.get(
                f"{s.scan_recommender_url}/next_scan",
                params=params,
            )
            if resp.status_code == 200:
                kb_result = resp.json()
    except Exception as e:
        log.warning("scan-recommender KB lookup failed: %s", e)

    # 2) Also try direct KB service lookup for richer data
    service_info = {}
    # Common port → service mapping for when service name isn't provided
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
        143: "imap", 389: "ldap", 443: "https", 445: "smb", 993: "imaps",
        995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
        3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
        6379: "redis", 8080: "http", 8443: "https", 9200: "elasticsearch",
        27017: "mongodb",
    }
    if req.service or req.port:
        try:
            svc_name = req.service or PORT_SERVICE_MAP.get(req.port, "")
            svc_port = req.port or 0
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                resp = await c.get(
                    f"{s.scan_recommender_url}/kb/services/{svc_name}",
                    params={"port": svc_port} if svc_port else {},
                )
                if resp.status_code == 200:
                    raw = resp.json()
                    # KB returns {"name": "ssh", "data": {"tools": [...], ...}}
                    # Flatten so we can access tools/description/etc directly
                    service_info = raw.get("data", {}) if "data" in raw else raw
                    if not service_info.get("description") and raw.get("description"):
                        service_info["description"] = raw["description"]
        except Exception:
            pass

    # 3) Build unified command list
    commands = []
    seen_tools = set()

    # From direct KB (richer: has command templates)
    for tool in service_info.get("tools", []):
        name = tool.get("name", "")
        cmd = tool.get("command", "")
        # Fill in placeholders
        cmd = cmd.replace("{target}", req.target)
        cmd = cmd.replace("{port}", str(req.port or 80))
        if "{product}" in cmd or "{version}" in cmd:
            cmd = cmd.replace("{product}", req.banner or "unknown")
            cmd = cmd.replace("{version}", "")

        output_info = TOOL_OUTPUT_MAP.get(name, {})

        commands.append({
            "tool": name,
            "purpose": tool.get("purpose", ""),
            "command": cmd,
            "risk": "safe" if name in SAFE_TOOLS else "active",
            "has_parser": output_info.get("ingest") is not None,
            "auto_ingest_type": output_info.get("ingest"),
            "category": "tool",
        })
        seen_tools.add(name)

    # From scan-recommender recommendations (may include LLM-generated)
    for rec in kb_result.get("recommendations", []):
        scanner = rec.get("scanner", "").strip()
        if scanner in seen_tools:
            continue
        script = rec.get("script", "").strip()
        template = rec.get("template", "")
        action = rec.get("action", "")
        port = req.port or 80

        # Build full command from script/template name
        if scanner == "nmap" and script:
            cmd = f"nmap --script {script} -p {port} {req.target}"
        elif scanner == "nuclei" and template:
            cmd = f"nuclei -u {req.target}:{port} -t {template}"
        elif script and "{target}" in script:
            cmd = script.replace("{target}", req.target).replace("{port}", str(port))
        elif script:
            cmd = f"{scanner} {script} {req.target}"
        else:
            cmd = f"{scanner} {req.target}"

        output_info = TOOL_OUTPUT_MAP.get(scanner, {})

        commands.append({
            "tool": scanner,
            "purpose": action or script,
            "command": cmd,
            "template": template,
            "risk": "safe" if scanner in SAFE_TOOLS else "active",
            "has_parser": output_info.get("ingest") is not None,
            "auto_ingest_type": output_info.get("ingest"),
            "category": "recommendation",
        })
        seen_tools.add(scanner)

    # Metasploit modules
    for msf in service_info.get("metasploit", []):
        module = msf.get("module", "")
        commands.append({
            "tool": "metasploit",
            "purpose": msf.get("purpose", ""),
            "command": f"msfconsole -q -x 'use {module}; set RHOSTS {req.target}; set RPORT {req.port or 0}; run; exit'",
            "risk": "exploit",
            "has_parser": False,
            "auto_ingest_type": None,
            "category": "metasploit",
        })

    # Nuclei tags
    nuclei_tags = service_info.get("nuclei_tags", [])
    if nuclei_tags and "nuclei" not in seen_tools:
        tag_str = ",".join(nuclei_tags[:10])
        commands.append({
            "tool": "nuclei",
            "purpose": f"template scan ({tag_str})",
            "command": f"nuclei -u {req.target}:{req.port or 80} -tags {tag_str}",
            "risk": "safe",
            "has_parser": True,
            "auto_ingest_type": "nuclei",
            "category": "tool",
        })

    # Fetch available nodes for the dropdown
    nodes = []
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            resp = await c.get(f"{s.tunnel_manager_url}/nodes")
            if resp.status_code == 200:
                for n in resp.json().get("nodes", []):
                    if n.get("status") == "online":
                        nodes.append({
                            "id": n["id"],
                            "name": n.get("name", n["id"][:8]),
                            "type": n.get("node_type", "unknown"),
                        })
    except Exception:
        pass

    # Substitute user-configured wordlist paths into commands
    wordlist_overrides = await _load_wordlist_paths(s)
    if wordlist_overrides:
        for cmd in commands:
            c = cmd["command"]
            for default_path, user_path in wordlist_overrides.items():
                if default_path in c:
                    c = c.replace(default_path, user_path)
            cmd["command"] = c

    return {
        "target": req.target,
        "port": req.port,
        "service": req.service or service_info.get("service"),
        "service_description": service_info.get("description"),
        "common_vulns": service_info.get("common_vulns", []),
        "commands": commands,
        "nodes": nodes,
    }


# --------------------------------------------------------------------------
# POST /api/targeted-recon/execute — Run command on remote node + ingest
# --------------------------------------------------------------------------

@router.post("/api/targeted-recon/execute")
async def targeted_recon_execute(req: ReconExecuteRequest):
    """
    Execute a KB command on a remote proxy node.

    1. Runs the command via SSH exec on the specified node
    2. If tool has a known parser: downloads output file and ingests via /ingest/{type}
    3. Otherwise: sends stdout to /ingest/tool-output for structured parsing
    4. Returns execution result + ingestion stats
    """
    s = get_settings()
    tool_info = TOOL_OUTPUT_MAP.get(req.tool_name, {})
    ingest_type = tool_info.get("ingest") if req.auto_ingest else None
    output_flag = tool_info.get("flag", "")
    mime = tool_info.get("mime", "application/json")

    # Build the command — append output flag if tool has a known parser
    command = req.command
    has_file_output = False
    if ingest_type and output_flag and output_flag not in command:
        command = f"{command} {output_flag}"
        has_file_output = True

    result = {
        "ok": False,
        "node_id": req.node_id,
        "tool": req.tool_name,
        "target": req.target,
        "command_executed": command,
        "stdout": "",
        "stderr": "",
        "exit_code": None,
        "ingest_result": None,
        "structured_result": None,
        "duration_ms": None,
    }

    # Step 1: Execute on remote node (retry on 404/503 — node may be reconnecting)
    exec_data = None
    last_error = ""
    last_status = 500
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(verify=False, timeout=req.timeout + 10) as c:
                exec_resp = await c.post(
                    f"{s.tunnel_manager_url}/ssh/{req.node_id}/exec",
                    json={"command": command, "timeout": req.timeout},
                )
                if exec_resp.status_code < 400:
                    exec_data = exec_resp.json()
                    break
                # Parse error from node-manager (avoid double-wrapping)
                try:
                    err_body = exec_resp.json()
                    last_error = err_body.get("detail", exec_resp.text)
                except Exception:
                    last_error = exec_resp.text
                last_status = exec_resp.status_code
                # Retry on 404 (not found) or 503 (tunnel offline) — trigger reconnect
                if exec_resp.status_code in (404, 503) and attempt < 2:
                    log.info("Node %s: %s (attempt %d) — triggering reconnect",
                             req.node_id, last_error[:80], attempt + 1)
                    try:
                        await c.post(f"{s.tunnel_manager_url}/ssh/{req.node_id}/reconnect")
                    except Exception:
                        pass
                    import asyncio as _aio
                    await _aio.sleep(3)
                    continue
                raise HTTPException(exec_resp.status_code, last_error)
        except httpx.TimeoutException:
            raise HTTPException(504, f"Command timed out after {req.timeout}s")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"Failed to execute on node: {e}")
    if exec_data is None:
        raise HTTPException(last_status, last_error or "Node not reachable after retries")

    result["stdout"] = exec_data.get("stdout", "")
    result["stderr"] = exec_data.get("stderr", "")
    result["exit_code"] = exec_data.get("exit_code")
    result["duration_ms"] = exec_data.get("duration_ms")
    result["ok"] = exec_data.get("ok", False)

    if not result["ok"]:
        return result

    stdout = result["stdout"]
    stderr = result["stderr"]

    # Step 2: Try file-based ingest if tool has a known parser
    if has_file_output and ingest_type:
        try:
            # Download the output file from the remote node
            async with httpx.AsyncClient(verify=False, timeout=60) as c:
                dl_resp = await c.post(
                    f"{s.tunnel_manager_url}/ssh/{req.node_id}/download",
                    json={"remote_path": _extract_output_path(output_flag)},
                )
                if dl_resp.status_code == 200:
                    # Ingest the file via rag-api
                    ingest_resp = await c.post(
                        f"{s.rag_api_url}/ingest/{ingest_type}",
                        headers={"x-api-key": s.api_key, **engagement_headers()},
                        files={"file": (f"tr_{req.tool_name}.out",
                                        dl_resp.content, mime)},
                        params={"job_id": f"tr-{req.node_id[:8]}"},
                    )
                    if ingest_resp.status_code < 400:
                        result["ingest_result"] = ingest_resp.json()
                        return result
                    else:
                        log.warning("File ingest failed (%s), falling back to stdout",
                                    ingest_resp.status_code)
        except Exception as e:
            log.warning("File download/ingest failed: %s, falling back to stdout", e)

    # Step 3: Structure stdout via /ingest/tool-output
    if stdout.strip() and req.auto_ingest:
        try:
            async with httpx.AsyncClient(verify=False, timeout=30) as c:
                struct_resp = await c.post(
                    f"{s.rag_api_url}/ingest/tool-output",
                    headers={"x-api-key": s.api_key, **engagement_headers()},
                    json={
                        "stdout": stdout,
                        "tool_name": req.tool_name,
                        "target": req.target,
                        "port": req.port,
                        "service": req.service,
                        "engagement_id": req.engagement_id,
                    },
                )
                if struct_resp.status_code < 400:
                    result["structured_result"] = struct_resp.json()
        except Exception as e:
            log.warning("stdout structuring failed: %s", e)

    return result


def _extract_output_path(flag: str) -> str:
    """Extract the file path from an output flag string."""
    # Handle patterns like "-oX /tmp/tr_out.xml" or "--log-json=/tmp/tr_out.json"
    for part in flag.split():
        if part.startswith("/tmp/"):
            return part
    if "=" in flag:
        return flag.split("=", 1)[1].strip()
    return "/tmp/tr_out.json"
