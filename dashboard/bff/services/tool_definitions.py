"""Ollama-format tool definitions mirroring MCP tool schemas."""

import json
import logging
import os
from typing import Optional

import httpx

log = logging.getLogger("tool_definitions")

CORE_TOOLS = ["search_findings", "search_recon", "search_identities",
              "get_assets", "get_open_ports", "read_uploaded_file"]

TOOL_PROFILES: dict[str, Optional[list[str]]] = {
    "recon": CORE_TOOLS + [
        "get_vulns", "start_masscan", "start_nmap_scan",
        "start_naabu", "start_httpx_probe", "get_job_status",
        "start_scan_pipeline", "get_pipeline_status", "stop_pipeline",
    ],
    "web": CORE_TOOLS + [
        "start_web_scan", "start_web_pipeline", "start_nuclei_scan",
        "start_nikto_scan", "start_katana", "start_playwright_scan", "get_job_status",
        "search_sitemap", "search_params", "get_content_intel",
    ],
    "osint": CORE_TOOLS + [
        "start_subfinder", "start_dnsx", "start_tlsx", "start_crtsh",
        "start_httpx_probe", "get_job_status",
    ],
    "exploit": CORE_TOOLS + [
        "get_vulns", "search_exploits", "get_pending_exploits",
        "get_all_exploits", "get_exploit_results",
        "get_msf_sessions", "get_recommendations",
    ],
    "analysis": CORE_TOOLS + [
        "get_vulns", "get_recommendations", "get_all_active_jobs",
        "get_job_status", "cleanup_findings",
        "search_sitemap", "search_params", "get_content_intel",
        "start_scan_pipeline", "get_pipeline_status", "stop_pipeline",
    ],
    "credentials": CORE_TOOLS + ["get_msf_sessions"],
    "mcp": [],  # Empty built-in list — only MCP tools
    "all": None,  # None = send all TOOLS
}

# Allowlist of MCP server names to include per profile. None = include every
# discovered MCP server (legacy behavior); a list (possibly empty) restricts
# the prompt to only those servers' tools so the LLM gets a much smaller
# tool schema and responds faster on a cold model.
MCP_PROFILES: dict[str, Optional[list[str]]] = {
    "recon": None,
    "web": None,
    "osint": None,
    "exploit": None,
    "analysis": None,
    "credentials": ["credentials"],
    "mcp": None,
    "all": None,
}

PROFILE_PROMPTS: dict[str, str] = {
    "recon": "You are in RECON mode. Focus on network discovery: scan ports, detect services, identify hosts. Use masscan for fast discovery, nmap for service details.",
    "web": "You are in WEB SCAN mode. Focus on web application security: directory brute-forcing, vulnerability scanning, crawling. Use web_scan for quick checks, web_pipeline for thorough assessment.",
    "osint": "You are in OSINT mode. Focus on passive and active reconnaissance: subdomains, DNS records, TLS certificates. Map the attack surface before scanning.",
    "exploit": "You are in EXPLOIT mode. Focus on finding and evaluating exploits for discovered vulnerabilities. Search ExploitDB/Metasploit, review pending exploits, list all exploits by status, view execution results, and manage Metasploit sessions.",
    "analysis": "You are in ANALYSIS mode. Focus on reviewing results: search findings, check scan status, get AI recommendations, clean up old data.",
    "credentials": "You are in CREDENTIALS mode. Focus on identities, group memberships, and credential testing. Use list_users / list_groups / get_group_members to surface accounts (e.g. all members of 'Domain Admins'), get_user for full detail, and start_brutus only when credential testing is explicitly authorized.",
    "mcp": "You are in MCP TOOLS mode. You have access to third-party MCP tools and integrations. Use the available tools to assist the tester. List your available tools if asked.",
}

BURP_SYSTEM_SUPPLEMENT = """
## Burp Suite MCP Tools

You have direct access to Burp Suite Professional via MCP tools. Key usage notes:

### HTTP Requests (send_http1_request)
- The `content` parameter must be a COMPLETE raw HTTP/1.1 request with \\r\\n line endings
- Example: "GET / HTTP/1.1\\r\\nHost: example.com\\r\\nUser-Agent: Mozilla/5.0\\r\\n\\r\\n"
- Always include Host header. End headers with \\r\\n\\r\\n

### Repeater & Intruder (create_repeater_tab, send_to_intruder)
- ALWAYS provide `tabName` — it is required even though the schema says optional
- For Intruder, mark insertion points with § markers: "param=§value§"

### Proxy History (get_proxy_http_history, get_proxy_http_history_regex)
- Use these to inspect traffic that has already been proxied through Burp

### Collaborator (generate_collaborator_payload, get_collaborator_interactions)
- First generate a payload, then inject it in requests, then poll for interactions

### General
- All tools prefixed with [MCP:burpsuite-pro] are Burp tools
- targetPort: use 443 for HTTPS, 80 for HTTP
- usesHttps: true for HTTPS, false for HTTP
""".strip()

# Burp Suite MCP tools ship with no parameter descriptions. This map enriches
# them so the LLM knows what to pass. Keys are tool names, values map param
# name → description. Also used to mark params that Burp requires even when
# not listed in the schema's required array.
BURP_PARAM_ENRICHMENTS: dict[str, dict[str, str]] = {
    "send_http1_request": {
        "content": "Full raw HTTP/1.1 request including method, path, headers, and body. Use \\r\\n for line endings. Example: GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
        "targetHostname": "Target hostname (e.g. example.com)",
        "targetPort": "Target port number (e.g. 443 for HTTPS, 80 for HTTP)",
        "usesHttps": "true for HTTPS, false for plain HTTP",
    },
    "send_http2_request": {
        "headers": "Object of HTTP/2 headers (key-value pairs). Do NOT include pseudo-headers here.",
        "pseudoHeaders": "HTTP/2 pseudo-headers object. Must include :method, :path, :scheme, :authority. Example: {\":method\":\"GET\",\":path\":\"/\",\":scheme\":\"https\",\":authority\":\"example.com\"}",
        "requestBody": "HTTP request body (empty string for GET)",
        "targetHostname": "Target hostname (e.g. example.com)",
        "targetPort": "Target port number (e.g. 443)",
        "usesHttps": "true for HTTPS, false for plain HTTP",
    },
    "create_repeater_tab": {
        "content": "Full raw HTTP request. Use \\r\\n for line endings.",
        "tabName": "Name for the Repeater tab (REQUIRED — always provide a descriptive name)",
        "targetHostname": "Target hostname",
        "targetPort": "Target port number",
        "usesHttps": "true for HTTPS, false for HTTP",
    },
    "send_to_intruder": {
        "content": "Full raw HTTP request with §payload§ markers around insertion points. Use \\r\\n for line endings.",
        "tabName": "Name for the Intruder tab (REQUIRED — always provide a descriptive name)",
        "targetHostname": "Target hostname",
        "targetPort": "Target port number",
        "usesHttps": "true for HTTPS, false for HTTP",
    },
    "get_scanner_issues": {
        "urlPrefix": "Optional URL prefix to filter issues (e.g. https://example.com)",
    },
    "generate_collaborator_payload": {},
    "get_collaborator_interactions": {
        "payload": "The Collaborator payload URL to check for interactions",
    },
    "get_proxy_http_history": {
        "count": "Number of recent items to return (default 10)",
    },
    "get_proxy_http_history_regex": {
        "regex": "Java regex pattern to match against request/response",
        "count": "Number of items to return",
    },
    "get_proxy_websocket_history": {
        "count": "Number of recent items to return",
    },
    "get_proxy_websocket_history_regex": {
        "regex": "Java regex pattern to match",
        "count": "Number of items to return",
    },
    "set_task_execution_engine_state": {
        "paused": "true to pause task execution, false to resume",
    },
    "set_proxy_intercept_state": {
        "enabled": "true to enable intercept, false to disable",
    },
    "url_encode": {
        "content": "String to URL-encode",
    },
    "url_decode": {
        "content": "URL-encoded string to decode",
    },
    "base64_encode": {
        "content": "String to Base64-encode",
    },
    "base64_decode": {
        "content": "Base64-encoded string to decode",
    },
    "generate_random_string": {
        "length": "Length of the random string",
        "characterSet": "Characters to use (e.g. 'abcdefghijklmnopqrstuvwxyz0123456789')",
    },
    "output_project_options": {},
    "output_user_options": {},
    "set_project_options": {
        "content": "JSON configuration to merge into project options",
    },
    "set_user_options": {
        "content": "JSON configuration to merge into user options",
    },
    "get_active_editor_contents": {},
    "set_active_editor_contents": {
        "content": "New content for the active message editor",
    },
}

# Extra required params that Burp enforces but omits from schema required list
BURP_EXTRA_REQUIRED: dict[str, list[str]] = {
    "create_repeater_tab": ["tabName"],
    "send_to_intruder": ["tabName"],
}


def get_tools_for_profile(profile: str) -> list[dict]:
    """Return the TOOLS list filtered to only those in the given profile.
    MCP tools default to always-included; profiles that set an entry in
    `MCP_PROFILES` restrict to only the listed MCP server names so the LLM
    sees a smaller tool schema and prompt-processes faster on a cold model."""
    all_tools = get_all_tools()
    tool_names = TOOL_PROFILES.get(profile)
    mcp_servers = MCP_PROFILES.get(profile)

    if tool_names is None:
        builtin_filtered = list(TOOLS)
    else:
        builtin_filtered = [t for t in TOOLS if t["function"]["name"] in tool_names]

    mcp_tools = [t for t in all_tools if t not in TOOLS]
    if mcp_servers is not None:
        mcp_tools = [t for t in mcp_tools if t.get("_mcp_server") in mcp_servers]

    return builtin_filtered + mcp_tools


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_uploaded_file",
            "description": (
                "Read content of a file the user attached to the chat. Returns up to 256 KB "
                "per call along with `eof`, `next_start`, and `total_size` fields. "
                "If `eof` is false, CALL THIS TOOL AGAIN with `start=<next_start>` until "
                "`eof` is true — do NOT answer the user from a partial file. "
                "Defaults to UTF-8 text; binary files come back as base64."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_id": {"type": "string", "description": "Evidence id of the uploaded file"},
                    "start": {"type": "integer", "description": "Starting byte offset (default 0). Use the `next_start` from the previous call to continue."},
                    "end": {"type": "integer", "description": "Exclusive ending byte offset (default start + 262144 i.e. 256 KB)"},
                    "as_text": {"type": "boolean", "description": "Try UTF-8 decode first (default true). If false or undecodable, returns base64."},
                },
                "required": ["file_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_findings",
            "description": "Search vulnerability findings across all scan sources (nmap, nuclei, zap, gobuster, playwright). Returns unified results with severity, CVE, source, and evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "description": "Filter by severity: critical, high, medium, low, info"},
                    "source": {"type": "string", "description": "Filter by source: nmap, nuclei, zap, gobuster, playwright"},
                    "ip": {"type": "string", "description": "Filter by IP address"},
                    "cve": {"type": "string", "description": "Search for specific CVE identifier"},
                    "search": {"type": "string", "description": "Free-text search in finding title and evidence"},
                    "port": {"type": "integer", "description": "Filter by port number"},
                    "limit": {"type": "integer", "description": "Max results (default 50)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_assets",
            "description": "List discovered assets (IP + hostname + OS + open port counts + cloud provider tag). PREFERRED: filter by 'provider' to find cloud-hosted assets — get_assets({\"provider\": \"aws\"}) returns every asset hosted on AWS, including vanity domains like cdn.example.com that resolve to *.cloudfront.net. The 'search' param is a substring match on hostname/IP for cases where provider tagging hasn't picked it up yet. Each row includes provider_evidence explaining why an asset was tagged (CNAMEs, certs, headers).",
            "parameters": {
                "type": "object",
                "properties": {
                    "provider": {"type": "string", "description": "Cloud-hosting provider tag: aws, azure, cloudflare. Comma-separated for OR: 'aws,azure'. This is the right tool for 'find me AWS-hosted assets' — works for vanity domains too."},
                    "search": {"type": "string", "description": "Substring match on hostname or IP. Use only when provider filter doesn't fit (e.g. searching for a specific tenant ID). Example: 'amazonaws' or a customer name."},
                    "limit": {"type": "integer", "description": "Max results (default 100, max 5000)"},
                    "offset": {"type": "integer", "description": "Pagination offset (default 0)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_open_ports",
            "description": "List open ports with service name, version, and banner information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Filter by IP address"},
                    "service": {"type": "string", "description": "Filter by service name (e.g. http, ssh, smb)"},
                    "limit": {"type": "integer", "description": "Max results (default 200)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_vulns",
            "description": "List Nmap NSE script vulnerability findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Filter by IP address"},
                    "limit": {"type": "integer", "description": "Max results (default 200)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_masscan",
            "description": "Start a fast Masscan port discovery scan. Returns job_id for tracking.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or CIDR range, e.g. '192.168.1.0/24'"},
                    "ports": {"type": "string", "description": "Port range, e.g. '1-1000' or '22,80,443' (default: 1-1000)"},
                    "rate": {"type": "integer", "description": "Packets per second (default: 1000)"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_nmap_scan",
            "description": "Start a Masscan→Nmap combined scan with service/version detection. Returns job_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or CIDR range"},
                    "ports": {"type": "string", "description": "Port range (default: 1-1000)"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_full_port_scan",
            "description": "Start a complete port scan pipeline: Masscan 1-1000 → Nmap → Masscan 1001-65535 → Nmap → SMB vuln scan. Returns job_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or CIDR range"},
                    "rate": {"type": "integer", "description": "Packets per second (default: 1000)"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_nuclei_scan",
            "description": "Start a Nuclei vulnerability template scan. Scans from DB targets if no target specified.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or URL (optional - uses DB targets if omitted)"},
                    "severity": {"type": "string", "description": "Severity filter: medium,high,critical (default)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_web_scan",
            "description": "Start a web scan with Gobuster directory brute-force and ZAP active scan.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL, e.g. 'http://192.168.1.150'"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_web_pipeline",
            "description": "Start a complete web scan pipeline: Gobuster → Playwright → ZAP → Nuclei.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL"},
                    "max_paths": {"type": "integer", "description": "Max paths for Playwright (default: 50)"},
                },
                "required": ["target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_httpx_probe",
            "description": "Probe HTTP services with technology detection.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "List of hosts/URLs"},
                    "ports": {"type": "string", "description": "Ports to probe, e.g. '80,443,8080'"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_katana",
            "description": "Start web crawler for URL and endpoint discovery.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "List of URLs to crawl"},
                    "depth": {"type": "integer", "description": "Max crawl depth (default: 3)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_naabu",
            "description": "Start Naabu port scanner (alternative to Masscan).",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "List of IPs or CIDRs"},
                    "ports": {"type": "string", "description": "Port range (default: 1-1000)"},
                    "rate": {"type": "integer", "description": "Packets per second (default: 1000)"},
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_udp_scan",
            "description": "Start a UDP port scan using Nmap.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or CIDR range"},
                    "ports": {"type": "string", "description": "UDP ports to scan (default: common UDP ports)"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_tlsx",
            "description": "Analyze TLS certificates on target hosts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "List of hosts"},
                    "ports": {"type": "string", "description": "Ports to probe (default: 443)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_subfinder",
            "description": "Start subdomain enumeration with Subfinder.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "Domains to enumerate"},
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_dnsx",
            "description": "Start DNS resolution and enumeration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "Domains or IPs"},
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_job_status",
            "description": "Get the status and results of a scan job by ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "job_id": {"type": "string", "description": "Job UUID"},
                },
                "required": ["job_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_recommendations",
            "description": "Get AI-generated scan recommendations based on current findings and asset state.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_exploits",
            "description": "Search ExploitDB and Metasploit for exploits matching a CVE, service, or version.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve": {"type": "string", "description": "CVE ID, e.g. CVE-2017-7494"},
                    "service": {"type": "string", "description": "Service name, e.g. samba, apache"},
                    "version": {"type": "string", "description": "Service version, e.g. 2.4.49"},
                    "query": {"type": "string", "description": "Additional search terms"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_pending_exploits",
            "description": "List exploits pending human approval before execution.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_msf_sessions",
            "description": "List active Metasploit sessions (shells, meterpreter).",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_all_exploits",
            "description": "List all exploits (pending, approved, executed, failed, rejected) with optional status filter. Returns exploit details including confidence, target, source, and match reasoning.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "description": "Filter by status: pending, approved, executed, failed, rejected"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_exploit_results",
            "description": "Get execution results for all exploits, including output, success/failure, session info, and timing.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_all_active_jobs",
            "description": "List all currently active scan jobs across all scanner services.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    # ── Scan Pipelines ─────────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "start_scan_pipeline",
            "description": (
                "Launch a multi-stage parallel scan pipeline for an engagement. "
                "Stages run per-host (not globally): 0=passive recon, 1=port discovery+httpx, "
                "2=nmap service fingerprint, 3=nuclei+web crawl, 4=aggregation. "
                "Each host progresses independently — Host A's nmap starts as soon as its "
                "masscan finishes even while Host B is still in masscan. "
                "Returns pipeline_id to track. Use get_pipeline_status to monitor."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "engagement_id": {"type": "string", "description": "Engagement UUID"},
                    "profile": {"type": "string", "enum": ["pentest", "redteam"],
                                "description": "Scan profile (pentest=fast, redteam=low-and-slow)"},
                    "scope_name": {"type": "string", "description": "Optional scope name (default: all scope targets)"},
                    "use_tunnels": {"type": "boolean", "description": "Spread scans across provisioned SSH/SOCKS tunnels (round-robin)"},
                },
                "required": ["engagement_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_pipeline_status",
            "description": "Get status of a scan pipeline including per-host stage progress, job counts, and findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pipeline_id": {"type": "string", "description": "Pipeline UUID"},
                },
                "required": ["pipeline_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stop_pipeline",
            "description": "Stop a running scan pipeline and all its in-flight jobs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pipeline_id": {"type": "string", "description": "Pipeline UUID"},
                },
                "required": ["pipeline_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_nikto_scan",
            "description": "Start a Nikto web server vulnerability scan. Returns job_id for tracking.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL, e.g. 'http://192.168.1.100'"},
                    "tuning": {"type": "string", "description": "Nikto tuning options to limit test types (optional)"},
                },
                "required": ["target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_playwright_scan",
            "description": "Start a browser-based security scan using Playwright for client-side issues.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL to scan"},
                },
                "required": ["target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cleanup_findings",
            "description": "Delete findings from the database. Use dry_run=true first to preview.",
            "parameters": {
                "type": "object",
                "properties": {
                    "sources": {"type": "array", "items": {"type": "string"}, "description": "Sources to clean: nuclei, nmap, zap, etc."},
                    "older_than_hours": {"type": "integer", "description": "Only delete findings older than N hours"},
                    "dry_run": {"type": "boolean", "description": "If true, only preview (default: true)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_recon",
            "description": "Search OSINT and recon findings: subdomains, DNS records, TLS certificates, CT log certs, httpx probes, whatweb results, and more. Data sources: subfinder, dnsx, httpx, tlsx, crtsh, asnmap, uncover, cloudlist, whatweb.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Filter by source tool: subfinder, dnsx, httpx, tlsx, crtsh, asnmap, uncover, cloudlist, whatweb"},
                    "finding_type": {"type": "string", "description": "Filter by type: subdomain, dns_a, dns_aaaa, dns_cname, dns_mx, dns_ns, tls_cert, ct_cert, asn_mapping, search_result, cloud_asset, web_service"},
                    "target": {"type": "string", "description": "Filter by target domain, IP, or hostname"},
                    "severity": {"type": "string", "description": "Filter by severity: critical, high, medium, low, info"},
                    "search": {"type": "string", "description": "Free-text search across recon finding data"},
                    "limit": {"type": "integer", "description": "Max results (default 100)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_identities",
            "description": "Search discovered user identities (Azure AD / MicroBurst / SSO / dirsync). Use when the operator wants to find user accounts, admins, guests, or pivot from a tenant/domain to a list of accounts for password-spray or further enumeration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "provider": {"type": "string", "description": "Source provider: microburst, azure_ad, okta, dirsync, sso. Use 'microburst' for NetSPI Azure AD imports."},
                    "principal_type": {"type": "string", "description": "Filter by type: user, guest, service_principal, group, application"},
                    "search": {"type": "string", "description": "Substring match on identifier / display_name / domain / tenant"},
                    "is_admin": {"type": "boolean", "description": "Only return identities flagged as admin (Global Admin, AzureAD admin, etc.)"},
                    "is_guest": {"type": "boolean", "description": "Only return guest / B2B accounts"},
                    "is_dirsync": {"type": "boolean", "description": "Only return on-prem-synced (dirsync / Entra Connect) accounts"},
                    "has_credential": {"type": "boolean", "description": "Only return identities for which we have a discovered credential"},
                    "member_of": {"type": "string", "description": "Filter by group membership tag, e.g. 'Domain Admins', 'Global Administrators'"},
                    "limit": {"type": "integer", "description": "Max results (default 100, max 2000)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_crtsh",
            "description": "Search Certificate Transparency logs via crt.sh for a domain. Discovers subdomains, wildcard certs, and expired certificates passively.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to search, e.g. 'example.com'"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_sitemap",
            "description": "Search the unified sitemap for a domain. Returns all discovered URLs from every scan source (gobuster, zap, playwright, nuclei, katana, nikto, content-extraction, etc.) with HTTP methods, status codes, finding counts, severity levels, and discovered parameters. Use this to understand the attack surface of a web application.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to search, e.g. 'demo.testfire.net'"},
                    "asset_id": {"type": "string", "description": "Filter by asset UUID (alternative to domain)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_params",
            "description": "Search discovered parameters (URL query params, POST body params, form fields, JSON body keys) found during web scanning. Returns parameter names, types (string, integer, boolean, password, uuid, email, path, encoded), URL patterns, HTTP methods, locations (query, body, json_body), and sample values. Use this to identify injection points, authentication forms, and hidden parameters.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url_pattern": {"type": "string", "description": "Filter by URL pattern (partial match)"},
                    "param_name": {"type": "string", "description": "Search by parameter name (partial match)"},
                    "param_type": {"type": "string", "description": "Filter by type: string, integer, boolean, password, uuid, email, path, encoded"},
                    "limit": {"type": "integer", "description": "Max results (default 100)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_content_intel",
            "description": "Get content intelligence summary for scanned targets: total emails found, exposed API keys/secrets, internal paths, API endpoints, technology indicators, sensitive comments, hidden form inputs, interesting files (PDFs, configs, backups), and file metadata (exiftool results with author/GPS/hostname disclosure). Use this to understand what sensitive data was discovered during content analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_id": {"type": "string", "description": "Filter by asset UUID"},
                },
                "required": [],
            },
        },
    },
]


# ── Dynamic MCP Tool Discovery ──────────────────────────

MCP_HOST = os.environ.get("MCP_STREAMABLE_HOST", "mcp-streamable")
# FastMCP streamable-http transport speaks plain HTTP. Override only if you wrap
# the MCP servers behind a TLS proxy.
MCP_SCHEME = os.environ.get("MCP_STREAMABLE_SCHEME", "http")
_mcp_tools_cache: list[dict] = []
_mcp_tools_loaded = False

# Names of tools already defined in TOOLS above — skip these
_BUILTIN_TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


def _parse_sse_json(resp) -> dict:
    """Parse MCP response — handles both JSON and SSE."""
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        for line in resp.text.split("\n"):
            line = line.strip()
            if line.startswith("data: "):
                try:
                    return json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
        return {}
    try:
        return resp.json()
    except Exception:
        return {}


def _discover_sse_server_tools(server_name: str, sse_url: str) -> list[dict]:
    """Discover tools from an SSE-transport MCP server.

    SSE protocol: GET / → long-lived stream with 'endpoint' event, then
    POST JSON-RPC to message URL. Responses arrive as 'message' events on
    the SSE stream (POST returns 202 Accepted).
    """
    import threading
    import queue

    tools = []
    try:
        from httpx_sse import connect_sse
        from urllib.parse import urljoin

        response_queue = queue.Queue()
        message_url_holder = [None]
        stop_event = threading.Event()

        def sse_listener():
            """Background thread: reads SSE events and pushes JSON-RPC responses."""
            try:
                with httpx.Client(verify=False, timeout=30) as sse_client:
                    with connect_sse(sse_client, "GET", sse_url) as event_source:
                        for event in event_source.iter_sse():
                            if stop_event.is_set():
                                break
                            if event.event == "endpoint":
                                endpoint = event.data.strip()
                                base = sse_url.rsplit("/", 1)[0] + "/"
                                message_url_holder[0] = urljoin(base, endpoint)
                                response_queue.put(("endpoint", message_url_holder[0]))
                            elif event.event == "message":
                                try:
                                    response_queue.put(("message", json.loads(event.data)))
                                except json.JSONDecodeError:
                                    pass
            except Exception as e:
                response_queue.put(("error", str(e)))

        # Start SSE listener in background
        listener = threading.Thread(target=sse_listener, daemon=True)
        listener.start()

        # Wait for endpoint event
        try:
            event_type, data = response_queue.get(timeout=10)
        except queue.Empty:
            log.warning("SSE server %s: timeout waiting for endpoint event", server_name)
            stop_event.set()
            return []

        if event_type != "endpoint":
            log.warning("SSE server %s: unexpected first event: %s", server_name, event_type)
            stop_event.set()
            return []

        message_url = data

        with httpx.Client(verify=False, timeout=10) as client:
            # Initialize (response comes via SSE stream)
            client.post(
                message_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "chat-bridge", "version": "1.0"}}},
            )
            # Wait for initialize response
            try:
                response_queue.get(timeout=5)
            except queue.Empty:
                pass

            # Send initialized notification
            client.post(
                message_url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )

            # List tools
            client.post(
                message_url,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )

            # Wait for tools/list response
            tools_data = None
            try:
                event_type, data = response_queue.get(timeout=10)
                if event_type == "message":
                    tools_data = data
            except queue.Empty:
                log.warning("SSE server %s: timeout waiting for tools/list", server_name)

        stop_event.set()

        if not tools_data:
            return []

        result = tools_data.get("result", tools_data)
        for tool in result.get("tools", []):
            name = tool["name"]
            if name in _BUILTIN_TOOL_NAMES:
                continue
            desc = tool.get("description", "").split("\n")[0].strip()[:300]
            params = _mcp_schema_to_ollama(tool.get("inputSchema", {}))
            # Enrich Burp tool parameters with descriptions
            enrichments = BURP_PARAM_ENRICHMENTS.get(name)
            if enrichments:
                for pname, pdesc in enrichments.items():
                    if pname in params.get("properties", {}):
                        params["properties"][pname]["description"] = pdesc
            extra_req = BURP_EXTRA_REQUIRED.get(name, [])
            if extra_req:
                existing = set(params.get("required", []))
                params["required"] = list(existing | set(extra_req))
            tools.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": f"[MCP:{server_name}] {desc}",
                    "parameters": params,
                },
                "_mcp_server": server_name,
                "_mcp_port": 0,
                "_mcp_url": sse_url,
                "_mcp_transport": "sse",
            })
        log.info("Discovered %d SSE MCP tools from %s (%s)", len(tools), server_name, sse_url)
    except Exception as e:
        log.debug("Failed to discover SSE MCP tools from %s (%s): %s", server_name, sse_url, e)
    return tools


def _mcp_schema_to_ollama(input_schema: dict) -> dict:
    """Convert MCP inputSchema (JSON Schema) to Ollama tool parameters format."""
    props = input_schema.get("properties", {})
    required = input_schema.get("required", [])
    ollama_props = {}
    for name, schema in props.items():
        ollama_props[name] = {
            "type": schema.get("type", "string"),
            "description": schema.get("description", ""),
        }
        if "enum" in schema:
            ollama_props[name]["enum"] = schema["enum"]
    return {
        "type": "object",
        "properties": ollama_props,
        "required": required,
    }


def _discover_mcp_tools() -> list[dict]:
    """Discover tools from MCP servers and convert to Ollama format."""
    # Built-in + third-party servers — (name, port, url_or_None)
    servers = [
        ("sessions", 9016, None), ("scanning", 9017, None), ("recon", 9018, None),
        ("exploit", 9019, None), ("credentials", 9020, None), ("pipelines", 9021, None),
        ("burp", 9022, None), ("zap", 9023, None),
    ]

    # Load third-party from registry
    # servers entries: (name, port, url_or_None)
    sse_servers = []  # SSE-transport servers handled separately
    try:
        import yaml
        registry_path = os.environ.get("MCP_REGISTRY_PATH", "/mcp/third_party/registry.yaml")
        if os.path.exists(registry_path):
            with open(registry_path) as f:
                data = yaml.safe_load(f) or {}
            for srv in (data.get("servers") or []):
                if srv.get("enabled", False):
                    if srv.get("transport") == "sse" and srv.get("url"):
                        sse_servers.append((srv["name"], srv["url"]))
                    else:
                        servers.append((srv["name"], srv.get("port", 9030), srv.get("url")))
    except Exception:
        pass

    tools = []

    # Discover from SSE-transport servers (e.g. Burp Suite MCP)
    for server_name, sse_url in sse_servers:
        tools.extend(_discover_sse_server_tools(server_name, sse_url))

    for entry in servers:
        server_name, port = entry[0], entry[1]
        direct_url = entry[2] if len(entry) > 2 else None
        base_url = direct_url or f"{MCP_SCHEME}://{MCP_HOST}:{port}/mcp"
        try:
            # Initialize
            httpx.post(
                base_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "chat-bridge", "version": "1.0"}}},
                headers={"Accept": "application/json, text/event-stream"},
                timeout=5,
            )
            # List tools
            resp = httpx.post(
                base_url,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers={"Accept": "application/json, text/event-stream"},
                timeout=5,
            )
            if resp.status_code != 200:
                continue

            data = _parse_sse_json(resp)
            result = data.get("result", data)
            for tool in result.get("tools", []):
                name = tool["name"]
                if name in _BUILTIN_TOOL_NAMES:
                    continue  # Skip duplicates
                desc = tool.get("description", "").split("\n")[0].strip()[:300]
                tool_entry = {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": f"[MCP:{server_name}] {desc}",
                        "parameters": _mcp_schema_to_ollama(tool.get("inputSchema", {})),
                    },
                    "_mcp_server": server_name,
                    "_mcp_port": port,
                }
                if direct_url:
                    tool_entry["_mcp_url"] = direct_url
                tools.append(tool_entry)
            log.info("Discovered %d MCP tools from %s (%s)", len(result.get("tools", [])), server_name, base_url)
        except Exception as e:
            log.debug("Failed to discover MCP tools from %s (%s): %s", server_name, base_url, e)

    # Also discover tools from remote Kali MCP nodes (via node-manager proxy)
    try:
        NODE_MANAGER_URL = os.environ.get("NODE_MANAGER_URL", "https://node-manager:8027")
        resp = httpx.get(f"{NODE_MANAGER_URL}/mcp-nodes", timeout=3)
        if resp.status_code == 200:
            mcp_nodes = resp.json().get("nodes", [])
            for node in mcp_nodes:
                if not node.get("active"):
                    continue
                node_id = node["node_id"]
                node_name = node.get("node_name", node_id[:8])
                server_label = f"kali@{node_name}"
                try:
                    resp2 = httpx.post(
                        f"{NODE_MANAGER_URL}/ssh/{node_id}/mcp-proxy",
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                        timeout=10,
                    )
                    if resp2.status_code == 200:
                        data = resp2.json()
                        result = data.get("result", data)
                        for tool in result.get("tools", []):
                            name = tool["name"]
                            if name in _BUILTIN_TOOL_NAMES:
                                continue
                            desc = tool.get("description", "").split("\n")[0].strip()[:300]
                            tools.append({
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "description": f"[MCP:{server_label}] {desc}",
                                    "parameters": _mcp_schema_to_ollama(tool.get("inputSchema", {})),
                                },
                                "_mcp_server": server_label,
                                "_mcp_port": node.get("local_port", 0),
                                "_mcp_node_id": node_id,
                            })
                        log.info("Discovered %d tools from remote Kali MCP on %s", len(result.get("tools", [])), node_name)
                except Exception as e:
                    log.debug("Failed to discover tools from Kali MCP on %s: %s", node_name, e)
    except Exception as e:
        log.debug("Failed to query MCP nodes: %s", e)

    log.info("Total dynamic MCP tools for chat: %d", len(tools))
    return tools


def load_mcp_tools():
    """Load MCP tools into cache (called once at startup or on demand)."""
    global _mcp_tools_cache, _mcp_tools_loaded
    _mcp_tools_cache = _discover_mcp_tools()
    _mcp_tools_loaded = True
    return _mcp_tools_cache


def reload_mcp_tools():
    """Force rediscovery of all MCP tools (call after starting/stopping remote MCP)."""
    global _mcp_tools_cache, _mcp_tools_loaded
    _mcp_tools_loaded = False
    return load_mcp_tools()


def get_all_tools() -> list[dict]:
    """Get all tools: built-in + dynamic MCP tools."""
    global _mcp_tools_loaded
    if not _mcp_tools_loaded:
        load_mcp_tools()
    return TOOLS + _mcp_tools_cache


def get_mcp_tool_info(tool_name: str) -> dict | None:
    """Get MCP server info for a dynamic tool."""
    for t in _mcp_tools_cache:
        if t["function"]["name"] == tool_name:
            info = {"server": t["_mcp_server"], "port": t["_mcp_port"]}
            if "_mcp_url" in t:
                info["url"] = t["_mcp_url"]
            if "_mcp_transport" in t:
                info["transport"] = t["_mcp_transport"]
            if "_mcp_message_url" in t:
                info["message_url"] = t["_mcp_message_url"]
            if "_mcp_node_id" in t:
                info["node_id"] = t["_mcp_node_id"]
            return info
    return None
