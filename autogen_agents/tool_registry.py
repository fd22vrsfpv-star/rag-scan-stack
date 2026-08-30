"""The agent tool registry — the single source of truth for what an LLM can call.

Generated once from the `register_for_llm(name=..., description=...)(fn)` calls in
the AutoGen `pentest_agents.PentestTeam` when AutoGen was retired
(Docs/LANGGRAPH_MIGRATION_PLAN.md, Phase 5), so no tool and no curated
description was lost in the move: 49 distinct tools, every one with the
description the model had been seeing.

Why a declarative list rather than the old arrangement:

  * The roster used to exist ONLY as a side effect of constructing AutoGen
    agents, so `langgraph_tools` had to PARSE `pentest_agents.py` to find it.
    Deleting AutoGen would have deleted the tool surface with it.
  * The descriptions are what the model actually reads when choosing a tool, and
    they were curated per tool over time. `langgraph_tools` had been substituting
    `inspect.getdoc(fn)` instead — so LangGraph agents were choosing tools from
    the Python docstring, not from the tuned description. This module ends that
    divergence: one description, used by every consumer.
  * A tool registered against several agents appeared several times (60
    registrations for 49 tools). Here each tool appears exactly once, and
    `tests/test_tool_registry.py` fails if that stops being true.

Tool BODIES are unchanged and still live in `scan_tools`, so the scope gate,
MAX_CONCURRENT_SCANS and webhook contracts are identical to before.

Adding a tool: import the body, add one ToolSpec entry. Nothing else.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

import scan_tools


@dataclass(frozen=True)
class ToolSpec:
    """One callable an LLM may invoke.

    `description` is the LLM-facing text — it decides whether the model picks
    this tool, so it is part of the contract, not a comment.
    """
    name: str
    description: str
    func: Callable


TOOL_SPECS: List[ToolSpec] = [
    ToolSpec(
        name="get_session_scan_status",
        description=(
            "Check status of ALL scans in this session. No parameters needed. Use this to "
            "see what's running, completed, or failed."
        ),
        func=scan_tools.get_session_scan_status,
    ),
    ToolSpec(
        name="get_scan_recommendations",
        description=(
            "Get AI-powered scan recommendations based on discovered services. Call this "
            "after full_scan completes to decide what follow-up scans to run. Pass a "
            "context string describing discovered services/ports."
        ),
        func=scan_tools.get_scan_recommendations,
    ),
    ToolSpec(
        name="analyze_attack_surface",
        description=(
            "Enumerate ONE host's full attack surface as structured JSON: the "
            "MITRE-mapped attack vectors, its open ports/services, web-finding "
            "count, and per-service tool/methodology recommendations (including "
            "ingested attack-path knowledge). Pass target_host to focus a host, "
            "or omit it to use the highest-risk host. This is the read-only "
            "'what could be attacked here' view a surface-test agent starts from."
        ),
        func=scan_tools.analyze_attack_surface,
    ),
    ToolSpec(
        name="get_wstg_guidance",
        description=(
            "Look up the OWASP WSTG-guided test for a SPECIFIC web finding. "
            "Pass the finding's issue_type / cwe / name / nuclei_tags (and "
            "optionally target + url) and get back the matched WSTG test spec "
            "(tier, category, tool, command, structured assertion) plus the "
            "'how to test' methodology prose. READ-ONLY — it dispatches nothing; "
            "it tells you HOW to prove a web finding so you can build a concrete "
            "security test for it."
        ),
        func=scan_tools.get_wstg_guidance,
    ),
    ToolSpec(
        name="get_exploitdb_guidance",
        description=(
            "Read ExploitDB writeups/PoCs relevant to a finding, to build a test "
            "from them. Search by CVE (best), free text, or a specific EDB id; "
            "returns matching entries plus the top writeup's text. READ-ONLY — "
            "reads the local exploit DB, runs nothing. Guidance for synthesizing "
            "a test (most ExploitDB-derived tests are impactful, approval-gated)."
        ),
        func=scan_tools.get_exploitdb_guidance,
    ),
    ToolSpec(
        name="get_tool_recommendations",
        description=(
            "Get the CONCRETE tests to run against a discovered service, as "
            "structured data. Pass service and/or port. Returns tools[] with "
            "ready command templates ({target} placeholder), metasploit[] "
            "modules, nuclei_tags[], common_vulns[] and rag_context (ingested "
            "methodology for that service). Prefer this over "
            "get_scan_recommendations when you know the service/port and need "
            "to decide what to actually run — that one answers a free-text "
            "question with a paragraph, this one returns the commands. Service "
            "aliases resolve, so https/http-proxy/ssl-http all return the web "
            "guidance and microsoft-ds returns SMB."
        ),
        func=scan_tools.get_tool_recommendations,
    ),
    ToolSpec(
        name="get_attack_vectors",
        description=(
            "Get the prioritized attack vector map: findings mapped to MITRE ATT&CK "
            "techniques with a unified risk score, ranked highest-risk first. Use this to "
            "choose the NEXT-BEST action — which finding/technique/target has the highest "
            "attack value. Prefer it over raw scan recommendations when deciding what to "
            "attack or investigate next."
        ),
        func=scan_tools.get_attack_vectors,
    ),
    ToolSpec(
        name="query_assets",
        description="Query discovered assets from database",
        func=scan_tools.query_assets,
    ),
    ToolSpec(
        name="query_open_ports",
        description=(
            "Query open ports from database. The result also carries 'operator_guidance': "
            "rules the operator authored for the services found, often ingested from a "
            "walkthrough of a comparable target. When it is present, follow it when "
            "choosing the next tool — it names techniques proven against these services "
            "and takes priority over generic defaults."
        ),
        func=scan_tools.query_open_ports,
    ),
    ToolSpec(
        name="start_subfinder",
        description=(
            "Start passive subdomain enumeration using Subfinder. Discovers subdomains "
            "via OSINT sources."
        ),
        func=scan_tools.start_subfinder,
    ),
    ToolSpec(
        name="start_dnsx",
        description=(
            "Start DNS resolution and enumeration with dnsx. Resolves domains to IPs and "
            "discovers DNS records (A, AAAA, CNAME, MX, NS)."
        ),
        func=scan_tools.start_dnsx,
    ),
    ToolSpec(
        name="start_asnmap",
        description=(
            "Start ASN to CIDR mapping with asnmap. Maps IPs/domains/ASNs to their CIDR "
            "ranges and organizations."
        ),
        func=scan_tools.start_asnmap,
    ),
    ToolSpec(
        name="start_uncover",
        description=(
            "Search Shodan/Censys/Fofa with uncover. Discovers exposed hosts and services "
            "via passive search engines."
        ),
        func=scan_tools.start_uncover,
    ),
    ToolSpec(
        name="start_cloudlist",
        description=(
            "Enumerate cloud provider IPs with cloudlist. Lists IPs from AWS, GCP, Azure, "
            "etc."
        ),
        func=scan_tools.start_cloudlist,
    ),
    ToolSpec(
        name="start_subdomain_takeover",
        description=(
            "Detect subdomain takeover vulnerabilities. CRITICAL: Run after subdomain "
            "enumeration to find unclaimed services (AWS S3, Azure, GitHub Pages, etc.)."
        ),
        func=scan_tools.start_subdomain_takeover,
    ),
    ToolSpec(
        name="get_osint_job_status",
        description=(
            "Check status of an OSINT Runner job (subfinder, dnsx, asnmap, uncover, "
            "cloudlist, subdomain-takeover)."
        ),
        func=scan_tools.get_osint_job_status,
    ),
    ToolSpec(
        name="start_passive_recon",
        description=(
            "Start a passive-only recon pipeline. Chains "
            "subfinder→findomain→dnsdumpster→whois→reverse- "
            "whois→dnsx→crtsh→httpx→tlsx→cert-chain→gau→katana→gowitness→whatweb. No "
            "active scanning."
        ),
        func=scan_tools.start_passive_recon,
    ),
    ToolSpec(
        name="get_passive_recon_plan",
        description="Preview the execution plan for a passive recon pipeline without running it.",
        func=scan_tools.get_passive_recon_plan,
    ),
    ToolSpec(
        name="get_nmap_job_status",
        description=(
            "Check status of an nmap/masscan job. ALWAYS call this after starting a scan "
            "to monitor progress and wait for completion."
        ),
        func=scan_tools.get_nmap_job_status,
    ),
    ToolSpec(
        name="get_web_scan_job_status",
        description=(
            "Check status of a web scan job (Gobuster/ZAP). Call after starting a web "
            "scan."
        ),
        func=scan_tools.get_web_scan_job_status,
    ),
    ToolSpec(
        name="get_nuclei_job_status",
        description="Check status of a Nuclei vulnerability scan job.",
        func=scan_tools.get_nuclei_job_status,
    ),
    ToolSpec(
        name="get_playwright_job_status",
        description="Check status of a Playwright browser security scan.",
        func=scan_tools.get_playwright_job_status,
    ),
    ToolSpec(
        name="wait_for_job_completion",
        description=(
            "Wait for a scan job to complete (polls until done or timeout). Use for "
            "critical scans that must finish before proceeding."
        ),
        func=scan_tools.wait_for_job_completion,
    ),
    ToolSpec(
        name="get_all_active_jobs",
        description=(
            "Get status of all active scan jobs across all scanners. Use to see what's "
            "currently running."
        ),
        func=scan_tools.get_all_active_jobs,
    ),
    ToolSpec(
        name="get_pd_job_status",
        description=(
            "Check status of a ProjectDiscovery tool job (subfinder, httpx, naabu, "
            "katana, brutus, etc.)."
        ),
        func=scan_tools.get_pd_job_status,
    ),
    ToolSpec(
        name="query_vulnerabilities",
        description=(
            "Query vulnerabilities from database. Parameters: severity "
            "(info/low/medium/high/critical), limit (int). Does NOT accept 'services', "
            "'target', or 'ip' filters."
        ),
        func=scan_tools.query_vulnerabilities,
    ),
    ToolSpec(
        name="query_exploitdb",
        description="Search ExploitDB for exploits related to a vulnerability",
        func=scan_tools.query_exploitdb,
    ),
    ToolSpec(
        name="search_all_findings",
        description=(
            "Unified search across ALL finding types (vulns, web, recon, credentials). "
            "Returns findings with severity, source, evidence. Call this FIRST for a "
            "complete picture."
        ),
        func=scan_tools.search_all_findings,
    ),
    ToolSpec(
        name="get_web_findings",
        description=(
            "Get web application findings: Gobuster directories, ZAP vulnerabilities, "
            "Playwright browser results."
        ),
        func=scan_tools.get_web_findings,
    ),
    ToolSpec(
        name="query_credential_findings",
        description=(
            "Get credential/brute-force testing results from Brutus: valid/invalid "
            "logins, protocols tested."
        ),
        func=scan_tools.query_credential_findings,
    ),
    ToolSpec(
        name="match_vuln_to_exploits",
        description="Match a service/version to known exploits in ExploitDB and Metasploit",
        func=scan_tools.match_vuln_to_exploits,
    ),
    ToolSpec(
        name="search_msf_modules",
        description="Search Metasploit module database by query, CVE, or platform",
        func=scan_tools.search_msf_modules_tool,
    ),
    ToolSpec(
        name="customize_exploit",
        description="Customize an exploit with target-specific parameters (RHOST, RPORT, etc.)",
        func=scan_tools.customize_exploit,
    ),
    ToolSpec(
        name="queue_exploit_for_approval",
        description="Queue a customized exploit for human approval before execution",
        func=scan_tools.queue_exploit_for_approval,
    ),
    ToolSpec(
        name="get_exploit_approval_status",
        description="Check if a pending exploit has been approved",
        func=scan_tools.get_exploit_approval_status,
    ),
    ToolSpec(
        name="list_pending_exploits",
        description="List all pending exploits awaiting approval",
        func=scan_tools.list_pending_exploits_tool,
    ),
    ToolSpec(
        name="execute_approved_exploit",
        description="Execute an exploit that has been approved by a human",
        func=scan_tools.execute_approved_exploit,
    ),
    ToolSpec(
        name="start_full_scan",
        description=(
            "Start a quick port scan (1-1000,8080,8443) with service detection. "
            "RECOMMENDED first step. Always follow with deep port and UDP scans."
        ),
        func=scan_tools.start_full_scan,
    ),
    ToolSpec(
        name="start_deep_port_scan",
        description=(
            "Start a deep port scan (1001-65535) with service detection. CRITICAL: ALWAYS "
            "run after web scans complete to find high ports."
        ),
        func=scan_tools.start_deep_port_scan,
    ),
    ToolSpec(
        name="start_pipeline_scan",
        description=(
            "Start web scan pipeline (Gobuster→Playwright→ZAP→Nuclei→Nikto). ONLY use if "
            "HTTP/HTTPS ports are open."
        ),
        func=scan_tools.start_pipeline_scan,
    ),
    ToolSpec(
        name="start_smb_vuln_scan",
        description=(
            "Start SMB vulnerability scan (CVE-2007-2447, MS17-010, SambaCry). ONLY use "
            "if ports 139/445 are open."
        ),
        func=scan_tools.start_smb_vuln_scan,
    ),
    ToolSpec(
        name="start_credential_check",
        description=(
            "Test for default/weak credentials on auth services. ONLY use for services "
            "actually discovered. Pass plain IP as target (e.g. '192.168.1.150'), NOT "
            "URLs. Check status with get_nmap_job_status."
        ),
        func=scan_tools.start_credential_check,
    ),
    ToolSpec(
        name="start_masscan",
        description="Start a fast Masscan TCP port scan for a specific port range.",
        func=scan_tools.start_masscan,
    ),
    ToolSpec(
        name="start_nmap_scan",
        description="Start an Nmap service detection scan. Run AFTER masscan finds open ports.",
        func=scan_tools.start_nmap_scan,
    ),
    ToolSpec(
        name="start_udp_scan",
        description=(
            "Start a UDP port scan (DNS, SNMP, NTP, DHCP). CRITICAL: ALWAYS run after "
            "deep port scan to find UDP services missed by TCP scans."
        ),
        func=scan_tools.start_udp_scan,
    ),
    ToolSpec(
        name="start_web_scan",
        description="Start web scanning with Gobuster and ZAP",
        func=scan_tools.start_web_scan,
    ),
    ToolSpec(
        name="start_nuclei_scan",
        description="Start Nuclei vulnerability scanning",
        func=scan_tools.start_nuclei_scan,
    ),
    ToolSpec(
        name="start_playwright_scan",
        description="Start Playwright browser security scan",
        func=scan_tools.start_playwright_scan,
    ),
    ToolSpec(
        name="start_httpx_probe",
        description=(
            "Start HTTP probing with httpx. Discovers web technologies, status codes, and "
            "titles. Use 'from_db' targets to probe all known web ports."
        ),
        func=scan_tools.start_httpx_probe,
    ),
    ToolSpec(
        name="start_naabu",
        description=(
            "Start fast port scanning with Naabu. Alternative/complement to Masscan for "
            "port discovery."
        ),
        func=scan_tools.start_naabu,
    ),
    ToolSpec(
        name="start_katana",
        description=(
            "Start web crawling with Katana. Discovers URLs, forms, and JS endpoints. Use "
            "'from_db' targets to crawl all known web services."
        ),
        func=scan_tools.start_katana,
    ),
    ToolSpec(
        name="start_brutus",
        description=(
            "Start credential testing with Brutus. Tests SSH, FTP, MySQL, SMB, and other "
            "protocols for weak/default credentials."
        ),
        func=scan_tools.start_brutus,
    ),
    ToolSpec(
        name="get_brutus_job_status",
        description="Check status of a Brutus credential testing job.",
        func=scan_tools.get_brutus_job_status,
    ),
]

# name -> callable / name -> ToolSpec. Built once; both are read by
# langgraph_tools and the MCP bridge.
TOOL_FUNCS: Dict[str, Callable] = {t.name: t.func for t in TOOL_SPECS}
TOOL_BY_NAME: Dict[str, ToolSpec] = {t.name: t for t in TOOL_SPECS}
TOOL_NAMES: List[str] = sorted(TOOL_FUNCS)

# Tools that send traffic at a target. Named here so a phase toolset can be
# checked against a real list instead of a `startswith("start_")` guess, and so
# adding a dispatcher is a visible edit. Bodies remain scope-gated in scan_tools.
DISPATCH_TOOL_NAMES: List[str] = sorted(n for n in TOOL_NAMES if n.startswith("start_"))
