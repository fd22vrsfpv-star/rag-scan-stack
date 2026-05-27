# RAG Scan Stack — Beta Tester Guide

**Pentest Workflow Automation Platform**
*Collect, normalize, triage, and export findings from 30+ security tools into a unified workflow*

---

## What This Is

A Docker-based platform that runs your pentest scans, collects all the data in one place, and feeds it into your manual testing tools (Burp Suite, ZAP). Instead of juggling terminal output from 15 different tools, everything flows into a single dashboard with cross-tool deduplication, CVE matching, and one-click export.

**For pentesters who want to:** scan fast → triage smart → test manually → report clean.

---

## Quick Start

```bash
git clone <repo>
cd rag-scan-stack
./scripts/setup.sh        # First time only
./scripts/update.sh       # Pull, build, start, DB schema, LLM model
```

Dashboard: **https://localhost:3002**

---

## Feature Walkthrough

### 1. Dashboard — Mission Control

![Dashboard](screenshots/01-dashboard.png)

At-a-glance view of your engagement:
- **Asset count** — discovered hosts, open ports, subdomains
- **Finding summary** — by severity across all tools
- **Recent scan activity** — what ran, what completed
- **Quick actions** — jump to any tool or page

---

### 2. Scan Launcher — 30+ Tools, One Interface

![Scan Launcher](screenshots/02-scan-launcher.png)

Launch any scan from the UI — no terminal needed:

| Category | Tools |
|----------|-------|
| **Port Scanning** | Nmap (with NSE script presets), Masscan, Naabu |
| **Web** | ZAP, Nuclei, Katana, Gobuster, ffuf, Playwright, Nikto, wafw00f |
| **Recon** | Subfinder, Amass, httpx, dnsx, tlsx, WhatWeb, GoWitness, CRT.sh |
| **Credentials** | Brutus (multi-protocol brute force), Hashcat |
| **AD/Internal** | NetExec, Impacket |
| **Cloud** | Prowler, ScoutSuite, CloudFox, AzureHound, Pacu |

**Key features:**
- **SOCKS proxy support** — route scans through SSH tunnels to internal networks
- **"Route through Burp" toggle** — sends tool traffic through Burp's proxy in real-time
- **Nmap options** — service detection, version intensity, OS detection, NSE script presets (vuln+safe+enum), timing templates
- **Scope-aware** — scans auto-link to your engagement scope

---

### 3. Scan Monitor — Live Progress

![Scan Monitor](screenshots/03-scan-monitor.png)

- Real-time progress for all running scans
- Command tracking — see exactly what ran
- Results summary when complete
- Cancel/stop running scans
- Stale scan cleanup

---

### 4. Assets — What You've Found

![Assets](screenshots/04-assets.png)

All discovered assets in one place:
- **IP/hostname** with reverse DNS lookup
- **Open ports** with service/version/banner
- **Subdomains** from all recon sources
- **Credentials** — discovered, brute-forced, or manually added
- **Per-asset drill-down** — click any asset to see ports, vulns, screenshots, recon intel

---

### 5. Software Inventory — Version Tracking + CVE Matching

![Software](screenshots/05-assets-software.png)

Aggregates software versions detected across **11 sources** (Nmap, httpx, WhatWeb, wafw00f, ZAP, Nuclei, Katana JS libraries):

- **Grouped by hostname** — expand to see all detected software
- **CVE/Exploit flags** — cross-references against CVE database + ExploitDB (46,000+ exploits)
- **Age-based confidence** — old CVEs get lower confidence (configurable)
- **Bulk dismiss** — mark false positives with feedback training
- **"CVE/Exploits Only" filter** — show only flagged software, sorted by CVE count

---

### 6. Findings Explorer — Cross-Tool Triage

![Findings](screenshots/06-findings.png)

All findings from all tools, normalized and deduplicated:
- **Filter by** severity, tool, host, port, date, status
- **Finding detail** — evidence, description, solution, CWE, CVE references
- **Tags** — add custom tags for workflow tracking
- **Fingerprint dedup** — same finding from different tools appears once

---

### 7. Follow-Ups — Agent-Flagged Issues

![Follow-Ups](screenshots/07-follow-ups.png)

The OSINT agent runs detection rules and flags items for manual review:
- **CVE matches** on detected software versions
- **Expired certificates**, self-signed certs on HTTPS
- **Login pages without WAF**
- **Open redirects**, exposed API endpoints, sensitive parameters
- **Grouped by finding** — "Vulnerable: IIS 10.0" rolls up all affected hosts
- **Dismiss with feedback** — trains the agent to skip similar in future

---

### 8. Content Intelligence — What's Inside the Apps

![Content Intel](screenshots/08-content-intel.png)

Extracted from crawled pages:
- **API Endpoints** — method, type (REST/GraphQL/WebSocket), confidence, with filter buttons
- **Login Pages** — with credential guess suggestions
- **Emails, Names** — from page content and metadata
- **Exposed Keys/Secrets** — API keys, tokens found in JS/HTML
- **Tech Indicators** — frameworks, libraries, server software
- **Grouped by hostname** with expand/collapse and follow-up flag tags

---

### 9. Reports — Export to Your Tools

![Reports](screenshots/10-reports.png)

**Export formats:**
- **HAR File** — import into Burp Suite (via HARBringer) or ZAP with real finding data
- **URL List** — seed Burp Spider, ZAP, nuclei, ffuf
- **SARIF** — VS Code, GitHub Code Scanning, Azure DevOps
- **PDF Report** — client deliverable with severity breakdown

**Proxy Replay** — the killer feature:
- Sends all discovered URLs, parameters, auth tokens, and attack payloads through Burp/ZAP in 4 phases
- **Dry run** — preview what would be sent without touching the target
- **Confirmation dialog** — warns before sending live traffic
- Burp's sitemap gets populated with real request/response pairs for manual testing
- Auto-configure Burp's SOCKS proxy from your SSH tunnel nodes

---

### 10. Engagements — Organize Your Work

![Engagements](screenshots/11-engagements.png)

- Create engagements with client, scope, methodology
- Status tracking: planning → active → paused → reporting → complete
- Notes per engagement
- All scans, findings, follow-ups linked to the engagement
- Campaign timeline with scan events

---

### 11. Scope Intelligence — What's In / Out

![Scope](screenshots/12-scope.png)

- Define scope with domain patterns, IPs, CIDRs
- Auto-classify discovered assets as in-scope/out-of-scope
- Scope filter applied across all pages
- Add-to-scope from any finding or asset

---

### 12. Nodes — Remote Scanning Infrastructure

![Nodes](screenshots/13-nodes.png)

Manage remote scan nodes connected via SSH tunnels:
- **SOCKS proxies** — route any scan through remote nodes
- **Remote command execution** — run tools on the node directly
- **SCP file transfer** — upload/download tools and results
- **Auto-connect** on startup
- **WSL2 port forwarding** helper for exposing tunnels to Burp on another machine

---

### 13. Services — Health & Diagnostics

![Services](screenshots/14-services.png)

- **Health status** for all 20+ services
- **Per-service logs** — click "Logs" to see recent container output inline
- **System Check** — verify DB schema, service connectivity, end-to-end tests
- **Fix Issues** — auto-repair missing tables/columns
- **Ollama diagnostics** — model status, VRAM usage, GPU info
- **Tool Updates** — update Nuclei templates, ExploitDB with one click

---

### 14. Settings — Tune Everything

![Settings](screenshots/15-settings.png)

- **Burp Suite REST API** — connect to Burp Pro for headless scanning
- **CVE Rule Tuning** — age penalties, skip products, confidence thresholds
- **Proxy configuration** — Burp/ZAP proxy URL with connection test
- **LLM backend** — Ollama, OpenAI, Anthropic, Azure
- **MCP Servers** — import third-party MCP tools
- **API Keys** — manage keys for external services
- **Scan defaults** — per-tool default options

---

### 15. Delta Compare — What Changed Between Scans

![Delta](screenshots/16-delta.png)

Compare two scan runs to see:
- **New findings** — appeared since last scan
- **Resolved** — gone since last scan
- **Unchanged** — still present
- **Dedup report** — cross-tool duplicate analysis

---

### 16. API Tester — Swagger/OpenAPI Import

![API Tester](screenshots/17-api-tester.png)

Import OpenAPI/Swagger specs and test API endpoints:
- Auto-discover endpoints from spec
- Execute requests with parameter configs
- Proxy through Burp for interception
- Named parameter configs per collection

---

## Burp Suite Integration

Three ways to get data into Burp:

1. **Proxy Replay** — sends real HTTP requests through Burp's proxy (Reports page)
2. **"Route through Burp" toggle** — on any scan, routes tool traffic through Burp live
3. **HAR Export** — import via HARBringer extension in Burp
4. **Burp REST API** — headless scanning via Burp Pro's API

---

## Architecture

```
Browser → Dashboard (React/TS) → BFF (FastAPI) → Services
                                                    ├── rag-api (core API + DB)
                                                    ├── nmap_scanner
                                                    ├── web-scanner (ZAP pipeline)
                                                    ├── nuclei-runner
                                                    ├── osint-runner (15+ tools)
                                                    ├── pd-runner (katana, httpx, ffuf)
                                                    ├── node-manager (SSH tunnels)
                                                    ├── autogen-agents (AI agent sessions)
                                                    ├── ollama (LLM - Gemma 4 26B)
                                                    └── 10+ more services
```

- **All traffic TLS-encrypted** (self-signed certs)
- **34 ETL parsers** — normalize output from every tool
- **PostgreSQL** with RAG vector search
- **Docker Compose** — single `docker compose up -d` deployment
- **6 MCP servers** for AI tool integration

---

## Getting Started for Beta Testers

```bash
# Clone and setup
git clone <repo>
cd rag-scan-stack
./scripts/update.sh

# Open dashboard
# https://localhost:3002

# Workflow:
# 1. Create an engagement (Engagements page)
# 2. Define scope (Scope page)
# 3. Run recon scans (Scan Launcher → Recon)
# 4. Run web scans (Scan Launcher → Web)
# 5. Review findings (Findings, Follow-Ups, Software)
# 6. Export to Burp (Reports → Proxy Replay or HAR)
# 7. Manual testing in Burp
# 8. Generate report (Reports → Export PDF)
```

---

## Feedback

Report issues or suggestions at the project repository. Use the Follow-Ups page feedback mechanism to help train the detection agent — your dismiss/accept actions improve future results.
