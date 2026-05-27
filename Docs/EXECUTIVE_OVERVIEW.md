# RAG Scan Stack — Executive Overview

**Unified Security Assessment Platform**
*Automate collection, normalize findings, accelerate manual testing*

---

## The Problem

Penetration testers juggle **30+ command-line tools**, each with different output formats, across multiple terminals. Findings get lost in text files, deduplication is manual, and getting data into reporting tools takes hours. Time spent on tool management is time not spent finding vulnerabilities.

**Today's workflow:**
```
Run nmap → parse XML → copy to spreadsheet
Run nuclei → parse JSON → cross-reference CVEs manually
Run ZAP → export report → merge with nmap findings
Run Burp → can't import other tool results
Write report → re-type everything into template
```

---

## The Solution

A single platform that **runs all the tools**, **normalizes all the output**, and **feeds it directly into manual testing workflows**.

![Dashboard](screenshots/01-dashboard.png)

---

## Key Capabilities

### 1. Automated Data Collection — 30+ Integrated Tools

![Scan Launcher](screenshots/02-scan-launcher.png)

One interface to launch any scan. No terminal, no syntax memorization.

| Category | Tools | What It Finds |
|----------|-------|---------------|
| Port Scanning | Nmap, Masscan, Naabu | Open ports, services, versions, OS |
| Web Application | ZAP, Nuclei, Katana, Gobuster, ffuf, Nikto | Vulnerabilities, directories, parameters, APIs |
| Reconnaissance | Subfinder, Amass, httpx, WhatWeb, GoWitness | Subdomains, tech stack, screenshots |
| Credentials | Brutus, Hashcat | Weak passwords, cracked hashes |
| Cloud | Prowler, ScoutSuite, CloudFox, AzureHound | Misconfigurations, IAM issues |
| Internal/AD | NetExec, Impacket | Domain enumeration, lateral movement |

**Impact:** What used to take a tester 2-3 hours of setup runs in minutes with pre-configured options.

---

### 2. Unified Finding Management — Nothing Gets Lost

![Findings](screenshots/06-findings.png)

All findings from every tool land in one database with:

- **Cross-tool deduplication** — the same vulnerability found by Nmap AND Nuclei appears once
- **Normalized severity** — consistent rating across all tools
- **CVE/CWE references** — linked to industry standards
- **Evidence preservation** — raw output, screenshots, request/response data retained

**Impact:** Zero data loss. Every finding is tracked from discovery through remediation.

---

### 3. Software Version Tracking + CVE Matching

![Software](screenshots/05-assets-software.png)

Automatically detects software versions across all assets and cross-references against:
- **CVE Database** — known vulnerabilities with CVSS scores
- **ExploitDB** — 46,000+ public exploits via searchsploit integration
- **Age-based confidence** — older CVEs flagged as lower priority (likely patched)

Testers see which hosts run vulnerable software **before** they start manual testing.

**Impact:** Prioritizes testing effort on the highest-risk targets.

---

### 4. Intelligent Triage — AI-Assisted Follow-Ups

![Follow-Ups](screenshots/07-follow-ups.png)

A detection rules engine automatically flags items requiring human attention:
- Vulnerable software versions with known CVEs
- Expired or self-signed TLS certificates
- Login pages without WAF protection
- Exposed API endpoints, sensitive parameters
- Open redirect vulnerabilities

Testers **dismiss false positives once** — the system learns and skips similar findings in future scans.

**Impact:** Reduces manual triage time. Testers focus on real issues, not noise.

---

### 5. Burp Suite Integration — Bridge to Manual Testing

![Reports](screenshots/10-reports.png)

The platform bridges the gap between automated scanning and manual testing:

- **Proxy Replay** — sends all discovered URLs, parameters, and attack payloads through Burp Suite with real HTTP responses
- **Route Through Burp** — any scan can be configured to proxy traffic through Burp in real-time
- **HAR Export** — import findings into Burp or ZAP via standard format
- **Burp REST API** — headless scanning via Burp Professional

**Impact:** Burp's sitemap is pre-populated with everything the automated scans found. Manual testing starts with full context, not a blank slate.

---

### 6. Remote Scanning Infrastructure

![Nodes](screenshots/13-nodes.png)

Manage remote scan nodes for testing internal networks or routing through different source IPs:

- **SSH tunnel management** — SOCKS proxies to internal networks
- **Remote command execution** — run tools directly on remote nodes
- **Multi-node support** — different nodes for different network segments

**Impact:** Enables internal network testing from a centralized platform without VPN complexity.

---

### 7. Engagement Management + Reporting

![Engagements](screenshots/11-engagements.png)

Full engagement lifecycle:
- **Engagement tracking** — planning through completion with status workflow
- **Scope management** — define what's in/out of scope, auto-classify assets
- **Export formats** — PDF reports, SARIF for CI/CD, CSV for tracking, HAR for tool import
- **Delta comparison** — what changed between scan runs

**Impact:** Consistent deliverables. Findings flow directly into reports without manual copy/paste.

---

### 8. Platform Health + Observability

![Services](screenshots/14-services.png)

Self-monitoring with:
- **Health dashboard** — all 20+ services at a glance
- **Per-service log viewer** — troubleshoot without SSH
- **System diagnostics** — DB schema verification, connectivity checks
- **One-click tool updates** — Nuclei templates, ExploitDB database
- **Auto-fix** — repair common issues automatically

---

## Deployment

| Requirement | Specification |
|-------------|--------------|
| **Platform** | Docker Compose on Linux, WSL2, or macOS |
| **Hardware** | 16GB RAM minimum, 32GB recommended, GPU optional (for AI) |
| **Setup time** | ~15 minutes (automated) |
| **Update** | Single command: `./scripts/update.sh` |

```bash
git clone <repo>
./scripts/update.sh    # Install, build, start — one command
```

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Browser (HTTPS)                                  │
│  └── React Dashboard                              │
│       └── BFF (FastAPI)                           │
│            ├── Core API + PostgreSQL (RAG)         │
│            ├── 10+ Scanner Services               │
│            ├── Node Manager (SSH Tunnels)          │
│            ├── AI Agent (Gemma 4 / Ollama)         │
│            ├── 6 MCP Tool Servers                  │
│            └── 34 ETL Parsers                      │
└──────────────────────────────────────────────────┘
```

- **All internal traffic TLS-encrypted**
- **Self-contained** — no external dependencies except Docker
- **Database** — PostgreSQL with vector search for RAG
- **AI** — local LLM (Gemma 4 26B) for analysis and agent sessions

---

## Competitive Advantage

| Capability | RAG Scan Stack | Manual Workflow | Commercial Platforms |
|------------|---------------|-----------------|---------------------|
| Tool count | 30+ integrated | Individual tools | 5-10 typically |
| Setup time | 15 minutes | Hours per tool | Days + licensing |
| Cross-tool dedup | Automatic | Manual | Partial |
| CVE matching | Automated + ExploitDB | Manual lookup | Basic |
| Burp integration | Proxy replay + HAR + REST API | Manual import | None |
| AI triage | Built-in agent | None | Add-on cost |
| Cost | Open source | Free (time cost) | $10K-100K+/year |
| Data ownership | Local / self-hosted | Local | Vendor cloud |

---

## Roadmap

- **Jira/GitLab integration** — push findings to issue trackers
- **Collaborative testing** — multi-user engagement support
- **Compliance mapping** — OWASP, NIST, PCI-DSS finding classification
- **Custom detection rules** — YAML-based, per-engagement
- **Automated retesting** — verify remediation against previous findings

---

## Next Steps

1. **Beta access** — request access to the repository
2. **Setup** — run `./scripts/update.sh` on your test machine
3. **Try it** — create an engagement, define scope, run a recon scan
4. **Feedback** — use the Follow-Ups feedback mechanism or report issues in the repo

---

*Built for pentesters, by pentesters. Authorized security testing only.*
