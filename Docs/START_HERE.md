# Start Here

Welcome to the Pentest Dashboard — a workflow collector for authorized security testing. This guide walks you through getting started, running your first scan, and reviewing findings.

## Quick Overview

The dashboard collects output from 30+ security tools, normalizes findings into a unified database, and lets you triage, export, and hand off to manual testing tools like Burp Suite and ZAP.

**Key pages:**
- **Scan Launcher** — Run scans, smart recon, and pipelines
- **Findings** — Browse and triage all findings across tools
- **Assets** — View discovered hosts, ports, subdomains, credentials
- **Reports** — Export HAR, CSV, SARIF, proxy replay to Burp
- **Nodes** — Manage SSH tunnels to remote scan boxes
- **Services** — Monitor all backend services, database status, and GPU

## Step 1: Connect a Scan Node

Most scans run through a remote node (Kali box, cloud droplet, etc.) via SSH tunnel.

1. Go to **Nodes** > **SSH Tunnels** tab
2. Fill in your node's IP, username, and select the SSH key
3. Click **Connect** — you should see it go green (online)
4. The node is now your default proxy for scans

> **Tip:** Click the **Provision** button to auto-install 70+ tools on a new node (nmap, nuclei, hydra, seclists, rockyou.txt, etc.)

**Node monitoring:**
- Each node shows **First Seen** and **Last Seen** timestamps with color-coded badges (green = recent, yellow = stale, red = error)
- **Last Error** displays the most recent failure with timestamp
- The **Tunnel Event Log** at the bottom of the SSH tab shows connect/disconnect/drop/reconnect history
- If a tunnel drops, the watchdog auto-reconnects it within 4 minutes

## Step 2: Run Your First Scan

### Option A: Quick Scan (Scan Launcher)
1. Go to **Scan Launcher**
2. Select a scan type (e.g., **nmap** under Network)
3. Enter a target IP/range
4. Click **Launch**
5. Watch progress in the scan status bar

### Option B: Smart Recon (Recommended)
1. Go to **Scan Launcher** > **Smart Recon** tab
2. Enter a target IP and port (e.g., `192.168.1.100` port `22`)
3. The KB recommends tools + commands for that service
4. Select your node from the **Execute on** dropdown (loads instantly, independent of KB lookup)
5. Click **Run** next to any command
6. Results are auto-ingested as findings with proper tool source (ssh-audit, sslscan, etc.)
7. Input is debounced — type freely without lag

### Option C: Full Pipeline
1. Go to **Scan Launcher** > **Pipelines** tab
2. Select a pipeline (e.g., **Recon Pipeline**, **Full Web Scan**)
3. Enter targets and launch — multiple tools run in sequence

## Step 3: Review Findings

1. Go to **Findings**
2. Use filters: severity, source tool, IP, port, tags
3. Click a finding to see detail panel with evidence
4. Set workflow status: **new** > **triaging** > **confirmed** > **in_report**
5. Add tester notes, assign to team members, mark verified

**Finding sources** are correctly identified per tool — ssh-audit findings show as `ssh-audit` (not nmap), sslscan as `sslscan`, etc. Each tool has its own color-coded badge.

## Step 4: Export for Manual Testing

Go to **Reports** to export:
- **HAR** — Import into Burp Suite (via HARBringer extension or Bambda)
- **CSV** — Flat export for spreadsheets and reporting
- **SARIF** — For CI/CD integration and code review tools
- **Proxy Replay** — Replay discovered URLs through Burp/ZAP proxy in 4 phases

**Before exporting**, the page shows a live **findings count summary** — total matching findings, breakdown by severity (colored badges), and by source tool. This updates as you change filters so you know exactly what will be exported.

### Burp Suite Extension
Install the **RAG Scan Bridge** extension (`burp-extension/RagScanBridge.py`) for direct integration:
- **Preview Count** — see exactly how many findings match before importing
- **Filter by scope/engagement** — dropdown selectors auto-populated from dashboard
- **Import with real HTTP data** — request/response from ZAP scans included
- **Visual connection test** — green/red status indicator with DB table count
- See `burp-extension/README.md` for setup instructions

## Step 5: Monitor Services

Go to **Services** to monitor:
- **Database section** — Local PostgreSQL and Remote PostgreSQL status side by side
  - Stop/Start button for local postgres
  - Warning banner when both local and remote are running simultaneously
  - DB tunnel status inferred from remote connectivity
- **GPU tab** — VRAM breakdown (model weights + KV cache + CUDA overhead), power, temperature, driver/CUDA version
- **Health Diagnostics** — scan all containers for errors, including webhook delivery status

## Key Concepts

### Engagements
Group scans and findings by engagement. Use the **engagement selector** in the top bar to filter everything to one project. Findings for IPs in the engagement's scope are automatically included, even if they were scanned before the engagement was created.

### Scope
Define in-scope targets under **Settings** > **Scope**. Scans and findings can be filtered to only show in-scope hosts.

### SSH Tunnels & SOCKS Proxies
Each remote node gets a SOCKS5 proxy port. Scans route through this tunnel. Ports are sticky — once assigned, they're kept unless manually deleted. Port conflicts are auto-resolved.

### Auto-Ingest
Most tool output is automatically parsed and inserted as findings. Supported tools with dedicated parsers:
- **Network**: nmap, masscan, nessus
- **Web**: ZAP (with full request/response), nuclei, nikto, whatweb, httpx, katana
- **Security audit**: ssh-audit (per-algorithm findings), sslscan, testssl, sslyze
- **Other**: gobuster, ffuf, wafw00f, trufflehog, amass, and more

Unknown tools fall back to structured text extraction (JSON, tables, CVEs, key-values).

### Wordlists
Configure wordlist paths under **Settings** > **Tool Options** > **Wordlist Paths**. Defaults point to standard Kali locations (`/usr/share/wordlists/rockyou.txt`, seclists). Click **Check on Nodes** to verify files exist on remote nodes. Seclists and rockyou are auto-installed during node provisioning.

### Data Management
- **Purge Domain** on the Assets page removes all data across all tables for a domain
- **Purge by Pattern** for flexible cleanup by IP range or hostname pattern
- Both show a preview of affected rows before deleting

## Common Workflows

### External Pentest
1. Create engagement, assign scope
2. Set scope (external IPs/domains)
3. Run recon pipeline (subfinder + dnsx + httpx + gowitness)
4. Review assets and subdomains
5. Run nuclei + nikto on discovered web services
6. Smart Recon for specific ports (SSH, SMB, RDP, etc.)
7. Export confirmed findings to CSV/SARIF for report
8. Use Burp extension to import findings for manual verification

### Internal Network Assessment
1. Connect SSH tunnel to internal pivot box
2. Run nmap service scan on internal range
3. Smart Recon per-service (SMB shares, LDAP, MSSQL, etc.)
4. Run nuclei on internal web apps
5. Check credentials page for discovered creds
6. Export to Burp for manual web testing

### Web Application Test
1. Set target URL in scope
2. Run full web pipeline (nikto + ZAP + nuclei + gobuster)
3. Export HAR to Burp for manual crawl + audit (includes real request/response from ZAP)
4. Use proxy replay to push discovered URLs through Burp
5. Review ZAP + playwright findings for XSS, CSRF, etc.
