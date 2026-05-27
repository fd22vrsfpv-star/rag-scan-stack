# Sample Workflow: End-to-End Pentest Data Collection

This guide walks through a complete workflow from first scan to final export.

## Prerequisites

- Stack is running (`docker compose up -d`)
- Dashboard accessible at `http://localhost:3000`

---

## Step 1: Create an Engagement

1. Open **Engagements** in the sidebar
2. Click **New Engagement**
3. Fill in: name, client, scope description, start/end dates
4. Set phase to **Reconnaissance**

All scans and findings can be linked to this engagement.

---

## Step 2: Add Targets to Scope

1. Go to **Settings** → **Scope** tab
2. Paste target IPs/domains (one per line):
   ```
   192.168.1.0/24
   example.com
   app.example.com
   ```
3. Click **Save Scope**

---

## Step 3: Run Reconnaissance Scans

### Via Dashboard (ScanLauncher)
1. Go to **Scan Launcher**
2. Select scope and tool:
   - **subfinder** — subdomain enumeration
   - **dnsx** — DNS resolution
   - **httpx** — HTTP probing
   - **tlsx** — TLS certificate info
3. Click **Launch**
4. Monitor progress in **Scan Monitor**

### Via CLI (direct ingest)
```bash
# Run nmap externally and ingest results
nmap -sV -sC -oX scan.xml 192.168.1.0/24
curl -X POST http://localhost:8000/ingest/nmap \
  -H "x-api-key: changeme" \
  -F "file=@scan.xml"
```

---

## Step 4: Review Assets & Subdomains

1. Go to **Assets** page
2. Browse discovered hosts, open ports, banners
3. Click an asset to see port details and scan recommendations
4. Switch to **Subdomains** tab to see discovered subdomains

---

## Step 5: Run Vulnerability Scans

From **Scan Launcher**, run:
- **Nuclei** — template-based vuln scanning
- **ZAP** — web application scanning (if ZAP is enabled)
- **Nessus** — import `.nessus` files via the ingest API

```bash
# Ingest a Nessus scan
curl -X POST http://localhost:8000/ingest/nessus \
  -H "x-api-key: changeme" \
  -F "file=@scan.nessus"

# Ingest Nuclei JSONL
curl -X POST http://localhost:8000/ingest/nuclei \
  -H "x-api-key: changeme" \
  -F "file=@nuclei-output.jsonl"
```

---

## Step 6: Browse Findings

1. Go to **Findings Explorer**
2. Filter by severity, tool, host, or port
3. Click a finding to see full details: evidence, CVEs, CWEs, references
4. Add tags to categorize findings
5. Use the engagement selector in the top bar to filter by engagement

---

## Step 7: Credential Testing (Optional)

If running Brutus scans:
1. Launch from **Scan Launcher** → Credentials category
2. Select protocol (SSH, FTP, RDP, etc.), target, wordlists
3. Results appear in **Assets** → select host → **Credentials** tab
4. Mark status: valid / invalid / unknown / remediated

---

## Step 8: API Testing (Optional)

1. Go to **API Tester**
2. Import a Swagger/OpenAPI spec via URL or from `import/swagger/` directory
3. Browse endpoints, configure parameters
4. Execute through Burp proxy (configure in Settings)
5. Review response history

---

## Step 9: Compare Scan Runs (Delta)

1. Go to **Delta Compare**
2. Select two scan runs to compare
3. See new, resolved, and unchanged findings
4. Switch to **Dedup Report** tab to see cross-tool duplicates

---

## Step 10: Export Results

### JSON Export
```bash
curl "http://localhost:8000/export/data?format=json&categories=assets,findings,recon,credentials" \
  -H "x-api-key: changeme" -o export.json
```

### CSV Export
```bash
curl "http://localhost:8000/export/data?format=csv&categories=findings" \
  -H "x-api-key: changeme" -o findings.csv
```

### SARIF Export (for CI/CD integration)
```bash
curl "http://localhost:8000/export/sarif" \
  -H "x-api-key: changeme" -o findings.sarif
```

### Nessus-compatible Export
```bash
curl "http://localhost:8000/export/data?format=nessus" \
  -H "x-api-key: changeme" -o findings.nessus
```

---

## Step 11: Generate Reports

1. Go to **Reports** page
2. Select report type and filters
3. Download or share the generated report

---

## Tips

- **OSINT tools**: Use Follow-Ups page to track flagged items from the OSINT agent
- **SSH Tunnel**: Configure in `.env` to route scans through a remote VPS
- **Scope Intel**: Aggregated view of all intelligence for scoped targets
- **OpSec Dashboard**: Monitor your operational security posture during the engagement
- **Detection Rules**: Custom YAML rules in `knowledge/detection_rules/` auto-flag patterns
