# RAG Scan Stack - Architecture Overview
**Simple, API-Driven Security Testing Platform**

---

## System Overview

RAG Scan Stack is a containerized security testing platform where **everything is accessible via REST APIs** and exposed through **MCP (Model Context Protocol) tools** for AI automation.

### Core Principle
- **API-First Design**: Every function accessible via REST endpoints
- **MCP Integration**: All capabilities exposed as AI-callable tools
- **Container Architecture**: Each scanner runs in isolated Docker containers
- **Unified Data Model**: All findings stored in PostgreSQL with consistent schema

---

## Basic Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Web Dashboard                      │
│                (React + FastAPI)                    │
└─────────────────────┬───────────────────────────────┘
                      │ HTTPS/REST
┌─────────────────────▼───────────────────────────────┐
│                  Main API                           │
│              (FastAPI + PostgreSQL)                 │
└─────────────────────┬───────────────────────────────┘
                      │ HTTP API Calls
┌─────────────────────▼───────────────────────────────┐
│              Security Scanners                      │
│   ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐    │
│   │ Nmap │ │Nuclei│ │ ZAP  │ │OSINT │ │ AI   │    │
│   │:8012 │ │:8011 │ │:8090 │ │:8024 │ │:8015 │    │
│   └──────┘ └──────┘ └──────┘ └──────┘ └──────┘    │
└─────────────────────────────────────────────────────┘
```

---

## Technology Stack

### **Core Components**
- **Database**: PostgreSQL (findings, assets, configurations)
- **API Server**: FastAPI (main coordination and data management)  
- **Web Interface**: React + TypeScript (dashboard for manual use)
- **Container Runtime**: Docker + Docker Compose

### **Security Scanners** (Each in separate container)
- **Nmap** (Port scanning): `nmap_scanner:8012`
- **Nuclei** (Vulnerability scanning): `nuclei-runner:8011` 
- **ZAP** (Web application scanning): `zap:8090`
- **OSINT** (Reconnaissance): `osint-runner:8024`
- **Playwright** (Modern web apps): `playwright-scanner:8014`
- **Brutus** (Credential testing): `brutus-runner:8026`

---

## API-First Design

### **Everything Has an API Endpoint**

**Scan Management:**
```
POST /run_masscan_nmap         # Start port scan
POST /jobs/masscan-nmap/upload # Upload scan results
GET  /scans/{id}               # Check scan status
POST /ingest/nmap              # Process scan results
POST /ingest/nuclei            # Process vuln scan results
```

**Finding Management:**
```
GET    /assets                 # List discovered assets
GET    /credentials            # List credential findings
DELETE /findings/bulk          # Bulk delete findings
GET    /ports/open             # List open ports
```

**Export Formats:**
```
GET  /export/sarif             # SARIF v2.1.0 export
GET  /export/har               # HAR format export
GET  /export/burp              # Burp Suite XML export
POST /findings/export          # Custom export formats
```

### **Direct Scanner APIs**
Each scanner exposes its own REST API:
- `https://nmap_scanner:8012/` - Port discovery service
- `https://nuclei-runner:8011/` - Vulnerability testing service 
- `https://zap:8090/` - Web application scanning
- `https://osint-runner:8024/` - Reconnaissance tools

---

## MCP Tool Integration

### **What is MCP?**
Model Context Protocol - allows AI agents to call platform functions as "tools"

### **Available MCP Tools** (26 total across 6 servers)

**Scanning Tools:**
- `scan_ports()` - Run Nmap port scans
- `scan_vulnerabilities()` - Run Nuclei templates
- `scan_web_app()` - ZAP web application testing
- `scan_subdomains()` - OSINT reconnaissance

**Data Management:**
- `search_findings()` - Query vulnerability database
- `get_asset_info()` - Asset and service details
- `export_results()` - Generate reports

**System Control:**
- `check_service_health()` - Monitor scanner status
- `manage_scan_queue()` - Control scan execution

### **MCP Server Endpoints**
```
http://localhost:9016  # pentest-sessions (scan coordination)
http://localhost:9017  # pentest-scanning (nmap, nuclei tools)
http://localhost:9018  # pentest-recon (OSINT, subdomain enum)
http://localhost:9019  # pentest-exploit (exploit execution) 
http://localhost:9020  # pentest-credentials (credential testing)
http://localhost:9021  # scan-pipelines (automated workflows)
```

---

## Data Flow

### **Simple Scan Workflow**
1. **API Request** → `POST /run_masscan_nmap` with target IPs
2. **Container Execution** → Nmap scanner container runs scan
3. **Result Processing** → ETL parser normalizes Nmap XML output
4. **Database Storage** → Findings stored in PostgreSQL via `POST /ingest/nmap`
5. **API Response** → Results available via `GET /assets` and `GET /ports/open`

### **Database Schema** (Simplified)
```sql
-- Core Tables
assets          # Target IPs and hostnames
ports           # Discovered services  
vulns           # Vulnerability findings
web_findings    # Web application issues
recon_findings  # OSINT discoveries

-- Metadata  
scan_runs       # Scan execution records
engagements     # Project organization
```

---

## Remote Access & Tunneling

### **SSH Tunnels**
- **Purpose**: Route scans through compromised hosts
- **Implementation**: autossh containers with SOCKS5 proxies
- **API**: `POST /ssh/connect` with credentials

### **WireGuard VPN**  
- **Purpose**: Modern VPN alternative to SSH
- **Implementation**: WireGuard server container
- **API**: `POST /wg/peers` to create VPN configs

---

## Deployment

### **Single Host Deployment**
```bash
git clone <repository>
docker compose up -d
curl https://localhost:3002  # Web interface (HTTPS)
curl https://localhost:8000/health  # API health check
```

### **Environment Requirements**
- **Minimum**: 8GB RAM, 4 CPU cores, 100GB storage
- **Recommended**: 16GB RAM, 8 CPU cores, 500GB SSD
- **Network**: Internet access for scanner updates
- **Optional**: NVIDIA GPU for AI features

---

## Security Model

### **Container Isolation**
- Each scanner runs in separate container
- Minimal privileges (no root where possible)
- Network segmentation via Docker networks

### **API Security**
- API key authentication
- HTTPS encryption for all communication
- Rate limiting and request validation

### **Data Protection**
- Database encryption at rest
- Secure credential storage
- No plaintext secrets in containers

---

## Integration Points

### **Import/Export**
- **Nessus**: Import `.nessus` files via `POST /ingest/nessus`
- **Burp Suite**: Export to XML sitemap via `GET /export/burp`
- **HAR**: HTTP Archive format export via `GET /export/har`
- **SARIF**: Security standard export via `GET /export/sarif`

### **External APIs**
- **SHODAN**: Internet-wide scanning data
- **VirusTotal**: File and URL analysis  
- **CVE Databases**: Vulnerability intelligence

---

## Monitoring & Health

### **Service Health**
- **Health Endpoint**: `GET /health` - All service status
- **Individual Services**: Each scanner has `/health` endpoint
- **Database**: Connection pool and query performance monitoring

### **Logging**
- **Container Logs**: `docker compose logs <service>`
- **Application Logs**: Structured JSON logging
- **Audit Trail**: All API calls logged with user attribution

---

## Summary

**RAG Scan Stack is fundamentally:**

1. **API-Driven**: Every function accessible via REST endpoints
2. **Container-Based**: Isolated, scalable scanner services  
3. **MCP-Enabled**: AI agents can call any platform function
4. **Data-Centric**: Unified PostgreSQL storage with consistent schema
5. **Integration-Ready**: Standard formats for import/export

**The architecture prioritizes simplicity and API accessibility over complexity.**

---

*This architecture enables both manual security testing via the web interface and fully automated testing via AI agents using the MCP tools.*