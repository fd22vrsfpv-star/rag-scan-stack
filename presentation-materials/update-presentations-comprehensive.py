#!/usr/bin/env python3
"""
Update presentation materials with comprehensive screenshots
Creates complete documentation with all RAG Scan Stack features
"""

import os
import re
from pathlib import Path

def create_comprehensive_user_guide():
    """Create comprehensive user guide with all screenshots"""

    content = '''# RAG Scan Stack - Complete User Guide
**Comprehensive Platform Walkthrough with Screenshots**

---

## 1. Platform Overview

RAG Scan Stack is a comprehensive security testing platform that provides:
- **Asset Discovery & Software Detection**
- **OSINT & Reconnaissance Tools**
- **Automated Vulnerability Scanning**
- **Exploit Management & Execution**
- **Remote Node & Tunnel Management**
- **AI-Powered Analysis & Automation**

![Main Dashboard](screenshots-complete/01-core-workflow/dashboard-main.png)

---

## 2. Core Workflow

### Engagement Management
Organize security testing projects and track progress through engagement lifecycle.

![Engagement Management](screenshots-complete/01-core-workflow/engagements-management.png)

### Platform Configuration
Configure system settings, API keys, and integration parameters.

![Settings & Configuration](screenshots-complete/01-core-workflow/settings-configuration.png)

---

## 3. Asset Discovery & Software Detection

### Asset Inventory
Comprehensive network asset discovery and inventory management.

![Asset Inventory](screenshots-complete/02-assets-software/assets-inventory.png)

### Software Detection
Detailed service identification, version detection, and software inventory.

![Software Detection](screenshots-complete/02-assets-software/assets-software-details.png)

### User Account Management
Track discovered user accounts and credential findings.

![User Accounts & Credentials](screenshots-complete/02-assets-software/users-credentials.png)

---

## 4. Reconnaissance & OSINT

### Reconnaissance Explorer
OSINT collection, subdomain enumeration, and passive intelligence gathering.

![Recon Explorer](screenshots-complete/03-recon-osint/recon-explorer.png)

### Targeted Reconnaissance
Focused OSINT operations against specific targets and domains.

![Targeted Reconnaissance](screenshots-complete/03-recon-osint/targeted-recon.png)

### Content Intelligence
Content discovery, analysis, and intelligence extraction.

![Content Intelligence](screenshots-complete/03-recon-osint/content-intelligence.png)

---

## 5. Scan Management & Automation

### Scan Configuration
Advanced scan launcher with tool selection and targeting options.

![Scan Launcher](screenshots-complete/04-scan-management/scan-launcher-detail.png)

### Scan Monitoring
Real-time scan progress monitoring and execution tracking.

![Scan Monitor](screenshots-complete/04-scan-management/scan-monitor.png)

### Automated Pipelines
Orchestrated scan workflows and automation pipelines.

![Scan Pipelines](screenshots-complete/04-scan-management/scan-pipelines.png)

### AI-Powered Agents
Autonomous scanning agents with intelligent analysis and decision-making.

![AI Agents](screenshots-complete/04-scan-management/ai-agents.png)

---

## 6. Vulnerability Analysis & Exploitation

### Exploit Management
Payload selection, configuration, and execution management.

![Exploit Manager](screenshots-complete/05-exploits-offensive/exploit-manager.png)

### Finding Analysis
Detailed vulnerability analysis and exploitation planning.

![Findings Explorer](screenshots-complete/05-exploits-offensive/findings-exploitation.png)

### Investigation Tracking
Follow-up task management and investigation workflow tracking.

![Follow-up Tracking](screenshots-complete/05-exploits-offensive/follow-ups-tracking.png)

---

## 7. Remote Access & Node Management

### Node Overview
Remote node management and connectivity monitoring.

![Nodes Overview](screenshots-complete/06-remote-nodes/nodes-overview.png)

### SSH Tunnel Management
Secure SSH tunnel configuration and proxy management.

![SSH Tunnels](screenshots-complete/06-remote-nodes/ssh-tunnels.png)

### WireGuard VPN
Modern VPN tunnel management with peer configuration.

![WireGuard VPN](screenshots-complete/06-remote-nodes/wireguard-vpn.png)

### Remote Command Execution
Execute commands and tools through established tunnels.

![Remote Commands](screenshots-complete/06-remote-nodes/remote-commands.png)

---

## 8. Advanced Security Features

### API Security Testing
OpenAPI/Swagger specification testing and API security assessment.

![API Tester](screenshots-complete/07-advanced-features/api-tester.png)

### Cloud Security Posture
Cloud infrastructure security assessment and posture management.

![Cloud Posture](screenshots-complete/07-advanced-features/cloud-posture.png)

### Scan Result Comparison
Delta analysis and scan result comparison between assessments.

![Delta Comparison](screenshots-complete/07-advanced-features/delta-comparison.png)

### Knowledge Management
Threat intelligence repository and documentation management.

![Knowledge Base](screenshots-complete/07-advanced-features/knowledge-base.png)

---

## 9. System Operations & Administration

### Service Management
Container and service control with health monitoring.

![Services Management](screenshots-complete/08-operations/services-management.png)

### System Maintenance
Platform maintenance operations and administrative tasks.

![System Maintenance](screenshots-complete/08-operations/maintenance.png)

### Performance Diagnostics
System performance monitoring and diagnostic analysis.

![System Diagnostics](screenshots-complete/08-operations/diagnostics.png)

### Operational Security
OpSec monitoring and operational security dashboard.

![OpSec Dashboard](screenshots-complete/08-operations/opsec-dashboard.png)

---

## 10. Intelligence & Analysis

### Threat Intelligence
Real-time threat intelligence feeds and security news monitoring.

![Threat Intelligence](screenshots-complete/09-intelligence/threat-intelligence.png)

### External Synchronization
Synchronization with external threat intelligence sources.

![Sync Dashboard](screenshots-complete/09-intelligence/sync-dashboard.png)

### Platform Documentation
Comprehensive platform documentation and MCP tool reference.

![Platform Information](screenshots-complete/09-intelligence/platform-info.png)

---

## 11. Reporting & Export

### Report Generation
Comprehensive reporting dashboard with multiple export formats.

![Reports Dashboard](screenshots-complete/10-reporting/reports-dashboard.png)

### Feedback System
User feedback collection and platform improvement tracking.

![Feedback System](screenshots-complete/10-reporting/feedback-system.png)

---

## Summary

RAG Scan Stack provides a complete security testing ecosystem with:

- **11 Major Functional Areas** covering all aspects of security testing
- **API-First Architecture** with REST endpoints for every function
- **MCP Tool Integration** for AI automation and external tool integration
- **Container-Based Deployment** with isolated, scalable services
- **Comprehensive Export Options** (SARIF, HAR, Burp Suite, custom formats)

The platform enables both manual security testing workflows and fully automated AI-driven assessments through its unified interface and extensive API coverage.

---

*Complete feature documentation with screenshots - RAG Scan Stack Platform Guide*
'''

    return content

def create_comprehensive_architecture_guide():
    """Create comprehensive architecture guide with technical details"""

    content = '''# RAG Scan Stack - Complete Architecture Guide
**Technical Deep Dive with Implementation Details**

---

## System Architecture Overview

RAG Scan Stack implements a microservices architecture where every function is accessible via REST APIs and exposed through MCP (Model Context Protocol) tools for AI automation.

![Platform Architecture](screenshots-complete/09-intelligence/platform-info.png)

---

## Core Components

### 1. Container Services Architecture

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
│              Security Scanner Services               │
│   ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐    │
│   │ Nmap │ │Nuclei│ │ ZAP  │ │OSINT │ │ AI   │    │
│   │:8012 │ │:8011 │ │:8090 │ │:8024 │ │:8015 │    │
│   └──────┘ └──────┘ └──────┘ └──────┘ └──────┘    │
└─────────────────────────────────────────────────────┘
```

### 2. Service Management Interface

![Services Management](screenshots-complete/08-operations/services-management.png)

---

## Scanner Service Architecture

### Security Tool Integration

**Core Scanning Services:**
- **Nmap** (Port scanning): `nmap_scanner:8012`
- **Nuclei** (Vulnerability scanning): `nuclei-runner:8011`
- **ZAP** (Web application scanning): `zap:8090`
- **OSINT** (Reconnaissance): `osint-runner:8024`
- **Playwright** (Modern web apps): `playwright-scanner:8014`
- **Brutus** (Credential testing): `brutus-runner:8026`

![Scan Management](screenshots-complete/04-scan-management/scan-launcher-detail.png)

---

## Data Architecture

### Database Schema Design

**Core Tables:**
```sql
assets          # Target IPs and hostnames
ports           # Discovered services
vulns           # Vulnerability findings
web_findings    # Web application issues
recon_findings  # OSINT discoveries
scan_runs       # Scan execution records
engagements     # Project organization
```

![Asset Management](screenshots-complete/02-assets-software/assets-inventory.png)

---

## API Architecture

### RESTful API Endpoints

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

![API Testing](screenshots-complete/07-advanced-features/api-tester.png)

---

## MCP Tool Integration

### Model Context Protocol Architecture

**MCP Server Endpoints:**
```
http://localhost:9016  # pentest-sessions (scan coordination)
http://localhost:9017  # pentest-scanning (nmap, nuclei tools)
http://localhost:9018  # pentest-recon (OSINT, subdomain enum)
http://localhost:9019  # pentest-exploit (exploit execution)
http://localhost:9020  # pentest-credentials (credential testing)
http://localhost:9021  # scan-pipelines (automated workflows)
```

**Available MCP Tools** (26 total across 6 servers):

- `scan_ports()` - Run Nmap port scans
- `scan_vulnerabilities()` - Run Nuclei templates
- `scan_web_app()` - ZAP web application testing
- `scan_subdomains()` - OSINT reconnaissance
- `search_findings()` - Query vulnerability database
- `get_asset_info()` - Asset and service details
- `export_results()` - Generate reports

![AI Automation](screenshots-complete/04-scan-management/ai-agents.png)

---

## Network & Remote Access Architecture

### Remote Node Management

![Remote Nodes](screenshots-complete/06-remote-nodes/nodes-overview.png)

### SSH Tunnel Infrastructure
- **Purpose**: Route scans through compromised hosts
- **Implementation**: autossh containers with SOCKS5 proxies
- **API**: `POST /ssh/connect` with credentials
- **Port Range**: 10120-10149 (30 tunnels)

![SSH Tunnels](screenshots-complete/06-remote-nodes/ssh-tunnels.png)

### WireGuard VPN Integration
- **Purpose**: Modern VPN alternative to SSH
- **Implementation**: WireGuard server container
- **API**: `POST /wg/peers` to create VPN configs
- **Network**: 10.66.0.0/24 subnet

![WireGuard Management](screenshots-complete/06-remote-nodes/wireguard-vpn.png)

---

## Intelligence & Analysis Architecture

### Threat Intelligence Integration

![Threat Intelligence](screenshots-complete/09-intelligence/threat-intelligence.png)

### External Data Sources
- **SHODAN**: Internet-wide scanning data
- **VirusTotal**: File and URL analysis
- **CVE Databases**: Vulnerability intelligence
- **OSINT Sources**: Passive reconnaissance

### Content Analysis Pipeline

![Content Intelligence](screenshots-complete/03-recon-osint/content-intelligence.png)

---

## Operational Architecture

### System Health Monitoring

![System Diagnostics](screenshots-complete/08-operations/diagnostics.png)

**Health Monitoring:**
- **Health Endpoint**: `GET /health` - All service status
- **Individual Services**: Each scanner has `/health` endpoint
- **Database**: Connection pool and query performance monitoring

### Performance Metrics
- **Container Logs**: `docker compose logs <service>`
- **Application Logs**: Structured JSON logging
- **Audit Trail**: All API calls logged with user attribution

---

## Exploit & Offensive Architecture

### Exploit Management System

![Exploit Manager](screenshots-complete/05-exploits-offensive/exploit-manager.png)

**Exploit Workflow:**
1. **Vulnerability Discovery** → Automated scanning identifies targets
2. **Exploit Matching** → AI matches CVEs to available exploits
3. **Payload Configuration** → Select and configure exploitation payloads
4. **Remote Execution** → Execute through tunnel infrastructure
5. **Result Analysis** → Process exploitation results and evidence

### Remote Command Infrastructure

![Remote Commands](screenshots-complete/06-remote-nodes/remote-commands.png)

---

## Advanced Feature Architecture

### Cloud Security Posture

![Cloud Posture](screenshots-complete/07-advanced-features/cloud-posture.png)

### Delta Analysis System

![Delta Comparison](screenshots-complete/07-advanced-features/delta-comparison.png)

**Comparison Engine:**
- **Fingerprinting**: Stable hash generation for deduplication
- **Delta Detection**: New, resolved, and changed findings
- **Trend Analysis**: Historical vulnerability trends

---

## Deployment Architecture

### Single Host Deployment
```bash
git clone <repository>
docker compose up -d
curl https://localhost:3002  # Web interface (HTTPS)
curl https://localhost:8000/health  # API health check
```

### Resource Requirements
- **Minimum**: 8GB RAM, 4 CPU cores, 100GB storage
- **Recommended**: 16GB RAM, 8 CPU cores, 500GB SSD
- **Network**: Internet access for scanner updates
- **Optional**: NVIDIA GPU for AI features

---

## Security Architecture

### Container Isolation
- Each scanner runs in separate container
- Minimal privileges (no root where possible)
- Network segmentation via Docker networks

### API Security
- API key authentication
- HTTPS encryption for all communication
- Rate limiting and request validation

### Data Protection
- Database encryption at rest
- Secure credential storage
- No plaintext secrets in containers

---

## Integration Architecture

### Import/Export Capabilities
- **Nessus**: Import `.nessus` files via `POST /ingest/nessus`
- **Burp Suite**: Export to XML sitemap via `GET /export/burp`
- **HAR**: HTTP Archive format export via `GET /export/har`
- **SARIF**: Security standard export via `GET /export/sarif`

![Reporting Dashboard](screenshots-complete/10-reporting/reports-dashboard.png)

---

## Summary

RAG Scan Stack implements a modern, API-first security testing architecture that provides:

1. **Microservices Design** - Isolated, scalable scanner services
2. **API-First Approach** - Every function accessible via REST endpoints
3. **MCP Integration** - AI agents can call any platform function
4. **Container Orchestration** - Docker-based deployment and scaling
5. **Unified Data Model** - PostgreSQL with consistent schema
6. **Remote Access Infrastructure** - SSH and WireGuard tunnel support
7. **Comprehensive Export** - Multiple standard formats supported

The architecture prioritizes simplicity, API accessibility, and integration capability over complexity, enabling both manual security testing and fully automated AI-driven assessments.

---

*Technical architecture documentation - RAG Scan Stack Platform*
'''

    return content

def main():
    """Generate comprehensive presentation materials"""

    print("📄 Generating comprehensive presentation materials...")

    # Create output directory
    output_dir = Path("presentation-complete")
    output_dir.mkdir(exist_ok=True)

    # Generate comprehensive guides
    user_guide = create_comprehensive_user_guide()
    architecture_guide = create_comprehensive_architecture_guide()

    # Write files
    user_guide_path = output_dir / "01-complete-user-guide.md"
    architecture_path = output_dir / "02-complete-architecture.md"

    with open(user_guide_path, 'w') as f:
        f.write(user_guide)

    with open(architecture_path, 'w') as f:
        f.write(architecture_guide)

    print(f"✅ Created comprehensive presentation materials:")
    print(f"   📄 {user_guide_path}")
    print(f"   📄 {architecture_path}")
    print(f"\n💡 Next steps:")
    print(f"   1. Run comprehensive-screenshot-capture.py to capture all screenshots")
    print(f"   2. Convert to PDF using the comprehensive materials")
    print(f"   3. Review and customize as needed")

if __name__ == "__main__":
    main()