# RAG Scan Stack - User Guide & Features Overview
**Comprehensive Penetration Testing & Red Team Workflow Platform**

---

## Table of Contents

1. **Platform Introduction**
2. **Getting Started - Dashboard Overview**
3. **Engagement Management**
4. **Scope Definition & Intelligence**
5. **AI-Powered Scanning**
6. **Findings Management**
7. **Node & Tunnel Management**
8. **Reporting & Export**
9. **Advanced Features**

---

## 1. Platform Introduction

### What is RAG Scan Stack?
- **Comprehensive Security Testing Platform** for authorized penetration testing and red team operations
- **AI-Enhanced Workflow** with automated scanning, intelligent findings correlation, and multi-agent coordination
- **Centralized Data Collection** from 20+ security tools with unified findings management
- **Advanced Tunneling** with SSH, WireGuard, and C2 framework support for remote assessments

### Key Value Propositions
- ✅ **Workflow Acceleration**: Reduce manual coordination between tools by 80%
- ✅ **AI-Driven Intelligence**: Automated reconnaissance, scan recommendations, and finding correlation
- ✅ **Unified Findings Management**: Single source of truth for all security findings
- ✅ **Remote Assessment Ready**: Built-in tunneling and proxy support for complex network environments

---

## 2. Dashboard Overview

![Dashboard Overview](screenshots-complete/01-core-workflow/dashboard-main.png)


### Main Navigation Areas
- **🏠 Dashboard**: Real-time status, scan activity, and quick actions
- **🎯 Engagements**: Project management and scope tracking
- **🔍 Findings**: Comprehensive vulnerability and findings explorer
- **💻 Assets**: Network discovery and asset intelligence
- **🤖 AI Agents**: Multi-agent automation and scan orchestration
- **🔗 Nodes**: Remote access and tunnel management
- **⚙️ Settings**: Configuration and system management

### Dashboard Status Cards
- **System Health**: Service status and performance metrics
- **Active Scans**: Real-time scan progress and queue status
- **Recent Findings**: Latest discoveries with severity indicators
- **Tunnel Status**: Remote node connectivity and proxy availability

---

## 3. Engagement Management Workflow

![Engagement Management](screenshots-complete/01-core-workflow/engagements-management.png)


### Step 1: Create New Engagement

#### Navigation
1. Click **Engagements** in main navigation
2. Click **+ New Engagement** button
3. Fill engagement details:

#### Required Fields
```
Engagement Name: "Acme Corp Assessment 2026"
Client: "Acme Corporation"
Start Date: "2026-05-15"
End Date: "2026-05-30"
Engagement Type: "Internal Network Assessment"
Status: "Planning"
```

#### Optional Configuration
- **Scope Notes**: Internal network ranges and critical systems
- **Rules of Engagement**: Approved testing windows and restrictions
- **Emergency Contacts**: Client SPOC and escalation procedures
- **Testing Methodology**: OWASP, NIST, Custom framework selection

### Step 2: Engagement Timeline & Phases
- **Planning Phase**: Scope definition and approval
- **Active Phase**: Scanning and manual testing
- **Reporting Phase**: Findings compilation and documentation
- **Complete Phase**: Deliverable submission and closure

### Step 3: Status Tracking
- **Real-time progress indicators** for each engagement phase
- **Automated timeline events** from scan completions and findings
- **Manual milestone tracking** for client meetings and deliverables

---

## 4. Scope Definition & Intelligence

![Recon Explorer](screenshots-complete/03-recon-osint/recon-explorer.png)


### Step 1: Define Target Scope

#### Manual Target Entry
```
Target Types Supported:
- IP Addresses: 192.168.1.0/24, 10.0.0.1-10.0.0.50
- Hostnames: mail.acme.com, *.internal.acme.com
- URLs: https://app.acme.com, http://admin.acme.local
- Domain Names: acme.com, subsidiary.net
```

#### Bulk Import Options
- **CSV Upload**: Structured target lists with metadata
- **Text Import**: Line-separated targets with auto-detection
- **API Integration**: Import from external asset management systems
- **Previous Engagement**: Clone scope from historical assessments

### Step 2: Automated Intelligence Gathering

#### OSINT Collection
- **Domain Intelligence**: DNS records, subdomains, certificate transparency
- **Cloud Asset Discovery**: AWS, Azure, GCP resource enumeration
- **Social Engineering Intel**: Employee enumeration, email patterns
- **Technology Stack Detection**: Framework fingerprinting and version detection

#### Passive Reconnaissance
```
Tools Integrated:
✓ Subfinder - Subdomain enumeration
✓ DNSx - DNS resolution and validation
✓ ASNmap - IP range and ownership mapping
✓ Amass - Comprehensive asset discovery
✓ Cloudlist - Cloud provider asset enumeration
```

### Step 3: Scope Validation & Approval
- **Asset verification** with client-provided scope documentation
- **Out-of-scope flagging** for discovered assets outside testing boundaries
- **Approval workflow** with client stakeholder sign-off
- **Change management** for scope modifications during testing

---

## 5. AI-Powered Scanning Workflow

![AI Agents](screenshots-complete/04-scan-management/ai-agents.png)


### Step 1: AI Agent Overview

#### Multi-Agent Architecture
- **🧠 Orchestrator Agent**: Coordinates scanning strategy and resource allocation
- **🔍 Recon Agent**: Automated reconnaissance and target discovery
- **🛡️ Scanning Agent**: Vulnerability assessment and service enumeration
- **⚡ Exploit Agent**: Safe exploit validation and proof-of-concept development
- **📊 Analysis Agent**: Finding correlation and risk assessment

### Step 2: Automated Scan Pipeline

#### Phase 1: Discovery & Reconnaissance
```
Scan Sequence:
1. Port Discovery (Masscan/Nmap)
   └─ TCP: 1-65535 (adaptive timing)
   └─ UDP: Top 1000 ports
   
2. Service Enumeration
   └─ Banner grabbing and fingerprinting
   └─ TLS/SSL configuration analysis
   └─ HTTP service discovery
   
3. Technology Detection
   └─ Framework identification
   └─ Version enumeration
   └─ Security header analysis
```

#### Phase 2: Vulnerability Assessment
```
Scanning Tools:
✓ Nuclei: 8000+ templates for known vulnerabilities
✓ ZAP: Dynamic web application scanning
✓ Playwright: Modern JavaScript application testing
✓ Custom Scripts: Organization-specific checks
```

#### Phase 3: Intelligence Correlation
- **Cross-reference findings** across multiple tools
- **Risk scoring** based on exploitability and business impact
- **Attack path mapping** for lateral movement scenarios
- **False positive filtering** using AI-powered validation

### Step 3: Manual Scan Initiation

#### Quick Launch Options
- **🚀 Full Pipeline**: Complete end-to-end assessment
- **🎯 Targeted Scan**: Specific service or vulnerability checks
- **🔄 Delta Scan**: Changes since last assessment
- **🚨 Emergency Scan**: Critical vulnerability validation

#### Custom Scan Configuration
```yaml
Scan Parameters:
- Timing Template: [Aggressive, Normal, Polite, Stealth]
- Scope Filtering: [In-scope only, Include adjacent, Full discovery]
- Tool Selection: [Enable/disable specific scanners]
- Proxy Settings: [Direct, Burp Suite, Custom SOCKS]
```

---

## 6. Findings Management

![Findings Explorer](screenshots-complete/05-exploits-offensive/findings-exploitation.png)


### Step 1: Findings Explorer Interface

#### Comprehensive View Options
- **📊 Summary Dashboard**: High-level metrics and trend analysis
- **🗂️ Detailed Table**: Sortable, filterable findings with rich metadata
- **🗺️ Asset Map**: Network topology with vulnerability overlays
- **⏱️ Timeline View**: Chronological discovery and remediation tracking

### Step 2: Finding Details & Evidence

#### Rich Finding Information
```
Finding Attributes:
✓ Title & Description: Clear vulnerability summary
✓ Severity Rating: Critical, High, Medium, Low, Info
✓ CVSS Score: Industry-standard risk scoring
✓ CWE/CVE References: Vulnerability classification
✓ Affected Assets: Complete host and service details
✓ Discovery Timeline: First seen, last verified dates
```

#### Evidence Documentation
- **📷 Screenshots**: Automated capture from web scanners
- **📋 Raw Output**: Complete tool output and command execution logs
- **🔍 Proof of Concept**: Safe demonstration of vulnerability impact
- **📊 Exploitation Risk**: AI-assessed likelihood and business impact

### Step 3: Workflow Management

#### Finding Status Tracking
- **🆕 New**: Recently discovered, pending review
- **✅ Confirmed**: Validated by security analyst
- **❓ False Positive**: Flagged as invalid finding
- **🔄 Retest**: Scheduled for remediation validation
- **✅ Fixed**: Confirmed remediation by client

#### Collaboration Features
- **💬 Comments & Notes**: Analyst discussion and client communication
- **🏷️ Custom Tags**: Organizational categorization and workflow tracking
- **📧 Notifications**: Automated alerts for critical findings
- **🔗 External Links**: Integration with ticketing and project management systems

---

## 7. Node & Tunnel Management

![Nodes Overview](screenshots-complete/06-remote-nodes/nodes-overview.png)

![SSH Tunnels](screenshots-complete/06-remote-nodes/ssh-tunnels.png)

![WireGuard VPN](screenshots-complete/06-remote-nodes/wireguard-vpn.png)


### Step 1: Remote Access Overview

#### Supported Connection Types
- **🔐 SSH Tunnels**: Traditional encrypted tunneling with key-based authentication
- **🛡️ WireGuard VPN**: Modern, high-performance VPN tunneling
- **👁️ C2 Frameworks**: Sliver implants for red team operations
- **🌐 HTTP Proxies**: Burp Suite and ZAP integration for web testing

### Step 2: WireGuard Management

#### Peer Configuration
```
WireGuard Setup:
1. Generate Keypair: Automatic server-side key generation
2. IP Allocation: Automatic subnet IP assignment
3. Configuration Export: Copy-paste or QR code for mobile apps
4. Status Monitoring: Real-time connection and traffic statistics
```

#### Mobile Device Support
- **📱 QR Code Generation**: Instant configuration for mobile WireGuard apps
- **📋 Configuration Export**: Text format for desktop clients
- **🔄 Dynamic Reconfiguration**: Update peers without service restart
- **📊 Usage Statistics**: Bandwidth monitoring and connection analytics

### Step 3: SSH Tunnel Operations

#### Tunnel Management
```
SSH Capabilities:
✓ SOCKS5 Proxy: Dynamic port forwarding for tool traffic
✓ Local Forward: Specific service access (RDP, VNC, etc.)
✓ Reverse Forward: Callback channels for restricted environments
✓ Auto-Reconnect: Resilient connections with health monitoring
```

#### Security Features
- **🔑 Key-Based Authentication**: No password authentication allowed
- **🔒 Certificate Validation**: Host key verification and rotation
- **🛡️ Connection Monitoring**: Real-time status and failure alerting
- **📈 Performance Metrics**: Latency, bandwidth, and stability tracking

---

## 8. Reporting & Export

![Reports Dashboard](screenshots-complete/10-reporting/reports-dashboard.png)


### Step 1: Report Generation Options

#### Standard Report Formats
```
Export Formats:
✓ Executive Summary: High-level findings for leadership
✓ Technical Report: Detailed findings for IT teams
✓ SARIF: Industry-standard format for security tools
✓ CSV: Spreadsheet analysis and custom processing
✓ JSON: API integration and programmatic access
✓ HAR: HTTP traffic for Burp Suite import
```

### Step 2: Customizable Report Content

#### Report Sections
- **📋 Executive Summary**: Business impact and strategic recommendations
- **🎯 Scope Overview**: Tested systems and methodology summary
- **🔍 Findings Details**: Complete vulnerability documentation with evidence
- **📊 Risk Analysis**: Prioritized remediation roadmap
- **📈 Metrics & Trends**: Comparative analysis with previous assessments
- **🛠️ Remediation Guidance**: Step-by-step resolution instructions

### Step 3: Integration & Distribution

#### Automated Delivery
- **📧 Email Distribution**: Scheduled delivery to stakeholder lists
- **🔗 API Webhooks**: Real-time integration with external systems
- **☁️ Cloud Storage**: Automatic upload to client document repositories
- **📱 Mobile Notifications**: Critical finding alerts for security teams

---

## 9. Advanced Features

### Delta Analysis & Trending
- **🔄 Comparative Analysis**: Before/after remediation validation
- **📈 Risk Trends**: Improvement tracking over multiple assessments
- **🆕 New Finding Detection**: Automatic identification of environment changes
- **📊 Remediation Metrics**: Time-to-fix tracking and SLA monitoring

### API Security Testing
- **📝 OpenAPI Import**: Automatic test generation from Swagger/OpenAPI specs
- **🔍 Endpoint Discovery**: Automated API surface mapping
- **🛡️ Authentication Testing**: Token validation and session management
- **📊 Parameter Fuzzing**: Input validation and injection testing

### Cloud Security Posture
- **☁️ Multi-Cloud Support**: AWS, Azure, GCP configuration assessment
- **🔐 IAM Analysis**: Permission auditing and privilege escalation detection
- **📦 Resource Inventory**: Complete infrastructure mapping and compliance
- **🚨 Misconfiguration Detection**: Automated security best practice validation

### Credential Testing & Management
- **🔑 Secure Vault**: Encrypted credential storage with audit logging
- **🎯 Targeted Testing**: Username/password validation against discovered services
- **📊 Success Tracking**: Credential reuse and policy compliance analysis
- **🔒 Integration Security**: Safe handling of client authentication data

---

## Next Steps

### For Pentesters & Red Teams
1. **Start with Engagement Creation** - Define project scope and timeline
2. **Configure Target Scope** - Import and validate testing boundaries
3. **Launch AI Scanning Pipeline** - Automated discovery and vulnerability assessment
4. **Review & Validate Findings** - Manual verification and evidence collection
5. **Generate Client Reports** - Professional deliverables with remediation guidance

### For Security Managers
1. **Review Dashboard Metrics** - Track team productivity and finding trends
2. **Monitor Service Health** - Ensure platform availability and performance
3. **Analyze Engagement ROI** - Measure testing effectiveness and coverage
4. **Plan Resource Allocation** - Scale infrastructure based on testing demand

### Training & Support Resources
- **📚 Documentation Wiki**: Comprehensive guides at `/about` → Documentation
- **🎥 Video Tutorials**: Step-by-step workflows and advanced techniques
- **🛠️ API Reference**: Complete OpenAPI documentation for automation
- **💬 Community Support**: Best practices sharing and troubleshooting assistance

---

## Conclusion

The RAG Scan Stack provides a comprehensive, AI-enhanced platform for modern security testing workflows. By automating routine tasks, centralizing findings management, and providing advanced tunneling capabilities, teams can focus on high-value manual testing while maintaining comprehensive coverage of the attack surface.

**Ready to start your first engagement?** Begin with the Engagements module and follow this guide for a complete testing workflow.