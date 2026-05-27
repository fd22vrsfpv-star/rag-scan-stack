# Screenshot Capture Guide
**Step-by-step instructions for capturing presentation screenshots**

---

## 🚀 Prerequisites

1. **Start the platform**:
```bash
cd /opt/rag-scan-stack
docker compose up -d
```

2. **Wait for services to be healthy** (2-3 minutes):
```bash
# Check health status
curl -k -s https://localhost:3002/api/health | jq '.status'
```

3. **Open browser**: Navigate to `https://localhost:3002` (accept self-signed certificate)

---

## 📷 Priority Screenshots for User Guide

### 1. Dashboard Overview
**URL**: `https://localhost:3002/`
**File**: `screenshots/01-user-guide/dashboard-overview.png`
**What to capture**: 
- Main dashboard with status cards
- Navigation sidebar
- Health indicators and active scans
- Recent findings summary

### 2. Engagements Management
**URL**: `https://localhost:3002/engagements`
**File**: `screenshots/01-user-guide/engagements-list.png`
**Steps**:
1. Navigate to Engagements
2. If empty, click "New Engagement" and create a sample:
   - Name: "Demo Security Assessment"
   - Client: "Acme Corporation"
   - Status: "Active"
3. Capture the engagements list view

### 3. Findings Explorer
**URL**: `https://localhost:3002/findings`
**File**: `screenshots/01-user-guide/findings-explorer.png`
**What to capture**:
- Findings table with severity indicators
- Filter/search controls
- Finding count and statistics

### 4. WireGuard Management
**URL**: `https://localhost:3002/nodes`
**File**: `screenshots/01-user-guide/wireguard-management.png`
**Steps**:
1. Navigate to Nodes
2. Click "WireGuard" tab
3. Capture the peer management interface
4. If possible, show QR code generation

### 5. AI Agents Dashboard
**URL**: `https://localhost:3002/agents`
**File**: `screenshots/01-user-guide/ai-agents.png`
**What to capture**:
- Multi-agent status
- Agent coordination interface
- Recent agent activity

---

## 📊 Priority Screenshots for Management Guide

### 6. System Health Dashboard
**URL**: `https://localhost:3002/settings` → System Status
**File**: `screenshots/02-management/health-dashboard.png`
**What to capture**:
- Service health indicators (green/yellow/red status)
- Core services vs optional services
- Error messages or warnings if any

### 7. Services Management
**URL**: `https://localhost:3002/settings` → Services
**File**: `screenshots/02-management/services-management.png` 
**What to capture**:
- Service profile groups (Core, Scan, AI, Optional)
- Start/Stop controls for individual services
- Resource usage indicators

### 8. Database Health
**URL**: Use health dashboard database section
**File**: `screenshots/02-management/database-health.png`
**What to capture**:
- Database connection status
- Connection pool statistics
- Query performance metrics

---

## 🏗️ Priority Screenshots for Architecture Guide

### 9. Node Management Overview
**URL**: `https://localhost:3002/nodes`
**File**: `screenshots/03-architecture/node-management.png`
**What to capture**:
- Different tunnel types (SSH, WireGuard)
- Connection status indicators
- Proxy port allocations

### 10. Scan Pipeline Configuration
**URL**: `https://localhost:3002/scans` or Scan Launcher
**File**: `screenshots/03-architecture/scan-pipeline.png`
**What to capture**:
- Available scan types
- Tool integration options
- Pipeline configuration interface

---

## 🎯 Quick Screenshot Session (15 minutes)

Run this sequence to capture the most essential screenshots:

### Step 1: Verify Platform Status
```bash
# Check all services are running
docker ps --format "table {{.Names}}\t{{.Status}}" | head -10

# Test dashboard access
curl -k -s https://localhost:3002/api/health > /dev/null && echo "✅ Dashboard accessible"
```

### Step 2: Navigate and Capture
1. **Dashboard** → `https://localhost:3002/`
   - Capture homepage with status overview

2. **Health Check** → Settings → System Status  
   - Capture service health grid

3. **Engagements** → `https://localhost:3002/engagements`
   - Create sample engagement if needed
   - Capture project management interface

4. **Nodes** → `https://localhost:3002/nodes`
   - Capture tunnel overview
   - Switch to WireGuard tab, capture peer management

5. **Findings** → `https://localhost:3002/findings`  
   - Capture findings explorer (may be empty, that's OK)

6. **Services** → Settings → Services
   - Capture container management interface

### Step 3: Optional Advanced Screenshots
If you have time and want more detailed captures:

7. **Create Sample Data**:
```bash
# Quick port scan to generate some findings
docker exec nmap_scanner nmap -p 22,80,443 127.0.0.1 > /dev/null 2>&1 &
```

8. **AI Agents** → `https://localhost:3002/agents`
   - Capture agent coordination interface

9. **About Page** → `https://localhost:3002/about`
   - Capture documentation and MCP tools overview

---

## 📱 Screenshot Best Practices

### Browser Setup
```bash
# Use consistent browser window size
# Chrome/Firefox: F11 for fullscreen, then F11 again
# Set browser zoom to 100%
# Use incognito/private mode for clean UI
```

### Capture Settings
- **Resolution**: Full HD (1920x1080) minimum  
- **Format**: PNG for crisp text
- **Tool**: 
  - macOS: `Cmd + Shift + 4` (select area)
  - Windows: Snipping Tool or `Win + Shift + S`
  - Linux: Flameshot, `gnome-screenshot`, or similar

### Quality Guidelines
- ✅ **Clean UI**: No browser bookmarks bar, clear navigation
- ✅ **Realistic Data**: Show meaningful content when possible
- ✅ **Consistent Theme**: Use same browser and UI state
- ✅ **Readable Text**: Ensure text is clear at presentation size
- ❌ **No Sensitive Data**: Use localhost IPs and generic names only

---

## 🔧 Troubleshooting Screenshot Issues

### Platform Not Accessible
```bash
# Check container status
docker compose ps

# Restart if needed
docker compose restart pentest-dashboard rag-api

# Check logs
docker compose logs pentest-dashboard --tail 20
```

### Services Showing Unhealthy
```bash
# This is normal for some optional services
# Focus on core services being healthy:
# - rag-api ✅
# - pentest-dashboard ✅ 
# - rag-postgres ✅ (if using local DB)
```

### Empty Interfaces
- **Engagements**: Create a sample engagement for screenshots
- **Findings**: Empty state is fine for demo purposes
- **Nodes**: May be empty, focus on UI layout
- **Scans**: Show configuration options rather than results

### Browser Certificate Warnings
```bash
# For localhost development, it's safe to:
# 1. Click "Advanced" 
# 2. Click "Proceed to localhost (unsafe)"
# This creates a self-signed certificate warning
```

---

## 📁 File Organization

Create this directory structure for your screenshots:
```
presentation-materials/
└── screenshots/
    ├── 01-user-guide/
    │   ├── dashboard-overview.png
    │   ├── engagements-list.png
    │   ├── findings-explorer.png
    │   └── wireguard-management.png
    ├── 02-management/
    │   ├── health-dashboard.png
    │   ├── services-management.png
    │   └── database-health.png
    └── 03-architecture/
        ├── node-management.png
        └── scan-pipeline.png
```

---

## ✅ Screenshot Checklist

Use this checklist to track your progress:

### Essential Screenshots (Must Have)
- [ ] Dashboard homepage with navigation
- [ ] System health with service status
- [ ] Engagements management interface  
- [ ] WireGuard peer management with QR code
- [ ] Services management with start/stop controls

### Important Screenshots (Should Have)
- [ ] Findings explorer table
- [ ] Node management overview
- [ ] Database health metrics
- [ ] AI Agents dashboard
- [ ] Scan pipeline configuration

### Nice-to-Have Screenshots  
- [ ] About page with documentation
- [ ] Settings configuration panels
- [ ] Error states or alerts
- [ ] Mobile responsive views
- [ ] Advanced features in use

---

## 🎯 Next Steps

1. **Run through the quick session** to get essential screenshots
2. **Review captured images** for quality and clarity  
3. **Update presentation markdown** files with actual screenshot references
4. **Test presentation flow** with real images
5. **Create backup scenarios** for live demos

**Estimated Time**: 15-30 minutes for essential screenshots, 1-2 hours for comprehensive coverage.

Good luck with your screenshot capture session! The platform should provide great visual material for your presentations.