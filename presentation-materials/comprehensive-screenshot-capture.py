#!/usr/bin/env python3
"""
Comprehensive screenshot capture for ALL RAG Scan Stack features
Covers assets, recon, exploits, remote nodes, and advanced features
"""

import time
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

def setup_screenshot_directories():
    """Create organized directory structure for comprehensive screenshots"""

    screenshots_dir = Path("screenshots-complete")

    directories = [
        "01-core-workflow",      # Main workflow features
        "02-assets-software",    # Asset inventory and software detection
        "03-recon-osint",       # Reconnaissance and OSINT
        "04-scan-management",   # Scan configuration and monitoring
        "05-exploits-offensive", # Exploit execution and offensive tools
        "06-remote-nodes",      # Node management, tunnels, implants
        "07-advanced-features", # API testing, cloud posture, etc.
        "08-operations",        # Maintenance, diagnostics, administration
        "09-intelligence",      # Threat intel, news, content analysis
        "10-reporting"          # Reports, export, delta comparison
    ]

    for directory in directories:
        (screenshots_dir / directory).mkdir(parents=True, exist_ok=True)

    return screenshots_dir

def comprehensive_screenshot_capture():
    """Capture screenshots of ALL major RAG Scan Stack features"""

    screenshots_dir = setup_screenshot_directories()

    print("🎬 Starting comprehensive RAG Scan Stack screenshot capture...")
    print("📁 Organized into 10 functional categories")

    # Comprehensive feature mapping
    screenshot_plan = [

        # ═══════════════════════════════════════════════════════════════
        # CORE WORKFLOW FEATURES
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "01-core-workflow",
            "features": [
                {
                    "url": "/",
                    "name": "dashboard-main.png",
                    "description": "Main Dashboard - Overview and navigation",
                    "wait_for": "text=RAG Scan Stack"
                },
                {
                    "url": "/engagements",
                    "name": "engagements-management.png",
                    "description": "Engagement Management - Project organization",
                    "wait_for": "text=Engagements"
                },
                {
                    "url": "/settings",
                    "name": "settings-configuration.png",
                    "description": "Settings & Configuration - System setup",
                    "wait_for": "text=Settings"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # ASSETS & SOFTWARE DETECTION
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "02-assets-software",
            "features": [
                {
                    "url": "/assets",
                    "name": "assets-inventory.png",
                    "description": "Asset Inventory - Network asset discovery",
                    "wait_for": "text=Assets"
                },
                {
                    "url": "/assets",
                    "name": "assets-software-details.png",
                    "description": "Software Detection - Service and version identification",
                    "wait_for": "text=Assets",
                    "action": "click_first_asset"
                },
                {
                    "url": "/users",
                    "name": "users-credentials.png",
                    "description": "User Accounts & Credentials - Identity management",
                    "wait_for": "text=Users"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # RECONNAISSANCE & OSINT
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "03-recon-osint",
            "features": [
                {
                    "url": "/recon",
                    "name": "recon-explorer.png",
                    "description": "Recon Explorer - OSINT and passive intelligence",
                    "wait_for": "text=Reconnaissance"
                },
                {
                    "url": "/targeted-recon",
                    "name": "targeted-recon.png",
                    "description": "Targeted Reconnaissance - Focused OSINT collection",
                    "wait_for": "text=Targeted"
                },
                {
                    "url": "/content-intel",
                    "name": "content-intelligence.png",
                    "description": "Content Intelligence - Content analysis and discovery",
                    "wait_for": "text=Content"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # SCAN MANAGEMENT
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "04-scan-management",
            "features": [
                {
                    "url": "/scans/launch",
                    "name": "scan-launcher-detail.png",
                    "description": "Scan Launcher - Tool configuration and targeting",
                    "wait_for": "text=Launch"
                },
                {
                    "url": "/scans",
                    "name": "scan-monitor.png",
                    "description": "Scan Monitor - Active scan tracking and progress",
                    "wait_for": "text=Scans"
                },
                {
                    "url": "/pipelines",
                    "name": "scan-pipelines.png",
                    "description": "Scan Pipelines - Automated workflow orchestration",
                    "wait_for": "text=Pipelines"
                },
                {
                    "url": "/agents",
                    "name": "ai-agents.png",
                    "description": "AI Agents - Autonomous scanning and analysis",
                    "wait_for": "text=Agents"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # EXPLOITS & OFFENSIVE TOOLS
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "05-exploits-offensive",
            "features": [
                {
                    "url": "/exploits",
                    "name": "exploit-manager.png",
                    "description": "Exploit Manager - Payload selection and execution",
                    "wait_for": "text=Exploits"
                },
                {
                    "url": "/findings",
                    "name": "findings-exploitation.png",
                    "description": "Findings Explorer - Vulnerability analysis and exploitation",
                    "wait_for": "text=Findings"
                },
                {
                    "url": "/follow-ups",
                    "name": "follow-ups-tracking.png",
                    "description": "Follow-up Tracking - Investigation workflow",
                    "wait_for": "text=Follow"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # REMOTE NODES & TUNNELING
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "06-remote-nodes",
            "features": [
                {
                    "url": "/nodes",
                    "name": "nodes-overview.png",
                    "description": "Nodes Overview - Remote node management",
                    "wait_for": "text=Nodes"
                },
                {
                    "url": "/nodes",
                    "name": "ssh-tunnels.png",
                    "description": "SSH Tunnels - Secure remote access configuration",
                    "wait_for": "text=SSH",
                    "action": "click_ssh_tab"
                },
                {
                    "url": "/nodes",
                    "name": "wireguard-vpn.png",
                    "description": "WireGuard VPN - Modern VPN tunnel management",
                    "wait_for": "text=WireGuard",
                    "action": "click_wireguard_tab"
                },
                {
                    "url": "/nodes",
                    "name": "remote-commands.png",
                    "description": "Remote Commands - Command execution through tunnels",
                    "wait_for": "text=Commands",
                    "action": "click_commands_tab"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # ADVANCED FEATURES
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "07-advanced-features",
            "features": [
                {
                    "url": "/api-tester",
                    "name": "api-tester.png",
                    "description": "API Tester - OpenAPI/Swagger security testing",
                    "wait_for": "text=API"
                },
                {
                    "url": "/cloud-posture",
                    "name": "cloud-posture.png",
                    "description": "Cloud Posture - Cloud security assessment",
                    "wait_for": "text=Cloud"
                },
                {
                    "url": "/delta",
                    "name": "delta-comparison.png",
                    "description": "Delta Comparison - Scan result analysis",
                    "wait_for": "text=Delta"
                },
                {
                    "url": "/knowledge",
                    "name": "knowledge-base.png",
                    "description": "Knowledge Base - Threat intelligence and documentation",
                    "wait_for": "text=Knowledge"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # OPERATIONS & ADMINISTRATION
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "08-operations",
            "features": [
                {
                    "url": "/services",
                    "name": "services-management.png",
                    "description": "Services Management - Container and service control",
                    "wait_for": "text=Services"
                },
                {
                    "url": "/maintenance",
                    "name": "maintenance.png",
                    "description": "System Maintenance - Operations and upkeep",
                    "wait_for": "text=Maintenance"
                },
                {
                    "url": "/diagnostics",
                    "name": "diagnostics.png",
                    "description": "System Diagnostics - Performance and health monitoring",
                    "wait_for": "text=Diagnostics"
                },
                {
                    "url": "/opsec",
                    "name": "opsec-dashboard.png",
                    "description": "OpSec Dashboard - Operational security monitoring",
                    "wait_for": "text=OpSec"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # INTELLIGENCE & ANALYSIS
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "09-intelligence",
            "features": [
                {
                    "url": "/news",
                    "name": "threat-intelligence.png",
                    "description": "Threat Intelligence - News feeds and intelligence",
                    "wait_for": "text=News"
                },
                {
                    "url": "/sync",
                    "name": "sync-dashboard.png",
                    "description": "Sync Dashboard - External intelligence synchronization",
                    "wait_for": "text=Sync"
                },
                {
                    "url": "/about",
                    "name": "platform-info.png",
                    "description": "Platform Information - Documentation and MCP tools",
                    "wait_for": "text=About"
                }
            ]
        },

        # ═══════════════════════════════════════════════════════════════
        # REPORTING & EXPORT
        # ═══════════════════════════════════════════════════════════════
        {
            "category": "10-reporting",
            "features": [
                {
                    "url": "/reports",
                    "name": "reports-dashboard.png",
                    "description": "Reports Dashboard - Export and reporting interface",
                    "wait_for": "text=Reports"
                },
                {
                    "url": "/feedback",
                    "name": "feedback-system.png",
                    "description": "Feedback System - User feedback and improvement tracking",
                    "wait_for": "text=Feedback"
                }
            ]
        }
    ]

    # Execute comprehensive capture
    with sync_playwright() as p:
        print("🌐 Launching browser...")

        browser = p.chromium.launch(
            headless=False,
            slow_mo=2000,
            args=['--ignore-certificate-errors', '--ignore-ssl-errors', '--disable-web-security']
        )

        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1920, "height": 1080}
        )

        page = context.new_page()

        try:
            # Test dashboard connectivity
            print("🔗 Testing dashboard connectivity...")

            dashboard_urls = [
                "http://localhost:3001",   # HTTP port
                "https://localhost:3002",  # HTTPS port
                "http://localhost:8080",   # Alternative port
                "http://127.0.0.1:3001"    # Direct IP
            ]

            dashboard_url = None
            for url in dashboard_urls:
                try:
                    print(f"   Trying {url}...")
                    page.goto(url, timeout=10000, wait_until="domcontentloaded")
                    dashboard_url = url
                    print(f"   ✅ Connected to {url}")
                    break
                except Exception as e:
                    print(f"   ❌ Failed: {e}")
                    continue

            if not dashboard_url:
                print("❌ Could not connect to dashboard on any port")
                print("💡 Please start the dashboard with: docker compose up -d pentest-dashboard")
                return

            # Wait for dashboard to load
            page.wait_for_timeout(5000)

            # Capture screenshots by category
            total_screenshots = sum(len(cat["features"]) for cat in screenshot_plan)
            current_screenshot = 0

            for category in screenshot_plan:
                print(f"\n📁 Capturing {category['category']} ({len(category['features'])} screenshots)")

                for feature in category["features"]:
                    current_screenshot += 1
                    print(f"   [{current_screenshot}/{total_screenshots}] {feature['description']}")

                    try:
                        # Navigate to feature
                        full_url = f"{dashboard_url}{feature['url']}"
                        page.goto(full_url, wait_until="networkidle", timeout=30000)

                        # Wait for specific element or default
                        if "wait_for" in feature:
                            try:
                                page.wait_for_selector(f"text={feature['wait_for']}", timeout=10000)
                            except:
                                print(f"      ⚠️ Wait condition not met, proceeding anyway")

                        page.wait_for_timeout(3000)

                        # Perform specific action if needed
                        if "action" in feature:
                            try:
                                if feature["action"] == "click_first_asset":
                                    page.click("tr[data-testid='asset-row']:first-child", timeout=5000)
                                elif feature["action"] == "click_ssh_tab":
                                    page.click("text=SSH Tunnels", timeout=5000)
                                elif feature["action"] == "click_wireguard_tab":
                                    page.click("text=WireGuard", timeout=5000)
                                elif feature["action"] == "click_commands_tab":
                                    page.click("text=Remote Commands", timeout=5000)
                                page.wait_for_timeout(2000)
                            except Exception as e:
                                print(f"      ⚠️ Action failed: {e}")

                        # Take screenshot
                        screenshot_path = screenshots_dir / category["category"] / feature["name"]
                        page.screenshot(path=screenshot_path, full_page=True)
                        print(f"      ✅ Saved: {screenshot_path}")

                        # Brief pause between captures
                        time.sleep(1)

                    except PlaywrightTimeoutError:
                        print(f"      ❌ Timeout loading {feature['url']}")
                    except Exception as e:
                        print(f"      ❌ Error: {e}")

        except Exception as e:
            print(f"❌ Critical error: {e}")
        finally:
            browser.close()

    # Generate summary report
    print(f"\n📋 Screenshot Capture Summary")
    print("=" * 50)

    total_captured = 0
    for category in screenshot_plan:
        category_dir = screenshots_dir / category["category"]
        screenshot_count = len(list(category_dir.glob("*.png")))
        total_captured += screenshot_count
        print(f"📁 {category['category']}: {screenshot_count} screenshots")

    print(f"\n✅ Total captured: {total_captured} screenshots")
    print(f"📁 All screenshots saved to: {screenshots_dir}")
    print("\n📄 Ready for comprehensive presentation material generation!")

if __name__ == "__main__":
    comprehensive_screenshot_capture()