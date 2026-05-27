#!/usr/bin/env python3
"""
Capture screenshots of missing RAG Scan Stack features
Focus on exploits, remote nodes, and other advanced features
"""

import time
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

def capture_missing_screenshots():
    """Capture screenshots of features we missed in the first round"""

    screenshots_dir = Path("screenshots")

    # Create additional screenshot directories
    (screenshots_dir / "04-exploits").mkdir(exist_ok=True)
    (screenshots_dir / "05-advanced").mkdir(exist_ok=True)

    print("🎬 Launching browser for missing screenshots...")

    with sync_playwright() as p:
        # Launch browser with SSL ignore
        browser = p.chromium.launch(headless=False, slow_mo=1000, args=['--ignore-certificate-errors', '--ignore-ssl-errors'])
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.set_viewport_size({"width": 1920, "height": 1080})

        try:
            # Navigate to dashboard
            print("📍 Navigating to dashboard...")
            page.goto("http://localhost:3001", wait_until="networkidle")
            page.wait_for_timeout(3000)

            # Screenshots to capture
            missing_features = [
                # Exploits and offensive features
                {
                    "url": "/exploits",
                    "name": "04-exploits/exploit-manager.png",
                    "description": "Exploit Manager - payload execution and management"
                },
                {
                    "url": "/nodes",
                    "name": "04-exploits/remote-nodes-detail.png",
                    "description": "Remote Nodes - SSH tunnels, Sliver, Chisel management"
                },
                {
                    "url": "/users",
                    "name": "04-exploits/users-credentials.png",
                    "description": "Users & Credentials - user account management"
                },

                # Advanced features
                {
                    "url": "/cloud-posture",
                    "name": "05-advanced/cloud-posture.png",
                    "description": "Cloud Posture - cloud security assessment"
                },
                {
                    "url": "/content-intel",
                    "name": "05-advanced/content-intel.png",
                    "description": "Content Intelligence - content analysis"
                },
                {
                    "url": "/news",
                    "name": "05-advanced/news-intel.png",
                    "description": "News Intelligence - threat intelligence feeds"
                },
                {
                    "url": "/api-tester",
                    "name": "05-advanced/api-tester.png",
                    "description": "API Tester - API security testing"
                },
                {
                    "url": "/delta",
                    "name": "05-advanced/delta-compare.png",
                    "description": "Delta Compare - scan result comparison"
                },
                {
                    "url": "/follow-ups",
                    "name": "05-advanced/follow-ups.png",
                    "description": "Follow Ups - investigation tracking"
                },
                {
                    "url": "/maintenance",
                    "name": "05-advanced/maintenance.png",
                    "description": "Maintenance - system operations"
                }
            ]

            # Capture each screenshot
            for feature in missing_features:
                try:
                    print(f"📸 Capturing {feature['description']}...")

                    # Navigate to the feature
                    page.goto(f"http://localhost:3001{feature['url']}", wait_until="networkidle")
                    page.wait_for_timeout(4000)  # Let content load

                    # Take screenshot
                    screenshot_path = screenshots_dir / feature["name"]
                    page.screenshot(path=screenshot_path, full_page=True)
                    print(f"   ✅ Saved: {screenshot_path}")

                    time.sleep(2)

                except PlaywrightTimeoutError:
                    print(f"   ⚠️ Timeout loading {feature['url']}")
                except Exception as e:
                    print(f"   ❌ Error capturing {feature['name']}: {e}")

        except Exception as e:
            print(f"❌ Browser error: {e}")
        finally:
            browser.close()

    print("\n✅ Missing screenshot capture complete!")
    print("📄 Additional features documented for comprehensive coverage")

if __name__ == "__main__":
    capture_missing_screenshots()