#!/usr/bin/env python3
"""
Automated Screenshot Capture for RAG Scan Stack Presentation Materials
Uses Playwright to capture consistent, high-quality screenshots of the dashboard
"""

import asyncio
import os
import json
from pathlib import Path
from datetime import datetime
from playwright.async_api import async_playwright

# Configuration
BASE_URL = "https://localhost:3002"
SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"
VIEWPORT_SIZE = {"width": 1920, "height": 1080}
WAIT_TIME = 3000  # milliseconds to wait for page loads
SCREENSHOT_QUALITY = 90

# Screenshot definitions
SCREENSHOTS = [
    # User Guide Screenshots
    {
        "category": "01-user-guide",
        "filename": "dashboard-overview.png",
        "url": "/",
        "description": "Main dashboard with status overview and navigation",
        "wait_for": "[data-testid='dashboard'], h1, .dashboard, body",
        "actions": []
    },
    {
        "category": "01-user-guide",
        "filename": "engagements-list.png",
        "url": "/engagements",
        "description": "Engagements management interface",
        "wait_for": "text=Engagements",
        "actions": [
            # Create sample engagement if needed
            {"type": "click_if_exists", "selector": "text=New Engagement"},
            {"type": "wait", "time": 1000},
            {"type": "fill_if_exists", "selector": "input[name='name']", "value": "Demo Security Assessment"},
            {"type": "fill_if_exists", "selector": "input[name='client']", "value": "Acme Corporation"},
            {"type": "click_if_exists", "selector": "text=Create"},
            {"type": "wait", "time": 2000}
        ]
    },
    {
        "category": "01-user-guide",
        "filename": "scope-intelligence.png",
        "url": "/scope",
        "description": "Scope Intelligence and target management",
        "wait_for": "text=Scope Intelligence",
        "actions": []
    },
    {
        "category": "01-user-guide",
        "filename": "findings-explorer.png",
        "url": "/findings",
        "description": "Findings Explorer with vulnerability data",
        "wait_for": "text=Findings",
        "actions": []
    },
    {
        "category": "01-user-guide",
        "filename": "ai-agents.png",
        "url": "/agents",
        "description": "AI Agents dashboard and coordination",
        "wait_for": "text=AI Agents",
        "actions": []
    },
    {
        "category": "01-user-guide",
        "filename": "nodes-overview.png",
        "url": "/nodes",
        "description": "Nodes management with tunnel overview",
        "wait_for": "text=Nodes",
        "actions": []
    },
    {
        "category": "01-user-guide",
        "filename": "wireguard-management.png",
        "url": "/nodes",
        "description": "WireGuard peer management with QR codes",
        "wait_for": "text=Nodes",
        "actions": [
            {"type": "click", "selector": "text=WireGuard"},
            {"type": "wait", "time": 2000}
        ]
    },
    {
        "category": "01-user-guide",
        "filename": "reports-dashboard.png",
        "url": "/reports",
        "description": "Reports and export functionality",
        "wait_for": "text=Reports",
        "actions": []
    },

    # Management & Health Screenshots
    {
        "category": "02-management",
        "filename": "health-dashboard.png",
        "url": "/settings",
        "description": "System health monitoring dashboard",
        "wait_for": "text=Settings",
        "actions": [
            {"type": "click", "selector": "text=System Status"},
            {"type": "wait", "time": 3000}
        ]
    },
    {
        "category": "02-management",
        "filename": "services-management.png",
        "url": "/settings",
        "description": "Service control and container management",
        "wait_for": "text=Settings",
        "actions": [
            {"type": "click", "selector": "text=Services"},
            {"type": "wait", "time": 2000}
        ]
    },
    {
        "category": "02-management",
        "filename": "diagnostics.png",
        "url": "/settings",
        "description": "Performance monitoring and diagnostics",
        "wait_for": "text=Settings",
        "actions": [
            {"type": "click", "selector": "text=Diagnostics"},
            {"type": "wait", "time": 2000}
        ]
    },

    # Architecture Screenshots
    {
        "category": "03-architecture",
        "filename": "assets-browser.png",
        "url": "/assets",
        "description": "Asset discovery and network topology",
        "wait_for": "text=Assets",
        "actions": []
    },
    {
        "category": "03-architecture",
        "filename": "scan-launcher.png",
        "url": "/scans",
        "description": "Scan pipeline configuration and tool selection",
        "wait_for": "text=Scan",
        "actions": []
    },
    {
        "category": "03-architecture",
        "filename": "about-documentation.png",
        "url": "/about",
        "description": "Architecture documentation and MCP tools",
        "wait_for": "text=About",
        "actions": [
            {"type": "click", "selector": "text=Documentation"},
            {"type": "wait", "time": 2000}
        ]
    }
]


class ScreenshotCapture:
    def __init__(self):
        self.browser = None
        self.page = None
        self.captured_count = 0
        self.failed_count = 0

    async def setup(self):
        """Initialize Playwright and browser"""
        print("🚀 Starting Playwright screenshot capture...")

        # Create screenshots directory structure
        for screenshot in SCREENSHOTS:
            category_dir = SCREENSHOTS_DIR / screenshot["category"]
            category_dir.mkdir(parents=True, exist_ok=True)

        self.playwright = await async_playwright().start()

        # Launch browser with options for screenshot capture
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--window-size=1920,1080"
            ]
        )

        # Create browser context with viewport
        context = await self.browser.new_context(
            viewport=VIEWPORT_SIZE,
            ignore_https_errors=True,  # Accept self-signed certificates
            user_agent="RAG-Scan-Stack Screenshot Bot"
        )

        self.page = await context.new_page()

        # Set longer timeouts for loading
        self.page.set_default_timeout(30000)

    async def cleanup(self):
        """Clean up browser resources"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def execute_action(self, action):
        """Execute a single action on the page"""
        try:
            action_type = action["type"]

            if action_type == "click":
                await self.page.click(action["selector"])
            elif action_type == "click_if_exists":
                try:
                    await self.page.click(action["selector"], timeout=2000)
                except:
                    pass  # Ignore if element doesn't exist
            elif action_type == "fill":
                await self.page.fill(action["selector"], action["value"])
            elif action_type == "fill_if_exists":
                try:
                    await self.page.fill(action["selector"], action["value"], timeout=2000)
                except:
                    pass  # Ignore if element doesn't exist
            elif action_type == "wait":
                await asyncio.sleep(action["time"] / 1000)
            elif action_type == "wait_for":
                await self.page.wait_for_selector(action["selector"])

        except Exception as e:
            print(f"   ⚠️  Action {action_type} failed: {str(e)}")

    async def capture_screenshot(self, screenshot_config):
        """Capture a single screenshot based on configuration"""
        category = screenshot_config["category"]
        filename = screenshot_config["filename"]
        url = screenshot_config["url"]
        description = screenshot_config["description"]

        print(f"\n📷 Capturing: {category}/{filename}")
        print(f"   📍 URL: {BASE_URL}{url}")
        print(f"   📝 Description: {description}")

        try:
            # Navigate to page
            await self.page.goto(f"{BASE_URL}{url}")

            # Wait for initial page load
            if "wait_for" in screenshot_config:
                try:
                    await self.page.wait_for_selector(f"text={screenshot_config['wait_for']}", timeout=10000)
                except:
                    print(f"   ⚠️  Wait condition not met, continuing anyway...")

            await asyncio.sleep(2)  # Additional wait for rendering

            # Execute any page actions
            for action in screenshot_config.get("actions", []):
                await self.execute_action(action)

            # Wait for any animations or loading to complete
            await asyncio.sleep(1)

            # Capture screenshot
            screenshot_path = SCREENSHOTS_DIR / category / filename
            await self.page.screenshot(
                path=str(screenshot_path),
                type="png",
                full_page=True  # Capture full page height
            )

            print(f"   ✅ Saved: {screenshot_path}")
            self.captured_count += 1

        except Exception as e:
            print(f"   ❌ Failed: {str(e)}")
            self.failed_count += 1

    async def capture_all(self):
        """Capture all defined screenshots"""
        start_time = datetime.now()
        print(f"🎯 Starting screenshot capture session...")
        print(f"   📊 Total screenshots to capture: {len(SCREENSHOTS)}")
        print(f"   📂 Output directory: {SCREENSHOTS_DIR}")

        await self.setup()

        try:
            for screenshot_config in SCREENSHOTS:
                await self.capture_screenshot(screenshot_config)

        finally:
            await self.cleanup()

        # Print summary
        end_time = datetime.now()
        duration = end_time - start_time

        print(f"\n🏁 Screenshot capture complete!")
        print(f"   ✅ Successfully captured: {self.captured_count}")
        print(f"   ❌ Failed: {self.failed_count}")
        print(f"   ⏱️  Total time: {duration.total_seconds():.1f} seconds")

        if self.captured_count > 0:
            print(f"\n📁 Screenshots saved to:")
            for category in set(s["category"] for s in SCREENSHOTS):
                category_path = SCREENSHOTS_DIR / category
                if category_path.exists():
                    files = list(category_path.glob("*.png"))
                    print(f"   📂 {category}: {len(files)} files")

        return self.captured_count, self.failed_count


async def check_platform_health():
    """Verify platform is accessible before starting screenshots"""
    print("🔍 Checking platform health...")

    try:
        import httpx
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(f"{BASE_URL}/api/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                status = health_data.get("status", "unknown")
                print(f"   ✅ Platform status: {status}")
                return True
            else:
                print(f"   ❌ Platform not healthy: HTTP {response.status_code}")
                return False
    except ImportError:
        print("   ⚠️  httpx not available, skipping health check")
        return True  # Assume healthy
    except Exception as e:
        print(f"   ❌ Health check failed: {str(e)}")
        return False


def create_screenshot_index():
    """Create an index file listing all captured screenshots"""
    index_path = SCREENSHOTS_DIR / "index.md"

    with open(index_path, "w") as f:
        f.write("# RAG Scan Stack Screenshots\n\n")
        f.write(f"*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")

        for category in sorted(set(s["category"] for s in SCREENSHOTS)):
            f.write(f"## {category.replace('-', ' ').title()}\n\n")

            category_path = SCREENSHOTS_DIR / category
            if category_path.exists():
                screenshots = [s for s in SCREENSHOTS if s["category"] == category]
                for screenshot in screenshots:
                    file_path = category_path / screenshot["filename"]
                    if file_path.exists():
                        f.write(f"### {screenshot['filename']}\n")
                        f.write(f"{screenshot['description']}\n\n")
                        f.write(f"![{screenshot['description']}]({category}/{screenshot['filename']})\n\n")

    print(f"📄 Created screenshot index: {index_path}")


async def main():
    """Main execution function"""
    print("📸 RAG Scan Stack Screenshot Capture")
    print("=====================================\n")

    # Check if platform is accessible
    if not await check_platform_health():
        print("\n❌ Platform is not accessible. Please ensure:")
        print("   1. Docker services are running: docker compose up -d")
        print("   2. Dashboard is accessible: https://localhost:3002")
        print("   3. Services are healthy: docker compose ps")
        return 1

    # Run screenshot capture
    capture = ScreenshotCapture()
    captured, failed = await capture.capture_all()

    if captured > 0:
        create_screenshot_index()

        print(f"\n🎉 Success! Captured {captured} screenshots for your presentation materials.")
        print(f"\n📋 Next steps:")
        print(f"   1. Review screenshots in: {SCREENSHOTS_DIR}")
        print(f"   2. Update presentation markdown files with image references")
        print(f"   3. Convert to PowerPoint/PDF: pandoc *.md -o presentation.pptx")
        return 0
    else:
        print(f"\n💥 No screenshots were captured successfully.")
        print(f"   Check the error messages above and verify platform accessibility.")
        return 1


if __name__ == "__main__":
    import sys
    try:
        result = asyncio.run(main())
        sys.exit(result)
    except KeyboardInterrupt:
        print("\n\n⏹️  Screenshot capture interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {str(e)}")
        sys.exit(1)