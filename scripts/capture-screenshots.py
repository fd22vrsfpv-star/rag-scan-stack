#!/usr/bin/env python3
"""Capture screenshots of all key dashboard pages for the beta guide."""

import asyncio
import os
from pathlib import Path

# pip install playwright && playwright install chromium
from playwright.async_api import async_playwright

BASE_URL = os.environ.get("DASHBOARD_URL", "https://localhost:3002")
OUT_DIR = Path(os.environ.get("SCREENSHOT_DIR", "Docs/screenshots"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

PAGES = [
    ("01-dashboard", "/", "Dashboard — Overview"),
    ("02-scan-launcher", "/scan-launcher", "Scan Launcher — Tool Selection"),
    ("03-scan-monitor", "/scans", "Scan Monitor — Active & Completed"),
    ("04-assets", "/assets", "Assets — Discovered Hosts"),
    ("05-assets-software", "/assets", "Assets — Software Inventory"),
    ("06-findings", "/findings", "Findings Explorer"),
    ("07-follow-ups", "/follow-ups", "Follow-Ups — CVE Triage"),
    ("08-content-intel", "/content-intel", "Content Intelligence"),
    ("09-recon", "/recon", "Recon Explorer"),
    ("10-reports", "/reports", "Reports — Export & Proxy Replay"),
    ("11-engagements", "/engagements", "Engagements"),
    ("12-scope", "/scope", "Scope Intelligence"),
    ("13-nodes", "/nodes", "Nodes — SSH Tunnels & Proxies"),
    ("14-services", "/services", "Services — Health & Diagnostics"),
    ("15-settings", "/settings", "Settings — Configuration"),
    ("16-delta", "/delta", "Delta Compare — Run Comparison"),
    ("17-api-tester", "/api-tester", "API Tester — Swagger Import"),
]


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
        )
        page = await context.new_page()

        for filename, path, title in PAGES:
            url = f"{BASE_URL}{path}"
            print(f"  Capturing: {title} ({url})")
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await page.wait_for_timeout(2000)  # Let charts/data load

                # Special handling for tabs that need clicking
                if filename == "05-assets-software":
                    try:
                        await page.click("text=Software", timeout=3000)
                        await page.wait_for_timeout(1500)
                    except Exception:
                        pass

                await page.screenshot(
                    path=str(OUT_DIR / f"{filename}.png"),
                    full_page=False,
                )
                print(f"    Saved: {filename}.png")
            except Exception as e:
                print(f"    ERROR: {e}")

        await browser.close()
    print(f"\nDone — {len(PAGES)} screenshots saved to {OUT_DIR}/")


if __name__ == "__main__":
    asyncio.run(main())
