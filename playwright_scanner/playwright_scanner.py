"""
Playwright Security Scanner - Main FastAPI Application
Performs browser-based security testing with ZAP integration
"""

import os
import uuid
import logging
import requests
from typing import Dict, List, Optional
from datetime import datetime
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field, HttpUrl
from playwright.async_api import async_playwright
from psycopg2.extras import Json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("playwright-scanner")

# Import validation utilities
from validation import (
    validate_scan_target,
    ValidationError
)

# Import our modules
from content_analyzer import ContentAnalyzer
from param_extractor import extract_params_from_network
from db_utils import (
    get_or_create_asset,
    create_playwright_scan,
    update_playwright_scan,
    create_playwright_finding,
    save_screenshot,
    save_dom_analysis,
    create_zap_session,
    update_zap_session,
    save_content_extraction
)
from security_checks import SecurityChecker
from dom_analyzer import DOMAnalyzer
from screenshot_handler import ScreenshotHandler
from zap_bridge import ZAPBridge

# Environment configuration
BROWSER_TYPE = os.environ.get("BROWSER_TYPE", "chromium")  # chromium, firefox, webkit
DEFAULT_VIEWPORT = {
    "width": int(os.environ.get("VIEWPORT_WIDTH", "1920")),
    "height": int(os.environ.get("VIEWPORT_HEIGHT", "1080"))
}
USER_AGENT = os.environ.get("USER_AGENT", "Mozilla/5.0 (Playwright Security Scanner)")
USE_ZAP = os.environ.get("USE_ZAP", "true").lower() == "true"
HEADLESS = os.environ.get("HEADLESS", "true").lower() == "true"
SCREENSHOT_FORMAT = os.environ.get("SCREENSHOT_FORMAT", "png")

# Webhook configuration
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"


def emit_webhook_event(event_type: str, source: str, data: dict, severity: str = None):
    """Emit a webhook event via the RAG API."""
    if not WEBHOOK_ENABLED:
        return
    try:
        payload = {
            "event_type": event_type,
            "source": source,
            "data": data
        }
        if severity:
            payload["severity"] = severity
        requests.post(
            f"{API_BASE}/webhooks/emit",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json=payload,
            timeout=5,
            verify=False,
        )
    except Exception as e:
        logger.warning(f"Failed to emit webhook: {e}")

# Initialize FastAPI
app = FastAPI(
    title="Playwright Security Scanner",
    description="Browser-based security testing with Playwright and ZAP integration",
    version="1.0.0"
)

# Initialize handlers
screenshot_handler = ScreenshotHandler()
zap_bridge = ZAPBridge() if USE_ZAP else None


# Pydantic models
class ScanRequest(BaseModel):
    url: HttpUrl = Field(..., description="Target URL to scan")
    browser: Optional[str] = Field("chromium", description="Browser type: chromium, firefox, or webkit")
    viewport_width: Optional[int] = Field(1920, description="Browser viewport width")
    viewport_height: Optional[int] = Field(1080, description="Browser viewport height")
    user_agent: Optional[str] = Field(None, description="Custom user agent string")
    use_zap_proxy: Optional[bool] = Field(True, description="Route traffic through ZAP proxy")
    capture_screenshots: Optional[bool] = Field(True, description="Capture screenshots")
    capture_dom: Optional[bool] = Field(True, description="Capture DOM snapshot")
    run_security_checks: Optional[bool] = Field(True, description="Run security checks")
    zap_spider: Optional[bool] = Field(False, description="Run ZAP spider after scan")
    zap_active_scan: Optional[bool] = Field(False, description="Run ZAP active scan")
    timeout: Optional[int] = Field(30, description="Page load timeout in seconds")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    url: str
    findings_count: int
    screenshots_count: int
    started_at: Optional[str]
    completed_at: Optional[str]


# Helper functions
async def perform_scan(scan_request: ScanRequest, scan_id: uuid.UUID):
    """
    Main scan function that runs in background

    Args:
        scan_request: Scan configuration
        scan_id: UUID of the scan record
    """
    browser = None
    context = None
    page = None

    try:
        # Initialize Playwright
        async with async_playwright() as p:
            # Select browser
            if scan_request.browser == "firefox":
                browser = await p.firefox.launch(headless=HEADLESS)
            elif scan_request.browser == "webkit":
                browser = await p.webkit.launch(headless=HEADLESS)
            else:
                browser = await p.chromium.launch(headless=HEADLESS)

            # Configure context with proxy if needed
            context_options = {
                "viewport": {
                    "width": scan_request.viewport_width,
                    "height": scan_request.viewport_height
                },
                "user_agent": scan_request.user_agent or USER_AGENT,
                "ignore_https_errors": True  # For testing purposes
            }

            # Add ZAP proxy if enabled
            if scan_request.use_zap_proxy and zap_bridge:
                if zap_bridge.is_zap_ready():
                    context_options["proxy"] = zap_bridge.get_proxy_config()
                else:
                    print("Warning: ZAP not ready, continuing without proxy")

            context = await browser.new_context(**context_options)
            page = await context.new_page()

            # Lists to collect findings and resources
            findings = []
            network_logs = []
            console_logs = []
            js_errors = []

            # Set up network listener (capture POST bodies for param extraction)
            def _capture_request(req):
                entry = {
                    "url": req.url,
                    "method": req.method,
                    "type": req.resource_type,
                }
                if req.method in ("POST", "PUT", "PATCH"):
                    try:
                        entry["post_data"] = req.post_data or ""
                    except Exception:
                        pass
                network_logs.append(entry)
            page.on("request", _capture_request)

            # Set up console listener
            page.on("console", lambda msg: console_logs.append({
                "type": msg.type,
                "text": msg.text
            }))

            # Set up error listener
            page.on("pageerror", lambda exc: js_errors.append(str(exc)))

            # Navigate to URL
            url_str = str(scan_request.url)
            try:
                response = await page.goto(
                    url_str,
                    timeout=scan_request.timeout * 1000,
                    wait_until="networkidle"
                )
            except Exception as e:
                update_playwright_scan(
                    scan_id,
                    status="failed",
                    errors=[{"error": f"Page load failed: {str(e)}"}]
                )
                return

            # Get asset ID from URL
            parsed_url = urlparse(url_str)
            hostname = parsed_url.netloc
            # For now, use hostname as IP (in real scenario, resolve it)
            asset_id = get_or_create_asset(hostname, hostname=hostname)

            # Initialize analyzers
            security_checker = SecurityChecker()
            dom_analyzer = DOMAnalyzer(page)

            # Perform DOM analysis
            dom_snapshot = None
            if scan_request.capture_dom:
                try:
                    dom_data = await dom_analyzer.analyze()

                    # Save DOM analysis to database (pass initial response to avoid re-navigation)
                    security_headers = await dom_analyzer.analyze_security_headers(response=response)
                    mixed_content = await dom_analyzer.check_mixed_content()
                    cors_config = await dom_analyzer.get_cors_config()
                    dom_snapshot = await dom_analyzer.get_dom_snapshot()

                    save_dom_analysis(
                        scan_id=scan_id,
                        asset_id=asset_id,
                        url=url_str,
                        forms=dom_data['forms'],
                        cookies=dom_data['cookies'],
                        local_storage=dom_data['local_storage'],
                        session_storage=dom_data['session_storage'],
                        javascript_libs=dom_data['javascript_libs'],
                        csp_header=security_headers.get('content-security-policy'),
                        cors_enabled=cors_config['enabled'],
                        cors_config=cors_config,
                        security_headers=security_headers,
                        external_scripts=dom_data['external_scripts'],
                        mixed_content=mixed_content,
                        websockets=dom_data['websockets'],
                        postmessage_usage=dom_data['postmessage_usage'],
                        dom_snapshot=dom_snapshot
                    )
                    logger.info("DOM analysis saved for %s (headers: %s, js_libs: %d)",
                                url_str, list(security_headers.keys())[:5],
                                len(dom_data.get('javascript_libs', [])))
                except Exception as e:
                    logger.error("DOM analysis failed for %s: %s", url_str, e)

                # Content analysis (extract emails, paths, keys, etc.)
                if dom_snapshot:
                    try:
                        content_data = await ContentAnalyzer(dom_snapshot, page).analyze()
                        save_content_extraction(scan_id, asset_id, url_str, content_data)
                        logger.info("Content extraction saved for %s", url_str)
                    except Exception as e:
                        logger.warning("Content analysis failed for %s: %s", url_str, e)

                # Parameter extraction from network requests + DOM forms
                try:
                    param_stats = extract_params_from_network(
                        network_logs, dom_data.get('forms', []), asset_id,
                        discovery_source='playwright',
                    )
                    logger.info("Param extraction: %s", param_stats)
                except Exception as e:
                    logger.warning("Param extraction failed for %s: %s", url_str, e)

            # Run security checks
            if scan_request.run_security_checks:
                headers = await response.all_headers() if response else {}

                # Check clickjacking
                clickjacking_finding = security_checker.check_clickjacking(headers, url_str)
                if clickjacking_finding:
                    findings.append(clickjacking_finding)

                # Check mixed content
                if dom_data:
                    mixed_content_findings = security_checker.check_mixed_content(
                        url_str,
                        network_logs
                    )
                    findings.extend(mixed_content_findings)

                # Check CSRF protection
                if dom_data and dom_data['forms']:
                    csrf_findings = security_checker.check_csrf_protection(
                        dom_data['forms'],
                        url_str
                    )
                    findings.extend(csrf_findings)

                # Check security headers
                header_findings = security_checker.check_security_headers(headers, url_str)
                findings.extend(header_findings)

                # Check sensitive data exposure
                if dom_data:
                    sensitive_findings = security_checker.check_sensitive_data_exposure(
                        dom_data['cookies'],
                        dom_data['local_storage'],
                        dom_data['session_storage'],
                        url_str
                    )
                    findings.extend(sensitive_findings)

                # Check CORS misconfiguration
                cors_finding = security_checker.check_cors_misconfiguration(headers, url_str)
                if cors_finding:
                    findings.append(cors_finding)

            # Save findings to database
            screenshot_count = 0
            for finding in findings:
                # Capture screenshot for critical findings if enabled
                screenshot_id = None
                if scan_request.capture_screenshots and finding['severity'] in ['high', 'critical']:
                    try:
                        img_data, img_hash, metadata = await screenshot_handler.capture_viewport(
                            page,
                            format=SCREENSHOT_FORMAT
                        )
                        screenshot_id = save_screenshot(
                            scan_id=scan_id,
                            url=url_str,
                            image_data=img_data,
                            image_hash=img_hash,
                            viewport=metadata.get('viewport'),
                            format=SCREENSHOT_FORMAT
                        )
                        screenshot_count += 1
                    except Exception as e:
                        print(f"Error capturing screenshot: {e}")

                # Save finding
                create_playwright_finding(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    url=url_str,
                    finding_type=finding['finding_type'],
                    title=finding['title'],
                    severity=finding['severity'],
                    description=finding.get('description'),
                    evidence=finding.get('evidence'),
                    location=finding.get('location'),
                    remediation=finding.get('remediation'),
                    cwe=finding.get('cwe'),
                    owasp_category=finding.get('owasp_category'),
                    screenshot_id=screenshot_id,
                    confidence=finding.get('confidence')
                )

            # Capture full-page screenshot
            if scan_request.capture_screenshots:
                try:
                    img_data, img_hash, metadata = await screenshot_handler.capture_full_page(
                        page,
                        format=SCREENSHOT_FORMAT
                    )
                    save_screenshot(
                        scan_id=scan_id,
                        url=url_str,
                        image_data=img_data,
                        image_hash=img_hash,
                        viewport=metadata.get('viewport'),
                        format=SCREENSHOT_FORMAT,
                        full_page=True
                    )
                    screenshot_count += 1
                except Exception as e:
                    print(f"Error capturing full page screenshot: {e}")

            # Run ZAP scans if requested
            zap_results = None
            if (scan_request.zap_spider or scan_request.zap_active_scan) and zap_bridge:
                context_name = f"playwright-{scan_id}"
                zap_session_id = create_zap_session(
                    playwright_scan_id=scan_id,
                    session_name=context_name,
                    zap_api_key=zap_bridge.zap_api_key,
                    sites=[url_str]
                )

                zap_results = await zap_bridge.scan_with_playwright_session(
                    url=url_str,
                    do_spider=scan_request.zap_spider,
                    do_active_scan=scan_request.zap_active_scan,
                    context_name=context_name
                )

                # Save ZAP findings to web_findings table
                from db_utils import get_db
                with get_db() as conn, conn.cursor() as cur:
                    for zap_finding in zap_results.get('alerts', []):
                        cur.execute(
                            """
                            INSERT INTO web_findings
                            (asset_id, url, source, issue_type, name, severity,
                             evidence, method, payload, cwe, references)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (asset_id, zap_finding['url'], zap_finding['source'],
                             zap_finding['issue_type'], zap_finding['name'],
                             zap_finding['severity'], zap_finding['evidence'],
                             zap_finding.get('method'), zap_finding.get('payload'),
                             zap_finding.get('cwe'), Json(zap_finding.get('references', {})))
                        )
                    conn.commit()

                # Update ZAP session record
                update_zap_session(
                    session_id=zap_session_id,
                    spider_completed=zap_results.get('spider_completed', False),
                    ascan_completed=zap_results.get('active_scan_completed', False),
                    alerts_count=len(zap_results.get('alerts', []))
                )

            # Update scan record with completion
            update_playwright_scan(
                scan_id=scan_id,
                status="completed",
                screenshots=screenshot_count,
                dom_snapshot=scan_request.capture_dom,
                console_logs=console_logs[:100],  # Limit size
                network_logs=[],  # Don't store full logs (too large)
                errors=js_errors[:50],
                metadata={
                    'findings_count': len(findings),
                    'zap_alerts': len(zap_results.get('alerts', [])) if zap_results else 0
                }
            )

            # Insert info finding if no security issues found
            if len(findings) == 0:
                try:
                    from db_utils import get_db
                    db = get_db()
                    with db.cursor() as _cur:
                        _cur.execute("""
                            INSERT INTO web_findings (id, url, source, issue_type, name, severity, evidence, first_seen, last_seen)
                            VALUES (gen_random_uuid(), %s, 'playwright', 'scan-note',
                                    'Playwright scan completed — no vulnerabilities found', 'info',
                                    'Browser-based security checks found no XSS, form injection, cookie, or DOM-based issues.',
                                    now(), now())
                            ON CONFLICT DO NOTHING
                        """, (url_str,))
                    db.commit()
                except Exception as _e:
                    logger.warning(f"Failed to insert info finding: {_e}")

            # Emit webhook for scan completion
            emit_webhook_event("scan_completed", "playwright", {
                "scan_id": str(scan_id),
                "url": url_str,
                "findings_count": len(findings),
                "screenshots_count": screenshot_count,
                "zap_alerts": len(zap_results.get('alerts', [])) if zap_results else 0
            })

    except Exception as e:
        logger.error(f"Scan error: {e}")
        update_playwright_scan(
            scan_id=scan_id,
            status="failed",
            errors=[{"error": str(e)}]
        )

        # Emit webhook for scan failure
        emit_webhook_event("scan_failed", "playwright", {
            "scan_id": str(scan_id),
            "url": str(scan_request.url),
            "error": str(e)
        })
    finally:
        # Cleanup - ignore errors if already closed
        try:
            if page:
                await page.close()
        except Exception:
            pass
        try:
            if context:
                await context.close()
        except Exception:
            pass
        try:
            if browser:
                await browser.close()
        except Exception:
            pass


# API Endpoints
@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "ok": True,
        "service": "playwright-scanner",
        "browser_type": BROWSER_TYPE,
        "zap_enabled": USE_ZAP and zap_bridge is not None and zap_bridge.is_zap_ready()
    }


@app.post("/scan", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Create and start a new Playwright security scan

    The scan runs in the background and tests for:
    - Clickjacking vulnerabilities
    - Mixed content issues
    - CSRF protection
    - Security headers
    - Sensitive data exposure
    - CORS misconfigurations
    - Optional: ZAP spider and active scan
    """
    try:
        # Create scan record
        scan_id = create_playwright_scan(
            url=str(scan_request.url),
            browser=scan_request.browser,
            viewport={"width": scan_request.viewport_width, "height": scan_request.viewport_height},
            user_agent=scan_request.user_agent
        )

        # Emit webhook for scan start
        emit_webhook_event("scan_started", "playwright", {
            "scan_id": str(scan_id),
            "scan_type": "playwright-scan",
            "url": str(scan_request.url),
            "browser": scan_request.browser,
            "use_zap_proxy": scan_request.use_zap_proxy,
            "zap_spider": scan_request.zap_spider,
            "zap_active_scan": scan_request.zap_active_scan
        })

        # Start scan in background
        background_tasks.add_task(perform_scan, scan_request, scan_id)

        return ScanResponse(
            scan_id=str(scan_id),
            status="running",
            message="Scan started successfully"
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@app.get("/jobs/{scan_id}")
async def get_job_status(scan_id: str):
    """Alias for /scan/{scan_id} — used by BFF polling."""
    return await get_scan_status(scan_id)


@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get status and results of a scan"""
    try:
        from db_utils import get_db
        from psycopg2.extras import RealDictCursor

        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get scan info
            cur.execute(
                "SELECT * FROM playwright_scans WHERE id = %s",
                (scan_id,)
            )
            scan = cur.fetchone()

            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")

            # Get findings count
            cur.execute(
                "SELECT COUNT(*) as count FROM playwright_findings WHERE scan_id = %s",
                (scan_id,)
            )
            findings_count = cur.fetchone()['count']

            return {
                "scan_id": str(scan['id']),
                "url": scan['url'],
                "status": scan['status'],
                "browser": scan['browser'],
                "start_time": scan['start_time'].isoformat() if scan['start_time'] else None,
                "end_time": scan['end_time'].isoformat() if scan['end_time'] else None,
                "screenshots": scan['screenshots'],
                "findings_count": findings_count,
                "console_logs_count": len(scan.get('console_logs', [])),
                "errors_count": len(scan.get('errors', []))
            }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity")
):
    """Get findings for a specific scan"""
    try:
        from db_utils import get_db
        from psycopg2.extras import RealDictCursor

        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            sql = "SELECT * FROM playwright_findings WHERE scan_id = %s"
            params = [scan_id]

            if severity:
                sql += " AND severity = %s"
                params.append(severity)

            sql += " ORDER BY severity DESC, created_at DESC"

            cur.execute(sql, params)
            findings = cur.fetchall()

            return {
                "scan_id": scan_id,
                "findings": findings
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Auth Token Capture — OAuth2 clientCredentials + network interception
# ============================================================================

class AuthCaptureRequest(BaseModel):
    login_url: str = Field(..., description="Token URL or login page URL")
    mode: str = Field("client_credentials", description="client_credentials or intercept")
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    token_patterns: list = Field(default=["authorization", "bearer", "token", "jwt", "access_token"])
    wait_seconds: int = Field(30, description="Max wait for intercept mode")
    extra_params: Optional[dict] = None


@app.post("/auth/capture")
async def capture_auth_token(req: AuthCaptureRequest):
    """
    Capture auth tokens via OAuth2 client_credentials flow or network interception.

    - client_credentials: POST to token URL with client_id/secret, return access_token
    - intercept: Launch browser, navigate to login_url, monitor network for tokens
    """
    if req.mode == "client_credentials":
        return await _capture_client_credentials(req)
    elif req.mode == "intercept":
        return await _capture_intercept(req)
    else:
        raise HTTPException(400, f"Unknown mode: {req.mode}. Use 'client_credentials' or 'intercept'")


async def _capture_client_credentials(req: AuthCaptureRequest):
    """Fetch token via OAuth2 client_credentials grant."""
    import httpx

    if not req.client_id or not req.client_secret:
        raise HTTPException(400, "client_id and client_secret required for client_credentials mode")

    form_data = {
        "grant_type": "client_credentials",
        "client_id": req.client_id,
        "client_secret": req.client_secret,
    }
    if req.extra_params:
        form_data.update(req.extra_params)

    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(
                req.login_url,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code >= 400:
                return {
                    "ok": False,
                    "error": f"Token endpoint returned {resp.status_code}",
                    "body": resp.text[:2000],
                }
            body = resp.json()
            return {
                "ok": True,
                "mode": "client_credentials",
                "access_token": body.get("access_token", ""),
                "token_type": body.get("token_type", "Bearer"),
                "expires_in": body.get("expires_in"),
                "full_response": body,
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _capture_intercept(req: AuthCaptureRequest):
    """Launch headless browser, navigate to URL, intercept network traffic for tokens."""
    import asyncio

    captured_tokens = []

    try:
        async with async_playwright() as pw:
            browser = await getattr(pw, BROWSER_TYPE).launch(headless=HEADLESS)
            context = await browser.new_context(
                viewport=DEFAULT_VIEWPORT,
                user_agent=USER_AGENT,
                ignore_https_errors=True,
            )
            page = await context.new_page()

            # Set up response interceptor
            async def on_response(response):
                try:
                    url_str = response.url.lower()
                    headers = response.headers
                    # Check response headers for tokens
                    for key, val in headers.items():
                        for pattern in req.token_patterns:
                            if pattern.lower() in key.lower() or pattern.lower() in val.lower()[:200]:
                                captured_tokens.append({
                                    "source": "response_header",
                                    "url": response.url,
                                    "header": key,
                                    "value": val[:500],
                                })

                    # Check response body for token patterns (JSON responses)
                    content_type = headers.get("content-type", "")
                    if "json" in content_type:
                        try:
                            body = await response.json()
                            if isinstance(body, dict):
                                for key in ("access_token", "token", "jwt", "id_token"):
                                    if key in body:
                                        captured_tokens.append({
                                            "source": "response_body",
                                            "url": response.url,
                                            "key": key,
                                            "value": str(body[key])[:2000],
                                        })
                        except Exception:
                            pass
                except Exception:
                    pass

            page.on("response", on_response)

            await page.goto(req.login_url, wait_until="networkidle", timeout=req.wait_seconds * 1000)

            # Wait a bit more for any XHR calls
            await asyncio.sleep(min(5, req.wait_seconds))

            await browser.close()

        if captured_tokens:
            # Return the most likely token (prefer access_token from body)
            best = next(
                (t for t in captured_tokens if t.get("key") == "access_token"),
                captured_tokens[0],
            )
            return {
                "ok": True,
                "mode": "intercept",
                "access_token": best.get("value", ""),
                "all_captured": captured_tokens,
            }
        else:
            return {
                "ok": False,
                "mode": "intercept",
                "message": "No tokens captured. For interactive login, paste the token manually.",
                "all_captured": [],
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ============================================================================
# PoC Executor — lightweight single-payload injection + screenshot
# ============================================================================

class PoCRequest(BaseModel):
    url: str = Field(..., description="Target URL")
    payload: str = Field(..., description="Attack payload string")
    injection_point: str = Field("query_param", description="Where to inject: query_param, form_field, header, cookie, request_body")
    parameter: Optional[str] = Field(None, description="Target parameter name (for query_param / form_field)")
    success_indicator: Optional[str] = Field(None, description="What to check: alert_dialog, response_contains:X, time_delay, url_change, dom_change")
    capture_screenshots: bool = Field(True, description="Capture before/after screenshots")
    timeout: int = Field(15, description="Page load timeout in seconds")


@app.post("/poc")
async def execute_poc(req: PoCRequest):
    """
    Execute a single PoC payload against a URL.

    Navigates to the URL, injects the payload at the specified point,
    waits for the page, checks for the success indicator, and captures
    before/after screenshots.

    Returns:
        success: whether the indicator was detected
        evidence: text evidence of the result
        screenshot_ids: list of screenshot UUIDs (before, after)
        response_body: first 2000 chars of page content
        dom_changes: summary of DOM changes if detected
    """
    import asyncio
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

    browser = None
    result = {
        "success": False,
        "evidence": "",
        "screenshot_ids": [],
        "response_body": "",
        "dom_changes": "",
        "indicator_type": req.success_indicator or "none",
    }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=HEADLESS)
            context = await browser.new_context(
                viewport=DEFAULT_VIEWPORT,
                user_agent=USER_AGENT,
                ignore_https_errors=True,
            )
            page = await context.new_page()

            # ── Step 1: Navigate to clean URL for "before" state ──
            clean_url = str(req.url)
            try:
                await page.goto(clean_url, timeout=req.timeout * 1000, wait_until="networkidle")
            except Exception as nav_err:
                result["evidence"] = f"Navigation failed: {nav_err}"
                return result

            # Capture "before" screenshot
            before_screenshot_id = None
            if req.capture_screenshots:
                try:
                    img_data, img_hash, meta = await screenshot_handler.capture_viewport(page, format=SCREENSHOT_FORMAT)
                    before_screenshot_id = save_screenshot(
                        scan_id=uuid.uuid4(),  # standalone PoC
                        url=clean_url,
                        image_data=img_data,
                        image_hash=img_hash,
                        viewport=meta.get("viewport"),
                        format=SCREENSHOT_FORMAT,
                        metadata={"poc_stage": "before"},
                    )
                    result["screenshot_ids"].append(str(before_screenshot_id))
                except Exception as ss_err:
                    logger.warning(f"Before screenshot failed: {ss_err}")

            # Get "before" page content for comparison
            before_content = await page.content()

            # ── Step 2: Inject payload ──
            injected_url = clean_url
            alert_detected = False

            if req.injection_point == "query_param" and req.parameter:
                # Append/replace query parameter
                parsed = urlparse(clean_url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[req.parameter] = [req.payload]
                new_query = urlencode(qs, doseq=True)
                injected_url = urlunparse(parsed._replace(query=new_query))

                # Set up alert handler if needed
                if req.success_indicator and "alert_dialog" in req.success_indicator:
                    page.on("dialog", lambda dialog: asyncio.ensure_future(_handle_dialog(dialog)))
                    alert_detected = False

                    async def _handle_dialog(dialog):
                        nonlocal alert_detected
                        alert_detected = True
                        result["evidence"] = f"Alert dialog: {dialog.message}"
                        await dialog.dismiss()

                try:
                    await page.goto(injected_url, timeout=req.timeout * 1000, wait_until="networkidle")
                except Exception:
                    pass  # Page may error on payload — that's expected

            elif req.injection_point == "form_field" and req.parameter:
                # Fill form field and submit
                try:
                    selector = f'input[name="{req.parameter}"], textarea[name="{req.parameter}"]'
                    await page.fill(selector, req.payload)
                    # Try to submit the form
                    form_selector = f'form:has(input[name="{req.parameter}"]), form:has(textarea[name="{req.parameter}"])'
                    await page.evaluate(f'document.querySelector(\'{form_selector}\')?.submit()')
                    await page.wait_for_load_state("networkidle", timeout=req.timeout * 1000)
                except Exception as form_err:
                    result["evidence"] = f"Form injection failed: {form_err}"

            elif req.injection_point == "header":
                # Navigate with custom header
                await context.set_extra_http_headers({req.parameter or "X-Custom": req.payload})
                try:
                    await page.goto(clean_url, timeout=req.timeout * 1000, wait_until="networkidle")
                except Exception:
                    pass

            elif req.injection_point == "cookie":
                # Set cookie and re-navigate
                parsed = urlparse(clean_url)
                await context.add_cookies([{
                    "name": req.parameter or "poc_cookie",
                    "value": req.payload,
                    "domain": parsed.hostname or "localhost",
                    "path": "/",
                }])
                try:
                    await page.goto(clean_url, timeout=req.timeout * 1000, wait_until="networkidle")
                except Exception:
                    pass

            # ── Step 3: Check success indicator ──
            after_content = await page.content()
            after_url = page.url

            indicator = (req.success_indicator or "").lower()

            if "alert_dialog" in indicator:
                if alert_detected:
                    result["success"] = True
                else:
                    result["evidence"] = "No alert dialog detected"

            elif indicator.startswith("response_contains:"):
                search_text = indicator.split(":", 1)[1]
                if search_text.lower() in after_content.lower():
                    result["success"] = True
                    result["evidence"] = f"Response contains '{search_text}'"
                else:
                    result["evidence"] = f"'{search_text}' not found in response"

            elif "time_delay" in indicator:
                # Already handled by page load time — check if navigation was slow
                result["evidence"] = "Time-based check: inspect response timing manually"

            elif "url_change" in indicator:
                if after_url != clean_url and after_url != injected_url:
                    result["success"] = True
                    result["evidence"] = f"URL changed to: {after_url}"
                else:
                    result["evidence"] = f"URL unchanged: {after_url}"

            elif "response_diff" in indicator:
                if after_content != before_content:
                    result["success"] = True
                    result["evidence"] = "Response content changed after payload injection"
                else:
                    result["evidence"] = "No response difference detected"

            elif "response_content" in indicator or not indicator:
                # Generic check — look for payload reflection
                if req.payload in after_content:
                    result["success"] = True
                    result["evidence"] = "Payload reflected in response"
                elif after_content != before_content:
                    result["evidence"] = "Response changed but payload not directly reflected"
                else:
                    result["evidence"] = "No change detected"

            # DOM changes summary
            if after_content != before_content:
                diff_len = abs(len(after_content) - len(before_content))
                result["dom_changes"] = f"Content length delta: {diff_len} chars"

            result["response_body"] = after_content[:2000]

            # ── Step 4: Capture "after" screenshot ──
            if req.capture_screenshots:
                try:
                    img_data, img_hash, meta = await screenshot_handler.capture_viewport(page, format=SCREENSHOT_FORMAT)
                    after_screenshot_id = save_screenshot(
                        scan_id=uuid.uuid4(),
                        url=injected_url,
                        image_data=img_data,
                        image_hash=img_hash,
                        viewport=meta.get("viewport"),
                        format=SCREENSHOT_FORMAT,
                        metadata={"poc_stage": "after"},
                    )
                    result["screenshot_ids"].append(str(after_screenshot_id))
                except Exception as ss_err:
                    logger.warning(f"After screenshot failed: {ss_err}")

            await browser.close()

    except Exception as e:
        logger.error(f"PoC execution error: {e}")
        result["evidence"] = f"Error: {e}"
        if browser:
            try:
                await browser.close()
            except Exception:
                pass

    return result


# ============================================================================
# Crawl endpoint — browser-based crawling that feeds discovered URLs to ZAP
# ============================================================================

class CrawlRequest(BaseModel):
    url: str = Field(..., description="Starting URL to crawl")
    max_depth: int = Field(3, description="Maximum crawl depth (1-5)", ge=1, le=5)
    max_pages: int = Field(100, description="Maximum pages to visit", ge=1, le=500)
    seed_urls: List[str] = Field(default=[], description="Additional seed URLs to crawl")
    use_zap_proxy: bool = Field(True, description="Route all traffic through ZAP proxy")
    timeout_per_page: int = Field(15, description="Page load timeout in seconds")
    same_origin_only: bool = Field(True, description="Only follow same-origin links")
    capture_screenshots: bool = Field(False, description="Screenshot each page")


class CrawlResponse(BaseModel):
    job_id: str
    status: str
    message: str


# In-memory crawl job tracker
_crawl_jobs: Dict[str, dict] = {}


async def _perform_crawl(job_id: str, req: CrawlRequest):
    """
    Browser-based crawl that discovers URLs by following links.
    All traffic goes through ZAP proxy so ZAP builds its site tree.
    Returns discovered URLs for downstream pipeline stages.
    """
    from urllib.parse import urlparse, urljoin
    from collections import deque

    job = _crawl_jobs[job_id]
    job["status"] = "running"
    job["started_at"] = datetime.now().isoformat()

    parsed_origin = urlparse(req.url)
    origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"

    # Track visited and discovered URLs
    visited = set()
    discovered = set()
    queue = deque()  # (url, depth)

    # Seed the queue
    queue.append((req.url, 0))
    for seed in req.seed_urls:
        if seed.strip():
            queue.append((seed.strip(), 0))

    browser = None
    try:
        async with async_playwright() as p:
            launch_args = {"headless": True}
            browser = await p.chromium.launch(**launch_args)

            context_options = {
                "viewport": {"width": 1920, "height": 1080},
                "user_agent": USER_AGENT,
                "ignore_https_errors": True,
            }

            # Route through ZAP proxy
            if req.use_zap_proxy and zap_bridge and zap_bridge.is_zap_ready():
                context_options["proxy"] = zap_bridge.get_proxy_config()
                logger.info(f"[crawl:{job_id[:8]}] ZAP proxy enabled — all traffic feeds ZAP site tree")
            else:
                logger.warning(f"[crawl:{job_id[:8]}] ZAP proxy NOT available — crawling without proxy")

            ctx = await browser.new_context(**context_options)
            page = await ctx.new_page()

            # Capture network requests as additional discovered URLs
            def _on_request(request):
                try:
                    discovered.add(request.url)
                except Exception:
                    pass
            page.on("request", _on_request)

            pages_visited = 0
            while queue and pages_visited < req.max_pages:
                url, depth = queue.popleft()

                # Normalize and skip if visited
                if url in visited:
                    continue
                visited.add(url)

                # Same-origin check
                if req.same_origin_only:
                    parsed = urlparse(url)
                    if f"{parsed.scheme}://{parsed.netloc}" != origin:
                        continue

                # Skip non-http, anchors, common static files
                if not url.startswith(("http://", "https://")):
                    continue
                skip_exts = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                             '.css', '.woff', '.woff2', '.ttf', '.eot',
                             '.mp4', '.mp3', '.avi', '.pdf', '.zip', '.gz')
                if any(url.lower().split('?')[0].endswith(ext) for ext in skip_exts):
                    discovered.add(url)
                    continue

                try:
                    response = await page.goto(
                        url,
                        timeout=req.timeout_per_page * 1000,
                        wait_until="domcontentloaded",
                    )
                    pages_visited += 1
                    discovered.add(url)

                    # Update progress
                    job["pages_visited"] = pages_visited
                    job["urls_discovered"] = len(discovered)

                    # Optional screenshot
                    if req.capture_screenshots:
                        try:
                            ss_path = f"/reports/crawl_{job_id[:8]}_{pages_visited}.png"
                            await page.screenshot(path=ss_path, full_page=False)
                        except Exception:
                            pass

                    # Extract links from the page if we haven't hit max depth
                    if depth < req.max_depth:
                        links = await page.evaluate("""() => {
                            const anchors = Array.from(document.querySelectorAll('a[href]'));
                            const forms = Array.from(document.querySelectorAll('form[action]'));
                            const urls = anchors.map(a => a.href).filter(h => h.startsWith('http'));
                            const formUrls = forms.map(f => f.action).filter(a => a.startsWith('http'));
                            return [...new Set([...urls, ...formUrls])];
                        }""")

                        for link in links:
                            resolved = urljoin(url, link)
                            if resolved not in visited:
                                queue.append((resolved, depth + 1))
                                discovered.add(resolved)

                    if pages_visited % 10 == 0:
                        logger.info(f"[crawl:{job_id[:8]}] Progress: {pages_visited} pages, {len(discovered)} URLs discovered")

                except Exception as e:
                    logger.debug(f"[crawl:{job_id[:8]}] Failed to load {url}: {e}")
                    continue

            await ctx.close()
            await browser.close()
            browser = None

        # Filter to same-origin if requested
        if req.same_origin_only:
            final_urls = sorted([u for u in discovered if u.startswith(origin)])
        else:
            final_urls = sorted(discovered)

        job["status"] = "completed"
        job["completed_at"] = datetime.now().isoformat()
        job["discovered_urls"] = final_urls
        job["pages_visited"] = pages_visited
        job["urls_discovered"] = len(final_urls)

        logger.info(f"[crawl:{job_id[:8]}] Crawl complete: {pages_visited} pages visited, {len(final_urls)} URLs discovered")

    except Exception as e:
        logger.error(f"[crawl:{job_id[:8]}] Crawl failed: {e}")
        job["status"] = "failed"
        job["error"] = str(e)
        job["completed_at"] = datetime.now().isoformat()
        job["discovered_urls"] = sorted(discovered)
        job["urls_discovered"] = len(discovered)
    finally:
        if browser:
            try:
                await browser.close()
            except Exception:
                pass


@app.post("/crawl", response_model=CrawlResponse)
async def start_crawl(req: CrawlRequest, background_tasks: BackgroundTasks):
    """
    Browser-based crawl that discovers URLs by following links.

    All traffic is routed through ZAP proxy so ZAP automatically builds
    its site tree from the crawled pages. The discovered URLs are returned
    so the pipeline can seed them into ZAP's active scan.

    Pipeline usage: Katana → **Playwright crawl** → Gobuster → Nikto → Nuclei → ZAP
    """
    # Validate target
    try:
        validate_scan_target(req.url)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    job_id = str(uuid.uuid4())
    _crawl_jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "target": req.url,
        "pages_visited": 0,
        "urls_discovered": 0,
        "discovered_urls": [],
        "created_at": datetime.now().isoformat(),
    }

    background_tasks.add_task(_perform_crawl, job_id, req)

    return CrawlResponse(
        job_id=job_id,
        status="queued",
        message=f"Crawl started for {req.url} (max_depth={req.max_depth}, max_pages={req.max_pages})"
    )


@app.get("/crawl/{job_id}")
async def get_crawl_status(job_id: str):
    """Get crawl job status and discovered URLs."""
    job = _crawl_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Crawl job not found")
    return job


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8014)
