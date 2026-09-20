"""
Playwright Security Scanner - Main FastAPI Application
Performs browser-based security testing with ZAP integration
"""

import os
import uuid
import time
import asyncio
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

# ── Engagement context (Option B / Phase 5) — see nmap_scanner for docs. ──
try:
    from audit_writer import current_engagement_id  # type: ignore

    @app.middleware("http")
    async def _capture_engagement_for_audit(request, call_next):
        eid = request.headers.get("x-engagement-id") or request.headers.get("X-Engagement-Id")
        token = current_engagement_id.set(eid or None)
        try:
            return await call_next(request)
        finally:
            current_engagement_id.reset(token)
except ImportError:
    pass

# Initialize handlers
screenshot_handler = ScreenshotHandler()
zap_bridge = ZAPBridge() if USE_ZAP else None


# Pydantic models
# ── Authorization gate ──────────────────────────────────────────────────────
# This service drives a real browser at whatever URL it is handed, across FOUR
# entry points — /scan, /auth/capture, /poc and /crawl — and none of them
# checked the engagement scope. /poc is the sharpest: it injects an attack
# payload into a URL and loads it.
#
# The gate takes a HOST, so the hostname is extracted from the URL. A URL whose
# host cannot be parsed is refused rather than passed through: an unparseable
# target is "cannot check", and cannot-check must never read as authorised.
try:
    from etl.scope_gate import enforce_target_scope
    _SCOPE_GATE_OK = True
    _SCOPE_GATE_ERROR = ""
except Exception as _scope_exc:            # pragma: no cover - deployment problem
    _SCOPE_GATE_OK = False
    _SCOPE_GATE_ERROR = str(_scope_exc)


# Bound by the shared ceiling rather than a private number. Each browser session
# is one scan's worth of load; see the per-service note in common/tool_job.py.
try:
    from common.tool_job import async_scan_slot, MAX_CONCURRENT_SCANS
    _SLOTS_OK = True
    _SLOTS_ERROR = ""
except Exception as _slot_exc:             # pragma: no cover - deployment problem
    _SLOTS_OK = False
    _SLOTS_ERROR = str(_slot_exc)
    MAX_CONCURRENT_SCANS = 0

    from contextlib import asynccontextmanager as _acm

    @_acm
    async def async_scan_slot(job_id: str = "", label: str = "scan", timeout=None):
        raise RuntimeError(
            f"scan slot pool unavailable ({_SLOTS_ERROR}) — check the "
            "./common:/app/common mount on playwright-scanner")
        yield  # pragma: no cover


def _scope_refusal_for_url(url, context: str = ""):
    """Refusal string when this URL must NOT be fetched, else None. Fails closed."""
    if not _SCOPE_GATE_OK:
        return (f"scope gate unavailable ({_SCOPE_GATE_ERROR}) — refusing to "
                "browse; check the ./etl:/app/etl mount on playwright-scanner")
    try:
        host = urlparse(str(url or "")).hostname
    except Exception as exc:
        return f"could not parse a host out of {url!r} ({exc}) — refusing"
    if not host:
        return f"no host in {url!r} — refusing rather than guessing"
    return enforce_target_scope(host, context or str(url))


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
    #: OFF by default — the ajax spider drives real browsers (memory-heavy, slow)
    #: and is redundant once the authenticated Playwright crawl has seeded the tree.
    #: Opt-in for a JS-heavy SPA the traditional spider can't map.
    zap_ajax_spider: Optional[bool] = Field(False, description="Run the ZAP ajax (browser) spider — off by default")
    #: >0 chunks the active scan into batches of this many URLs, flushing ZAP's
    #: message store to disk between batches so peak memory stays bounded. 0 =
    #: whole-tree active scan (grows to fill the heap on large sites).
    zap_active_scan_chunk_size: Optional[int] = Field(0, description="Active-scan batch size (0 = whole tree)")
    auth: Optional[Dict] = Field(None, description="ZAP form-auth for an authenticated scan: {login_url, login_data (with {%username%}/{%password%}), username, password, logged_in_regex?, logged_out_regex?}. If omitted, a stored per-host config is used.")
    #: Run the ZAP Access Control Testing add-on (broken access control / IDOR)
    #: after the authenticated crawl+spider. Off by default. Best with a second
    #: user (below) for the horizontal-IDOR comparison; the ajax spider should be
    #: on so dropdown/form object-ref params are in the tree to compare.
    zap_access_control: Optional[bool] = Field(False, description="Run the ZAP access-control (IDOR) scan — off by default")
    #: A SECOND user for the access-control comparison: {username, password}. If
    #: omitted, one is auto-resolved from a second credential for the same host.
    second_auth: Optional[Dict] = Field(None, description="Second user {username, password} for the access-control (IDOR) comparison")
    #: Engagement for resolving the stored Auth Profile. The X-Engagement-Id header
    #: contextvar is RESET when the request returns, but the ZAP scan runs after
    #: that — so the header alone resolves to None. Carrying it in the body lets the
    #: scan resolve the (engagement-scoped) profile regardless.
    engagement_id: Optional[str] = Field(None, description="Engagement id for resolving the stored Auth Profile")
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
    refusal = _scope_refusal_for_url(scan_request.url, f"playwright scan {scan_request.url}")
    if refusal:
        logger.warning("REFUSED playwright scan of %s: %s", scan_request.url, refusal)
        # 'blocked', not 'failed': a refusal is a decision, and an operator
        # reading "failed" would retry it. CLAUDE.md — blocked items must be
        # labelled, not silently dropped.
        update_playwright_scan(scan_id=scan_id, status="blocked",
                               errors=[{"error": refusal, "blocked": "out_of_scope"}])
        emit_webhook_event("playwright_scan_blocked", "playwright", {
            "scan_id": str(scan_id), "url": str(scan_request.url),
            "reason": refusal,
        })
        return

    async with async_scan_slot(job_id=str(scan_id), label="playwright"):
        await _perform_scan_slotted(scan_request, scan_id)


async def _perform_scan_slotted(scan_request: ScanRequest, scan_id: uuid.UUID):
    """Body of perform_scan(), inside the scope gate and a scan slot."""
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

            # Get asset ID from URL.
            #
            # .hostname, not .netloc: netloc keeps the port ("host:8080") and the
            # userinfo, so an IP target became the un-resolvable string
            # "192.168.1.150:8080" and landed on the 0.0.0.0 placeholder asset.
            #
            # And when the host IS an ip literal, do NOT pass it as the hostname.
            # This called get_or_create_asset(netloc, hostname=netloc), which
            # wrote assets(ip='X', hostname='X'). The unique index is
            # ix_assets_ip_hostname(ip, COALESCE(hostname,'')), so 'X' and ''
            # count as different rows — creating a second asset for a host that
            # already had one. Ports hang off asset_id, so every asset row for
            # an IP carried its own copy of that host's ports: 99 port rows for
            # 59 real (ip, proto, port) tuples.
            # get_or_create_asset drops a hostname that is merely the ip, so
            # passing both is safe and other callers get the same protection.
            parsed_url = urlparse(url_str)
            host = parsed_url.hostname or ""
            asset_id = get_or_create_asset(host, hostname=host)

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

                # Client-side WSTG family (CLNT-01/02/10/11/12/13) from the live
                # browser — DOM sinks, unsafe eval, ws://, origin-less postMessage,
                # sensitive storage, cross-origin scripts without SRI.
                if dom_data:
                    try:
                        findings.extend(security_checker.check_client_side(
                            dom_data.get('client_signals'),
                            dom_data.get('local_storage'),
                            dom_data.get('session_storage'),
                            url_str))
                    except Exception as e:
                        logger.warning("client-side checks failed for %s: %s", url_str, e)

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

                # Auth: explicit request auth wins; otherwise a stored per-host
                # config (set via /web-auth) so the auto-driven pipeline scans
                # login-gated apps authenticated without the caller passing creds.
                try:
                    _eid = current_engagement_id.get()
                except Exception:  # noqa: BLE001
                    _eid = None
                # The header contextvar is reset when the request returns, but this
                # ZAP work runs after that — fall back to the body's engagement_id so
                # the engagement-scoped Auth Profile still resolves.
                _eid = _eid or getattr(scan_request, "engagement_id", None)
                _auth = scan_request.auth or _resolve_web_auth(url_str, _eid)
                _do_ac = bool(getattr(scan_request, "zap_access_control", False))
                # Second user for the access-control (IDOR) comparison: explicit, or
                # auto-resolved from a second credential registered for the host.
                _second = getattr(scan_request, "second_auth", None)
                if _do_ac and not _second and _auth:
                    _second = _resolve_second_web_auth(url_str, _eid, _auth)
                zap_results = await zap_bridge.scan_with_playwright_session(
                    url=url_str,
                    do_spider=scan_request.zap_spider,
                    do_active_scan=scan_request.zap_active_scan,
                    context_name=context_name,
                    auth=_auth,
                    do_ajax_spider=bool(getattr(scan_request, "zap_ajax_spider", False)),
                    active_scan_chunk_size=int(getattr(scan_request, "zap_active_scan_chunk_size", 0) or 0),
                    second_auth=_second,
                    do_access_control=_do_ac,
                )
                if _auth:
                    logger.info(f"ZAP authenticated scan for {url_str} (login {_auth.get('login_url')})")

                # Save ZAP findings to web_findings table
                from db_utils import get_db
                with get_db() as conn, conn.cursor() as cur:
                    for zap_finding in zap_results.get('alerts', []):
                        # web_findings.cwe is text[], but the ZAP alert carries a
                        # single string ("CWE-79") — psycopg2 cannot adapt a str
                        # to an array, so the insert failed on the type as well
                        # as on the column name. etl/parse_zap.py builds a list
                        # for the same column; match it.
                        cwe_value = zap_finding.get('cwe')
                        if cwe_value is None or cwe_value == []:
                            cwe_array = None
                        elif isinstance(cwe_value, (list, tuple)):
                            cwe_array = [str(c) for c in cwe_value if c]
                        else:
                            cwe_array = [str(cwe_value)]
                        cur.execute(
                            """
                            -- `refs` (jsonb), not `references` — which is both the
                            -- wrong column name and a SQL reserved word, so every
                            -- ZAP finding from this path failed to save. Matches
                            -- how etl/parse_zap.py writes the same data.
                            INSERT INTO web_findings
                            (asset_id, url, source, issue_type, name, severity,
                             evidence, method, payload, cwe, refs)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (asset_id, zap_finding['url'], zap_finding['source'],
                             zap_finding['issue_type'], zap_finding['name'],
                             zap_finding['severity'], zap_finding['evidence'],
                             zap_finding.get('method'), zap_finding.get('payload'),
                             cwe_array, Json(zap_finding.get('references', {})))
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


def _ensure_web_auth_table():
    """web_auth_configs: per-host ZAP form-auth so the auto-driven pipeline can
    scan login-gated apps authenticated. Runtime CREATE for existing DBs (also in
    db_init for clean builds)."""
    try:
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS web_auth_configs (
                    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                    host text NOT NULL UNIQUE,
                    login_url text NOT NULL,
                    login_data text NOT NULL,
                    username text NOT NULL,
                    password text,
                    logged_in_regex text,
                    logged_out_regex text,
                    auth_type text DEFAULT 'form',
                    csrf_field text,
                    enabled boolean DEFAULT true,
                    engagement_id uuid,
                    created_at timestamptz DEFAULT now(),
                    updated_at timestamptz DEFAULT now()
                )""")
            cur.execute("ALTER TABLE web_auth_configs ADD COLUMN IF NOT EXISTS auth_type text DEFAULT 'form'")
            cur.execute("ALTER TABLE web_auth_configs ADD COLUMN IF NOT EXISTS csrf_field text")
            # Auth Profile columns: credential_id (resolve secret at scan time, no
            # plaintext) + session (reusable cookies/headers, feeds ZAP + Burp).
            cur.execute("ALTER TABLE web_auth_configs ADD COLUMN IF NOT EXISTS credential_id uuid")
            cur.execute("ALTER TABLE web_auth_configs ADD COLUMN IF NOT EXISTS session jsonb DEFAULT '{}'::jsonb")
            for col in ("login_url", "login_data", "username"):
                cur.execute(f"ALTER TABLE web_auth_configs ALTER COLUMN {col} DROP NOT NULL")
            # per-(engagement,host) uniqueness (COALESCE nullable engagement_id)
            cur.execute("ALTER TABLE web_auth_configs DROP CONSTRAINT IF EXISTS web_auth_configs_host_key")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_web_auth_configs_eng_host "
                        "ON web_auth_configs (COALESCE(engagement_id, "
                        "'00000000-0000-0000-0000-000000000000'::uuid), host)")
            conn.commit()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"web_auth_configs ensure failed: {e}")


def _resolve_web_auth(url: str, engagement_id: Optional[str] = None):
    """Resolve the Auth Profile for this URL's host into a ready-to-use auth dict.

    Engagement-scoped: prefers a row for `engagement_id`, else a global
    (NULL-engagement) row; NEVER applies another engagement's profile to this one
    (the previous host-only lookup leaked a stored credential across engagements).
    The secret is resolved at THIS point: from `credential_id` -> credential_findings
    (never stored plaintext in the profile), falling back to an inline `password`
    for back-compat. Also returns the reusable `session` (cookies/headers)."""
    try:
        import json as _json
        from urllib.parse import urlparse
        from db_utils import get_db
        pu = urlparse(url if "://" in url else f"http://{url}")
        netloc, host = pu.netloc, pu.hostname
        if not netloc:
            return None
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT login_url, login_data, username, password,
                          logged_in_regex, logged_out_regex, auth_type, csrf_field,
                          credential_id, session, engagement_id
                     FROM web_auth_configs
                    WHERE enabled AND host IN (%s, %s)
                      AND (engagement_id IS NULL
                           OR (%s::uuid IS NOT NULL AND engagement_id = %s::uuid))
                    ORDER BY (engagement_id IS NOT NULL) DESC, (host = %s) DESC
                    LIMIT 1""",
                (netloc, host, engagement_id, engagement_id, netloc))
            r = cur.fetchone()
            if not r:
                return None
            password = r[3]
            cred_id = r[8]
            # Resolve the secret from credential_findings at scan time.
            if cred_id:
                try:
                    cur.execute("SELECT secret_value FROM credential_findings "
                                "WHERE id = %s::uuid", (str(cred_id),))
                    cr = cur.fetchone()
                    if cr and cr[0]:
                        password = cr[0]
                except Exception as ce:  # noqa: BLE001
                    logger.warning(f"credential_id resolve failed: {ce}")
        session = r[9]
        if isinstance(session, str):
            try:
                session = _json.loads(session)
            except Exception:  # noqa: BLE001
                session = {}
        # Auto-refresh a near-expiry access token so a long authenticated scan
        # doesn't silently drop mid-run (durability for every token flow).
        session = _maybe_refresh_session(host or netloc, r[10], session or {})
        return {"login_url": r[0], "login_data": r[1], "username": r[2],
                "password": password, "logged_in_regex": r[4],
                "logged_out_regex": r[5], "auth_type": r[6], "csrf_field": r[7],
                "credential_id": str(cred_id) if cred_id else None,
                "session": session or {}}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"web auth resolve failed for {url}: {e}")
        return None


def _resolve_second_web_auth(url: str, engagement_id: Optional[str], primary_auth: Optional[Dict]):
    """Resolve a SECOND distinct web credential for the access-control (IDOR)
    comparison: a different username at the same target with a resolvable secret.
    credential_findings is IP-keyed, so we anchor on the primary credential's IP
    when known (else fall back to any distinct web credential). Returns
    {username, password} or None (single-cred → the scan still runs one-user)."""
    try:
        from db_utils import get_db
        primary_user = (primary_auth or {}).get("username") or ""
        cred_id = (primary_auth or {}).get("credential_id")
        with get_db() as conn, conn.cursor() as cur:
            target_ip = None
            if cred_id:
                cur.execute("SELECT ip::text FROM credential_findings WHERE id=%s::uuid",
                            (str(cred_id),))
                row = cur.fetchone()
                if row:
                    target_ip = row[0]
            web_types = "('password','web','http','form','login','')"
            if target_ip:
                cur.execute(
                    f"""SELECT username, secret_value FROM credential_findings
                         WHERE ip = %s::inet AND username <> %s
                           AND secret_value IS NOT NULL
                           AND COALESCE(auth_type,'') IN {web_types}
                         ORDER BY (valid_cred IS TRUE) DESC, created_at DESC
                         LIMIT 1""",
                    (target_ip, primary_user))
            else:
                cur.execute(
                    f"""SELECT username, secret_value FROM credential_findings
                         WHERE username <> %s AND secret_value IS NOT NULL
                           AND COALESCE(auth_type,'') IN {web_types}
                         ORDER BY (valid_cred IS TRUE) DESC, created_at DESC
                         LIMIT 1""",
                    (primary_user,))
            r = cur.fetchone()
            if r and r[0]:
                return {"username": r[0], "password": r[1] or ""}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"second web auth resolve failed for {url}: {e}")
    return None


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


@app.post("/web-auth")
async def set_web_auth(body: Dict):
    """Store/UPSERT an Auth Profile — one portable, tool-agnostic auth model.
    Body: {host, engagement_id?, enabled?,
           login_url?, login_data?, username?, csrf_field?, auth_type?,
           logged_in_regex?, logged_out_regex?,
           credential_id?,        # resolve the secret at scan time (preferred)
           password?,             # inline secret (back-compat; discouraged)
           session?}              # {cookies:[...], headers:{...}} reusable session
    Requires `host` plus at least ONE of: a login macro (login_url+login_data),
    a credential_id, or a session. Upserts per (engagement_id, host)."""
    import json as _json
    _ensure_web_auth_table()
    host = (body.get("host") or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="missing required: host")
    has_macro = (body.get("login_url") or "").strip() and (body.get("login_data") or "").strip()
    has_cred = bool(body.get("credential_id"))
    has_session = bool(body.get("session"))
    if not (has_macro or has_cred or has_session):
        raise HTTPException(status_code=400, detail=(
            "provide at least one of: a login macro (login_url+login_data), "
            "credential_id, or session"))
    session = body.get("session") or {}
    if not isinstance(session, dict):
        raise HTTPException(status_code=400, detail="session must be an object")
    from db_utils import get_db
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO web_auth_configs
                      (host, login_url, login_data, username, password,
                       logged_in_regex, logged_out_regex, auth_type, csrf_field,
                       enabled, engagement_id, credential_id, session)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    ON CONFLICT (COALESCE(engagement_id,
                        '00000000-0000-0000-0000-000000000000'::uuid), host)
                    DO UPDATE SET
                      login_url=EXCLUDED.login_url, login_data=EXCLUDED.login_data,
                      username=EXCLUDED.username, password=EXCLUDED.password,
                      logged_in_regex=EXCLUDED.logged_in_regex,
                      logged_out_regex=EXCLUDED.logged_out_regex,
                      auth_type=EXCLUDED.auth_type, csrf_field=EXCLUDED.csrf_field,
                      enabled=EXCLUDED.enabled, credential_id=EXCLUDED.credential_id,
                      session=EXCLUDED.session, updated_at=now()""",
                (host,
                 (body.get("login_url") or "").strip() or None,
                 (body.get("login_data") or "").strip() or None,
                 (body.get("username") or "").strip() or None,
                 # Do not persist a plaintext password when a credential_id is given.
                 (None if has_cred else body.get("password")),
                 body.get("logged_in_regex"), body.get("logged_out_regex"),
                 (body.get("auth_type") or ("csrf" if body.get("csrf_field") else "form")),
                 body.get("csrf_field"),
                 bool(body.get("enabled", True)), body.get("engagement_id"),
                 body.get("credential_id"), _json.dumps(session)))
            conn.commit()
        return {"ok": True, "host": host}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/web-auth")
async def list_web_auth():
    """List Auth Profiles (secrets never returned)."""
    _ensure_web_auth_table()
    from db_utils import get_db
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT host, login_url, username, (password IS NOT NULL), enabled, "
            "updated_at, auth_type, (credential_id IS NOT NULL), "
            "(COALESCE(session,'{}'::jsonb) <> '{}'::jsonb), engagement_id "
            "FROM web_auth_configs ORDER BY host")
        rows = cur.fetchall()
    return {"configs": [
        {"host": r[0], "login_url": r[1], "username": r[2],
         "has_password": r[3], "enabled": r[4],
         "updated_at": r[5].isoformat() if r[5] else None,
         "auth_type": r[6], "has_credential": r[7], "has_session": r[8],
         "engagement_id": str(r[9]) if r[9] else None} for r in rows]}


@app.delete("/web-auth/{host}")
async def delete_web_auth(host: str, engagement_id: Optional[str] = None):
    """Delete the Auth Profile for a host (optionally engagement-scoped)."""
    _ensure_web_auth_table()
    from db_utils import get_db
    try:
        with get_db() as conn, conn.cursor() as cur:
            if engagement_id:
                cur.execute("DELETE FROM web_auth_configs WHERE host=%s AND engagement_id=%s::uuid",
                            (host, engagement_id))
            else:
                cur.execute("DELETE FROM web_auth_configs WHERE host=%s AND engagement_id IS NULL",
                            (host,))
            n = cur.rowcount
            conn.commit()
        return {"ok": True, "host": host, "deleted": n}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e))


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
    persist_host: Optional[str] = Field(None, description="If set, persist the captured token into a session-only Auth Profile for this host (reusable by ZAP/Burp).")
    engagement_id: Optional[str] = None
    # authorization_code mode (scripted OAuth2 where the IdP allows programmatic login)
    authorize_url: Optional[str] = None
    token_url: Optional[str] = None
    redirect_uri: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    code_verifier: Optional[str] = None
    totp_secret: Optional[str] = None
    # headless OIDC: discover endpoints from an issuer; ROPC / device-code
    issuer: Optional[str] = None
    scope: Optional[str] = None
    device_code: Optional[str] = None


def _persist_session(host: str, session: dict, engagement_id=None,
                     auth_type: str = "token"):
    """Upsert a captured SESSION (cookies + headers + storage) into a session-only
    Auth Profile for `host`, so a session obtained interactively (SSO/OAuth/SAML/
    MFA) or imported by the operator is reusable by later ZAP scans and the Burp
    bundle. Best-effort."""
    if not host or not session:
        return False
    import json as _json
    _ensure_web_auth_table()
    try:
        from db_utils import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO web_auth_configs (host, auth_type, session, enabled, engagement_id)
                   VALUES (%s,%s,%s::jsonb,true,%s)
                   ON CONFLICT (COALESCE(engagement_id,
                       '00000000-0000-0000-0000-000000000000'::uuid), host)
                   DO UPDATE SET session=EXCLUDED.session, auth_type=EXCLUDED.auth_type,
                     updated_at=now()""",
                (host, auth_type, _json.dumps(session), engagement_id))
            conn.commit()
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning(f"persist session failed for {host}: {e}")
        return False


def _maybe_refresh_session(host, engagement_id, session: dict) -> dict:
    """If the session's access token is near expiry and carries a refresh_token,
    mint a fresh one (grant_type=refresh_token) and persist it — so a long
    authenticated scan stays logged in. Sync + best-effort; returns the (possibly
    refreshed) session unchanged on any problem."""
    try:
        import oidc_flows as of
        if not of.needs_refresh(session):
            return session
        form = of.refresh_form(session)
        if not form:
            return session
        r = requests.post(form["url"], data=form["data"],
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          timeout=15, verify=False)
        if r.status_code >= 400:
            logger.warning(f"token refresh for {host} failed: {r.status_code}")
            return session
        updated = of.apply_refresh(session, r.json())
        _persist_session(host, updated, engagement_id, "token")
        logger.info(f"[auth] refreshed access token for {host}")
        return updated
    except Exception as e:  # noqa: BLE001
        logger.warning(f"token refresh error for {host}: {e}")
        return session


def _persist_session_headers(host: str, headers: dict, engagement_id=None):
    """Back-compat: persist header-only session material (OAuth2 client-creds)."""
    if not headers:
        return False
    return _persist_session(host, {"headers": headers, "captured_from": "auth_capture"},
                            engagement_id)


@app.post("/auth/import-session")
async def import_session(body: Dict):
    """Manual import: tie an interactively-obtained session (the operator logged
    in via SSO/OAuth/MFA in their OWN browser) into an Auth Profile. Body:
    {host, engagement_id?, cookies?:[{name,value}], storage_state?, har?,
    headers?}. Builds a replayable session and upserts a session-only profile."""
    import session_capture as sc
    host = (body.get("host") or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="host is required")
    session = None
    if body.get("storage_state"):
        session = sc.session_from_storage_state(body["storage_state"], captured_from="import:storage_state")
    elif body.get("har"):
        session = sc.session_from_har(body["har"], captured_from="import:har")
    else:
        session = sc.build_session(cookies=body.get("cookies"),
                                   headers=body.get("headers"),
                                   captured_from="import:manual")
    if not (session.get("cookies") or session.get("headers")):
        raise HTTPException(status_code=400, detail="no session material found (provide cookies, headers, storage_state, or har)")
    ok = _persist_session(host, session, body.get("engagement_id"),
                          auth_type="session")
    if not ok:
        raise HTTPException(status_code=500, detail="failed to persist session")
    return {"ok": True, "host": host,
            "cookies": len(session.get("cookies") or []),
            "headers": sorted((session.get("headers") or {}).keys())}


# Held browser contexts for out-of-band-OTP interactive logins (id -> objects).
_login_sessions: Dict[str, dict] = {}
_LOGIN_TTL = 300

_OTP_SELECTOR = ("input[autocomplete='one-time-code'], input[name*='otp' i], "
                 "input[name*='code' i], input[name*='token' i], input[id*='otp' i]")


# Selectors that cover the common IdPs without per-provider hardcoding: email-first
# flows (Azure AD, Google) split username/password across pages; Keycloak/Okta are
# single-page. The multi-step loop fills whatever visible field is present each step.
_USER_SEL = ("input[type='email'], input[name*='user' i], input[name*='email' i], "
             "input#identifierId, input#okta-signin-username, input#username, "
             "input[type='text']:not([type='hidden'])")
_PASS_SEL = "input[type='password']:not([aria-hidden='true'])"
_SUBMIT_SEL = ("button[type='submit'], input[type='submit'], #idSIButton9, "
               "#kc-login, #okta-signin-submit, button")


async def _fill_if_present(page, selector, value):
    """Fill a visible, empty field; return True if we filled it."""
    try:
        el = await page.query_selector(selector)
        if el and await el.is_visible() and not (await el.input_value()):
            await el.fill(value, timeout=8000)
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


async def _drive_login(page, url, username, password, user_sel, pass_sel, submit_sel):
    """MULTI-STEP login that follows OAuth/OIDC/SAML redirects and handles
    provider email-first flows (Azure/Google: email → Next → password → Sign in →
    'Stay signed in?') as well as single-page forms (Keycloak/Okta). Fills
    whatever visible field each page presents, up to a few steps."""
    await page.goto(url, wait_until="domcontentloaded", timeout=25000)
    for step in range(4):
        filled = False
        if username:
            filled |= await _fill_if_present(page, user_sel or _USER_SEL, username)
        if password:
            filled |= await _fill_if_present(page, pass_sel or _PASS_SEL, password)
        try:
            btn = await page.query_selector(submit_sel or _SUBMIT_SEL)
            if btn:
                await btn.click()
        except Exception as e:  # noqa: BLE001
            logger.info(f"[interactive-login] submit note (step {step}): {e}")
        try:
            await page.wait_for_load_state("networkidle", timeout=12000)
        except Exception:  # noqa: BLE001
            pass
        # Done once there is nothing left to fill (and we advanced at least once).
        if step > 0 and not filled:
            break


async def _otp_present(page, otp_sel):
    try:
        return (await page.query_selector(otp_sel or _OTP_SELECTOR)) is not None
    except Exception:  # noqa: BLE001
        return False


async def _capture_login(context, page, host, engagement_id):
    import session_capture as sc
    state = await context.storage_state()
    session = sc.session_from_storage_state(state, captured_from="interactive")
    _persist_session(host, session, engagement_id, auth_type="session")
    return {"cookies": len(session.get("cookies") or []),
            "has_bearer": "Authorization" in (session.get("headers") or {}),
            "final_url": page.url}


async def _teardown_login(rec):
    for k in ("context", "browser"):
        try:
            await rec[k].close()
        except Exception:  # noqa: BLE001
            pass
    try:
        await rec["pw"].stop()
    except Exception:  # noqa: BLE001
        pass


def _sweep_login_sessions():
    now = time.time()
    for sid in [s for s, r in _login_sessions.items() if now - r["created"] > _LOGIN_TTL]:
        rec = _login_sessions.pop(sid, None)
        if rec:
            asyncio.ensure_future(_teardown_login(rec))


@app.post("/auth/interactive-login")
async def interactive_login(body: Dict):
    """Assisted interactive login for SSO/OAuth/OIDC/SAML (and MFA): drive a real
    browser through the login, following the IdP redirect chain, then CAPTURE the
    resulting session (cookies + localStorage token) into an Auth Profile that
    ZAP/Burp replay. MFA: pass `totp_secret` (computed here) or `otp`; if MFA is
    required and neither is given, the browser is held and {mfa_required,
    login_session_id} is returned for POST /auth/interactive-login/{id}/otp.
    Body: {login_url, host?, engagement_id?, username?, password?, user_selector?,
    pass_selector?, submit_selector?, otp_selector?, totp_secret?, otp?,
    success_url_contains?}."""
    import session_capture as sc
    from urllib.parse import urlparse
    login_url = (body.get("login_url") or "").strip()
    if not login_url:
        raise HTTPException(status_code=400, detail="login_url is required")
    refusal = _scope_refusal_for_url(login_url, "interactive login")
    if refusal:
        raise HTTPException(status_code=403, detail=refusal)
    host = (body.get("host") or urlparse(login_url).hostname or "").strip()
    eid = body.get("engagement_id")
    _sweep_login_sessions()

    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=True)
    context = await browser.new_context(ignore_https_errors=True, user_agent=USER_AGENT)
    page = await context.new_page()
    rec = {"pw": pw, "browser": browser, "context": context, "page": page,
           "host": host, "engagement_id": eid, "created": time.time()}
    try:
        await _drive_login(page, login_url, body.get("username"), body.get("password"),
                           body.get("user_selector"), body.get("pass_selector"),
                           body.get("submit_selector"))
        if await _otp_present(page, body.get("otp_selector")):
            otp = body.get("otp") or (sc.totp_now(body["totp_secret"]) if body.get("totp_secret") else None)
            if not otp:
                # Out-of-band OTP (SMS/email): hold the browser for a resume call.
                sid = str(uuid.uuid4())
                _login_sessions[sid] = rec
                return {"ok": True, "mfa_required": True, "login_session_id": sid,
                        "host": host, "message": "OTP required — resume via "
                        "POST /auth/interactive-login/{id}/otp"}
            try:
                await page.fill(body.get("otp_selector") or _OTP_SELECTOR, str(otp), timeout=8000)
                await page.click(body.get("submit_selector")
                                 or "button[type='submit'], input[type='submit'], button")
                await page.wait_for_load_state("networkidle", timeout=15000)
            except Exception as e:  # noqa: BLE001
                logger.info(f"[interactive-login] otp fill note: {e}")
        cap = await _capture_login(context, page, host, eid)
        suc = body.get("success_url_contains")
        authenticated = (suc in page.url) if suc else bool(cap["cookies"] or cap["has_bearer"])
        return {"ok": True, "authenticated": authenticated, "host": host, **cap}
    finally:
        # Not held for OTP resume -> tear down now.
        if not any(r is rec for r in _login_sessions.values()):
            await _teardown_login(rec)


@app.post("/auth/interactive-login/{login_session_id}/otp")
async def interactive_login_otp(login_session_id: str, body: Dict):
    """Resume a held interactive login by supplying the out-of-band OTP."""
    rec = _login_sessions.pop(login_session_id, None)
    if not rec:
        raise HTTPException(status_code=404, detail="login session not found or expired")
    otp = str(body.get("otp") or "").strip()
    if not otp:
        await _teardown_login(rec)
        raise HTTPException(status_code=400, detail="otp is required")
    page, context = rec["page"], rec["context"]
    try:
        await page.fill(body.get("otp_selector") or _OTP_SELECTOR, otp, timeout=8000)
        await page.click(body.get("submit_selector")
                         or "button[type='submit'], input[type='submit'], button")
        await page.wait_for_load_state("networkidle", timeout=15000)
        cap = await _capture_login(context, page, rec["host"], rec["engagement_id"])
        return {"ok": True, "authenticated": bool(cap["cookies"] or cap["has_bearer"]),
                "host": rec["host"], **cap}
    finally:
        await _teardown_login(rec)


@app.post("/auth/capture")
async def capture_auth_token(req: AuthCaptureRequest):
    """
    Capture auth tokens via OAuth2 client_credentials flow or network interception.

    - client_credentials: POST to token URL with client_id/secret, return access_token
    - intercept: Launch browser, navigate to login_url, monitor network for tokens
    """
    refusal = _scope_refusal_for_url(req.login_url, f"auth capture {req.mode}")
    if refusal:
        logger.warning("REFUSED auth capture at %s: %s", req.login_url, refusal)
        raise HTTPException(403, refusal)

    if req.mode == "client_credentials":
        return await _capture_client_credentials(req)
    elif req.mode == "intercept":
        return await _capture_intercept(req)
    elif req.mode == "authorization_code":
        return await _capture_authorization_code(req)
    elif req.mode == "password":
        return await _capture_password(req)
    elif req.mode == "device_code":
        return await _capture_device_start(req)
    else:
        raise HTTPException(400, f"Unknown mode: {req.mode}. Use 'client_credentials', "
                            "'password', 'device_code', 'authorization_code', or 'intercept'")


async def _oidc_discover(issuer: str) -> dict:
    """Fetch the OIDC discovery document for an issuer. Best-effort ({} on error)."""
    import oidc_flows as of
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as c:
            r = await c.get(of.discovery_url(issuer))
            return r.json() if r.status_code < 400 else {}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"OIDC discovery failed for {issuer}: {e}")
        return {}


async def _capture_password(req: AuthCaptureRequest):
    """ROPC / direct-grant (grant_type=password) — fully headless, no browser, for
    IdPs that permit it (Azure AD ROPC, Keycloak direct access grant)."""
    import httpx
    import oidc_flows as of
    token_url = req.token_url
    if not token_url and req.issuer:
        token_url = (await _oidc_discover(req.issuer)).get("token_endpoint")
    if not (token_url and req.client_id and req.username and req.password):
        raise HTTPException(400, "password grant needs token_url (or issuer), client_id, username, password")
    data = {"grant_type": "password", "client_id": req.client_id,
            "username": req.username, "password": req.password}
    if req.client_secret:
        data["client_secret"] = req.client_secret
    if req.scope:
        data["scope"] = req.scope
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as c:
            resp = await c.post(token_url, data=data,
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
            if resp.status_code >= 400:
                return {"ok": False, "error": f"token endpoint {resp.status_code}", "body": resp.text[:1500]}
            body = resp.json()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    session = of.session_from_token_response(
        body, token_url=token_url, client_id=req.client_id,
        client_secret=req.client_secret, scope=req.scope, captured_from="ropc")
    if not session:
        return {"ok": False, "error": "no access_token in response"}
    persisted = _persist_session(req.persist_host, session, req.engagement_id, "token") if req.persist_host else False
    return {"ok": True, "mode": "password", "access_token": body.get("access_token"),
            "has_refresh": bool(session.get("refresh", {}).get("refresh_token")),
            "persisted_profile": persisted}


async def _capture_device_start(req: AuthCaptureRequest):
    """OAuth2 device-authorization grant — start: request device+user codes. The
    human approves at verification_uri on another device, then poll /auth/device-poll."""
    import httpx
    disco = await _oidc_discover(req.issuer) if req.issuer else {}
    device_ep = disco.get("device_authorization_endpoint") or req.authorize_url
    if not (device_ep and req.client_id):
        raise HTTPException(400, "device_code needs issuer (or authorize_url as device endpoint) and client_id")
    data = {"client_id": req.client_id}
    if req.scope:
        data["scope"] = req.scope
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as c:
            resp = await c.post(device_ep, data=data,
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
            if resp.status_code >= 400:
                return {"ok": False, "error": f"device endpoint {resp.status_code}", "body": resp.text[:1000]}
            body = resp.json()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    return {"ok": True, "mode": "device_code",
            "device_code": body.get("device_code"), "user_code": body.get("user_code"),
            "verification_uri": body.get("verification_uri") or body.get("verification_url"),
            "verification_uri_complete": body.get("verification_uri_complete"),
            "interval": body.get("interval", 5), "expires_in": body.get("expires_in"),
            "token_url": disco.get("token_endpoint") or req.token_url,
            "message": "Approve at verification_uri, then POST /auth/device-poll with device_code + token_url."}


@app.post("/auth/device-poll")
async def device_poll(body: Dict):
    """Poll the token endpoint ONCE for a device_code grant. Returns
    {ok:true, pending:true} while the user has not yet approved; on success
    persists the session and returns the token. Body: {device_code, token_url,
    client_id, client_secret?, scope?, persist_host?, engagement_id?}."""
    import httpx
    import oidc_flows as of
    dc, token_url, client_id = body.get("device_code"), body.get("token_url"), body.get("client_id")
    if not (dc and token_url and client_id):
        raise HTTPException(400, "device_code, token_url and client_id are required")
    data = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc, "client_id": client_id}
    if body.get("client_secret"):
        data["client_secret"] = body["client_secret"]
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as c:
            resp = await c.post(token_url, data=data,
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
            j = resp.json()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    if resp.status_code >= 400:
        err = (j or {}).get("error", "")
        if err in ("authorization_pending", "slow_down"):
            return {"ok": True, "pending": True, "error": err}
        return {"ok": False, "error": err or f"token endpoint {resp.status_code}", "body": resp.text[:800]}
    session = of.session_from_token_response(
        j, token_url=token_url, client_id=client_id,
        client_secret=body.get("client_secret"), scope=body.get("scope"), captured_from="device_code")
    if not session:
        return {"ok": False, "error": "no access_token"}
    persisted = _persist_session(body["persist_host"], session, body.get("engagement_id"), "token") if body.get("persist_host") else False
    return {"ok": True, "pending": False, "access_token": j.get("access_token"),
            "has_refresh": bool(session.get("refresh", {}).get("refresh_token")),
            "persisted_profile": persisted}


async def _capture_authorization_code(req: AuthCaptureRequest):
    """Scripted OAuth2 authorization-code (+PKCE): drive the browser through the
    authorize redirect (filling IdP creds, TOTP if given), grab the `code` from
    the redirect back to redirect_uri, and exchange it at token_url for an
    access_token. Works when the IdP allows programmatic login (no interactive
    consent / no unscriptable MFA); for those, use /auth/interactive-login."""
    import httpx
    import session_capture as sc
    from urllib.parse import urlparse, parse_qs
    if not (req.authorize_url and req.token_url and req.redirect_uri and req.client_id):
        raise HTTPException(400, "authorization_code needs authorize_url, token_url, "
                            "redirect_uri and client_id")
    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=True)
    context = await browser.new_context(ignore_https_errors=True, user_agent=USER_AGENT)
    page = await context.new_page()
    try:
        await _drive_login(page, req.authorize_url, req.username, req.password,
                           None, None, None)
        if req.totp_secret and await _otp_present(page, None):
            code = sc.totp_now(req.totp_secret)
            if code:
                try:
                    await page.fill(_OTP_SELECTOR, code, timeout=8000)
                    await page.click("button[type='submit'], input[type='submit'], button")
                    await page.wait_for_load_state("networkidle", timeout=15000)
                except Exception:  # noqa: BLE001
                    pass
        auth_code = None
        base_redirect = req.redirect_uri.split("?")[0]
        for _ in range(20):
            if page.url.startswith(base_redirect):
                q = parse_qs(urlparse(page.url).query)
                auth_code = (q.get("code") or [None])[0]
                if auth_code:
                    break
            await page.wait_for_timeout(500)
        if not auth_code:
            return {"ok": False, "error": "no authorization code captured "
                    f"(final url {page.url[:200]})"}
    finally:
        for k in (context, browser):
            try:
                await k.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            await pw.stop()
        except Exception:  # noqa: BLE001
            pass

    data = {"grant_type": "authorization_code", "code": auth_code,
            "redirect_uri": req.redirect_uri, "client_id": req.client_id}
    if req.client_secret:
        data["client_secret"] = req.client_secret
    if req.code_verifier:
        data["code_verifier"] = req.code_verifier
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(req.token_url, data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
            if resp.status_code >= 400:
                return {"ok": False, "error": f"token endpoint {resp.status_code}",
                        "body": resp.text[:2000]}
            body = resp.json()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    token = body.get("access_token", "")
    token_type = body.get("token_type", "Bearer")
    persisted = False
    if token and req.persist_host:
        persisted = _persist_session_headers(
            req.persist_host, {"Authorization": f"{token_type} {token}"}, req.engagement_id)
    return {"ok": True, "mode": "authorization_code", "access_token": token,
            "token_type": token_type, "persisted_profile": persisted,
            "full_response": body}


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
            token = body.get("access_token", "")
            token_type = body.get("token_type", "Bearer")
            persisted = False
            if token and req.persist_host:
                persisted = _persist_session_headers(
                    req.persist_host,
                    {"Authorization": f"{token_type} {token}"}, req.engagement_id)
            return {
                "ok": True,
                "mode": "client_credentials",
                "access_token": token,
                "token_type": token_type,
                "expires_in": body.get("expires_in"),
                "persisted_profile": persisted,
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


class PreviewRequest(BaseModel):
    """Render one page through a proxy and hand back what it looks like."""
    url: str = Field(..., description="Absolute URL to load")
    proxy: Optional[str] = Field(
        None, description="SOCKS/HTTP proxy, e.g. socks5://node-manager:10120. "
                          "Omitted means the request leaves from THIS container.")
    timeout: int = Field(20, ge=5, le=60, description="Page load timeout (seconds)")
    width: int = Field(1280, ge=320, le=2560)
    height: int = Field(800, ge=240, le=2000)


@app.post("/preview")
async def preview_page(req: PreviewRequest):
    """Load a URL through the exit-node proxy and return a look at it.

    WHY THIS EXISTS: an operator triaging Recon Intel wants to see what is on a
    host before deciding whether it matters. Clicking a link in the dashboard
    would fetch it from the OPERATOR'S OWN browser and address — precisely what
    the exit nodes exist to prevent. This renders it headless, from the node, so
    the only traffic the target sees comes from the proxy.

    Scope-gated like every other path here: a preview is traffic to a host, so
    it goes through the same refusal as a scan. There is no override.
    """
    refusal = _scope_refusal_for_url(req.url, f"preview {req.url}")
    if refusal:
        logger.warning("REFUSED preview of %s: %s", req.url, refusal)
        raise HTTPException(403, refusal)

    import base64
    browser = None
    out = {
        "url": req.url, "final_url": None, "status": None, "title": None,
        "headers": {}, "screenshot_b64": None, "via_proxy": req.proxy or None,
        "error": None,
    }
    try:
        async with async_playwright() as p:
            launch_kwargs = {"headless": HEADLESS}
            if req.proxy:
                # Playwright takes the proxy at LAUNCH for socks5://; a
                # context-level socks proxy is ignored by Chromium, which is the
                # kind of silent no-op that would send the request out of this
                # container's own address while the UI claimed it was proxied.
                launch_kwargs["proxy"] = {"server": req.proxy}
            browser = await p.chromium.launch(**launch_kwargs)
            context = await browser.new_context(
                viewport={"width": req.width, "height": req.height},
                user_agent=USER_AGENT,
                ignore_https_errors=True,
            )
            page = await context.new_page()
            resp = await page.goto(req.url, timeout=req.timeout * 1000,
                                   wait_until="domcontentloaded")
            if resp is not None:
                out["status"] = resp.status
                try:
                    out["headers"] = dict(resp.headers)
                except Exception:  # noqa: BLE001
                    out["headers"] = {}
            out["final_url"] = page.url
            try:
                out["title"] = await page.title()
            except Exception:  # noqa: BLE001
                out["title"] = None
            shot = await page.screenshot(full_page=False)
            out["screenshot_b64"] = base64.b64encode(shot).decode("ascii")
    except Exception as e:  # noqa: BLE001
        # Reported, never swallowed: "could not load" and "loaded but empty" are
        # different answers and the operator has to be able to tell them apart.
        out["error"] = f"{type(e).__name__}: {e}"[:400]
        logger.warning("preview of %s failed: %s", req.url, out["error"])
    finally:
        if browser:
            try:
                await browser.close()
            except Exception:  # noqa: BLE001
                pass
    return out


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
    refusal = _scope_refusal_for_url(req.url, f"poc {req.injection_point} {req.url}")
    if refusal:
        logger.warning("REFUSED poc against %s: %s", req.url, refusal)
        raise HTTPException(403, refusal)

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
    auth: Optional[Dict] = Field(None, description="Auth Profile for an AUTHENTICATED crawl: {login_url, login_data (with {%username%}/{%password%}), username, password}. If omitted, a stored Auth Profile for the host is used. The browser logs in before crawling so the tree seeded into ZAP is authenticated.")
    #: Engagement for resolving the stored Auth Profile (the X-Engagement-Id header
    #: contextvar is reset before the async crawl runs — see ScanRequest.engagement_id).
    engagement_id: Optional[str] = Field(None, description="Engagement id for resolving the stored Auth Profile")


class CrawlResponse(BaseModel):
    job_id: str
    status: str
    message: str


# In-memory crawl job tracker
_crawl_jobs: Dict[str, dict] = {}


def _login_fields(login_data: str):
    """(user_field, pass_field) input names from a login_data template such as
    'user={%username%}&pass={%password%}&csrf={%csrf%}'. Pure/testable."""
    from urllib.parse import parse_qsl
    user_field = pass_field = None
    for k, v in parse_qsl(login_data or "", keep_blank_values=True):
        if "{%username%}" in v:
            user_field = k
        elif "{%password%}" in v:
            pass_field = k
    return user_field, pass_field


_IDOR_NAME_RE = __import__("re").compile(
    r"(?i)(^id$|_id$|acct|account|user$|uid|customer|profile|order|invoice|doc|file|record|msg|ticket|num$|no$|number)")
# URLs that DESTROY the authenticated session — an authenticated crawl must NOT
# navigate to them, or every step after (further crawl, katana, the IDOR probe,
# the ZAP tree it seeds) runs logged-out. Matched case-insensitively on the URL.
_LOGOUT_RE = __import__("re").compile(
    r"(?i)(logout|log-?off|log_?off|sign-?off|sign-?out|signout|/exit\b|loggedout|session.?end)")

# ── Business-logic testing (IDOR/BOLA + value tampering) — RAG-driven ─────────
_BL_CFG = None


def _bl_config() -> dict:
    """Load knowledge/business_logic_tests.yaml once (name patterns, tamper
    value-sets, response oracle). Data-driven: edit the YAML, not this file."""
    global _BL_CFG
    if _BL_CFG is not None:
        return _BL_CFG
    cfg = {}
    for p in ("/knowledge/business_logic_tests.yaml",
              os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "knowledge", "business_logic_tests.yaml")):
        try:
            if os.path.exists(p):
                import yaml
                cfg = (yaml.safe_load(open(p, encoding="utf-8")) or {}).get("business_logic_tests") or {}
                break
        except Exception:  # noqa: BLE001
            cfg = {}
    _BL_CFG = cfg
    return cfg


def _bl_asset_id(cur, host: str):
    """Resolve the asset id for a host by hostname OR ip (assets.ip is inet)."""
    cur.execute("SELECT id FROM assets WHERE hostname=%s OR host(ip)=%s LIMIT 1", (host, host))
    r = cur.fetchone()
    return r[0] if r else None


def _bl_body_params(cur, host: str, url_pattern: str) -> dict:
    """Reconstruct a POST body for url_pattern from discovered_params: {name: value}
    for every body param, using the first sample value (or '1' when none)."""
    cur.execute(
        """SELECT param_name, sample_values FROM discovered_params dp
             JOIN assets a ON a.id = dp.asset_id
            WHERE (a.hostname=%s OR host(a.ip)=%s) AND url_pattern=%s
              AND param_location='body'""", (host, host, url_pattern))
    body = {}
    for name, samples in cur.fetchall():
        body[name] = (samples[0] if samples else "1")
    return body


def _bl_is_blocked(body: str) -> bool:
    """True if the response is a login/denied/blocked page (a password field or an
    explicit denial), per the YAML oracle — NOT a word-match on 'login'."""
    markers = (_bl_config().get("oracle") or {}).get("blocked_markers") or []
    low = (body or "").lower()
    return any(m.lower() in low for m in markers)


def _bl_discovered_paths(cur, host: str, root: str, limit: int = 60) -> list:
    """Paths that gobuster/ffuf/feroxbuster already discovered for this host,
    normalized to absolute URLs — the forced-browsing probe tests ANONYMOUS access
    to them (content discovery is those tools' job; access control is the probe's).
    ffuf stores data->>'url'; gobuster stores a raw_output text block whose lines
    look like 'admin  (Status: 302) [Size: 0] [--> /login.jsp]'."""
    import re as _re
    urls, seen = [], set()

    def _add(u):
        if u and u not in seen:
            seen.add(u); urls.append(u)

    try:
        cur.execute(
            """SELECT source, finding_type, data FROM recon_findings rf
                 JOIN assets a ON a.id = rf.asset_id
                WHERE (a.hostname=%s OR host(a.ip)=%s)
                  AND source IN ('ffuf','gobuster','feroxbuster')""", (host, host))
        rows = cur.fetchall()
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
        return []
    for source, ftype, data in rows:
        if not isinstance(data, dict):
            continue
        u = data.get("url")
        if u:
            _add(u if "://" in str(u) else root.rstrip("/") + "/" + str(u).lstrip("/"))
        raw = data.get("raw_output") or ""
        for line in str(raw).splitlines():
            m = _re.match(r"\s*(/?[^\s(]+)\s+\(Status:", line)
            if m:
                p = m.group(1).strip()
                if p and not p.lower().startswith(("http", "status")):
                    _add(root.rstrip("/") + "/" + p.lstrip("/"))
        if len(urls) >= limit:
            break
    return urls[:limit]


async def _bl_fetch(ctx, method: str, url: str, body: dict = None) -> str:
    """Replay a request in the authenticated context (shares cookies). Returns the
    response text, or '' on error. POST sends form-encoded body."""
    try:
        if (method or "GET").upper() == "POST":
            resp = await ctx.request.post(url, form=(body or {}), timeout=15000)
        else:
            resp = await ctx.request.get(url, timeout=15000)
        return await resp.text()
    except Exception:  # noqa: BLE001
        return ""


async def _run_authenticated_katana(ctx, base_url: str, engagement_id, job_id: str,
                                    landing_url: str = None) -> Dict:
    """Run pd-runner katana AUTHENTICATED with the browser's live session cookies
    and form-fill on. This is the discovery half of the IDOR path: katana's
    -aff SUBMITS forms (the account dropdown), producing object-reference URLs
    like showAccount?listAccounts=<value> that parse_katana ingests into
    discovered_params — which the mutation probe below then mutates. The link-only
    crawl and even the ajax spider miss these (they stay in ZAP); katana emits
    them as structured params. Polls to completion so ingestion finishes BEFORE
    the probe runs. Best-effort, bounded."""
    import httpx
    import os as _os
    import asyncio as _aio
    from urllib.parse import urlparse as _up
    out = {"dispatched": False}
    try:
        host = _up(base_url).hostname or ""
        cookies = await ctx.cookies()
        pairs = []
        for c in cookies or []:
            dom = (c.get("domain") or "").lstrip(".")
            if c.get("name") and (not host or not dom or dom in host or host in dom):
                pairs.append(f"{c['name']}={c['value']}")
        if not pairs:
            out["error"] = "no session cookies to authenticate katana"
            return out
        cookie_hdr = "Cookie: " + "; ".join(pairs)
        pd = _os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023").rstrip("/")
        targets = [t for t in (landing_url, base_url) if t]
        targets = list(dict.fromkeys(targets))  # dedupe, keep order
        payload = {"targets": targets, "depth": 2, "field_scope": "fqdn",
                   "js_crawl": True, "form_extraction": True,
                   "auto_form_fill": True, "headers": [cookie_hdr]}
        hdr = {"X-Engagement-Id": engagement_id} if engagement_id else {}
        async with httpx.AsyncClient(timeout=30, verify=False) as c:
            r = await c.post(f"{pd}/jobs/katana", json=payload, headers=hdr)
            if r.status_code >= 400:
                out["error"] = f"katana dispatch HTTP {r.status_code}"
                return out
            kid = (r.json() or {}).get("job_id")
            out.update({"dispatched": True, "job_id": kid})
            waited = 0
            while kid and waited < 180:
                await _aio.sleep(6)
                waited += 6
                try:
                    jr = await c.get(f"{pd}/jobs/{kid}")
                    st = (jr.json() or {}).get("status") if jr.status_code < 400 else None
                except Exception:  # noqa: BLE001
                    st = None
                out["status"] = st
                if st in ("completed", "failed"):
                    break
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:160]
    return out


async def _idor_mutate_probe(ctx, base_url: str, host: str, engagement_id, job_id: str,
                             max_candidates: int = 8) -> int:
    """Single-credential IDOR / object-reference probe.

    As the ALREADY-LOGGED-IN user, take URLs whose parameters look like object
    references (id-like name, or a numeric value) and re-request them with mutated
    numeric ids in the SAME authenticated browser context. Flag a potential IDOR
    when a mutated id returns a distinct, substantive 200 that is NOT a login/error
    page — i.e. the account reached a DIFFERENT object it may not own. This covers
    the case where we DON'T have a second credential (the two-user path uses ZAP's
    accessControl add-on). Heuristic + bounded; findings are 'medium'.

    Covers GET query object-refs (via page navigation) AND POST-body object-refs
    (replayed in the authenticated context via ctx.request, reconstructing the
    full body from discovered_params) — the latter catches form/dropdown object
    references katana's -aff seeds. Object-ref param names come from
    knowledge/business_logic_tests.yaml."""
    import re
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    from db_utils import get_db

    # Candidate (url, param) from discovered_params + crawled URLs with numeric query values.
    cands = []
    try:
        with get_db() as conn, conn.cursor() as cur:
            # Match the asset by hostname OR IP — the probe is called with the URL
            # host (a hostname like demo.testfire.net), but assets.ip is inet, so a
            # bare `ip = <hostname>` errors and returns nothing. assets carries both
            # ip and hostname; match either.
            cur.execute("""SELECT DISTINCT url_pattern, param_name, sample_values
                             FROM discovered_params dp JOIN assets a ON a.id = dp.asset_id
                            WHERE (a.hostname = %s OR host(a.ip) = %s)
                              AND dp.http_method = 'GET'""", (host, host))
            for up, pn, samples in cur.fetchall():
                sample = (samples[0] if samples else "")
                if _IDOR_NAME_RE.search(pn or "") or str(sample).isdigit():
                    cands.append((up, pn, sample))
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[idor:{job_id[:8]}] param load failed: {e}")
    cands = cands[:max_candidates]
    if not cands:
        return 0

    def _build(pu, q, param, value):
        q2 = {k: (v[0] if isinstance(v, list) else v) for k, v in q.items()}
        q2[param] = str(value)
        return urlunparse(pu._replace(query=urlencode(q2)))

    found = 0
    page = await ctx.new_page()
    try:
        for up, pn, sample in cands:
            pu = urlparse(up)
            q = parse_qs(pu.query)
            base_val = (q.get(pn, [sample])[0] if q.get(pn) else sample)
            if not str(base_val).isdigit():
                continue  # only mutate numeric object refs (safe, low-FP)
            try:
                await page.goto(_build(pu, q, pn, base_val), wait_until="domcontentloaded", timeout=15000)
                orig = await page.content()
                n = int(base_val)
                hits = []
                for mv in (n + 1, n - 1, n + 2):
                    if mv < 0:
                        continue
                    await page.goto(_build(pu, q, pn, mv), wait_until="domcontentloaded", timeout=15000)
                    body = await page.content()
                    # Detect a "blocked" response by the LOGIN FORM / denial text,
                    # NOT by the word "login": authenticated pages carry static
                    # labels like alt="Secure Login" and id="LoginLink" that a
                    # word match trips on, so every valid object response was
                    # wrongly discarded. A password field (type=password / name=
                    # passw|uid|...) appears on the login/blocked page and NOT on an
                    # object-data page — a robust, app-agnostic negative signal.
                    _blocked = re.search(
                        r"(?i)type=[\"']?password|name=[\"']?(?:passw|pwd|uid|"
                        r"username|user|j_username|j_password)\b|not authori[sz]ed|"
                        r"access denied|\bforbidden\b|must be logged|please log ?in",
                        body)
                    if len(body) > 500 and body != orig and not _blocked:
                        hits.append(mv)
                if hits:
                    found += 1
                    with get_db() as conn, conn.cursor() as cur:
                        cur.execute("SELECT id FROM assets WHERE hostname=%s OR host(ip)=%s LIMIT 1",
                                    (host, host))
                        r = cur.fetchone()
                        cur.execute(
                            """INSERT INTO web_findings
                                 (asset_id, url, source, issue_type, name, severity, param,
                                  evidence, method, engagement_id)
                               VALUES (%s,%s,'idor_probe','idor',
                                       'Potential IDOR (object reference)','medium',%s,%s,'GET',%s)
                               ON CONFLICT DO NOTHING""",
                            (r[0] if r else None, _build(pu, q, pn, hits[0]), pn,
                             f"authenticated request with {pn}={n} mutated to {hits} returned distinct "
                             f"content (possible access to another object)"[:300], engagement_id))
                        conn.commit()
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[idor:{job_id[:8]}] probe {up} err: {e}")

        # POST-BODY object refs: replay the form in the authenticated context with
        # the object-ref param mutated, reconstructing the full body so the request
        # is valid. Catches form/dropdown object references (e.g. account numbers)
        # the GET pass can't see.
        try:
            found += await _idor_post_body_pass(ctx, host, engagement_id, job_id)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[idor:{job_id[:8]}] post-body pass err: {e}")
    finally:
        await page.close()
    return found


async def _idor_post_body_pass(ctx, host: str, engagement_id, job_id: str) -> int:
    """POST-body IDOR: for each POST url_pattern with an object-reference body
    param, replay the reconstructed body with the id mutated and flag a distinct,
    non-blocked response (the account reached another object). Bounded by
    business_logic_tests.yaml (idor.name_patterns / mutations / max_candidates)."""
    import re as _re
    from db_utils import get_db
    cfg = _bl_config().get("idor") or {}
    offsets = [int(x) for x in (cfg.get("mutations") or [1, -1, 2])]
    name_pats = [str(n).lower() for n in (cfg.get("name_patterns") or [])]
    maxc = int(cfg.get("max_candidates", 8))
    skip = {str(s).lower() for s in (_bl_config().get("skip_params") or [])}

    cands = []  # (url_pattern, param_name, base_value)
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT DISTINCT url_pattern, param_name, sample_values
                     FROM discovered_params dp JOIN assets a ON a.id = dp.asset_id
                    WHERE (a.hostname=%s OR host(a.ip)=%s)
                      AND http_method='POST' AND param_location='body'""", (host, host))
            for up, pn, samples in cur.fetchall():
                pl = (pn or "").lower()
                if pl in skip:
                    continue
                sample = (samples[0] if samples else "")
                is_ref = any(p in pl for p in name_pats) or _IDOR_NAME_RE.search(pn or "")
                if (is_ref or str(sample).isdigit()) and str(sample).isdigit():
                    cands.append((up, pn, sample))
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[idor:{job_id[:8]}] post-body candidate load failed: {e}")
        return 0
    cands = cands[:maxc]
    if not cands:
        return 0

    found = 0
    for up, pn, base_val in cands:
        try:
            with get_db() as conn, conn.cursor() as cur:
                body = _bl_body_params(cur, host, up)
            if pn not in body:
                body[pn] = base_val
            base_body = dict(body, **{pn: base_val})
            orig = await _bl_fetch(ctx, "POST", up, base_body)
            if not orig or _bl_is_blocked(orig):
                continue
            n = int(base_val)
            hits = []
            for off in offsets:
                mv = n + off
                if mv < 0:
                    continue
                resp = await _bl_fetch(ctx, "POST", up, dict(body, **{pn: str(mv)}))
                if len(resp) > 500 and resp != orig and not _bl_is_blocked(resp):
                    hits.append(mv)
            if hits:
                found += 1
                with get_db() as conn, conn.cursor() as cur:
                    aid = _bl_asset_id(cur, host)
                    cur.execute(
                        """INSERT INTO web_findings
                             (asset_id, url, source, issue_type, name, severity, param,
                              evidence, method, engagement_id)
                           VALUES (%s,%s,'idor_probe','idor',
                                   'Potential IDOR (object reference, POST body)','medium',%s,%s,'POST',%s)
                           ON CONFLICT DO NOTHING""",
                        (aid, up, pn,
                         f"authenticated POST with {pn}={n} mutated to {hits} returned distinct "
                         f"content (possible access to another object)"[:300], engagement_id))
                    conn.commit()
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[idor:{job_id[:8]}] post-body {up} err: {e}")
    return found


async def _value_tamper_probe(ctx, base_url: str, host: str, engagement_id, job_id: str) -> int:
    """Business-VALUE tampering (WSTG-BUSL-01/03). For numeric params whose name
    looks like a monetary/quantity value, resubmit the request (GET or POST, in
    the authenticated context) with negative/zero/oversized values from
    business_logic_tests.yaml. Flag when a tampered value yields a SUCCESSFUL,
    non-validation-error response that differs from the baseline — a potential
    business-logic flaw (e.g. a negative-amount transfer accepted). Heuristic;
    findings are 'medium' potential flags for manual triage."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    from db_utils import get_db
    cfg = _bl_config().get("value_tamper") or {}
    oracle = _bl_config().get("oracle") or {}
    name_pats = [str(n).lower() for n in (cfg.get("name_patterns") or [])]
    values = [str(v) for v in (cfg.get("values") or ["-1", "0", "999999999"])]
    maxc = int(cfg.get("max_candidates", 6))
    succ = [m.lower() for m in (oracle.get("success_markers") or [])]
    errm = [m.lower() for m in (oracle.get("error_markers") or [])]
    minb = int(oracle.get("min_response_bytes", 500))
    skip = {str(s).lower() for s in (_bl_config().get("skip_params") or [])}
    if not name_pats:
        return 0

    cands = []  # (url_pattern, param_name, method, base_value)
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT DISTINCT url_pattern, param_name, http_method, param_location, sample_values
                     FROM discovered_params dp JOIN assets a ON a.id = dp.asset_id
                    WHERE (a.hostname=%s OR host(a.ip)=%s)""", (host, host))
            for up, pn, method, loc, samples in cur.fetchall():
                pl = (pn or "").lower()
                if pl in skip or not any(p in pl for p in name_pats):
                    continue
                sample = (samples[0] if samples else "")
                # only tamper numeric business values
                try:
                    float(str(sample))
                except (TypeError, ValueError):
                    sample = "1"
                cands.append((up, pn, (method or "GET").upper(), loc, sample))
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[valtamper:{job_id[:8]}] candidate load failed: {e}")
        return 0
    cands = cands[:maxc]
    if not cands:
        return 0

    def _has(markers, text):
        low = text.lower()
        return any(m in low for m in markers)

    found = 0
    for up, pn, method, loc, base_val in cands:
        try:
            if method == "POST" or loc == "body":
                with get_db() as conn, conn.cursor() as cur:
                    body = _bl_body_params(cur, host, up)
                body[pn] = base_val
                baseline = await _bl_fetch(ctx, "POST", up, dict(body, **{pn: base_val}))
                def _send(val):  # noqa: E306
                    return _bl_fetch(ctx, "POST", up, dict(body, **{pn: val}))
            else:
                pu = urlparse(up)
                q = {k: (v[0] if isinstance(v, list) else v) for k, v in parse_qs(pu.query).items()}
                q[pn] = base_val
                base_url_full = urlunparse(pu._replace(query=urlencode(q)))
                baseline = await _bl_fetch(ctx, "GET", base_url_full)
                def _send(val):  # noqa: E306
                    q2 = dict(q, **{pn: val})
                    return _bl_fetch(ctx, "GET", urlunparse(pu._replace(query=urlencode(q2))))
            if not baseline or _bl_is_blocked(baseline):
                continue
            for val in values:
                resp = await _send(val)
                if (len(resp) > minb and not _bl_is_blocked(resp)
                        and _has(succ, resp) and not _has(errm, resp)
                        and resp != baseline):
                    found += 1
                    with get_db() as conn, conn.cursor() as cur:
                        aid = _bl_asset_id(cur, host)
                        cur.execute(
                            """INSERT INTO web_findings
                                 (asset_id, url, source, issue_type, name, severity, param,
                                  payload, evidence, method, engagement_id)
                               VALUES (%s,%s,'value_tamper','business_logic',
                                       'Potential business-logic flaw (value tampering)','medium',
                                       %s,%s,%s,%s,%s)
                               ON CONFLICT DO NOTHING""",
                            (aid, up, pn, val,
                             f"tampered {pn}={val} (from {base_val}) returned a success-shaped "
                             f"response with no validation error — possible unchecked business "
                             f"value (WSTG-BUSL-01/03)"[:300], method, engagement_id))
                        conn.commit()
                    break  # one finding per param is enough
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[valtamper:{job_id[:8]}] {up} err: {e}")
    return found


async def _forced_browsing_probe(base_url: str, host: str, engagement_id, job_id: str,
                                 discovered_urls=None) -> int:
    """Forced browsing / function-level access control (WSTG-ATHZ-02).

    (1) Re-request each AUTHENTICATED-area page the crawl discovered with NO
    session (anonymous httpx, no cookies): a page that serves content to an
    anonymous user instead of redirecting to login / 401 / 403 is missing
    authentication enforcement (high). (2) Request a small wordlist of
    sensitive/privileged paths anonymously (medium if exposed). Each URL is
    scope-gated. Data-driven by business_logic_tests.yaml::forced_browsing."""
    import httpx
    from urllib.parse import urlparse, urljoin
    from db_utils import get_db
    fb = _bl_config().get("forced_browsing") or {}
    if not fb:
        return 0
    auth_pats = [str(p).lower() for p in (fb.get("authenticated_path_patterns") or [])]
    priv_paths = fb.get("privileged_paths") or []
    maxc = int(fb.get("max_candidates", 25))
    minb = int((_bl_config().get("oracle") or {}).get("min_response_bytes", 500))

    pu0 = urlparse(base_url if "://" in base_url else f"http://{base_url}")
    root = f"{pu0.scheme}://{pu0.netloc}"

    cands, seen = [], set()   # (url, kind) kind in ('authed','privileged')
    for u in (discovered_urls or []):
        try:
            up = urlparse(u)
            if (up.hostname or "") != host:
                continue
            if any(p in (up.path or "").lower() for p in auth_pats) and u not in seen:
                cands.append((u, "authed")); seen.add(u)
        except Exception:  # noqa: BLE001
            continue
    for p in priv_paths:
        u = urljoin(root + "/", str(p).lstrip("/"))
        if u not in seen:
            cands.append((u, "privileged")); seen.add(u)
    # Paths gobuster/ffuf/feroxbuster already discovered — test anon access to what
    # the content-discovery tools found, not just a static wordlist.
    try:
        with get_db() as conn, conn.cursor() as cur:
            for u in _bl_discovered_paths(cur, host, root):
                if u not in seen:
                    cands.append((u, "discovered")); seen.add(u)
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[forcedbrowse:{job_id[:8]}] discovered-path load failed: {e}")
    cands = cands[:maxc]
    if not cands:
        return 0

    found = 0
    async with httpx.AsyncClient(verify=False, timeout=12, follow_redirects=False) as c:
        for url, kind in cands:
            # scope-gate every anonymous request
            if _scope_refusal_for_url(url, f"forced-browsing {url}"):
                continue
            try:
                r = await c.get(url)   # NO cookies -> anonymous
            except Exception:  # noqa: BLE001
                continue
            # redirect (usually to login) / 401 / 403 / non-200 = correctly enforced
            if r.status_code != 200:
                continue
            body = r.text or ""
            if len(body) < minb or _bl_is_blocked(body):
                continue
            found += 1
            sev = "high" if kind == "authed" else "medium"
            name = ("Broken access control — authenticated page reachable without a session"
                    if kind == "authed"
                    else "Forced browsing — sensitive path exposed anonymously")
            try:
                with get_db() as conn, conn.cursor() as cur:
                    aid = _bl_asset_id(cur, host)
                    cur.execute(
                        """INSERT INTO web_findings
                             (asset_id, url, source, issue_type, name, severity,
                              evidence, method, engagement_id)
                           VALUES (%s,%s,'forced_browsing','access_control',%s,%s,%s,'GET',%s)
                           ON CONFLICT DO NOTHING""",
                        (aid, url, name, sev,
                         f"anonymous GET returned 200 with a substantive non-login page "
                         f"({len(body)} bytes) — {kind} resource reachable without "
                         f"authentication (WSTG-ATHZ-02)"[:300], engagement_id))
                    conn.commit()
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[forcedbrowse:{job_id[:8]}] store failed for {url}: {e}")
    return found


async def _browser_login(page, auth: Dict) -> bool:
    """Best-effort form login in the browser so the crawl (and the ZAP site tree
    it seeds) is authenticated. Parses the login_data template to find the
    username/password fields, fills and submits them, and — when a
    logged_in_regex is given — verifies the result rather than assuming success.
    Never raises into the crawl."""
    try:
        login_url = auth.get("login_url")
        login_data = auth.get("login_data") or ""
        if not login_url or not login_data:
            return False
        user_field, pass_field = _login_fields(login_data)
        # Navigate to the login FORM PAGE, which may differ from login_url (the form
        # ACTION). e.g. AltoroMutual's form is on /login.jsp but posts to /doLogin —
        # GETting /doLogin shows no form, so the fill/login/verify all fail. The
        # profile carries the page in session.login_page (set by the default-cred
        # check). Fall back to login_url when unknown.
        nav_url = ((auth.get("session") or {}).get("login_page")) or login_url
        await page.goto(nav_url, wait_until="domcontentloaded", timeout=20000)
        # If the page has no password field (nav_url was the action, not the form),
        # try login_url as a fallback page.
        if nav_url != login_url:
            try:
                if not await page.query_selector("input[type=password]"):
                    await page.goto(login_url, wait_until="domcontentloaded", timeout=20000)
            except Exception:  # noqa: BLE001
                pass
        if user_field and auth.get("username"):
            try:
                await page.fill(f"input[name='{user_field}']", str(auth["username"]))
            except Exception:  # noqa: BLE001
                pass
        if pass_field and auth.get("password"):
            try:
                await page.fill(f"input[name='{pass_field}']", str(auth["password"]))
            except Exception:  # noqa: BLE001
                pass
        # Submit the LOGIN form specifically. A page often has other forms before
        # it (e.g. a search box with its own submit button) — a bare
        # `input[type=submit]` selector grabs that first button and submits the
        # wrong form, so scope the submit to the form that OWNS the password field.
        try:
            btn = await page.query_selector(
                "form:has(input[type=password]) button[type=submit], "
                "form:has(input[type=password]) input[type=submit]")
            if btn:
                await btn.click()
            else:
                # submit the password field's own form (bypasses sibling forms)
                submitted = False
                try:
                    submitted = await page.eval_on_selector(
                        "input[type=password]",
                        "el => { if (el.form) { el.form.submit(); return true; } return false; }")
                except Exception:  # noqa: BLE001
                    submitted = False
                if not submitted:
                    await page.keyboard.press("Enter")
            await page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:  # noqa: BLE001
            pass
        rx = auth.get("logged_in_regex")
        if rx:
            import re as _re
            body = await page.content()
            ok = bool(_re.search(rx, body))
            logger.info(f"[crawl] browser login verified={ok} (logged_in_regex)")
            return ok
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[crawl] browser login failed: {e}")
        return False


async def _perform_crawl(job_id: str, req: CrawlRequest):
    """
    Browser-based crawl that discovers URLs by following links.
    All traffic goes through ZAP proxy so ZAP builds its site tree.
    Returns discovered URLs for downstream pipeline stages.
    When an Auth Profile is present, the browser logs in FIRST so the seeded
    tree — and thus ZAP's authenticated active scan — covers post-login pages.
    """
    # Every seed, not just req.url: a single unchecked seed_urls entry is a
    # complete bypass of the gate on req.url.
    for _u in [req.url, *(req.seed_urls or [])]:
        refusal = _scope_refusal_for_url(_u, f"crawl seed {_u}")
        if refusal:
            logger.warning("REFUSED crawl seed %s: %s", _u, refusal)
            _crawl_jobs[job_id] = {"status": "blocked", "error": refusal,
                                   "pages_visited": 0, "urls_found": 0}
            return

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

            # AUTHENTICATED crawl: log the browser in BEFORE crawling so every
            # discovered page (and the ZAP tree seeded from this traffic) is
            # post-login. Explicit req.auth wins; else a stored Auth Profile.
            try:
                _eid = current_engagement_id.get()
            except Exception:  # noqa: BLE001
                _eid = None
            # The header contextvar is reset when the request returns, but this
            # crawl runs after that — fall back to the body's engagement_id so the
            # engagement-scoped Auth Profile resolves (else the crawl is anonymous).
            _eid = _eid or getattr(req, "engagement_id", None)
            _crawl_auth = req.auth or _resolve_web_auth(req.url, _eid)
            if _crawl_auth and _crawl_auth.get("login_url"):
                job["authenticated"] = await _browser_login(page, _crawl_auth)
                # Seed the POST-LOGIN landing page (e.g. /bank/main.jsp) at the FRONT
                # of the queue: the logged-out homepage (req.url) usually does not
                # link into the authenticated area, so without this the crawl walks
                # only public pages even when logged in. Same-origin, scope-gated.
                if job.get("authenticated"):
                    try:
                        from urllib.parse import urlparse as _upl
                        landed = page.url or ""
                        same = (not req.same_origin_only
                                or _upl(landed).netloc == _upl(req.url).netloc)
                        if (landed and landed not in visited and same
                                and not _scope_refusal_for_url(landed, "post-login seed")):
                            queue.appendleft((landed, 0))
                            logger.info(f"[crawl:{job_id[:8]}] seeded post-login landing {landed}")
                    except Exception:  # noqa: BLE001
                        pass

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

                # Never NAVIGATE to a logout link during an authenticated crawl — it
                # would end the session and log out everything that runs after
                # (remaining crawl, authenticated katana, the IDOR probe, and the
                # ZAP tree seeded from this browser). Still record it as discovered.
                if job.get("authenticated") and _LOGOUT_RE.search(url):
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

            # IDOR: single-credential object-reference probe, reusing this
            # authenticated context — only meaningful once logged in.
            if job.get("authenticated"):
                try:
                    _eng = _eid
                    # DISCOVERY: authenticated katana (form-fill) seeds
                    # discovered_params with object-ref params (e.g.
                    # listAccounts=<value>) the link-crawl misses, so the probe
                    # below has candidates to mutate. Waits for ingestion first.
                    try:
                        job["katana_auth"] = await _run_authenticated_katana(
                            ctx, req.url, _eng, job_id, landing_url=(page.url or None))
                    except Exception as _ke:  # noqa: BLE001
                        logger.debug(f"[crawl:{job_id[:8]}] auth katana failed: {_ke}")
                    _bl_host = urlparse(req.url).hostname or ""
                    n = await _idor_mutate_probe(ctx, req.url, _bl_host, _eng, job_id)
                    job["idor_findings"] = n
                    if n:
                        logger.info(f"[crawl:{job_id[:8]}] IDOR probe flagged {n} potential object-reference issue(s)")
                except Exception as e:  # noqa: BLE001
                    logger.debug(f"[crawl:{job_id[:8]}] IDOR probe failed: {e}")
                # Business-VALUE tampering (negative amounts / price / qty) — same
                # authenticated context. Separate try so an IDOR failure doesn't
                # skip it and vice versa.
                try:
                    vt = await _value_tamper_probe(ctx, req.url, urlparse(req.url).hostname or "", _eng, job_id)
                    job["value_tamper_findings"] = vt
                    if vt:
                        logger.info(f"[crawl:{job_id[:8]}] value-tamper probe flagged {vt} potential business-logic issue(s)")
                except Exception as e:  # noqa: BLE001
                    logger.debug(f"[crawl:{job_id[:8]}] value-tamper probe failed: {e}")
                # Forced browsing / function-level access control (ATHZ-02): re-request
                # the authenticated pages we discovered with NO session + a sensitive-
                # path wordlist. Uses anonymous httpx (not the authed ctx), so it needs
                # the discovered URLs, not the browser context.
                try:
                    fb = await _forced_browsing_probe(
                        req.url, urlparse(req.url).hostname or "", _eng, job_id,
                        discovered_urls=list(visited) + list(discovered))
                    job["forced_browsing_findings"] = fb
                    if fb:
                        logger.info(f"[crawl:{job_id[:8]}] forced-browsing probe flagged {fb} access-control issue(s)")
                except Exception as e:  # noqa: BLE001
                    logger.debug(f"[crawl:{job_id[:8]}] forced-browsing probe failed: {e}")

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
    # Validate target.
    #
    # allow_private=True, matching all 23 other validate_scan_target call sites
    # across nmap_scanner / web_scanner / nuclei. This route was the lone
    # exception, so the SSRF guard rejected every RFC1918 address — i.e. the
    # normal case for an internal engagement. A pipeline scan of
    # http://192.168.1.150 failed here with HTTP 400 and the log only said
    # "Playwright crawl start failed: HTTP 400", so it read as a transport
    # problem rather than the target being refused on principle.
    #
    # Authorization is not this function's job: scope enforcement (BFF +
    # nmap_scanner, via etl.scope_gate) decides what may be scanned. This check
    # is input validation.
    # validate_scan_target takes a HOST, not a URL — handing it the full
    # "http://192.168.1.150" fails with "Invalid domain name format". The nine
    # other URL-based callers in this stack all parse first
    # (validate_scan_target(parsed.hostname, allow_private=True)); this one did
    # not, so every crawl of an http:// target was rejected before it started.
    try:
        _parsed = urlparse(req.url)
        _host = _parsed.hostname or _parsed.netloc or req.url
        validate_scan_target(_host, allow_private=True)
    except ValidationError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid crawl target {req.url!r} (host {_host!r}): {e}",
        )

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
