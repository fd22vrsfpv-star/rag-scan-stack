"""
Database utilities for Playwright Scanner
Handles all database interactions with the scans database
"""

import os
import uuid
from typing import Optional, Dict, List
from contextlib import contextmanager
import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = psycopg2.connect(DB_DSN)
    try:
        yield conn
    finally:
        conn.close()


def get_or_create_asset(ip: str, hostname: Optional[str] = None) -> uuid.UUID:
    """
    Get existing asset or create new one

    Args:
        ip: IP address of the asset (can be hostname for web-only targets)
        hostname: Optional hostname

    Returns:
        UUID of the asset
    """
    import socket

    # Try to resolve hostname to IP if the input looks like a hostname
    resolved_ip = ip
    if not _is_valid_ip(ip):
        # Input is a hostname, try to resolve it
        try:
            resolved_ip = socket.gethostbyname(ip)
            if hostname is None:
                hostname = ip  # Store original hostname
        except socket.gaierror:
            # Cannot resolve - use placeholder IP for web-only assets
            resolved_ip = "0.0.0.0"
            if hostname is None:
                hostname = ip

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Look up by hostname first (exact match), then by IP+hostname combo
        if hostname:
            cur.execute(
                "SELECT id FROM assets WHERE hostname = %s LIMIT 1",
                (hostname,)
            )
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE assets SET last_seen = now() WHERE id = %s", (row['id'],))
                conn.commit()
                return row['id']

        # Try IP + hostname combo (allows multiple vhosts per IP)
        cur.execute(
            "SELECT id FROM assets WHERE ip = %s::inet AND COALESCE(hostname, '') = COALESCE(%s, '') LIMIT 1",
            (resolved_ip, hostname)
        )
        row = cur.fetchone()

        if row:
            cur.execute("UPDATE assets SET last_seen = now() WHERE id = %s", (row['id'],))
            conn.commit()
            return row['id']

        # Create new asset (unique on ip + hostname)
        cur.execute(
            """
            INSERT INTO assets (ip, hostname)
            VALUES (%s::inet, %s)
            RETURNING id
            """,
            (resolved_ip, hostname)
        )
        asset_id = cur.fetchone()['id']
        conn.commit()
        return asset_id


def _is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address"""
    import socket
    try:
        socket.inet_pton(socket.AF_INET, ip_str)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip_str)
        return True
    except socket.error:
        return False


def create_playwright_scan(
    url: str,
    asset_id: Optional[uuid.UUID] = None,
    browser: str = "chromium",
    viewport: Optional[Dict] = None,
    user_agent: Optional[str] = None,
    cookies: Optional[List[Dict]] = None
) -> uuid.UUID:
    """
    Create a new Playwright scan record

    Args:
        url: Target URL
        asset_id: Optional asset UUID
        browser: Browser type (chromium, firefox, webkit)
        viewport: Browser viewport configuration
        user_agent: Custom user agent
        cookies: Initial cookies to set

    Returns:
        UUID of the created scan
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO playwright_scans
            (asset_id, url, status, browser, viewport, user_agent, cookies, start_time)
            VALUES (%s, %s, 'running', %s, %s, %s, %s, now())
            RETURNING id
            """,
            (asset_id, url, browser, Json(viewport or {}), user_agent, Json(cookies or []))
        )
        scan_id = cur.fetchone()['id']
        conn.commit()
        return scan_id


def update_playwright_scan(
    scan_id: uuid.UUID,
    status: str,
    screenshots: Optional[int] = None,
    dom_snapshot: Optional[bool] = None,
    console_logs: Optional[List] = None,
    network_logs: Optional[List] = None,
    errors: Optional[List] = None,
    metadata: Optional[Dict] = None
):
    """
    Update Playwright scan with results

    Args:
        scan_id: Scan UUID
        status: 'running', 'completed', or 'failed'
        screenshots: Number of screenshots taken
        dom_snapshot: Whether DOM was captured
        console_logs: Browser console output
        network_logs: Network requests captured
        errors: JavaScript errors encountered
        metadata: Additional metadata
    """
    with get_db() as conn, conn.cursor() as cur:
        updates = ["status = %s", "end_time = now()", "updated_at = now()"]
        params = [status]

        if screenshots is not None:
            updates.append("screenshots = %s")
            params.append(screenshots)

        if dom_snapshot is not None:
            updates.append("dom_snapshot = %s")
            params.append(dom_snapshot)

        if console_logs is not None:
            updates.append("console_logs = %s")
            params.append(Json(console_logs))

        if network_logs is not None:
            updates.append("network_logs = %s")
            params.append(Json(network_logs))

        if errors is not None:
            updates.append("errors = %s")
            params.append(Json(errors))

        if metadata is not None:
            updates.append("metadata = %s")
            params.append(Json(metadata))

        params.append(scan_id)

        sql = f"UPDATE playwright_scans SET {', '.join(updates)} WHERE id = %s"
        cur.execute(sql, params)
        conn.commit()


def create_playwright_finding(
    scan_id: uuid.UUID,
    asset_id: Optional[uuid.UUID],
    url: str,
    finding_type: str,
    title: str,
    severity: str,
    description: Optional[str] = None,
    evidence: Optional[str] = None,
    location: Optional[str] = None,
    remediation: Optional[str] = None,
    cwe: Optional[List[str]] = None,
    owasp_category: Optional[str] = None,
    references: Optional[List[Dict]] = None,
    screenshot_id: Optional[uuid.UUID] = None,
    dom_element: Optional[Dict] = None,
    related_request: Optional[Dict] = None,
    confidence: Optional[float] = None
) -> uuid.UUID:
    """
    Create a new Playwright finding

    Args:
        scan_id: Scan UUID
        asset_id: Asset UUID
        url: URL where finding was discovered
        finding_type: Type of finding (xss, csrf, clickjacking, etc.)
        title: Finding title
        severity: info, low, medium, high, critical
        description: Detailed description
        evidence: Evidence/proof
        location: CSS selector or URL fragment
        remediation: How to fix
        cwe: CWE identifiers
        owasp_category: OWASP Top 10 category
        references: External references
        screenshot_id: Reference to screenshot
        dom_element: Captured DOM node
        related_request: HTTP request that triggered this
        confidence: 0.0-1.0 confidence score

    Returns:
        UUID of the created finding
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO playwright_findings
            (scan_id, asset_id, url, finding_type, title, severity, description,
             evidence, location, remediation, cwe, owasp_category, refs,
             screenshot_id, dom_element, related_request, confidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (scan_id, asset_id, url, finding_type, title, severity, description,
             evidence, location, remediation, cwe, owasp_category,
             Json(references or []), screenshot_id, Json(dom_element or {}),
             Json(related_request or {}), confidence)
        )
        finding_id = cur.fetchone()['id']
        conn.commit()
        return finding_id


def save_screenshot(
    scan_id: uuid.UUID,
    url: str,
    image_data: bytes,
    image_hash: str,
    viewport: Optional[Dict] = None,
    format: str = "png",
    full_page: bool = False,
    selector: Optional[str] = None,
    metadata: Optional[Dict] = None
) -> uuid.UUID:
    """
    Save screenshot to database

    Args:
        scan_id: Scan UUID
        url: URL of the screenshot
        image_data: Binary image data
        image_hash: SHA256 hash of image
        viewport: Viewport configuration
        format: Image format (png, jpeg, webp)
        full_page: Whether this is a full page screenshot
        selector: CSS selector if element-specific
        metadata: Additional metadata

    Returns:
        UUID of the saved screenshot
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Check if screenshot with same hash already exists
        cur.execute(
            "SELECT id FROM playwright_screenshots WHERE image_hash = %s LIMIT 1",
            (image_hash,)
        )
        existing = cur.fetchone()

        if existing:
            return existing['id']

        cur.execute(
            """
            INSERT INTO playwright_screenshots
            (scan_id, url, image_data, image_hash, viewport, format,
             file_size, full_page, selector, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (scan_id, url, image_data, image_hash, Json(viewport or {}), format,
             len(image_data), full_page, selector, Json(metadata or {}))
        )
        screenshot_id = cur.fetchone()['id']
        conn.commit()
        return screenshot_id


def save_dom_analysis(
    scan_id: uuid.UUID,
    asset_id: Optional[uuid.UUID],
    url: str,
    forms: List[Dict],
    cookies: List[Dict],
    local_storage: Dict,
    session_storage: Dict,
    javascript_libs: List[Dict],
    csp_header: Optional[str],
    cors_enabled: bool,
    cors_config: Dict,
    security_headers: Dict,
    external_scripts: List[str],
    mixed_content: bool,
    websockets: List[Dict],
    postmessage_usage: bool,
    dom_snapshot: Optional[str] = None,
    metadata: Optional[Dict] = None
) -> uuid.UUID:
    """
    Save DOM analysis results

    Args:
        scan_id: Scan UUID
        asset_id: Asset UUID
        url: Analyzed URL
        forms: Detected forms
        cookies: Cookies found
        local_storage: localStorage contents
        session_storage: sessionStorage contents
        javascript_libs: Detected JS frameworks
        csp_header: Content Security Policy header
        cors_enabled: Whether CORS is enabled
        cors_config: CORS configuration
        security_headers: All security headers
        external_scripts: External script sources
        mixed_content: HTTP resources on HTTPS
        websockets: WebSocket connections
        postmessage_usage: postMessage API usage
        dom_snapshot: Full HTML snapshot
        metadata: Additional metadata

    Returns:
        UUID of the saved analysis
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO dom_analysis
            (scan_id, asset_id, url, forms_count, forms, inputs_count,
             cookies, local_storage, session_storage, javascript_libs,
             csp_header, cors_enabled, cors_config, security_headers,
             external_scripts, mixed_content, websockets, postmessage_usage,
             dom_snapshot, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (scan_id, asset_id, url, len(forms), Json(forms),
             sum(len(f.get('inputs', [])) for f in forms),
             Json(cookies), Json(local_storage), Json(session_storage),
             Json(javascript_libs), csp_header, cors_enabled, Json(cors_config),
             Json(security_headers), Json(external_scripts), mixed_content,
             Json(websockets), postmessage_usage, dom_snapshot, Json(metadata or {}))
        )
        analysis_id = cur.fetchone()['id']
        conn.commit()
        return analysis_id


def save_content_extraction(
    scan_id: uuid.UUID,
    asset_id: Optional[uuid.UUID],
    url: str,
    data: Dict
) -> uuid.UUID:
    """
    Save content extraction results from content analyzer.

    Args:
        scan_id: Scan UUID
        asset_id: Asset UUID
        url: Analyzed URL
        data: Dict with keys: emails, names, internal_paths, api_endpoints,
              exposed_keys, tech_indicators, comments, hidden_inputs, js_configs, word_corpus

    Returns:
        UUID of the saved extraction
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO content_extractions
            (scan_id, asset_id, url, emails, names, internal_paths, api_endpoints,
             exposed_keys, tech_indicators, comments, hidden_inputs, js_configs,
             interesting_files, file_metadata, login_pages, word_corpus, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (scan_id, asset_id, url,
             Json(data.get('emails', [])),
             Json(data.get('names', [])),
             Json(data.get('internal_paths', [])),
             Json(data.get('api_endpoints', [])),
             Json(data.get('exposed_keys', [])),
             Json(data.get('tech_indicators', [])),
             Json(data.get('comments', [])),
             Json(data.get('hidden_inputs', [])),
             Json(data.get('js_configs', {})),
             Json(data.get('interesting_files', [])),
             Json(data.get('file_metadata', [])),
             Json(data.get('login_pages', [])),
             data.get('word_corpus', ''),
             Json(data.get('metadata', {})))
        )
        extraction_id = cur.fetchone()['id']
        conn.commit()
        return extraction_id


def get_content_extractions(
    asset_id: Optional[uuid.UUID] = None,
    scan_id: Optional[uuid.UUID] = None,
    limit: int = 100
) -> List[Dict]:
    """
    Query content extractions with optional filters.

    Args:
        asset_id: Filter by asset
        scan_id: Filter by scan
        limit: Max rows

    Returns:
        List of extraction dicts
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        conditions = []
        params: list = []
        if asset_id:
            conditions.append("asset_id = %s")
            params.append(asset_id)
        if scan_id:
            conditions.append("scan_id = %s")
            params.append(scan_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        cur.execute(
            f"SELECT * FROM content_extractions {where} ORDER BY created_at DESC LIMIT %s",
            params,
        )
        rows = cur.fetchall()
        for row in rows:
            row['id'] = str(row['id'])
            if row.get('scan_id'):
                row['scan_id'] = str(row['scan_id'])
            if row.get('asset_id'):
                row['asset_id'] = str(row['asset_id'])
            if row.get('created_at'):
                row['created_at'] = row['created_at'].isoformat()
        return rows


def create_zap_session(
    playwright_scan_id: Optional[uuid.UUID],
    session_name: str,
    zap_api_key: str,
    context_name: Optional[str] = None,
    sites: Optional[List[str]] = None
) -> uuid.UUID:
    """
    Create ZAP session record

    Args:
        playwright_scan_id: Associated Playwright scan
        session_name: ZAP session name
        zap_api_key: ZAP API key used
        context_name: ZAP context name
        sites: List of sites in session

    Returns:
        UUID of the created session
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO zap_sessions
            (playwright_scan_id, session_name, zap_api_key, context_name, sites)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (playwright_scan_id, session_name, zap_api_key, context_name, Json(sites or []))
        )
        session_id = cur.fetchone()['id']
        conn.commit()
        return session_id


def update_zap_session(
    session_id: uuid.UUID,
    spider_completed: bool = False,
    ascan_completed: bool = False,
    alerts_count: int = 0,
    session_file: Optional[str] = None
):
    """
    Update ZAP session status

    Args:
        session_id: Session UUID
        spider_completed: Spider finished
        ascan_completed: Active scan finished
        alerts_count: Number of alerts
        session_file: Session file path
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE zap_sessions
            SET spider_completed = %s, ascan_completed = %s,
                alerts_count = %s, session_file = %s, updated_at = now()
            WHERE id = %s
            """,
            (spider_completed, ascan_completed, alerts_count, session_file, session_id)
        )
        conn.commit()
