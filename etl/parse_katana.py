import os, json, uuid, re, ipaddress
import psycopg2
from psycopg2.extras import RealDictCursor
from urllib.parse import urlparse, parse_qs


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, AttributeError):
        return False

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

def _load_jsonl(path):
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: results.append(json.loads(line))
            except json.JSONDecodeError: pass
    return results


# ── Param type inference heuristics ──────────────────────
_RE_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_RE_EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[a-z]{2,}$', re.I)
_RE_FLOAT = re.compile(r'^-?\d+\.\d+$')
_RE_B64 = re.compile(r'^[A-Za-z0-9+/]{16,}={0,3}$')

def _infer_param_type(value: str) -> str:
    """Infer parameter type from a sample value."""
    v = value.strip()
    if not v:
        return 'string'
    if v.lower() in ('true', 'false', '0', '1'):
        return 'boolean'
    if v.isdigit() or (v.startswith('-') and v[1:].isdigit()):
        return 'integer'
    if _RE_FLOAT.match(v):
        return 'float'
    if _RE_UUID.match(v):
        return 'uuid'
    if _RE_EMAIL.match(v):
        return 'email'
    if v.startswith('/') and '/' in v[1:]:
        return 'path'
    if _RE_B64.match(v) and len(v) >= 20:
        return 'encoded'
    return 'string'


# ── API endpoint classification ──────────────────────────

# Path patterns that indicate API endpoints
_API_PATH_PATTERNS = [
    re.compile(r'/api/', re.I),
    re.compile(r'/v\d+/', re.I),              # /v1/, /v2/, etc.
    re.compile(r'/rest/', re.I),
    re.compile(r'/graphql', re.I),
    re.compile(r'/gql', re.I),
    re.compile(r'/query', re.I),
    re.compile(r'/mutation', re.I),
    re.compile(r'/websocket', re.I),
    re.compile(r'/ws/', re.I),
    re.compile(r'/socket\.io', re.I),
    re.compile(r'/hub/', re.I),               # SignalR
    re.compile(r'/json-?rpc', re.I),
    re.compile(r'/xmlrpc', re.I),
    re.compile(r'/soap', re.I),
    re.compile(r'/wsdl', re.I),
    re.compile(r'/odata/', re.I),
    re.compile(r'/grpc', re.I),
]

# Content-type patterns that indicate API responses
_API_CONTENT_TYPES = [
    'application/json',
    'application/xml',
    'application/graphql',
    'application/grpc',
    'text/xml',
    'application/soap+xml',
    'application/problem+json',
    'application/vnd.api+json',
    'application/hal+json',
]

# File extensions that are NOT API endpoints
_STATIC_EXTENSIONS = {
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.pdf', '.zip', '.gz', '.tar', '.mp4', '.mp3', '.avi',
    '.map', '.webp', '.avif', '.webm',
}

# Known API spec / documentation files
_API_SPEC_PATTERNS = [
    re.compile(r'swagger', re.I),
    re.compile(r'openapi', re.I),
    re.compile(r'api-docs', re.I),
    re.compile(r'\.yaml$', re.I),
    re.compile(r'\.yml$', re.I),
]


def _classify_endpoint(url: str, method: str, response: dict, tag: str) -> dict | None:
    """Classify a URL as an API endpoint if it matches patterns.

    Returns a classification dict or None if not an API endpoint.
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Skip obvious static assets
    for ext in _STATIC_EXTENSIONS:
        if path.endswith(ext):
            return None

    classification = {
        "url": url,
        "method": method.upper(),
        "path": parsed.path,
        "host": parsed.hostname or "",
        "port": parsed.port,
        "scheme": parsed.scheme,
        "api_type": None,       # rest, graphql, websocket, soap, grpc, rpc, spec, unknown
        "confidence": "low",    # low, medium, high
        "signals": [],          # why we classified it as API
    }

    signals = []

    # Check path patterns
    for pattern in _API_PATH_PATTERNS:
        if pattern.search(path):
            signals.append(f"path_match:{pattern.pattern}")

    # Check for GraphQL specifically
    if re.search(r'/graphql|/gql', path, re.I):
        classification["api_type"] = "graphql"
        signals.append("graphql_path")
    elif re.search(r'/ws/|/websocket|/socket\.io|/hub/', path, re.I):
        classification["api_type"] = "websocket"
        signals.append("websocket_path")
    elif re.search(r'/soap|/wsdl|/xmlrpc', path, re.I):
        classification["api_type"] = "soap"
        signals.append("soap_path")
    elif re.search(r'/grpc', path, re.I):
        classification["api_type"] = "grpc"
        signals.append("grpc_path")
    elif re.search(r'/json-?rpc', path, re.I):
        classification["api_type"] = "rpc"
        signals.append("jsonrpc_path")

    # Check response content-type
    resp_headers = response.get("headers", {}) if isinstance(response, dict) else {}
    content_type = ""
    if isinstance(resp_headers, dict):
        content_type = resp_headers.get("content-type", resp_headers.get("Content-Type", "")).lower()
    elif isinstance(resp_headers, str):
        ct_match = re.search(r'content-type:\s*([^\r\n]+)', resp_headers, re.I)
        if ct_match:
            content_type = ct_match.group(1).lower()

    for api_ct in _API_CONTENT_TYPES:
        if api_ct in content_type:
            signals.append(f"content_type:{api_ct}")
            if not classification["api_type"]:
                if 'graphql' in api_ct:
                    classification["api_type"] = "graphql"
                elif 'xml' in api_ct or 'soap' in api_ct:
                    classification["api_type"] = "soap"
                elif 'grpc' in api_ct:
                    classification["api_type"] = "grpc"
                else:
                    classification["api_type"] = "rest"
            break

    # Check for JSON response body
    resp_body = response.get("body", "") if isinstance(response, dict) else ""
    if resp_body and isinstance(resp_body, str):
        body_stripped = resp_body.strip()
        if body_stripped.startswith('{') or body_stripped.startswith('['):
            signals.append("json_response_body")
            if not classification["api_type"]:
                classification["api_type"] = "rest"

    # Non-GET methods are strong API signals
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        signals.append(f"method:{method.upper()}")

    # XHR tag from katana is a strong signal
    if tag in ("xhr", "fetch", "js"):
        signals.append(f"tag:{tag}")

    # Check for API spec files
    for pattern in _API_SPEC_PATTERNS:
        if pattern.search(path):
            classification["api_type"] = "spec"
            signals.append(f"api_spec:{pattern.pattern}")
            break

    # If no signals, not an API endpoint
    if not signals:
        return None

    classification["signals"] = signals

    # Confidence scoring
    if len(signals) >= 3:
        classification["confidence"] = "high"
    elif len(signals) >= 2:
        classification["confidence"] = "medium"
    else:
        classification["confidence"] = "low"

    # Default type
    if not classification["api_type"]:
        classification["api_type"] = "rest" if any("path_match" in s for s in signals) else "unknown"

    return classification


def _extract_json_body_params(raw_request: str, method: str, url: str) -> list:
    """Extract parameters from JSON request bodies (POST/PUT/PATCH)."""
    if method.upper() not in ("POST", "PUT", "PATCH"):
        return []

    body = ""
    if "\r\n\r\n" in raw_request:
        body = raw_request.split("\r\n\r\n", 1)[1]
    elif "\n\n" in raw_request:
        body = raw_request.split("\n\n", 1)[1]

    if not body or not body.strip():
        return []

    body = body.strip()
    if not (body.startswith('{') or body.startswith('[')):
        return []

    parsed = urlparse(url)
    url_pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else parsed.path
    results = []

    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for key, val in data.items():
                val_str = json.dumps(val) if not isinstance(val, str) else val
                results.append({
                    "url_pattern": url_pattern,
                    "param_name": key,
                    "param_type": _infer_param_type(val_str) if isinstance(val, str) else type(val).__name__,
                    "value": val_str[:200],
                    "location": "json_body",
                    "method": method.upper(),
                })
    except (json.JSONDecodeError, ValueError):
        pass

    return results


def _extract_params(url: str, method: str, raw_request: str = ""):
    """
    Extract query, body, and JSON parameters from a URL / raw request.

    Returns list of dicts: {url_pattern, param_name, param_type, value, location, method}
    """
    parsed = urlparse(url)
    url_pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else parsed.path
    results = []

    # Query params
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for name, vals in qs.items():
        sample = vals[0] if vals else ""
        results.append({
            "url_pattern": url_pattern,
            "param_name": name,
            "param_type": _infer_param_type(sample),
            "value": sample,
            "location": "query",
            "method": method.upper(),
        })

    # POST body params (form-encoded)
    if method.upper() in ("POST", "PUT", "PATCH") and raw_request:
        body = ""
        if "\r\n\r\n" in raw_request:
            body = raw_request.split("\r\n\r\n", 1)[1]
        elif "\n\n" in raw_request:
            body = raw_request.split("\n\n", 1)[1]
        if body:
            body_stripped = body.strip()
            # JSON body params
            if body_stripped.startswith('{') or body_stripped.startswith('['):
                results.extend(_extract_json_body_params(raw_request, method, url))
            else:
                # Form-encoded body params
                try:
                    body_params = parse_qs(body_stripped, keep_blank_values=True)
                    for name, vals in body_params.items():
                        sample = vals[0] if vals else ""
                        results.append({
                            "url_pattern": url_pattern,
                            "param_name": name,
                            "param_type": _infer_param_type(sample),
                            "value": sample,
                            "location": "body",
                            "method": method.upper(),
                        })
                except Exception:
                    pass

    return results


def _upsert_param(cur, asset_id, param):
    """Upsert a single discovered param into the DB."""
    cur.execute("""
        INSERT INTO discovered_params
            (asset_id, url_pattern, param_name, param_type, http_method, param_location, sample_values, occurrence_count)
        VALUES (%s, %s, %s, %s, %s, %s, ARRAY[%s], 1)
        ON CONFLICT (url_pattern, param_name, http_method, param_location)
        DO UPDATE SET
            occurrence_count = discovered_params.occurrence_count + 1,
            last_seen = now(),
            sample_values = (
                SELECT array_agg(DISTINCT v)
                FROM (
                    SELECT unnest(discovered_params.sample_values || ARRAY[EXCLUDED.sample_values[1]]) AS v
                ) sub
                LIMIT 5
            )
    """, (
        asset_id,
        param["url_pattern"],
        param["param_name"],
        param["param_type"],
        param["method"],
        param["location"],
        param["value"],
    ))


def _upsert_api_endpoint(cur, asset_id, classification, scan_id=None):
    """Upsert a discovered API endpoint into content_extractions."""
    url = classification["url"]
    host = classification["host"]

    # Try to find existing content_extractions row for this host
    if scan_id:
        cur.execute("""
            SELECT id, api_endpoints FROM content_extractions
            WHERE scan_id = %s AND url = %s LIMIT 1
        """, (scan_id, f"{classification['scheme']}://{host}"))
    else:
        cur.execute("""
            SELECT id, api_endpoints FROM content_extractions
            WHERE asset_id = %s AND url = %s ORDER BY created_at DESC LIMIT 1
        """, (asset_id, f"{classification['scheme']}://{host}"))

    row = cur.fetchone()

    endpoint_entry = {
        "url": url,
        "method": classification["method"],
        "path": classification["path"],
        "api_type": classification["api_type"],
        "confidence": classification["confidence"],
        "signals": classification["signals"],
        "source": "katana",
    }

    if row:
        existing = row["api_endpoints"] or []
        # Deduplicate by method+path
        existing_keys = {(e.get("method"), e.get("path")) for e in existing if isinstance(e, dict)}
        if (classification["method"], classification["path"]) not in existing_keys:
            existing.append(endpoint_entry)
            cur.execute("""
                UPDATE content_extractions SET api_endpoints = %s WHERE id = %s
            """, (json.dumps(existing), row["id"]))
            return True
        return False
    else:
        # Create a new content_extractions row for this host
        cur.execute("""
            INSERT INTO content_extractions (scan_id, asset_id, url, api_endpoints)
            VALUES (%s, %s, %s, %s)
        """, (scan_id, asset_id, f"{classification['scheme']}://{host}",
              json.dumps([endpoint_entry])))
        return True


def parse_katana(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(
        records_seen=0, findings_inserted=0, params_extracted=0,
        api_endpoints_found=0, api_endpoints_by_type={},
        skipped=0, errors=0, error_examples=[]
    )
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT katana_rec")

                    # Extract URL from katana output
                    # Katana can have 'request' dict or direct fields
                    request = rec.get("request", {})
                    url = request.get("endpoint") or request.get("url") or rec.get("endpoint") or rec.get("url", "")
                    url = url.strip()
                    if not url:
                        cur.execute("RELEASE SAVEPOINT katana_rec")
                        stats["skipped"] += 1; continue

                    # Extract other fields
                    method = request.get("method") or rec.get("method", "GET")
                    tag = request.get("tag") or rec.get("tag", "")
                    source = request.get("source") or rec.get("source", "")
                    response = rec.get("response", {})
                    status_code = response.get("status_code") if isinstance(response, dict) else None

                    # Try to lookup asset_id from URL hostname
                    asset_id = None
                    try:
                        parsed = urlparse(url)
                        hostname = parsed.hostname
                        if hostname:
                            if _is_ip(hostname):
                                cur.execute("SELECT id FROM assets WHERE ip = %s", (hostname,))
                            else:
                                cur.execute("SELECT id FROM assets WHERE hostname = %s", (hostname,))
                            row = cur.fetchone()
                            if row: asset_id = str(row["id"])
                    except Exception:
                        cur.execute("ROLLBACK TO SAVEPOINT katana_rec")
                        cur.execute("SAVEPOINT katana_rec")

                    # ── API endpoint classification ──
                    api_class = _classify_endpoint(url, method, response, tag)

                    # Build evidence and refs
                    evidence_parts = []
                    if method: evidence_parts.append(f"Method: {method}")
                    if tag: evidence_parts.append(f"Tag: {tag}")
                    if source: evidence_parts.append(f"Source: {source}")
                    if api_class:
                        evidence_parts.append(f"API: {api_class['api_type']} ({api_class['confidence']})")
                    evidence = " | ".join(evidence_parts) if evidence_parts else None

                    refs = {}
                    if tag: refs["tag"] = tag
                    if source: refs["source"] = source
                    if api_class:
                        refs["api_type"] = api_class["api_type"]
                        refs["api_confidence"] = api_class["confidence"]
                        refs["api_signals"] = api_class["signals"]

                    # Determine severity: API endpoints get "info" for visibility
                    severity = "recon"
                    issue_type = None
                    if api_class:
                        severity = "info"
                        issue_type = f"api_endpoint:{api_class['api_type']}"

                    finding_id = str(uuid.uuid4())
                    cur.execute("""
                        INSERT INTO web_findings
                        (id, asset_id, url, source, method, status_code, severity, evidence, refs, issue_type)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (finding_id, asset_id, url, "katana", method, status_code, severity, evidence, json.dumps(refs), issue_type))
                    stats["findings_inserted"] += 1

                    # Ensure port record exists
                    if asset_id:
                        try:
                            from urllib.parse import urlparse as _kup
                            _kp = _kup(url)
                            k_port = int(_kp.port) if _kp.port else (443 if _kp.scheme == 'https' else 80)
                            k_svc = _kp.scheme or 'http'
                            cur.execute("SAVEPOINT katana_port")
                            cur.execute("""INSERT INTO ports (id, asset_id, proto, port, service, is_open)
                                          VALUES (%s, %s, 'tcp', %s, %s, true)
                                          ON CONFLICT DO NOTHING""",
                                        (str(uuid.uuid4()), asset_id, k_port, k_svc))
                            cur.execute("RELEASE SAVEPOINT katana_port")
                        except Exception:
                            try: cur.execute("ROLLBACK TO SAVEPOINT katana_port")
                            except: pass

                    # ── Store API endpoint in content_extractions ──
                    if api_class:
                        try:
                            if _upsert_api_endpoint(cur, asset_id, api_class, scan_id=job_id):
                                stats["api_endpoints_found"] += 1
                                api_type = api_class["api_type"]
                                stats["api_endpoints_by_type"][api_type] = stats["api_endpoints_by_type"].get(api_type, 0) + 1
                        except Exception:
                            pass  # Don't fail for content_extractions issues

                    # Extract and upsert discovered params
                    raw_request = ""
                    if isinstance(request, dict):
                        raw_request = request.get("raw", "") or ""
                    params = _extract_params(url, method, raw_request)
                    for p in params:
                        try:
                            _upsert_param(cur, asset_id, p)
                            stats["params_extracted"] += 1
                        except Exception:
                            pass  # Don't fail the main loop for param extraction issues

                    cur.execute("RELEASE SAVEPOINT katana_rec")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT katana_rec")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
