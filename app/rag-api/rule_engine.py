"""
YAML-based Detection Rule Engine for the OSINT flagging agent.

Loads detection rules from YAML files, builds safe parameterized SQL,
applies pattern matching, and supports dry-run testing.
"""

import os
import re
import glob
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import yaml

log = logging.getLogger("rule_engine")

# ──────────────────────────────────────────────────────────────
# Safety: table / column whitelists
# ──────────────────────────────────────────────────────────────

ALLOWED_TABLES = {
    "recon_findings", "web_findings", "vulns", "ports",
    "credential_vault", "playwright_findings", "credential_findings",
    "content_extractions", "dom_analysis", "discovered_params",
    "detected_software",
}

ALLOWED_COLUMNS = {
    "recon_findings": {
        "id", "target", "data", "source", "finding_type",
        "severity", "confidence", "created_at", "updated_at", "tags",
    },
    "web_findings": {
        "id", "url", "name", "evidence", "source", "severity",
        "status_code", "method", "issue_type",
        "user_tags", "created_at", "updated_at",
    },
    "vulns": {
        "id", "script", "output", "severity", "asset_id",
        "port", "protocol", "created_at", "updated_at",
    },
    "ports": {
        "id", "asset_id", "proto", "port", "is_open", "service",
        "product", "version", "banner", "created_at", "updated_at",
    },
    "credential_vault": {
        "id", "username", "domain", "credential_value", "cracked_value",
        "credential_type", "status", "source", "created_at", "updated_at",
        "expires_at", "cloud_metadata", "permissions_summary",
    },
    "playwright_findings": {
        "id", "url", "title", "evidence", "severity", "tags",
        "created_at", "updated_at",
    },
    "credential_findings": {
        "id", "target", "data", "source", "finding_type",
        "created_at", "updated_at",
    },
    "content_extractions": {
        "id", "url", "login_pages", "api_endpoints", "exposed_keys",
        "internal_paths", "emails", "names", "comments", "tech_indicators",
        "created_at",
    },
    "dom_analysis": {
        "id", "url", "forms", "forms_count", "cookies", "javascript_libs",
        "security_headers", "csp_header", "cors_enabled", "cors_config",
        "external_scripts", "mixed_content", "websockets",
        "created_at",
    },
    "discovered_params": {
        "id", "url_pattern", "param_name", "param_type", "http_method",
        "param_location", "sample_values", "occurrence_count", "discovery_source",
        "first_seen", "last_seen",
    },
    "detected_software": {
        "asset_id", "ip", "hostname", "port", "protocol",
        "product", "version", "source", "detection_type",
        "first_seen", "last_seen",
    },
}

_JSON_KEY_RE = re.compile(r"^[a-zA-Z0-9_]+$")

# Common weak passwords (used by check_weak_creds)
COMMON_PASSWORDS = {
    "password", "123456", "admin", "root", "letmein", "welcome",
    "changeme", "default", "guest", "test", "1234", "12345678",
    "qwerty", "abc123", "password1", "admin123", "toor",
}

# Redirect patterns (used by open redirect checks)
REDIRECT_PARAM_PATTERN = re.compile(
    r"[\?&](url|redirect|redirect_uri|redirect_url|return|return_url|returnto|"
    r"return_to|next|next_url|dest|destination|target|target_url|continue|"
    r"forward|fwd|goto|go|to|out|link|redir|rurl|callback|cb|fallback|"
    r"checkout_url|success_url|error_url|cancel_url|logout_redirect|"
    r"post_login_redirect|saml_redirect|RelayState)=",
    re.IGNORECASE,
)

REDIRECT_FINDING_PATTERN = re.compile(
    r"(open.?redirect|url.?redirect|unvalidated.?redirect|redirect.?vulnerab|"
    r"CWE-601|external.?redirect|arbitrary.?redirect|redirect.?injection)",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────
# Built-in Python match functions (for complex logic not
# expressible via simple regex/set YAML declarations)
# ──────────────────────────────────────────────────────────────

def check_self_signed(row, _rule):
    """Check if a tlsx finding indicates a self-signed cert."""
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    is_self_signed = data.get("self_signed", False)
    issuer = (data.get("issuer", "") or "").lower()
    target = (row.get("target", "") or "").lower()
    return is_self_signed or (target and target in issuer)


def check_expired_cert(row, _rule):
    """Check if a tlsx finding has an expired certificate."""
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    not_after = data.get("not_after", "")
    if not not_after:
        return False
    try:
        expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        if expiry < datetime.now(timezone.utc):
            row["not_after"] = not_after  # expose for template
            return True
    except (ValueError, TypeError):
        pass
    return False


def check_self_signed_plus_service(row, _rule):
    """Check self-signed cert on high-value HTTPS ports."""
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    is_self_signed = data.get("self_signed", False)
    port = str(data.get("port", ""))
    high_value_ports = {"443", "8443", "8080", "9443", "4443"}
    if is_self_signed and port in high_value_ports:
        row["port"] = port  # expose for template
        return True
    return False


def check_weak_creds(row, _rule):
    """Check if credential has a weak/default password."""
    pw = ""
    if row.get("cracked_value"):
        pw = row["cracked_value"].strip().lower()
    elif row.get("credential_type") == "password" and row.get("credential_value"):
        pw = row["credential_value"].strip().lower()
    if pw and pw in COMMON_PASSWORDS:
        row["domain"] = row.get("domain") or "unknown"
        return True
    return False


def check_open_redirect_web(row, _rule):
    """Check web_findings for redirect patterns in name/evidence or URL params."""
    text = f"{row.get('name', '')} {row.get('evidence', '')}"
    url = row.get("url", "")
    is_redirect_finding = REDIRECT_FINDING_PATTERN.search(text)
    has_redirect_param = REDIRECT_PARAM_PATTERN.search(url)

    if is_redirect_finding:
        row["_confidence_override"] = 0.9
        row["_reason_override"] = (
            f"Open redirect found by {row.get('source', 'scanner')}: {row.get('name', '')}"
        )
        return True
    if has_redirect_param:
        row["_confidence_override"] = 0.7
        row["_reason_override"] = (
            f"URL contains redirect parameter — test for open redirect: {url}"
        )
        return True
    return False


def check_open_redirect_recon(row, _rule):
    """Check recon_findings crawled URLs for redirect params."""
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    url = data.get("url") or data.get("input") or row.get("target", "")
    if url and REDIRECT_PARAM_PATTERN.search(url):
        row["url"] = url  # expose for template
        return True
    return False


# ── Scope intelligence match functions ──

_ADMIN_TITLE_RE = re.compile(
    r"(admin|dashboard|panel|console|manager|jenkins|grafana|kibana|"
    r"phpmyadmin|webmin|portainer|tomcat|jmx|actuator|setup|install|config|swagger)",
    re.IGNORECASE,
)


def check_interesting_http_service(row, _rule):
    """Flag HTTP services with admin/management titles or non-standard ports."""
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    title = data.get("title") or ""
    url = data.get("url") or row.get("target", "")
    status = data.get("status_code")
    if title and _ADMIN_TITLE_RE.search(title):
        row["url"] = url
        row["title"] = title
        row["_reason_override"] = f"Interesting page title: {title}"
        return True
    # Non-standard HTTP port
    port = data.get("port") or ""
    if port and str(port) not in ("80", "443", "8080", "8443"):
        if status and int(status) < 400:
            row["url"] = url
            row["title"] = title or "(no title)"
            row["port"] = str(port)
            row["_reason_override"] = f"HTTP on non-standard port {port}: {url}"
            return True
    return False


def check_exposed_api_endpoints(row, _rule):
    """Flag content extractions that found API endpoints."""
    eps = row.get("api_endpoints")
    if not eps:
        return False
    if isinstance(eps, list) and len(eps) > 0:
        row["endpoint_count"] = str(len(eps))
        row["sample"] = str(eps[0])[:100] if eps else ""
        return True
    return False


def check_exposed_keys(row, _rule):
    """Flag content extractions that found exposed keys/secrets."""
    keys = row.get("exposed_keys")
    if not keys:
        return False
    if isinstance(keys, list) and len(keys) > 0:
        row["key_count"] = str(len(keys))
        row["sample"] = str(keys[0])[:80] if keys else ""
        return True
    return False


def check_sensitive_params(row, _rule):
    """Flag discovered parameters with security-sensitive names."""
    param = (row.get("param_name") or "").lower()
    sensitive = {"token", "key", "secret", "password", "passwd", "pass", "auth",
                 "api_key", "apikey", "access_token", "session", "jwt", "debug",
                 "admin", "redirect", "callback"}
    if any(s in param for s in sensitive):
        return True
    return False


# Cache for CVE lookups to avoid repeated queries within same agent run
_SOFTWARE_CVE_CACHE: dict = {}

# Tuning parameters (loaded from DB app_settings on first use)
_CVE_TUNING: dict = {}
_CVE_TUNING_LOADED = False

_CVE_TUNING_DEFAULTS = {
    "age_penalty_2yr": 0.8,
    "age_penalty_3yr": 0.6,
    "age_penalty_5yr": 0.4,
    "min_confidence_threshold": 0.3,   # skip if final confidence below this
    "skip_products": "",               # comma-separated product names to ignore
    "extra_aliases": "",               # "product1:alias1,alias2;product2:alias3"
}


def _load_cve_tuning(cur):
    """Load CVE rule tuning parameters from app_settings (cached per engine run)."""
    global _CVE_TUNING, _CVE_TUNING_LOADED
    if _CVE_TUNING_LOADED:
        return _CVE_TUNING
    _CVE_TUNING_LOADED = True
    _CVE_TUNING = dict(_CVE_TUNING_DEFAULTS)
    try:
        cur.execute(
            "SELECT key, value FROM app_settings WHERE key LIKE 'cve_rule.%' AND category = 'config'"
        )
        for row in cur.fetchall():
            param = row["key"].replace("cve_rule.", "")
            if param in _CVE_TUNING_DEFAULTS:
                val = row["value"]
                if isinstance(_CVE_TUNING_DEFAULTS[param], float):
                    _CVE_TUNING[param] = float(val)
                else:
                    _CVE_TUNING[param] = val
        # Parse extra aliases into _SOFTWARE_ALIASES
        extra = _CVE_TUNING.get("extra_aliases", "")
        if extra:
            for entry in extra.split(";"):
                entry = entry.strip()
                if ":" in entry:
                    prod, aliases_str = entry.split(":", 1)
                    _SOFTWARE_ALIASES[prod.strip().lower()] = [a.strip() for a in aliases_str.split(",")]
    except Exception as e:
        log.debug("Could not load CVE tuning from DB: %s", e)
    return _CVE_TUNING


def reset_cve_tuning_cache():
    """Reset tuning cache so next call reloads from DB."""
    global _CVE_TUNING_LOADED, _SOFTWARE_CVE_CACHE
    _CVE_TUNING_LOADED = False
    _SOFTWARE_CVE_CACHE = {}

# Web CVE search cache (DDG results cached to avoid repeated lookups)
_WEB_CVE_CACHE: dict = {}


def _web_cve_search(product: str, version: str, timeout: float = 10.0) -> list:
    """Search for CVEs: NVD API for product + DDG web search. Cache results in DB."""
    cache_key = f"{product.lower()}|{version}"
    if cache_key in _WEB_CVE_CACHE:
        return list(_WEB_CVE_CACHE[cache_key])

    import requests as _req
    seen = set()
    cve_ids = []

    # 1. NVD API: pull CVEs for product + vendor keywords
    nvd_keywords = [product]
    parts = product.split()
    if len(parts) >= 2:
        nvd_keywords.append(parts[0])  # vendor name
    # Load NVD API key if configured
    nvd_api_key = os.environ.get("NVD_API_KEY", "")
    if not nvd_api_key:
        try:
            db_dsn = os.environ.get("DB_DSN", "")
            import psycopg2 as _pg2
            _c = _pg2.connect(db_dsn)
            _cur = _c.cursor()
            _cur.execute("SELECT value FROM app_settings WHERE key = 'nvd_api_key' AND category IN ('config', 'api_key')")
            _r = _cur.fetchone()
            if _r: nvd_api_key = _r[0]
            _cur.close(); _c.close()
        except Exception:
            pass
    nvd_headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
    for kw in nvd_keywords:
        try:
            nvd_resp = _req.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": kw, "resultsPerPage": 50},
                headers=nvd_headers, timeout=timeout, verify=False,
            )
            if nvd_resp.status_code == 200:
                for v in nvd_resp.json().get("vulnerabilities", []):
                    cve = v.get("cve", {})
                    cve_id = cve.get("id", "")
                    if cve_id and cve_id not in seen:
                        seen.add(cve_id)
                        cve_ids.append(cve_id)
                        _cache_cve_to_db(cve)
        except Exception as e:
            log.debug("NVD API search failed for %s: %s", kw, e)

    # 2. DDG web search for CVEs + vendor advisories
    from api import ddg_search as _ddg_search
    ddg_queries = [
        f"{product} {version} security issues",
        f"{product} {version} CVE",
        f"{product} security advisory CVE",
    ]
    advisory_urls = []
    for query in ddg_queries:
        for r in _ddg_search(query, max_results=10, timeout=timeout):
            # Extract CVEs from titles/snippets
            for cve_id in re.findall(r'CVE-\d{4}-\d{4,7}', r.get("title", "") + " " + r.get("snippet", "")):
                if cve_id not in seen:
                    seen.add(cve_id)
                    cve_ids.append(cve_id)
            # Collect advisory URLs
            url = r.get("url", "")
            if any(s in url.lower() for s in ('security', 'advisory', 'bulletin', 'cve', 'cert.')):
                advisory_urls.append(url)

    # 3. Scrape advisory pages for CVEs not in DDG snippets
    for aurl in list(set(advisory_urls))[:3]:
        try:
            aresp = _req.get(aurl,
                headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout, verify=False)
            if aresp.status_code == 200:
                for cve_id in re.findall(r'CVE-\d{4}-\d{4,7}', aresp.text):
                    if cve_id not in seen:
                        seen.add(cve_id)
                        cve_ids.append(cve_id)
                        _cache_cve_to_db({"id": cve_id, "descriptions": [{"lang": "en", "value": f"Found in advisory: {aurl[:80]}"}], "metrics": {}, "references": []})
        except Exception:
            pass

    _WEB_CVE_CACHE[cache_key] = cve_ids
    return cve_ids


def _cache_cve_to_db(cve: dict):
    """Cache a CVE into the local cve table. Only enriches — never overwrites richer data."""
    try:
        import psycopg2 as _pg
        import json as _json

        cve_id = cve.get("id", "")
        if not cve_id or not cve_id.startswith("CVE-"):
            return
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        cvss = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                if cvss:
                    break

        refs = [{"url": r.get("url", ""), "source": r.get("source", "")} for r in cve.get("references", [])]
        published = cve.get("published")
        modified = cve.get("lastModified")

        db_dsn = os.environ.get("DB_DSN", "dbname=scans user=app password=app host=127.0.0.1 port=5432")
        conn = _pg.connect(db_dsn)
        conn.autocommit = True
        cur = conn.cursor()
        # Insert new CVEs; on conflict only update fields that are better than existing
        # - summary: only update if new summary is longer (NVD > advisory stub)
        # - cvss: only update if new value is non-null
        # - refs: merge arrays
        cur.execute("""INSERT INTO cve (id, summary, cvss, published, last_modified, refs)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                summary = CASE WHEN LENGTH(EXCLUDED.summary) > LENGTH(COALESCE(cve.summary, '')) THEN EXCLUDED.summary ELSE cve.summary END,
                cvss = COALESCE(EXCLUDED.cvss, cve.cvss),
                published = COALESCE(EXCLUDED.published, cve.published),
                last_modified = COALESCE(EXCLUDED.last_modified, cve.last_modified),
                refs = CASE WHEN cve.refs IS NULL OR cve.refs = '[]'::jsonb THEN EXCLUDED.refs
                            ELSE cve.refs || EXCLUDED.refs END""",
            (cve_id, summary, cvss, published, modified, _json.dumps(refs)))
        cur.close()
        conn.close()
    except Exception:
        pass


# ExploitDB search index (loaded on first use)
_EXPLOITDB_INDEX: list = []
_EXPLOITDB_LOADED = False

EXPLOITDB_CSV = os.environ.get("EXPLOITDB_CSV", "/exploitdb/files_exploits.csv")


def _load_exploitdb():
    """Load ExploitDB CSV into memory as a searchable index."""
    global _EXPLOITDB_INDEX, _EXPLOITDB_LOADED
    if _EXPLOITDB_LOADED:
        return
    _EXPLOITDB_LOADED = True
    import csv
    path = EXPLOITDB_CSV
    if not os.path.exists(path):
        log.info("ExploitDB CSV not found at %s — searchsploit matching disabled", path)
        return
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                desc = (row.get("description") or "").lower()
                if desc:
                    _EXPLOITDB_INDEX.append({
                        "id": row.get("id", ""),
                        "description": row.get("description", ""),
                        "desc_lower": desc,
                        "type": row.get("type", ""),
                        "platform": row.get("platform", ""),
                        "codes": row.get("codes", ""),
                        "verified": row.get("verified", "0") == "1",
                        "date": row.get("date_published", ""),
                    })
        log.info("ExploitDB loaded: %d exploits indexed", len(_EXPLOITDB_INDEX))
    except Exception as e:
        log.warning("Failed to load ExploitDB CSV: %s", e)


def _searchsploit(product: str, version: str, limit: int = 10) -> list:
    """Search ExploitDB for exploits matching product+version.

    Returns results in ranked order:
    - Tier 1: Exact version match (e.g. "9.12.11" in description)
    - Tier 2: Major.minor match with word boundary (e.g. "9.12" but not "9.120")
    - Tier 3: Range patterns (< X.Y, X.Y.x, before X.Y)
    - Tier 4: Product-only match (no version in query)
    """
    _load_exploitdb()
    if not _EXPLOITDB_INDEX:
        return []

    import re as _re

    product_lower = product.lower().replace("-", " ").replace("_", " ")
    # Build search terms from product + aliases
    terms = {product_lower}
    for key, aliases in _SOFTWARE_ALIASES.items():
        if key in product_lower or product_lower in key:
            for a in aliases:
                terms.add(a.lower())

    # Build word-boundary regexes for product matching to avoid false positives
    # e.g. "apache" should not match inside "omnihttpd" descriptions
    term_regexes = [_re.compile(r'(?:^|[\s/(\-])' + _re.escape(t) + r'(?:[\s/)\-.,:]|$)') for t in terms]

    # Version prefix for broader matching (e.g., "2.4" from "2.4.41")
    version_parts = version.split(".") if version else []
    version_major_minor = ".".join(version_parts[:2]) if len(version_parts) >= 2 else version

    # Build version boundary patterns for precise matching
    # "9.12.11" should match "9.12.11" but not "9.12.110"
    v_exact_re = _re.compile(r'(?<![.\d])' + _re.escape(version) + r'(?![.\d])') if version else None
    v_mm_re = _re.compile(r'(?<![.\d])' + _re.escape(version_major_minor) + r'(?![.\d])') if version_major_minor else None

    tier1 = []  # exact version
    tier2 = []  # major.minor
    tier3 = []  # range patterns
    tier4 = []  # product only (no version filtering)

    for entry in _EXPLOITDB_INDEX:
        desc = entry["desc_lower"]
        # Must match at least one product term with word boundaries
        if not any(rx.search(desc) for rx in term_regexes):
            continue

        if not version:
            tier4.append(entry)
            continue

        # Tier 1: exact version with word boundaries
        if v_exact_re and v_exact_re.search(desc):
            tier1.append(entry)
        # Tier 2: major.minor with word boundaries
        elif version_major_minor != version and v_mm_re and v_mm_re.search(desc):
            tier2.append(entry)
        # Tier 3: range patterns like "< 9.13", "before 9.13", "9.12.x"
        elif f"{version_major_minor}.x" in desc:
            tier3.append(entry)
        elif f"< {version_major_minor}" in desc or f"before {version_major_minor}" in desc:
            tier3.append(entry)
        # Check if a higher version is mentioned as the fix (meaning our version is vulnerable)
        elif version_parts:
            try:
                major = int(version_parts[0])
                minor = int(version_parts[1]) if len(version_parts) > 1 else 0
                # "< X.(minor+1)" or "< (major+1)" patterns
                for delta_minor in range(1, 4):
                    fix_ver = f"{major}.{minor + delta_minor}"
                    if f"< {fix_ver}" in desc or f"before {fix_ver}" in desc:
                        tier3.append(entry)
                        break
            except (ValueError, IndexError):
                pass

    # Combine tiers, prioritizing exact matches
    results = tier1 + tier2 + tier3
    if not results:
        results = tier4  # fall back to product-only if no version matches
    return results[:limit]


_SOFTWARE_ALIASES = {
    "microsoft iis": ["iis"],
    "apache": ["apache http server", "httpd"],
    "nginx": ["nginx"],
    "openssl": ["openssl"],
    "jquery": ["jquery"],
    "php": ["php"],
    "wordpress": ["wordpress"],
    "bootstrap": ["bootstrap"],
    "citrix netscaler": ["citrix netscaler", "netscaler adc", "netscaler gateway"],
    "resin": ["caucho resin"],
}


def check_software_cve(row, _rule):
    """Cross-reference detected software product/version against CVE table.

    Matches on:
    1. Exact product+version in CVE summary text
    2. Known vulnerable product families (Apache, nginx, OpenSSL, jQuery, etc.)
       where version is present and old enough to have CVEs
    """
    product = (row.get("product") or "").strip()
    version = (row.get("version") or "").strip()
    row["ip"] = row.get("ip") or "unknown"

    if not product or not version:
        return False

    # Generate a stable finding id for dedup (detected_software view has no id column)
    # Use asset_id if available, otherwise create a deterministic UUID from product+version+ip
    if not row.get("id"):
        if row.get("asset_id"):
            row["id"] = row["asset_id"]
        else:
            import uuid as _uuid
            row["id"] = str(_uuid.uuid5(
                _uuid.NAMESPACE_URL,
                f"software:{row.get('ip', '')}:{product}:{version}"
            ))

    # Skip hash-like versions (webpack chunk hashes, etc.)
    if len(version) > 12 or not re.search(r"\d+\.\d+", version):
        return False

    cur = row.get("_db_cur")
    if not cur:
        return False

    # Load tuning parameters from DB
    tuning = _load_cve_tuning(cur)

    # Check skip list
    skip_products = [p.strip().lower() for p in tuning.get("skip_products", "").split(",") if p.strip()]
    if any(s in product.lower() for s in skip_products):
        return False

    # Use cached CVE lookup results to avoid repeated queries
    cache = _SOFTWARE_CVE_CACHE
    cache_key = f"{product.lower()}|{version}"
    if cache_key in cache:
        cached = cache[cache_key]
        if cached is None:
            return False
        row.update(cached)
        return True

    product_lower = product.lower()

    # Normalize product name for CVE matching: "microsoft-iis" -> "microsoft iis"
    product_normalized = product_lower.replace("-", " ").replace("_", " ")
    search_terms = {product_normalized}
    # Add aliases for common products
    for key, aliases in _SOFTWARE_ALIASES.items():
        if key in product_normalized or product_normalized in key:
            search_terms.update(aliases)

    # Search for CVEs via web (DuckDuckGo) + local CVE table fallback
    try:
        cve_ids = _web_cve_search(product, version)

        # Also check local CVE table if it has data
        try:
            for term in search_terms:
                cur.execute("""
                    SELECT id FROM cve
                    WHERE LOWER(summary) LIKE %s AND LOWER(summary) LIKE %s
                    ORDER BY cvss DESC NULLS LAST LIMIT 10
                """, (f"%{term}%", f"%{version}%"))
                for c in cur.fetchall():
                    if str(c["id"]) not in cve_ids:
                        cve_ids.append(str(c["id"]))
        except Exception:
            pass

        if cve_ids:
            # Age penalty: CVEs older than 2 years get reduced confidence
            from datetime import datetime as _dt
            current_year = _dt.now().year
            newest_year = 0
            for cve_id in cve_ids:
                m = re.match(r"CVE-(\d{4})", cve_id)
                if m:
                    newest_year = max(newest_year, int(m.group(1)))
            age_years = current_year - newest_year if newest_year else 0

            base_confidence = 0.85
            if age_years >= 5:
                base_confidence *= tuning.get("age_penalty_5yr", 0.4)
            elif age_years >= 3:
                base_confidence *= tuning.get("age_penalty_3yr", 0.6)
            elif age_years >= 2:
                base_confidence *= tuning.get("age_penalty_2yr", 0.8)

            min_conf = tuning.get("min_confidence_threshold", 0.3)
            if base_confidence < min_conf:
                cache[cache_key] = None
                return False

            result = {
                "cve_list": ", ".join(cve_ids[:5]),
                "cve_count": str(len(cve_ids)),
                "max_cvss": "web",
                "_confidence_override": round(base_confidence, 2),
            }
            cache[cache_key] = result
            row.update(result)
            return True
    except Exception as e:
        log.debug("CVE lookup failed for %s %s: %s", product, version, e)

    # Fallback: searchsploit (ExploitDB) lookup
    try:
        exploits = _searchsploit(product, version, limit=10)
        if exploits:
            edb_ids = [f"EDB-{e['id']}" for e in exploits]
            # Extract CVE codes from exploits if available
            cve_codes = []
            for e in exploits:
                for code in (e.get("codes") or "").split(";"):
                    code = code.strip()
                    if code.startswith("CVE-"):
                        cve_codes.append(code)
            label_parts = edb_ids[:3]
            if cve_codes:
                label_parts = list(dict.fromkeys(cve_codes[:3] + edb_ids[:2]))  # CVEs first, deduped

            result = {
                "cve_list": ", ".join(label_parts[:5]),
                "cve_count": str(len(exploits)),
                "max_cvss": "exploit-db",
                "_confidence_override": 0.8 if any(e["verified"] for e in exploits) else 0.6,
            }
            cache[cache_key] = result
            row.update(result)
            return True
    except Exception as e:
        log.debug("Searchsploit lookup failed for %s %s: %s", product, version, e)

    cache[cache_key] = None  # Negative cache
    return False


def check_missing_security_headers(row, _rule):
    """Flag pages missing critical security headers."""
    headers = row.get("security_headers")
    if not headers or not isinstance(headers, dict):
        return True  # no headers at all = flag

    # Comprehensive security headers check
    critical_headers = [
        "content-security-policy",      # CSP - XSS/injection protection
        "x-frame-options",              # Clickjacking protection
        "strict-transport-security",    # HSTS - force HTTPS
        "x-content-type-options",       # MIME sniffing protection
        "referrer-policy",              # Control referrer information
        "permissions-policy"            # Feature policy restrictions
    ]

    # Additional headers worth checking but not critical
    recommended_headers = [
        "x-xss-protection",             # Legacy XSS protection
        "expect-ct",                    # Certificate transparency
        "cross-origin-embedder-policy", # COEP
        "cross-origin-opener-policy",   # COOP
        "cross-origin-resource-policy"  # CORP
    ]

    missing_critical = []
    missing_recommended = []

    for h in critical_headers:
        if not headers.get(h):
            missing_critical.append(h)

    for h in recommended_headers:
        if not headers.get(h):
            missing_recommended.append(h)

    # Flag if any critical headers are missing
    if missing_critical:
        all_missing = missing_critical + missing_recommended
        row["missing_headers"] = ", ".join(all_missing[:5])  # Limit to first 5 for readability
        row["missing_critical_headers"] = ", ".join(missing_critical)
        row["missing_recommended_headers"] = ", ".join(missing_recommended)
        return True

    return False


def check_tcpwrapped_security_control(row, _rule):
    """Detect hosts with many tcpwrapped ports — indicates WAF/LB/security appliance."""
    asset_id = row.get("asset_id")
    if not asset_id:
        return False
    service = str(row.get("service", "")).lower()
    if service != "tcpwrapped":
        return False
    # Need DB connection to count — stored in row by multi_pass or injected
    # For simple rule: just flag any tcpwrapped port (the grouping happens in the follow-up title)
    return True


def check_tcpwrapped_mass(row, _rule):
    """Check if this tcpwrapped finding is part of a mass-open pattern (10+ tcpwrapped ports on same host).
    Requires the rule to inject _db_cur via extra_context."""
    asset_id = row.get("asset_id")
    if not asset_id:
        return False
    service = str(row.get("service", "")).lower()
    if service != "tcpwrapped":
        return False
    cur = row.get("_db_cur")
    if not cur:
        return True  # Fallback: flag all tcpwrapped
    try:
        cur.execute(
            "SELECT COUNT(*) FROM ports WHERE asset_id = %s AND is_open = true AND service = 'tcpwrapped'",
            (asset_id,))
        count = cur.fetchone()[0]
        row["_tcpwrapped_count"] = count
        return count >= 10  # Only flag if 10+ tcpwrapped ports
    except Exception:
        return True


def check_in_scope_domain(row, _rule):
    """Check if a web finding URL is from an in-scope domain (has associated asset_id)."""
    asset_id = row.get("asset_id")
    url = row.get("url", "")

    # If there's an asset_id, it's in scope (this is the primary indicator)
    if asset_id:
        return True

    # If no asset_id but URL exists, check if domain might be in scope
    # This is a more conservative check - we assume in scope unless clearly external
    if url:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if ':' in domain:
                domain = domain.split(':')[0]

            # Only flag as out-of-scope if it's a known external service domain
            external_service_patterns = [
                "demo.testfire.net",
                "addons.mozilla.org",
                "github.com",
                "stackoverflow.com",
                "w3.org",
                "mozilla.org",
                "google.com",
                "microsoft.com",
                "apple.com",
                "facebook.com",
                "twitter.com",
                "linkedin.com",
                "cloudfront.net",
                "amazonaws.com",
                "googleapis.com",
                "gstatic.com"
            ]

            for pattern in external_service_patterns:
                if domain == pattern or domain.endswith(f".{pattern}"):
                    return False

            # Internal/private addresses are definitely in scope
            if any(internal in domain for internal in ["localhost", "127.", "10.", "192.168.", "172.", "local", "test", "dev"]):
                return True

        except Exception:
            pass

    # Be conservative - assume in scope unless we have clear evidence it's external
    # This prevents false positives where legitimate findings get filtered out
    return True


def check_external_domain(row, _rule):
    """Identify external domains discovered during crawling for scope review."""
    asset_id = row.get("asset_id")
    url = row.get("url", "")

    # Only flag if no asset_id (not associated with in-scope asset)
    if asset_id:
        return False

    if url:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if ':' in domain:
                domain = domain.split(':')[0]

            # Skip obvious localhost/internal addresses
            if any(internal in domain for internal in ["localhost", "127.", "10.", "192.168.", "172.", "local", "test", "dev"]):
                return False

            # Only flag domains that are clearly external services or CDNs
            external_service_indicators = [
                "cloudfront.net",
                "amazonaws.com",
                "googleapis.com",
                "gstatic.com",
                "cdn.",
                "static.",
                "assets.",
                "media.",
                "github.com",
                "stackoverflow.com",
                "mozilla.org"
            ]

            for indicator in external_service_indicators:
                if indicator in domain:
                    row["domain"] = domain
                    return True

            # Don't flag regular domains - they might be legitimately in scope
            # This prevents false positives for unknown but valid target domains

        except Exception:
            pass

    return False


def check_valuable_external_login(row, _rule):
    """Identify potentially valuable external login pages that might warrant scope expansion."""
    asset_id = row.get("asset_id")
    url = row.get("url", "")
    name = row.get("name", "")
    evidence = row.get("evidence", "")

    # Only consider if no asset_id (external)
    if asset_id:
        return False

    if url:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Skip obviously low-value external domains
            skip_domains = ["demo.", "test.", "example.", "localhost", "127.", "10.", "192.168.", "172."]
            if any(skip in domain for skip in skip_domains):
                return False

            # Look for high-value login indicators
            high_value_patterns = [
                "admin", "portal", "dashboard", "console", "management",
                "api", "service", "enterprise", "corp", "internal"
            ]

            text_content = f"{url} {name} {evidence}".lower()
            if any(pattern in text_content for pattern in high_value_patterns):
                row["domain"] = domain
                return True

            # Flag login pages on custom/business domains (not common services)
            common_services = [
                "google.com", "microsoft.com", "apple.com", "facebook.com",
                "twitter.com", "linkedin.com", "github.com", "stackoverflow.com"
            ]

            if not any(service in domain for service in common_services) and "." in domain:
                row["domain"] = domain
                return True

        except Exception:
            pass

    return False


# Registry of built-in Python match functions
PYTHON_MATCH_FUNCTIONS = {
    "check_self_signed": check_self_signed,
    "check_expired_cert": check_expired_cert,
    "check_self_signed_plus_service": check_self_signed_plus_service,
    "check_weak_creds": check_weak_creds,
    "check_open_redirect_web": check_open_redirect_web,
    "check_tcpwrapped_security_control": check_tcpwrapped_security_control,
    "check_tcpwrapped_mass": check_tcpwrapped_mass,
    "check_open_redirect_recon": check_open_redirect_recon,
    "check_interesting_http_service": check_interesting_http_service,
    "check_exposed_api_endpoints": check_exposed_api_endpoints,
    "check_exposed_keys": check_exposed_keys,
    "check_sensitive_params": check_sensitive_params,
    "check_missing_security_headers": check_missing_security_headers,
    "check_software_cve": check_software_cve,
    "check_in_scope_domain": check_in_scope_domain,
    "check_external_domain": check_external_domain,
    "check_valuable_external_login": check_valuable_external_login,
}


# ──────────────────────────────────────────────────────────────
# Validation helpers
# ──────────────────────────────────────────────────────────────

def _validate_table(table: str):
    if table not in ALLOWED_TABLES:
        raise ValueError(f"Table '{table}' not in whitelist: {ALLOWED_TABLES}")


def _validate_columns(table: str, columns: list):
    allowed = ALLOWED_COLUMNS.get(table, set())
    for col in columns:
        if col not in allowed:
            raise ValueError(f"Column '{col}' not allowed for table '{table}'. Allowed: {allowed}")


def _validate_json_key(key: str):
    if not _JSON_KEY_RE.match(key):
        raise ValueError(f"Invalid JSON key name: '{key}' (must match ^[a-zA-Z0-9_]+$)")


# ──────────────────────────────────────────────────────────────
# SQL Builder
# ──────────────────────────────────────────────────────────────

def _build_query(query_spec: dict, since_minutes: int) -> tuple:
    """
    Build a safe parameterized SQL query from a YAML query spec.
    Returns (sql_string, params_list).
    """
    table = query_spec["table"]
    _validate_table(table)

    columns = query_spec.get("columns", ["id"])
    _validate_columns(table, columns)

    table_alias = query_spec.get("table_alias", "")
    alias_prefix = f"{table_alias}." if table_alias else ""

    # SELECT clause
    col_list = ", ".join(f"{alias_prefix}{c}" for c in columns)
    extra_select = query_spec.get("extra_select", "")
    if extra_select:
        col_list += f", {extra_select}"

    from_clause = f"{table} {table_alias}" if table_alias else table

    # WHERE clause
    conditions = []
    params = []

    where = query_spec.get("where", {})
    for key, value in where.items():
        if key == "array_contains":
            # Special: column @> ARRAY[value]
            col = value["column"]
            _validate_columns(table, [col])
            conditions.append(f"{alias_prefix}{col} @> ARRAY[%s]")
            params.append(value["value"])
        elif key == "source_in":
            # Special: source IN (%s, %s, ...)
            _validate_columns(table, ["source"])
            placeholders = ", ".join(["%s"] * len(value))
            conditions.append(f"{alias_prefix}source IN ({placeholders})")
            params.extend(value)
        else:
            _validate_columns(table, [key])
            conditions.append(f"{alias_prefix}{key} = %s")
            params.append(value)

    # JSON conditions
    for jc in query_spec.get("json_conditions", []):
        col = jc["column"]
        _validate_columns(table, [col])
        _validate_json_key(jc["key"])
        op = jc["op"]
        if op == "is_not_true":
            conditions.append(f"({alias_prefix}{col}->>'{jc['key']}')::boolean IS NOT TRUE")
        elif op == "eq":
            conditions.append(f"{alias_prefix}{col}->>'{jc['key']}' = %s")
            params.append(jc["value"])
        elif op == "neq":
            conditions.append(f"{alias_prefix}{col}->>'{jc['key']}' != %s")
            params.append(jc["value"])
        else:
            raise ValueError(f"Unknown json_condition op: '{op}'")

    # Time filter
    time_col = query_spec.get("time_column")
    if time_col:
        _validate_columns(table, [time_col])
        conditions.append(f"{alias_prefix}{time_col} > now() - interval '%s minutes'")
        params.append(since_minutes)

    where_clause = " AND ".join(conditions) if conditions else "TRUE"
    sql = f"SELECT {col_list} FROM {from_clause} WHERE {where_clause}"

    return sql, params


def _build_cross_source_queries(sources: list, since_minutes: int):
    """Build queries for cross_source rule. Returns list of (name, sql, params, spec)."""
    results = []
    for src in sources:
        table = src["table"]
        _validate_table(table)
        columns = src.get("columns", ["id"])
        _validate_columns(table, columns)

        col_list = ", ".join(columns)

        conditions = []
        params = []
        where = src.get("where", {})
        for key, value in where.items():
            _validate_columns(table, [key])
            conditions.append(f"{key} = %s")
            params.append(value)

        for jc in src.get("json_conditions", []):
            col = jc["column"]
            _validate_columns(table, [col])
            _validate_json_key(jc["key"])
            op = jc["op"]
            if op == "is_not_true":
                conditions.append(f"({col}->>'{jc['key']}')::boolean IS NOT TRUE")
            elif op == "eq":
                conditions.append(f"{col}->>'{jc['key']}' = %s")
                params.append(jc["value"])

        time_col = src.get("time_column")
        if time_col:
            _validate_columns(table, [time_col])
            conditions.append(f"{time_col} > now() - interval '%s minutes'")
            params.append(since_minutes)

        where_clause = " AND ".join(conditions) if conditions else "TRUE"

        distinct = src.get("distinct")
        if distinct:
            _validate_columns(table, [distinct])
            sql = f"SELECT DISTINCT {distinct} FROM {table} WHERE {where_clause}"
        else:
            sql = f"SELECT {col_list} FROM {table} WHERE {where_clause}"

        results.append((src["name"], sql, params, src))
    return results


# ──────────────────────────────────────────────────────────────
# Pattern Matching
# ──────────────────────────────────────────────────────────────

def _apply_match(row: dict, match_spec: dict, rule: dict) -> bool:
    """Apply a match specification to a row. Returns True if row matches."""
    if not match_spec:
        return True

    match_type = match_spec.get("type", "regex")

    if match_type == "regex":
        pattern = match_spec["pattern"]
        flags = re.IGNORECASE if match_spec.get("case_insensitive") else 0
        compiled = re.compile(pattern, flags)
        fields = match_spec.get("fields", [])
        text = " ".join(str(row.get(f, "")) for f in fields)
        return bool(compiled.search(text))

    elif match_type == "set":
        field = match_spec["field"]
        values = set(v.lower() for v in match_spec["values"])
        row_val = str(row.get(field, "")).lower().strip()
        return row_val in values

    elif match_type == "python":
        fn_name = match_spec["function"]
        fn = PYTHON_MATCH_FUNCTIONS.get(fn_name)
        if not fn:
            log.warning("Unknown Python match function: %s", fn_name)
            return False
        return fn(row, rule)

    else:
        log.warning("Unknown match type: %s", match_type)
        return False


# ──────────────────────────────────────────────────────────────
# Template rendering
# ──────────────────────────────────────────────────────────────

def _render_template(template: str, row: dict) -> str:
    """Safe template rendering — only replaces {key} with row values."""
    try:
        # Build a safe dict — only string values, truncated
        safe = {}
        for k, v in row.items():
            if k.startswith("_"):
                continue
            s = str(v) if v is not None else ""
            safe[k] = s[:200]
        return template.format_map(safe)
    except (KeyError, IndexError):
        return template


def _extract_host(url: str) -> str:
    """Extract hostname from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


# ──────────────────────────────────────────────────────────────
# Rule Engine
# ──────────────────────────────────────────────────────────────

class RuleEngine:
    """
    YAML-based detection rule engine.

    Loads rules from YAML files on disk plus ad-hoc rules from the DB.
    Merges enabled/disabled state from the detection_rule_state table.
    Executes rules against the database and returns matches.
    """

    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir or os.environ.get(
            "DETECTION_RULES_DIR", "/knowledge/detection_rules"
        )
        self.rules: list[dict] = []
        self._loaded = False

    def load_rules(self, db_cursor=None) -> int:
        """
        Load all rules from YAML files + DB adhoc rules.
        Merge enabled/disabled state from detection_rule_state.
        Returns number of rules loaded.
        """
        rules = []

        # 1. Load builtin.yaml
        builtin_path = os.path.join(self.rules_dir, "builtin.yaml")
        if os.path.isfile(builtin_path):
            try:
                with open(builtin_path) as f:
                    data = yaml.safe_load(f)
                if isinstance(data, list):
                    for r in data:
                        r["_source"] = "builtin"
                    rules.extend(data)
                log.info("Loaded %d builtin rules from %s", len(data) if data else 0, builtin_path)
            except Exception as e:
                log.error("Failed to load builtin rules: %s", e)

        # 2. Load custom/*.yaml
        custom_dir = os.path.join(self.rules_dir, "custom")
        if os.path.isdir(custom_dir):
            for path in sorted(glob.glob(os.path.join(custom_dir, "*.yaml"))):
                try:
                    with open(path) as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, list):
                        for r in data:
                            r["_source"] = "custom"
                        rules.extend(data)
                        log.info("Loaded %d custom rules from %s", len(data), path)
                except Exception as e:
                    log.warning("Failed to load custom rules from %s: %s", path, e)

        # 3. Load adhoc rules from DB
        if db_cursor:
            try:
                db_cursor.execute("""
                    SELECT rule_id, rule_yaml FROM detection_rule_state
                    WHERE source = 'adhoc' AND rule_yaml IS NOT NULL
                """)
                for row in db_cursor.fetchall():
                    try:
                        data = yaml.safe_load(row["rule_yaml"])
                        if isinstance(data, dict):
                            data["_source"] = "adhoc"
                            rules.append(data)
                        elif isinstance(data, list):
                            for r in data:
                                r["_source"] = "adhoc"
                            rules.extend(data)
                    except Exception as e:
                        log.warning("Failed to parse adhoc rule %s: %s", row["rule_id"], e)
            except Exception as e:
                log.warning("Could not load adhoc rules from DB: %s", e)

        # 4. Merge enabled/disabled state from DB
        if db_cursor:
            try:
                db_cursor.execute("SELECT rule_id, enabled FROM detection_rule_state")
                state_map = {row["rule_id"]: row["enabled"] for row in db_cursor.fetchall()}
                for rule in rules:
                    rid = rule.get("id")
                    if rid and rid in state_map:
                        rule["enabled"] = state_map[rid]
            except Exception as e:
                log.warning("Could not load rule state from DB: %s", e)

        self.rules = rules
        self._loaded = True
        log.info("Rule engine: %d total rules loaded", len(rules))
        return len(rules)

    def reload(self, db_cursor=None) -> int:
        """Hot-reload rules from disk + DB."""
        return self.load_rules(db_cursor)

    def get_rules(self) -> list[dict]:
        """Return all rules with their public fields."""
        return [
            {
                "id": r.get("id"),
                "name": r.get("name"),
                "type": r.get("type", "simple"),
                "severity": r.get("severity"),
                "confidence": r.get("confidence", 0.9),
                "description": r.get("description"),
                "enabled": r.get("enabled", True),
                "finding_source": r.get("finding_source"),
                "source": r.get("_source", "builtin"),
            }
            for r in self.rules
        ]

    def get_rule(self, rule_id: str) -> Optional[dict]:
        """Get a specific rule by ID."""
        for r in self.rules:
            if r.get("id") == rule_id:
                return r
        return None

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        """Set enabled state for a rule (in memory). Returns True if found."""
        for r in self.rules:
            if r.get("id") == rule_id:
                r["enabled"] = enabled
                return True
        return False

    def persist_enabled(self, cur, rule_id: str, enabled: bool):
        """Persist enabled/disabled state to DB."""
        source = "builtin"
        for r in self.rules:
            if r.get("id") == rule_id:
                source = r.get("_source", "builtin")
                break
        cur.execute("""
            INSERT INTO detection_rule_state (rule_id, enabled, source, updated_at)
            VALUES (%s, %s, %s, now())
            ON CONFLICT (rule_id) DO UPDATE SET enabled = %s, updated_at = now()
        """, (rule_id, enabled, source, enabled))

    # ──────────────────────────────────────────────────────
    # Rule execution
    # ──────────────────────────────────────────────────────

    def execute_rule(self, cur, rule: dict, since_minutes: int = 60,
                     dry_run: bool = False, limit: int = 0) -> list:
        """
        Execute a single rule against the database.
        Returns list of match dicts (title, target, severity, finding_source, finding_id, ...).
        If dry_run=True, does not check _already_flagged.
        """
        rule_type = rule.get("type", "simple")

        if rule_type in ("simple", "pattern"):
            return self._execute_simple(cur, rule, since_minutes, dry_run, limit)
        elif rule_type == "cross_source":
            return self._execute_cross_source(cur, rule, since_minutes, dry_run, limit)
        elif rule_type == "multi_pass":
            return self._execute_multi_pass(cur, rule, since_minutes, dry_run, limit)
        else:
            log.warning("Unknown rule type: %s for rule %s", rule_type, rule.get("id"))
            return []

    def _execute_simple(self, cur, rule, since_minutes, dry_run, limit) -> list:
        """Execute a simple or pattern rule."""
        query_spec = rule.get("query", {})
        if "table" not in query_spec:
            raise ValueError(f"Rule '{rule.get('id')}' query spec missing 'table' key")
        match_spec = rule.get("match")
        rule_id = rule["id"]
        finding_source = rule.get("finding_source", "recon")

        sql, params = _build_query(query_spec, since_minutes)
        cur.execute(sql, params)

        results = []
        seen_assets = set()  # Dedup by asset_id for per-host rules
        for row in cur.fetchall():
            row = dict(row)
            row["_db_cur"] = cur  # Inject cursor for Python match functions
            if match_spec and not _apply_match(row, match_spec, rule):
                continue
            row.pop("_db_cur", None)

            # Per-asset dedup: only one follow-up per host for rules like tcpwrapped
            if row.get("asset_id") and rule_id in ("tcpwrapped_security_control",):
                if row["asset_id"] in seen_assets:
                    continue
                seen_assets.add(row["asset_id"])

            fid = str(row.get("id", ""))
            if not dry_run and self._already_flagged(cur, rule_id, finding_source, fid):
                continue

            # Build result
            confidence = row.pop("_confidence_override", None) or rule.get("confidence", 0.9)
            reason_override = row.pop("_reason_override", None)

            # Special fields for exposed_bucket
            if rule_id == "exposed_bucket":
                data = row.get("data") if isinstance(row.get("data"), dict) else {}
                row["bucket"] = data.get("bucket", row.get("target", ""))

            # Special fields for weak_creds — domain fallback
            if rule_id == "weak_creds":
                row.setdefault("domain", "unknown")

            # Special fields for default_install — name fallback
            if rule_id == "default_install":
                row.setdefault("name", row.get("url", ""))

            # Special fields for tcpwrapped — get IP and port count (use fresh cursor to avoid iterator conflict)
            if rule_id == "tcpwrapped_security_control":
                asset_id = row.get("asset_id")
                port_count = "?"
                if asset_id:
                    try:
                        import psycopg2 as _pg2
                        _tc = _pg2.connect(os.environ.get("DATABASE_URL", "postgresql://app:app@rag-postgres:5432/scans"))
                        _tcur = _tc.cursor()
                        _tcur.execute("SELECT host(ip)::text, hostname FROM assets WHERE id = %s", (str(asset_id),))
                        _ar = _tcur.fetchone()
                        if _ar:
                            row["ip"] = _ar[0] or "unknown"
                            row["hostname"] = _ar[1] or ""
                        _tcur.execute("SELECT COUNT(*) FROM ports WHERE asset_id = %s AND is_open = true AND service = 'tcpwrapped'", (str(asset_id),))
                        port_count = _tcur.fetchone()[0]
                        _tcur.close(); _tc.close()
                    except Exception as _e:
                        logging.warning(f"tcpwrapped lookup failed: {_e}")
                row["port_count"] = port_count
                row.setdefault("ip", "unknown")

            title = _render_template(rule.get("title_template", "{id}"), row)
            target = row.get("target") or row.get("url") or row.get("ip") or "unknown"
            reason = reason_override or _render_template(
                rule.get("reason_template", rule.get("description", "")), row
            )

            # Build metadata with CVE/EDB reference links for software CVE rules
            metadata = None
            cve_list_str = row.get("cve_list", "")
            if cve_list_str and rule_id in ("software_known_cve",):
                refs = []
                cve_ids = [c.strip() for c in cve_list_str.split(",") if c.strip()]
                for cid in cve_ids[:10]:
                    if cid.startswith("CVE-"):
                        refs.append({"label": cid, "url": f"https://nvd.nist.gov/vuln/detail/{cid}", "type": "cve"})
                    elif cid.startswith("EDB-"):
                        refs.append({"label": cid, "url": f"https://www.exploit-db.com/exploits/{cid[4:]}", "type": "edb"})
                metadata = {
                    "product": row.get("product", ""),
                    "version": row.get("version", ""),
                    "cve_ids": cve_ids,
                    "refs": refs,
                    "software_link": f"/assets?tab=software&search={row.get('product', '')}",
                    "source": "rule_engine",
                }

            results.append({
                "rule_id": rule_id,
                "title": title,
                "target": target,
                "severity": rule.get("severity", "medium"),
                "reason": reason,
                "finding_source": finding_source,
                "finding_id": fid,
                "confidence": confidence,
                "tags": rule.get("tags"),
                "metadata": metadata,
            })
            if limit and len(results) >= limit:
                break

        return results

    def _execute_cross_source(self, cur, rule, since_minutes, dry_run, limit) -> list:
        """Execute a cross_source rule (join two tables in Python)."""
        sources = rule.get("sources", [])
        rule_id = rule["id"]
        finding_source = rule.get("finding_source", "web")

        if len(sources) < 2:
            log.warning("cross_source rule %s needs at least 2 sources", rule_id)
            return []

        queries = _build_cross_source_queries(sources, since_minutes)

        # Execute each source query and collect results
        source_data = {}
        for name, sql, params, spec in queries:
            cur.execute(sql, params)
            rows = [dict(r) for r in cur.fetchall()]

            # If extract_host_from is set, extract hostname
            extract_from = spec.get("extract_host_from")
            if extract_from:
                for row in rows:
                    row["host"] = _extract_host(str(row.get(extract_from, "")))

            source_data[name] = rows

        # Apply join
        join_spec = rule.get("join", {})
        left_ref = join_spec.get("left", "")   # e.g. "login_urls.host"
        right_ref = join_spec.get("right", "")  # e.g. "no_waf_hosts.target"

        left_src, left_field = left_ref.split(".", 1) if "." in left_ref else ("", "")
        right_src, right_field = right_ref.split(".", 1) if "." in right_ref else ("", "")

        left_rows = source_data.get(left_src, [])
        right_rows = source_data.get(right_src, [])

        # Build set of right values for efficient lookup
        right_values = {str(r.get(right_field, "")).lower() for r in right_rows}

        # Join: keep left rows where left_field is in right_values
        joined = [r for r in left_rows if str(r.get(left_field, "")).lower() in right_values]

        # Apply post_filter
        post_filter = rule.get("post_filter")
        results = []
        for row in joined:
            if post_filter and not _apply_match(row, post_filter, rule):
                continue

            fid = str(row.get("id", ""))
            if not dry_run and self._already_flagged(cur, rule_id, finding_source, fid):
                continue

            row.setdefault("host", row.get("target", ""))
            title = _render_template(rule.get("title_template", "{id}"), row)
            target = row.get("url") or row.get("target") or "unknown"
            reason = _render_template(
                rule.get("reason_template", rule.get("description", "")), row
            )

            results.append({
                "rule_id": rule_id,
                "title": title,
                "target": target,
                "severity": rule.get("severity", "high"),
                "reason": reason,
                "finding_source": finding_source,
                "finding_id": fid,
                "confidence": rule.get("confidence", 0.95),
                "tags": rule.get("tags"),
            })
            if limit and len(results) >= limit:
                break

        return results

    def _execute_multi_pass(self, cur, rule, since_minutes, dry_run, limit) -> list:
        """Execute a multi_pass rule — each pass is independent."""
        passes = rule.get("passes", [])
        rule_id = rule["id"]
        all_results = []

        for p in passes:
            finding_source = p.get("finding_source", rule.get("finding_source", "recon"))
            query_spec = p.get("query", {})
            match_spec = p.get("match")
            confidence = p.get("confidence", rule.get("confidence", 0.9))

            sql, params = _build_query(query_spec, since_minutes)
            cur.execute(sql, params)

            for row in cur.fetchall():
                row = dict(row)
                if match_spec and not _apply_match(row, match_spec, rule):
                    continue

                fid = str(row.get("id", ""))
                if not dry_run and self._already_flagged(cur, rule_id, finding_source, fid):
                    continue

                # For vulns pass — target_ip
                row.setdefault("target", row.get("target_ip") or "unknown")

                # For recon open_redirect — extract URL from data
                if "data" in row and isinstance(row["data"], dict):
                    row.setdefault("url", row["data"].get("url") or row["data"].get("input") or row.get("target", ""))

                override_confidence = row.pop("_confidence_override", None)
                reason_override = row.pop("_reason_override", None)

                title = _render_template(p.get("title_template", "{id}"), row)
                target = row.get("url") or row.get("target") or "unknown"
                reason = reason_override or _render_template(
                    p.get("reason_template", rule.get("description", "")), row
                )

                all_results.append({
                    "rule_id": rule_id,
                    "title": title,
                    "target": target,
                    "severity": rule.get("severity", "medium"),
                    "reason": reason,
                    "finding_source": finding_source,
                    "finding_id": fid,
                    "confidence": override_confidence or confidence,
                    "tags": p.get("tags") or rule.get("tags"),
                })
                if limit and len(all_results) >= limit:
                    return all_results

        return all_results

    def execute_all(self, cur, since_minutes: int = 60) -> list:
        """Execute all enabled rules. Returns list of all matches."""
        all_results = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            try:
                cur.execute("SAVEPOINT rule_exec")
                results = self.execute_rule(cur, rule, since_minutes)
                cur.execute("RELEASE SAVEPOINT rule_exec")
                all_results.extend(results)
            except Exception as e:
                log.warning("Rule '%s' failed: %s", rule.get("id"), e)
                try:
                    cur.execute("ROLLBACK TO SAVEPOINT rule_exec")
                except Exception:
                    pass
        return all_results

    def dry_run_rule(self, cur, rule_or_yaml, since_minutes: int = 60,
                     limit: int = 50) -> dict:
        """
        Dry-run a rule (by dict or YAML string) — returns matches without
        creating follow-ups or checking _already_flagged.
        """
        if isinstance(rule_or_yaml, str):
            rule = yaml.safe_load(rule_or_yaml)
            if isinstance(rule, list):
                rule = rule[0]
        else:
            rule = rule_or_yaml

        results = self.execute_rule(cur, rule, since_minutes, dry_run=True, limit=limit)
        return {
            "ok": True,
            "rule_id": rule.get("id", "unknown"),
            "matches": len(results),
            "results": results[:limit],
            "dry_run": True,
        }

    @staticmethod
    def _already_flagged(cur, rule_id: str, finding_source: str, finding_id: str) -> bool:
        """Check if this exact finding+rule combination already has a follow-up.

        Uses a SAVEPOINT so a failed UUID cast (non-UUID finding_id) doesn't
        poison the surrounding transaction.
        """
        try:
            cur.execute("SAVEPOINT already_flagged_check")
            cur.execute("""
                SELECT 1 FROM follow_up_items
                WHERE rule_id = %s AND finding_source = %s AND finding_id = %s::uuid
                LIMIT 1
            """, (rule_id, finding_source, finding_id))
            result = cur.fetchone() is not None
            cur.execute("RELEASE SAVEPOINT already_flagged_check")
            return result
        except Exception:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT already_flagged_check")
            except Exception:
                pass
            return False

    def delete_adhoc_rule(self, cur, rule_id: str) -> bool:
        """Delete an adhoc rule from DB and memory."""
        cur.execute("""
            DELETE FROM detection_rule_state
            WHERE rule_id = %s AND source = 'adhoc'
            RETURNING rule_id
        """, (rule_id,))
        deleted = cur.fetchone() is not None
        if deleted:
            self.rules = [r for r in self.rules if r.get("id") != rule_id]
        return deleted


# ──────────────────────────────────────────────────────────────
# Singleton instance
# ──────────────────────────────────────────────────────────────

_engine: Optional[RuleEngine] = None


def get_engine() -> RuleEngine:
    """Get or create the singleton RuleEngine instance."""
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine
