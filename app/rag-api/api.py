import os
import json
import base64
import uuid
import time
import logging
import xml.etree.ElementTree as ET

log = logging.getLogger("rag-api")
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Depends, Query, BackgroundTasks, Body
from fastapi.responses import Response
from pydantic import BaseModel, Field
import psycopg2
from psycopg2.extras import Json, RealDictCursor
from psycopg2.pool import ThreadedConnectionPool
from contextlib import contextmanager
import threading
from datetime import datetime, timezone
import ipaddress
import requests

logger = logging.getLogger("rag-api")

# Vault-backed secret accessor (falls back to env var when VAULT_ADDR unset)
from vault_client import get_secret as _get_secret  # noqa: E402

# Ensure all necessary imports are here
API_KEY = _get_secret("rag-api", "API_KEY", default="changeme") or "changeme"
DB_DSN = _get_secret("rag-api", "DB_DSN",
                     default="dbname=scans user=app password=app host=127.0.0.1 port=5432") \
    or "dbname=scans user=app password=app host=127.0.0.1 port=5432"
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "https://embedder:8030")
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Header, Query
from psycopg2.extras import Json, RealDictCursor
from datetime import datetime, timezone
import ipaddress
import requests


# ── DDG search helper (uses lite endpoint for reliability) ──
import re as _re_module
from urllib.parse import unquote as _unquote, parse_qs as _parse_qs, urlparse as _urlparse_fn


DDG_PROXY = os.environ.get("DDG_PROXY", "")  # e.g. socks5://node-manager:10125
_NVD_API_KEY_CACHE: dict = {"key": None, "ts": 0}


def _get_nvd_api_key() -> str:
    """Get NVD API key from app_settings (cached 5 min). Returns '' if not set."""
    import time
    now = time.time()
    if _NVD_API_KEY_CACHE["ts"] > now - 300 and _NVD_API_KEY_CACHE["key"] is not None:
        return _NVD_API_KEY_CACHE["key"]
    key = os.environ.get("NVD_API_KEY", "")
    if not key:
        try:
            with get_db() as conn, conn.cursor() as cur:
                cur.execute("SELECT value FROM app_settings WHERE key = 'nvd_api_key' AND category IN ('config', 'api_key')")
                row = cur.fetchone()
                if row:
                    key = row[0]
        except Exception:
            pass
    _NVD_API_KEY_CACHE["key"] = key
    _NVD_API_KEY_CACHE["ts"] = now
    return key


_SETTING_CACHE: dict = {}

# ── Default CVE analysis prompts (shared by runtime + GET /software/cve-prompt) ──
_DEFAULT_CVE_SYSTEM_PROMPT = (
    "You are a precise vulnerability analyst. Your job is to determine which CVEs apply to "
    "a SPECIFIC software version and assign an accurate probability score based on technical evidence.\n\n"
    "CRITICAL VERSION ANALYSIS RULES:\n"
    "1. VERSION RANGES: Parse these patterns carefully:\n"
    "   - 'affects versions before X.Y.Z' → versions < X.Y.Z are vulnerable\n"
    "   - 'fixed in X.Y.Z' → versions < X.Y.Z are vulnerable, X.Y.Z+ are safe\n"
    "   - 'affects X.Y.0 through X.Y.Z' → only that exact range is vulnerable\n"
    "   - 'versions X.Y.Z and earlier' → versions ≤ X.Y.Z are vulnerable\n\n"
    "2. MULTI-TRACK VERSIONING: Products like Atlassian (Confluence, Jira) have multiple parallel tracks:\n"
    "   - LTS tracks (e.g., 9.2.x) and feature tracks (e.g., 9.12.x) are SEPARATE\n"
    "   - A fix in '9.2.14' does NOT automatically protect 9.12.x versions\n"
    "   - Look for advisories listing MULTIPLE version ranges for different tracks\n"
    "   - Example: 'Fixed in 9.2.14 and 9.12.8' means 9.12.7 is still vulnerable\n\n"
    "3. PRODUCT VARIANTS: These refer to the SAME product:\n"
    "   - 'Confluence Data Center', 'Confluence Server', 'Confluence Data Center and Server'\n"
    "   - 'Jira Software', 'Jira Core', 'Jira Service Management' (for platform CVEs)\n\n"
    "4. EVIDENCE STANDARDS:\n"
    "   - applies=true: CVE explicitly names this version OR a range that includes it\n"
    "   - applies=false: CVE explicitly excludes this version OR affects different component\n"
    "   - applies='likely': Vendor bulletin mentions product but version range is unclear\n\n"
    "5. AGE CONTEXT: Consider the software release timeline:\n"
    "   - CVEs from BEFORE the software release may still apply if not properly addressed\n"
    "   - Focus on TECHNICAL EVIDENCE over age assumptions\n"
    "   - Recent CVEs (post-release) deserve higher scrutiny\n\n"
    "6. PROBABILITY GUIDELINES:\n"
    "   - 90-100: CVE explicitly names this version or confirmed vulnerable range\n"
    "   - 70-89: Strong technical evidence, clear version overlap\n"
    "   - 50-69: Probable based on vendor bulletin, unclear range boundaries\n"
    "   - 30-49: Possible but limited evidence, different but related component\n"
    "   - 10-29: Weak evidence, likely different version/component\n"
    "   - 0-9: No credible evidence of applicability\n\n"
    "ANALYSIS APPROACH: Focus on TECHNICAL VERSION MATCHING first, then consider context."
)

_DEFAULT_CVE_USER_PROMPT = (
    "ANALYZE: {product} version {version}\n\n"
    "For EACH CVE below, determine technical applicability to version {version}:\n\n"
    "{evidence}\n\n"
    "Return a JSON array with one entry per relevant CVE:\n"
    '[{{"cve_id":"CVE-...","title":"concise description","severity":"critical/high/medium/low",'
    '"applies":true/false/"likely","probability":0-100,"reason":"technical justification with version evidence"}}]\n\n'
    "ANALYSIS REQUIREMENTS:\n"
    "- applies: Base on TECHNICAL VERSION EVIDENCE:\n"
    "  * true = CVE explicitly affects {version} or confirmed vulnerable range\n"
    "  * false = CVE explicitly excludes {version} or different component\n"
    "  * \"likely\" = vendor advisory mentions product but version boundaries unclear\n\n"
    "- probability: Technical confidence (0-100):\n"
    "  * 90-100 = CVE advisory explicitly lists {version} as vulnerable\n"
    "  * 70-89 = Strong version range evidence (e.g., \"affects before X\" where {version} < X)\n"
    "  * 50-69 = Probable based on vendor bulletin, some version overlap\n"
    "  * 30-49 = Weak evidence, related component or unclear range\n"
    "  * 10-29 = Minimal evidence, likely different version track\n"
    "  * 0-9 = No credible technical evidence\n\n"
    "- reason: Must include specific version logic:\n"
    "  * Quote exact version ranges from advisories\n"
    "  * Explain multi-track versioning if relevant\n"
    "  * Note if evidence is from vendor bulletin vs. technical details\n\n"
    "FOCUS: Prioritize TECHNICAL VERSION MATCHING over age-based assumptions.\n"
    "INCLUDE: Only CVEs with meaningful probability (>10) for this specific version.\n"
    "OUTPUT: JSON array only, no explanatory text."
)

def _get_setting(key: str, default: str = "") -> str:
    """Get a config value from app_settings with 5-minute cache. Falls back to default."""
    import time as _st
    now = _st.time()
    cached = _SETTING_CACHE.get(key)
    if cached and cached["ts"] > now - 300:
        return cached["val"]
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("SELECT value FROM app_settings WHERE key = %s AND category = 'config'", (key,))
            row = cur.fetchone()
            if row and row[0]:
                _SETTING_CACHE[key] = {"val": row[0], "ts": now}
                return row[0]
    except Exception:
        pass
    _SETTING_CACHE[key] = {"val": default, "ts": now}
    return default


def ddg_search(query: str, max_results: int = 15, timeout: float = 10.0, proxy: str = None) -> list:
    """Search DuckDuckGo via lite endpoint. Returns list of {title, url, snippet}."""
    results = []
    proxy_url = proxy or DDG_PROXY
    proxies = {"https": proxy_url, "http": proxy_url} if proxy_url else None
    try:
        resp = requests.get("https://lite.duckduckgo.com/lite/",
            params={"q": query},
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=timeout, verify=False, proxies=proxies)
        if resp.status_code != 200:
            return results

        # Extract result links (DDG lite format: //duckduckgo.com/l/?uddg=ENCODED_URL)
        raw_links = _re_module.findall(r'href="(//duckduckgo\.com/l/\?uddg=[^"]+)"', resp.text)
        # Extract titles: text between <a> tags with result-link class or nofollow
        title_matches = _re_module.findall(
            r'<a[^>]*rel="nofollow"[^>]*>(.*?)</a>', resp.text, _re_module.DOTALL)
        # Extract snippets: <td> with class="result-snippet"
        snippet_matches = _re_module.findall(
            r'class="result-snippet"[^>]*>(.*?)</td>', resp.text, _re_module.DOTALL)

        seen = set()
        for i, raw_url in enumerate(raw_links[:max_results]):
            url = "https:" + raw_url
            actual_url = _unquote(_parse_qs(_urlparse_fn(url).query).get("uddg", [url])[0])
            if actual_url in seen:
                continue
            seen.add(actual_url)
            title = _re_module.sub(r'<[^>]+>', '', title_matches[i]).strip() if i < len(title_matches) else ""
            snippet = _re_module.sub(r'<[^>]+>', '', snippet_matches[i]).strip()[:300] if i < len(snippet_matches) else ""
            results.append({"title": title, "url": actual_url, "snippet": snippet})
    except Exception:
        pass
    return results


# ── LLM call helper with automatic metrics logging ──
OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
LLM_MODEL = os.environ.get("LLM_MODEL", "gemma4:31b")


def llm_generate(prompt: str, caller: str, model: str = None, think: bool = False,
                 temperature: float = 0.1, num_predict: int = 1024, timeout: int = 120) -> dict:
    """Call Ollama LLM and log metrics to llm_request_metrics table.

    Returns dict with: response, eval_count, tokens_per_sec, latency_ms, ok, error
    """
    import time as _t
    model = model or LLM_MODEL
    result = {"response": "", "eval_count": 0, "tokens_per_sec": 0, "latency_ms": 0, "ok": False, "error": None}

    t0 = _t.time()
    try:
        resp = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "think": think,
                  "options": {"temperature": temperature, "num_predict": num_predict}},
            timeout=timeout, verify=False,
        )
        latency_ms = round((_t.time() - t0) * 1000, 1)
        result["latency_ms"] = latency_ms

        if resp.status_code == 200:
            data = resp.json()
            result["response"] = data.get("response", "")
            result["eval_count"] = data.get("eval_count", 0)
            eval_dur = data.get("eval_duration", 0)
            result["tokens_per_sec"] = round(result["eval_count"] / (eval_dur / 1e9), 1) if eval_dur else 0
            result["prompt_tokens"] = data.get("prompt_eval_count", 0)
            result["ok"] = True
            logger.info("[llm:%s] %s: %d tokens, %.1f tok/s, %dms",
                        caller, model, result["eval_count"], result["tokens_per_sec"], latency_ms)
        else:
            result["error"] = f"HTTP {resp.status_code}"
            logger.warning("[llm:%s] HTTP %s from Ollama", caller, resp.status_code)
    except Exception as e:
        latency_ms = round((_t.time() - t0) * 1000, 1)
        result["latency_ms"] = latency_ms
        result["error"] = f"{type(e).__name__}: {e}"
        logger.warning("[llm:%s] error: %s", caller, result["error"])

    # Log to database (fire-and-forget)
    try:
        with get_db(autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("""INSERT INTO llm_request_metrics
                (caller, model_name, prompt_tokens, completion_tokens, total_tokens, tokens_per_sec,
                 latency_ms, is_error, error_message, request_params)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (caller, model, result.get("prompt_tokens", 0), result["eval_count"],
                 result.get("prompt_tokens", 0) + result["eval_count"], result["tokens_per_sec"],
                 result["latency_ms"], not result["ok"], result.get("error"),
                 Json({"temperature": temperature, "num_predict": num_predict, "prompt_len": len(prompt),
                       "prompt": prompt[:8000], "response": result["response"][:8000]})))
    except Exception:
        pass

    return result


def _embed_texts(texts: list[str]) -> list[list[float]]:
    """Call the embedder microservice to get vectors."""
    resp = requests.post(f"{EMBEDDER_URL}/embed", json={"texts": texts}, verify=False, timeout=30)
    resp.raise_for_status()
    return resp.json()["embeddings"]


def _embed_text(text: str) -> list[float]:
    """Convenience wrapper for a single text."""
    return _embed_texts([text])[0]

# Import health check router
from health_router import router as health_router

# Import metrics router
from metrics_router import router as metrics_router

# Import webhook router and dispatcher
from webhooks import webhook_router, start_retry_worker, stop_retry_worker, ensure_default_webhook

app = FastAPI(title="Pentest RAG API", version="1.0.0")


# ── Engagement context (cross-engagement isolation, Option B / Phase 4) ──
# Frontend sends the active engagement as the `X-Engagement-Id` request
# header on every API call.  An HTTP middleware captures it into a
# contextvar so scan-launch / INSERT sites deep in the call stack can read
# it without threading the value through every function signature.
#
# Endpoints/INSERT sites should prefer an explicit `engagement_id`
# parameter where present, and fall back to `current_engagement_id.get()`
# otherwise — see `_resolve_engagement_id()` below.
import contextvars

current_engagement_id: contextvars.ContextVar = contextvars.ContextVar(
    "current_engagement_id", default=None,
)


@app.middleware("http")
async def _capture_engagement_header(request, call_next):
    """Bind X-Engagement-Id from the request to the current contextvar so
    any code in this request's call stack can read the active engagement.
    Resets on response so it doesn't leak between requests."""
    eid = request.headers.get("x-engagement-id") or request.headers.get("X-Engagement-Id")
    token = current_engagement_id.set(eid or None)
    try:
        return await call_next(request)
    finally:
        current_engagement_id.reset(token)


def _resolve_engagement_id(explicit: Optional[str] = None) -> Optional[str]:
    """Return the engagement_id to attach to a scan-launch / job INSERT.
    Prefers an explicitly-passed value (from query param or request body),
    falling back to the contextvar captured from the `X-Engagement-Id`
    header.  Returns None when no engagement is active (legacy / unscoped)."""
    if explicit:
        return explicit
    try:
        return current_engagement_id.get()
    except LookupError:
        return None


def _validate_engagement_uuid(eid: Optional[str]) -> Optional[str]:
    """Validate that a resolved engagement_id is a well-formed UUID before it
    reaches the SQL layer (the column is ``uuid``). Returns the value unchanged
    (or None for the unscoped/legacy case). Raises HTTP 422 on a malformed value
    so a bad query param / ``X-Engagement-Id`` header yields a clean client error
    instead of a psycopg2 InvalidTextRepresentation 500."""
    if eid is None:
        return None
    try:
        uuid.UUID(str(eid))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(422, f"engagement_id must be a valid UUID, got: {eid!r}")
    return eid


def _outgoing_runner_headers(
    extra: Optional[Dict[str, str]] = None,
    engagement_id: Optional[str] = None,
) -> Dict[str, str]:
    """Build the headers dict for a rag-api → scanner_runner / scan_recommender
    outgoing HTTP call.

    Always includes ``x-api-key`` for inter-service auth.  Forwards
    ``X-Engagement-Id`` from either the explicit ``engagement_id`` arg or the
    request-scoped contextvar -- without this, the runner-side middleware
    (added in Option B / Phase 5) sees no engagement header and the audit.jsonl
    lines it writes come out with ``engagement_id: null``.

    Pass ``extra`` for additional headers (e.g. ``Content-Type``).  Pass
    ``engagement_id`` explicitly when calling from a context where the
    contextvar may not be set reliably (e.g. some background-task chains).
    """
    headers: Dict[str, str] = {"x-api-key": API_KEY}
    eid = _resolve_engagement_id(engagement_id)
    if eid:
        headers["X-Engagement-Id"] = eid
    if extra:
        headers.update(extra)
    return headers


# ── Rate limiting (per-IP) ──────────────────────────────────────
# Default: 120 req/min global, configurable via RATE_LIMIT env (e.g. "60/minute").
# Endpoints exempted: /health, /metrics. Set RATE_LIMIT="" to disable.
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    _RATE_LIMIT = os.environ.get("RATE_LIMIT", "120/minute")
    if _RATE_LIMIT:
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=[_RATE_LIMIT],
            headers_enabled=True,
        )
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.add_middleware(SlowAPIMiddleware)
        logger.info("Rate limiter enabled: %s per IP", _RATE_LIMIT)
except ImportError:
    logger.warning("slowapi not installed — rate limiting disabled")

# Include health check router (provides /health/* endpoints)
app.include_router(health_router)

# Include metrics router (provides /metrics/* endpoints)
app.include_router(metrics_router)

# Include webhook router (provides /webhooks/* endpoints)
app.include_router(webhook_router)

# Keep legacy /health endpoint for backward compatibility
@app.get("/health")
def health():
    """
    Legacy health check endpoint with enhanced details.

    Returns:
    - ok: Boolean indicating if service is operational
    - service: Service name
    - database: Database connection status and table count
    - dependencies: Status of critical dependencies (Ollama, scan-recommender)
    - timestamp: ISO 8601 timestamp

    Maintains backward compatibility - always returns {"ok": true/false} at minimum.
    """
    import requests
    from datetime import datetime, timezone

    response = {
        "ok": True,
        "service": "rag-api",
        "version": os.environ.get("BUILD_VERSION", "dev"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Check database
    try:
        with get_db() as conn, conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")
            table_count = cursor.fetchone()[0]

        response["database"] = {
            "connected": True,
            "tables_found": table_count,
            "tables_expected": 34
        }
    except Exception as e:
        response["ok"] = False
        response["database"] = {
            "connected": False,
            "error": str(e)
        }

    # Check critical dependencies
    dependencies = {}

    # Check Ollama
    try:
        ollama_resp = requests.get("http://ollama:11434/api/tags", verify=False, timeout=3)
        if ollama_resp.status_code == 200:
            models = ollama_resp.json().get("models", [])
            dependencies["ollama"] = {
                "healthy": True,
                "models": len(models)
            }
        else:
            dependencies["ollama"] = {"healthy": False}
    except Exception:
        dependencies["ollama"] = {"healthy": False}
        response["ok"] = False

    # Check scan-recommender
    try:
        scan_rec_resp = requests.get("https://scan-recommender:8013/health", verify=False, timeout=3)
        dependencies["scan_recommender"] = {
            "healthy": scan_rec_resp.status_code == 200
        }
    except Exception:
        dependencies["scan_recommender"] = {"healthy": False}

    response["dependencies"] = dependencies

    # Check ExploitDB / searchsploit data
    try:
        from rule_engine import _load_exploitdb, _EXPLOITDB_INDEX
        _load_exploitdb()
        response["exploitdb"] = {
            "loaded": len(_EXPLOITDB_INDEX) > 0,
            "count": len(_EXPLOITDB_INDEX),
        }
    except Exception:
        response["exploitdb"] = {"loaded": False, "count": 0}

    return response

api_router = APIRouter()

@app.get("/scans/{job_id}", tags=["Scans"])
async def get_scan_results(job_id: str, x_api_key: str = Header(...), db_dsn=DB_DSN):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid X-API-Key")

    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM scan_results WHERE job_id = %s", (job_id,))
            results = cursor.fetchall()
        return {"job_id": job_id, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

app.include_router(api_router)

# --- moved auth() above routes to avoid NameError in Depends ---
def auth(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid X-API-Key")
    return True

# --- OpenAPI: add ApiKeyAuth and preauthorize Swagger UI with default key ---
from fastapi.openapi.utils import get_openapi
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version="1.0.0",
        routes=app.routes,
        description="Pentest RAG API",
    )
    comps = openapi_schema.setdefault("components", {})
    security_schemes = comps.setdefault("securitySchemes", {})
    security_schemes["ApiKeyAuth"] = {
        "type": "apiKey",
        "in": "header",
        "name": "x-api-key",
        "description": "API key for authenticated endpoints",
    }
    # Apply globally so all operations require the x-api-key unless explicitly overridden
    openapi_schema["security"] = [{"ApiKeyAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi  # type: ignore[assignment]

@app.get("/docs", include_in_schema=False)
def custom_swagger_ui_html() -> HTMLResponse:
    # Render default Swagger UI
    html = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Docs",
        swagger_ui_parameters={"persistAuthorization": True},
    )
    # Append a small script to pre-authorize x-api-key with the configured API key
    # Note: Only for development. In production, users should manually enter their API key.
    body = html.body.decode("utf-8")

    # Only pre-auth in development mode (when using default key)
    if API_KEY != "changeme":
        # Production mode - don't pre-authorize for security
        pass
    else:
        # Development mode - pre-authorize for convenience
        body += f"""
<script>
window.addEventListener('load', function() {{
  function preauth() {{
    if (window.ui && window.ui.preauthorizeApiKey) {{
      try {{ window.ui.preauthorizeApiKey('ApiKeyAuth', '{API_KEY}'); }} catch(e) {{}}
    }} else {{
      setTimeout(preauth, 100);
    }}
  }}
  preauth();
}});
</script>
"""
    return HTMLResponse(content=body, status_code=html.status_code, headers=html.headers)

# --- end OpenAPI customization ---

# ── DB connection pool ─────────────────────────────────────────────
# Replaces per-request psycopg2.connect() calls. Pool created lazily
# so that import-time DB outages don't crash the API.
_DB_POOL: Optional[ThreadedConnectionPool] = None
_DB_POOL_LOCK = threading.Lock()
_DB_POOL_MIN = int(os.environ.get("DB_POOL_MIN", "2"))
_DB_POOL_MAX = int(os.environ.get("DB_POOL_MAX", "40"))  # bumped from 20 — bulk check can use many slots


def _get_pool() -> ThreadedConnectionPool:
    global _DB_POOL
    if _DB_POOL is None:
        with _DB_POOL_LOCK:
            if _DB_POOL is None:
                # idle_in_transaction_session_timeout (2 min) prevents connections
                # that forget to commit/rollback from holding locks indefinitely.
                _DB_POOL = ThreadedConnectionPool(
                    _DB_POOL_MIN, _DB_POOL_MAX, dsn=DB_DSN,
                    options="-c idle_in_transaction_session_timeout=120000",
                )
                logger.info("DB pool initialized: min=%d max=%d", _DB_POOL_MIN, _DB_POOL_MAX)
    return _DB_POOL


def _conn_is_alive(conn) -> bool:
    """Cheap pre-use health check. Returns False if the connection is closed
    or a trivial SELECT 1 fails (stale conn after Postgres restart / idle drop).
    """
    try:
        if conn.closed:
            return False
        # psycopg2 exposes broken-connection hint via conn.info on psycopg2 >= 2.8
        with conn.cursor() as _cur:
            _cur.execute("SELECT 1")
            _cur.fetchone()
        # Caller expects a clean transaction boundary
        try:
            conn.rollback()
        except Exception:
            pass
        return True
    except Exception:
        return False


def _discard_conn(pool, conn):
    """Remove a broken conn from the pool without returning it for reuse."""
    try:
        pool.putconn(conn, close=True)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


@contextmanager
def get_db(autocommit: bool = False):
    """Yield a pooled psycopg2 connection.

    Commits on clean exit (unless autocommit=True), rolls back on exception,
    and always returns the connection to the pool. Use as:
        with get_db() as conn, conn.cursor() as cur: ...
        with get_db(autocommit=True) as conn: ...

    Robustness: validates the pooled conn with `SELECT 1` before yielding.
    If the idle conn was dropped by Postgres (network blip, server restart,
    idle_in_transaction_session_timeout), we discard and fetch a fresh one
    once, so callers don't see sporadic OperationalError on the first query.
    """
    pool = _get_pool()
    conn = pool.getconn()
    # Validate; replace once if stale. Avoid infinite retry loops on a dead DB.
    if not _conn_is_alive(conn):
        logger.info("DB pool: discarded stale connection, fetching fresh one")
        _discard_conn(pool, conn)
        conn = pool.getconn()
        # If the fresh conn is also bad, let the caller see the failure.
    try:
        conn.autocommit = bool(autocommit)
        try:
            yield conn
            if not autocommit:
                conn.commit()
        except Exception:
            if not autocommit:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise
    finally:
        try:
            conn.autocommit = False
        except Exception:
            pass
        # If the connection broke mid-request (server-side disconnect), don't
        # recycle it — close it so the pool allocates a fresh one next time.
        if conn.closed:
            _discard_conn(pool, conn)
            return
        try:
            pool.putconn(conn)
        except Exception:
            # If putconn fails (e.g., closed conn), close hard
            try:
                conn.close()
            except Exception:
                pass

def ensure_phase0_schema():
    # Create jobs/tasks tables if they're missing so Phase 0 endpoints work without manual migration
    ddl = [
        "CREATE EXTENSION IF NOT EXISTS pgcrypto",
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            type             text NOT NULL CHECK (type IN ('masscan-nmap')),
            status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','finished','failed','canceled')),
            params           jsonb NOT NULL DEFAULT '{}'::jsonb,
            total_tasks      integer NOT NULL DEFAULT 0,
            finished_tasks   integer NOT NULL DEFAULT 0,
            error            text,
            idempotency_key  text UNIQUE,
            created_at       timestamptz NOT NULL DEFAULT now(),
            started_at       timestamptz,
            finished_at      timestamptz
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)",
        "CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC)",
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id       uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            type         text NOT NULL CHECK (type IN ('pipeline','masscan','nmap','followup')),
            target_host  inet,
            target_port  integer,
            proto        text,
            status       text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','finished','failed','canceled')),
            attempt      integer NOT NULL DEFAULT 0,
            last_error   text,
            created_at   timestamptz NOT NULL DEFAULT now(),
            started_at   timestamptz,
            finished_at  timestamptz
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_tasks_job_target
        ON tasks (job_id, type, target_host, target_port, COALESCE(proto,''))
        """,
        "CREATE INDEX IF NOT EXISTS idx_tasks_job ON tasks(job_id)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_job_status ON tasks(job_id, status)",
        """
        CREATE TABLE IF NOT EXISTS assets (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            ip           inet NOT NULL,
            os           text,  -- Ensure this column is present
            created_at   timestamptz NOT NULL DEFAULT now(),
            updated_at   timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ports (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            asset_id     uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            proto        text NOT NULL CHECK (proto IN ('tcp', 'udp')),
            port         integer NOT NULL,
            is_open      boolean NOT NULL DEFAULT true,
            service      text,
            product      text,
            version      text,
            banner       text,
            created_at   timestamptz NOT NULL DEFAULT now(),
            updated_at   timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_ports_asset_id ON ports(asset_id)",
        # session_scan_metrics table for pipeline performance metrics
        """
        CREATE TABLE IF NOT EXISTS session_scan_metrics (
            id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id        uuid NOT NULL,
            scan_type         text NOT NULL,
            scan_phase        text,
            job_id            text,
            status            text NOT NULL DEFAULT 'running',
            started_at        timestamptz,
            completed_at      timestamptz,
            duration_seconds  numeric,
            params            jsonb DEFAULT '{}'::jsonb,
            result_summary    jsonb DEFAULT '{}'::jsonb,
            created_at        timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_session_id ON session_scan_metrics(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_scan_type ON session_scan_metrics(scan_type)",
        "CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_created_at ON session_scan_metrics(created_at DESC)",
        # llm_request_metrics table for per-LLM-call instrumentation
        """
        CREATE TABLE IF NOT EXISTS llm_request_metrics (
            id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id          uuid NOT NULL,
            agent_name          text,
            model_name          text NOT NULL,
            prompt_tokens       integer,
            completion_tokens   integer,
            total_tokens        integer,
            latency_ms          numeric NOT NULL,
            has_tool_calls      boolean NOT NULL DEFAULT false,
            tool_call_count     integer DEFAULT 0,
            tool_names          text[],
            is_error            boolean NOT NULL DEFAULT false,
            error_message       text,
            request_params      jsonb DEFAULT '{}'::jsonb,
            created_at          timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_session_id ON llm_request_metrics(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_model_name ON llm_request_metrics(model_name)",
        "CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_agent_name ON llm_request_metrics(agent_name)",
        "CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_created_at ON llm_request_metrics(created_at DESC)",
        # recon_findings table for OSINT data (subfinder, dnsx, tlsx, asnmap, uncover, cloudlist)
        """
        CREATE TABLE IF NOT EXISTS recon_findings (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            asset_id      uuid REFERENCES assets(id) ON DELETE SET NULL,
            source        text NOT NULL,
            finding_type  text NOT NULL,
            target        text NOT NULL,
            data          jsonb NOT NULL,
            severity      text CHECK (severity IN ('info','low','medium','high','critical')),
            created_at    timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_recon_findings_source ON recon_findings(source)",
        "CREATE INDEX IF NOT EXISTS idx_recon_findings_finding_type ON recon_findings(finding_type)",
        "CREATE INDEX IF NOT EXISTS idx_recon_findings_target ON recon_findings(target)",
        "CREATE INDEX IF NOT EXISTS idx_recon_findings_asset_id ON recon_findings(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_recon_findings_created_at ON recon_findings(created_at DESC)",
        # scope_targets table for grouping recon findings into named scopes
        """
        CREATE TABLE IF NOT EXISTS scope_targets (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            name        text NOT NULL DEFAULT 'default',
            target      text NOT NULL,
            target_type text CHECK (target_type IN ('domain','ip','cidr','asn','url')),
            source      text,
            added_at    timestamptz NOT NULL DEFAULT now(),
            UNIQUE(name, target)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_scope_targets_name ON scope_targets(name)",
    ]
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            for stmt in ddl:
                try:
                    cur.execute(stmt)
                except Exception as e:
                    print(f"Error executing DDL: {e}")
            # Create pipeline_performance view (safe to CREATE OR REPLACE)
            try:
                cur.execute("""
                CREATE OR REPLACE VIEW pipeline_performance AS
                SELECT 'jobs' AS metric_source, j.id::text AS entity_id,
                       NULL::uuid AS session_id, j.type AS scan_type, j.status,
                       j.started_at, j.finished_at AS finished_at,
                       EXTRACT(EPOCH FROM (j.finished_at - j.started_at)) AS duration_seconds
                FROM jobs j WHERE j.started_at IS NOT NULL
                UNION ALL
                SELECT 'tasks', t.id::text, NULL::uuid, t.type, t.status,
                       t.started_at, t.finished_at,
                       EXTRACT(EPOCH FROM (t.finished_at - t.started_at))
                FROM tasks t WHERE t.started_at IS NOT NULL
                UNION ALL
                SELECT 'session_scan_metrics', ssm.id::text, ssm.session_id,
                       ssm.scan_type, ssm.status, ssm.started_at,
                       ssm.completed_at, ssm.duration_seconds
                FROM session_scan_metrics ssm
                """)
            except Exception as e:
                print(f"Error creating pipeline_performance view: {e}")
            conn.commit()
    except Exception as e:
        print(f"Error in ensure_phase0_schema: {e}")

@app.post("/run_masscan_nmap")
def run_masscan_nmap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Text file with newline/comma separated IPs/CIDRs; supports # comments"),
    ports: str = Query("1-65535", description="Ports range/list for Masscan"),
    rate: int = Query(1000, ge=1, description="Masscan rate (pps)"),
    interface: Optional[str] = Query(None, description="Network interface for Masscan (-e)"),
    whitelist: Optional[List[str]] = Query(None, description="Optional CIDRs to include; others excluded"),
    blacklist: Optional[List[str]] = Query(None, description="Optional CIDRs to exclude"),
    idempotency_key: Optional[str] = Query(None),
    authorized: bool = Depends(auth),
):
    # Read and parse targets file
    tmp_path = _save_upload_to_tmp(file)
    try:
        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    finally:
        os.remove(tmp_path)

    targets = _parse_targets_text(content, whitelist=whitelist, blacklist=blacklist)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets after applying filters")

    # Create job and queued pipeline task
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if idempotency_key:
            cur.execute("SELECT id, status FROM jobs WHERE idempotency_key=%s AND type=%s", (idempotency_key, "masscan-nmap"))
            row = cur.fetchone()
            if row:
                return {"id": str(row["id"]), "status": row["status"], "dedup": True}

        params = {
            "ports": ports,
            "rate": rate,
            "interface": interface,
            "targets_count": len(targets),
            "whitelist": whitelist or [],
            "blacklist": blacklist or [],
        }
        eid = _resolve_engagement_id()
        cur.execute(
            "INSERT INTO jobs (type, params, idempotency_key, status, engagement_id) "
            "VALUES (%s,%s,%s,'queued',%s::uuid) RETURNING id",
            ("masscan-nmap", Json(params), idempotency_key, eid),
        )
        job_id = str(cur.fetchone()["id"])
        cur.execute("INSERT INTO tasks (job_id, type, status) VALUES (%s::uuid,'pipeline','queued')", (job_id,))
        cur.execute("UPDATE jobs SET total_tasks = GREATEST(total_tasks, 1) WHERE id=%s::uuid", (job_id,))
        conn.commit()

    # Schedule background execution and return immediately
    background_tasks.add_task(_background_run_masscan_nmap, job_id, targets, ports, rate, interface)
    return {"id": job_id, "status": "queued"}

@app.post("/jobs/masscan-nmap/upload")
def masscan_nmap_upload(
    file: UploadFile = File(..., description="Text file with newline/comma separated IPs/CIDRs; supports # comments"),
    ports: str = Query("1-65535", description="Ports range/list for Masscan"),
    rate: int = Query(1000, ge=1, description="Masscan rate (pps)"),
    interface: Optional[str] = Query(None, description="Network interface for Masscan (-e)"),
    whitelist: Optional[List[str]] = Query(None, description="Optional CIDRs to include; others excluded"),
    blacklist: Optional[List[str]] = Query(None, description="Optional CIDRs to exclude"),
    idempotency_key: Optional[str] = Query(None),
    authorized: bool = Depends(auth),
):
    # Read and parse targets file
    tmp_path = _save_upload_to_tmp(file)
    try:
        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    finally:
        os.remove(tmp_path)

    targets = _parse_targets_text(content, whitelist=whitelist, blacklist=blacklist)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets after applying filters")

    # Create job and running pipeline task
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if idempotency_key:
            cur.execute("SELECT id, status FROM jobs WHERE idempotency_key=%s AND type=%s", (idempotency_key, "masscan-nmap"))
            row = cur.fetchone()
            if row:
                return {"id": str(row["id"]), "status": row["status"], "dedup": True}

        params = {
            "ports": ports,
            "rate": rate,
            "interface": interface,
            "targets_count": len(targets),
            "whitelist": whitelist or [],
            "blacklist": blacklist or [],
        }
        eid = _resolve_engagement_id()
        cur.execute(
            "INSERT INTO jobs (type, params, idempotency_key, status, started_at, engagement_id) "
            "VALUES (%s,%s,%s,'running',now(),%s::uuid) RETURNING id",
            ("masscan-nmap", Json(params), idempotency_key, eid),
        )
        job_id = str(cur.fetchone()["id"])
        cur.execute("INSERT INTO tasks (job_id, type, status, started_at) VALUES (%s::uuid,'pipeline','running',now())", (job_id,))
        cur.execute("UPDATE jobs SET total_tasks = GREATEST(total_tasks, 1) WHERE id=%s::uuid", (job_id,))
        conn.commit()

    # Kick off scanner Masscan -> ingest -> Nmap
    base = os.environ.get("NMAP_SCANNER_URL", "https://nmap_scanner:8012")
    since_ts = datetime.now(timezone.utc)
    try:
        payload: Dict[str, Any] = {"targets": targets, "ports": ports, "rate": rate}
        if interface:
            payload["interface"] = interface
        # Synchronous handler: the request's contextvar is reliably set, so
        # _outgoing_runner_headers() picks engagement_id up automatically.
        r = requests.post(
            f"{base}/jobs/masscan-then-nmap",
            json=payload,
            headers=_outgoing_runner_headers(),
            verify=False, timeout=3600,
        )
        r.raise_for_status()
        resp = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"ok": True}
        ok = bool(resp.get("ok", True))
    except requests.RequestException as e:
        err = f"scanner unavailable: {e}"
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("UPDATE tasks SET status='failed', finished_at=now(), last_error=%s WHERE job_id=%s::uuid AND type='pipeline' AND status='running'", (err, job_id))
            cur.execute("UPDATE jobs SET status='failed', finished_at=now(), error=%s WHERE id=%s::uuid", (err, job_id))
            conn.commit()
        raise HTTPException(status_code=502, detail=err)

    # Enqueue deduplicated Nmap tasks from the newly observed ports
    created_tasks = 0
    try:
        created_tasks = _create_nmap_tasks_from_recent(job_id, since_ts)
    except Exception:
        pass

    # Finalize pipeline task and job status
    with get_db() as conn, conn.cursor() as cur:
        if ok:
            cur.execute("UPDATE tasks SET status='finished', finished_at=now() WHERE job_id=%s::uuid AND type='pipeline' AND status='running'", (job_id,))
            cur.execute("UPDATE jobs SET finished_tasks = LEAST(total_tasks, finished_tasks + 1), status='finished', finished_at=now(), error=NULL WHERE id=%s::uuid", (job_id,))
        else:
            err = resp.get("error", "unknown error")
            cur.execute("UPDATE tasks SET status='failed', finished_at=now(), last_error=%s WHERE job_id=%s::uuid AND type='pipeline' AND status='running'", (err, job_id))
            cur.execute("UPDATE jobs SET status='failed', finished_at=now(), error=%s WHERE id=%s::uuid", (err, job_id))
        conn.commit()

    return {"id": job_id, "ok": ok, "targets": len(targets), "nmap_tasks_enqueued": created_tasks, "scanner": resp}

@app.post("/jobs/nmap-from-masscan")
def nmap_from_masscan(authorized: bool = Depends(auth), job_id: Optional[str] = Query(None)):
    # Delegate to the external nmap_scanner service and optionally manage job lifecycle
    base = os.environ.get("NMAP_SCANNER_URL", "https://nmap_scanner:8012")
    task_id = None
    if job_id:
        try:
            with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                # transition job -> running
                cur.execute("UPDATE jobs SET status='running', started_at=COALESCE(started_at, now()) WHERE id=%s::uuid", (job_id,))
                # create a pipeline task marked running
                cur.execute("INSERT INTO tasks (job_id, type, status, started_at) VALUES (%s::uuid,'pipeline','running',now()) RETURNING id", (job_id,))
                task_id = str(cur.fetchone()["id"])
                # ensure total_tasks reflects at least one
                cur.execute("UPDATE jobs SET total_tasks = GREATEST(total_tasks, 1) WHERE id=%s::uuid", (job_id,))
                conn.commit()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"failed to init job lifecycle: {type(e).__name__}: {e}")
    try:
        # Resolve engagement_id from the jobs row to forward to the runner.
        _eid = None
        try:
            with get_db() as conn, conn.cursor() as cur:
                cur.execute("SELECT engagement_id FROM jobs WHERE id=%s::uuid", (job_id,))
                row = cur.fetchone()
                if row and row[0]:
                    _eid = str(row[0])
        except Exception:
            pass
        r = requests.post(
            f"{base}/jobs/nmap-from-masscan",
            headers=_outgoing_runner_headers(engagement_id=_eid),
            verify=False, timeout=600,
        )
        r.raise_for_status()
        payload = r.json() if r.headers.get("content-type","").startswith("application/json") else {"ok": True}
        ok = bool(payload.get("ok", True))
        if job_id:
            with get_db() as conn, conn.cursor() as cur:
                if ok:
                    cur.execute("UPDATE tasks SET status='finished', finished_at=now() WHERE id=%s::uuid", (task_id,))
                    cur.execute("UPDATE jobs SET finished_tasks = LEAST(total_tasks, finished_tasks + 1), status='finished', finished_at=now(), error=NULL WHERE id=%s::uuid", (job_id,))
                else:
                    cur.execute("UPDATE tasks SET status='failed', finished_at=now(), last_error=%s WHERE id=%s::uuid", (payload.get("error","unknown error"), task_id))
                    cur.execute("UPDATE jobs SET status='failed', finished_at=now(), error=%s WHERE id=%s::uuid", (payload.get("error","unknown error"), job_id))
                conn.commit()
        return payload
    except requests.RequestException as e:
        if job_id:
            with get_db() as conn, conn.cursor() as cur:
                err = f"scanner unavailable: {e}"
                if task_id:
                    cur.execute("UPDATE tasks SET status='failed', finished_at=now(), last_error=%s WHERE id=%s::uuid", (err, task_id))
                cur.execute("UPDATE jobs SET status='failed', finished_at=now(), error=%s WHERE id=%s::uuid", (err, job_id))
                conn.commit()
        raise HTTPException(status_code=502, detail=f"nmap_scanner unavailable: {e}")

@app.get("/assets")
def get_assets(
    search: Optional[str] = Query(None, description="Substring match on hostname or IP (case-insensitive)"),
    provider: Optional[str] = Query(None, description="Filter by cloud-hosting provider tag(s). Comma-separated for OR-match: 'aws', 'aws,azure'. Backed by the GIN index on assets.provider."),
    asset_kind: Optional[str] = Query(None, description="Filter by asset type: 'hosts-only' (exclude cloud imports), 'cloud-only' (cloud imports only), or null for all"),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0, description="Pagination offset for retrieving > limit rows"),
    authorized: bool = Depends(auth),
):
    # Return discovered assets, enriching hostname from credential metadata if missing
    where_clauses = []
    where_params: list = []
    if search:
        where_clauses.append("(a.hostname ILIKE %s OR host(a.ip)::text ILIKE %s)")
        where_params.extend([f"%{search}%", f"%{search}%"])
    if provider:
        # OR-overlap match — '&&' uses the GIN index on assets.provider.
        provider_list = [p.strip().lower() for p in provider.split(",") if p.strip()]
        if provider_list:
            where_clauses.append("a.provider && %s::text[]")
            where_params.append(provider_list)

    if asset_kind:
        # Filter by asset type (cloud imports vs network hosts)
        # Handle null tags properly - need to check if tags IS NOT NULL before using && operator
        cloud_import_condition = "((a.tags IS NOT NULL AND a.tags && ARRAY['cloud_import','microburst','azurehound','prowler','scoutsuite','pacu','cloudfox']) OR host(a.ip)::text IN ('127.0.1.1', '127.0.0.1'))"
        if asset_kind == 'cloud-only':
            where_clauses.append(cloud_import_condition)
        elif asset_kind == 'hosts-only':
            where_clauses.append(f"NOT {cloud_import_condition}")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""


    total = 0
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"SELECT count(*) AS n FROM assets a {where_sql}", where_params)
        total = cur.fetchone()["n"]

        sql = f"""
            SELECT a.id,
                   host(a.ip)::text AS ip,
                   COALESCE(a.hostname, cm.hostname) AS hostname,
                   a.os,
                   a.tags,
                   a.engagement_id,
                   a.first_seen,
                   a.last_seen,
                   a.provider,
                   a.provider_evidence,
                   COUNT(DISTINCT p.id) AS open_ports_count,
                   (SELECT count(*) FROM recon_findings rf WHERE rf.asset_id = a.id)
                       AS recon_findings_count
            FROM assets a
            LEFT JOIN ports p ON p.asset_id = a.id AND COALESCE(p.is_open, true)
            LEFT JOIN LATERAL (
                SELECT metadata->>'hostname' AS hostname
                FROM credential_findings
                WHERE asset_id = a.id AND metadata->>'hostname' IS NOT NULL
                ORDER BY created_at DESC LIMIT 1
            ) cm ON a.hostname IS NULL
            {where_sql}
            GROUP BY a.id, a.ip, a.hostname, a.os, a.tags, a.engagement_id,
                     a.first_seen, a.last_seen, a.provider, a.provider_evidence, cm.hostname
            ORDER BY a.ip
            LIMIT %s OFFSET %s
        """
        cur.execute(sql, (*where_params, limit, offset))
        rows = cur.fetchall()

    # Fast batch lookup: which tools discovered each asset
    asset_ids = [str(r["id"]) for r in rows if r.get("id")]
    if asset_ids:
        source_map: dict = {}
        try:
            with get_db() as conn2, conn2.cursor() as cur2:
                for tbl, src_col in [
                    ("ports", "CASE WHEN service IN ('http','https') THEN 'web-probe' ELSE 'nmap' END"),
                    ("web_findings", "source"),
                    ("recon_findings", "source"),
                    ("credential_findings", "source"),
                ]:
                    try:
                        cur2.execute(f"SELECT asset_id::text, array_agg(DISTINCT {src_col}) FROM {tbl} WHERE asset_id = ANY(%s::uuid[]) GROUP BY asset_id", (asset_ids,))
                        for row2 in cur2.fetchall():
                            source_map.setdefault(row2[0], set()).update(s for s in row2[1] if s)
                    except Exception as _src_err:
                        logger.warning("[assets] Source lookup for %s failed: %s", tbl, _src_err)
        except Exception:
            pass
        for row in rows:
            row["discovered_by"] = sorted(source_map.get(str(row["id"]), set()))

    # Reverse DNS lookup (dig -x) for assets still missing a hostname
    import subprocess as _sp
    for row in rows:
        if row.get("hostname") or not row.get("ip") or row["ip"] == "0.0.0.0":
            continue
        try:
            cp = _sp.run(
                ["dig", "+short", "-x", row["ip"]],
                capture_output=True, text=True, timeout=5,
            )
            ptr = cp.stdout.strip().rstrip(".")
            if ptr and ptr != row["ip"] and not ptr.startswith(";"):
                row["hostname"] = ptr
                # Persist so we don't re-lookup every request
                try:
                    with get_db() as conn2, conn2.cursor() as cur2:
                        cur2.execute(
                            "UPDATE assets SET hostname = %s WHERE id = %s AND hostname IS NULL",
                            (ptr, row["id"]),
                        )
                        conn2.commit()
                except Exception:
                    pass
        except Exception:
            pass  # dig not available or timed out

    # Surface id as a string (used for drill-downs like /recon/search?asset_id=).
    # tags is a Postgres text[] — psycopg2 returns it as a Python list; ensure JSON-safe.
    for row in rows:
        if row.get("id") is not None:
            row["id"] = str(row["id"])
        if row.get("engagement_id") is not None:
            row["engagement_id"] = str(row["engagement_id"])

    return {"count": len(rows), "total": total, "limit": limit, "offset": offset, "assets": rows}

@app.delete("/findings/bulk")
def delete_findings_bulk(body: dict, authorized: bool = Depends(auth)):
    """Bulk-delete findings by ID across web_findings, vulns, and playwright_findings."""
    ids = body.get("ids", [])
    source = body.get("source")  # optional: web, vuln, playwright
    if not ids:
        raise HTTPException(status_code=400, detail="No IDs provided")
    deleted = 0
    with get_db() as conn, conn.cursor() as cur:
        for table in ["web_findings", "vulns", "playwright_findings"]:
            if source and source not in table:
                continue
            cur.execute(f"DELETE FROM {table} WHERE id::text = ANY(%s)", (ids,))
            deleted += cur.rowcount
        conn.commit()
    return {"ok": True, "deleted": deleted}


@app.delete("/recon/findings/bulk")
def delete_recon_findings_bulk(body: dict, authorized: bool = Depends(auth)):
    """Bulk-delete recon findings by ID."""
    ids = body.get("ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="No IDs provided")
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM recon_findings WHERE id::text = ANY(%s)", (ids,))
        deleted = cur.rowcount
        conn.commit()
    return {"ok": True, "deleted": deleted}


@app.delete("/purge/pattern")
def purge_by_pattern(body: dict, authorized: bool = Depends(auth)):
    """Delete all data matching a pattern (IP range, domain) across all tables.
    Body: { pattern: "192.168.1.%", dry_run: true/false }
    """
    pattern = body.get("pattern", "").strip()
    dry_run = body.get("dry_run", True)
    if not pattern or len(pattern) < 3:
        raise HTTPException(400, "Pattern must be at least 3 characters")
    # Safety: require % wildcard
    if "%" not in pattern and "*" not in pattern:
        pattern = f"%{pattern}%"
    pattern = pattern.replace("*", "%")
    # URL-wrapped pattern — for tables where the value is embedded in a URL
    url_pattern = f"%{pattern.strip('%')}%" if not pattern.startswith("%") else pattern

    results = {}
    with get_db() as conn, conn.cursor() as cur:
        # Count/delete across tables
        # For URL-based tables, use url_pattern (wraps with %) to match inside URLs
        tables_to_check = [
            ("assets", "host(ip)::text LIKE %s OR hostname LIKE %s", (pattern, url_pattern)),
            ("web_findings", "url LIKE %s", (url_pattern,)),
            ("recon_findings", "target LIKE %s OR target LIKE %s", (pattern, url_pattern)),
            ("playwright_findings", "url LIKE %s", (url_pattern,)),
            ("content_extractions", "url LIKE %s", (url_pattern,)),
            ("scope_targets", "target LIKE %s", (pattern,)),
            ("discovered_params", "url_pattern LIKE %s", (url_pattern,)),
        ]
        for entry in tables_to_check:
            table, where, params_tuple = entry[0], entry[1], entry[2]
            try:
                cur.execute("SAVEPOINT pp_check")
                cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params_tuple)
                count = cur.fetchone()[0]
                results[table] = count
                if not dry_run and count > 0:
                    cur.execute(f"DELETE FROM {table} WHERE {where}", params_tuple)
                    results[table] = cur.rowcount
                cur.execute("RELEASE SAVEPOINT pp_check")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT pp_check")
                results[table] = f"error: {e}"

        # Also check ports/vulns via asset_id join
        try:
            cur.execute("SAVEPOINT pp_ports")
            cur.execute("""
                SELECT COUNT(*) FROM ports p
                JOIN assets a ON p.asset_id = a.id
                WHERE host(a.ip)::text LIKE %s OR a.hostname LIKE %s
            """, (pattern, url_pattern))
            port_count = cur.fetchone()[0]
            results["ports"] = port_count
            if not dry_run and port_count > 0:
                cur.execute("""
                    DELETE FROM ports WHERE asset_id IN (
                        SELECT id FROM assets WHERE host(ip)::text LIKE %s OR hostname LIKE %s
                    )
                """, (pattern, url_pattern))
                results["ports"] = cur.rowcount
            cur.execute("RELEASE SAVEPOINT pp_ports")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT pp_ports")
            results["ports"] = f"error: {e}"

        if not dry_run:
            conn.commit()

    total = sum(v for v in results.values() if isinstance(v, int))
    return {"ok": True, "pattern": pattern, "dry_run": dry_run,
            "total": total, "details": results}


@app.delete("/assets")
def delete_assets(body: dict, authorized: bool = Depends(auth)):
    """Bulk-delete assets by IP. Cascades to ports, vulns, web_findings, etc."""
    ips = body.get("ips", [])
    if not ips:
        raise HTTPException(status_code=400, detail="No IPs provided")
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM assets WHERE host(ip)::text = ANY(%s)", (ips,))
        deleted = cur.rowcount
        conn.commit()
    return {"ok": True, "deleted": deleted}


@app.delete("/targets/{domain}", tags=["Targets"])
def purge_target_domain(domain: str, dry_run: bool = Query(False), authorized: bool = Depends(auth)):
    """
    Delete ALL data associated with a domain (e.g. example.com).

    Matches: hostname, target, url, subdomain fields containing the domain.
    Cascades through all finding tables, recon, scans, scope, and assets.
    Use dry_run=true to preview counts before deleting.
    """
    domain = domain.strip().lower()
    if not domain or len(domain) < 3:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Tables and the column + match strategy for each.
    # Order: dependents first, then parents.
    targets = [
        ("screenshot_metadata",  "LOWER(path) LIKE %s"),
        ("finding_activity",     "finding_id IN (SELECT id FROM recon_findings WHERE LOWER(target) LIKE %s)"),
        ("finding_activity",     "finding_id IN (SELECT id FROM web_findings WHERE LOWER(url) LIKE %s)"),
        ("finding_activity",     "finding_id IN (SELECT id FROM vulns WHERE asset_id IN (SELECT id FROM assets WHERE LOWER(hostname) LIKE %s))"),
        ("evidence_links",       "finding_id IN (SELECT id::text FROM recon_findings WHERE LOWER(target) LIKE %s)"),
        ("scan_run_findings",    "finding_id IN (SELECT id FROM recon_findings WHERE LOWER(target) LIKE %s)"),
        ("scan_run_findings",    "finding_id IN (SELECT id FROM web_findings WHERE LOWER(url) LIKE %s)"),
        ("follow_up_items",      "LOWER(target) LIKE %s"),
        ("follow_up_items",      "LOWER(title) LIKE %s"),
        ("campaign_events",      "LOWER(target) LIKE %s"),
        ("discovered_params",    "LOWER(url) LIKE %s"),
        ("dom_analysis",         "LOWER(url) LIKE %s"),
        ("playwright_screenshots", "scan_id IN (SELECT id FROM playwright_scans WHERE LOWER(url) LIKE %s)"),
        ("playwright_findings",  "LOWER(url) LIKE %s"),
        ("playwright_scans",     "LOWER(url) LIKE %s"),
        ("credential_findings",  "asset_id IN (SELECT id FROM assets WHERE LOWER(hostname) LIKE %s)"),
        ("web_findings",         "LOWER(url) LIKE %s"),
        ("recon_findings",       "LOWER(target) LIKE %s"),
        ("vulns",                "asset_id IN (SELECT id FROM assets WHERE LOWER(hostname) LIKE %s)"),
        ("ports",                "asset_id IN (SELECT id FROM assets WHERE LOWER(hostname) LIKE %s)"),
        ("scan_recommendations", "LOWER(ip::text) LIKE %s"),
        ("scan_recommendations", "LOWER(banner) LIKE %s"),
        ("scope_targets",        "LOWER(target) LIKE %s"),
        ("assets",               "LOWER(hostname) LIKE %s"),
    ]

    pattern = f"%{domain}%"
    counts = {}

    with get_db() as conn, conn.cursor() as cur:
        for table, where_clause in targets:
            try:
                cur.execute("SAVEPOINT purge_count")
                cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {where_clause}", (pattern,))
                count = cur.fetchone()[0]
                if count > 0:
                    counts[table] = counts.get(table, 0) + count
                cur.execute("RELEASE SAVEPOINT purge_count")
            except Exception:
                cur.execute("ROLLBACK TO SAVEPOINT purge_count")

        if dry_run:
            total = sum(counts.values())
            return {"dry_run": True, "domain": domain, "total_rows": total, "tables": counts}

        deleted = {}
        for table, where_clause in targets:
            try:
                cur.execute("SAVEPOINT purge_del")
                cur.execute(f"DELETE FROM {table} WHERE {where_clause}", (pattern,))
                if cur.rowcount > 0:
                    deleted[table] = deleted.get(table, 0) + cur.rowcount
                cur.execute("RELEASE SAVEPOINT purge_del")
            except Exception:
                cur.execute("ROLLBACK TO SAVEPOINT purge_del")

        conn.commit()

    total = sum(deleted.values())
    return {"ok": True, "domain": domain, "total_deleted": total, "tables": deleted}


@app.get("/credentials", tags=["Credentials"])
def list_all_credentials(
    status: str = Query(None, description="Filter by status"),
    protocol: str = Query(None, description="Filter by protocol"),
    source: str = Query(None, description="Filter by source"),
    limit: int = Query(500, le=5000),
    authorized: bool = Depends(auth),
):
    """List all credential findings across all assets."""
    clauses, params = [], []
    if status:
        clauses.append("status = %s"); params.append(status)
    if protocol:
        clauses.append("protocol = %s"); params.append(protocol)
    if source:
        clauses.append("source = %s"); params.append(source)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"""
            SELECT id, host(ip)::text as ip, port, protocol, username, valid_cred,
                   auth_type, secret_type, severity, banner, source, status,
                   discovered_at, last_verified_at, duration_ms, metadata, created_at
            FROM credential_findings
            {where}
            ORDER BY created_at DESC
            LIMIT %s
        """, params)
        rows = cur.fetchall()
    return {"count": len(rows), "credentials": [dict(r) for r in rows]}


VALID_SECRET_TYPES = {"password", "aws_key", "azure_key", "ssh_key", "api_token", "ntlm_hash", "kerberos_ticket", "certificate", "other"}

@app.post("/credentials", tags=["Credentials"])
def create_credential(
    ip: str = Query("0.0.0.0", description="IP address"),
    port: int = Query(0, description="Port number"),
    protocol: str = Query("other", description="Protocol"),
    username: str = Query("", description="Username"),
    secret_value: str = Query("", description="Password / secret value"),
    secret_type: str = Query("password", description="Secret type"),
    status: str = Query("unknown", description="Status"),
    source: str = Query("manual", description="Source"),
    banner: str = Query(None, description="Banner"),
    authorized: bool = Depends(auth),
):
    """Manually add a credential finding."""
    if secret_type not in VALID_SECRET_TYPES:
        secret_type = "other"
    if status not in ("valid", "invalid", "unknown", "remediated"):
        status = "unknown"
    # Resolve hostname to IP if needed (inet column requires valid IP)
    import socket as _socket
    original_host = ip or ""
    if not ip or ip.strip() == "":
        ip = "0.0.0.0"
    else:
        ip = ip.strip()
        # Check if it's already a valid IP
        try:
            _socket.inet_pton(_socket.AF_INET, ip)
        except _socket.error:
            try:
                _socket.inet_pton(_socket.AF_INET6, ip)
            except _socket.error:
                # Not an IP — try to resolve hostname
                try:
                    resolved = _socket.getaddrinfo(ip, None, _socket.AF_INET)
                    if resolved:
                        ip = resolved[0][4][0]
                except _socket.gaierror:
                    # Can't resolve — store as 0.0.0.0, keep hostname in metadata
                    ip = "0.0.0.0"
    # Store secret_value and original hostname in metadata
    metadata = {}
    if secret_value:
        metadata["secret_value"] = secret_value
    if original_host and original_host != ip:
        metadata["hostname"] = original_host
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        asset_id = None
        if ip and ip != "0.0.0.0":
            cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
            row = cur.fetchone()
            if row:
                asset_id = str(row["id"])
        # Also try to find asset by hostname if ip lookup failed
        if not asset_id and original_host and original_host != ip:
            cur.execute("SELECT id FROM assets WHERE hostname = %s", (original_host,))
            row = cur.fetchone()
            if row:
                asset_id = str(row["id"])
        cred_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO credential_findings
                (id, asset_id, ip, port, protocol, username, valid_cred, auth_type,
                 secret_type, source, banner, status, discovered_at, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), %s)
            RETURNING id, host(ip)::text as ip, port, protocol, username, valid_cred,
                      auth_type, secret_type, source, banner, status, discovered_at, created_at
        """, (cred_id, asset_id, ip or '0.0.0.0', port, protocol, username,
              status == 'valid', secret_type, secret_type, source, banner, status,
              Json(metadata)))
        row = cur.fetchone()
        conn.commit()
    return dict(row)


@app.delete("/credentials/{cid}", tags=["Credentials"])
def delete_credential(cid: str, authorized: bool = Depends(auth)):
    """Delete a credential finding by ID."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM credential_findings WHERE id = %s", (cid,))
        deleted = cur.rowcount
        conn.commit()
    if not deleted:
        raise HTTPException(404, "Credential not found")
    return {"ok": True, "deleted": cid}


@app.get("/assets/{ip}/credentials", tags=["Assets"])
def get_asset_credentials(ip: str, authorized: bool = Depends(auth)):
    """Get all credential findings for an asset by IP."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, host(ip)::text as ip, port, protocol, username, valid_cred,
                   auth_type, secret_type, severity, banner, source, status,
                   discovered_at, last_verified_at, duration_ms, metadata, created_at
            FROM credential_findings
            WHERE host(ip)::text = %s
            ORDER BY created_at DESC
        """, (ip,))
        rows = cur.fetchall()
    return {"credentials": [dict(r) for r in rows]}


@app.patch("/credential-findings/{cid}/status", tags=["Assets"])
def update_credential_finding_status(
    cid: str,
    status: str = Query(..., description="valid, invalid, unknown, or remediated"),
    authorized: bool = Depends(auth),
):
    """Update the status of a credential finding and set last_verified_at."""
    if status not in ("valid", "invalid", "unknown", "remediated"):
        raise HTTPException(400, "Status must be valid, invalid, unknown, or remediated")
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """UPDATE credential_findings
               SET status = %s, last_verified_at = now()
               WHERE id = %s RETURNING *""",
            (status, cid),
        )
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Credential finding not found")
    return dict(row)


@app.get("/ports/open")
def get_open_ports(
    ip: Optional[str] = Query(None, description="Optional IP filter, e.g., 192.168.1.5"),
    service: Optional[str] = Query(None, description="Optional service filter (e.g. ssh, http)"),
    search: Optional[str] = Query(None, description="Substring match on service / product / banner (case-insensitive)"),
    limit: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0, description="Pagination offset for retrieving > limit rows"),
    authorized: bool = Depends(auth),
):
    # Return normalized open ports, optionally filtered by IP
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        where = ["COALESCE(p.is_open, true)"]
        params: list = []
        if ip:
            where.append("host(a.ip)=%s")
            params.append(ip)
        if service:
            where.append("p.service ILIKE %s")
            params.append(service)
        if search:
            where.append("(p.service ILIKE %s OR p.product ILIKE %s OR p.banner ILIKE %s)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        where_sql = "WHERE " + " AND ".join(where)
        # Count total matching rows (independent of LIMIT/OFFSET) for pagination.
        cur.execute(
            f"SELECT count(DISTINCT (p.id)) AS n FROM ports p JOIN assets a ON p.asset_id = a.id {where_sql}",
            params,
        )
        total = cur.fetchone()["n"]
        sql = f"""
            SELECT host(a.ip)::text AS ip,
                   p.proto, p.port,
                   COALESCE(p.service,'?') AS service,
                   p.product, p.version, p.banner,
                   a.os,
                   COALESCE(COUNT(DISTINCT v.id), 0)::int AS finding_count,
                   CASE MAX(
                       CASE v.severity
                           WHEN 'critical' THEN 5
                           WHEN 'high' THEN 4
                           WHEN 'medium' THEN 3
                           WHEN 'low' THEN 2
                           WHEN 'info' THEN 1
                           ELSE 0
                       END
                   )
                       WHEN 5 THEN 'critical'
                       WHEN 4 THEN 'high'
                       WHEN 3 THEN 'medium'
                       WHEN 2 THEN 'low'
                       WHEN 1 THEN 'info'
                       ELSE NULL
                   END AS max_severity
            FROM ports p
            JOIN assets a ON p.asset_id = a.id
            LEFT JOIN vulns v ON v.port_id = p.id
            {where_sql}
            GROUP BY a.ip, p.id, p.proto, p.port, p.service, p.product, p.version, p.banner, a.os
            ORDER BY a.ip, p.port
            LIMIT %s OFFSET %s
        """
        cur.execute(sql, (*params, limit, offset))
        rows = cur.fetchall()
    return {"count": len(rows), "total": total, "limit": limit, "offset": offset, "items": rows}

def _save_upload_to_tmp(file: UploadFile) -> str:
    tmp_path = f"/tmp/{file.filename}"
    with open(tmp_path, "wb") as buffer:
        buffer.write(file.file.read())
    return tmp_path

def _parse_targets_text(content: str, whitelist: Optional[List[str]], blacklist: Optional[List[str]]) -> List[str]:
    targets = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)

    # Apply whitelist and blacklist
    if whitelist:
        targets = [target for target in targets if any(ipaddress.ip_address(target) in ipaddress.ip_network(wl) for wl in whitelist)]
    if blacklist:
        targets = [target for target in targets if not any(ipaddress.ip_address(target) in ipaddress.ip_network(bl) for bl in blacklist)]

    return targets

def _create_nmap_tasks_from_recent(job_id: str, since_ts: datetime) -> int:
    base = os.environ.get("NMAP_SCANNER_URL", "https://nmap_scanner:8012")
    _eid = None
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("SELECT engagement_id FROM jobs WHERE id=%s::uuid", (job_id,))
            row = cur.fetchone()
            if row and row[0]:
                _eid = str(row[0])
    except Exception:
        pass
    try:
        r = requests.post(
            f"{base}/jobs/masscan-results-since/{since_ts.isoformat()}",
            headers=_outgoing_runner_headers(engagement_id=_eid),
            verify=False,
        )
        r.raise_for_status()
        results = r.json().get("results", [])
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            for result in results:
                ip = result.get("ip")
                ports = result.get("ports", [])
                for port_info in ports:
                    port = port_info.get("port")
                    proto = port_info.get("proto", "tcp")
                    cur.execute(
                        """
                        INSERT INTO tasks (job_id, type, target_host, target_port, proto, status)
                        VALUES (%s::uuid, 'nmap', %s, %s, %s, 'queued')
                        ON CONFLICT DO NOTHING
                        """,
                        (job_id, ip, port, proto),
                    )
            cur.execute("UPDATE jobs SET total_tasks = GREATEST(total_tasks, finished_tasks + 1) WHERE id=%s::uuid", (job_id,))
            conn.commit()
        return len(results)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"scanner unavailable: {e}")

def _background_run_masscan_nmap(job_id: str, targets: List[str], ports: str, rate: int, interface: Optional[str]) -> None:
    base = os.environ.get("NMAP_SCANNER_URL", "https://nmap_scanner:8012")
    since_ts = datetime.now(timezone.utc)
    # Resolve engagement_id from the jobs row we already stamped at launch.
    # The contextvar isn't reliable in background tasks; DB lookup is.
    _bg_eid: Optional[str] = None
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("SELECT engagement_id FROM jobs WHERE id=%s::uuid", (job_id,))
            row = cur.fetchone()
            if row and row[0]:
                _bg_eid = str(row[0])
    except Exception:
        pass
    # transition job/tasks to running if queued
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("UPDATE jobs SET status='running', started_at=COALESCE(started_at, now()) WHERE id=%s::uuid", (job_id,))
            cur.execute("""
                        INSERT INTO tasks (job_id, type, status, started_at)
                        VALUES (%s::uuid,'pipeline','running',now())
                        ON CONFLICT DO NOTHING
                        """, (job_id,))
            # If already existed queued, mark running
            cur.execute("UPDATE tasks SET status='running', started_at=COALESCE(started_at, now()) WHERE job_id=%s::uuid AND type='pipeline' AND status='queued'", (job_id,))
            cur.execute("UPDATE jobs SET total_tasks = GREATEST(total_tasks, 1) WHERE id=%s::uuid", (job_id,))
            conn.commit()
    except Exception:
        pass

    # call scanner
    ok = False
    resp: Dict[str, Any] = {}
    try:
        payload: Dict[str, Any] = {"targets": targets, "ports": ports, "rate": rate}
        if interface:
            payload["interface"] = interface
        r = requests.post(
            f"{base}/jobs/masscan-then-nmap",
            json=payload,
            headers=_outgoing_runner_headers(engagement_id=_bg_eid),
            verify=False, timeout=3600,
        )
        r.raise_for_status()
        resp = r.json() if r.headers.get("content-type","").startswith("application/json") else {"ok": True}
        ok = bool(resp.get("ok", True))
    except requests.RequestException as e:
        err = f"scanner unavailable: {e}"
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("UPDATE tasks SET status='failed', finished_at=now(), last_error=%s WHERE job_id=%s::uuid AND type='pipeline'", (err, job_id))
            cur.execute("UPDATE jobs SET status='failed', finished_at=now(), error=%s WHERE id=%s::uuid", (err, job_id))
            conn.commit()
        return

    # enqueue Nmap tasks from recent results
    try:
        _create_nmap_tasks_from_recent(job_id, since_ts)
    except Exception:
        pass

    # finalize pipeline task and job
    with get_db() as conn, conn.cursor() as cur:
        if ok:
            cur.execute("UPDATE tasks SET status='finished', finished_at=now() WHERE job_id=%s::uuid AND type='pipeline'", (job_id,))
            cur.execute("UPDATE jobs SET finished_tasks = LEAST(total_tasks, finished_tasks + 1), status='finished', finished_at=now(), error=NULL WHERE id=%s::uuid", (job_id,))
        else:
            err = resp.get("error", "unknown error")
            cur.execute("UPDATE tasks SET status='failed', finished_at=now(), last_error=%s WHERE job_id=%s::uuid AND type='pipeline'", (err, job_id))
            cur.execute("UPDATE jobs SET status='failed', finished_at=now(), error=%s WHERE id=%s::uuid", (err, job_id))
        conn.commit()

# Service-discovery sources whose ingest produces new (ip, service, banner)
# tuples that the local-LLM scan_recommender can usefully reason about.
# Sources NOT in this set (burp, subfinder, dnsx, tlsx, crtsh, brutus,
# trufflehog, amass, gau, waybackurls, …) don't produce service-centric
# output, so calling /next_scan for them would be a no-op or wasted call —
# exploit_watcher's existing periodic poll picks up findings from them.
_RECOMMENDER_TRIGGER_SOURCES = {
    "nmap", "masscan", "naabu", "nessus", "nuclei",
    "whatweb", "wafw00f", "httpx", "zap",
}


def _emit_ingest_event(source: str, stats: dict = None):
    """Emit ingest_completed webhook, and — for service-discovery sources —
    fire the local-LLM scan recommender for every freshly-touched open port
    that doesn't yet have a recommendation.  Together these make prioritized
    follow-ups appear as soon as scan results land, instead of waiting for the
    exploit_watcher's polling cycle."""
    try:
        from webhooks import emit_webhook
        emit_webhook("ingest_completed", source, {"stats": stats or {}})
    except Exception:
        pass  # Non-critical — dashboard will still poll
    try:
        _trigger_recommendations_for(source, stats)
    except Exception as e:
        logger.warning("recommender trigger failed for source=%s: %s", source, e)


def _select_open_ports_without_recs(window_minutes: int = None, limit: int = 200,
                                    ip: str = None):
    """Return open ports that don't yet have a scan recommendation.

    LEFT JOIN + IS NULL keeps this idempotent: ports already recommended are
    filtered out, so running again over the same data is a no-op.

    window_minutes: if set, only consider ports touched within that many
    minutes (the reactive ingest path uses 10). If None, consider ALL current
    open ports — used by on-demand generation for targets scanned earlier.
    """
    clauses = ["COALESCE(p.is_open, true)", "sr.id IS NULL"]
    params: dict = {"limit": limit}
    if window_minutes is not None:
        clauses.append("p.last_seen >= now() - make_interval(mins => %(mins)s)")
        params["mins"] = window_minutes
    if ip:
        clauses.append("host(a.ip)::text = %(ip)s")
        params["ip"] = ip
    where_sql = " AND ".join(clauses)
    with get_db() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"""
            SELECT host(a.ip)::text AS ip,
                   p.port,
                   p.service,
                   COALESCE(NULLIF(p.banner, ''),
                            NULLIF(CONCAT_WS(' ', p.product, p.version), '')
                   ) AS banner
            FROM public.ports p
            JOIN public.assets a ON a.id = p.asset_id
            LEFT JOIN public.scan_recommendations sr
              ON sr.ip = a.ip
             AND COALESCE(sr.service, '') = COALESCE(p.service, '')
            WHERE {where_sql}
            ORDER BY p.last_seen DESC
            LIMIT %(limit)s
        """, params)
        return cur.fetchall()


def _dispatch_recommender_for_ports(rows) -> int:
    """Call the scan_recommender's /next_scan (persist=true) for each port row,
    generating + persisting recommendations. Returns the number dispatched.

    Must run inside a copy_context() (or a request scope) so
    _outgoing_runner_headers() resolves the engagement_id contextvar.
    """
    scan_rec_url = os.environ.get("SCAN_RECOMMENDER_URL",
                                  "https://scan-recommender:8013")
    dispatched = 0
    for row in rows:
        params = {
            "ip": row["ip"],
            "port": str(row["port"]),
            "persist": "true",
        }
        if row.get("service"):
            params["service"] = row["service"]
        if row.get("banner"):
            params["banner"] = row["banner"]
        try:
            requests.get(
                f"{scan_rec_url}/next_scan",
                params=params,
                headers=_outgoing_runner_headers(),
                timeout=60,
                verify=False,
            )
            dispatched += 1
        except Exception as e:
            logger.debug(
                "recommender call failed for %s:%s — %s",
                row["ip"], row["port"], e,
            )
    return dispatched


def _trigger_recommendations_for(source: str, stats: dict = None):
    """Fire-and-forget: ask the local-LLM scan_recommender to recommend next
    probes for every recently-touched open port without a recommendation yet.

    Runs in a daemon thread so the ingest response isn't blocked by LLM
    inference.  Only fires for sources in `_RECOMMENDER_TRIGGER_SOURCES`;
    everything else is a no-op (no shape match, no value)."""
    if source not in _RECOMMENDER_TRIGGER_SOURCES:
        return

    def _worker():
        try:
            # Pull the most-recently-touched open ports that haven't been
            # recommended on yet (10-minute reactive window for ingest).
            rows = _select_open_ports_without_recs(window_minutes=10)
            dispatched = _dispatch_recommender_for_ports(rows)

            if dispatched:
                logger.info(
                    "scan_recommender dispatched: source=%s dispatched=%d",
                    source, dispatched,
                )
                # Surface this on the webhook bus so external tools / the
                # OPSEC timeline can see that follow-ups were generated
                # reactively in response to this ingest.
                try:
                    from webhooks import emit_webhook
                    emit_webhook("recommendations_generated", source, {
                        "source": source,
                        "dispatched": dispatched,
                    })
                except Exception:
                    pass
        except Exception as e:
            logger.warning(
                "recommender trigger worker failed: source=%s err=%s",
                source, e,
            )

    # Propagate the request's contextvars (including current_engagement_id)
    # into the worker thread.  `threading.Thread` does NOT inherit contextvars
    # by default -- without this the worker runs with default (None) values
    # for any contextvar set by the HTTP middleware, which would silently
    # break engagement-scoped lookups added in future worker code paths.
    # See: https://docs.python.org/3/library/contextvars.html#contextvars.copy_context
    ctx = contextvars.copy_context()
    threading.Thread(
        target=ctx.run, args=(_worker,),
        daemon=True, name=f"reco-trigger-{source}",
    ).start()

@app.post("/ingest/nmap")
def ingest_nmap(
    file: UploadFile = File(...),
    job_id: str = None,
    target: str = None,
    authorized: bool = Depends(auth)
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_nmap import parse_nmap
        stats = parse_nmap(path, profile="api-upload", job_id=job_id, target=target)
        _emit_ingest_event("nmap", stats)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/nessus")
def ingest_nessus(
    file: UploadFile = File(...),
    job_id: str = None,
    target: str = None,
    authorized: bool = Depends(auth),
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_nessus import parse_nessus
        stats = parse_nessus(path, profile="api-upload", job_id=job_id, target=target)
        _emit_ingest_event("nessus", stats)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/nuclei")
def ingest_nuclei(
    file: UploadFile = File(...),
    job_id: str = None,
    target: str = None,
    authorized: bool = Depends(auth)
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_nuclei import parse_nuclei
        stats = parse_nuclei(path, profile="api-upload", job_id=job_id, target=target)
        _emit_ingest_event("nuclei", stats)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/burp")
def ingest_burp(file: UploadFile = File(...), authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_burp import parse_burp
        stats = parse_burp(path, profile="api-upload")
        _emit_ingest_event("burp", stats)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/masscan")
def ingest_masscan(file: UploadFile = File(...), authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_masscan import parse_masscan
        stats = parse_masscan(path, profile="upload")
        _emit_ingest_event("masscan", stats)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/masscan/dedupe")
def dedupe_masscan(file: UploadFile = File(...), authorized: bool = Depends(auth)):
    """
    Accept a Masscan -oJ JSON file and return a deduplicated list of host:port pairs.
    """
    path = _save_upload_to_tmp(file)
    try:
        items: List[Dict[str, Any]] = []
        pairs = set()
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError:
                # Fallback: attempt to parse line-delimited JSON entries
                fh.seek(0)
                data = []
                for line in fh:
                    s = line.strip()
                    if not s or s in ("[", "]", ","):
                        continue
                    if s.endswith(","):
                        s = s[:-1]
                    try:
                        obj = json.loads(s)
                        data.append(obj)
                    except Exception:
                        pass
        if isinstance(data, list):
            for rec in data:
                if not isinstance(rec, dict):
                    continue
                ip = rec.get("ip")
                for p in rec.get("ports", []) or []:
                    port = p.get("port")
                    proto = p.get("proto", "tcp")
                    if ip and isinstance(port, int):
                        key = (ip, port, proto)
                        if key not in pairs:
                            pairs.add(key)
                            items.append({"host": ip, "port": port, "proto": proto})
        return {"count": len(items), "items": items}
    finally:
        os.remove(path)

@app.post("/ingest/subfinder")
def ingest_subfinder(file: UploadFile = File(...), job_id: str = None,
                     engagement_id: Optional[str] = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_subfinder import parse_subfinder
        # Resolve engagement from the explicit param or the X-Engagement-Id
        # header so in-scope discoveries can enter the engagement scan loop.
        eid = _resolve_engagement_id(engagement_id)
        stats = parse_subfinder(path, profile="api-upload", job_id=job_id, engagement_id=eid)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/httpx")
def ingest_httpx(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_httpx import parse_httpx
        stats = parse_httpx(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/whatweb")
def ingest_whatweb(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_whatweb import parse_whatweb
        stats = parse_whatweb(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/wafw00f")
def ingest_wafw00f(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_wafw00f import parse_wafw00f
        stats = parse_wafw00f(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/naabu")
def ingest_naabu(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_naabu import parse_naabu
        stats = parse_naabu(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/katana")
def ingest_katana(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_katana import parse_katana
        stats = parse_katana(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/brutus")
def ingest_brutus(file: UploadFile = File(...), job_id: str = None, secret_type: str = "password", authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_brutus import parse_brutus
        stats = parse_brutus(path, profile="api-upload", job_id=job_id, secret_type=secret_type)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/dnsx")
def ingest_dnsx(file: UploadFile = File(...), job_id: str = None,
                engagement_id: Optional[str] = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_dnsx import parse_dnsx
        # Resolve engagement (explicit param or X-Engagement-Id header) so
        # in-scope resolved hosts can enter the engagement scan loop.
        eid = _resolve_engagement_id(engagement_id)
        stats = parse_dnsx(path, profile="api-upload", job_id=job_id, engagement_id=eid)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/tlsx")
def ingest_tlsx(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_tlsx import parse_tlsx
        stats = parse_tlsx(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/crtsh")
def ingest_crtsh(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_crtsh import parse_crtsh
        stats = parse_crtsh(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/cloud-tenant")
def ingest_cloud_tenant(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    """JSONL of cloud-tenant discovery results — one record per (domain, provider) pair."""
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_cloud_tenant import parse_cloud_tenant
        stats = parse_cloud_tenant(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)


@app.get("/cloud-tenants", tags=["Cloud"])
def list_cloud_tenants(
    domain: Optional[str] = Query(None, description="Filter to a specific domain (case-insensitive)"),
    provider: Optional[str] = Query(None, description="Filter to azure / aws / gcp"),
    engagement_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    authorized: bool = Depends(auth),
):
    """List discovered cloud-tenant rows. Used by ScanLauncher and the
    forthcoming Cloud Tenants panel on ScopeIntelligence."""
    conds = []
    params: list = []
    if domain:
        conds.append("LOWER(domain) = %s")
        params.append(domain.lower())
    if provider:
        conds.append("provider = %s")
        params.append(provider)
    if engagement_id:
        conds.append("engagement_id = %s::uuid")
        params.append(engagement_id)
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    sql = f"""
        SELECT id, domain, provider, tenant_id, federation_type, sts_auth_url,
               name_space_type, cloud_instance, indicators, engagement_id,
               first_seen, last_seen
        FROM cloud_tenants
        {where}
        ORDER BY last_seen DESC
        LIMIT %s OFFSET %s
    """
    count_sql = f"SELECT count(*) AS n FROM cloud_tenants{where}"
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(count_sql, params)
        total = cur.fetchone()["n"]
        cur.execute(sql, list(params) + [limit, offset])
        rows = cur.fetchall()

    def _ser(r):
        return {
            "id": str(r["id"]),
            "domain": r["domain"],
            "provider": r["provider"],
            "tenant_id": r["tenant_id"],
            "federation_type": r["federation_type"],
            "sts_auth_url": r["sts_auth_url"],
            "name_space_type": r["name_space_type"],
            "cloud_instance": r["cloud_instance"],
            "indicators": r["indicators"] or {},
            "engagement_id": str(r["engagement_id"]) if r["engagement_id"] else None,
            "first_seen": r["first_seen"].isoformat() if r["first_seen"] else None,
            "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
        }
    return {"total": total, "limit": limit, "offset": offset,
            "results": [_ser(r) for r in rows]}


# ============================================================================
# News Intelligence
# ============================================================================

class NewsBulkBody(BaseModel):
    ids: list[str]
    action: str  # 'set_status' | 'delete' | 'acknowledge' | 'clear_acknowledge'
    value: Optional[str] = None  # status name when action='set_status'


class NewsItemPatch(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[list[str]] = None
    acknowledged_by: Optional[str] = None


class NewsSourcePatch(BaseModel):
    enabled: Optional[bool] = None
    url: Optional[str] = None
    name: Optional[str] = None


class NewsSourceCreate(BaseModel):
    name: str
    url: str
    parser: str = "rss"
    enabled: bool = True


class NewsDeepSearchBody(BaseModel):
    topic: str
    include_deleted: Optional[bool] = False
    refresh_llm: Optional[bool] = False
    max_items: Optional[int] = 50


_NEWS_VALID_STATUSES = {"new", "reviewed", "follow_up", "applies",
                         "research", "future", "deleted"}


def _ser_news_item(r: dict) -> dict:
    return {
        "id": str(r["id"]),
        "title": r["title"],
        "summary": r["summary"],
        "primary_cve": r["primary_cve"],
        "all_cves": list(r["all_cves"] or []),
        "status": r["status"],
        "acknowledged_by": r["acknowledged_by"],
        "acknowledged_at": r["acknowledged_at"].isoformat() if r["acknowledged_at"] else None,
        "kev_listed": r["kev_listed"],
        "rce": r["rce"],
        "easily_exploitable": r["easily_exploitable"],
        "malware_exploitable": r["malware_exploitable"],
        "active_internet_breach": r["active_internet_breach"],
        "patch_available": r["patch_available"],
        "articles": r["articles"] or [],
        "github_links": r["github_links"] or [],
        "asset_matches": r["asset_matches"] or [],
        "first_seen": r["first_seen"].isoformat() if r["first_seen"] else None,
        "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
        "enriched_at": r["enriched_at"].isoformat() if r["enriched_at"] else None,
        "github_searched_at": r["github_searched_at"].isoformat() if r["github_searched_at"] else None,
        "asset_matched_at": r["asset_matched_at"].isoformat() if r["asset_matched_at"] else None,
        "notes": r["notes"],
        "tags": list(r["tags"] or []),
    }


_NEWS_RUNNER_URL = os.environ.get("NEWS_RUNNER_URL", "http://news-runner:8028").rstrip("/")


def _news_runner_post(path: str, json_body: Optional[dict] = None,
                      timeout: int = 30) -> dict:
    """Proxy to news-runner. Raises HTTPException on transport / 4xx / 5xx."""
    try:
        resp = requests.post(
            f"{_NEWS_RUNNER_URL}{path}",
            json=json_body or {},
            headers={"x-api-key": API_KEY},
            timeout=timeout, verify=False,
        )
    except Exception as e:
        raise HTTPException(502, f"news-runner unreachable: {e}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    try:
        return resp.json()
    except Exception:
        return {"ok": True, "raw": resp.text}


@app.post("/news/ingest", tags=["News"])
def news_ingest(source_id: Optional[str] = Query(None),
                authorized: bool = Depends(auth)):
    """Manual run of the full news cycle — proxied to news-runner."""
    return _news_runner_post("/jobs/ingest", {"source_id": source_id})


@app.get("/news/runs/{run_id}", tags=["News"])
def news_run_status(run_id: str, authorized: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM news_runs WHERE id = %s::uuid", (run_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "run not found")
        return {
            "id": str(row["id"]),
            "triggered_by": row["triggered_by"],
            "status": row["status"],
            "started_at": row["started_at"].isoformat() if row["started_at"] else None,
            "completed_at": row["completed_at"].isoformat() if row["completed_at"] else None,
            "sources_fetched": row["sources_fetched"],
            "articles_seen": row["articles_seen"],
            "items_new": row["items_new"],
            "items_updated": row["items_updated"],
            "items_enriched": row["items_enriched"],
            "error": row["error"],
            "per_source": row["per_source"] or [],
            "topic": row["topic"],
        }


@app.get("/news/runs", tags=["News"])
def news_runs_list(limit: int = Query(20, ge=1, le=200),
                   authorized: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT id, triggered_by, status, started_at, completed_at,
                      sources_fetched, articles_seen, items_new, items_updated,
                      items_enriched, topic
                 FROM news_runs ORDER BY started_at DESC LIMIT %s""",
            (limit,),
        )
        rows = cur.fetchall()
    return {"results": [{
        "id": str(r["id"]),
        "triggered_by": r["triggered_by"],
        "status": r["status"],
        "started_at": r["started_at"].isoformat() if r["started_at"] else None,
        "completed_at": r["completed_at"].isoformat() if r["completed_at"] else None,
        "sources_fetched": r["sources_fetched"],
        "articles_seen": r["articles_seen"],
        "items_new": r["items_new"],
        "items_updated": r["items_updated"],
        "items_enriched": r["items_enriched"],
        "topic": r["topic"],
    } for r in rows]}


@app.get("/news/items", tags=["News"])
def news_items_list(
    status: Optional[str] = Query(None),
    hide_statuses: Optional[str] = Query(None, description="CSV of statuses to hide (applied IN ADDITION to other filters)"),
    cve: Optional[str] = Query(None),
    kev_listed: Optional[bool] = Query(None),
    rce: Optional[bool] = Query(None),
    red_team_only: bool = Query(False, description="Only items with at least one offensive flag (kev/rce/easy/itw/malware)"),
    q: Optional[str] = Query(None, description="Substring on title/summary"),
    since: Optional[str] = Query(None, description="ISO timestamp; only items with last_seen >= since"),
    include_deleted: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    authorized: bool = Depends(auth),
):
    conds = []
    params: list = []
    if status:
        conds.append("status = %s"); params.append(status)
    elif not include_deleted:
        conds.append("status <> 'deleted'")
    if hide_statuses:
        wanted = [s.strip() for s in hide_statuses.split(",") if s.strip()]
        if wanted:
            conds.append("status <> ALL(%s::text[])")
            params.append(wanted)
    if cve:
        conds.append("(primary_cve = %s OR %s = ANY(all_cves))")
        params.extend([cve.upper(), cve.upper()])
    if kev_listed is not None:
        conds.append("kev_listed = %s"); params.append(kev_listed)
    if rce is not None:
        conds.append("rce = %s"); params.append(rce)
    if red_team_only:
        # An item is red-team relevant when at least one offensive flag is true.
        # Items still pending enrichment (all flags NULL) are excluded so the
        # default view doesn't show commentary/marketing pieces.
        conds.append(
            "(kev_listed IS TRUE OR rce IS TRUE OR easily_exploitable IS TRUE "
            "OR active_internet_breach IS TRUE OR malware_exploitable IS TRUE)"
        )
    if q:
        conds.append("(title ILIKE %s OR summary ILIKE %s)")
        params.extend([f"%{q}%", f"%{q}%"])
    if since:
        conds.append("last_seen >= %s::timestamptz"); params.append(since)
    where = (" WHERE " + " AND ".join(conds)) if conds else ""

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"SELECT count(*) AS n FROM news_items{where}", params)
        total = cur.fetchone()["n"]
        # Red-team-relevant items rank higher (KEV → RCE → ITW → easy → malware)
        # so the default view bubbles dangerous items above commentary even
        # when red_team_only is off.
        cur.execute(
            f"""SELECT * FROM news_items {where}
                ORDER BY
                    (CASE WHEN kev_listed             IS TRUE THEN 1 ELSE 0 END
                   + CASE WHEN rce                    IS TRUE THEN 1 ELSE 0 END
                   + CASE WHEN active_internet_breach IS TRUE THEN 1 ELSE 0 END
                   + CASE WHEN easily_exploitable     IS TRUE THEN 1 ELSE 0 END
                   + CASE WHEN malware_exploitable    IS TRUE THEN 1 ELSE 0 END) DESC,
                    last_seen DESC
                LIMIT %s OFFSET %s""",
            list(params) + [limit, offset],
        )
        rows = cur.fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "results": [_ser_news_item(r) for r in rows]}


@app.get("/news/items/{item_id}", tags=["News"])
def news_item_detail(item_id: str, authorized: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM news_items WHERE id = %s::uuid", (item_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "item not found")
        return _ser_news_item(row)


@app.patch("/news/items/{item_id}", tags=["News"])
def news_item_patch(item_id: str, body: NewsItemPatch, authorized: bool = Depends(auth)):
    sets = []
    params: list = []
    prev_status = None
    if body.status is not None:
        if body.status not in _NEWS_VALID_STATUSES:
            raise HTTPException(400, f"invalid status (allowed: {sorted(_NEWS_VALID_STATUSES)})")
        sets.append("status = %s"); params.append(body.status)
    if body.notes is not None:
        sets.append("notes = %s"); params.append(body.notes)
    if body.tags is not None:
        sets.append("tags = %s"); params.append(list(body.tags))
    if body.acknowledged_by is not None:
        sets.append("acknowledged_by = %s"); params.append(body.acknowledged_by)
        sets.append("acknowledged_at = now()")
    if not sets:
        raise HTTPException(400, "no fields to update")
    params.append(item_id)

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if body.status is not None:
            cur.execute("SELECT status FROM news_items WHERE id = %s::uuid", (item_id,))
            prev = cur.fetchone()
            prev_status = prev["status"] if prev else None
        cur.execute(
            f"UPDATE news_items SET {', '.join(sets)} WHERE id = %s::uuid RETURNING *",
            params,
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "item not found")
        conn.commit()

    if body.status and prev_status and prev_status != body.status:
        try:
            from webhooks import emit_webhook
            emit_webhook("news_item_status_changed", "news_agent",
                         {"id": item_id, "from": prev_status, "to": body.status})
        except Exception:
            pass
    return _ser_news_item(row)


@app.post("/news/items/bulk", tags=["News"])
def news_items_bulk(body: NewsBulkBody, authorized: bool = Depends(auth)):
    if not body.ids:
        return {"updated": 0}
    if body.action == "set_status":
        if not body.value or body.value not in _NEWS_VALID_STATUSES:
            raise HTTPException(400, "value must be a valid status")
        sql = "UPDATE news_items SET status = %s WHERE id = ANY(%s::uuid[])"
        params = [body.value, body.ids]
    elif body.action == "delete":
        sql = "UPDATE news_items SET status = 'deleted' WHERE id = ANY(%s::uuid[])"
        params = [body.ids]
    elif body.action == "acknowledge":
        ack = body.value or "operator"
        sql = """UPDATE news_items
                    SET acknowledged_by = %s, acknowledged_at = now()
                  WHERE id = ANY(%s::uuid[])"""
        params = [ack, body.ids]
    elif body.action == "clear_acknowledge":
        sql = """UPDATE news_items
                    SET acknowledged_by = NULL, acknowledged_at = NULL
                  WHERE id = ANY(%s::uuid[])"""
        params = [body.ids]
    else:
        raise HTTPException(400, "unknown action")

    with get_db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        conn.commit()
        return {"updated": cur.rowcount}


@app.post("/news/items/{item_id}/match-assets", tags=["News"])
def news_item_match_assets(item_id: str, authorized: bool = Depends(auth)):
    return _news_runner_post("/jobs/match-assets", {"item_id": item_id})


@app.post("/news/items/{item_id}/github-search", tags=["News"])
def news_item_github_search(item_id: str, authorized: bool = Depends(auth)):
    return _news_runner_post("/jobs/github-search", {"item_id": item_id}, timeout=60)


@app.post("/news/items/{item_id}/enrich", tags=["News"])
def news_item_enrich(item_id: str, authorized: bool = Depends(auth)):
    return _news_runner_post("/jobs/enrich", {"item_id": item_id}, timeout=300)


@app.post("/news/deep-search", tags=["News"])
def news_deep_search(body: NewsDeepSearchBody,
                     authorized: bool = Depends(auth)):
    """Run expensive enrichment across every news item matching `topic` —
    proxied to news-runner."""
    return _news_runner_post("/jobs/deep-search", body.model_dump())


@app.get("/news/sources", tags=["News"])
def news_sources_list(authorized: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT id, name, url, parser, enabled,
                      last_fetched_at, last_status, last_error, created_at
                 FROM news_sources ORDER BY name"""
        )
        rows = cur.fetchall()
    return {"results": [{
        "id": str(r["id"]),
        "name": r["name"],
        "url": r["url"],
        "parser": r["parser"],
        "enabled": r["enabled"],
        "last_fetched_at": r["last_fetched_at"].isoformat() if r["last_fetched_at"] else None,
        "last_status": r["last_status"],
        "last_error": r["last_error"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
    } for r in rows]}


@app.post("/news/sources", tags=["News"])
def news_source_create(body: NewsSourceCreate, authorized: bool = Depends(auth)):
    """Add a new news source."""
    # Validate parser type
    if body.parser not in ['rss', 'atom', 'html']:
        raise HTTPException(400, f"Invalid parser type: {body.parser}. Must be one of: rss, atom, html")

    # Check URL format
    if not body.url.startswith(('http://', 'https://')):
        raise HTTPException(400, "URL must start with http:// or https://")

    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if URL already exists
            cur.execute("SELECT id FROM news_sources WHERE url = %s", (body.url,))
            if cur.fetchone():
                raise HTTPException(400, "A news source with this URL already exists")

            # Insert new source
            cur.execute(
                """INSERT INTO news_sources (name, url, parser, enabled)
                   VALUES (%s, %s, %s, %s)
                   RETURNING id, name, url, parser, enabled, created_at""",
                (body.name, body.url, body.parser, body.enabled)
            )
            row = cur.fetchone()
            conn.commit()

            # Emit webhook for new source added
            from webhooks import emit_webhook
            emit_webhook("news_source_added", "rag_api", {
                "id": str(row["id"]),
                "name": row["name"],
                "url": row["url"],
                "parser": row["parser"]
            })

            return {
                "id": str(row["id"]),
                "name": row["name"],
                "url": row["url"],
                "parser": row["parser"],
                "enabled": row["enabled"],
                "created_at": row["created_at"].isoformat(),
                "last_fetched_at": None,
                "last_status": None,
                "last_error": None
            }
    except psycopg2.IntegrityError as e:
        if "unique constraint" in str(e).lower():
            raise HTTPException(400, "A news source with this URL already exists")
        raise HTTPException(500, f"Database error: {str(e)}")


@app.patch("/news/sources/{source_id}", tags=["News"])
def news_source_patch(source_id: str, body: NewsSourcePatch,
                      authorized: bool = Depends(auth)):
    sets = []
    params: list = []
    if body.enabled is not None:
        sets.append("enabled = %s"); params.append(body.enabled)
    if body.url:
        sets.append("url = %s"); params.append(body.url)
    if body.name:
        sets.append("name = %s"); params.append(body.name)
    if not sets:
        raise HTTPException(400, "no fields to update")
    params.append(source_id)
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            f"UPDATE news_sources SET {', '.join(sets)} WHERE id = %s::uuid RETURNING id",
            params,
        )
        if not cur.fetchone():
            raise HTTPException(404, "source not found")
        conn.commit()
    return {"ok": True}


@app.post("/news/sources/{source_id}/refetch", tags=["News"])
def news_source_refetch(source_id: str, authorized: bool = Depends(auth)):
    """Manual refetch of a single source — proxied to news-runner."""
    return _news_runner_post("/jobs/ingest", {"source_id": source_id})


@app.get("/news/stats", tags=["News"])
def news_stats(authorized: bool = Depends(auth)):
    """Counts per status for the page header tiles."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT status, count(*) AS n FROM news_items
                WHERE status <> 'deleted' GROUP BY status"""
        )
        by_status = {r["status"]: r["n"] for r in cur.fetchall()}
        cur.execute("SELECT count(*) AS n FROM news_items WHERE status = 'deleted'")
        deleted = cur.fetchone()["n"]
        cur.execute("SELECT count(*) AS n FROM news_items WHERE kev_listed = true")
        kev = cur.fetchone()["n"]
        cur.execute("SELECT MAX(last_fetched_at) AS t FROM news_sources")
        last_fetched = cur.fetchone()["t"]
    return {
        "by_status": by_status, "deleted": deleted, "kev_listed": kev,
        "last_fetched_at": last_fetched.isoformat() if last_fetched else None,
        "auto_fetch_enabled": os.environ.get("NEWS_AUTO_FETCH", "1") not in ("0", "false", ""),
    }


@app.post("/ingest/recon")
def ingest_recon(file: UploadFile = File(...), source: str = "recon", job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_recon import parse_recon
        stats = parse_recon(path, source=source, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)


class ToolOutputRequest(BaseModel):
    stdout: str
    tool_name: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    job_id: Optional[str] = None
    engagement_id: Optional[str] = None


@app.post("/ingest/tool-output", tags=["Ingest"])
def ingest_tool_output(req: ToolOutputRequest, authorized: bool = Depends(auth)):
    """
    Ingest raw tool stdout and attempt to structure it into findings.

    Tries (in order): JSON parsing, table parsing, CVE extraction,
    URL extraction, key-value extraction, raw text fallback.
    """
    from etl.parse_tool_output import structure_tool_output
    stats = structure_tool_output(
        stdout=req.stdout,
        tool_name=req.tool_name,
        target=req.target,
        port=req.port,
        service=req.service,
        job_id=req.job_id,
        engagement_id=req.engagement_id,
    )
    return {"ok": True, "stats": stats}


@app.post("/ingest/vulnx")
def ingest_vulnx(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_vulnx import parse_vulnx
        stats = parse_vulnx(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/amass")
def ingest_amass(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_amass import parse_amass
        stats = parse_amass(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/gau")
def ingest_gau(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_gau import parse_gau
        stats = parse_gau(path, source="gau", profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/waybackurls")
def ingest_waybackurls(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_gau import parse_gau
        stats = parse_gau(path, source="waybackurls", profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/trufflehog")
def ingest_trufflehog(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_trufflehog import parse_trufflehog
        stats = parse_trufflehog(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/censys")
def ingest_censys(file: UploadFile = File(...), job_id: str = None, search_type: str = "hosts", authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_censys import parse_censys
        stats = parse_censys(path, search_type=search_type, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/ffuf")
def ingest_ffuf(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_ffuf import parse_ffuf
        stats = parse_ffuf(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/netexec")
def ingest_netexec(file: UploadFile = File(...), job_id: str = None, authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_netexec import parse_netexec
        stats = parse_netexec(path, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/impacket")
def ingest_impacket(file: UploadFile = File(...), job_id: str = None, tool: str = "secretsdump", target: str = "", authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_impacket import parse_impacket
        stats = parse_impacket(path, tool=tool, target=target, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/hashcat")
def ingest_hashcat(file: UploadFile = File(...), job_id: str = None, hash_type: str = "unknown", authorized: bool = Depends(auth)):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_hashcat import parse_hashcat
        stats = parse_hashcat(path, hash_type=hash_type, profile="api-upload", job_id=job_id)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/greyhatwarfare")
def ingest_greyhatwarfare(
    file: UploadFile = File(...),
    job_id: str = None,
    background_tasks: BackgroundTasks = None,
    authorized: bool = Depends(auth),
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_greyhatwarfare import parse_greyhatwarfare
        stats = parse_greyhatwarfare(path, profile="api-upload", job_id=job_id)
        # Trigger OSINT agent scan after successful ingest
        if stats.get("findings_inserted", 0) > 0 and background_tasks:
            try:
                from osint_agent import scan_new_findings
                background_tasks.add_task(scan_new_findings, tool="greyhatwarfare")
            except ImportError:
                pass
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/subdomain_takeover")
def ingest_subdomain_takeover(
    file: UploadFile = File(...),
    job_id: str = None,
    background_tasks: BackgroundTasks = None,
    authorized: bool = Depends(auth),
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_subdomain_takeover import parse_subdomain_takeover_file
        stats = parse_subdomain_takeover_file(path, source="subdomain_takeover", scan_id=job_id)
        # Trigger OSINT agent scan after successful ingest
        if stats > 0 and background_tasks:
            try:
                from osint_agent import scan_new_findings
                background_tasks.add_task(scan_new_findings, tool="subdomain_takeover")
            except ImportError:
                pass
        return {"ok": True, "findings_inserted": stats}
    finally:
        os.remove(path)

# ── Cloud tool ingest endpoints ──

@app.post("/ingest/prowler")
def ingest_prowler(
    file: UploadFile = File(...),
    job_id: str = None,
    authorized: bool = Depends(auth),
    background_tasks: BackgroundTasks = None,
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_prowler import parse_prowler
        stats = parse_prowler(path, profile="api-upload", job_id=job_id)
        if background_tasks:
            background_tasks.add_task(_refresh_cloud_suggestions)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/scoutsuite")
def ingest_scoutsuite(
    file: UploadFile = File(...),
    job_id: str = None,
    authorized: bool = Depends(auth),
    background_tasks: BackgroundTasks = None,
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_scoutsuite import parse_scoutsuite
        stats = parse_scoutsuite(path, profile="api-upload", job_id=job_id)
        if background_tasks:
            background_tasks.add_task(_refresh_cloud_suggestions)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/pacu")
def ingest_pacu(
    file: UploadFile = File(...),
    job_id: str = None,
    authorized: bool = Depends(auth),
    background_tasks: BackgroundTasks = None,
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_pacu import parse_pacu
        stats = parse_pacu(path, profile="api-upload", job_id=job_id)
        if background_tasks:
            background_tasks.add_task(_refresh_cloud_suggestions)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/cloudfox")
def ingest_cloudfox(
    file: UploadFile = File(...),
    job_id: str = None,
    authorized: bool = Depends(auth),
    background_tasks: BackgroundTasks = None,
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_cloudfox import parse_cloudfox
        stats = parse_cloudfox(path, profile="api-upload", job_id=job_id)
        if background_tasks:
            background_tasks.add_task(_refresh_cloud_suggestions)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

@app.post("/ingest/azurehound")
def ingest_azurehound(
    file: UploadFile = File(...),
    job_id: str = None,
    authorized: bool = Depends(auth),
    background_tasks: BackgroundTasks = None,
):
    path = _save_upload_to_tmp(file)
    try:
        from etl.parse_azurehound import parse_azurehound
        stats = parse_azurehound(path, profile="api-upload", job_id=job_id)
        if background_tasks:
            background_tasks.add_task(_refresh_cloud_suggestions)
        return {"ok": True, "stats": stats}
    finally:
        os.remove(path)

_MICROBURST_MAX_RETRIES = 3   # 1 initial + 2 retries


def _run_microburst_ingest(job_id: str, path: str, engagement_id: str | None = None):
    """Background worker: parse the MicroBurst bundle, stream progress to jobs.progress,
    write final stats to jobs.result, then refresh cloud suggestions.

    Auto-retries on connection-level psycopg2 errors. Each retry leverages
    the parser's per-file resume mechanism — already-committed files are
    skipped instantly, so retries are cheap and idempotent.
    """
    import psycopg2  # local import: avoid circular issues at module load
    import time

    def _progress(stats: dict):
        try:
            with get_db(autocommit=True) as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE jobs SET progress=%s, status='running', "
                    "progress_updated_at=now() WHERE id=%s::uuid",
                    (Json(stats), job_id),
                )
        except Exception as e:
            log.warning("microburst progress update failed: %s", e)

    final_stats = None
    last_error = None
    try:
        with get_db(autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE jobs SET status='running', started_at=now() WHERE id=%s::uuid",
                (job_id,),
            )

        # Webhook: ingest started
        try:
            from webhooks import emit_webhook
            emit_webhook("microburst_ingest_started", "microburst", {
                "job_id": job_id,
                "engagement_id": engagement_id,
                "path": os.path.basename(path),
            })
        except Exception:
            pass

        from etl.parse_microburst import parse_microburst

        # Retry loop — bounded, with exponential backoff. Connection errors
        # (postgres restart, idle reset, network blip) trigger a retry. Other
        # exceptions propagate immediately and fail the job.
        for attempt in range(1, _MICROBURST_MAX_RETRIES + 1):
            try:
                final_stats = parse_microburst(path, profile="api-upload",
                                               job_id=job_id,
                                               engagement_id=engagement_id,
                                               progress_cb=_progress)
                last_error = None
                break  # success
            except (psycopg2.InterfaceError,
                    psycopg2.OperationalError) as conn_err:
                last_error = conn_err
                log.warning("microburst job %s attempt %d/%d hit connection error: %s",
                            job_id, attempt, _MICROBURST_MAX_RETRIES, conn_err)
                # Record the retry so an operator watching jobs.progress sees it
                try:
                    with get_db(autocommit=True) as conn, conn.cursor() as cur:
                        cur.execute(
                            "UPDATE jobs SET error=%s WHERE id=%s::uuid",
                            (f"retrying after attempt {attempt}/{_MICROBURST_MAX_RETRIES}: "
                             f"{type(conn_err).__name__}: {conn_err}", job_id),
                        )
                except Exception:
                    pass
                # Webhook: retry kicked off
                try:
                    from webhooks import emit_webhook
                    emit_webhook("microburst_ingest_retrying", "microburst", {
                        "job_id": job_id,
                        "engagement_id": engagement_id,
                        "attempt": attempt,
                        "max_attempts": _MICROBURST_MAX_RETRIES,
                        "error": f"{type(conn_err).__name__}: {conn_err}",
                    })
                except Exception:
                    pass
                if attempt < _MICROBURST_MAX_RETRIES:
                    time.sleep(2 * attempt)  # 2s, 4s

        if final_stats is None:
            # All retries exhausted — propagate so the outer except marks failed
            raise last_error if last_error else RuntimeError(
                "microburst ingest failed without an error object")

        with get_db(autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE jobs SET status='finished', finished_at=now(), "
                "result=%s, progress=%s, error=NULL WHERE id=%s::uuid",
                (Json(final_stats), Json(final_stats), job_id),
            )

        _emit_ingest_event("microburst", final_stats)
        try:
            from webhooks import emit_webhook
            files_resumed_skip = int(final_stats.get("files_resumed_skip", 0) or 0)
            if files_resumed_skip > 0:
                emit_webhook("microburst_ingest_resumed", "microburst", {
                    "job_id": job_id,
                    "engagement_id": engagement_id,
                    "files_resumed_skip": files_resumed_skip,
                    "files_processed": final_stats.get("files_processed", 0),
                    "findings_inserted": final_stats.get("findings_inserted", 0),
                })

            emit_webhook("microburst_ingest_completed", "microburst", {
                "files_processed": final_stats.get("files_processed", 0),
                "files_resumed_skip": files_resumed_skip,
                "findings_inserted": final_stats.get("findings_inserted", 0),
                "identities_upserted": final_stats.get("identities_upserted", 0),
                "assets_created": final_stats.get("assets_created", 0),
                "by_type": final_stats.get("by_type", {}),
                "job_id": job_id,
                "engagement_id": engagement_id,
            })
        except Exception:
            pass
        try:
            _refresh_cloud_suggestions()
        except Exception as e:
            log.warning("cloud suggestor refresh after microburst ingest failed: %s", e)
        try:
            _run_vault_auto_import_if_enabled(engagement_id=engagement_id, job_id=job_id)
        except Exception as e:
            log.warning("vault auto-import after microburst ingest failed: %s", e)
    except Exception as e:
        log.exception("microburst background ingest failed for job %s", job_id)
        try:
            with get_db(autocommit=True) as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE jobs SET status='failed', finished_at=now(), error=%s WHERE id=%s::uuid",
                    (f"{type(e).__name__}: {e}", job_id),
                )
        except Exception:
            pass
        # Webhook: final failure
        try:
            from webhooks import emit_webhook
            emit_webhook("microburst_ingest_failed", "microburst", {
                "job_id": job_id,
                "engagement_id": engagement_id,
                "error": f"{type(e).__name__}: {e}",
                "attempts": _MICROBURST_MAX_RETRIES,
            })
        except Exception:
            pass
    finally:
        # Only delete the upload after all retries are done. Without this,
        # a dead-cursor in attempt 1 would leave nothing for attempts 2-3.
        try:
            os.remove(path)
        except Exception:
            pass


@app.post("/ingest/microburst")
def ingest_microburst(
    file: UploadFile = File(...),
    engagement_id: Optional[str] = Form(None),
    authorized: bool = Depends(auth),
    background_tasks: BackgroundTasks = None,
):
    """Ingest a MicroBurst (NetSPI) Azure AD output bundle (.zip / dir-of-CSVs / single CSV).

    When engagement_id is supplied, every CSV in the zip becomes an asset under
    that engagement (ip=127.0.1.1, hostname=<engagement_short>/<filename>) and
    every recon_finding + identity gets the engagement_id stamped.

    Returns immediately with a job_id; ingest runs in a background task so large
    tenant dumps don't time out at the proxy layer. Poll GET /jobs/{job_id}
    for status, progress (jobs.progress jsonb), and final stats (jobs.result jsonb).

    Dedup: refuses with HTTP 409 if a microburst-ingest with the same filename
    AND engagement_id is already running/queued. The body of the response
    includes the existing `job_id` so the operator can poll/inspect that one
    instead of creating a duplicate."""
    filename = getattr(file, "filename", None)

    # Pre-flight dedup. A duplicate run wastes work, races on asset upserts,
    # and confuses the Scan Monitor. Match on filename + engagement scope so
    # uploading the same zip into a different engagement is still allowed.
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, status, started_at, params
            FROM jobs
            WHERE type='microburst-ingest'
              AND status IN ('queued','running')
              AND params->>'filename' = %s
              AND COALESCE(params->>'engagement_id','') = COALESCE(%s, '')
            ORDER BY created_at DESC LIMIT 1
        """, (filename, engagement_id))
        existing = cur.fetchone()
        if existing:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "duplicate_ingest",
                    "message": (
                        f"An ingest of {filename!r} is already "
                        f"{existing['status']} (started {existing['started_at']}). "
                        "Wait for it to finish or cancel it before re-uploading."
                    ),
                    "existing_job_id": str(existing["id"]),
                    "status": existing["status"],
                    "poll": f"/jobs/{existing['id']}",
                },
            )

    path = _save_upload_to_tmp(file)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        eid = _resolve_engagement_id(engagement_id)
        cur.execute(
            "INSERT INTO jobs (type, params, status, engagement_id) "
            "VALUES (%s, %s, 'queued', %s::uuid) RETURNING id",
            (
                "microburst-ingest",
                Json({"filename": filename, "engagement_id": eid}),
                eid,
            ),
        )
        job_id = str(cur.fetchone()["id"])
        conn.commit()

    if background_tasks is not None:
        background_tasks.add_task(_run_microburst_ingest, job_id, path, engagement_id)
    else:
        # No background-task manager available — fall back to synchronous ingest
        _run_microburst_ingest(job_id, path, engagement_id)

    return {"ok": True, "job_id": job_id, "status": "queued",
            "poll": f"/jobs/{job_id}"}


# ── Cloud Scan Suggestor ──

def _refresh_cloud_suggestions():
    """Background task: re-evaluate cloud suggestions after ingest, then run
    AI triage (debounced — back-to-back imports won't spam the LLM)."""
    try:
        import cloud_suggestor
        with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            result = cloud_suggestor.refresh(cur)
        log.info("Cloud suggestor refresh: %s", result)
    except Exception as e:
        log.warning("Cloud suggestor refresh failed: %s", e)

    # Auto-triage after ingest. Built-in 60s debounce means a flurry of
    # ingests in quick succession will only trigger one LLM call.
    # Respects per-agent auto toggle (default ON for cloud_triage — preserves
    # historical behavior; operator can disable from Settings → LLM Tuning).
    if get_agent_auto_enabled("cloud_triage_agent", default=True):
        try:
            import cloud_triage_agent
            with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                triage = cloud_triage_agent.triage_recommendations(cur)
            if triage.get("cached"):
                log.info("Cloud triage debounced (cached run %s)", triage.get("run_id"))
            else:
                log.info("Cloud triage ran: %s actions, %d ranked, latency=%dms",
                         len(triage.get("top_actions") or []),
                         triage.get("ranked_count") or 0,
                         triage.get("latency_ms") or 0)
        except Exception as e:
            log.warning("Cloud triage agent failed (non-fatal): %s", e)
    else:
        log.info("cloud_triage_agent auto-run disabled in settings; skipping")

    # Takeover hunter — fires after recon ingests; agent-level 10-min debounce
    # prevents target hammering on burst events. Off by default because it
    # actively probes external resources via the configured proxy.
    try:
        _run_takeover_hunter_if_enabled()
    except Exception as e:
        log.warning("takeover_hunter post-ingest hook failed: %s", e)


def _run_vault_auto_import_if_enabled(engagement_id: Optional[str] = None,
                                      job_id: Optional[str] = None) -> None:
    """Post-ingest hook: when vault_import_agent.auto_enabled is True, import
    fresh secret findings into credential_vault. Idempotent (skips already-
    imported via source_entity_id), safe to call multiple times. Off by default
    because writing creds is a side-effect operators should opt into."""
    if not get_agent_auto_enabled("vault_import_agent", default=False):
        return
    try:
        import vault_import_agent
        with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            result = vault_import_agent.import_secrets_from_recon(
                cur, engagement_id=engagement_id,
                source="microburst", dry_run=False, limit=500,
            )
        log.info("vault_import auto-run: imported=%s candidates=%s skipped=%s",
                 result.get("imported"), result.get("candidates_examined"),
                 result.get("skipped_already_imported"))
        try:
            from webhooks import emit_webhook
            emit_webhook("vault_import_auto_completed", "vault_import_agent", {
                "job_id": job_id,
                "engagement_id": engagement_id,
                "imported": result.get("imported", 0),
                "candidates_examined": result.get("candidates_examined", 0),
                "skipped_already_imported": result.get("skipped_already_imported", 0),
                "model": result.get("model"),
            })
        except Exception:
            pass
    except Exception as e:
        log.warning("Vault import auto-run failed (non-fatal): %s", e)


@app.get("/cloud/posture")
def cloud_posture(authorized: bool = Depends(auth)):
    """Cloud posture summary: sources imported, finding counts, credential status."""
    import cloud_suggestor
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        return cloud_suggestor.get_posture(cur)


# ── Identities (unified directory of detected users / SPs / guests) ──────────

@app.get("/identities", tags=["Identities"])
def list_identities(
    provider: Optional[str] = Query(None, description="Filter by provider (azure, on_prem_ad, aws, ...)"),
    principal_type: Optional[str] = Query(None, description="Filter by principal_type (user, guest, service_principal, group)"),
    is_admin: Optional[bool] = Query(None),
    is_guest: Optional[bool] = Query(None),
    is_dirsync: Optional[bool] = Query(None),
    has_credential: Optional[bool] = Query(None, description="True to only return identities with a matching credential_vault row"),
    source: Optional[str] = Query(None, description="Filter by membership in sources[] array (e.g. microburst, azurehound)"),
    member_of: Optional[str] = Query(None, description="Filter to members of a specific group (matches the 'member_of:<group>' tag)"),
    search: Optional[str] = Query(None, description="Substring match on identifier or display_name"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    authorized: bool = Depends(auth),
):
    """List identities with optional filters. Includes 'has_credential' boolean per row
    derived from credential_vault.username match."""
    conds = []
    params: list = []
    if provider:
        conds.append("i.provider = %s"); params.append(provider)
    if principal_type:
        conds.append("i.principal_type = %s"); params.append(principal_type)
    if is_admin is not None:
        conds.append("i.is_admin = %s"); params.append(is_admin)
    if is_guest is not None:
        conds.append("i.is_guest = %s"); params.append(is_guest)
    if is_dirsync is not None:
        conds.append("i.is_dirsync = %s"); params.append(is_dirsync)
    if source:
        conds.append("%s = ANY(i.sources)"); params.append(source)
    if member_of:
        # Case-insensitive tag match — operators (and LLMs) often type group
        # names in mixed/lower case, but tags are stored exactly as ingested.
        conds.append("EXISTS (SELECT 1 FROM unnest(i.tags) t WHERE t ILIKE %s)")
        params.append(f"member_of:{member_of[:80]}")
    if search:
        conds.append("(i.identifier ILIKE %s OR i.display_name ILIKE %s)")
        params.extend([f"%{search}%", f"%{search}%"])
    where = (" WHERE " + " AND ".join(conds)) if conds else ""

    sql = f"""
        SELECT i.id, i.provider, i.identifier, i.display_name, i.principal_type,
               i.status, i.mfa_state, i.last_signin, i.tenant_id, i.domain,
               i.is_admin, i.is_guest, i.is_dirsync, i.tags, i.sources,
               i.first_seen, i.last_seen, i.engagement_id,
               EXISTS (
                   SELECT 1 FROM credential_vault cv
                   WHERE LOWER(cv.username) = LOWER(i.identifier)
                      OR LOWER(cv.username || '@' || COALESCE(cv.domain,'')) = LOWER(i.identifier)
               ) AS has_credential
        FROM identities i
        {where}
        ORDER BY i.is_admin DESC, i.last_seen DESC
        LIMIT %s OFFSET %s
    """
    params_full = list(params) + [limit, offset]

    count_sql = f"SELECT count(*) AS n FROM identities i{where}"

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(count_sql, params)
        total = cur.fetchone()["n"]
        cur.execute(sql, params_full)
        rows = cur.fetchall()
        # Optional has_credential filter applied after the EXISTS subquery
        if has_credential is not None:
            rows = [r for r in rows if r["has_credential"] == has_credential]

    def _serialize(r):
        return {
            "id": str(r["id"]),
            "provider": r["provider"],
            "identifier": r["identifier"],
            "display_name": r["display_name"],
            "principal_type": r["principal_type"],
            "status": r["status"],
            "mfa_state": r["mfa_state"],
            "last_signin": r["last_signin"].isoformat() if r["last_signin"] else None,
            "tenant_id": r["tenant_id"],
            "domain": r["domain"],
            "is_admin": r["is_admin"],
            "is_guest": r["is_guest"],
            "is_dirsync": r["is_dirsync"],
            "tags": list(r["tags"] or []),
            "sources": list(r["sources"] or []),
            "first_seen": r["first_seen"].isoformat() if r["first_seen"] else None,
            "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
            "engagement_id": str(r["engagement_id"]) if r["engagement_id"] else None,
            "has_credential": r["has_credential"],
        }

    return {"total": total, "limit": limit, "offset": offset,
            "results": [_serialize(r) for r in rows]}


@app.get("/identities/groups", tags=["Identities"])
def identities_groups(
    search: Optional[str] = Query(None, description="Substring filter on group name (case-insensitive)"),
    min_members: int = Query(1, ge=1, description="Drop groups smaller than this"),
    limit: int = Query(20000, ge=1, le=20000, description="Max rows to return — high default so existing frontend callers keep getting everything; MCP tool defaults to 500"),
    offset: int = Query(0, ge=0, description="Pagination offset for the sorted result"),
    authorized: bool = Depends(auth),
):
    """Distinct group names derived from `member_of:<group>` tags on identities,
    with member counts. Returns `{total, count, limit, offset, results}` so
    callers can page or filter rather than receiving all 14k+ groups in one
    blob (which routinely exceeds chat-UI display caps and LLM context)."""
    # Pass the 'member_of:%' literal as a parameter to avoid psycopg2 trying
    # to interpret the bare `%` as a placeholder when other params are present.
    where = ["t LIKE %s"]
    params: list = ["member_of:%"]
    if search:
        where.append("substring(t FROM 11) ILIKE %s")
        params.append(f"%{search}%")

    where_sql = " AND ".join(where)
    having_sql = "HAVING count(*) >= %s" if min_members > 1 else ""
    having_params = [min_members] if min_members > 1 else []

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Total matching distinct groups (post-filter, pre-pagination).
        cur.execute(
            f"""
            SELECT count(*) AS n FROM (
                SELECT t FROM identities, unnest(tags) AS t
                 WHERE {where_sql}
                 GROUP BY t
                 {having_sql}
            ) sub
            """,
            params + having_params,
        )
        total = cur.fetchone()["n"]

        cur.execute(
            f"""
            SELECT substring(t FROM 11) AS name,
                   count(*)             AS members
              FROM identities, unnest(tags) AS t
             WHERE {where_sql}
             GROUP BY t
             {having_sql}
             ORDER BY count(*) DESC, t ASC
             LIMIT %s OFFSET %s
            """,
            params + having_params + [limit, offset],
        )
        rows = cur.fetchall()
    return {
        "total": total,
        "count": len(rows),
        "limit": limit,
        "offset": offset,
        "results": [{"name": r["name"], "members": r["members"]} for r in rows],
    }


@app.get("/identities/{identity_id}", tags=["Identities"])
def get_identity(identity_id: str, authorized: bool = Depends(auth)):
    """Identity detail with linked credential_vault rows + provenance."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM identities WHERE id=%s::uuid", (identity_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Identity not found")

        cur.execute("""
            SELECT id, username, domain, credential_type, status, source, created_at
            FROM credential_vault
            WHERE LOWER(username) = LOWER(%s)
               OR LOWER(username || '@' || COALESCE(domain,'')) = LOWER(%s)
            ORDER BY created_at DESC
        """, (row["identifier"], row["identifier"]))
        creds = [{
            "id": str(c["id"]), "username": c["username"], "domain": c["domain"],
            "credential_type": c["credential_type"], "status": c["status"],
            "source": c["source"],
            "created_at": c["created_at"].isoformat() if c["created_at"] else None,
        } for c in cur.fetchall()]

        # Recon findings that mention this identifier
        cur.execute("""
            SELECT id, source, finding_type, target, severity, created_at
            FROM recon_findings
            WHERE target = %s OR target ILIKE %s
            ORDER BY created_at DESC LIMIT 200
        """, (row["identifier"], f"%{row['identifier']}%"))
        findings = [{
            "id": str(f["id"]), "source": f["source"], "finding_type": f["finding_type"],
            "target": f["target"], "severity": f["severity"],
            "created_at": f["created_at"].isoformat() if f["created_at"] else None,
        } for f in cur.fetchall()]

    return {
        "id": str(row["id"]),
        "provider": row["provider"], "identifier": row["identifier"],
        "display_name": row["display_name"], "principal_type": row["principal_type"],
        "status": row["status"], "mfa_state": row["mfa_state"],
        "last_signin": row["last_signin"].isoformat() if row["last_signin"] else None,
        "tenant_id": row["tenant_id"], "domain": row["domain"],
        "is_admin": row["is_admin"], "is_guest": row["is_guest"], "is_dirsync": row["is_dirsync"],
        "tags": list(row["tags"] or []),
        "sources": list(row["sources"] or []),
        "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
        "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
        "raw": row["raw"],
        "credentials": creds,
        "recon_findings": findings,
    }


@app.get("/identities/stats/summary", tags=["Identities"])
def identities_summary(authorized: bool = Depends(auth)):
    """Aggregated counts for the Users page header tiles."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                count(*)                                      AS total,
                count(*) FILTER (WHERE is_admin)              AS admins,
                count(*) FILTER (WHERE is_guest)              AS guests,
                count(*) FILTER (WHERE is_dirsync)            AS dirsync,
                count(*) FILTER (WHERE principal_type='service_principal') AS service_principals,
                count(DISTINCT provider)                      AS providers
            FROM identities
        """)
        row = cur.fetchone() or {}
    return dict(row)


@app.get("/cloud/recommendations")
def cloud_recommendations(
    provider: str = Query(None),
    priority: str = Query(None),
    status: str = Query("open"),
    limit: int = Query(100),
    offset: int = Query(0),
    authorized: bool = Depends(auth),
):
    """List cloud scan recommendations with filters."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        conditions = []
        params = []
        if provider:
            conditions.append("provider = %s")
            params.append(provider)
        if priority:
            conditions.append("priority = %s")
            params.append(priority)
        if status:
            conditions.append("status = %s")
            params.append(status)

        where = " AND ".join(conditions) if conditions else "TRUE"
        params.extend([limit, offset])

        # Sort: triage_order (when set) first, then static priority, then created_at.
        # NULLS LAST keeps un-triaged recs visible after AI-ranked ones.
        cur.execute(f"""
            SELECT id, rule_id, rule_name, priority, tool, action,
                   command_hint, import_as, trigger_source, trigger_finding_id,
                   trigger_summary, provider, account_id, status,
                   triage_order, triage_reasoning, triaged_at,
                   created_at
            FROM cloud_scan_recommendations
            WHERE {where}
            ORDER BY
                triage_order ASC NULLS LAST,
                CASE priority
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                END,
                created_at DESC
            LIMIT %s OFFSET %s
        """, params)
        rows = cur.fetchall()

        # Serialize
        for r in rows:
            r["id"] = str(r["id"])
            if r.get("trigger_finding_id"):
                r["trigger_finding_id"] = str(r["trigger_finding_id"])
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
            if r.get("triaged_at"):
                r["triaged_at"] = r["triaged_at"].isoformat()

        return {"recommendations": rows, "count": len(rows)}


@app.post("/cloud/recommendations/refresh")
def cloud_recommendations_refresh(authorized: bool = Depends(auth)):
    """Re-evaluate all cloud rules and insert new recommendations."""
    import cloud_suggestor
    with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        result = cloud_suggestor.refresh(cur)
        return {"ok": True, **result}


@app.patch("/cloud/recommendations/{rec_id}")
def cloud_recommendation_update(
    rec_id: str,
    status: str = Query(...),
    authorized: bool = Depends(auth),
):
    """Update recommendation status (open/accepted/dismissed/completed)."""
    if status not in ("open", "accepted", "dismissed", "completed"):
        raise HTTPException(400, f"Invalid status: {status}")
    with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            UPDATE cloud_scan_recommendations
            SET status = %s
            WHERE id = %s::uuid
            RETURNING id
        """, (status, rec_id))
        if not cur.fetchone():
            raise HTTPException(404, "Recommendation not found")
        return {"ok": True, "id": rec_id, "status": status}


# ── Cloud Triage Agent ─────────────────────────────────────────────────────

@app.post("/cloud/triage/run", tags=["Cloud"])
def cloud_triage_run(
    engagement_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    force: bool = Query(False, description="Bypass debounce / cached result"),
    model: Optional[str] = Query(None, description="Override the triage LLM for this run (e.g. gemma4:latest, deepseek-r1:14b). Auto-bypasses cache."),
    authorized: bool = Depends(auth),
):
    """Run the AI triage agent: re-rank open cloud recommendations and produce
    a top-3 next-actions plan. Idempotent within the debounce window unless force=true.
    Pass `model` to swap the LLM for a single run (useful when the default
    is too slow / not installed)."""
    import cloud_triage_agent
    with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        try:
            result = cloud_triage_agent.triage_recommendations(
                cur, engagement_id=engagement_id, provider=provider,
                force=force, model=model,
            )
        except Exception as e:
            log.exception("cloud_triage_run failed")
            raise HTTPException(500, f"triage failed: {type(e).__name__}: {e}")
    # Webhook so n8n / Slack can react to a fresh ranking
    try:
        from webhooks import emit_webhook
        emit_webhook("cloud_triage_completed", "cloud_triage_agent", {
            "run_id": result.get("run_id"),
            "engagement_id": engagement_id,
            "provider": provider,
            "ranked_count": result.get("ranked_count"),
            "cached": result.get("cached", False),
            "model": result.get("model"),
        })
    except Exception:
        pass
    return {"ok": True, **result}


class VaultImportBody(BaseModel):
    source: str = "microburst"
    finding_types: Optional[List[str]] = None
    engagement_id: Optional[str] = None
    dry_run: bool = True
    limit: int = 200
    model: Optional[str] = None


@app.post("/vault/import-from-recon", tags=["Vault"])
def vault_import_from_recon(body: VaultImportBody, _: bool = Depends(auth)):
    """Run the vault-import agent over recon_findings of a given source/type
    and either preview (dry_run=true) or commit credential_vault rows."""
    import vault_import_agent
    with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        try:
            result = vault_import_agent.import_secrets_from_recon(
                cur,
                engagement_id=body.engagement_id,
                source=body.source,
                finding_types=body.finding_types,
                dry_run=body.dry_run,
                limit=body.limit,
                model=body.model,
            )
        except Exception as e:
            log.exception("vault_import_from_recon failed")
            raise HTTPException(500, f"vault import failed: {type(e).__name__}: {e}")
    if not body.dry_run and result.get("imported"):
        try:
            from webhooks import emit_webhook
            emit_webhook("vault_import_completed", "vault_import_agent", {
                "source": body.source,
                "engagement_id": body.engagement_id,
                "imported": result.get("imported"),
                "proposed": result.get("proposed"),
                "model": result.get("model"),
            })
        except Exception:
            pass
    return {"ok": True, **result}


@app.get("/cloud/triage/latest", tags=["Cloud"])
def cloud_triage_latest(
    engagement_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    authorized: bool = Depends(auth),
):
    """Return the most recent triage run (top_actions + summary). Returns
    {present: false} when no run has been recorded yet."""
    import cloud_triage_agent
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        run = cloud_triage_agent.get_latest_run(cur, engagement_id=engagement_id, provider=provider)
    if run is None:
        return {"present": False}
    return {"present": True, **run}


# ── Subdomain Takeover Hunter ──────────────────────────────────────────────

class TakeoverHuntBody(BaseModel):
    engagement_ids: Optional[list[str]] = None  # None → discover active engagements
    dry_run: bool = False
    limit: int = 5000
    concurrency: int = 50
    force: bool = False  # bypass 10-min debounce


@app.post("/agents/takeover-hunter/run", tags=["Agents"])
def takeover_hunter_run(body: TakeoverHuntBody, _: bool = Depends(auth)):
    """Probe DNS recon findings for dangling cloud-resource takeovers.

    Active engagements only by default. Routes through the configured
    burp/operator proxy. Idempotent: re-running upserts the existing
    `subdomain_takeover` finding rather than duplicating, bumping last_seen
    on each confirmation. Returns a summary keyed by detector id."""
    import takeover_hunter
    with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        try:
            result = takeover_hunter.hunt(
                cur,
                engagement_ids=body.engagement_ids,
                limit=body.limit,
                concurrency=body.concurrency,
                force=body.force,
                dry_run=body.dry_run,
            )
        except Exception as e:
            log.exception("takeover_hunter_run failed")
            raise HTTPException(500, f"takeover hunter failed: {type(e).__name__}: {e}")
    try:
        from webhooks import emit_webhook
        emit_webhook("takeover_hunter_completed", "takeover_hunter", {
            "engagement_ids": result.get("engagement_ids"),
            "candidates_examined": result.get("candidates_examined"),
            "confirmed": result.get("confirmed", 0),
            "inserted": result.get("inserted", 0),
            "updated": result.get("updated", 0),
            "by_detector": result.get("by_detector"),
            "dry_run": body.dry_run,
            "debounced": result.get("debounced", False),
        })
    except Exception:
        pass
    return {"ok": True, **result}


def _run_takeover_hunter_if_enabled(engagement_id: Optional[str] = None) -> None:
    """Post-recon hook. Fires automatically when the agent's auto toggle is
    on AND there's been a fresh recon ingest. Operator must opt in (default
    OFF) because this actively probes external resources via the configured
    proxy. Debounce in the agent itself ensures back-to-back ingests don't
    spam targets."""
    if not get_agent_auto_enabled("takeover_hunter_agent", default=False):
        return
    try:
        import takeover_hunter
        with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            engagement_ids = [engagement_id] if engagement_id else None
            result = takeover_hunter.hunt(
                cur, engagement_ids=engagement_ids, dry_run=False, force=False,
            )
        if result.get("debounced"):
            log.info("takeover_hunter auto-run debounced (next eligible in %ss)",
                     result.get("next_eligible_in_s"))
        else:
            log.info("takeover_hunter auto-run: candidates=%s confirmed=%s inserted=%s",
                     result.get("candidates_examined"),
                     result.get("confirmed"),
                     result.get("inserted"))
    except Exception as e:
        log.warning("takeover_hunter auto-run failed (non-fatal): %s", e)


_STUCK_JOB_TIMEOUT_S = int(os.environ.get("STUCK_JOB_TIMEOUT_S", "300"))   # 5 min default
_STUCK_JOB_SWEEP_S   = int(os.environ.get("STUCK_JOB_SWEEP_S", "600"))    # check every 10 min
_stuck_sweeper_task = None


def _sweep_stuck_jobs_once():
    """Mark running jobs as failed if their progress hasn't been bumped
    within _STUCK_JOB_TIMEOUT_S seconds. COALESCE to started_at so jobs
    that never wrote progress (parser died before first batch) still get
    detected. Returns the list of swept job ids for logging / webhook."""
    swept: list[tuple[str, str, str]] = []  # (id, type, last_bump_at)
    try:
        with get_db(autocommit=True) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                UPDATE jobs
                SET status      = 'failed',
                    finished_at = now(),
                    error       = COALESCE(error || ' | ', '') ||
                                  'auto-sweeper: no progress in '
                                  || %s::int || 's (parser likely died)'
                WHERE status = 'running'
                  AND COALESCE(progress_updated_at, started_at)
                      < now() - (%s::int || ' seconds')::interval
                RETURNING id::text, type,
                    COALESCE(progress_updated_at, started_at)::text AS last_bump
            """, (_STUCK_JOB_TIMEOUT_S, _STUCK_JOB_TIMEOUT_S))
            swept = [(r["id"], r["type"], r["last_bump"]) for r in cur.fetchall()]
    except Exception as e:
        log.warning("stuck-job sweeper query failed: %s", e)
        return []

    if swept:
        log.warning("stuck-job sweeper marked %d job(s) failed: %s",
                    len(swept), [(jid[:8], jt) for jid, jt, _ in swept])
        try:
            from webhooks import emit_webhook
            for jid, jt, last in swept:
                emit_webhook("job_marked_stale", "stuck_job_sweeper", {
                    "job_id": jid, "job_type": jt,
                    "last_progress_at": last,
                    "timeout_s": _STUCK_JOB_TIMEOUT_S,
                })
        except Exception:
            pass
    return swept


async def _stuck_sweeper_loop():
    import asyncio as _asyncio
    log.info("stuck-job sweeper started — sweep every %ds, timeout %ds",
             _STUCK_JOB_SWEEP_S, _STUCK_JOB_TIMEOUT_S)
    while True:
        try:
            await _asyncio.sleep(_STUCK_JOB_SWEEP_S)
            _sweep_stuck_jobs_once()
        except _asyncio.CancelledError:
            raise
        except Exception:
            log.exception("stuck-job sweeper iteration failed")


@app.on_event("startup")
async def startup_event():
    ensure_phase0_schema()
    # Start webhook retry worker for failed delivery retries
    start_retry_worker()
    # Register default catch-all event-log webhook so all events are recorded
    ensure_default_webhook()
    # Sweep stuck/abandoned running jobs on startup, then every 60s
    import asyncio
    global _stuck_sweeper_task
    try:
        _sweep_stuck_jobs_once()  # immediate sweep covers crashes pre-restart
    except Exception:
        log.exception("initial stuck-job sweep failed")
    _stuck_sweeper_task = asyncio.create_task(_stuck_sweeper_loop())
    # News intelligence — fetch + LLM enrichment now lives in the news-runner
    # container; trigger endpoints below proxy to it. The news-runner owns
    # its own scheduler.


@app.on_event("shutdown")
async def shutdown_event():
    # Stop webhook retry worker
    stop_retry_worker()
    global _stuck_sweeper_task
    if _stuck_sweeper_task is not None:
        _stuck_sweeper_task.cancel()

class Job(BaseModel):
    id: str = Field(..., description="Unique identifier for the job")
    type: str = Field(..., description="Type of the job (e.g., masscan-nmap)")
    status: str = Field(..., description="Current status of the job (queued, running, finished, failed, canceled)")
    params: Dict[str, Any] = Field(..., description="Parameters for the job")
    total_tasks: int = Field(0, description="Total number of tasks for the job")
    finished_tasks: int = Field(0, description="Number of finished tasks for the job")
    error: Optional[str] = Field(None, description="Error message if applicable")
    created_at: datetime = Field(..., description="Creation timestamp of the job")
    started_at: Optional[datetime] = Field(None, description="Start timestamp of the job")
    finished_at: Optional[datetime] = Field(None, description="Completion timestamp of the job")

class JobListResponse(BaseModel):
    jobs: List[Job]

@app.get("/jobs/{job_id}")
def get_job_results(job_id: str, authorized: bool = Depends(auth)):
    # Check in-memory DDG jobs first (non-UUID IDs like ai-check-*)
    if job_id in _ddg_jobs:
        job = _ddg_jobs[job_id]
        return {"id": job_id, "status": job["status"], "stage": job.get("stage", ""),
                "stages_done": job.get("stages_done", []),
                "params": {"product": job.get("product"), "version": job.get("version")},
                "result": job.get("result"), "progress": {}}
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        try:
            cur.execute(
                "SELECT id, type, params, result, progress, status, error, "
                "started_at, finished_at, created_at "
                "FROM jobs WHERE id=%s::uuid",
                (job_id,),
            )
        except Exception:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Job not found")

    return {
        "id": str(row["id"]),
        "type": row["type"],
        "params": row["params"],
        "result": row["result"],
        "progress": row["progress"],
        "status": row["status"],
        "error": row["error"],
        "started_at": row["started_at"].isoformat() if row["started_at"] else None,
        "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None,
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }

# added to get details on a specific job
router = APIRouter(prefix="/tasks", tags=["Tasks"])

class Task(BaseModel):
    id: str
    job_id: str
    type: str
    target_host: Optional[str]
    target_port: Optional[int]
    proto: Optional[str]
    status: str
    attempt: int
    last_error: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]

@router.get("/{job_id}", response_model=List[Task])
def get_tasks_for_job(job_id: str, authorized: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM tasks WHERE job_id=%s::uuid", (job_id,))
        rows = cur.fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="No tasks found for this job ID")
    return rows
# adding for vulns
class Vuln(BaseModel):
    id: str = Field(..., description="Unique identifier for the vulnerability")
    script: str = Field(..., description="Nmap script used to detect the vulnerability")
    output: str = Field(..., description="Detailed output from the NSE script")
    ip: Optional[str] = Field(None, description="IP address of the asset")
    port: Optional[int] = Field(None, description="Port number where the vulnerability was found")
    proto: Optional[str] = Field(None, description="Protocol (tcp/udp)")
    service: Optional[str] = Field(None, description="Service running on the port")
    product: Optional[str] = Field(None, description="Product name of the service")
    version: Optional[str] = Field(None, description="Version of the service")
    banner: Optional[str] = Field(None, description="Banner from the service")
    created_at: datetime = Field(..., description="Timestamp when the vulnerability was found")

class VulnListResponse(BaseModel):
    vulns: List[Vuln]

@app.get("/vulns")
def get_vulnerabilities(
    ip: Optional[str] = Query(None, description="Filter by IP address"),
    script_type: Optional[str] = Query(None, description="Filter by Nmap script type"),
    severity: Optional[str] = Query(None, description="Filter by severity (info/low/medium/high/critical)"),
    search: Optional[str] = Query(None, description="Substring match on script / output / banner (case-insensitive)"),
    limit: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0, description="Pagination offset for retrieving > limit rows"),
    authorized: bool = Depends(auth)
):
    # Construct the SQL query with optional filters
    where = []
    params = []

    if ip:
        where.append("host(a.ip)=%s")
        params.append(ip)

    if script_type:
        where.append("v.script=%s")
        params.append(script_type)

    if severity:
        where.append("v.severity=%s")
        params.append(severity)

    if search:
        where.append("(v.script ILIKE %s OR v.output ILIKE %s OR p.banner ILIKE %s)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    where_sql = "WHERE " + " AND ".join(where) if where else ""

    count_sql = f"""
        SELECT count(*) AS n FROM public.vulns v
        JOIN public.ports p ON v.port_id = p.id
        JOIN public.assets a ON p.asset_id = a.id
        {where_sql}
    """

    sql = f"""
        SELECT v.id,
               v.script, v.output,
               host(a.ip)::text AS ip,
               p.port, p.proto, p.service, p.product, p.version, p.banner,
               v.created_at
        FROM public.vulns v
        JOIN public.ports p ON v.port_id = p.id
        JOIN public.assets a ON p.asset_id = a.id
        {where_sql}
        ORDER BY v.created_at DESC
        LIMIT %s OFFSET %s
    """

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(count_sql, params)
        total = cur.fetchone()["n"]
        cur.execute(sql, params + [limit, offset])
        rows = cur.fetchall()

    # Vuln model expects an `id` (UUID); psycopg2 returns the UUID type which Pydantic
    # accepts. Stringify other UUIDs for downstream serializers if needed.
    vulns = [Vuln(**row) for row in rows]
    return {"vulns": vulns, "total": total, "count": len(vulns), "limit": limit, "offset": offset}


# --- Unified Findings Search ---

class UnifiedFinding(BaseModel):
    id: str = Field(..., description="Unique identifier")
    source: str = Field(..., description="Source scanner (nmap, nuclei, zap, gobuster, playwright)")
    asset_id: Optional[str] = Field(None, description="Asset UUID")
    ip: Optional[str] = Field(None, description="IP address")
    hostname: Optional[str] = Field(None, description="DNS hostname")
    port: Optional[int] = Field(None, description="Port number")
    url: Optional[str] = Field(None, description="URL (for web findings)")
    severity: Optional[str] = Field(None, description="Severity level")
    title: str = Field(..., description="Finding title/name")
    evidence: Optional[str] = Field(None, description="Evidence or output")
    cve: List[str] = Field(default_factory=list, description="CVE identifiers")
    cwe: List[str] = Field(default_factory=list, description="CWE identifiers")
    cvss: Optional[float] = Field(None, description="CVSS score")
    method: Optional[str] = Field(None, description="HTTP method (for web findings)")
    description: Optional[str] = Field(None, description="Full description of the finding")
    solution: Optional[str] = Field(None, description="Remediation guidance")
    reference: Optional[str] = Field(None, description="External references")
    confidence: Optional[str] = Field(None, description="Confidence level (High, Medium, Low)")
    tags: Optional[list] = Field(None, description="User-assigned tags")
    created_at: datetime = Field(..., description="When the finding was created")


class SearchAggregations(BaseModel):
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_source: Dict[str, int] = Field(default_factory=dict)


class UnifiedSearchResponse(BaseModel):
    findings: List[UnifiedFinding]
    total: int
    aggregations: SearchAggregations


@app.get("/findings/search", response_model=UnifiedSearchResponse, tags=["Findings"])
def search_findings(
    severity: Optional[List[str]] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    source: Optional[List[str]] = Query(None, description="Filter by source (nmap, nuclei, zap, gobuster, playwright)"),
    ip: Optional[str] = Query(None, description="Filter by IP address"),
    asset_id: Optional[str] = Query(None, description="Filter by asset UUID"),
    cve: Optional[str] = Query(None, description="Search for CVE (e.g., CVE-2024)"),
    cwe: Optional[str] = Query(None, description="Search for CWE (e.g., CWE-79)"),
    search: Optional[str] = Query(None, description="Free-text search in title/evidence"),
    port: Optional[int] = Query(None, description="Filter by port number"),
    date_from: Optional[datetime] = Query(None, description="Created after this date"),
    date_to: Optional[datetime] = Query(None, description="Created before this date"),
    workflow_status: Optional[List[str]] = Query(None, description="Filter by workflow status (new, triaging, confirmed, false_positive, accepted_risk, in_report, deferred)"),
    engagement_id: Optional[str] = Query(None, description="Filter by engagement ID"),
    tags: Optional[List[str]] = Query(None, description="Filter by tags (findings must have ALL specified tags)"),
    limit: int = Query(100, ge=1, le=1000, description="Max results to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    authorized: bool = Depends(auth)
):
    """
    Search across all vulnerability and finding tables (vulns, web_findings, playwright_findings).
    Returns unified results with aggregations by severity and source.
    """
    # Build the base UNION query
    base_query = """
    WITH unified AS (
        -- From vulns table (nmap/nuclei/ssh-audit/sslscan/etc)
        SELECT
            v.id::text,
            CASE
                WHEN v.metadata->>'source' LIKE 'nuclei:%%' THEN 'nuclei'
                WHEN v.metadata->>'tool' IS NOT NULL THEN v.metadata->>'tool'
                WHEN v.script = 'vulnx' THEN 'vulnx'
                WHEN v.script LIKE 'ssh-audit:%%' THEN 'ssh-audit'
                WHEN v.script LIKE 'sslscan:%%' THEN 'sslscan'
                WHEN v.script LIKE 'testssl:%%' THEN 'testssl'
                WHEN v.script LIKE 'sslyze:%%' THEN 'sslyze'
                WHEN v.script LIKE 'nmap-%%' OR v.script LIKE 'nmap:%%' THEN 'nmap'
                WHEN v.script LIKE 'vulscan:%%' THEN 'vulscan'
                WHEN v.script LIKE 'vulners:%%' THEN 'vulners'
                WHEN v.script LIKE '%%:%%' THEN split_part(v.script, ':', 1)
                ELSE 'nmap'
            END as source,
            v.asset_id::text,
            COALESCE(host(a.ip)::text, '') as ip,
            a.hostname,
            COALESCE(p.port, (v.metadata->>'port')::int) as port,
            v.metadata->>'url' as url,
            v.severity,
            COALESCE(v.title, v.script) as title,
            LEFT(v.output, 500) as evidence,
            COALESCE(v.cve, ARRAY[]::text[]) as cve,
            ARRAY[]::text[] as cwe,
            v.cvss,
            NULL::text as method,
            NULL::text as description,
            NULL::text as solution,
            NULL::text as reference,
            NULL::text as confidence,
            COALESCE(v.tags, ARRAY[]::text[]) as tags,
            v.created_at,
            v.workflow_status,
            v.assigned_to,
            v.verified_by,
            v.verified_at,
            v.tester_notes,
            v.original_severity,
            v.report_ready,
            v.engagement_id::text,
            'vuln' as finding_source
        FROM vulns v
        LEFT JOIN assets a ON a.id = v.asset_id
        LEFT JOIN ports p ON p.id = v.port_id

        UNION ALL

        -- From web_findings table (zap/gobuster)
        SELECT
            wf.id::text,
            wf.source,
            wf.asset_id::text,
            COALESCE(host(a.ip)::text, split_part(split_part(wf.url, '://', 2), '/', 1), split_part(split_part(wf.url, '://', 2), ':', 1)) as ip,
            a.hostname,
            wf.port,
            wf.url,
            wf.severity,
            wf.name as title,
            LEFT(wf.evidence, 500) as evidence,
            ARRAY[]::text[] as cve,
            COALESCE(wf.cwe, ARRAY[]::text[]) as cwe,
            NULL::float as cvss,
            wf.method,
            LEFT(wf.description, 1000) as description,
            LEFT(wf.solution, 1000) as solution,
            LEFT(wf.reference, 500) as reference,
            wf.confidence,
            COALESCE(wf.user_tags, ARRAY[]::text[]) as tags,
            wf.created_at,
            wf.workflow_status,
            wf.assigned_to,
            wf.verified_by,
            wf.verified_at,
            wf.tester_notes,
            wf.original_severity,
            wf.report_ready,
            wf.engagement_id::text,
            'web' as finding_source
        FROM web_findings wf
        LEFT JOIN assets a ON a.id = wf.asset_id

        UNION ALL

        -- From playwright_findings table
        SELECT
            pf.id::text,
            'playwright' as source,
            pf.asset_id::text,
            COALESCE(host(a.ip)::text, split_part(split_part(pf.url, '://', 2), '/', 1), split_part(split_part(pf.url, '://', 2), ':', 1)) as ip,
            a.hostname,
            COALESCE(
                (substring(pf.url from '://[^/:]+:(\d+)'))::int,
                CASE WHEN pf.url LIKE 'https://%%' THEN 443 WHEN pf.url LIKE 'http://%%' THEN 80 ELSE NULL END
            ) as port,
            pf.url,
            pf.severity,
            pf.title,
            LEFT(pf.evidence, 500) as evidence,
            ARRAY[]::text[] as cve,
            COALESCE(pf.cwe, ARRAY[]::text[]) as cwe,
            NULL::float as cvss,
            NULL::text as method,
            LEFT(pf.description, 1000) as description,
            pf.remediation as solution,
            NULL::text as reference,
            NULL::text as confidence,
            COALESCE(pf.tags, ARRAY[]::text[]) as tags,
            pf.created_at,
            pf.workflow_status,
            pf.assigned_to,
            pf.verified_by,
            pf.verified_at,
            pf.tester_notes,
            pf.original_severity,
            pf.report_ready,
            pf.engagement_id::text,
            'playwright' as finding_source
        FROM playwright_findings pf
        LEFT JOIN assets a ON a.id = pf.asset_id

        UNION ALL

        -- From ports table (nmap/masscan port scans)
        SELECT
            pt.id::text,
            'portscan' as source,
            pt.asset_id::text,
            COALESCE(host(a.ip)::text, '') as ip,
            a.hostname,
            pt.port,
            NULL::text as url,
            CASE WHEN pt.service = 'tcpwrapped' THEN 'info' ELSE 'recon' END as severity,
            COALESCE(pt.service, '') || ' ' || COALESCE(pt.product, '') || ' ' || COALESCE(pt.version, '') as title,
            CASE WHEN pt.is_open THEN 'open' ELSE 'closed' END || '/' || pt.proto || ' ' || COALESCE(pt.service, '?') || COALESCE(' ' || pt.product || ' ' || pt.version, '') || COALESCE(' banner=' || LEFT(pt.banner, 100), '') as evidence,
            ARRAY[]::text[] as cve,
            ARRAY[]::text[] as cwe,
            NULL::float as cvss,
            NULL::text as method,
            NULL::text as description,
            NULL::text as solution,
            NULL::text as reference,
            NULL::text as confidence,
            ARRAY[]::text[] as tags,
            pt.created_at,
            NULL::text as workflow_status,
            NULL::text as assigned_to,
            NULL::text as verified_by,
            NULL::timestamptz as verified_at,
            NULL::text as tester_notes,
            NULL::text as original_severity,
            NULL::boolean as report_ready,
            NULL::text as engagement_id,
            'portscan' as finding_source
        FROM ports pt
        LEFT JOIN assets a ON a.id = pt.asset_id
        WHERE pt.is_open = true
    )
    SELECT * FROM unified
    """

    # Build WHERE clause with psycopg2 %s placeholders
    where_clauses_pg = []
    params_pg: List[Any] = []

    if severity:
        where_clauses_pg.append("severity = ANY(%s::text[])")
        params_pg.append(list(severity))

    if source:
        where_clauses_pg.append("source = ANY(%s::text[])")
        params_pg.append(list(source))

    if ip:
        where_clauses_pg.append("ip = %s")
        params_pg.append(ip)

    if asset_id:
        where_clauses_pg.append("asset_id = %s")
        params_pg.append(asset_id)

    if port:
        where_clauses_pg.append("port = %s")
        params_pg.append(port)

    if cve:
        where_clauses_pg.append("EXISTS (SELECT 1 FROM unnest(cve) c WHERE c ILIKE %s)")
        params_pg.append(f"%{cve}%")

    if cwe:
        where_clauses_pg.append("EXISTS (SELECT 1 FROM unnest(cwe) c WHERE c ILIKE %s)")
        params_pg.append(f"%{cwe}%")

    if search:
        where_clauses_pg.append(
            "(title ILIKE %s OR evidence ILIKE %s"
            " OR description ILIKE %s OR url ILIKE %s"
            " OR solution ILIKE %s OR reference ILIKE %s)"
        )
        for _ in range(6):
            params_pg.append(f"%{search}%")

    if date_from:
        where_clauses_pg.append("created_at >= %s")
        params_pg.append(date_from)

    if date_to:
        where_clauses_pg.append("created_at <= %s")
        params_pg.append(date_to)

    if workflow_status:
        where_clauses_pg.append("workflow_status = ANY(%s::text[])")
        params_pg.append(list(workflow_status))

    if engagement_id:
        # Match findings directly linked to engagement OR whose IP is in the engagement's scope
        where_clauses_pg.append(
            "(engagement_id = %s OR ip IN ("
            "  SELECT target FROM scope_targets WHERE name = ("
            "    SELECT scope_name FROM engagements WHERE id = %s::uuid"
            "  ) AND target_type = 'ip'"
            "))"
        )
        params_pg.append(engagement_id)
        params_pg.append(engagement_id)

    if tags:
        where_clauses_pg.append("tags @> %s::text[]")
        params_pg.append(tags)

    where_sql = ""
    if where_clauses_pg:
        where_sql = "WHERE " + " AND ".join(where_clauses_pg)

    # Main query for results — order by severity rank then date
    severity_order = """
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'low'      THEN 4
        WHEN 'info'     THEN 5
        WHEN 'recon'    THEN 6
        ELSE 7
    END
    """
    main_sql = f"""
    {base_query}
    {where_sql}
    ORDER BY {severity_order}, created_at DESC
    LIMIT %s OFFSET %s
    """
    params_pg.extend([limit, offset])

    # Count query
    count_sql = f"""
    {base_query}
    {where_sql}
    """

    # Aggregation query
    agg_sql = f"""
    WITH unified AS (
        SELECT
            CASE
                WHEN v.metadata->>'source' LIKE 'nuclei:%%' THEN 'nuclei'
                WHEN v.metadata->>'tool' IS NOT NULL THEN v.metadata->>'tool'
                WHEN v.script LIKE '%%:%%' THEN split_part(v.script, ':', 1)
                ELSE 'nmap'
            END as source,
            v.severity
        FROM vulns v
        UNION ALL
        SELECT wf.source, wf.severity FROM web_findings wf
        UNION ALL
        SELECT 'playwright' as source, pf.severity FROM playwright_findings pf
        UNION ALL
        SELECT 'portscan' as source, CASE WHEN service = 'tcpwrapped' THEN 'info' ELSE 'recon' END as severity FROM ports WHERE is_open = true
    )
    SELECT
        COALESCE(severity, 'recon') as severity,
        source,
        COUNT(*) as cnt
    FROM unified
    GROUP BY COALESCE(severity, 'recon'), source
    """

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get results
        cur.execute(main_sql, params_pg)
        rows = cur.fetchall()

        # Get total count (without limit/offset)
        count_params = params_pg[:-2]  # Remove limit and offset
        cur.execute(f"SELECT COUNT(*) as total FROM ({count_sql}) sub", count_params)
        total = cur.fetchone()["total"]

        # Get aggregations
        cur.execute(agg_sql)
        agg_rows = cur.fetchall()

    # Process aggregations
    by_severity: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    for row in agg_rows:
        sev = row["severity"] or "unknown"
        src = row["source"] or "unknown"
        cnt = row["cnt"]
        by_severity[sev] = by_severity.get(sev, 0) + cnt
        by_source[src] = by_source.get(src, 0) + cnt

    # Convert rows to UnifiedFinding objects
    findings = []
    for row in rows:
        findings.append(UnifiedFinding(
            id=row["id"],
            source=row["source"],
            asset_id=row["asset_id"],
            ip=row["ip"],
            hostname=row.get("hostname"),
            port=row["port"],
            url=row["url"],
            severity=row["severity"],
            title=row["title"] or "Unknown",
            evidence=row["evidence"],
            cve=row["cve"] or [],
            cwe=row["cwe"] or [],
            cvss=row["cvss"],
            method=row.get("method"),
            description=row.get("description"),
            solution=row.get("solution"),
            reference=row.get("reference"),
            confidence=row.get("confidence"),
            tags=row.get("tags") or [],
            created_at=row["created_at"]
        ))

    return UnifiedSearchResponse(
        findings=findings,
        total=total,
        aggregations=SearchAggregations(
            by_severity=by_severity,
            by_source=by_source
        )
    )


class NoteRequest(BaseModel):
    source: str
    url: str
    name: str
    severity: str = "info"
    evidence: Optional[str] = None


@app.post("/findings/note", tags=["Findings"])
def create_finding_note(note: NoteRequest, authorized: bool = Depends(auth)):
    """
    Insert an informational finding into web_findings.

    Used to log scan executions so they appear in unified findings search and reports.
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO web_findings (url, source, name, severity, evidence, issue_type)
               VALUES (%s, %s, %s, %s, %s, 'scan_execution')
               RETURNING id""",
            (note.url, note.source, note.name, note.severity, note.evidence),
        )
        row = cur.fetchone()
        conn.commit()
    return {"ok": True, "id": str(row["id"])}


@app.get("/last-completed-scan")
def get_last_completed_scan(authorized: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Query the most recent completed job
        cur.execute(
            "SELECT id, params, results, status FROM jobs WHERE status='completed' ORDER BY created_at DESC LIMIT 1"
        )
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="No completed scan found")

    return {
        "id": str(row["id"]),
        "params": row["params"],
        "results": row["results"],
        "status": row["status"]
    }


class CleanupResponse(BaseModel):
    """Response from cleanup operation"""
    web_findings_deleted: int = 0
    playwright_findings_deleted: int = 0
    playwright_scans_deleted: int = 0
    vulns_deleted: int = 0
    dry_run: bool = False
    message: str = ""


@app.post("/cleanup/findings", response_model=CleanupResponse, tags=["Cleanup"])
def cleanup_findings(
    sources: str = Query(
        default="all",
        description="Comma-separated sources to clean: 'all', 'web', 'playwright', 'vulns', or specific sources like 'zap,gobuster'"
    ),
    older_than_hours: Optional[int] = Query(
        default=None,
        ge=1,
        description="Only delete findings older than this many hours (optional)"
    ),
    dry_run: bool = Query(
        default=False,
        description="If true, show what would be deleted without actually deleting"
    ),
    authorized: bool = Depends(auth)
):
    """
    Delete web findings, playwright findings, and/or vulnerability records.

    Sources:
    - 'all': Delete from all tables (web_findings, playwright_findings, vulns)
    - 'web': Delete from web_findings only (includes zap, gobuster)
    - 'playwright': Delete from playwright_findings and playwright_scans
    - 'vulns': Delete from vulns table only
    - Specific sources: 'zap', 'gobuster', etc. (filters web_findings by source)

    Use dry_run=true to preview what would be deleted.
    """
    result = CleanupResponse(dry_run=dry_run)
    source_list = [s.strip().lower() for s in sources.split(',') if s.strip()]

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Build time filter if specified
        time_filter = ""
        time_params = []
        if older_than_hours:
            time_filter = " AND created_at < now() - interval '%s hours'"
            time_params = [older_than_hours]

        # Determine what to clean
        clean_web = 'all' in source_list or 'web' in source_list
        clean_playwright = 'all' in source_list or 'playwright' in source_list
        clean_vulns = 'all' in source_list or 'vulns' in source_list

        # Check for specific web sources (zap, gobuster, etc.)
        specific_sources = [s for s in source_list if s not in ('all', 'web', 'playwright', 'vulns')]

        if dry_run:
            # Count what would be deleted
            if clean_web or specific_sources:
                if specific_sources:
                    placeholders = ','.join(['%s'] * len(specific_sources))
                    cur.execute(
                        f"SELECT COUNT(*) as cnt FROM web_findings WHERE source IN ({placeholders})" +
                        (time_filter if time_filter else ""),
                        specific_sources + time_params
                    )
                else:
                    cur.execute(
                        "SELECT COUNT(*) as cnt FROM web_findings WHERE 1=1" + time_filter,
                        time_params if time_params else None
                    )
                result.web_findings_deleted = cur.fetchone()['cnt']

            if clean_playwright:
                cur.execute(
                    "SELECT COUNT(*) as cnt FROM playwright_findings WHERE 1=1" + time_filter,
                    time_params if time_params else None
                )
                result.playwright_findings_deleted = cur.fetchone()['cnt']

                cur.execute(
                    "SELECT COUNT(*) as cnt FROM playwright_scans WHERE 1=1" + time_filter,
                    time_params if time_params else None
                )
                result.playwright_scans_deleted = cur.fetchone()['cnt']

            if clean_vulns:
                cur.execute(
                    "SELECT COUNT(*) as cnt FROM vulns WHERE 1=1" + time_filter,
                    time_params if time_params else None
                )
                result.vulns_deleted = cur.fetchone()['cnt']

            total = (result.web_findings_deleted + result.playwright_findings_deleted +
                     result.playwright_scans_deleted + result.vulns_deleted)
            result.message = f"Dry run: would delete {total} total records"

        else:
            # Actually delete
            if clean_web or specific_sources:
                if specific_sources:
                    placeholders = ','.join(['%s'] * len(specific_sources))
                    cur.execute(
                        f"DELETE FROM web_findings WHERE source IN ({placeholders})" +
                        (time_filter if time_filter else ""),
                        specific_sources + time_params
                    )
                else:
                    cur.execute(
                        "DELETE FROM web_findings WHERE 1=1" + time_filter,
                        time_params if time_params else None
                    )
                result.web_findings_deleted = cur.rowcount

            if clean_playwright:
                # Delete findings first (FK constraint)
                cur.execute(
                    "DELETE FROM playwright_findings WHERE 1=1" + time_filter,
                    time_params if time_params else None
                )
                result.playwright_findings_deleted = cur.rowcount

                # Then delete scans
                cur.execute(
                    "DELETE FROM playwright_scans WHERE 1=1" + time_filter,
                    time_params if time_params else None
                )
                result.playwright_scans_deleted = cur.rowcount

            if clean_vulns:
                cur.execute(
                    "DELETE FROM vulns WHERE 1=1" + time_filter,
                    time_params if time_params else None
                )
                result.vulns_deleted = cur.rowcount

            conn.commit()

            total = (result.web_findings_deleted + result.playwright_findings_deleted +
                     result.playwright_scans_deleted + result.vulns_deleted)
            result.message = f"Deleted {total} total records"

    return result


# --- RAG/Exploit Search Proxy ---
# Proxy requests to the scan_recommender service which has ExploitDB access

SCAN_RECOMMENDER_URL = os.environ.get("SCAN_RECOMMENDER_URL", "https://scan-recommender:8013")
EXPLOIT_RUNNER_URL = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")


class EnhancedExploitResult(BaseModel):
    """Individual exploit search result."""
    edb_id: Optional[int] = None
    module_path: Optional[str] = None
    title: str
    source: str  # "exploitdb" or "metasploit"
    confidence: float
    cve_match: bool = False
    service_match: bool = False
    version_match: bool = False
    snippet: Optional[str] = None
    path: Optional[str] = None
    platform: Optional[str] = None
    exploit_type: Optional[str] = None


class EnhancedExploitSearchResponse(BaseModel):
    """Response from enhanced exploit search."""
    query: Dict[str, Any]
    exploitdb: List[EnhancedExploitResult]
    metasploit: List[EnhancedExploitResult]
    total_matches: int
    exploitdb_count: int = 0
    metasploit_count: int = 0


@app.get("/rag/search/enhanced", response_model=EnhancedExploitSearchResponse, tags=["RAG/Exploits"])
def enhanced_exploit_search(
    cve: Optional[str] = Query(None, description="CVE ID to search for (e.g., CVE-2017-7494)"),
    service: Optional[str] = Query(None, description="Service name (e.g., samba, apache, openssh)"),
    version: Optional[str] = Query(None, description="Service version (e.g., 2.4.49, 7.4)"),
    port: Optional[int] = Query(None, description="Target port for context"),
    query: Optional[str] = Query(None, description="Additional search terms"),
    top_k: int = Query(10, ge=1, le=50, description="Max results per source"),
    min_confidence: float = Query(0.2, ge=0.0, le=1.0, description="Minimum confidence threshold"),
    authorized: bool = Depends(auth)
):
    """
    Search for exploits matching CVE, service, or version.

    Proxies to the scan_recommender service which has access to:
    - ExploitDB database (CSV and embedded vectors)
    - Metasploit module cache

    Returns matching exploits with confidence scores based on:
    - CVE exact match: +0.4
    - Service name match: +0.25
    - Version match: +0.2
    - Verified exploit: +0.05

    Used by ETL parsers to correlate findings with known exploits
    and trigger finding_exploitable webhooks.
    """
    try:
        # Build query params
        params = {}
        if cve:
            params["cve"] = cve
        if service:
            params["service"] = service
        if version:
            params["version"] = version
        if port:
            params["port"] = port
        if query:
            params["query"] = query
        params["top_k"] = top_k
        params["min_confidence"] = min_confidence

        # Forward to scan_recommender
        resp = requests.get(
            f"{SCAN_RECOMMENDER_URL}/rag/search/enhanced",
            params=params,
            timeout=30,
            verify=False
        )

        if resp.status_code == 200:
            data = resp.json()
            # Add convenience counts
            data["exploitdb_count"] = len(data.get("exploitdb", []))
            data["metasploit_count"] = len(data.get("metasploit", []))
            return data
        else:
            # Return empty results on error (don't fail the calling ETL)
            return EnhancedExploitSearchResponse(
                query={"cve": cve, "service": service, "version": version, "port": port, "query": query},
                exploitdb=[],
                metasploit=[],
                total_matches=0,
                exploitdb_count=0,
                metasploit_count=0
            )

    except requests.RequestException as e:
        # Log but don't fail - return empty results
        import logging
        logging.getLogger("rag-api").warning(f"Exploit search proxy failed: {e}")
        return EnhancedExploitSearchResponse(
            query={"cve": cve, "service": service, "version": version, "port": port, "query": query},
            exploitdb=[],
            metasploit=[],
            total_matches=0,
            exploitdb_count=0,
            metasploit_count=0
        )


## --- Maintenance endpoints ---

@app.get("/maintenance/stats", tags=["Maintenance"])
def maintenance_stats(authorized: bool = Depends(auth)):
    """Return row counts for key database tables."""
    tables = [
        "assets", "ports", "scans", "findings", "web_findings", "vulns",
        "playwright_findings", "playwright_scans", "jobs", "tasks",
        "agent_sessions", "agent_messages", "scan_recommendations",
        "recon_findings", "credential_findings",
    ]
    counts = {}
    with get_db() as conn, conn.cursor() as cur:
        for t in tables:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {t}")
                counts[t] = cur.fetchone()[0]
            except Exception:
                conn.rollback()
                counts[t] = -1
    return counts


@app.post("/cleanup/jobs", tags=["Maintenance"])
def cleanup_jobs(
    older_than_hours: Optional[int] = Query(default=None, ge=1),
    dry_run: bool = Query(default=False),
    authorized: bool = Depends(auth),
):
    """Delete finished/failed/canceled jobs and their tasks."""
    time_filter = ""
    time_params: list = []
    if older_than_hours:
        time_filter = " AND j.finished_at < now() - interval '%s hours'"
        time_params = [older_than_hours]

    with get_db() as conn, conn.cursor() as cur:
        count_sql = (
            "SELECT COUNT(*) FROM jobs j WHERE j.status IN ('finished','failed','canceled')"
            + time_filter
        )
        cur.execute(count_sql, time_params or None)
        job_count = cur.fetchone()[0]

        task_sql = (
            "SELECT COUNT(*) FROM tasks t JOIN jobs j ON t.job_id = j.id"
            " WHERE j.status IN ('finished','failed','canceled')" + time_filter
        )
        cur.execute(task_sql, time_params or None)
        task_count = cur.fetchone()[0]

        if dry_run:
            return {"dry_run": True, "jobs": job_count, "tasks": task_count}

        # tasks first (FK), then jobs
        del_tasks = (
            "DELETE FROM tasks t USING jobs j WHERE t.job_id = j.id"
            " AND j.status IN ('finished','failed','canceled')" + time_filter
        )
        cur.execute(del_tasks, time_params or None)
        tasks_deleted = cur.rowcount

        del_jobs = (
            "DELETE FROM jobs j WHERE j.status IN ('finished','failed','canceled')"
            + time_filter
        )
        cur.execute(del_jobs, time_params or None)
        jobs_deleted = cur.rowcount
        conn.commit()

    return {"dry_run": False, "jobs": jobs_deleted, "tasks": tasks_deleted}


@app.post("/cleanup/sessions", tags=["Maintenance"])
def cleanup_sessions(
    older_than_hours: Optional[int] = Query(default=None, ge=1),
    dry_run: bool = Query(default=False),
    authorized: bool = Depends(auth),
):
    """Delete agent sessions and their messages."""
    time_filter = ""
    time_params: list = []
    if older_than_hours:
        time_filter = " WHERE created_at < now() - interval '%s hours'"
        time_params = [older_than_hours]

    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM agent_sessions" + time_filter, time_params or None)
        session_count = cur.fetchone()[0]

        if older_than_hours:
            msg_filter = " WHERE session_id IN (SELECT id FROM agent_sessions" + time_filter + ")"
            cur.execute("SELECT COUNT(*) FROM agent_messages" + msg_filter, time_params or None)
        else:
            cur.execute("SELECT COUNT(*) FROM agent_messages")
        message_count = cur.fetchone()[0]

        if dry_run:
            return {"dry_run": True, "sessions": session_count, "messages": message_count}

        # messages first (FK), then sessions
        if older_than_hours:
            cur.execute("DELETE FROM agent_messages" + msg_filter, time_params or None)
        else:
            cur.execute("DELETE FROM agent_messages")
        messages_deleted = cur.rowcount

        cur.execute("DELETE FROM agent_sessions" + time_filter, time_params or None)
        sessions_deleted = cur.rowcount
        conn.commit()

    return {"dry_run": False, "sessions": sessions_deleted, "messages": messages_deleted}


@app.post("/cleanup/scans", tags=["Maintenance"])
def cleanup_scans(
    older_than_hours: Optional[int] = Query(default=None, ge=1),
    dry_run: bool = Query(default=False),
    authorized: bool = Depends(auth),
):
    """Delete completed scan records."""
    time_filter = ""
    time_params: list = []
    base_where = " WHERE finished_at IS NOT NULL"
    if older_than_hours:
        time_filter = " AND finished_at < now() - interval '%s hours'"
        time_params = [older_than_hours]

    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM scans" + base_where + time_filter, time_params or None)
        scan_count = cur.fetchone()[0]

        if dry_run:
            return {"dry_run": True, "scans": scan_count}

        cur.execute("DELETE FROM scans" + base_where + time_filter, time_params or None)
        scans_deleted = cur.rowcount
        conn.commit()

    return {"dry_run": False, "scans": scans_deleted}


@app.post("/cleanup/assets", tags=["Maintenance"])
def cleanup_assets(
    dry_run: bool = Query(default=False),
    authorized: bool = Depends(auth),
):
    """Delete ALL data — assets, findings, scans, jobs, sessions, recommendations."""
    # Order matters: delete dependent rows before parent rows
    tables = [
        "agent_messages",
        "agent_sessions",
        "scan_recommendations",
        "recon_findings",
        "credential_findings",
        "tasks",
        "jobs",
        "playwright_findings",
        "playwright_scans",
        "web_findings",
        "vulns",
        "findings",
        "scans",
        "ports",
        "assets",
    ]
    counts = {}
    with get_db() as conn, conn.cursor() as cur:
        for t in tables:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {t}")
                counts[t] = cur.fetchone()[0]
            except Exception:
                conn.rollback()
                counts[t] = 0

        if dry_run:
            return {"dry_run": True, **counts}

        deleted = {}
        for t in tables:
            try:
                cur.execute(f"DELETE FROM {t}")
                deleted[t] = cur.rowcount
            except Exception:
                conn.rollback()
                deleted[t] = 0
        conn.commit()

    return {"dry_run": False, **deleted}


@app.post("/cleanup/recommendations", tags=["Maintenance"])
def cleanup_recommendations(
    older_than_hours: Optional[int] = Query(default=None, ge=1),
    status: Optional[str] = Query(default=None),
    dry_run: bool = Query(default=False),
    authorized: bool = Depends(auth),
):
    """Delete scan recommendations."""
    where_parts = ["1=1"]
    params: list = []
    if older_than_hours:
        where_parts.append("created_at < now() - interval '%s hours'")
        params.append(older_than_hours)
    if status:
        where_parts.append("status = %s")
        params.append(status)

    where_sql = " WHERE " + " AND ".join(where_parts)

    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM scan_recommendations" + where_sql, params or None)
        rec_count = cur.fetchone()[0]

        if dry_run:
            return {"dry_run": True, "recommendations": rec_count}

        cur.execute("DELETE FROM scan_recommendations" + where_sql, params or None)
        recs_deleted = cur.rowcount
        conn.commit()

    return {"dry_run": False, "recommendations": recs_deleted}


@app.post("/recommendations/generate", tags=["Recommendations"])
def generate_recommendations(
    ip: Optional[str] = Query(default=None),
    authorized: bool = Depends(auth),
):
    """Generate scan recommendations for currently-detected open ports that
    don't have one yet — with NO time window.

    The reactive ingest path (`_trigger_recommendations_for`) only generates
    recs for ports touched in the last 10 minutes, so a target scanned earlier
    shows an empty Recommendations page ("run a port-discovery scan"). This
    endpoint lets the operator (re)populate recommendations on demand for all
    detected ports, so suggested scans can then be dispatched against them.

    Runs synchronously (one local-LLM call per port) and returns the count.
    Optionally scope to a single `ip`.
    """
    rows = _select_open_ports_without_recs(window_minutes=None, ip=ip)
    # Runs in a request scope, so _outgoing_runner_headers() resolves the
    # engagement contextvar set by middleware.
    generated = _dispatch_recommender_for_ports(rows)

    try:
        from webhooks import emit_webhook
        emit_webhook("recommendations_generated", "manual", {
            "source": "manual",
            "ip": ip,
            "ports_considered": len(rows),
            "dispatched": generated,
        })
    except Exception:
        pass

    return {"ok": True, "ports_considered": len(rows), "generated": generated}


# ── Attack vector map (MITRE ATT&CK prioritization) ──────────────────────────

@app.post("/attack-vectors/compute", tags=["Attack Vectors"])
def attack_vectors_compute(
    engagement_id: Optional[str] = Query(default=None),
    authorized: bool = Depends(auth),
):
    """(Re)compute the attack vector map: map findings → MITRE ATT&CK techniques
    + unified risk score, into the attack_vectors table. Emits a webhook."""
    import attack_vectors as _av
    eid = _validate_engagement_uuid(engagement_id or _resolve_engagement_id(None))
    result = _av.compute_attack_vectors(engagement_id=eid)
    try:
        from webhooks import emit_webhook
        emit_webhook("attack_vectors_recomputed", "attack_map", {
            "engagement_id": eid, **result,
        })
    except Exception:
        pass
    return {"ok": True, "engagement_id": eid, **result}


@app.get("/attack-vectors", tags=["Attack Vectors"])
def attack_vectors_list(
    engagement_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, le=1000),
    min_risk: float = Query(default=0.0, ge=0, le=100),
    authorized: bool = Depends(auth),
):
    """Ranked attack vectors (highest risk first) — the prioritized list the AI
    agents and UI consume to choose the next-best action."""
    import attack_vectors as _av
    eid = _validate_engagement_uuid(engagement_id or _resolve_engagement_id(None))
    vectors = _av.get_attack_vectors(engagement_id=eid, limit=limit, min_risk=min_risk)
    return {"count": len(vectors), "vectors": vectors}


@app.get("/attack-vectors/graph", tags=["Attack Vectors"])
def attack_vectors_graph(
    engagement_id: Optional[str] = Query(default=None),
    authorized: bool = Depends(auth),
):
    """Graph (nodes+edges: target → technique → tactic) for the Attack Map UI."""
    import attack_vectors as _av
    eid = _validate_engagement_uuid(engagement_id or _resolve_engagement_id(None))
    return _av.get_graph(engagement_id=eid)


@app.post("/cleanup/exploits", tags=["Maintenance"])
def cleanup_exploits(
    dry_run: bool = Query(default=False),
    authorized: bool = Depends(auth),
):
    """Delete ALL exploit data: exploit_results, pending_exploits, and exploit_chunks."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM exploit_results")
        results_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM pending_exploits")
        pending_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM exploit_chunks")
        chunks_count = cur.fetchone()[0]

        if dry_run:
            return {"dry_run": True, "exploit_results": results_count, "pending_exploits": pending_count, "exploit_chunks": chunks_count}

        cur.execute("DELETE FROM exploit_results")
        results_deleted = cur.rowcount
        cur.execute("DELETE FROM pending_exploits")
        pending_deleted = cur.rowcount
        cur.execute("DELETE FROM exploit_chunks")
        chunks_deleted = cur.rowcount
        conn.commit()

    return {"dry_run": False, "exploit_results": results_deleted, "pending_exploits": pending_deleted, "exploit_chunks": chunks_deleted}


@app.put("/exploits/{exploit_id}/status", tags=["Exploits"])
def update_exploit_status(
    exploit_id: str,
    request: dict,
    authorized: bool = Depends(auth),
):
    """Update the status of a pending exploit (approve, reject, etc.)"""
    status = request.get("status")
    if not status:
        raise HTTPException(400, "status field is required")

    valid_statuses = ["pending", "approved", "rejected", "executed", "failed"]
    if status not in valid_statuses:
        raise HTTPException(400, f"Invalid status. Must be one of: {valid_statuses}")

    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE pending_exploits SET status = %s WHERE id = %s",
            (status, exploit_id)
        )

        if cur.rowcount == 0:
            raise HTTPException(404, "Exploit not found")

        conn.commit()

    return {"success": True, "exploit_id": exploit_id, "status": status}


@app.post("/exploits/{exploit_id}/rerun", tags=["Exploits"])
def rerun_exploit(
    exploit_id: str,
    authorized: bool = Depends(auth),
):
    """Create a new pending exploit based on a failed one for retry."""
    import uuid

    with get_db() as conn, conn.cursor() as cur:
        # Get the original exploit
        cur.execute("SELECT * FROM pending_exploits WHERE id = %s", (exploit_id,))
        original = cur.fetchone()

        if not original:
            raise HTTPException(404, "Original exploit not found")

        if original["status"] not in ["failed", "rejected"]:
            raise HTTPException(400, f"Can only rerun failed or rejected exploits, not {original['status']}")

        # Create new exploit based on original
        new_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO pending_exploits
            (id, source, exploit_id, exploit_title, exploit_type, exploit_category,
             target_ip, target_port, target_service, target_version,
             customized_command, parameters, match_confidence, match_reasoning,
             status, requested_by, metadata, asset_id, port_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    'pending', %s, %s, %s, %s)
        """, (
            new_id,
            original["source"],
            original["exploit_id"],
            f"[RERUN] {original['exploit_title']}" if original['exploit_title'] else "[RERUN] Exploit",
            original["exploit_type"],
            original["exploit_category"],
            original["target_ip"],
            original["target_port"],
            original["target_service"],
            original["target_version"],
            original["customized_command"],
            original["parameters"],
            original["match_confidence"],
            f"Rerun of failed exploit {exploit_id}. Original reasoning: {original['match_reasoning'] or 'N/A'}",
            "user",  # Mark as user-requested
            original["metadata"],
            original["asset_id"],
            original["port_id"]
        ))

        conn.commit()

    return {"success": True, "new_exploit_id": new_id, "original_exploit_id": exploit_id}


@app.post("/exploits/{exploit_id}/export-burp", tags=["Exploits"])
def export_exploit_to_burp(
    exploit_id: str,
    request: dict,
    authorized: bool = Depends(auth),
):
    """Export exploit details in Burp Suite compatible format."""
    format_type = request.get("format", "request")

    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM pending_exploits WHERE id = %s", (exploit_id,))
        exploit = cur.fetchone()

        if not exploit:
            raise HTTPException(404, "Exploit not found")

        if exploit["exploit_category"] != "webapp":
            raise HTTPException(400, "Only webapp exploits can be exported to Burp Suite")

        target_ip = str(exploit["target_ip"]).split('/')[0] if exploit["target_ip"] else ""
        target_port = exploit["target_port"] or 80
        target_service = exploit["target_service"] or "http"

        # Determine protocol
        protocol = "https" if target_port in [443, 8443] or "ssl" in str(target_service).lower() else "http"

        if format_type == "request":
            # Generate raw HTTP request format for Burp Suite
            request_data = f"""GET / HTTP/1.1
Host: {target_ip}:{target_port}
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

# Exploit Details:
# Title: {exploit["exploit_title"] or "Unknown"}
# Source: {exploit["source"]} (ID: {exploit["exploit_id"]})
# Type: {exploit["exploit_type"]}
# Confidence: {exploit["match_confidence"] or "Unknown"}
# Command: {exploit["customized_command"] or "N/A"}
# Reasoning: {exploit["match_reasoning"] or "N/A"}
#
# Instructions for Burp Suite:
# 1. Import this request into Burp Suite Repeater
# 2. Modify the request based on the exploit details above
# 3. Test the payload against the target manually
# 4. Use Burp Scanner for additional vulnerability detection"""

            filename = f"exploit_{exploit_id[:8]}_{target_ip}_{target_port}.txt"

        else:  # HAR format
            # Generate HAR format for web requests
            import json
            from datetime import datetime

            har_data = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "RAG Scan Stack", "version": "1.0"},
                    "entries": [{
                        "startedDateTime": datetime.now().isoformat(),
                        "request": {
                            "method": "GET",
                            "url": f"{protocol}://{target_ip}:{target_port}/",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                {"name": "Host", "value": f"{target_ip}:{target_port}"},
                                {"name": "User-Agent", "value": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"},
                                {"name": "Accept", "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
                            ],
                            "queryString": [],
                            "cookies": [],
                            "bodySize": 0,
                            "comment": f"Exploit: {exploit['exploit_title']} | Source: {exploit['source']} | Type: {exploit['exploit_type']}"
                        },
                        "response": {"status": 0, "statusText": "", "httpVersion": "", "headers": [], "cookies": [], "content": {"size": 0, "mimeType": ""}}
                    }]
                }
            }

            request_data = json.dumps(har_data, indent=2)
            filename = f"exploit_{exploit_id[:8]}_{target_ip}_{target_port}.har"

    return {"success": True, "data": request_data, "filename": filename}


@app.post("/cleanup/followups", tags=["Maintenance"])
def cleanup_followups(
    older_than_hours: Optional[int] = Query(default=None, ge=1),
    status: Optional[str] = Query(default=None),
    dry_run: bool = Query(default=False),
    authorized: bool = Depends(auth),
):
    """Delete follow-up items, optionally filtered by status and/or age."""
    where_parts = ["1=1"]
    params: list = []
    if older_than_hours:
        where_parts.append("created_at < now() - interval '%s hours'")
        params.append(older_than_hours)
    if status:
        where_parts.append("status = %s")
        params.append(status)

    where_sql = " WHERE " + " AND ".join(where_parts)

    with get_db() as conn, conn.cursor() as cur:
        # Count feedback that will be orphaned
        cur.execute(
            "SELECT COUNT(*) FROM osint_agent_feedback WHERE follow_up_id IN "
            f"(SELECT id FROM follow_up_items{where_sql})",
            params or None,
        )
        feedback_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM follow_up_items" + where_sql, params or None)
        followup_count = cur.fetchone()[0]

        if dry_run:
            return {"dry_run": True, "follow_ups": followup_count, "feedback": feedback_count}

        # Delete feedback first (FK), then follow-ups
        cur.execute(
            "DELETE FROM osint_agent_feedback WHERE follow_up_id IN "
            f"(SELECT id FROM follow_up_items{where_sql})",
            params or None,
        )
        feedback_deleted = cur.rowcount
        cur.execute("DELETE FROM follow_up_items" + where_sql, params or None)
        followups_deleted = cur.rowcount
        conn.commit()

    return {"dry_run": False, "follow_ups": followups_deleted, "feedback": feedback_deleted}


@app.post("/cleanup/engagements", tags=["Maintenance"])
def cleanup_engagements(
    older_than_hours: Optional[int] = Query(default=None, ge=1),
    status: Optional[str] = Query(default=None),
    dry_run: bool = Query(default=False),
    authorized: bool = Depends(auth),
):
    """Delete engagements and their campaign events. Nulls out engagement_id on findings/assets."""
    where_parts = ["1=1"]
    params: list = []
    if older_than_hours:
        where_parts.append("created_at < now() - interval '%s hours'")
        params.append(older_than_hours)
    if status:
        where_parts.append("status = %s")
        params.append(status)

    where_sql = " WHERE " + " AND ".join(where_parts)

    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM engagements" + where_sql, params or None)
        eng_count = cur.fetchone()[0]

        # Count cascade-delete rows
        cur.execute(
            "SELECT COUNT(*) FROM campaign_events WHERE engagement_id IN "
            f"(SELECT id FROM engagements{where_sql})", params or None)
        campaign_count = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM evidence_store WHERE engagement_id IN "
            f"(SELECT id FROM engagements{where_sql})", params or None)
        evidence_count = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM credential_vault WHERE engagement_id IN "
            f"(SELECT id FROM engagements{where_sql})", params or None)
        cred_vault_count = cur.fetchone()[0]

        if dry_run:
            return {
                "dry_run": True,
                "engagements": eng_count,
                "campaign_events": campaign_count,
                "evidence": evidence_count,
                "credential_vault": cred_vault_count,
            }

        # NULL out engagement_id on tables with NO ACTION FK (prevents delete failure)
        null_tables = [
            "findings", "web_findings", "vulns", "recon_findings",
            "credential_findings", "assets", "playwright_findings", "scheduled_scans",
        ]
        for t in null_tables:
            try:
                cur.execute(
                    f"UPDATE {t} SET engagement_id = NULL WHERE engagement_id IN "
                    f"(SELECT id FROM engagements{where_sql})", params or None)
            except Exception:
                conn.rollback()

        # Delete engagements (campaign_events, evidence_store, credential_vault CASCADE)
        cur.execute("DELETE FROM engagements" + where_sql, params or None)
        eng_deleted = cur.rowcount
        conn.commit()

    return {
        "dry_run": False,
        "engagements": eng_deleted,
        "campaign_events": campaign_count,
        "evidence": evidence_count,
        "credential_vault": cred_vault_count,
    }


@app.post("/followups/bulk-update", tags=["Follow-Ups"])
def bulk_update_followups(
    body: dict,
    authorized: bool = Depends(auth),
):
    """Bulk update follow-up items. Body: {ids, action, status?, priority?, notes?}
    action: 'dismiss', 'accept', 'delete', 'update'
    ids: list of specific UUIDs (required)
    status: set status (for action='update')
    priority: set priority (for action='update')
    notes: append notes (for action='update')
    """
    action = body.get("action", "")
    ids = body.get("ids")

    if action not in ("dismiss", "accept", "delete", "update"):
        raise HTTPException(400, "action must be 'dismiss', 'accept', 'delete', or 'update'")
    if not ids or not isinstance(ids, list):
        raise HTTPException(400, "ids must be a non-empty list")

    with get_db() as conn, conn.cursor() as cur:
        if action == "delete":
            cur.execute(
                "DELETE FROM osint_agent_feedback WHERE follow_up_id = ANY(%s::uuid[])", (ids,))
            cur.execute("DELETE FROM follow_up_items WHERE id = ANY(%s::uuid[])", (ids,))
            affected = cur.rowcount
        elif action == "dismiss":
            cur.execute("UPDATE follow_up_items SET status = 'dismissed', updated_at = now() WHERE id = ANY(%s::uuid[])", (ids,))
            affected = cur.rowcount
        elif action == "accept":
            cur.execute("UPDATE follow_up_items SET status = 'in_progress', updated_at = now() WHERE id = ANY(%s::uuid[])", (ids,))
            affected = cur.rowcount
        elif action == "update":
            sets = ["updated_at = now()"]
            params: list = []
            new_status = body.get("status")
            new_priority = body.get("priority")
            new_notes = body.get("notes")
            if new_status:
                sets.append("status = %s")
                params.append(new_status)
            if new_priority:
                sets.append("priority = %s")
                params.append(new_priority)
            if new_notes is not None:
                sets.append("notes = %s")
                params.append(new_notes)
            if len(sets) <= 1:
                raise HTTPException(400, "update requires at least one of: status, priority, notes")
            params.append(ids)
            cur.execute(
                f"UPDATE follow_up_items SET {', '.join(sets)} WHERE id = ANY(%s::uuid[])",
                params,
            )
            affected = cur.rowcount
        else:
            affected = 0

        conn.commit()

    return {"ok": True, "action": action, "affected": affected}


@app.get("/rag/status", tags=["RAG/Exploits"])
def rag_status(authorized: bool = Depends(auth)):
    """
    Get RAG/exploit search system status.

    Proxies to scan_recommender to check:
    - Database connection and exploit_chunks table
    - Embedding model availability
    - ExploitDB data presence
    """
    try:
        resp = requests.get(f"{SCAN_RECOMMENDER_URL}/rag/status", verify=False, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        return {"healthy": False, "error": f"scan_recommender returned {resp.status_code}"}
    except requests.RequestException as e:
        return {"healthy": False, "error": f"scan_recommender unavailable: {e}"}


# --- Burp Suite Sitemap Export ---

def _parse_url_parts(url_str: str) -> dict:
    """Parse a URL string into components needed for Burp sitemap XML."""
    if not url_str:
        return {"host": "", "port": "0", "protocol": "http", "path": "/", "extension": "", "url": ""}
    # Add scheme if missing so urlparse works correctly
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str
    parsed = urlparse(url_str)
    protocol = parsed.scheme or "http"
    host = parsed.hostname or ""
    if parsed.port:
        port = str(parsed.port)
    elif protocol == "https":
        port = "443"
    else:
        port = "80"
    path = parsed.path or "/"
    # Extract file extension from last path segment
    ext = ""
    last_segment = path.rsplit("/", 1)[-1]
    if "." in last_segment:
        ext = last_segment.rsplit(".", 1)[-1]
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "path": path,
        "extension": ext,
        "url": url_str,
    }


def _build_burp_item_xml(row: dict) -> ET.Element:
    """Convert a unified finding row into a Burp <item> XML element.

    Generates a synthetic HTML response body containing the finding details
    so items are useful when imported into Burp's sitemap.
    """
    url_str = row.get("url") or ""
    ip = row.get("ip") or ""
    port_num = row.get("port")

    # For vuln findings without a URL, synthesize one from IP:port
    if not url_str and ip:
        scheme = "https" if port_num == 443 else "http"
        port_suffix = "" if port_num in (80, 443, None) else f":{port_num}"
        url_str = f"{scheme}://{ip}{port_suffix}/"

    parts = _parse_url_parts(url_str)

    # Override port from DB row if present and no URL was provided (vulns)
    if port_num and not row.get("url"):
        parts["port"] = str(port_num)

    method = row.get("method") or "GET"
    status_code = row.get("status_code") or 200

    # Extract finding metadata
    severity = row.get("severity") or ""
    source = row.get("source") or ""
    title = row.get("title") or ""
    evidence = row.get("evidence") or ""
    description = row.get("description") or ""
    solution = row.get("solution") or ""
    cves = row.get("cve") or []

    # Build comment for Burp UI sidebar
    comment_parts = []
    if severity:
        comment_parts.append(f"[{severity.upper()}]")
    if source:
        comment_parts.append(f"Source: {source}")
    if title:
        comment_parts.append(f"Title: {title}")
    if cves:
        comment_parts.append(f"CVE: {', '.join(cves)}")
    comment = " | ".join(comment_parts)

    # Synthesize HTTP request with proper headers
    host_header = parts["host"]
    if parts["port"] not in ("80", "443", "0"):
        host_header = f"{parts['host']}:{parts['port']}"
    request_str = (
        f"{method} {parts['path']} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: PentestDashboard/1.0\r\n"
        f"Accept: text/html,application/xhtml+xml,*/*\r\n"
        f"\r\n"
    )
    request_b64 = base64.b64encode(request_str.encode("utf-8")).decode("ascii")

    # Build HTML response body with finding details (so Burp shows useful content)
    from xml.sax.saxutils import escape as _esc
    body_parts = [
        f"<h2>{_esc(title or 'Finding')}</h2>",
        f"<table border='1' cellpadding='4' cellspacing='0' style='border-collapse:collapse'>",
        f"<tr><td><b>Severity</b></td><td>{_esc(severity.upper())}</td></tr>",
        f"<tr><td><b>Source</b></td><td>{_esc(source)}</td></tr>",
    ]
    if cves:
        body_parts.append(f"<tr><td><b>CVE</b></td><td>{_esc(', '.join(cves))}</td></tr>")
    if evidence:
        body_parts.append(f"<tr><td><b>Evidence</b></td><td><pre>{_esc(evidence[:2000])}</pre></td></tr>")
    if description:
        body_parts.append(f"<tr><td><b>Description</b></td><td>{_esc(description[:2000])}</td></tr>")
    if solution:
        body_parts.append(f"<tr><td><b>Solution</b></td><td>{_esc(solution[:1000])}</td></tr>")
    body_parts.append("</table>")
    html_body = (
        f"<html><head><title>{_esc(title or 'Finding')}</title></head>"
        f"<body>{''.join(body_parts)}</body></html>"
    )

    response_str = (
        f"HTTP/1.1 {status_code} OK\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(html_body)}\r\n"
        f"X-Finding-Severity: {severity}\r\n"
        f"X-Finding-Source: {source}\r\n"
        f"\r\n"
        f"{html_body}"
    )
    response_b64 = base64.b64encode(response_str.encode("utf-8")).decode("ascii")

    item = ET.Element("item")

    def _sub(tag, text, **attribs):
        el = ET.SubElement(item, tag, **attribs)
        el.text = str(text) if text is not None else ""
        return el

    created = row.get("created_at", "")
    if isinstance(created, datetime):
        created = created.isoformat()

    _sub("time", created)
    _sub("url", parts["url"])
    _sub("host", parts["host"], ip=ip or parts["host"])
    _sub("port", parts["port"])
    _sub("protocol", parts["protocol"])
    _sub("method", method)
    _sub("path", parts["path"])
    _sub("extension", parts["extension"])
    req_el = _sub("request", request_b64)
    req_el.set("base64", "true")
    _sub("status", str(status_code))
    _sub("responselength", str(len(html_body)))
    _sub("mimetype", "text/html")
    resp_el = _sub("response", response_b64)
    resp_el.set("base64", "true")
    _sub("comment", comment)

    return item


@app.get("/export/burp", tags=["Export"])
def export_burp_sitemap(
    severity: Optional[List[str]] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    source: Optional[List[str]] = Query(None, description="Filter by source (nmap, nuclei, zap, gobuster, playwright)"),
    ip: Optional[str] = Query(None, description="Filter by IP address"),
    asset_id: Optional[str] = Query(None, description="Filter by asset UUID"),
    port: Optional[int] = Query(None, description="Filter by port number"),
    cve: Optional[str] = Query(None, description="Search CVE identifiers"),
    search: Optional[str] = Query(None, description="Free-text search in title/evidence"),
    date_from: Optional[datetime] = Query(None, description="Created after this date"),
    date_to: Optional[datetime] = Query(None, description="Created before this date"),
    limit: int = Query(1000, ge=1, le=10000, description="Max items to export"),
    authorized: bool = Depends(auth),
):
    """
    Export findings as a Burp Suite sitemap XML file.

    Returns an XML file compatible with Burp Suite's sitemap import.
    Finding metadata (severity, title, CVEs, evidence) is placed in the
    <comment> field so it appears in Burp's Target > Site map UI.
    """
    base_query = """
    WITH unified AS (
        -- vulns (nmap/nuclei) — only HTTP-related services
        SELECT
            v.id::text,
            CASE WHEN v.metadata->>'source' LIKE 'nuclei:%%' THEN 'nuclei' WHEN v.metadata->>'tool' IS NOT NULL THEN v.metadata->>'tool' WHEN v.script LIKE '%%:%%' THEN split_part(v.script, ':', 1) ELSE 'nmap' END as source,
            v.asset_id::text,
            host(a.ip)::text as ip,
            p.port,
            NULL::text as url,
            v.severity,
            v.script as title,
            LEFT(v.output, 2000) as evidence,
            COALESCE(v.cve, ARRAY[]::text[]) as cve,
            NULL::text as method,
            NULL::integer as status_code,
            NULL::text as description,
            NULL::text as solution,
            v.created_at
        FROM vulns v
        LEFT JOIN assets a ON a.id = v.asset_id
        LEFT JOIN ports p ON p.id = v.port_id
        WHERE (
            lower(p.service) IN ('http', 'https', 'http-proxy', 'ssl/http', 'http-alt')
            OR p.port IN (80, 443, 8080, 8443, 8000, 8008, 8180, 8888, 3000, 5000, 9000, 9443)
            OR v.metadata->>'source' = 'nuclei'
        )
        AND v.severity <> 'info'
        AND position('No findings' in v.output) = 0

        UNION ALL

        -- web_findings (zap/gobuster/nikto/katana)
        SELECT
            wf.id::text,
            wf.source,
            wf.asset_id::text,
            host(a.ip)::text as ip,
            NULL::int as port,
            CASE
                WHEN wf.source IN ('gobuster') AND left(wf.name, 1) = '/'
                THEN rtrim(wf.url, '/') || wf.name
                ELSE wf.url
            END as url,
            wf.severity,
            wf.name as title,
            LEFT(wf.evidence, 2000) as evidence,
            COALESCE(wf.cwe, ARRAY[]::text[]) as cve,
            wf.method,
            wf.status_code,
            wf.description,
            wf.solution,
            wf.created_at
        FROM web_findings wf
        LEFT JOIN assets a ON a.id = wf.asset_id
        WHERE position('scan launched' in lower(coalesce(wf.name, ''))) = 0
        AND (wf.url LIKE 'http%%' OR wf.url IS NULL)
        AND wf.url NOT LIKE '%%,%%'

        UNION ALL

        -- playwright_findings
        SELECT
            pf.id::text,
            'playwright' as source,
            pf.asset_id::text,
            host(a.ip)::text as ip,
            NULL::int as port,
            pf.url,
            pf.severity,
            pf.title,
            LEFT(pf.evidence, 2000) as evidence,
            ARRAY[]::text[] as cve,
            NULL::text as method,
            NULL::integer as status_code,
            NULL::text as description,
            NULL::text as solution,
            pf.created_at
        FROM playwright_findings pf
        LEFT JOIN assets a ON a.id = pf.asset_id

        UNION ALL

        -- recon_findings (subfinder subdomains)
        SELECT
            rf.id::text,
            'subfinder' as source,
            rf.asset_id::text,
            COALESCE(host(a.ip)::text, rf.target) as ip,
            NULL::int as port,
            'http://' || rf.target || '/' as url,
            rf.severity,
            'Subdomain: ' || rf.target as title,
            'Discovered via subfinder' as evidence,
            ARRAY[]::text[] as cve,
            NULL::text as method,
            NULL::integer as status_code,
            NULL::text as description,
            NULL::text as solution,
            rf.created_at
        FROM recon_findings rf
        LEFT JOIN assets a ON a.id = rf.asset_id
        WHERE rf.source = 'subfinder'
    )
    SELECT * FROM unified
    """

    # Build WHERE clauses with psycopg2 %s placeholders
    where_clauses: List[str] = []
    params_pg: List[Any] = []

    if severity:
        placeholders = ", ".join(["%s"] * len(severity))
        where_clauses.append(f"severity IN ({placeholders})")
        params_pg.extend(severity)

    if source:
        placeholders = ", ".join(["%s"] * len(source))
        where_clauses.append(f"source IN ({placeholders})")
        params_pg.extend(source)

    if ip:
        where_clauses.append("ip = %s")
        params_pg.append(ip)

    if asset_id:
        where_clauses.append("asset_id = %s")
        params_pg.append(asset_id)

    if port:
        where_clauses.append("port = %s")
        params_pg.append(port)

    if cve:
        where_clauses.append("EXISTS (SELECT 1 FROM unnest(cve) c WHERE c ILIKE %s)")
        params_pg.append(f"%{cve}%")

    if search:
        where_clauses.append("(title ILIKE %s OR evidence ILIKE %s)")
        params_pg.append(f"%{search}%")
        params_pg.append(f"%{search}%")

    if date_from:
        where_clauses.append("created_at >= %s")
        params_pg.append(date_from)

    if date_to:
        where_clauses.append("created_at <= %s")
        params_pg.append(date_to)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
    {base_query}
    {where_sql}
    ORDER BY created_at DESC
    LIMIT %s
    """
    params_pg.append(limit)

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params_pg)
        rows = cur.fetchall()

    # Build Burp sitemap XML
    export_time = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Z %Y")
    root = ET.Element("items", burpVersion="2024.1", exportTime=export_time)

    for row in rows:
        item = _build_burp_item_xml(dict(row))
        root.append(item)

    # Serialize with inline DTD (required by Burp Suite)
    dtd = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE items [\n'
        '<!ELEMENT items (item*)>\n'
        '<!ATTLIST items burpVersion CDATA "">\n'
        '<!ATTLIST items exportTime CDATA "">\n'
        '<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>\n'
        '<!ELEMENT time (#PCDATA)>\n'
        '<!ELEMENT url (#PCDATA)>\n'
        '<!ELEMENT host (#PCDATA)>\n'
        '<!ATTLIST host ip CDATA "">\n'
        '<!ELEMENT port (#PCDATA)>\n'
        '<!ELEMENT protocol (#PCDATA)>\n'
        '<!ELEMENT method (#PCDATA)>\n'
        '<!ELEMENT path (#PCDATA)>\n'
        '<!ELEMENT extension (#PCDATA)>\n'
        '<!ELEMENT request (#PCDATA)>\n'
        '<!ATTLIST request base64 (true|false) "false">\n'
        '<!ELEMENT status (#PCDATA)>\n'
        '<!ELEMENT responselength (#PCDATA)>\n'
        '<!ELEMENT mimetype (#PCDATA)>\n'
        '<!ELEMENT response (#PCDATA)>\n'
        '<!ATTLIST response base64 (true|false) "false">\n'
        '<!ELEMENT comment (#PCDATA)>\n'
        ']>\n'
    )
    xml_body = ET.tostring(root, encoding="unicode")
    xml_str = dtd + xml_body

    return Response(
        content=xml_str.encode("utf-8"),
        media_type="application/xml; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="burp_sitemap_export.xml"'},
    )


@app.get("/export/har", tags=["Export"])
def export_har(
    severity: Optional[List[str]] = Query(None),
    source: Optional[List[str]] = Query(None),
    ip: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(2000, ge=1, le=10000),
    authorized: bool = Depends(auth),
):
    """Export findings as HAR (HTTP Archive) file.

    Compatible with Burp Suite (Proxy > Import) and ZAP (Import/Export add-on).
    Each finding becomes an entry with a synthesized request and an HTML response
    containing the finding details (severity, evidence, CVEs, description).
    """
    from xml.sax.saxutils import escape as _esc
    from urllib.parse import urlparse as _urlparse

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        where = []
        params: list = []

        if severity:
            ph = ", ".join(["%s"] * len(severity))
            where.append(f"severity IN ({ph})")
            params.extend(severity)
        if source:
            ph = ", ".join(["%s"] * len(source))
            where.append(f"source IN ({ph})")
            params.extend(source)
        if ip:
            where.append("host(a.ip)::text = %s")
            params.append(ip)
        if asset_id:
            where.append("wf.asset_id = %s::uuid")
            params.append(asset_id)
        if search:
            where.append("(LOWER(wf.name) LIKE LOWER(%s) OR LOWER(wf.evidence) LIKE LOWER(%s))")
            params.extend([f"%{search}%", f"%{search}%"])

        where_sql = "WHERE " + " AND ".join(where) if where else ""

        # Pull from web_findings (richest data for HAR)
        cur.execute(f"""
            SELECT wf.url, wf.name, wf.severity, wf.evidence, wf.method,
                   wf.status_code, wf.payload, wf.description, wf.solution,
                   wf.reference, wf.confidence, wf.cwe, wf.source,
                   wf.issue_type, wf.created_at,
                   host(a.ip)::text as ip, a.hostname
            FROM web_findings wf
            LEFT JOIN assets a ON a.id = wf.asset_id
            {where_sql}
            AND wf.url LIKE 'http%%'
            AND wf.url NOT LIKE '%%,%%'
            ORDER BY wf.created_at DESC
            LIMIT %s
        """, (*params, limit))
        web_rows = cur.fetchall()

        # Also pull vulns with HTTP services
        vuln_where = []
        vuln_params: list = []
        if severity:
            ph = ", ".join(["%s"] * len(severity))
            vuln_where.append(f"v.severity IN ({ph})")
            vuln_params.extend(severity)
        if ip:
            vuln_where.append("host(a.ip)::text = %s")
            vuln_params.append(ip)
        vuln_where_sql = "WHERE " + " AND ".join(vuln_where) if vuln_where else ""

        cur.execute(f"""
            SELECT v.script as name, v.severity, v.output as evidence,
                   v.cve, v.cvss, v.created_at,
                   host(a.ip)::text as ip, a.hostname, p.port, p.service,
                   CASE WHEN v.metadata->>'source' LIKE 'nuclei:%%' THEN 'nuclei' WHEN v.metadata->>'tool' IS NOT NULL THEN v.metadata->>'tool' WHEN v.script LIKE '%%:%%' THEN split_part(v.script, ':', 1) ELSE 'nmap' END as source
            FROM vulns v
            LEFT JOIN assets a ON a.id = v.asset_id
            LEFT JOIN ports p ON p.id = v.port_id
            {vuln_where_sql}
            AND v.severity <> 'info'
            AND position('No findings' in v.output) = 0
            ORDER BY v.created_at DESC
            LIMIT %s
        """, (*vuln_params, limit))
        vuln_rows = cur.fetchall()

    # Build HAR entries
    entries = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for row in web_rows:
        url = row.get("url") or ""
        if not url or "," in url:
            continue
        # Ensure proper URL format
        if not url.startswith("http://") and not url.startswith("https://"):
            if " " in url or not "." in url:
                continue
            url = f"https://{url}/"
        method = row.get("method") or "GET"
        status = row.get("status_code") or 200
        name = row.get("name") or ""
        sev = row.get("severity") or "info"
        evidence = row.get("evidence") or ""
        description = row.get("description") or ""
        solution = row.get("solution") or ""
        cwe_list = row.get("cwe") or []
        src = row.get("source") or ""
        ip_addr = row.get("ip") or ""

        try:
            parsed = _urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except Exception:
            host = ""
            port = 80

        # Build HTML response body with finding details
        body_parts = [f"<h2>{_esc(name or 'Finding')}</h2>"]
        body_parts.append("<table border='1' cellpadding='4' cellspacing='0' style='border-collapse:collapse'>")
        body_parts.append(f"<tr><td><b>Severity</b></td><td>{_esc(sev.upper())}</td></tr>")
        body_parts.append(f"<tr><td><b>Source</b></td><td>{_esc(src)}</td></tr>")
        if cwe_list:
            body_parts.append(f"<tr><td><b>CWE</b></td><td>{_esc(', '.join(cwe_list))}</td></tr>")
        if evidence:
            body_parts.append(f"<tr><td><b>Evidence</b></td><td><pre>{_esc(evidence[:2000])}</pre></td></tr>")
        if description:
            body_parts.append(f"<tr><td><b>Description</b></td><td>{_esc(description[:2000])}</td></tr>")
        if solution:
            body_parts.append(f"<tr><td><b>Solution</b></td><td>{_esc(solution[:1000])}</td></tr>")
        body_parts.append("</table>")
        html_body = f"<html><head><title>{_esc(name)}</title></head><body>{''.join(body_parts)}</body></html>"

        # Parse query string parameters
        query_params = []
        if parsed.query:
            from urllib.parse import parse_qsl
            for qk, qv in parse_qsl(parsed.query, keep_blank_values=True):
                query_params.append({"name": qk, "value": qv})

        # Request headers (full set for realistic Burp import)
        host_val = f"{host}:{port}" if port not in (80, 443) else host
        req_headers = [
            {"name": "Host", "value": host_val},
            {"name": "User-Agent", "value": "Mozilla/5.0 (RAG-Scan-Stack/1.0) AppleWebKit/537.36"},
            {"name": "Accept", "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            {"name": "Accept-Language", "value": "en-US,en;q=0.5"},
            {"name": "Accept-Encoding", "value": "gzip, deflate"},
            {"name": "Connection", "value": "close"},
        ]
        payload_text = row.get("payload") or ""
        if method in ("POST", "PUT", "PATCH") and payload_text:
            req_headers.append({"name": "Content-Type", "value": "application/x-www-form-urlencoded"})
            req_headers.append({"name": "Content-Length", "value": str(len(payload_text))})

        # Response headers
        resp_headers = [
            {"name": "Content-Type", "value": "text/html; charset=utf-8"},
            {"name": "Content-Length", "value": str(len(html_body))},
            {"name": "X-Finding-Severity", "value": sev},
            {"name": "X-Finding-Source", "value": src},
        ]

        # Comment with finding metadata
        comment_parts = [f"[{sev.upper()}]", f"Source: {src}"]
        if name:
            comment_parts.append(f"Title: {name}")
        if cwe_list:
            comment_parts.append(f"CWE: {', '.join(cwe_list)}")

        created = row.get("created_at")
        started = created.isoformat() if hasattr(created, "isoformat") else str(created or now_iso)

        post_data = None
        if method in ("POST", "PUT", "PATCH") and row.get("payload"):
            post_data = {
                "mimeType": "application/x-www-form-urlencoded",
                "text": row["payload"],
            }

        # Build full request text for _requestRaw
        path_query = parsed.path or "/"
        if parsed.query:
            path_query += "?" + parsed.query
        req_text_lines = [f"{method} {path_query} HTTP/1.1"]
        for h in req_headers:
            req_text_lines.append(f"{h['name']}: {h['value']}")
        req_text_lines.append("")
        if payload_text:
            req_text_lines.append(payload_text)
        else:
            req_text_lines.append("")
        full_request_text = "\r\n".join(req_text_lines)

        entry = {
            "startedDateTime": started,
            "time": 1,
            "request": {
                "method": method,
                "url": url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": req_headers,
                "queryString": query_params,
                "headersSize": len("\r\n".join(req_text_lines[:len(req_headers)+1])),
                "bodySize": len(payload_text),
                "_requestRaw": full_request_text,
            },
            "response": {
                "status": status,
                "statusText": {200:"OK",301:"Moved",302:"Found",403:"Forbidden",404:"Not Found",500:"Internal Server Error"}.get(status, "OK"),
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": resp_headers,
                "content": {
                    "size": len(html_body),
                    "mimeType": "text/html",
                    "text": html_body,
                },
                "redirectURL": "",
                "headersSize": sum(len(f"{h['name']}: {h['value']}\r\n") for h in resp_headers) + 2,
                "bodySize": len(html_body),
            },
            "cache": {},
            "timings": {"send": 0, "wait": 1, "receive": 0},
            "serverIPAddress": ip_addr,
            "comment": " | ".join(comment_parts),
        }
        if post_data:
            entry["request"]["postData"] = post_data

        entries.append(entry)

    # Add vuln entries (nmap/nuclei findings on HTTP ports)
    for row in vuln_rows:
        ip_addr = row.get("ip") or ""
        port_num = row.get("port") or 80
        service = row.get("service") or ""
        scheme = "https" if port_num == 443 or "ssl" in (service or "").lower() else "http"
        hostname = row.get("hostname") or ip_addr
        port_suffix = "" if port_num in (80, 443) else f":{port_num}"
        url = f"{scheme}://{hostname}{port_suffix}/"
        name = row.get("name") or ""
        sev = row.get("severity") or "info"
        evidence = row.get("evidence") or ""
        cves = row.get("cve") or []
        src = row.get("source") or "nmap"

        html_body = (
            f"<html><body><h2>{_esc(name)}</h2>"
            f"<p><b>Severity:</b> {_esc(sev.upper())}</p>"
            f"<p><b>Source:</b> {_esc(src)}</p>"
            + (f"<p><b>CVE:</b> {_esc(', '.join(cves))}</p>" if cves else "")
            + (f"<p><b>CVSS:</b> {row.get('cvss', '')}</p>" if row.get("cvss") else "")
            + f"<pre>{_esc(evidence[:2000])}</pre>"
            f"</body></html>"
        )

        comment = f"[{sev.upper()}] Source: {src}"
        if name:
            comment += f" | {name}"
        if cves:
            comment += f" | CVE: {', '.join(cves)}"

        created = row.get("created_at")
        started = created.isoformat() if hasattr(created, "isoformat") else str(created or now_iso)

        entries.append({
            "startedDateTime": started,
            "time": 1,
            "request": {
                "method": "GET",
                "url": url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [
                    {"name": "Host", "value": hostname + port_suffix},
                    {"name": "User-Agent", "value": "PentestDashboard/1.0"},
                ],
                "queryString": [],
                "headersSize": -1,
                "bodySize": 0,
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [
                    {"name": "Content-Type", "value": "text/html"},
                    {"name": "Content-Length", "value": str(len(html_body))},
                    {"name": "X-Finding-Severity", "value": sev},
                ],
                "content": {"size": len(html_body), "mimeType": "text/html", "text": html_body},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(html_body),
            },
            "cache": {},
            "timings": {"send": 0, "wait": 1, "receive": 0},
            "serverIPAddress": ip_addr,
            "comment": comment,
        })

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "PentestDashboard", "version": "2026.04.01"},
            "browser": {"name": "PentestDashboard", "version": "2026.04.01"},
            "pages": [
                {
                    "startedDateTime": now_iso,
                    "id": "page_0",
                    "title": "Pentest Dashboard Export",
                    "pageTimings": {"onContentLoad": -1, "onLoad": -1},
                }
            ],
            "entries": entries,
            "comment": f"Exported {len(entries)} findings from pentest dashboard",
        }
    }

    # Add pageref to all entries (some importers require it)
    for e in entries:
        e["pageref"] = "page_0"

    # Validate HAR before returning
    validation = _validate_har(har)
    if not validation["valid"]:
        raise HTTPException(500, f"HAR validation failed: {validation['errors']}")

    return Response(
        content=json.dumps(har, default=str).encode("utf-8"),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="findings_export.har"',
            "X-HAR-Entries": str(len(entries)),
            "X-HAR-Validation": "passed",
        },
    )


def _validate_har(har: dict) -> dict:
    """Validate a HAR dict against the HAR 1.2 spec. Returns {valid, errors, warnings}."""
    errors = []
    warnings = []

    log = har.get("log")
    if not log:
        return {"valid": False, "errors": ["missing 'log' object"], "warnings": []}

    if log.get("version") != "1.2":
        errors.append(f"version should be '1.2', got '{log.get('version')}'")
    if not log.get("creator"):
        errors.append("missing 'creator'")
    if not log.get("pages"):
        warnings.append("missing 'pages' array (optional but recommended)")
    if not log.get("entries"):
        warnings.append("no entries in HAR")

    for i, entry in enumerate(log.get("entries", [])):
        prefix = f"entry[{i}]"
        for field in ("startedDateTime", "time", "request", "response", "cache", "timings"):
            if field not in entry:
                errors.append(f"{prefix}: missing '{field}'")

        req = entry.get("request", {})
        for field in ("method", "url", "httpVersion", "cookies", "headers", "queryString", "headersSize", "bodySize"):
            if field not in req:
                errors.append(f"{prefix}.request: missing '{field}'")
        url = req.get("url", "")
        if url and not url.startswith("http"):
            errors.append(f"{prefix}.request.url: not a valid URL: {url[:60]}")

        resp = entry.get("response", {})
        for field in ("status", "statusText", "httpVersion", "cookies", "headers", "content", "redirectURL", "headersSize", "bodySize"):
            if field not in resp:
                errors.append(f"{prefix}.response: missing '{field}'")

        content = resp.get("content", {})
        if "size" not in content:
            errors.append(f"{prefix}.response.content: missing 'size'")
        if "mimeType" not in content:
            errors.append(f"{prefix}.response.content: missing 'mimeType'")

        if not entry.get("pageref"):
            warnings.append(f"{prefix}: missing 'pageref'")

        # Stop after 10 errors to avoid huge output
        if len(errors) >= 10:
            errors.append(f"... (stopped after 10 errors, {len(log.get('entries', []))} entries total)")
            break

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


# Proxy replay progress tracking (in-memory, single worker)
_replay_status: dict = {"running": False, "phase": "", "progress": 0, "total": 0, "success": 0, "failed": 0, "details": {}}


@app.get("/export/proxy-replay/status", tags=["Export"])
def proxy_replay_status(authorized: bool = Depends(auth)):
    """Get current proxy replay progress."""
    return _replay_status


@app.post("/export/proxy-replay", tags=["Export"])
def proxy_replay(
    body: dict,
    background_tasks: BackgroundTasks,
    authorized: bool = Depends(auth),
):
    """Enhanced proxy replay — sends discovered URLs, parameters, auth tokens,
    and vulnerability payloads through Burp/ZAP proxy in 4 phases.

    Body: {
        proxy_url: "http://127.0.0.1:8080" (required),
        severity: ["high", "medium"] (optional filter),
        source: ["zap", "nuclei"] (optional filter),
        ip: "1.2.3.4" (optional filter),
        limit: 1000 (default 1000),
        delay_ms: 50 (delay between requests, default 50),
        include_params: true (replay with discovered parameters),
        include_auth: true (include credentials from vault as headers),
        include_payloads: true (replay exact attack payloads from findings),
        order: "sequential" | "severity" | "random" (default "sequential"),
        dry_run: false (if true, return what would be sent without contacting target),
    }

    Phases:
    1. Base URL crawl — GET all discovered URLs sorted by path depth
    2. Parameterized requests — rebuild URLs with discovered params + POST bodies
    3. Authenticated requests — replay with credentials from vault
    4. Vulnerability payloads — replay exact method+URL+payload from findings
    """
    import requests as _req
    from urllib.parse import urlparse as _urlparse, urlencode as _urlencode, urlunparse as _urlunparse, parse_qs as _parse_qs

    proxy_url = body.get("proxy_url")
    if not proxy_url:
        raise HTTPException(400, "proxy_url is required (e.g., http://127.0.0.1:8080)")

    if _replay_status["running"]:
        raise HTTPException(409, "A replay is already in progress. Check /export/proxy-replay/status")

    limit = body.get("limit", 1000)
    delay_ms = body.get("delay_ms", 50)
    include_params = body.get("include_params", True)
    include_auth = body.get("include_auth", True)
    include_payloads = body.get("include_payloads", True)
    order = body.get("order", "sequential")

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Severity/source filter
        where = []
        fparams: list = []
        if body.get("severity"):
            ph = ", ".join(["%s"] * len(body["severity"]))
            where.append(f"wf.severity IN ({ph})")
            fparams.extend(body["severity"])
        if body.get("source"):
            ph = ", ".join(["%s"] * len(body["source"]))
            where.append(f"wf.source IN ({ph})")
            fparams.extend(body["source"])
        if body.get("ip"):
            where.append("host(a.ip)::text = %s")
            fparams.append(body["ip"])
        where_sql = "AND " + " AND ".join(where) if where else ""

        # Phase 1: Base URLs
        cur.execute(f"""
            SELECT DISTINCT wf.url, wf.method, wf.severity
            FROM web_findings wf
            LEFT JOIN assets a ON a.id = wf.asset_id
            WHERE wf.url LIKE 'http%%'
              AND wf.url NOT LIKE '%%,%%'
              AND wf.url NOT LIKE '%% %%'
              {where_sql}
            ORDER BY wf.url
            LIMIT %s
        """, (*fparams, limit))
        base_urls = cur.fetchall()

        # Also get vuln service URLs
        cur.execute("""
            SELECT DISTINCT
                CASE WHEN p.port = 443 THEN 'https' ELSE 'http' END || '://' ||
                COALESCE(a.hostname, host(a.ip)::text) ||
                CASE WHEN p.port NOT IN (80, 443) THEN ':' || p.port ELSE '' END || '/' as url,
                'GET' as method, v.severity
            FROM vulns v
            JOIN assets a ON a.id = v.asset_id
            JOIN ports p ON p.id = v.port_id
            WHERE v.severity <> 'info'
            LIMIT %s
        """, (limit,))
        for r in cur.fetchall():
            if r["url"]:
                base_urls.append(r)

        # Phase 2: Parameterized requests
        param_requests = []
        if include_params:
            cur.execute("""
                SELECT dp.url_pattern, dp.param_name, dp.param_type, dp.http_method,
                       dp.param_location, dp.sample_values
                FROM discovered_params dp
                ORDER BY dp.url_pattern, dp.param_name
                LIMIT %s
            """, (limit,))
            for row in cur.fetchall():
                url = row["url_pattern"]
                if not url or not url.startswith("http"):
                    continue
                name = row["param_name"]
                method = row["http_method"] or "GET"
                location = row["param_location"] or "query"
                samples = row["sample_values"] or ["pentest"]
                value = samples[0] if samples else "pentest"
                param_requests.append({
                    "url": url, "method": method, "param_name": name,
                    "param_value": value, "location": location,
                })

        # Phase 3: Auth tokens
        auth_headers = {}
        if include_auth:
            cur.execute("""
                SELECT credential_type, credential_value, domain, username
                FROM credential_vault
                WHERE status = 'valid' AND credential_type IN ('cookie', 'token', 'api_key', 'bearer')
                ORDER BY updated_at DESC
                LIMIT 50
            """)
            for row in cur.fetchall():
                domain = row.get("domain") or "*"
                ctype = row["credential_type"]
                cval = row["credential_value"] or ""
                if ctype == "cookie":
                    auth_headers.setdefault(domain, {})["Cookie"] = cval
                elif ctype in ("bearer", "token"):
                    auth_headers.setdefault(domain, {})["Authorization"] = f"Bearer {cval}"
                elif ctype == "api_key":
                    auth_headers.setdefault(domain, {})["X-API-Key"] = cval

        # Phase 4: Attack payloads
        payload_requests = []
        if include_payloads:
            cur.execute(f"""
                SELECT wf.url, wf.method, wf.payload, wf.name, wf.severity
                FROM web_findings wf
                LEFT JOIN assets a ON a.id = wf.asset_id
                WHERE wf.payload IS NOT NULL AND wf.payload != ''
                  AND wf.url LIKE 'http%%'
                  AND wf.url NOT LIKE '%%,%%'
                  {where_sql}
                ORDER BY
                    CASE wf.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
                LIMIT %s
            """, (*fparams, limit))
            payload_requests = cur.fetchall()

    # Sort base URLs
    def _path_depth(url):
        try:
            return len(_urlparse(url).path.strip("/").split("/"))
        except Exception:
            return 0

    if order == "sequential":
        base_urls.sort(key=lambda r: (_path_depth(r["url"]), r["url"]))
    elif order == "severity":
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "recon": 5}
        base_urls.sort(key=lambda r: sev_order.get(r.get("severity", "info"), 9))

    # Dedup base URLs
    seen = set()
    deduped_urls = []
    for r in base_urls:
        if r["url"] not in seen:
            seen.add(r["url"])
            deduped_urls.append(r)

    total_requests = len(deduped_urls) + len(param_requests) + len(payload_requests)
    if total_requests == 0:
        return {"ok": True, "queued": 0, "message": "No requests to replay"}

    # Dry run — return what would be sent without contacting target
    dry_run = body.get("dry_run", False)
    if dry_run:
        sample_urls = [{"method": r.get("method") or "GET", "url": r["url"], "phase": "base_url"} for r in deduped_urls[:20]]
        sample_params = [{"method": pr["method"], "url": pr["url"], "param": pr["param_name"], "value": pr["param_value"], "location": pr["location"], "phase": "parameter"} for pr in param_requests[:20]]
        sample_payloads = [{"method": pr.get("method", "GET"), "url": pr["url"], "payload": pr["payload"][:100], "name": pr.get("name", ""), "phase": "payload"} for pr in payload_requests[:20]]
        return {
            "ok": True,
            "dry_run": True,
            "total_requests": total_requests,
            "phases": {
                "base_urls": len(deduped_urls),
                "parameters": len(param_requests),
                "payloads": len(payload_requests),
                "auth_domains": len(auth_headers),
            },
            "auth_domains": list(auth_headers.keys()),
            "samples": {
                "base_urls": sample_urls,
                "parameters": sample_params,
                "payloads": sample_payloads,
            },
            "warning": f"This will send {total_requests} real HTTP requests to targets through {proxy_url}. Targets WILL see this traffic.",
        }

    # Run replay in background with progress tracking
    def _run_replay():
        import time
        global _replay_status
        _replay_status = {
            "running": True, "phase": "starting", "progress": 0,
            "total": total_requests, "success": 0, "failed": 0,
            "details": {"base_urls": len(deduped_urls), "params": len(param_requests),
                        "payloads": len(payload_requests), "auth_domains": len(auth_headers)},
        }
        proxies = {"http": proxy_url, "https": proxy_url}
        success = 0
        failed = 0

        def _send(method, url, headers=None, data=None):
            nonlocal success, failed
            try:
                kwargs = {"proxies": proxies, "timeout": 15, "verify": False, "allow_redirects": True}
                if headers:
                    kwargs["headers"] = headers
                if data:
                    kwargs["data"] = data
                if method.upper() == "POST":
                    _req.post(url, **kwargs)
                elif method.upper() == "PUT":
                    _req.put(url, **kwargs)
                else:
                    _req.get(url, **kwargs)
                success += 1
            except Exception:
                failed += 1
            _replay_status["success"] = success
            _replay_status["failed"] = failed
            _replay_status["progress"] = success + failed
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

        # Phase 1: Base URL crawl
        _replay_status["phase"] = "base_urls"
        for r in deduped_urls:
            # Add auth headers if domain matches
            extra_headers = {}
            try:
                domain = _urlparse(r["url"]).hostname or ""
                for pattern, hdrs in auth_headers.items():
                    if pattern == "*" or pattern in domain:
                        extra_headers.update(hdrs)
            except Exception:
                pass
            _send(r.get("method") or "GET", r["url"], headers=extra_headers or None)

        # Phase 2: Parameterized requests
        if include_params and param_requests:
            _replay_status["phase"] = "parameters"
            for pr in param_requests:
                url = pr["url"]
                method = pr["method"]
                if pr["location"] == "query":
                    parsed = _urlparse(url)
                    qs = _parse_qs(parsed.query)
                    qs[pr["param_name"]] = [pr["param_value"]]
                    new_query = _urlencode(qs, doseq=True)
                    url = _urlunparse(parsed._replace(query=new_query))
                    _send("GET", url)
                elif pr["location"] in ("body", "json_body"):
                    _send("POST", url, data={pr["param_name"]: pr["param_value"]},
                           headers={"Content-Type": "application/x-www-form-urlencoded"})

        # Phase 3: Already handled in Phase 1 (auth headers added to base requests)

        # Phase 4: Vulnerability payloads
        if include_payloads and payload_requests:
            _replay_status["phase"] = "payloads"
            for pr in payload_requests:
                method = pr.get("method") or "GET"
                url = pr["url"]
                payload = pr["payload"]
                if method.upper() in ("POST", "PUT", "PATCH"):
                    _send(method, url, data=payload,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    # Append payload as query parameter for GET
                    sep = "&" if "?" in url else "?"
                    _send("GET", f"{url}{sep}{payload}")

        _replay_status["phase"] = "complete"
        _replay_status["running"] = False
        log.info("Proxy replay complete: %d success, %d failed, %d total",
                 success, failed, total_requests)

    background_tasks.add_task(_run_replay)

    return {
        "ok": True,
        "queued": total_requests,
        "proxy": proxy_url,
        "phases": {
            "base_urls": len(deduped_urls),
            "parameters": len(param_requests),
            "payloads": len(payload_requests),
            "auth_domains": len(auth_headers),
        },
        "message": f"Replaying {total_requests} requests through {proxy_url} in 4 phases",
    }


@app.get("/export/zap-report", tags=["Export"])
def export_zap_report(
    severity: Optional[List[str]] = Query(None),
    source: Optional[List[str]] = Query(None),
    ip: Optional[str] = Query(None),
    limit: int = Query(2000, ge=1, le=10000),
    authorized: bool = Depends(auth),
):
    """Export findings as a ZAP XML report file compatible with ZAP import.

    Generates <OWASPZAPReport> XML grouped by site, with <alertitem> elements
    containing severity, CWE, description, evidence, and remediation.
    """
    from xml.sax.saxutils import escape as _esc

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        where = []
        params: list = []
        if severity:
            placeholders = ", ".join(["%s"] * len(severity))
            where.append(f"severity IN ({placeholders})")
            params.extend(severity)
        if source:
            placeholders = ", ".join(["%s"] * len(source))
            where.append(f"source IN ({placeholders})")
            params.extend(source)
        if ip:
            where.append("host(a.ip)::text = %s")
            params.append(ip)
        where_sql = "WHERE " + " AND ".join(where) if where else ""

        cur.execute(f"""
            SELECT wf.url, wf.name, wf.severity, wf.confidence, wf.evidence,
                   wf.method, wf.payload, wf.description, wf.solution, wf.reference,
                   wf.cwe, wf.source, wf.status_code, wf.created_at,
                   host(a.ip)::text as ip
            FROM web_findings wf
            LEFT JOIN assets a ON a.id = wf.asset_id
            {where_sql}
            ORDER BY wf.url, wf.severity
            LIMIT %s
        """, (*params, limit))
        rows = cur.fetchall()

    # Severity → ZAP risk code mapping
    risk_map = {"critical": 3, "high": 3, "medium": 2, "low": 1, "info": 0}
    conf_map = {"high": 3, "medium": 2, "low": 1, "confirmed": 3}

    # Group findings by site (hostname)
    from collections import defaultdict
    from urllib.parse import urlparse as _urlparse
    sites: dict = defaultdict(list)
    for row in rows:
        url = row.get("url") or ""
        try:
            parsed = _urlparse(url)
            host = parsed.hostname or row.get("ip") or "unknown"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            ssl = parsed.scheme == "https"
            site_key = f"{parsed.scheme}://{host}:{port}"
        except Exception:
            host = row.get("ip") or "unknown"
            port = 80
            ssl = False
            site_key = f"http://{host}:{port}"
        sites[site_key].append({**dict(row), "_host": host, "_port": port, "_ssl": ssl})

    # Build ZAP XML
    generated = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S")
    xml_parts = [f'<?xml version="1.0" encoding="UTF-8"?>']
    xml_parts.append(f'<OWASPZAPReport version="2.15.0" generated="{generated}">')

    plugin_counter = 10001
    for site_key, findings in sites.items():
        host = findings[0]["_host"]
        port = findings[0]["_port"]
        ssl = findings[0]["_ssl"]
        xml_parts.append(f'<site name="{_esc(site_key)}" host="{_esc(host)}" port="{port}" ssl="{str(ssl).lower()}">')
        xml_parts.append("<alerts>")

        # Group by finding name to avoid duplicate alertitems
        alert_groups: dict = defaultdict(list)
        for f in findings:
            alert_groups[f.get("name") or f.get("source") or "Unknown"].append(f)

        for alert_name, instances in alert_groups.items():
            rep = instances[0]  # Representative finding for metadata
            risk = risk_map.get(rep.get("severity", "info"), 0)
            conf_str = (rep.get("confidence") or "medium").lower()
            conf = conf_map.get(conf_str, 2)
            risk_labels = {3: "High", 2: "Medium", 1: "Low", 0: "Informational"}
            conf_labels = {3: "High", 2: "Medium", 1: "Low"}
            cwes = rep.get("cwe") or []
            cwe_id = ""
            if cwes:
                cwe_id = cwes[0].replace("CWE-", "") if cwes[0].startswith("CWE-") else cwes[0]

            xml_parts.append("<alertitem>")
            xml_parts.append(f"<pluginid>{plugin_counter}</pluginid>")
            plugin_counter += 1
            xml_parts.append(f"<alertRef>{plugin_counter}</alertRef>")
            xml_parts.append(f"<alert>{_esc(alert_name)}</alert>")
            xml_parts.append(f"<name>{_esc(alert_name)}</name>")
            xml_parts.append(f"<riskcode>{risk}</riskcode>")
            xml_parts.append(f"<confidence>{conf}</confidence>")
            xml_parts.append(f"<riskdesc>{risk_labels.get(risk, 'Info')} ({conf_labels.get(conf, 'Medium')})</riskdesc>")
            xml_parts.append(f"<confidencedesc>{conf_labels.get(conf, 'Medium')}</confidencedesc>")
            xml_parts.append(f"<desc>{_esc(rep.get('description') or alert_name)}</desc>")
            xml_parts.append(f"<count>{len(instances)}</count>")

            xml_parts.append("<instances>")
            for inst in instances[:50]:
                xml_parts.append("<instance>")
                xml_parts.append(f"<uri>{_esc(inst.get('url') or '')}</uri>")
                xml_parts.append(f"<method>{_esc(inst.get('method') or 'GET')}</method>")
                if inst.get("payload"):
                    xml_parts.append(f"<param>{_esc(inst['payload'])}</param>")
                if inst.get("evidence"):
                    xml_parts.append(f"<evidence>{_esc(inst['evidence'][:500])}</evidence>")
                xml_parts.append("</instance>")
            xml_parts.append("</instances>")

            xml_parts.append(f"<solution>{_esc(rep.get('solution') or '')}</solution>")
            xml_parts.append(f"<reference>{_esc(rep.get('reference') or '')}</reference>")
            xml_parts.append(f"<cweid>{_esc(cwe_id)}</cweid>")
            xml_parts.append(f"<wascid></wascid>")
            xml_parts.append(f"<sourceid>3</sourceid>")
            xml_parts.append("</alertitem>")

        xml_parts.append("</alerts>")
        xml_parts.append("</site>")

    xml_parts.append("</OWASPZAPReport>")
    xml_str = "\n".join(xml_parts)

    return Response(
        content=xml_str.encode("utf-8"),
        media_type="application/xml; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="zap_report_export.xml"'},
    )


@app.get("/recon/subdomains", tags=["Recon"])
def get_recon_subdomains(
    domain: Optional[str] = Query(None, description="Filter by parent domain"),
    limit: int = Query(500, ge=1, le=5000, description="Max results"),
    authorized: bool = Depends(auth),
):
    """Return discovered subdomains from subfinder recon_findings."""
    sql = """
        SELECT rf.target AS subdomain,
               rf.data->>'input' AS parent_domain,
               host(a.ip)::text AS resolved_ip,
               rf.source AS discovery_source,
               rf.created_at
        FROM recon_findings rf
        LEFT JOIN assets a ON a.id = rf.asset_id
        WHERE rf.source = 'subfinder'
    """
    params: list = []
    if domain:
        sql += " AND rf.data->>'input' = %s"
        params.append(domain)
    sql += " ORDER BY rf.created_at DESC LIMIT %s"
    params.append(limit)

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    subdomains = []
    for r in rows:
        subdomains.append({
            "subdomain": r["subdomain"],
            "parent_domain": r.get("parent_domain") or "",
            "resolved_ip": r.get("resolved_ip") or "",
            "discovery_source": r.get("discovery_source") or "subfinder",
            "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
        })

    return {"count": len(subdomains), "subdomains": subdomains}

@app.delete("/recon/subdomains", tags=["Recon"])
def delete_subdomains(body: dict, authorized: bool = Depends(auth)):
    """Bulk-delete subdomains from recon_findings."""
    subdomains = body.get("subdomains", [])
    if not subdomains:
        raise HTTPException(status_code=400, detail="No subdomains provided")
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM recon_findings WHERE source = 'subfinder' AND LOWER(target) = ANY(%s)",
            ([s.lower() for s in subdomains],),
        )
        deleted = cur.rowcount
        conn.commit()
    return {"ok": True, "deleted": deleted}


@app.get("/recon/search", tags=["Recon"])
def search_recon(
    source: Optional[List[str]] = Query(None, description="Filter by source (subfinder, dnsx, tlsx, asnmap, uncover, cloudlist)"),
    finding_type: Optional[List[str]] = Query(None, description="Filter by finding_type"),
    provider: Optional[List[str]] = Query(None, description="Filter by linked asset's cloud provider tag (aws, azure, cloudflare). OR-match via assets.provider GIN index."),
    target: Optional[str] = Query(None, description="Filter by target (ILIKE)"),
    search: Optional[str] = Query(None, description="Free-text search in target + data"),
    severity: Optional[List[str]] = Query(None, description="Filter by severity"),
    asset_id: Optional[str] = Query(None, description="Filter to findings linked to this asset_id (for drill-down)"),
    engagement_id: Optional[str] = Query(None, description="Filter to findings scoped to this engagement"),
    date_from: Optional[datetime] = Query(None, description="Created after this date"),
    date_to: Optional[datetime] = Query(None, description="Created before this date"),
    limit: int = Query(200, ge=1, le=2000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    authorized: bool = Depends(auth),
):
    """Search across all recon_findings with filtering and aggregations."""
    where_clauses: list[str] = []
    params: list = []

    if source:
        where_clauses.append("rf.source = ANY(%s)")
        params.append(source)
    if finding_type:
        where_clauses.append("rf.finding_type = ANY(%s)")
        params.append(finding_type)
    if provider:
        # Provider lives on the linked asset, not the finding. Filter via the
        # JOIN — assets.provider is GIN-indexed, so && is fast.
        where_clauses.append("a.provider && %s::text[]")
        params.append([p.lower() for p in provider])
        # Identity-import sources (MicroBurst Azure AD enumeration, AzureHound
        # graph dumps) attach rows to the same asset_id but carry no hosting
        # signal. Exclude them when filtering by provider so a cloudflare-tagged
        # asset doesn't drag its azure_user / azure_group_member rows along.
        where_clauses.append("rf.source NOT IN ('microburst','azurehound','prowler','scoutsuite','pacu','cloudfox')")
    if target:
        where_clauses.append("rf.target ILIKE %s")
        params.append(f"%{target}%")
    if search:
        where_clauses.append("(rf.target ILIKE %s OR rf.data::text ILIKE %s)")
        params.append(f"%{search}%")
        params.append(f"%{search}%")
    if severity:
        where_clauses.append("rf.severity = ANY(%s)")
        params.append(severity)
    if asset_id:
        where_clauses.append("rf.asset_id = %s::uuid")
        params.append(asset_id)
    if engagement_id:
        where_clauses.append("rf.engagement_id = %s::uuid")
        params.append(engagement_id)
    if date_from:
        where_clauses.append("rf.created_at >= %s")
        params.append(date_from)
    if date_to:
        where_clauses.append("rf.created_at <= %s")
        params.append(date_to)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    # Count + aggregations need the same JOIN as the data SELECT so the
    # provider filter (which lives on assets) applies consistently.
    join_sql = "FROM recon_findings rf LEFT JOIN assets a ON a.id = rf.asset_id"

    data_sql = f"""
        SELECT rf.id::text, rf.source, rf.finding_type, rf.target,
               rf.data, rf.severity, rf.created_at,
               host(a.ip)::text as resolved_ip, a.hostname,
               a.provider, a.provider_evidence
        {join_sql}
        {where_sql}
        ORDER BY rf.created_at DESC
        LIMIT %s OFFSET %s
    """
    count_sql = f"SELECT COUNT(*) {join_sql} {where_sql}"
    by_source_sql = f"SELECT rf.source, COUNT(*) as cnt {join_sql} {where_sql} GROUP BY rf.source"
    by_type_sql   = f"SELECT rf.finding_type, COUNT(*) as cnt {join_sql} {where_sql} GROUP BY rf.finding_type"
    # Per-provider aggregation: unnest the asset's provider array so a
    # multi-tagged asset (CloudFront fronting Azure) contributes to each.
    by_provider_sql = f"""
        SELECT p AS provider, COUNT(*) as cnt
        {join_sql}
        LEFT JOIN LATERAL unnest(COALESCE(a.provider, '{{}}'::text[])) AS p ON true
        {where_sql}
        GROUP BY p
    """

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(data_sql, params + [limit, offset])
        rows = cur.fetchall()

        cur.execute(count_sql, params)
        total = cur.fetchone()["count"]

        cur.execute(by_source_sql, params)
        by_source = {r["source"]: r["cnt"] for r in cur.fetchall()}

        cur.execute(by_type_sql, params)
        by_type = {r["finding_type"]: r["cnt"] for r in cur.fetchall()}

        cur.execute(by_provider_sql, params)
        by_provider = {r["provider"]: r["cnt"] for r in cur.fetchall() if r["provider"]}

    findings = []
    for r in rows:
        findings.append({
            "id": r["id"],
            "source": r["source"],
            "finding_type": r["finding_type"] or "",
            "target": r["target"] or "",
            "data": r["data"] if isinstance(r["data"], dict) else {},
            "severity": r["severity"] or "",
            "resolved_ip": r["resolved_ip"] or "",
            "hostname": r["hostname"] or "",
            "provider": list(r["provider"]) if r.get("provider") else [],
            "provider_evidence": r["provider_evidence"] if isinstance(r.get("provider_evidence"), dict) else {},
            "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
        })

    return {
        "findings": findings,
        "total": total,
        "aggregations": {
            "by_source": by_source,
            "by_finding_type": by_type,
            "by_provider": by_provider,
        },
    }


# ── Domain Overview ────────────────────────────────────────────────────────────

def _extract_parent_domain(target: str) -> str:
    """Extract parent domain from a target string (subdomain, URL, etc.)."""
    import re
    host = target.strip().lower()
    # Strip protocol
    host = re.sub(r'^https?://', '', host)
    # Strip path/port
    host = host.split('/')[0].split(':')[0]
    # If it looks like an IP, return as-is
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        return host
    parts = host.rstrip('.').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


@app.get("/recon/domains", tags=["Recon"])
def list_recon_domains(
    search: Optional[str] = Query(None, description="Filter domains (ILIKE)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    include_excluded: bool = Query(False, description="Include out-of-scope domains"),
    authorized: bool = Depends(auth),
):
    """List distinct parent domains with per-source counts."""
    where_sql = ""
    params: list = []
    if search:
        where_sql = "WHERE rf.target ILIKE %s"
        params.append(f"%{search}%")

    sql = f"""
        SELECT rf.target, rf.source, rf.finding_type, rf.created_at
        FROM recon_findings rf
        {where_sql}
    """

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

        # Always load excluded domains (for marking + filtering)
        cur.execute("SELECT target FROM scope_targets WHERE name = 'not_in_scope'")
        excluded_domains = {r["target"] for r in cur.fetchall()}

    # Group by parent domain in Python for flexibility
    from collections import defaultdict
    domain_map: dict = defaultdict(lambda: {
        "subdomain_count": 0, "dns_count": 0, "http_count": 0,
        "tls_count": 0, "ct_count": 0, "total": 0, "last_seen": None,
        "excluded": False,
    })

    for r in rows:
        pd = _extract_parent_domain(r["target"] or "")
        if not pd:
            continue
        # Skip excluded domains unless requested
        if pd in excluded_domains:
            if not include_excluded:
                continue
            domain_map[pd]["excluded"] = True
        d = domain_map[pd]
        d["total"] += 1
        ft = r.get("finding_type") or ""
        src = r.get("source") or ""
        if ft == "subdomain" or src == "subfinder":
            d["subdomain_count"] += 1
        elif ft.startswith("dns_"):
            d["dns_count"] += 1
        elif ft == "web_service" or src == "httpx":
            d["http_count"] += 1
        elif ft == "tls_cert" or src == "tlsx":
            d["tls_count"] += 1
        elif ft == "ct_cert" or src == "crtsh":
            d["ct_count"] += 1
        ts = r.get("created_at")
        if ts and (d["last_seen"] is None or ts > d["last_seen"]):
            d["last_seen"] = ts

    # Sort by total desc, paginate
    sorted_domains = sorted(domain_map.items(), key=lambda x: x[1]["total"], reverse=True)
    total = len(sorted_domains)
    page = sorted_domains[offset:offset + limit]

    domains = []
    for name, info in page:
        domains.append({
            "domain": name,
            "subdomain_count": info["subdomain_count"],
            "dns_count": info["dns_count"],
            "http_count": info["http_count"],
            "tls_count": info["tls_count"],
            "ct_count": info["ct_count"],
            "total": info["total"],
            "last_seen": info["last_seen"].isoformat() if info["last_seen"] else None,
            "excluded": info["excluded"],
        })

    return {"domains": domains, "total": total, "excluded_count": len(excluded_domains)}


@app.get("/recon/domains/{domain}/overview", tags=["Recon"])
def get_domain_overview(
    domain: str,
    authorized: bool = Depends(auth),
):
    """Full domain intel aggregation: subdomains, DNS, HTTP, TLS, CT, stats."""
    like_pattern = f"%{domain}"

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # 1. Subdomains (deduplicated in SQL to avoid limit truncation)
        cur.execute("""
            SELECT DISTINCT ON (rf.target)
                rf.target, host(a.ip)::text as resolved_ip, rf.created_at
            FROM recon_findings rf
            LEFT JOIN assets a ON a.id = rf.asset_id
            WHERE rf.target ILIKE %s
              AND (rf.finding_type = 'subdomain' OR rf.source = 'subfinder')
            ORDER BY rf.target, rf.created_at DESC
            LIMIT 5000
        """, [like_pattern])
        subdomains = []
        for r in cur.fetchall():
            name = r["target"] or ""
            subdomains.append({
                "name": name,
                "resolved_ip": r["resolved_ip"] or "",
                "first_seen": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 2. DNS records (grouped by type, deduplicated)
        cur.execute("""
            SELECT DISTINCT ON (rf.target, rf.finding_type)
                rf.target, rf.finding_type, rf.data
            FROM recon_findings rf
            WHERE rf.target ILIKE %s
              AND rf.finding_type LIKE 'dns_%%'
            ORDER BY rf.target, rf.finding_type, rf.created_at DESC
            LIMIT 5000
        """, [like_pattern])
        dns_records: dict = {}
        for r in cur.fetchall():
            ft = r["finding_type"] or "dns_other"
            if ft not in dns_records:
                dns_records[ft] = []
            data = r["data"] if isinstance(r["data"], dict) else {}
            dns_records[ft].append({
                "target": r["target"] or "",
                "values": data.get(ft.replace("dns_", ""), data.get("a", [])),
                "data": data,
            })

        # 3. HTTP services (deduplicated per target)
        cur.execute("""
            SELECT DISTINCT ON (rf.target)
                rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE rf.target ILIKE %s
              AND (rf.finding_type = 'web_service' OR rf.source = 'httpx')
            ORDER BY rf.target, rf.created_at DESC
            LIMIT 5000
        """, [like_pattern])
        http_services = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            http_services.append({
                "url": data.get("url", r["target"] or ""),
                "status_code": data.get("status_code", ""),
                "title": data.get("title", ""),
                "webserver": data.get("webserver", ""),
                "tech": data.get("tech", []),
                "content_length": data.get("content_length", ""),
                "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 4. TLS certs (deduplicated per target)
        cur.execute("""
            SELECT DISTINCT ON (rf.target)
                rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE rf.target ILIKE %s
              AND (rf.finding_type = 'tls_cert' OR rf.source = 'tlsx')
            ORDER BY rf.target, rf.created_at DESC
            LIMIT 5000
        """, [like_pattern])
        tls_certs = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            tls_certs.append({
                "host": data.get("host", r["target"] or ""),
                "subject_cn": data.get("subject_cn", ""),
                "issuer": data.get("issuer_org", data.get("issuer", "")),
                "not_after": data.get("not_after", ""),
                "not_before": data.get("not_before", ""),
                "serial": data.get("serial", ""),
                "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 5. CT log certs
        cur.execute("""
            SELECT rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE rf.target ILIKE %s
              AND (rf.finding_type = 'ct_cert' OR rf.source = 'crtsh')
            ORDER BY rf.created_at DESC
            LIMIT 100
        """, [like_pattern])
        ct_certs = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            ct_certs.append({
                "common_name": data.get("common_name", r["target"] or ""),
                "issuer_name": data.get("issuer_name", ""),
                "not_after": data.get("not_after", ""),
                "serial": data.get("serial_number", data.get("serial", "")),
                "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 6. ASN mappings — collect resolved IPs first, then find matching ASN entries
        resolved_ips = set()
        for s in subdomains:
            if s.get("resolved_ip"):
                resolved_ips.add(s["resolved_ip"])
        # Also get IPs from DNS A records
        for entries in dns_records.values():
            for e in entries:
                vals = e.get("values", [])
                if isinstance(vals, list):
                    for v in vals:
                        if isinstance(v, str) and v.count(".") == 3:
                            resolved_ips.add(v)

        asn_mappings = []
        if resolved_ips:
            ip_list = list(resolved_ips)[:500]
            cur.execute("""
                SELECT rf.target, rf.data, rf.created_at
                FROM recon_findings rf
                WHERE (rf.finding_type = 'asn_mapping' OR rf.source = 'asnmap')
                  AND rf.target = ANY(%s)
                ORDER BY rf.created_at DESC
                LIMIT 200
            """, [ip_list])
            for r in cur.fetchall():
                data = r["data"] if isinstance(r["data"], dict) else {}
                asn_mappings.append({
                    "ip": data.get("input", r["target"] or ""),
                    "asn": data.get("as_number", data.get("asn", "")),
                    "org": data.get("as_name", data.get("org", "")),
                    "country": data.get("as_country", data.get("country", "")),
                    "cidr": data.get("as_range", data.get("cidr", "")),
                    "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
                })

        # 7. WAF detections
        cur.execute("""
            SELECT rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE rf.target ILIKE %s
              AND (rf.finding_type = 'waf_detection' OR rf.source = 'wafw00f')
            ORDER BY rf.created_at DESC
            LIMIT 100
        """, [like_pattern])
        waf_detections = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            waf_detections.append({
                "url": data.get("url", r["target"] or ""),
                "detected": data.get("detected", False),
                "firewall": data.get("firewall", ""),
                "manufacturer": data.get("manufacturer", ""),
                "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 8. Stats: total count, by-source breakdown, first/last seen
        cur.execute("""
            SELECT COUNT(*) as total,
                   MIN(rf.created_at) as first_seen,
                   MAX(rf.created_at) as last_seen
            FROM recon_findings rf
            WHERE rf.target ILIKE %s
        """, [like_pattern])
        stats_row = cur.fetchone()

        cur.execute("""
            SELECT rf.source, COUNT(*) as cnt
            FROM recon_findings rf
            WHERE rf.target ILIKE %s
            GROUP BY rf.source
            ORDER BY cnt DESC
        """, [like_pattern])
        by_source = {r["source"]: r["cnt"] for r in cur.fetchall()}

        # 9. Web findings (content-recon, katana, gobuster, etc.)
        url_like = f"%{domain}%"
        cur.execute("""
            SELECT DISTINCT ON (wf.url, wf.source)
                wf.url, wf.source, wf.name, wf.severity, wf.issue_type, wf.first_seen
            FROM web_findings wf
            WHERE wf.url ILIKE %s
            ORDER BY wf.url, wf.source, wf.first_seen DESC
            LIMIT 500
        """, [url_like])
        web_findings = []
        for r in cur.fetchall():
            web_findings.append({
                "url": r["url"] or "",
                "source": r["source"] or "",
                "name": r["name"] or "",
                "severity": r["severity"] or "info",
                "issue_type": r.get("issue_type", ""),
                "first_seen": r["first_seen"].isoformat() if r.get("first_seen") else "",
            })

        # 10. Content extractions count
        cur.execute("""
            SELECT COUNT(*) as cnt FROM content_extractions WHERE url ILIKE %s
        """, [url_like])
        content_extractions_count = cur.fetchone()["cnt"]

        # 11. Playwright findings count
        cur.execute("""
            SELECT COUNT(*) as cnt FROM playwright_findings WHERE url ILIKE %s
        """, [url_like])
        playwright_count = cur.fetchone()["cnt"]

        # 12. Discovered parameters summary
        cur.execute("""
            SELECT param_name, COUNT(*) as cnt,
                   array_agg(DISTINCT param_type) as types,
                   array_agg(DISTINCT param_location) as locations
            FROM discovered_params
            WHERE url_pattern ILIKE %s
            GROUP BY param_name
            ORDER BY cnt DESC
            LIMIT 50
        """, [url_like])
        discovered_params = []
        for r in cur.fetchall():
            discovered_params.append({
                "name": r["param_name"],
                "count": r["cnt"],
                "types": [t for t in (r["types"] or []) if t],
                "locations": [l for l in (r["locations"] or []) if l],
            })

    return {
        "domain": domain,
        "stats": {
            "total_findings": stats_row["total"] if stats_row else 0,
            "first_seen": stats_row["first_seen"].isoformat() if stats_row and stats_row["first_seen"] else None,
            "last_seen": stats_row["last_seen"].isoformat() if stats_row and stats_row["last_seen"] else None,
            "by_source": by_source,
            "web_findings_count": len(web_findings),
            "content_extractions_count": content_extractions_count,
            "playwright_findings_count": playwright_count,
        },
        "subdomains": subdomains,
        "dns_records": dns_records,
        "http_services": http_services,
        "tls_certs": tls_certs,
        "ct_certs": ct_certs,
        "asn_mappings": asn_mappings,
        "waf_detections": waf_detections,
        "web_findings": web_findings,
        "discovered_params": discovered_params,
    }


# ── Sitemap ──────────────────────────────────────────────────────────────────

@app.get("/ports/summary", tags=["Ports"])
def port_scan_summary(authorized: bool = Depends(auth)):
    """Return a summary of all open ports: hosts with ports, total ports, grouped by service."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT COUNT(DISTINCT asset_id) as hosts_with_ports FROM ports WHERE is_open = true")
        hosts = cur.fetchone()["hosts_with_ports"]
        cur.execute("SELECT COUNT(*) as total FROM ports WHERE is_open = true")
        total = cur.fetchone()["total"]

        # Group by service
        cur.execute("""
            SELECT service, COUNT(*) as cnt,
                   array_agg(DISTINCT host(a.ip)::text) as hosts
            FROM ports p JOIN assets a ON a.id = p.asset_id
            WHERE p.is_open = true
            GROUP BY service ORDER BY cnt DESC LIMIT 20
        """)
        by_service = [{"service": r["service"] or "unknown", "count": r["cnt"],
                       "hosts": r["hosts"][:5]} for r in cur.fetchall()]

        # Group by host
        cur.execute("""
            SELECT host(a.ip)::text as ip, a.hostname, COUNT(*) as open_ports,
                   array_agg(DISTINCT p.port ORDER BY p.port) as ports
            FROM ports p JOIN assets a ON a.id = p.asset_id
            WHERE p.is_open = true
            GROUP BY a.ip, a.hostname ORDER BY open_ports DESC LIMIT 20
        """)
        by_host = [{"ip": r["ip"], "hostname": r["hostname"] or "",
                     "open_ports": r["open_ports"], "ports": r["ports"][:20]} for r in cur.fetchall()]

    return {
        "hosts_with_ports": hosts, "total_open_ports": total,
        "by_service": by_service, "by_host": by_host,
    }


# ── Detected Software Inventory ──────────────────────────────────────────────

@app.get("/software", tags=["Assets"])
def get_detected_software(
    ip: Optional[str] = Query(None, description="Filter by asset IP"),
    product: Optional[str] = Query(None, description="Filter by product name (substring)"),
    search: Optional[str] = Query(None, description="Search across product, version, hostname, IP"),
    source: Optional[str] = Query(None, description="Filter by detection source"),
    limit: int = Query(2000, ge=1, le=10000),
    authorized: bool = Depends(auth),
):
    """Return detected software inventory aggregated from ports, httpx, whatweb, wafw00f."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        where = []
        params: list = []
        if search:
            where.append("(ip ILIKE %s OR hostname ILIKE %s OR LOWER(product) LIKE LOWER(%s) OR LOWER(version) LIKE LOWER(%s))")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"])
        elif ip:
            where.append("(ip ILIKE %s OR hostname ILIKE %s)")
            params.append(f"%{ip}%")
            params.append(f"%{ip}%")
        if product and not search:
            where.append("LOWER(product) LIKE LOWER(%s)")
            params.append(f"%{product}%")
        if source:
            where.append("source = %s")
            params.append(source)
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        # Deduplicate: group by host + product + version + source, keep latest
        sql = f"""
            SELECT ip, MAX(hostname) AS hostname,
                   port, protocol, product, version,
                   source, detection_type,
                   MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen,
                   COUNT(*)::int AS occurrence_count
            FROM detected_software
            {where_sql}
            GROUP BY ip, port, protocol, product, version, source, detection_type
            ORDER BY ip, product, source
            LIMIT %s
        """
        params.append(limit)
        cur.execute(sql, params)
        rows = cur.fetchall()

        # Summary stats (on deduplicated data)
        cur.execute(f"""
            SELECT COUNT(DISTINCT ip) AS asset_count,
                   COUNT(DISTINCT product) AS product_count,
                   COUNT(*) AS total_detections,
                   COUNT(DISTINCT source) AS source_count
            FROM (
                SELECT ip, product, source
                FROM detected_software
                {where_sql}
                GROUP BY ip, port, protocol, product, version, source, detection_type
            ) deduped
        """, params[:-1])  # exclude limit
        summary = cur.fetchone()

        # Enrich with CVE/exploit follow-up flags from follow_up_items
        # Include both open AND dismissed — dismissed means acknowledged, not patched
        import re as _re
        cve_by_ip: dict = {}      # ip -> [flags]
        cve_by_pv: dict = {}      # "product|version" -> [flags]
        try:
            cur.execute("""
                SELECT target, title, severity, reason, tags, status
                FROM follow_up_items
                WHERE rule_id = 'software_known_cve'
            """)
            for fu in cur.fetchall():
                flag = {
                    "title": fu["title"],
                    "severity": fu["severity"],
                    "reason": fu["reason"],
                    "tags": fu["tags"],
                    "status": fu["status"],
                }
                # Index by IP
                t = fu["target"] or ""
                if t and t != "unknown":
                    cve_by_ip.setdefault(t, []).append(flag)
                # Extract product+version from title: "Vulnerable: {product} {version} on ..."
                title = fu["title"] or ""
                m = _re.match(r"Vulnerable:\s+(.+?)\s+(\S+)\s+on\s+", title)
                if m:
                    pv_key = f"{m.group(1).lower()}|{m.group(2).lower()}"
                    cve_by_pv.setdefault(pv_key, []).append(flag)
                # Also extract CVE/EDB IDs from the title after " — " and index by those
                dash_idx = title.find(" \u2014 ")
                if dash_idx < 0:
                    dash_idx = title.find(" -- ")
                if dash_idx >= 0:
                    ids_part = title[dash_idx+3:].strip()
                    # Store the flag under the product portion before " on "
                    on_idx = title.find(" on ")
                    if on_idx > 0:
                        product_part = title[len("Vulnerable: "):on_idx].strip().lower() if title.startswith("Vulnerable:") else ""
                        # Split product from version: last space-separated token is version
                        parts = product_part.rsplit(" ", 1)
                        if len(parts) == 2:
                            p_name, p_ver = parts
                            pv_key2 = f"{p_name}|{p_ver}"
                            if pv_key2 not in cve_by_pv:
                                cve_by_pv.setdefault(pv_key2, []).append(flag)
        except Exception:
            pass  # follow_up_items may not exist yet

        # Attach flags to matching rows
        # Primary: match by product+version (most precise)
        # Secondary: match by IP only if the follow-up title mentions this product
        for row in rows:
            flags = []
            product = (row.get("product") or "").lower()
            version = (row.get("version") or "").lower()

            # Match by product+version (catches target=unknown follow-ups)
            if product and version:
                pv_key = f"{product}|{version}"
                if pv_key in cve_by_pv:
                    flags.extend(cve_by_pv[pv_key])

            # Match by IP, but only if the follow-up title mentions this product AND version
            ip = row.get("ip") or ""
            if ip and ip in cve_by_ip and product and version:
                existing_titles = {f["title"] for f in flags}
                for f in cve_by_ip[ip]:
                    f_title_lower = (f.get("title") or "").lower()
                    if f["title"] not in existing_titles and product in f_title_lower and version in f_title_lower:
                        flags.append(f)

            row["cve_flags"] = flags

        # Mark which products have been AI-checked (have research cache)
        try:
            cur.execute("SELECT LOWER(product) || '|' || LOWER(version) AS key FROM software_research_cache")
            checked_set = {r["key"] for r in cur.fetchall()}
            for row in rows:
                pv = f"{(row.get('product') or '').lower()}|{(row.get('version') or '').lower()}"
                row["ai_checked"] = pv in checked_set
        except Exception:
            pass

    return {"count": len(rows), "summary": summary, "items": rows}


# ── ExploitDB / Searchsploit Management ──────────────────────────────────────

EXPLOITDB_DIR = os.environ.get("EXPLOITDB_DIR", "/exploitdb")


@app.get("/exploitdb/version", tags=["Tools"])
def exploitdb_version(authorized: bool = Depends(auth)):
    """Get ExploitDB version info (last git commit, exploit count)."""
    import subprocess
    info = {"exploits": 0, "last_update": "unknown", "git_hash": "unknown"}
    csv_path = os.path.join(EXPLOITDB_DIR, "files_exploits.csv")
    if os.path.exists(csv_path):
        with open(csv_path) as f:
            info["exploits"] = sum(1 for _ in f) - 1  # minus header
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H %ai"], capture_output=True, text=True,
            cwd=EXPLOITDB_DIR, timeout=10,
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split(" ", 1)
            info["git_hash"] = parts[0][:12]
            info["last_update"] = parts[1] if len(parts) > 1 else "unknown"
    except Exception:
        pass
    return {"output": f"{info['exploits']} exploits | updated {info['last_update']} | {info['git_hash']}"}


@app.post("/exploitdb/update", tags=["Tools"])
def exploitdb_update(authorized: bool = Depends(auth)):
    """Update ExploitDB via git pull and reload the in-memory index."""
    import subprocess
    if not os.path.isdir(os.path.join(EXPLOITDB_DIR, ".git")):
        return {"ok": False, "error": f"No git repo at {EXPLOITDB_DIR}"}
    try:
        result = subprocess.run(
            ["git", "pull", "--ff-only"], capture_output=True, text=True,
            cwd=EXPLOITDB_DIR, timeout=120,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if result.returncode != 0:
            return {"ok": False, "error": stderr or stdout, "stdout": stdout, "stderr": stderr}

        # Reload the in-memory exploitdb index
        try:
            from rule_engine import _load_exploitdb, _EXPLOITDB_INDEX
            import rule_engine
            rule_engine._EXPLOITDB_LOADED = False
            rule_engine._EXPLOITDB_INDEX = []
            _load_exploitdb()
            stdout += f"\nReloaded {len(rule_engine._EXPLOITDB_INDEX)} exploits into memory"
        except Exception as e:
            stdout += f"\nWarning: index reload failed: {e}"

        return {"ok": True, "stdout": stdout, "stderr": stderr}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "git pull timed out after 120s"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _check_cve_cache(product: str, version: str) -> list:
    """Check local CVE DB for cached CVEs matching product+version. Returns list of dicts."""
    cached = []
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            product_lower = product.lower().replace("-", " ").replace("_", " ")
            cur.execute("""
                SELECT id, summary, cvss, published, refs
                FROM cve
                WHERE LOWER(summary) LIKE %s AND (LOWER(summary) LIKE %s OR LOWER(summary) LIKE %s)
                ORDER BY cvss DESC NULLS LAST
                LIMIT 30
            """, (f"%{product_lower}%", f"%{version}%", f"%.{version.rsplit('.', 1)[0] if '.' in version else version}%"))
            for r in cur.fetchall():
                cached.append({
                    "cve_id": str(r["id"]),
                    "summary": (r["summary"] or "")[:200],
                    "cvss": float(r["cvss"]) if r["cvss"] else None,
                    "published": r["published"].isoformat() if r.get("published") else None,
                    "source": "cache",
                })
    except Exception:
        pass
    return cached


def _apply_cves_to_inventory(product: str, version: str, cve_ids: list, source: str = "ai_check"):
    """Create follow_up_items for all assets in detected_software matching product+version."""
    if not cve_ids:
        return 0
    created = 0
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Find all hosts with this product+version
            cur.execute("""
                SELECT DISTINCT ip, hostname FROM detected_software
                WHERE LOWER(product) = LOWER(%s) AND version = %s
            """, (product, version))
            hosts = cur.fetchall()
            if not hosts:
                return 0

            cve_label = ", ".join(cve_ids[:5])
            for host in hosts:
                target = host.get("hostname") or host.get("ip") or ""
                if not target or target == "unknown":
                    continue  # skip unresolved hosts
                title = f"Vulnerable: {product} {version} on {target} \u2014 {cve_label}"
                # Check if already exists
                cur.execute("""
                    SELECT 1 FROM follow_up_items
                    WHERE rule_id = 'software_known_cve' AND target = %s
                    AND title LIKE %s LIMIT 1
                """, (target, f"Vulnerable: {product} {version} on {target}%"))
                if cur.fetchone():
                    continue
                # Build reference links
                refs = []
                for cid in cve_ids[:5]:
                    if cid.startswith("CVE-"):
                        refs.append({"label": cid, "url": f"https://nvd.nist.gov/vuln/detail/{cid}", "type": "cve"})
                    elif cid.startswith("EDB-"):
                        refs.append({"label": cid, "url": f"https://www.exploit-db.com/exploits/{cid[4:]}", "type": "edb"})
                meta = {
                    "product": product, "version": version,
                    "cve_ids": cve_ids[:10],
                    "refs": refs,
                    "software_link": f"/assets?tab=software&search={product}",
                    "source": source,
                }
                cur.execute("""
                    INSERT INTO follow_up_items
                        (id, rule_id, finding_source, target, title, severity, reason, confidence, status, tags, metadata)
                    VALUES (gen_random_uuid(), 'software_known_cve', %s, %s, %s, %s, %s, %s, 'open', %s, %s)
                """, (
                    source, target, title,
                    'critical' if any('critical' in str(c).lower() for c in cve_ids) else 'high',
                    f"CVEs: {cve_label}. Found via {source}.",
                    0.85,
                    [product, version] + cve_ids[:3],
                    Json(meta),
                ))
                created += 1
            conn.commit()
        # Emit webhook for confirmed CVEs
        if created > 0:
            try:
                from webhooks import emit_webhook
                emit_webhook("cve_confirmed", source, {
                    "product": product, "version": version,
                    "cve_ids": cve_ids[:10], "hosts_flagged": created,
                })
            except Exception:
                pass
    except Exception as e:
        logger.warning("Failed to apply CVEs to inventory: %s", e)
    return created


def _save_research_cache(product: str, version: str, source: str, results: dict, cve_ids: list):
    """Save research results to cache."""
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO software_research_cache (product, version, source, results, cve_ids)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (LOWER(product), LOWER(version), source)
                DO UPDATE SET results = EXCLUDED.results, cve_ids = EXCLUDED.cve_ids, updated_at = now()
            """, (product, version, source, Json(results), cve_ids))
            conn.commit()
    except Exception:
        pass


def _load_research_cache(product: str, version: str, source: str = None) -> list:
    """Load cached research results. Returns list of cache entries."""
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            if source:
                cur.execute("""
                    SELECT source, results, cve_ids, created_at, updated_at
                    FROM software_research_cache
                    WHERE LOWER(product) = LOWER(%s) AND LOWER(version) = LOWER(%s) AND source = %s
                    ORDER BY updated_at DESC LIMIT 1
                """, (product, version, source))
            else:
                cur.execute("""
                    SELECT source, results, cve_ids, created_at, updated_at
                    FROM software_research_cache
                    WHERE LOWER(product) = LOWER(%s) AND LOWER(version) = LOWER(%s)
                    ORDER BY updated_at DESC
                """, (product, version))
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


@app.get("/software/research-cache", tags=["Assets"])
def get_research_cache(
    product: str = Query(...),
    version: str = Query(""),
    authorized: bool = Depends(auth),
):
    """Get cached research results for a product+version."""
    entries = _load_research_cache(product, version)
    return {"product": product, "version": version, "entries": entries, "has_cache": len(entries) > 0}


@app.delete("/software/research-cache", tags=["Assets"])
def clear_research_cache(product: str, version: str = "", authorized: bool = Depends(auth)):
    """Clear cached research results for a product+version so next search runs fresh."""
    with get_db() as conn, conn.cursor() as cur:
        if version:
            cur.execute("DELETE FROM software_research_cache WHERE LOWER(product) = LOWER(%s) AND LOWER(version) = LOWER(%s)",
                        (product, version))
        else:
            cur.execute("DELETE FROM software_research_cache WHERE LOWER(product) = LOWER(%s)", (product,))
        deleted = cur.rowcount
        conn.commit()
    # Also clear the in-memory setting cache for CVE prompts
    _SETTING_CACHE.clear()
    return {"ok": True, "deleted": deleted, "product": product, "version": version}


@app.get("/software/searchsploit", tags=["Assets"])
def software_searchsploit(
    product: str = Query(..., description="Product name"),
    version: str = Query("", description="Version string for EDB search filter"),
    target_version: str = Query("", description="Actual installed version for AI applicability check"),
    analyze: bool = Query(False, description="Use LLM to check version applicability"),
    limit: int = Query(20, ge=1, le=50),
    authorized: bool = Depends(auth),
):
    """Search local ExploitDB index for exploits matching product + version.
    Results are ranked: exact version > major.minor > range patterns > product-only.
    With analyze=true, sends results through LLM to assess version applicability.
    Checks local CVE cache first before running AI analysis."""
    from rule_engine import _searchsploit
    check_version = target_version or version

    # Check local CVE cache first — skip AI if we already have matches
    cached_cves = _check_cve_cache(product, check_version) if check_version else []

    results = _searchsploit(product, version, limit=limit)
    exploits = [
        {
            "id": r["id"],
            "title": r["description"],
            "type": r["type"],
            "platform": r["platform"],
            "verified": r.get("verified", False),
            "date": r.get("date", ""),
            "codes": r.get("codes", ""),
            "edb_url": f"https://www.exploit-db.com/exploits/{r['id']}",
        }
        for r in results
    ]

    llm_analysis = None
    used_cache = False
    # If cache has CVE matches for this product+version, use them instead of LLM
    if analyze and cached_cves and check_version:
        used_cache = True
        logger.info("[searchsploit] Using %d cached CVEs for %s %s (skipping AI)", len(cached_cves), product, check_version)

    if analyze and exploits and check_version and not used_cache:
        import re as _re
        lines = []
        for e in exploits[:15]:
            codes = f" [{e['codes']}]" if e.get("codes") else ""
            lines.append(f"EDB-{e['id']}: {e['title']}{codes}")

        prompt = (
            f"I am running {product} version {check_version}. "
            f"For each exploit below, determine if it likely applies to my version. "
            f"Consider version ranges in the title (e.g. '< 2.4.38' means versions before 2.4.38 are affected, "
            f"'7.12.4' means that specific version is affected). "
            f"Return JSON array: [{{\"edb_id\":\"50377\",\"applies\":true,\"severity\":\"high\",\"reason\":\"affects versions before X\"}}]\n\n"
            + "\n".join(lines)
            + "\n\nReturn ONLY the JSON array."
        )

        result = llm_generate(prompt, caller="searchsploit_analyze")
        if result["ok"]:
            llm_text = _re.sub(r'```(?:json)?\s*', '', result["response"])
            json_match = _re.search(r'\[.*\]', llm_text, _re.DOTALL)
            if json_match:
                try:
                    llm_analysis = json.loads(json_match.group())
                except json.JSONDecodeError:
                    logger.warning("[searchsploit] JSON parse failed: %s", llm_text[:300])

    # Merge LLM analysis into exploits
    if llm_analysis:
        analysis_map = {str(a.get("edb_id", "")): a for a in llm_analysis}
        for e in exploits:
            a = analysis_map.get(e["id"])
            if a:
                e["applies"] = a.get("applies")
                e["ai_severity"] = a.get("severity")
                e["ai_reason"] = a.get("reason")

    # Cache any CVEs found in EDB exploit codes to local DB
    from rule_engine import _cache_cve_to_db
    all_cve_ids = []
    for e in exploits:
        for code in (e.get("codes") or "").split(";"):
            code = code.strip()
            if code.startswith("CVE-"):
                all_cve_ids.append(code)
                _cache_cve_to_db({
                    "id": code,
                    "descriptions": [{"lang": "en", "value": f"ExploitDB EDB-{e['id']}: {e['title'][:120]}"}],
                    "metrics": {},
                    "references": [{"url": e.get("edb_url", ""), "source": "exploitdb"}],
                })
    # Add cached CVE IDs
    for c in cached_cves:
        if c["cve_id"] not in all_cve_ids:
            all_cve_ids.append(c["cve_id"])

    # Cross-apply: only flag CVEs confirmed as applicable by LLM
    confirmed_cves = []
    if llm_analysis:
        for e in exploits:
            if e.get("applies") is True and e.get("codes"):
                for code in e["codes"].split(";"):
                    code = code.strip()
                    if code.startswith("CVE-") and code not in confirmed_cves:
                        confirmed_cves.append(code)
    flagged = 0
    if check_version and confirmed_cves:
        flagged = _apply_cves_to_inventory(product, check_version, confirmed_cves, source="searchsploit")

    response = {
        "product": product,
        "version": version,
        "count": len(exploits),
        "analyzed": analyze and llm_analysis is not None,
        "used_cache": used_cache,
        "cached_cves": cached_cves,
        "exploits": exploits,
        "inventory_flagged": flagged,
    }

    # Save to research cache
    if exploits or cached_cves:
        _save_research_cache(product, check_version or version, "searchsploit", response, all_cve_ids)

    return response


@app.get("/software/ddg-search-raw", tags=["Assets"])
def software_ddg_search_raw(
    query: str = Query(..., description="Search query"),
    max_results: int = Query(20),
    _: bool = Depends(auth),
):
    """Generic DuckDuckGo search — returns raw results for custom queries."""
    results = ddg_search(query, max_results=max_results)
    return {"results": results, "query": query, "count": len(results)}


@app.get("/software/ddg-search", tags=["Assets"])
def software_ddg_search(
    product: str = Query(..., description="Product name"),
    version: str = Query("", description="Version string"),
    force: bool = Query(False, description="Bypass cache and run fresh search"),
    authorized: bool = Depends(auth),
):
    """Live DuckDuckGo search for CVEs/exploits, processed through LLM for relevance."""
    import time as _ddg_time
    _ddg_start = _ddg_time.time()
    logger.info("[ddg-search] Starting for %s %s (force=%s)", product, version, force)

    # Check research cache — return cached only if not forced and cache has useful analysis
    if not force:
        cached = _load_research_cache(product, version, "ddg_search")
        if cached:
            r = cached[0].get("results", {})
            # Only use cache if it has LLM analysis results (not stale empty analysis)
            if r.get("analysis") and len(r["analysis"]) > 0:
                logger.info("[ddg-search] Returning cached results for %s %s (%d analysis)", product, version, len(r["analysis"]))
                r["from_cache"] = True
                r["cached_at"] = str(cached[0].get("updated_at", ""))
                return r
            logger.info("[ddg-search] Cache exists but has empty analysis — running fresh")

    # Run as background job — return job_id for polling
    import threading
    job_id = str(uuid.uuid4())
    _ddg_jobs[job_id] = {"status": "running", "product": product, "version": version,
                         "result": None, "stage": "starting", "stages_done": [], "started_at": time.time()}
    threading.Thread(target=_do_ddg_search_bg, args=(job_id, product, version), daemon=True).start()
    return {"job_id": job_id, "status": "running", "product": product, "version": version}


_ddg_jobs: dict = {}


def _ddg_set_stage(job_id: str, stage: str):
    """Update the current stage of a DDG search job for progress tracking."""
    if job_id in _ddg_jobs:
        _ddg_jobs[job_id]["stage"] = stage
        if stage not in _ddg_jobs[job_id].get("stages_done", []):
            _ddg_jobs[job_id].setdefault("stages_done", []).append(stage)


@app.get("/software/ddg-search/{job_id}", tags=["Assets"])
def software_ddg_search_status(job_id: str, authorized: bool = Depends(auth)):
    """Poll DDG search job status with stage progress."""
    job = _ddg_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] == "completed":
        result = job["result"]
        # Keep job for 5 minutes so reopening modal can find it, then clean up
        if time.time() - job.get("completed_at", 0) > 300:
            del _ddg_jobs[job_id]
        return result
    return {"job_id": job_id, "status": job["status"], "stage": job.get("stage", ""),
            "stages_done": job.get("stages_done", []),
            "product": job["product"], "version": job["version"]}


@app.get("/software/ddg-jobs", tags=["Assets"])
def list_ddg_jobs(authorized: bool = Depends(auth)):
    """List all active/recent DDG search jobs for progress monitoring."""
    jobs = []
    for jid, j in list(_ddg_jobs.items()):
        # Clean up old completed jobs (>10 min)
        if j["status"] == "completed" and time.time() - j.get("completed_at", 0) > 600:
            del _ddg_jobs[jid]
            continue
        jobs.append({
            "job_id": jid, "status": j["status"], "stage": j.get("stage", ""),
            "stages_done": j.get("stages_done", []),
            "product": j["product"], "version": j["version"],
            "elapsed": round(time.time() - j.get("started_at", time.time()), 1),
        })
    return {"jobs": jobs}


# ── GitHub PoC/Exploit Search ─────────────────────────────────────────────

_github_rate = {"remaining": 30, "reset": 0}


def _github_exploit_search(product: str, version: str, cve_ids: list = None) -> list:
    """Search GitHub for PoC/exploit repos matching product+version or CVE IDs.

    Returns list of dicts: {repo, url, stars, updated, description, language, topics}.
    Rate-limit aware — backs off on 403/429. Uses GitHub PAT from app_settings if set.
    """
    import time as _t
    cve_ids = cve_ids or []
    pat = ""
    try:
        pat = _get_setting("github_pat") or ""
    except Exception:
        pass
    headers = {"Accept": "application/vnd.github+json"}
    if pat:
        headers["Authorization"] = f"Bearer {pat}"

    # Check cached rate limit
    if _github_rate["remaining"] < 3 and _t.time() < _github_rate["reset"]:
        logger.debug("[github] rate limited until %s", _github_rate["reset"])
        return []

    queries = []
    if product:
        queries.append(f"{product} {version} exploit".strip())
        queries.append(f"{product} {version} PoC".strip())
    for cve in (cve_ids or [])[:5]:
        queries.append(f"{cve} exploit OR PoC")

    repos: dict = {}  # url → dict (dedup)
    for q in queries:
        try:
            resp = requests.get(
                "https://api.github.com/search/repositories",
                params={"q": q, "sort": "stars", "per_page": 10},
                headers=headers, timeout=10,
            )
            # Track rate limits
            _github_rate["remaining"] = int(resp.headers.get("X-RateLimit-Remaining", 30))
            _github_rate["reset"] = int(resp.headers.get("X-RateLimit-Reset", 0))

            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    url = item.get("html_url", "")
                    if url and url not in repos:
                        repos[url] = {
                            "repo": item.get("full_name", ""),
                            "url": url,
                            "stars": item.get("stargazers_count", 0),
                            "updated": item.get("updated_at", ""),
                            "description": (item.get("description") or "")[:200],
                            "language": item.get("language"),
                            "topics": item.get("topics", []),
                        }
            elif resp.status_code in (403, 429):
                logger.warning("[github] rate limited (%d), stopping", resp.status_code)
                break
        except Exception as e:
            logger.debug("[github] search error for %r: %s", q, e)

    return sorted(repos.values(), key=lambda r: r.get("stars", 0), reverse=True)[:15]


def _do_ddg_search_bg(job_id: str, product: str, version: str):
    """Background thread: run DDG search and store result."""
    import time as _t
    _start = _t.time()
    try:
        result = _do_ddg_search(product, version, _start, _t, _job_id=job_id)
        _ddg_jobs[job_id] = {"status": "completed", "product": product, "version": version,
                             "result": result, "completed_at": _t.time(), "started_at": _start}
    except Exception as e:
        logger.error("[ddg-search] FAILED for %s %s: %s", product, version, e, exc_info=True)
        _ddg_jobs[job_id] = {"status": "failed", "product": product, "version": version,
                             "result": {"error": str(e), "product": product, "version": version},
                             "completed_at": _t.time(), "started_at": _start}


def _do_ddg_search(product: str, version: str, _ddg_start, _ddg_time, _job_id: str = ""):
    """Internal: actual DDG search logic, separated for error handling."""
    import requests as _req
    _set_stage = lambda s: _ddg_set_stage(_job_id, s) if _job_id else None
    from rule_engine import _cache_cve_to_db
    q_base = f"{product} {version}".strip()
    query = f"{q_base} CVE exploit vulnerability"

    quick_links = [
        {"label": "Exploits", "url": f"https://duckduckgo.com/?q={q_base.replace(' ', '+')}+exploit"},
        {"label": "CVEs", "url": f"https://duckduckgo.com/?q={q_base.replace(' ', '+')}+CVE"},
        {"label": "ExploitDB", "url": f"https://duckduckgo.com/?q=site%3Aexploit-db.com+{q_base.replace(' ', '+')}"},
        {"label": "Tenable", "url": f"https://www.tenable.com/plugins/search?q={q_base.replace(' ', '+')}"},
    ]

    # Look up software release date — check manual override first, then search
    import re as _vdr
    from datetime import datetime as _dt_cls
    _current_year = _dt_cls.now().year
    version_date_info = {}
    logger.info("[ddg-search] Stage 0: Release date lookup for %s %s", product, version)
    _set_stage("Release date lookup")

    # Check for manually set release date (sticky override)
    _manual_date_key = f"release_date:{product.lower()}:{version}"
    _manual_date = _get_setting(_manual_date_key, "")
    if _manual_date:
        # Parse manual date: stored as "YYYY|date_str|url"
        _md_parts = _manual_date.split("|", 2)
        try:
            _md_year = int(_md_parts[0])
            version_date_info["release_date"] = _md_parts[1] if len(_md_parts) > 1 else str(_md_year)
            version_date_info["release_year"] = _md_year
            version_date_info["release_url"] = _md_parts[2] if len(_md_parts) > 2 else ""
            version_date_info["estimated_release_year"] = _md_year
            version_date_info["manual_override"] = True
            logger.info("[ddg-search] Using manual release date: %s for %s %s", version_date_info["release_date"], product, version)
        except (ValueError, IndexError):
            pass

    # Extract version components for flexible search
    _ver_parts = version.split('.')
    _ver_major_minor = '.'.join(_ver_parts[:2]) if len(_ver_parts) >= 2 else version

    # Build product search terms — use the last meaningful word (e.g., "Confluence" from "Atlassian Confluence")
    _product_words = [w for w in product.split() if len(w) >= 4 and w.lower() not in ('server', 'data', 'center', 'cloud')]
    _product_short = _product_words[-1] if _product_words else product

    # Search for release notes pages — STRICT: page must mention both product AND exact version
    _release_queries = [
        f'"{_product_short}" "{version}" release notes',
        f'"{_product_short}" "{version}" issues resolved',
        f'{_product_short} {version} release notes',
        f'{_product_short} {version} issues resolved',
        f'"{_product_short}" "{_ver_major_minor}" release notes',
    ]
    _release_date = None
    _release_url = None
    _release_date_str = None
    _ddg_hdr = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    # Date patterns — only match years up to current year (no future dates)
    # FIXED: Handle decade boundaries properly
    if _current_year >= 2020:
        if _current_year < 2030:
            # 2020-2029: allow 201X and 202X up to current year
            decade_digit = _current_year % 10
            _year_range = f'20(?:1[0-9]|2[0-{decade_digit}])'
        else:
            # 2030+: allow 201X, 202X, and appropriate 203X+ ranges
            _year_range = f'20(?:1[0-9]|2[0-9]|3[0-{_current_year % 10}])'
    else:
        # Fallback for edge cases
        _year_range = f'20(?:0[5-9]|1[0-9]|{str(_current_year)[2:]})'

    logger.debug("[release-date] Year range pattern: %s (current year: %d)", _year_range, _current_year)
    _date_patterns = [
        rf'((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{{1,2}},?\s+{_year_range})',
        rf'(\d{{1,2}}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+{_year_range})',
        rf'({_year_range}[-/]\d{{1,2}}[-/]\d{{1,2}})',
        rf'((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+{_year_range})',
    ]
    _release_signals = ('release note', 'changelog', 'release date', "what's new",
                        'issues resolved', 'resolved in', 'bug fix', 'patch note')

    for rq in (_release_queries if not version_date_info.get("manual_override") else []):
        if _release_date:
            break
        for r in ddg_search(rq, max_results=5):
            url = r["url"]
            combined = (r.get("title", "") + " " + r.get("snippet", "")).lower()
            if not any(s in combined for s in _release_signals):
                continue
            try:
                _rn_resp = _req.get(url, headers=_ddg_hdr, timeout=10, verify=False)
                if _rn_resp.status_code != 200:
                    continue
                _rn_text = _vdr.sub(r'<[^>]+>', ' ', _rn_resp.text)
                _rn_text = _vdr.sub(r'\s+', ' ', _rn_text)
                _rn_lower = _rn_text.lower()

                # STRICT: page MUST mention the product name
                if _product_short.lower() not in _rn_lower:
                    logger.debug("[release-date] Skipping %s — product '%s' not on page", url, _product_short)
                    continue

                # STRICT: page MUST mention the exact version (or major.minor)
                _ver_pos = _rn_lower.find(version)
                if _ver_pos < 0:
                    _ver_pos = _rn_lower.find(_ver_major_minor)
                if _ver_pos < 0:
                    logger.debug("[release-date] Skipping %s — version '%s' not on page", url, version)
                    continue

                # Only search for dates near the version mention (±300 chars)
                _window = _rn_text[max(0, _ver_pos - 300):_ver_pos + 500]

                for pat in _date_patterns:
                    m = _vdr.search(pat, _window, _vdr.IGNORECASE)
                    if m:
                        _candidate_str = m.group(1).strip()
                        ym = _vdr.search(r'(20\d{2})', _candidate_str)
                        if ym:
                            _candidate_year = int(ym.group(1))

                            # ENHANCED: Strict future date validation with logging
                            if _candidate_year > _current_year:
                                logger.warning("[release-date] Rejected future date: %s (year %d > current %d) from %s",
                                              _candidate_str, _candidate_year, _current_year, url)
                                continue
                            if _candidate_year < 2005:
                                logger.debug("[release-date] Rejected too-old date: %s (year %d < 2005) from %s",
                                            _candidate_str, _candidate_year, url)
                                continue

                            # Additional sanity check: parse the full date if possible
                            try:
                                from datetime import datetime as _dt_check
                                for _check_fmt in ["%B %d, %Y", "%B %d %Y", "%d %B %Y", "%Y-%m-%d"]:
                                    try:
                                        _parsed_date = _dt_check.strptime(_candidate_str.strip().rstrip(','), _check_fmt)
                                        if _parsed_date.year > _current_year:
                                            logger.warning("[release-date] Rejected future parsed date: %s from %s",
                                                          _candidate_str, url)
                                            raise ValueError("Future date")
                                        if _parsed_date > _dt_check.now():
                                            logger.warning("[release-date] Rejected future timestamp: %s from %s",
                                                          _candidate_str, url)
                                            raise ValueError("Future timestamp")
                                        break
                                    except ValueError:
                                        continue
                            except Exception:
                                # Date parsing failed, but year validation passed, so continue
                                pass

                            _release_date_str = _candidate_str
                            _release_date = _candidate_year
                            _release_url = url
                            logger.info("[release-date] Found valid date: %s (year %d) from %s", _candidate_str, _candidate_year, url)
                            break
                if _release_date:
                    break
            except Exception:
                pass

    if _release_date:
        version_date_info["release_date"] = _release_date_str
        version_date_info["release_year"] = _release_date
        version_date_info["release_url"] = _release_url
    else:
        logger.info("[ddg-search] No release date found for %s %s", product, version)

    estimated_release_year = version_date_info.get("release_year")
    if estimated_release_year:
        version_date_info["estimated_release_year"] = estimated_release_year
    logger.info("[ddg-search] Version date info for %s %s: %s", product, version, version_date_info)

    # Pull CVEs from NVD API and cache in local DB
    nvd_cves = []
    nvd_seen = set()
    logger.info("[ddg-search] Stage 1: NVD API lookup for %s", product)
    _set_stage("NVD API lookup")
    # Search NVD with multiple keyword variants
    nvd_keywords = [product]
    parts = product.split()
    if len(parts) >= 2:
        nvd_keywords.append(parts[0])
    nvd_api_key = _get_nvd_api_key()
    nvd_headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
    for kw in nvd_keywords:
        try:
            nvd_resp = _req.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": kw, "resultsPerPage": 50},
                headers=nvd_headers, timeout=15, verify=False)
            if nvd_resp.status_code == 200:
                for v in nvd_resp.json().get("vulnerabilities", []):
                    cve = v.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id or cve_id in nvd_seen:
                        continue
                    nvd_seen.add(cve_id)
                    summary = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                    cvss = None
                    for mk in ("cvssMetricV31", "cvssMetricV30"):
                        m = cve.get("metrics", {}).get(mk)
                        if m:
                            cvss = m[0].get("cvssData", {}).get("baseScore")
                            if cvss: break
                    nvd_cves.append({"cve_id": cve_id, "summary": summary[:200], "cvss": cvss})
                    _cache_cve_to_db(cve)
        except Exception:
            pass

    logger.info("[ddg-search] Stage 1 done: %d NVD CVEs", len(nvd_cves))
    # Scrape vendor security bulletins for dependency CVEs — works for ANY product
    logger.info("[ddg-search] Stage 2: Vendor bulletin scraping")
    _set_stage("Vendor bulletin scraping")
    vendor_cves = []
    import re as _vre
    from urllib.parse import unquote as _unquote, parse_qs as _parse_qs, urlparse as _up2

    def _extract_cve_context(html_text: str, cve_id: str, product_name: str, max_chars: int = 300) -> str:
        """Extract meaningful context around a CVE mention in HTML text.
        Looks for version ranges, severity, affected products near the CVE ID."""
        import re as _ecr
        # Strip HTML tags for text extraction
        text = _ecr.sub(r'<[^>]+>', ' ', html_text)
        text = _ecr.sub(r'\s+', ' ', text)

        # Find CVE position and grab surrounding context
        pos = text.find(cve_id)
        if pos < 0:
            return ""
        start = max(0, pos - 200)
        end = min(len(text), pos + len(cve_id) + 300)
        context = text[start:end].strip()

        # Also try to find version-range patterns nearby
        version_patterns = _ecr.findall(
            r'(?:affect|impact|fix|patch|version|before|prior|through|up to|<=?)\s*[\d]+\.[\d]+[.\d]*',
            text[max(0, pos - 500):min(len(text), pos + 500)],
            _ecr.IGNORECASE
        )
        if version_patterns:
            context += " | Versions: " + "; ".join(version_patterns[:5])

        return context[:max_chars]

    def _cve_mentions_product(html_text: str, cve_id: str, product_name: str) -> bool:
        """Check if the product name appears near a CVE mention OR in the same section.
        Returns True if the product is mentioned within ~1500 chars of the CVE ID,
        OR if the page title/heading mentions the product (single-product advisory)."""
        import re as _cmp
        text = _cmp.sub(r'<[^>]+>', ' ', html_text)
        text_lower = text.lower()

        # Build product search terms — include common variants
        product_terms = set()
        for part in product_name.split():
            if len(part) >= 4 and part.lower() not in ('server', 'data', 'center', 'cloud', 'the'):
                product_terms.add(part.lower())
        product_terms.add(product_name.lower())
        # Add "data center" and "server" variants for enterprise products
        for term in list(product_terms):
            product_terms.add(f"{term} data center")
            product_terms.add(f"{term} server")

        # Check 1: product in page title (first 500 chars) — single-product advisory
        page_header = text_lower[:500]
        if any(term in page_header for term in product_terms):
            return True

        # Check 2: product near the CVE mention (wider window — 1500 chars)
        pos = text_lower.find(cve_id.lower())
        if pos < 0:
            return False
        window = text_lower[max(0, pos - 800):min(len(text_lower), pos + 800)]
        return any(term in window for term in product_terms)

    def _extract_page_title(html_text: str) -> str:
        """Extract <title> from HTML."""
        import re as _etr
        m = _etr.search(r'<title[^>]*>([^<]+)</title>', html_text, _etr.IGNORECASE)
        return m.group(1).strip()[:150] if m else ""

    def _extract_advisory_summary(html_text: str, product_name: str) -> str:
        """Extract the first meaningful paragraph from an advisory page."""
        import re as _esr
        text = _esr.sub(r'<script[^>]*>.*?</script>', '', html_text, flags=_esr.DOTALL | _esr.IGNORECASE)
        text = _esr.sub(r'<style[^>]*>.*?</style>', '', text, flags=_esr.DOTALL | _esr.IGNORECASE)
        text = _esr.sub(r'<[^>]+>', ' ', text)
        text = _esr.sub(r'\s+', ' ', text).strip()
        # Find sentences mentioning the product or CVE
        sentences = _esr.split(r'(?<=[.!?])\s+', text)
        relevant = []
        for s in sentences:
            s = s.strip()
            if len(s) < 20:
                continue
            sl = s.lower()
            if product_name.lower() in sl or 'cve-' in sl or 'vulnerability' in sl or 'security' in sl or 'affected' in sl:
                relevant.append(s)
                if len(" ".join(relevant)) > 400:
                    break
        return " ".join(relevant)[:500] if relevant else text[:300]

    # DDG searches to find security advisories for this specific product
    bulletin_queries = [
        f'{_product_short} security advisory CVE',
        f'{_product_short} security bulletin vulnerability',
        f'{_product_short} CVE site:securityweek.com OR site:darkreading.com OR site:bleepingcomputer.com OR site:thehackernews.com',
        f'site:confluence.atlassian.com {_product_short} security bulletin',
        f'site:www.cisa.gov {_product_short} vulnerability advisory',
    ]
    bulletin_urls = set()
    ddg_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    skip_domains = {'duckduckgo.com', 'google.com', 'twitter.com', 'x.com', 'facebook.com', 'reddit.com', 'youtube.com', 'linkedin.com', 'www.linkedin.com'}
    advisory_signals = ('security', 'advisory', 'bulletin', 'vuln', 'cve', 'exploit', 'patch', 'update-guide', 'cert.')
    for bq in bulletin_queries:
        for r in ddg_search(bq, max_results=10):
            url = r["url"]
            domain = _up2(url).netloc.lower()
            if domain in skip_domains:
                continue
            if any(s in url.lower() for s in advisory_signals) or any(s in domain for s in ('cert.', 'security', 'nvd.')):
                bulletin_urls.add(url)

    # Direct scrape of known vendor security bulletin indexes (DDG often misses these)
    _vendor_bulletin_indexes = {
        "atlassian": "https://confluence.atlassian.com/security/security-advisories-bulletins-1236937381.html",
        "confluence": "https://confluence.atlassian.com/security/security-advisories-bulletins-1236937381.html",
        "jira": "https://confluence.atlassian.com/security/security-advisories-bulletins-1236937381.html",
        "bitbucket": "https://confluence.atlassian.com/security/security-advisories-bulletins-1236937381.html",
    }
    # Also add the vendor's main vulnerability disclosure page
    _vendor_vuln_pages = {
        "atlassian": "https://www.atlassian.com/trust/data-protection/vulnerabilities",
        "confluence": "https://www.atlassian.com/trust/data-protection/vulnerabilities",
        "jira": "https://www.atlassian.com/trust/data-protection/vulnerabilities",
        "bitbucket": "https://www.atlassian.com/trust/data-protection/vulnerabilities",
    }
    for _vvk, _vvu in _vendor_vuln_pages.items():
        if _vvk in product.lower() or _vvk in _product_short.lower():
            bulletin_urls.add(_vvu)
            break

    # Load user-configured vendor pages from app_settings
    try:
        with get_db() as _vpconn, _vpconn.cursor(cursor_factory=RealDictCursor) as _vpcur:
            _vpcur.execute("SELECT key, value FROM app_settings WHERE key LIKE 'vendor_page:%' AND category = 'config'")
            for _vpr in _vpcur.fetchall():
                _vpk = _vpr["key"].replace("vendor_page:", "", 1)
                if _vpk in product.lower() or _vpk in _product_short.lower():
                    try:
                        _vpdata = json.loads(_vpr["value"])
                        _vpurl = _vpdata.get("url", "")
                        _vptmpl = _vpdata.get("template", "")
                        if _vptmpl:
                            # Template with {url}, {product}, {version} placeholders
                            _vpurl = _vptmpl.replace("{url}", _vpdata.get("url", "")).replace("{product}", _product_short).replace("{version}", version)
                        if _vpurl:
                            bulletin_urls.add(_vpurl)
                            logger.info("[ddg-search] Added user-configured vendor page for '%s': %s", _vpk, _vpurl)
                    except Exception:
                        pass
    except Exception:
        pass
    _priority_bulletin_urls = []  # These get scraped first (most recent bulletins)
    for _vk, _vurl in _vendor_bulletin_indexes.items():
        if _vk in product.lower() or _vk in _product_short.lower():
            # Scrape the index page and extract the MOST RECENT bulletin links
            try:
                _idx_resp = _req.get(_vurl, headers=ddg_headers, timeout=10, verify=False)
                if _idx_resp.status_code == 200:
                    _idx_links = _vre.findall(r'href="(/security/security-bulletin-[^"]+)"', _idx_resp.text)
                    # Take the 6 most recent (they're listed newest first)
                    for _il in _idx_links[:6]:
                        _full = f"https://confluence.atlassian.com{_il}"
                        _priority_bulletin_urls.append(_full)
                    logger.info("[ddg-search] Extracted %d recent bulletins from index", len(_priority_bulletin_urls))
            except Exception:
                pass
            # Try current and recent month bulletin URLs directly (may not be on index yet)
            _months = ['january','february','march','april','may','june','july','august','september','october','november','december']
            _now = _dt_cls.now()
            for _mo_offset in range(3):  # current month, last month, 2 months ago
                _m = _now.month - _mo_offset
                _y = _now.year
                if _m <= 0:
                    _m += 12
                    _y -= 1
                _month_name = _months[_m - 1]
                # Atlassian publishes on ~3rd Tuesday — try 15-21 range
                for _day in [15, 16, 17, 18, 19, 20, 21]:
                    _try_url = f"https://confluence.atlassian.com/security/security-bulletin-{_month_name}-{_day}-{_y}-"
                    # We don't know the page ID, so search DDG for it
                    pass
                # Simpler: search DDG for the specific month
                for _sr in ddg_search(f'site:confluence.atlassian.com "security bulletin" "{_month_name}" {_y}', max_results=3):
                    if 'security-bulletin' in _sr["url"].lower() and _sr["url"] not in _priority_bulletin_urls:
                        _priority_bulletin_urls.insert(0, _sr["url"])  # insert at front (most recent)
                        logger.info("[ddg-search] Found month-specific bulletin: %s", _sr["url"])
            # Also search DDG for recent bulletins
            for _vq in [
                f'site:confluence.atlassian.com security bulletin {_product_short} CVE 2026',
                f'site:confluence.atlassian.com security bulletin {_product_short} CVE 2025',
                f'Atlassian security bulletin {_product_short} CVE',
            ]:
                for r in ddg_search(_vq, max_results=5):
                    if 'security-bulletin' in r["url"].lower():
                        if r["url"] not in _priority_bulletin_urls:
                            _priority_bulletin_urls.append(r["url"])
            logger.info("[ddg-search] Total priority bulletin URLs: %d", len(_priority_bulletin_urls))
            break
    # Priority bulletins go first, then DDG-found URLs
    _ordered_bulletin_urls = _priority_bulletin_urls + [u for u in bulletin_urls if u not in _priority_bulletin_urls]

    # Fetch advisory pages, extract CVEs with context, and follow sub-links
    visited = set()
    for burl in _ordered_bulletin_urls[:12]:
        if burl in visited:
            continue
        visited.add(burl)
        try:
            bresp2 = _req.get(burl, headers=ddg_headers, timeout=10, verify=False)
            if bresp2.status_code != 200:
                continue
            source_domain = _up2(burl).netloc
            page_title = _extract_page_title(bresp2.text)
            page_summary = _extract_advisory_summary(bresp2.text, product)
            page_cves = set(_vre.findall(r'CVE-\d{4}-\d{4,7}', bresp2.text))
            for cve_id in page_cves:
                if cve_id not in nvd_seen:
                    # Only include CVEs where the product is mentioned near the CVE
                    if not _cve_mentions_product(bresp2.text, cve_id, product):
                        continue
                    # Skip CVEs much older than the release date
                    _cve_ym = _vre.match(r'CVE-(\d{4})', cve_id)
                    if _cve_ym and estimated_release_year:
                        _cve_age = estimated_release_year - int(_cve_ym.group(1))
                        if _cve_age >= 3:
                            continue  # CVE is 3+ years before release — skip
                    nvd_seen.add(cve_id)
                    cve_context = _extract_cve_context(bresp2.text, cve_id, product)
                    summary = f"{page_title or source_domain}: {cve_context or page_summary}"[:250]
                    vendor_cves.append({"cve_id": cve_id, "summary": summary, "cvss": None, "source": "vendor_advisory", "url": burl})
                    _cache_cve_to_db({"id": cve_id, "descriptions": [{"lang": "en", "value": summary}], "metrics": {}, "references": [{"url": burl, "source": source_domain}]})
            # Follow security page links (bulletins, advisories, sub-indexes)
            if ('/security' in burl.lower() or 'bulletin' in burl.lower()) and len(visited) < 15:
                # Match both relative (/security/...) and absolute (https://...security...) links
                for link_match in _vre.finditer(r'href="((?:/security/|https?://[^"]*security[^"]*bulletin)[^"]*)"', bresp2.text):
                    sub_path = link_match.group(1)
                    sub_url = sub_path if sub_path.startswith('http') else f"https://{source_domain}{sub_path}"
                    if sub_url not in visited and len(visited) < 15:
                        visited.add(sub_url)
                        try:
                            sub_resp = _req.get(sub_url, headers=ddg_headers, timeout=10, verify=False)
                            if sub_resp.status_code == 200:
                                sub_title = _extract_page_title(sub_resp.text)
                                sub_summary = _extract_advisory_summary(sub_resp.text, product)
                                for cve_id in set(_vre.findall(r'CVE-\d{4}-\d{4,7}', sub_resp.text)):
                                    if cve_id not in nvd_seen:
                                        if not _cve_mentions_product(sub_resp.text, cve_id, product):
                                            continue
                                        _cve_ym2 = _vre.match(r'CVE-(\d{4})', cve_id)
                                        if _cve_ym2 and estimated_release_year:
                                            if estimated_release_year - int(_cve_ym2.group(1)) >= 3:
                                                continue
                                        nvd_seen.add(cve_id)
                                        cve_context = _extract_cve_context(sub_resp.text, cve_id, product)
                                        summary = f"{sub_title or source_domain}: {cve_context or sub_summary}"[:250]
                                        vendor_cves.append({"cve_id": cve_id, "summary": summary, "cvss": None, "source": "vendor_bulletin", "url": sub_url})
                                        _cache_cve_to_db({"id": cve_id, "descriptions": [{"lang": "en", "value": summary}], "metrics": {}, "references": [{"url": sub_url, "source": source_domain}]})
                        except Exception:
                            pass
        except Exception:
            pass
    nvd_cves.extend(vendor_cves)

    logger.info("[ddg-search] Stage 2 done: %d vendor advisory CVEs", len(vendor_cves))

    # Stage 2b: Tenable Nessus plugin lookup — version-specific CVE data
    logger.info("[ddg-search] Stage 2b: Tenable plugin lookup for %s %s", product, version)
    _set_stage("Tenable plugin lookup")
    tenable_cves = []
    tenable_url = None
    try:
        from urllib.parse import quote_plus as _qp
        _tenable_q = f"{_product_short} {version}"
        _tenable_search_url = f"https://www.tenable.com/plugins/search?q={_qp(_tenable_q)}"
        _tn_resp = _req.get(_tenable_search_url, headers=_ddg_hdr, timeout=15, verify=False)
        if _tn_resp.status_code == 200:
            tenable_url = _tenable_search_url
            _tn_text = _tn_resp.text
            # Extract plugin entries — Tenable pages list CVEs in plugin descriptions
            _tn_cves = set(_vre.findall(r'CVE-\d{4}-\d{4,7}', _tn_text))
            # Extract plugin titles for context
            _tn_titles = _vre.findall(r'<a[^>]*class="[^"]*plugin-name[^"]*"[^>]*>([^<]+)</a>', _tn_text)
            if not _tn_titles:
                _tn_titles = _vre.findall(r'"plugin_name"\s*:\s*"([^"]+)"', _tn_text)
            _tn_title_str = "; ".join(_tn_titles[:5]) if _tn_titles else ""

            for cve_id in _tn_cves:
                if cve_id not in nvd_seen:
                    # Age filter
                    _cve_ym3 = _vre.match(r'CVE-(\d{4})', cve_id)
                    if _cve_ym3 and estimated_release_year:
                        if estimated_release_year - int(_cve_ym3.group(1)) >= 3:
                            continue
                    nvd_seen.add(cve_id)
                    context = _extract_cve_context(_tn_text, cve_id, product) if _cve_mentions_product(_tn_text, cve_id, product) else ""
                    summary = f"Tenable plugin: {context or _tn_title_str}"[:250]
                    tenable_cves.append({"cve_id": cve_id, "summary": summary, "cvss": None, "source": "tenable", "url": _tenable_search_url})
                    _cache_cve_to_db({"id": cve_id, "descriptions": [{"lang": "en", "value": summary}], "metrics": {}, "references": [{"url": _tenable_search_url, "source": "tenable.com"}]})
            logger.info("[ddg-search] Stage 2b done: %d Tenable CVEs from %d plugins", len(tenable_cves), len(_tn_titles))
        else:
            logger.info("[ddg-search] Tenable returned HTTP %d", _tn_resp.status_code)
    except Exception as e:
        logger.warning("[ddg-search] Tenable lookup failed: %s", e)
    nvd_cves.extend(tenable_cves)

    # DDG web search for broader results
    logger.info("[ddg-search] Stage 3: DDG web search")
    _set_stage("DDG web search")
    import re
    results = []
    seen_urls = set()
    ddg_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    queries = [
        f"{q_base} security issues",
        f"{q_base} CVE exploit vulnerability",
        f"{q_base} CVE vulnerability",
        f"{product} dependency CVE vulnerability",
        f"{product} security bulletin advisory",
        f"site:tenable.com {_product_short} {version} vulnerability",
    ]
    for ddg_query in queries:
        for r in ddg_search(ddg_query, max_results=15):
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                results.append(r)
                # Cache any CVE IDs found in titles/snippets
                for cve_id in _re_module.findall(r'CVE-\d{4}-\d{4,7}', r.get("title", "") + " " + r.get("snippet", "")):
                    if cve_id not in nvd_seen:
                        nvd_seen.add(cve_id)
                        _cache_cve_to_db({"id": cve_id, "descriptions": [{"lang": "en", "value": f"From web search: {r['title'][:100]}"}], "metrics": {}, "references": [{"url": r["url"], "source": "ddg_search"}]})

    logger.info("[ddg-search] Stage 3 done: %d web results", len(results))
    # Process through LLM to filter NVD CVEs + web results for version applicability
    logger.info("[ddg-search] Stage 4: LLM analysis")
    _set_stage("LLM analysis")
    import re as _ddg_re
    llm_analysis = None
    if results or nvd_cves:
        lines = []
        # Add version date context at the top so the LLM can use it for probability
        if version_date_info:
            lines.append(f"VERSION RELEASE DATE for {product} {version}:")
            if version_date_info.get("release_date"):
                lines.append(f"  Software release date: {version_date_info['release_date']}")
                if version_date_info.get("release_url"):
                    lines.append(f"  Source: {version_date_info['release_url']}")
            elif estimated_release_year:
                lines.append(f"  Estimated release year: {estimated_release_year}")
            if version_date_info.get("copyright_years"):
                lines.append(f"  Copyright years found on pages: {', '.join(version_date_info['copyright_years'])}")
            lines.append(f"  USE THIS: A CVE from years before this release date is very likely already patched. "
                         f"A CVE published AFTER this release date is much more likely to apply.")
            lines.append("")
        # Include NVD + vendor CVEs in the prompt with full context
        if nvd_cves:
            lines.append(f"Known CVEs for {product}:")
            for c in nvd_cves[:25]:
                src_tag = f" [{c.get('source', 'nvd')}]" if c.get('source') else ""
                url_tag = f" URL: {c['url']}" if c.get('url') else ""
                lines.append(f"  {c['cve_id']} (CVSS:{c['cvss'] or '?'}){src_tag} {c['summary'][:200]}{url_tag}")
            lines.append("")
        # Include web search results
        if results:
            lines.append("Web search results:")
            for i, r in enumerate(results[:10]):
                lines.append(f"  {i+1}. {r['title'][:100]} | {r['url'][:80]}")

        # Load customizable prompt template from app_settings (or use default)
        _cve_system_prompt = _get_setting("cve_analysis.system_prompt", _DEFAULT_CVE_SYSTEM_PROMPT)
        _cve_user_template = _get_setting("cve_analysis.user_prompt", _DEFAULT_CVE_USER_PROMPT)

        prompt = _cve_system_prompt + "\n\n" + _cve_user_template.format(
            product=product, version=version, evidence="\n".join(lines)
        )

        llm_result = llm_generate(prompt, caller="ddg_cve_search", num_predict=2048)
        if llm_result["ok"]:
            llm_text = _ddg_re.sub(r'```(?:json)?\s*', '', llm_result["response"])
            json_match = _ddg_re.search(r'\[.*\]', llm_text, _ddg_re.DOTALL)
            if json_match:
                try:
                    llm_analysis = json.loads(json_match.group())
                    # Cache CVE IDs from LLM analysis
                    for item in llm_analysis:
                        cve_id = item.get("cve_id", "")
                        if cve_id and cve_id.startswith("CVE-"):
                            _cache_cve_to_db({
                                "id": cve_id,
                                "descriptions": [{"lang": "en", "value": f"LLM identified for {product} {version}: {item.get('title', '')[:120]}"}],
                                "metrics": {},
                                "references": [{"url": item.get("url", ""), "source": "llm_analysis"}],
                            })
                except json.JSONDecodeError:
                    pass

    # Collect all discovered CVE IDs for cross-apply
    all_found_cves = list(nvd_seen)
    if llm_analysis:
        for item in llm_analysis:
            cid = item.get("cve_id", "")
            if cid and cid.startswith("CVE-") and cid not in all_found_cves:
                all_found_cves.append(cid)

    # Post-LLM probability adjustment: age-aware scoring that respects LLM analysis
    # IMPROVED: Less aggressive age penalties, preserves LLM reasoning for high-confidence applies=true CVEs
    if llm_analysis and estimated_release_year:
        import re as _cve_yr_re
        from datetime import datetime as _age_dt

        # Parse the release date string for precise comparison
        _rel_date_str = version_date_info.get("release_date", "")
        _rel_dt = None
        if _rel_date_str:
            for _fmt in ["%B %d, %Y", "%B %d %Y", "%d %B %Y", "%Y-%m-%d"]:
                try:
                    _rel_dt = _age_dt.strptime(_rel_date_str.strip().rstrip(','), _fmt)
                    break
                except ValueError:
                    pass

        # Batch-fetch published dates from cve table
        _analysis_cve_ids = [item.get("cve_id", "") for item in llm_analysis if item.get("cve_id", "").startswith("CVE-")]
        _pub_dates = {}
        if _analysis_cve_ids:
            try:
                with get_db() as _aconn, _aconn.cursor(cursor_factory=RealDictCursor) as _acur:
                    _acur.execute("SELECT id, published FROM cve WHERE id = ANY(%s) AND published IS NOT NULL", (_analysis_cve_ids,))
                    for _r in _acur.fetchall():
                        _pub_dates[_r["id"]] = _r["published"]
            except Exception:
                pass

        for item in llm_analysis:
            cid = item.get("cve_id", "")
            m = _cve_yr_re.match(r'CVE-(\d{4})', cid)
            if not m:
                continue

            original_prob = item.get("probability", 50)
            if isinstance(original_prob, str):
                try:
                    original_prob = int(original_prob)
                except ValueError:
                    original_prob = 50

            applies = item.get("applies")
            llm_reason = item.get("reason", "")

            # Store original LLM assessment
            item["llm_probability"] = original_prob
            item["llm_applies"] = applies

            prob = original_prob

            # Use actual published date if available, otherwise fall back to CVE year
            pub_date = _pub_dates.get(cid)
            if pub_date and _rel_dt:
                pub_naive = pub_date.replace(tzinfo=None) if hasattr(pub_date, 'replace') else pub_date
                days_before = (_rel_dt - pub_naive).days
                years_before = days_before / 365.25

                # IMPROVED: Respect LLM's assessment for high-confidence applies=true CVEs
                # Only apply age penalties for lower-confidence or unclear cases
                if applies is True and original_prob >= 80:
                    # High confidence LLM says it applies - minimal age penalty
                    if years_before > 5:
                        prob = max(prob - 20, 60)  # Reduce by 20 but keep >= 60
                        item["age_note"] = f"Published {years_before:.1f}yr before release (LLM confidence preserved)"
                    elif years_before > 2:
                        prob = max(prob - 10, 70)  # Reduce by 10 but keep >= 70
                        item["age_note"] = f"Published {years_before:.1f}yr before release (minor age penalty)"
                    else:
                        item["age_note"] = f"Published {pub_date.strftime('%Y-%m-%d')} — recent relative to release"
                elif applies is True and original_prob >= 60:
                    # Medium confidence LLM says it applies - moderate age penalty
                    if years_before > 5:
                        prob = min(prob, 40)
                        item["age_note"] = f"Published {years_before:.1f}yr before release — likely patched"
                    elif years_before > 3:
                        prob = min(prob, 50)
                        item["age_note"] = f"Published {years_before:.1f}yr before release — may be patched"
                    elif years_before > 1:
                        prob = min(prob, 60)
                        item["age_note"] = f"Published {years_before:.1f}yr before release"
                    else:
                        item["age_note"] = f"Published {pub_date.strftime('%Y-%m-%d')} — timing supports LLM analysis"
                else:
                    # Original logic for low confidence or applies=false/likely cases
                    if years_before > 5:
                        prob = min(prob, 15)
                        item["age_note"] = f"Published {years_before:.1f}yr before release — very likely patched"
                    elif years_before > 3:
                        prob = min(prob, 25)
                        item["age_note"] = f"Published {years_before:.1f}yr before release — likely patched"
                    elif years_before > 1:
                        prob = min(prob, 50)
                        item["age_note"] = f"Published {years_before:.1f}yr before release"
                    elif days_before > 0:
                        prob = min(prob, 70)
                        item["age_note"] = f"Published {days_before}d before release"
                    else:
                        # Published AFTER release — boost confidence
                        if prob < 70 and applies is True:
                            prob = max(prob, 75)
                        item["age_note"] = f"Published {pub_date.strftime('%Y-%m-%d')} — after release"

                item["published"] = str(pub_date)[:10]
            else:
                # Fall back to CVE year with similar improved logic
                cve_year = int(m.group(1))
                years_before = estimated_release_year - cve_year

                if applies is True and original_prob >= 80:
                    # High confidence LLM - preserve assessment
                    if years_before >= 5:
                        prob = max(prob - 25, 55)
                        item["age_note"] = f"CVE year {cve_year} — {years_before}yr before release (LLM confidence preserved)"
                    elif years_before >= 2:
                        prob = max(prob - 15, 65)
                        item["age_note"] = f"CVE year {cve_year} — {years_before}yr before release (minor age penalty)"
                elif applies is True and original_prob >= 60:
                    # Medium confidence - moderate penalty
                    if years_before >= 5:
                        prob = min(prob, 35)
                        item["age_note"] = f"CVE year {cve_year} — {years_before}yr before release — likely patched"
                    elif years_before >= 3:
                        prob = min(prob, 45)
                        item["age_note"] = f"CVE year {cve_year} — {years_before}yr before release — may be patched"
                    elif years_before >= 1:
                        prob = min(prob, 55)
                        item["age_note"] = f"CVE year {cve_year} — {years_before}yr before release"
                else:
                    # Original aggressive logic for low confidence cases
                    if years_before >= 5:
                        prob = min(prob, 10)
                        item["age_note"] = f"CVE year {cve_year} — {years_before}yr before release"
                    elif years_before >= 3:
                        prob = min(prob, 25)
                        item["age_note"] = f"CVE year {cve_year} — {years_before}yr before release"
                    elif years_before >= 1:
                        prob = min(prob, 50)
                        item["age_note"] = f"CVE year {cve_year} — {years_before}yr before release"
                    elif years_before <= -1:
                        if prob < 70 and applies is True:
                            prob = max(prob, 75)
                        item["age_note"] = f"CVE year {cve_year} — after release year"

            # Log significant probability changes for debugging
            if abs(prob - original_prob) > 15:
                logger.info("[ddg-search] Adjusted %s probability: %d → %d (%s applies=%s)",
                           cid, original_prob, prob, "LLM" if applies is True else "age penalty", applies)

            item["probability"] = prob

    # Cross-apply: Flexible confirmation logic that respects LLM assessment
    confirmed_cves = []
    likely_cves = []
    if llm_analysis:
        for item in llm_analysis:
            cid = item.get("cve_id", "")
            if not cid or not cid.startswith("CVE-"):
                continue
            applies = item.get("applies")
            prob = item.get("probability", 0)
            llm_prob = item.get("llm_probability", prob)  # Original LLM assessment
            if isinstance(prob, str):
                try:
                    prob = int(prob)
                except ValueError:
                    prob = 0
            item["probability"] = prob  # normalize for response

            # IMPROVED: More flexible confirmation logic
            if applies is True:
                # High LLM confidence gets confirmed even if age-adjusted down slightly
                if prob >= 70 or (llm_prob >= 80 and prob >= 55):
                    confirmed_cves.append(cid)
                    item["confidence_level"] = "confirmed"
                elif prob >= 50 or (llm_prob >= 70 and prob >= 40):
                    likely_cves.append(cid)
                    item["confidence_level"] = "likely"
                else:
                    item["confidence_level"] = "low"
            elif applies == "likely" or applies == "probable":
                if prob >= 40:
                    likely_cves.append(cid)
                    item["confidence_level"] = "likely"
                else:
                    item["confidence_level"] = "low"
            else:
                item["confidence_level"] = "rejected"
    flagged = 0
    # Only auto-flag high-probability confirmed CVEs to inventory
    if version and confirmed_cves:
        flagged = _apply_cves_to_inventory(product, version, confirmed_cves, source="ddg_search")

    # Stage 5: Nuclei template search + scan recommendation creation
    logger.info("[ddg-search] Stage 5: Nuclei template lookup for %s", product)
    _set_stage("Nuclei template lookup")
    nuclei_templates = []
    nuclei_recs_created = 0
    try:
        _nuclei_url = os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011")
        _nr = _req.get(f"{_nuclei_url}/templates/search", params={"q": _product_short, "limit": 20},
                       timeout=15, verify=False)
        if _nr.status_code == 200:
            _nr_data = _nr.json()
            nuclei_templates = _nr_data.get("results", [])
            logger.info("[ddg-search] Found %d nuclei templates for %s", len(nuclei_templates), _product_short)

            # Create scan recommendations for matching templates
            if nuclei_templates:
                with get_db() as conn, conn.cursor() as cur:
                    # Find all hosts running this product+version
                    cur.execute("""
                        SELECT DISTINCT ip, hostname FROM detected_software
                        WHERE LOWER(product) = LOWER(%s) AND version = %s
                    """, (product, version))
                    _hosts = cur.fetchall()
                    for _host_row in _hosts:
                        _host_ip = _host_row[0] if isinstance(_host_row, tuple) else _host_row.get("ip")
                        if not _host_ip:
                            continue
                        # Build comma-separated tags from matching templates
                        _all_tags = set()
                        _template_paths = []
                        for t in nuclei_templates[:10]:
                            for tag in (t.get("tags") or "").split(","):
                                tag = tag.strip()
                                if tag:
                                    _all_tags.add(tag)
                            _template_paths.append(t.get("template_path", ""))
                        _tags_str = ",".join(sorted(_all_tags)[:15])
                        _action = f"Nuclei scan: {len(nuclei_templates)} templates matching {_product_short}"
                        # engagement_id is auto-filled by the propagate trigger
                        # (assets-by-ip lookup) when the active engagement context
                        # is available, so the INSERT itself stays minimal.
                        cur.execute("""
                            INSERT INTO scan_recommendations
                                (id, ip, scanner, action, template, source, confidence, priority, status, engagement_id)
                            VALUES (gen_random_uuid(), %s::inet, 'nuclei', %s, %s, 'ai_check', 0.8, 70, 'pending', %s::uuid)
                            ON CONFLICT (fingerprint) DO NOTHING
                        """, (_host_ip, _action, _tags_str, _resolve_engagement_id()))
                        if cur.rowcount > 0:
                            nuclei_recs_created += 1
                    conn.commit()
                logger.info("[ddg-search] Created %d nuclei scan recommendations", nuclei_recs_created)
    except Exception as e:
        logger.warning("[ddg-search] Nuclei template lookup failed: %s", e)

    # Build vendor source summary
    vendor_advisory_urls = [c.get("url") for c in vendor_cves if c.get("url")]
    _all_source_urls = list(dict.fromkeys(vendor_advisory_urls))[:10]
    if tenable_url:
        _all_source_urls.append(tenable_url)
    _source_notes = []
    # Stage 5b: GitHub PoC/exploit repo search (can be disabled via app_settings)
    github_pocs = []
    _github_enabled = (_get_setting("github_search_enabled") or "true").lower() != "false"
    if _github_enabled:
        try:
            _set_stage("github_poc_search")
            _all_cve_ids = [c.get("cve_id", "") for c in confirmed_cves + likely_cves][:5]
            github_pocs = _github_exploit_search(product, version, _all_cve_ids)
            if github_pocs:
                logger.info("[ddg-search] GitHub: found %d PoC repos for %s %s", len(github_pocs), product, version)
        except Exception as e:
            logger.warning("[ddg-search] GitHub PoC search failed: %s", e)
    else:
        logger.debug("[ddg-search] GitHub search disabled via settings")

    if vendor_cves:
        _source_notes.append(f"{len(vendor_cves)} CVEs from {len(visited)} vendor advisory pages")
    if tenable_cves:
        _source_notes.append(f"{len(tenable_cves)} CVEs from Tenable plugins")
    if github_pocs:
        _source_notes.append(f"{len(github_pocs)} GitHub PoC repos found")
    vendor_sources_info = {
        "found": len(vendor_cves) > 0 or len(tenable_cves) > 0,
        "cve_count": len(vendor_cves) + len(tenable_cves),
        "pages_scraped": len(visited),
        "tenable_count": len(tenable_cves),
        "urls": _all_source_urls,
        "note": "; ".join(_source_notes) if _source_notes else "No vendor-specific patch list found",
    }

    response = {
        "product": product,
        "version": version,
        "version_date_info": version_date_info,
        "query": query,
        "quick_links": quick_links,
        "nvd_cves": nvd_cves,
        "nvd_count": len(nvd_cves),
        "vendor_sources": vendor_sources_info,
        "raw_results": results[:15],
        "analysis": llm_analysis or [],
        "confirmed_cves": confirmed_cves,
        "likely_cves": likely_cves,
        "nuclei_templates": nuclei_templates[:10],
        "nuclei_recs_created": nuclei_recs_created,
        "github_pocs": github_pocs[:10],
        "count": len(results),
        "inventory_flagged": flagged,
    }

    # Save to research cache — replace ALL old cache entries for this product+version
    if nvd_cves or results or llm_analysis:
        try:
            with get_db() as conn, conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM software_research_cache
                    WHERE LOWER(product) = LOWER(%s) AND LOWER(version) = LOWER(%s)
                      AND source != 'ddg_search'
                """, (product, version))
                conn.commit()
        except Exception:
            pass
        _save_research_cache(product, version, "ddg_search", response, all_found_cves)

    elapsed = round(_ddg_time.time() - _ddg_start, 1)
    logger.info("[ddg-search] Complete for %s %s: %d NVD, %d web, %d analysis, %d flagged in %.1fs",
                product, version, len(nvd_cves), len(results), len(llm_analysis or []), flagged, elapsed)

    # Emit webhook for AI check completed
    try:
        from webhooks import emit_webhook
        emit_webhook("ai_check_completed", "ddg_search", {
            "product": product, "version": version,
            "nvd_count": len(nvd_cves), "analysis_count": len(llm_analysis or []),
            "confirmed_cves": confirmed_cves, "likely_cves": likely_cves,
            "inventory_flagged": flagged, "elapsed_seconds": elapsed,
            "release_date": version_date_info.get("release_date"),
        })
    except Exception:
        pass

    return response


_bulk_check_status: dict = {"running": False, "cancelled": False, "progress": {}}


class BulkCheckRequest(BaseModel):
    skip_cached: bool = True
    proxy: str = ""
    rate_limit: float = 3.0
    selected: list = []  # Optional list of {"product": "...", "version": "..."} to check
    deep_search: bool = False  # Run deep search on vendor bulletin CVEs after initial check


@app.post("/software/bulk-check", tags=["Assets"])
def software_bulk_check(
    body: BulkCheckRequest,
    background_tasks: BackgroundTasks,
    authorized: bool = Depends(auth),
):
    """Bulk AI check product+version combos. If selected is empty, checks all."""
    if _bulk_check_status["running"]:
        return {"ok": False, "error": "Bulk check already running", "progress": _bulk_check_status["progress"]}

    if body.selected:
        items = [{"product": s["product"], "version": s["version"], "host_count": 0} for s in body.selected]
    else:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT product, version, COUNT(DISTINCT COALESCE(hostname, ip)) as host_count
                FROM detected_software
                WHERE version IS NOT NULL AND version != '' AND product IS NOT NULL AND product != ''
                GROUP BY product, version
                ORDER BY host_count DESC
            """)
            items = [dict(r) for r in cur.fetchall()]

    # Filter out already-cached if requested
    if body.skip_cached:
        uncached = []
        for item in items:
            cached = _load_research_cache(item["product"], item["version"])
            if not cached:
                uncached.append(item)
        skipped = len(items) - len(uncached)
        items = uncached
    else:
        skipped = 0

    _bulk_check_status["running"] = True
    _bulk_check_status["progress"] = {
        "total": len(items), "completed": 0, "skipped": skipped,
        "flagged": 0, "errors": 0, "current": None, "stage": None,
        "stages_run": {"searchsploit": 0, "nvd": 0, "ddg": 0, "advisory": 0, "cve_cache": 0},
    }

    background_tasks.add_task(_run_bulk_check, items, body.proxy or DDG_PROXY, body.rate_limit, body.deep_search)
    _bulk_check_status["progress"]["deep_search"] = body.deep_search

    try:
        from webhooks import emit_webhook
        emit_webhook("bulk_check_started", "ai_check", {
            "total": len(items), "skipped": skipped, "deep_search": body.deep_search,
        })
    except Exception:
        pass

    return {"ok": True, "total": len(items), "skipped": skipped}


@app.get("/software/bulk-check/status", tags=["Assets"])
def software_bulk_check_status(authorized: bool = Depends(auth)):
    """Get status of running bulk check."""
    return _bulk_check_status


@app.post("/software/bulk-check/cancel", tags=["Assets"])
def software_bulk_check_cancel(authorized: bool = Depends(auth)):
    """Cancel running bulk check."""
    if _bulk_check_status["running"]:
        _bulk_check_status["cancelled"] = True
        return {"ok": True, "message": "Cancel requested"}
    return {"ok": False, "message": "No bulk check running"}


def _run_bulk_check(items: list, proxy: str, rate_limit: float, deep_search: bool = False):
    """Background: check each product+version sequentially with per-site rate limiting."""
    import time
    from urllib.parse import urlparse as _urlparse_bl
    from rule_engine import _searchsploit, _web_cve_search, _cache_cve_to_db

    _bulk_check_status["cancelled"] = False
    progress = _bulk_check_status["progress"]

    # Per-site rate limiting: track last request time per domain
    _site_last_hit: dict = {}

    def _rate_limit_site(domain: str):
        """Sleep if we hit the same domain too recently."""
        now = time.time()
        last = _site_last_hit.get(domain, 0)
        wait = rate_limit - (now - last)
        if wait > 0:
            time.sleep(wait)
        _site_last_hit[domain] = time.time()

    # Monkey-patch ddg_search to respect per-site rate limit
    _orig_ddg = ddg_search
    proxy_default = proxy  # capture outer proxy arg for use in closure

    def _throttled_ddg(query, max_results=15, timeout=10.0, proxy=None, **kwargs):
        _rate_limit_site("lite.duckduckgo.com")
        return _orig_ddg(query, max_results=max_results, timeout=timeout, proxy=proxy or proxy_default)

    # Patch _web_cve_search's NVD calls via rate limiting
    _orig_requests_get = requests.get

    def _throttled_get(url, **kwargs):
        try:
            domain = _urlparse_bl(url).netloc
            if domain:
                _rate_limit_site(domain)
        except Exception:
            pass
        return _orig_requests_get(url, **kwargs)

    try:
        # Temporarily patch for rate limiting
        import api as _api_mod
        _api_mod.ddg_search = _throttled_ddg
        requests.get = _throttled_get

        for i, item in enumerate(items):
            if _bulk_check_status["cancelled"]:
                progress["current"] = "Cancelled"
                break
            product = item["product"]
            version = item["version"]
            progress["current"] = f"{product} {version}"
            progress["completed"] = i

            try:
                # 1. Local searchsploit (instant, no network)
                progress["stage"] = f"searchsploit: {product}"
                edb_results = _searchsploit(product, version, limit=10)
                progress["stages_run"]["searchsploit"] += 1
                cve_ids = []
                for e in edb_results:
                    for code in (e.get("codes") or "").split(";"):
                        code = code.strip()
                        if code.startswith("CVE-"):
                            cve_ids.append(code)
                            _cache_cve_to_db({"id": code, "descriptions": [{"lang": "en", "value": f"EDB: {e['description'][:100]}"}], "metrics": {}, "references": []})

                # 2. Web CVE search (DDG + NVD, per-site rate limited)
                progress["stage"] = f"NVD + DDG: {product}"
                web_cves = _web_cve_search(product, version)
                progress["stages_run"]["nvd"] += 1
                progress["stages_run"]["ddg"] += 1
                cve_ids.extend([c for c in web_cves if c not in cve_ids])

                # 3. Check CVE cache (instant, local DB)
                progress["stage"] = f"CVE cache: {product}"
                cached = _check_cve_cache(product, version)
                progress["stages_run"]["cve_cache"] += 1
                for c in cached:
                    if c["cve_id"] not in cve_ids:
                        cve_ids.append(c["cve_id"])

                # 4. Cross-apply — only EDB version-matched CVEs
                edb_cves = []
                for e in edb_results:
                    for code in (e.get("codes") or "").split(";"):
                        code = code.strip()
                        if code.startswith("CVE-") and code not in edb_cves:
                            edb_cves.append(code)
                if edb_cves:
                    flagged_count = _apply_cves_to_inventory(product, version, edb_cves, source="bulk_check")
                    progress["flagged"] += flagged_count

                # Save to research cache
                _save_research_cache(product, version, "searchsploit", {
                    "count": len(edb_results), "cve_ids": cve_ids,
                    "exploits": [{"id": e["id"], "title": e["description"][:100]} for e in edb_results[:10]],
                }, cve_ids)

                # 5. Deep search on vendor bulletin CVEs if enabled
                # Only deep-search CVEs published after the software release date
                if deep_search and cve_ids:
                    import re as _dsr
                    from datetime import datetime as _ds_dt

                    # Get release date (full date string + year)
                    _release_yr = 0
                    _release_date_str = ""
                    _rd_key = f"release_date:{product.lower()}:{version}"
                    _rd_val = _get_setting(_rd_key, "")
                    if _rd_val:
                        _rd_parts = _rd_val.split("|", 2)
                        try: _release_yr = int(_rd_parts[0])
                        except: pass
                        _release_date_str = _rd_parts[1] if len(_rd_parts) > 1 else ""

                    # Try to parse the release date for precise comparison
                    _release_dt = None
                    if _release_date_str:
                        for _fmt in ["%B %d, %Y", "%B %d %Y", "%d %B %Y", "%Y-%m-%d"]:
                            try:
                                _release_dt = _ds_dt.strptime(_release_date_str.strip().rstrip(','), _fmt)
                                break
                            except ValueError:
                                pass

                    # Look up actual published dates from the cve table
                    _cve_pub_dates = {}
                    try:
                        with get_db() as _dconn, _dconn.cursor(cursor_factory=RealDictCursor) as _dcur:
                            _dcur.execute("SELECT id, published FROM cve WHERE id = ANY(%s) AND published IS NOT NULL", (cve_ids,))
                            for _r in _dcur.fetchall():
                                _cve_pub_dates[_r["id"]] = _r["published"]
                    except Exception:
                        pass

                    # Filter: skip CVEs published before the release date
                    _deep_cves = []
                    for c in cve_ids:
                        pub = _cve_pub_dates.get(c)
                        if pub and _release_dt:
                            # Use actual dates if both available
                            if pub.replace(tzinfo=None) < _release_dt:
                                continue
                        elif _release_yr:
                            # Fall back to CVE year vs release year
                            _cm = _dsr.match(r'CVE-(\d{4})', c)
                            if _cm and int(_cm.group(1)) < _release_yr:
                                continue
                        _deep_cves.append(c)

                    logger.info("[bulk-deep] Filtered %d → %d CVEs (release: %s)", len(cve_ids), len(_deep_cves), _release_date_str or _release_yr or 'unknown')
                    progress["stage"] = f"Deep search: {product} ({len(_deep_cves)} CVEs)"
                    try:
                        _pw = [w for w in product.split() if len(w) >= 4 and w.lower() not in ('server', 'data', 'center', 'cloud')]
                        _ps = _pw[-1] if _pw else product
                        _hdr = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                        for cve_id in _deep_cves[:10]:
                            if _bulk_check_status["cancelled"]:
                                break
                            best_context = ""
                            for sq in [f'{cve_id} {_ps}', f'{cve_id} {_ps} {version}']:
                                for r in ddg_search(sq, max_results=3):
                                    try:
                                        resp = requests.get(r["url"], headers=_hdr, timeout=10, verify=False)
                                        if resp.status_code != 200:
                                            continue
                                        text = _dsr.sub(r'<[^>]+>', ' ', resp.text)
                                        text = _dsr.sub(r'\s+', ' ', text)
                                        if cve_id.lower() in text.lower():
                                            pos = text.lower().find(cve_id.lower())
                                            ctx = text[max(0, pos - 400):pos + 600].strip()[:500]
                                            if len(ctx) > len(best_context):
                                                best_context = ctx
                                    except Exception:
                                        pass
                            if best_context:
                                _prompt = (
                                    f"Does {cve_id} affect {product} version {version}?\n\n"
                                    f"Evidence:\n{best_context[:1500]}\n\n"
                                    f"Answer JSON: {{\"applies\": true/false, \"probability\": 0-100, \"reason\": \"...\"}}\n"
                                    f"Return ONLY the JSON."
                                )
                                llm_r = llm_generate(_prompt, caller="bulk_deep_search", num_predict=256)
                                if llm_r["ok"]:
                                    try:
                                        _m = _dsr.search(r'\{[^}]+\}', llm_r["response"])
                                        if _m:
                                            _p = json.loads(_m.group())
                                            if _p.get("applies") is True and (_p.get("probability", 0) >= 75):
                                                _apply_cves_to_inventory(product, version, [cve_id], source="deep_search")
                                                progress["flagged"] += 1
                                                logger.info("[bulk-deep] Confirmed %s for %s %s (prob=%s)", cve_id, product, version, _p.get("probability"))
                                    except Exception:
                                        pass
                            time.sleep(rate_limit)
                    except Exception as de:
                        logger.warning("[bulk-deep] Deep search failed for %s: %s", product, de)

            except Exception as e:
                progress["errors"] += 1
                logger.warning("[bulk-check] Error for %s %s: %s", product, version, e)

        progress["completed"] = len(items)
        progress["current"] = None
    finally:
        # Restore original functions
        _api_mod.ddg_search = _orig_ddg
        requests.get = _orig_requests_get
        _bulk_check_status["running"] = False

        try:
            from webhooks import emit_webhook
            emit_webhook("bulk_check_completed", "ai_check", {
                "total": progress.get("completed", 0),
                "flagged": progress.get("flagged", 0),
                "errors": progress.get("errors", 0),
                "stages_run": progress.get("stages_run", {}),
            })
        except Exception:
            pass


class CveDeepSearchBody(BaseModel):
    product: str
    version: str
    cve_ids: list  # list of CVE IDs to deep-search


@app.get("/software/vendor-pages", tags=["Assets"])
def list_vendor_pages(authorized: bool = Depends(auth)):
    """List configured vendor search pages per product keyword."""
    pages = []
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT key, value FROM app_settings WHERE key LIKE 'vendor_page:%' AND category = 'config' ORDER BY key")
        for row in cur.fetchall():
            key = row["key"].replace("vendor_page:", "", 1)
            try:
                data = json.loads(row["value"])
            except Exception:
                data = {"url": row["value"], "template": ""}
            pages.append({
                "product_keyword": key,
                "url": data.get("url", ""),
                "search_template": data.get("template", ""),
                "note": data.get("note", ""),
            })
    return {"pages": pages}


class VendorPageBody(BaseModel):
    product_keyword: str  # e.g., "atlassian" or "confluence"
    url: str
    search_template: str = ""  # e.g., "{url}?q={product}+{version}" — {product}, {version}, {url} placeholders
    note: str = ""


@app.put("/software/vendor-pages", tags=["Assets"])
def save_vendor_page(body: VendorPageBody, authorized: bool = Depends(auth)):
    """Add or update a vendor search page for a product keyword."""
    key = f"vendor_page:{body.product_keyword.lower().strip()}"
    val = json.dumps({"url": body.url.strip(), "template": body.search_template.strip(), "note": body.note.strip()})
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO app_settings (key, value, category)
            VALUES (%s, %s, 'config')
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        """, (key, val))
        conn.commit()
    _SETTING_CACHE.pop(key, None)
    return {"ok": True, "product_keyword": body.product_keyword}


@app.delete("/software/vendor-pages/{keyword}", tags=["Assets"])
def delete_vendor_page(keyword: str, authorized: bool = Depends(auth)):
    """Remove a vendor page entry."""
    key = f"vendor_page:{keyword.lower().strip()}"
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM app_settings WHERE key = %s", (key,))
        conn.commit()
    _SETTING_CACHE.pop(key, None)
    return {"ok": True, "keyword": keyword}


@app.get("/software/github-search", tags=["Assets"])
def software_github_search(
    product: str = Query(...),
    version: str = Query(""),
    cve: str = Query("", description="Comma-separated CVE IDs"),
    force: bool = Query(False, description="Bypass cache"),
    authorized: bool = Depends(auth),
):
    """Search GitHub for PoC/exploit repositories matching product+version or CVEs."""
    cve_ids = [c.strip() for c in cve.split(",") if c.strip()] if cve else []

    # Check cache unless force
    if not force:
        try:
            with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT results FROM software_research_cache
                    WHERE LOWER(product) = LOWER(%s) AND LOWER(version) = LOWER(%s)
                      AND source = 'github_search' AND created_at > now() - interval '24 hours'
                    ORDER BY created_at DESC LIMIT 1
                """, (product, version))
                row = cur.fetchone()
                if row and row["results"]:
                    cached = row["results"] if isinstance(row["results"], dict) else json.loads(row["results"])
                    return {"product": product, "version": version, "repos": cached.get("repos", []),
                            "cached": True, "count": len(cached.get("repos", []))}
        except Exception:
            pass

    repos = _github_exploit_search(product, version, cve_ids)

    # Cache results
    if repos:
        try:
            with get_db() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO software_research_cache (product, version, source, results, cve_ids)
                    VALUES (%s, %s, 'github_search', %s, %s)
                """, (product, version, Json({"repos": repos}), cve_ids or None))
        except Exception:
            pass

    return {"product": product, "version": version, "repos": repos,
            "cached": False, "count": len(repos)}


class ManualUrlScanBody(BaseModel):
    product: str
    version: str
    urls: list  # list of URLs to scrape


@app.post("/software/scan-urls", tags=["Assets"])
def scan_manual_urls(body: ManualUrlScanBody, authorized: bool = Depends(auth)):
    """Scrape user-provided URLs, extract CVEs, and run LLM analysis against the product+version.
    Use this to manually add vendor advisory pages the automated search missed."""
    import re as _mur

    _hdr = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    _pw = [w for w in body.product.split() if len(w) >= 4 and w.lower() not in ('server', 'data', 'center', 'cloud')]
    _ps = _pw[-1] if _pw else body.product

    pages = []
    all_cves = []
    all_context = []

    for url in body.urls[:10]:
        url = url.strip()
        if not url.startswith('http'):
            continue
        page_info = {"url": url, "title": "", "cves_found": 0, "has_product": False}
        try:
            resp = requests.get(url, headers=_hdr, timeout=15, verify=False)
            if resp.status_code != 200:
                page_info["error"] = f"HTTP {resp.status_code}"
                pages.append(page_info)
                continue
            text = _mur.sub(r'<[^>]+>', ' ', resp.text)
            text = _mur.sub(r'\s+', ' ', text)

            # Extract title
            tm = _mur.search(r'<title[^>]*>([^<]+)</title>', resp.text, _mur.IGNORECASE)
            page_info["title"] = tm.group(1).strip()[:100] if tm else ""

            page_info["has_product"] = _ps.lower() in text.lower()

            # Extract CVEs
            cves = list(dict.fromkeys(_mur.findall(r'CVE-\d{4}-\d{4,7}', text)))
            page_info["cves_found"] = len(cves)

            for cve_id in cves:
                if cve_id not in all_cves:
                    all_cves.append(cve_id)
                    # Extract context around CVE
                    pos = text.lower().find(cve_id.lower())
                    if pos >= 0:
                        ctx = text[max(0, pos - 300):pos + 500].strip()[:400]
                        all_context.append(f"{cve_id}: {ctx}")
                    # Cache the CVE
                    from rule_engine import _cache_cve_to_db
                    _cache_cve_to_db({"id": cve_id, "descriptions": [{"lang": "en", "value": f"Manual URL: {page_info['title'][:80]}"}], "metrics": {}, "references": [{"url": url, "source": "manual"}]})
        except Exception as e:
            page_info["error"] = str(e)[:100]
        pages.append(page_info)

    # Run LLM analysis on extracted CVEs
    analysis = []
    if all_cves and all_context:
        evidence = "\n".join(all_context[:30])
        # Manual URL scan uses a more aggressive prompt — tester vouches for this URL
        _manual_system = (
            "You are a vulnerability analyst. A security tester has manually provided a URL to a "
            "vendor advisory page. Their confidence is that the advisory applies to the target product+version. "
            "Analyze the evidence from that page.\n"
            "IMPORTANT multi-track versioning rules for Atlassian:\n"
            "- Confluence has parallel tracks: LTS (e.g. 9.2.x) and feature release (e.g. 9.12.x)\n"
            "- A fix in '9.2.15' LTS does NOT mean 9.12.x is safe — the fix may need a different feature release\n"
            "- If the advisory lists 9.2.x as affected without mentioning 9.12.x explicitly, treat 9.12.x as 'likely' affected "
            "unless the advisory EXPLICITLY states 9.12.x is not vulnerable\n"
            "- Since the tester manually provided this URL, default to higher probability (60-90) for matches\n"
        )
        _usr = _get_setting("cve_analysis.user_prompt", _DEFAULT_CVE_USER_PROMPT)
        prompt = _manual_system + "\n\n" + _usr.format(product=body.product, version=body.version, evidence=evidence)

        llm_result = llm_generate(prompt, caller="manual_url_scan", num_predict=2048)
        if llm_result["ok"]:
            import re as _ljr
            llm_text = _ljr.sub(r'```(?:json)?\s*', '', llm_result["response"])
            jm = _ljr.search(r'\[.*\]', llm_text, _ljr.DOTALL)
            if jm:
                try:
                    analysis = json.loads(jm.group())
                    # Auto-flag confirmed high-probability CVEs — lower threshold for manual URLs (tester vouched)
                    for item in analysis:
                        cid = item.get("cve_id", "")
                        applies = item.get("applies")
                        prob = item.get("probability", 0)
                        if cid and (applies is True and prob >= 50) or (applies == "likely" and prob >= 70):
                            _apply_cves_to_inventory(body.product, body.version, [cid], source="manual_url")
                except json.JSONDecodeError:
                    pass

    return {
        "product": body.product, "version": body.version,
        "pages": pages, "cves_found": all_cves,
        "analysis": analysis, "cve_count": len(all_cves),
    }


@app.get("/software/deep-search-cache", tags=["Assets"])
def get_deep_search_cache(product: str, version: str, authorized: bool = Depends(auth)):
    """Get cached deep search results for a product+version."""
    key = f"deep_search:{product.lower()}:{version}"
    val = _get_setting(key, "")
    if val:
        try:
            return {"product": product, "version": version, "results": json.loads(val)}
        except Exception:
            pass
    return {"product": product, "version": version, "results": {}}


@app.post("/software/cve-deep-search", tags=["Assets"])
def cve_deep_search(body: CveDeepSearchBody, authorized: bool = Depends(auth)):
    """Deep search specific CVEs: for each CVE, search DDG for the CVE+product+version,
    fetch the top advisory pages, extract version applicability context, and run through LLM.
    Returns per-CVE results with vendor page links and applicability assessment."""
    import re as _dsr
    product = body.product
    version = body.version
    cve_ids = body.cve_ids[:20]  # limit to 20

    # Build product short name
    _pw = [w for w in product.split() if len(w) >= 4 and w.lower() not in ('server', 'data', 'center', 'cloud')]
    _ps = _pw[-1] if _pw else product

    _hdr = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    results = []

    for cve_id in cve_ids:
        entry = {"cve_id": cve_id, "pages": [], "context": "", "applies": None, "probability": None, "reason": ""}
        # Search DDG for this specific CVE + product
        search_queries = [
            f'{cve_id} {_ps}',
            f'{cve_id} {_ps} {version}',
        ]
        pages_checked = []
        best_context = ""
        for sq in search_queries:
            for r in ddg_search(sq, max_results=5):
                url = r["url"]
                if url in [p["url"] for p in pages_checked]:
                    continue
                page_info = {"url": url, "title": r.get("title", ""), "has_cve": False, "has_product": False, "context": ""}
                try:
                    resp = requests.get(url, headers=_hdr, timeout=10, verify=False)
                    if resp.status_code != 200:
                        pages_checked.append(page_info)
                        continue
                    text = _dsr.sub(r'<[^>]+>', ' ', resp.text)
                    text = _dsr.sub(r'\s+', ' ', text)
                    text_lower = text.lower()

                    page_info["has_cve"] = cve_id.lower() in text_lower
                    page_info["has_product"] = _ps.lower() in text_lower

                    if page_info["has_cve"]:
                        # Extract context around the CVE mention
                        pos = text_lower.find(cve_id.lower())
                        if pos >= 0:
                            ctx = text[max(0, pos - 400):pos + 600].strip()
                            page_info["context"] = ctx[:500]
                            # Look for version info near the CVE
                            ver_window = text_lower[max(0, pos - 800):pos + 800]
                            ver_matches = _dsr.findall(
                                r'(?:affect|impact|fix|before|prior|through|up to|<=?)\s*[\d]+\.[\d]+[.\d]*',
                                ver_window, _dsr.IGNORECASE
                            )
                            if ver_matches:
                                page_info["context"] += " | Versions: " + "; ".join(ver_matches[:5])
                            if not best_context or len(page_info["context"]) > len(best_context):
                                best_context = page_info["context"]
                except Exception:
                    pass
                pages_checked.append(page_info)
                if len(pages_checked) >= 6:
                    break
            if len(pages_checked) >= 6:
                break

        entry["pages"] = [p for p in pages_checked if p["has_cve"] or p["has_product"]]
        entry["context"] = best_context

        # Use LLM to assess applicability if we found context
        if best_context:
            _prompt = (
                f"Does {cve_id} affect {product} version {version}?\n\n"
                f"Evidence from advisory pages:\n{best_context[:1500]}\n\n"
                f"Answer with JSON: {{\"applies\": true/false/\"likely\", \"probability\": 0-100, "
                f"\"reason\": \"brief explanation\"}}\n"
                f"Consider multi-track versioning (LTS vs feature releases). Return ONLY the JSON."
            )
            llm_result = llm_generate(_prompt, caller="cve_deep_search", num_predict=256)
            if llm_result["ok"]:
                try:
                    _match = _dsr.search(r'\{[^}]+\}', llm_result["response"])
                    if _match:
                        _parsed = json.loads(_match.group())
                        entry["applies"] = _parsed.get("applies")
                        entry["probability"] = _parsed.get("probability")
                        entry["reason"] = _parsed.get("reason", "")
                except Exception:
                    pass

        results.append(entry)

    # Persist results to app_settings so they survive across modal sessions
    try:
        _ds_key = f"deep_search:{product.lower()}:{version}"
        # Merge with any existing cached results (don't lose previous deep searches)
        _existing = {}
        _ev = _get_setting(_ds_key, "")
        if _ev:
            try:
                _existing = json.loads(_ev)
            except Exception:
                pass
        # Index by cve_id
        _new_dict = {r["cve_id"]: r for r in results}
        _existing.update(_new_dict)
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO app_settings (key, value, category)
                VALUES (%s, %s, 'config')
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
            """, (_ds_key, json.dumps(_existing)))
            conn.commit()
        _SETTING_CACHE.pop(_ds_key, None)
    except Exception as e:
        logger.warning("Failed to cache deep search results: %s", e)

    return {"product": product, "version": version, "results": results}


class CveDecisionBody(BaseModel):
    product: str
    version: str
    cve_id: str
    action: str  # "accept" or "decline"
    target: str = ""


@app.post("/software/cve-decision", tags=["Assets"])
def software_cve_decision(body: CveDecisionBody, authorized: bool = Depends(auth)):
    """Accept or decline a probable CVE match for a product+version."""
    if body.action == "accept":
        # Create follow_up_item
        cve_ids = [body.cve_id]
        flagged = _apply_cves_to_inventory(body.product, body.version, cve_ids, source="manual_accept")
        return {"ok": True, "action": "accepted", "flagged": flagged}
    elif body.action == "decline":
        # Store decline in research cache so it doesn't show again
        try:
            with get_db() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO app_settings (key, value, category)
                    VALUES (%s, %s, 'cve_decline')
                    ON CONFLICT (key) DO NOTHING
                """, (f"decline:{body.product}:{body.version}:{body.cve_id}", "declined"))
                conn.commit()
        except Exception:
            pass
        return {"ok": True, "action": "declined"}
    return {"ok": False, "error": "action must be 'accept' or 'decline'"}


@app.get("/software/cve-decisions", tags=["Assets"])
def get_cve_decisions(product: str, version: str, authorized: bool = Depends(auth)):
    """Get declined CVEs for a product+version."""
    declined = set()
    try:
        with get_db() as conn, conn.cursor() as cur:
            prefix = f"decline:{product}:{version}:"
            cur.execute("SELECT key FROM app_settings WHERE category = 'cve_decline' AND key LIKE %s", (f"{prefix}%",))
            for row in cur.fetchall():
                cve_id = row[0].replace(prefix, "")
                declined.add(cve_id)
    except Exception:
        pass
    return {"product": product, "version": version, "declined": list(declined)}


@app.get("/software/llm-debug", tags=["Assets"])
def get_llm_debug(product: str, version: str = "", authorized: bool = Depends(auth)):
    """Get the last LLM prompt + response for a CVE analysis on a given product+version.
    Useful for reviewing/debugging why specific CVEs were or weren't flagged."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, caller, model_name, prompt_tokens, completion_tokens, tokens_per_sec,
                   latency_ms, is_error, error_message, request_params, created_at
            FROM llm_request_metrics
            WHERE caller = 'ddg_cve_search'
              AND request_params->>'prompt' LIKE %s
            ORDER BY created_at DESC LIMIT 5
        """, (f"%{product}%",))
        rows = cur.fetchall()
        # Filter further by version if specified
        if version:
            filtered = [r for r in rows if version in (r.get("request_params") or {}).get("prompt", "")]
            if filtered:
                rows = filtered
        results = []
        for r in rows:
            params = r.get("request_params") or {}
            results.append({
                "id": str(r["id"]),
                "model": r["model_name"],
                "created_at": str(r["created_at"]),
                "latency_ms": r["latency_ms"],
                "tokens": r["completion_tokens"],
                "prompt": params.get("prompt", ""),
                "response": params.get("response", ""),
                "is_error": r["is_error"],
                "error": r["error_message"],
            })
    return {"product": product, "version": version, "checks": results}


@app.get("/software/analysis-debug", tags=["Assets"])
def get_analysis_debug(product: str, version: str = "", authorized: bool = Depends(auth)):
    """Get comprehensive debug information for AI exploit analysis of a product+version.
    Shows release date info, CVE sources, LLM analysis, age adjustments, and final decisions."""
    debug_info = {
        "product": product,
        "version": version,
        "timestamp": str(datetime.datetime.now()),
        "release_date_info": {},
        "cve_sources": {},
        "llm_analysis": {},
        "age_adjustments": {},
        "final_decisions": {},
        "configuration": {}
    }

    # 1. Release date information
    rel_key = f"release_date:{product.lower()}:{version}"
    rel_override = _get_setting(rel_key, "")
    if rel_override:
        parts = rel_override.split("|", 2)
        debug_info["release_date_info"] = {
            "manual_override": True,
            "release_year": int(parts[0]) if parts[0].isdigit() else None,
            "release_date": parts[1] if len(parts) > 1 else parts[0],
            "release_url": parts[2] if len(parts) > 2 else "",
            "source": "manual_override"
        }
    else:
        debug_info["release_date_info"] = {
            "manual_override": False,
            "note": "Would be auto-detected from web search during DDG analysis"
        }

    # 2. Research cache information
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT source, results, updated_at
                FROM software_research_cache
                WHERE LOWER(product) = LOWER(%s) AND version = %s
                ORDER BY updated_at DESC
            """, (product, version))
            cache_entries = cur.fetchall()

            for entry in cache_entries:
                source = entry["source"]
                results = entry.get("results", {})
                debug_info["cve_sources"][source] = {
                    "cached_at": str(entry["updated_at"]),
                    "analysis_count": len(results.get("analysis", [])),
                    "raw_results_count": len(results.get("raw_results", [])),
                    "vendor_sources": results.get("vendor_sources", {}),
                    "sample_analysis": results.get("analysis", [])[:3]  # First 3 for preview
                }
    except Exception as e:
        debug_info["cve_sources"]["error"] = str(e)

    # 3. Current LLM configuration
    debug_info["configuration"] = {
        "system_prompt_length": len(_get_setting("cve_analysis.system_prompt", _DEFAULT_CVE_SYSTEM_PROMPT)),
        "user_prompt_template_length": len(_get_setting("cve_analysis.user_prompt", _DEFAULT_CVE_USER_PROMPT)),
        "using_custom_prompts": bool(_get_setting("cve_analysis.system_prompt", "")),
        "current_year": datetime.datetime.now().year
    }

    # 4. Recent LLM requests for this product
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT created_at, model_name, completion_tokens, latency_ms, is_error
                FROM llm_request_metrics
                WHERE caller = 'ddg_cve_search'
                  AND request_params->>'prompt' LIKE %s
                ORDER BY created_at DESC LIMIT 3
            """, (f"%{product}%",))
            llm_requests = cur.fetchall()

            debug_info["llm_analysis"] = {
                "recent_requests": [
                    {
                        "timestamp": str(req["created_at"]),
                        "model": req["model_name"],
                        "tokens": req["completion_tokens"],
                        "latency_ms": req["latency_ms"],
                        "success": not req["is_error"]
                    }
                    for req in llm_requests
                ]
            }
    except Exception as e:
        debug_info["llm_analysis"]["error"] = str(e)

    # 5. Follow-up items (flagged CVEs)
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT title, severity, status, reason, tags, created_at
                FROM follow_up_items
                WHERE rule_id = 'software_known_cve'
                  AND title LIKE %s
                ORDER BY created_at DESC LIMIT 5
            """, (f"%{product}%",))
            follow_ups = cur.fetchall()

            debug_info["final_decisions"] = {
                "flagged_cves": [
                    {
                        "title": fu["title"],
                        "severity": fu["severity"],
                        "status": fu["status"],
                        "reason": fu["reason"],
                        "flagged_at": str(fu["created_at"])
                    }
                    for fu in follow_ups
                ]
            }
    except Exception as e:
        debug_info["final_decisions"]["error"] = str(e)

    # 6. Recommendations
    recommendations = []
    if not debug_info["release_date_info"].get("manual_override"):
        recommendations.append("Set manual release date for more accurate age analysis")
    if not debug_info["cve_sources"]:
        recommendations.append("Run DDG search to populate CVE analysis cache")
    if debug_info["configuration"].get("using_custom_prompts"):
        recommendations.append("Review custom LLM prompts for optimal version analysis")

    debug_info["recommendations"] = recommendations

    return debug_info


@app.get("/software/release-date", tags=["Assets"])
def get_release_date(product: str, version: str, authorized: bool = Depends(auth)):
    """Get the stored release date for a product+version (manual or auto-detected)."""
    key = f"release_date:{product.lower()}:{version}"
    val = _get_setting(key, "")
    if val:
        parts = val.split("|", 2)
        return {
            "product": product, "version": version, "manual": True,
            "release_year": int(parts[0]) if parts[0].isdigit() else None,
            "release_date": parts[1] if len(parts) > 1 else parts[0],
            "release_url": parts[2] if len(parts) > 2 else "",
        }
    return {"product": product, "version": version, "manual": False,
            "release_year": None, "release_date": None, "release_url": None}


@app.put("/software/release-date", tags=["Assets"])
def set_release_date(body: dict, authorized: bool = Depends(auth)):
    """Set or clear a manual release date for a product+version.
    Body: {product, version, release_date: "August 30, 2023", release_year: 2023, release_url: "..."}
    Set release_date to empty string to clear the override."""
    import re as _rdy
    from datetime import datetime as _dt_validate

    product = body.get("product", "")
    version = body.get("version", "")
    if not product or not version:
        raise HTTPException(400, "product and version required")

    key = f"release_date:{product.lower()}:{version}"
    release_date = body.get("release_date", "").strip()

    if not release_date:
        # Clear override
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM app_settings WHERE key = %s", (key,))
            conn.commit()
        _SETTING_CACHE.pop(key, None)
        logger.info("[manual-release-date] Cleared override for %s %s", product, version)
        return {"ok": True, "action": "cleared", "product": product, "version": version}

    # Extract and validate year
    release_year = body.get("release_year", 0)
    if not release_year:
        ym = _rdy.search(r'(20\d{2})', release_date)
        release_year = int(ym.group(1)) if ym else 0

    # ENHANCED: Validate the release date
    current_year = _dt_validate.now().year
    if release_year > current_year:
        raise HTTPException(400, f"Release year {release_year} cannot be in the future (current: {current_year})")

    if release_year < 2000:
        raise HTTPException(400, f"Release year {release_year} is too old (minimum: 2000)")

    # Try to parse the full date for additional validation
    parsed_date = None
    try:
        for _fmt in ["%B %d, %Y", "%B %d %Y", "%d %B %Y", "%Y-%m-%d", "%m/%d/%Y"]:
            try:
                parsed_date = _dt_validate.strptime(release_date.strip().rstrip(','), _fmt)
                if parsed_date.year != release_year:
                    logger.warning("[manual-release-date] Year mismatch: date=%s parsed_year=%d expected_year=%d",
                                  release_date, parsed_date.year, release_year)
                if parsed_date > _dt_validate.now():
                    raise HTTPException(400, f"Release date {release_date} cannot be in the future")
                break
            except ValueError:
                continue
    except ValueError:
        # Date parsing failed, but we have a valid year, so continue
        logger.debug("[manual-release-date] Could not parse date format: %s", release_date)

    release_url = body.get("release_url", "").strip()

    # Validate URL if provided
    if release_url and not (release_url.startswith('http://') or release_url.startswith('https://')):
        logger.warning("[manual-release-date] URL appears invalid: %s", release_url)

    val = f"{release_year}|{release_date}|{release_url}"

    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO app_settings (key, value, category)
            VALUES (%s, %s, 'config')
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        """, (key, val))
        conn.commit()

    _SETTING_CACHE.pop(key, None)

    logger.info("[manual-release-date] Set override for %s %s: %s (year %d)",
               product, version, release_date, release_year)

    return {
        "ok": True,
        "action": "saved",
        "product": product,
        "version": version,
        "release_date": release_date,
        "release_year": release_year,
        "release_url": release_url,
        "parsed_date": parsed_date.isoformat() if parsed_date else None,
        "note": "Manual override set - will be used for all AI analysis"
    }


@app.get("/software/cve-prompt", tags=["Assets"])
def get_cve_prompt(authorized: bool = Depends(auth)):
    """Get the current CVE analysis prompt templates (system + user)."""
    defaults = {
        "system_prompt": _DEFAULT_CVE_SYSTEM_PROMPT,
        "user_prompt": _DEFAULT_CVE_USER_PROMPT,
    }
    result = dict(defaults)
    with get_db() as conn, conn.cursor() as cur:
        for key in ("system_prompt", "user_prompt"):
            cur.execute("SELECT value FROM app_settings WHERE key = %s AND category = 'config'",
                        (f"cve_analysis.{key}",))
            row = cur.fetchone()
            if row and row[0]:
                result[key] = row[0]
    return {"prompts": result, "defaults": defaults, "note": "Use PUT /software/cve-prompt to customize. Variables: {product}, {version}, {evidence}"}


@app.put("/software/cve-prompt", tags=["Assets"])
def update_cve_prompt(body: dict, authorized: bool = Depends(auth)):
    """Update the CVE analysis prompt templates. Body: {system_prompt: "...", user_prompt: "..."}
    Set a key to empty string to revert to default. Variables available: {product}, {version}, {evidence}"""
    updated = {}
    with get_db() as conn, conn.cursor() as cur:
        for key in ("system_prompt", "user_prompt"):
            if key in body:
                db_key = f"cve_analysis.{key}"
                val = body[key].strip()
                if val:
                    cur.execute("""
                        INSERT INTO app_settings (key, value, category)
                        VALUES (%s, %s, 'config')
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
                    """, (db_key, val))
                    updated[key] = val
                    # Clear cache so next call uses new prompt
                    _SETTING_CACHE.pop(db_key, None)
                else:
                    # Empty = revert to default (delete custom setting)
                    cur.execute("DELETE FROM app_settings WHERE key = %s AND category = 'config'", (db_key,))
                    _SETTING_CACHE.pop(db_key, None)
                    updated[key] = "(reverted to default)"
        conn.commit()
    return {"ok": True, "updated": updated}


@app.get("/software/cve-tuning", tags=["Assets"])
def get_cve_tuning(authorized: bool = Depends(auth)):
    """Get CVE rule tuning parameters."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        from rule_engine import _CVE_TUNING_DEFAULTS
        result = dict(_CVE_TUNING_DEFAULTS)
        try:
            cur.execute("SELECT key, value FROM app_settings WHERE key LIKE 'cve_rule.%%' AND category = 'config'")
            for row in cur.fetchall():
                param = row["key"].replace("cve_rule.", "")
                if param in result:
                    if isinstance(_CVE_TUNING_DEFAULTS.get(param), float):
                        result[param] = float(row["value"])
                    else:
                        result[param] = row["value"]
        except Exception:
            pass
    return {"tuning": result}


@app.put("/software/cve-tuning", tags=["Assets"])
def update_cve_tuning(body: dict, authorized: bool = Depends(auth)):
    """Update CVE rule tuning parameters. Body: {param: value, ...}"""
    from rule_engine import _CVE_TUNING_DEFAULTS, reset_cve_tuning_cache
    allowed = set(_CVE_TUNING_DEFAULTS.keys())
    updated = {}
    with get_db() as conn, conn.cursor() as cur:
        for key, value in body.items():
            if key not in allowed:
                continue
            db_key = f"cve_rule.{key}"
            cur.execute("""
                INSERT INTO app_settings (key, value, category)
                VALUES (%s, %s, 'config')
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
            """, (db_key, str(value)))
            updated[key] = value
        conn.commit()
    reset_cve_tuning_cache()
    return {"ok": True, "updated": updated}


@app.get("/software/vulnx-findings", tags=["Assets"])
def get_vulnx_findings(
    product: str = Query(..., description="Product name to search for"),
    version: str = Query("", description="Version to filter by (optional)"),
    ip: Optional[str] = Query(None, description="IP address to filter by (optional)"),
    authorized: bool = Depends(auth),
):
    """Get VulnX vulnerabilities for a specific product/version combination."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        where_conditions = ["v.script = 'vulnx'"]
        params = []

        # Filter by High+ severity only (CVSS >= 7.0)
        where_conditions.append("v.cvss >= 7.0")

        # Filter by product (case-insensitive partial match)
        where_conditions.append("LOWER(v.metadata->>'product') LIKE LOWER(%s)")
        params.append(f"%{product}%")

        # Filter by version if provided
        if version:
            where_conditions.append("LOWER(v.metadata->>'version') LIKE LOWER(%s)")
            params.append(f"%{version}%")

        # Filter by IP if provided
        if ip:
            where_conditions.append("host(a.ip) = %s")
            params.append(ip)

        where_sql = " AND ".join(where_conditions)

        cur.execute(f"""
            SELECT
                v.id,
                v.title,
                v.severity,
                v.cve,
                v.metadata->>'product' as product,
                v.metadata->>'version' as version,
                v.metadata->>'port' as port,
                v.metadata->>'cvss_score' as cvss_score,
                host(a.ip)::text as ip,
                a.hostname,
                v.created_at,
                v.output
            FROM vulns v
            JOIN assets a ON a.id = v.asset_id
            WHERE {where_sql}
            ORDER BY v.created_at DESC
            LIMIT 100
        """, params)

        findings = cur.fetchall()

        # Extract unique CVEs and their details
        cve_details = {}
        for finding in findings:
            for cve_id in finding['cve'] or []:
                if cve_id not in cve_details:
                    cve_details[cve_id] = {
                        'cve_id': cve_id,
                        'cvss_score': finding['cvss_score'],
                        'severity': finding['severity'],
                        'affected_assets': []
                    }

                asset_info = {
                    'ip': finding['ip'],
                    'hostname': finding['hostname'],
                    'port': finding['port'],
                    'product': finding['product'],
                    'version': finding['version']
                }
                if asset_info not in cve_details[cve_id]['affected_assets']:
                    cve_details[cve_id]['affected_assets'].append(asset_info)

        return {
            "product": product,
            "version": version,
            "total_findings": len(findings),
            "unique_cves": len(cve_details),
            "findings": [dict(f) for f in findings],
            "cve_summary": list(cve_details.values())
        }


@app.post("/software/backfill-refs", tags=["Assets"])
def backfill_followup_refs(authorized: bool = Depends(auth)):
    """Backfill metadata.refs on existing follow_up_items that have CVE IDs in title but no refs."""
    import re as _re
    updated = 0
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, title, reason, metadata
            FROM follow_up_items
            WHERE rule_id = 'software_known_cve'
              AND (metadata IS NULL OR metadata = '{}'::jsonb OR NOT (metadata ? 'refs')
                   OR jsonb_array_length(COALESCE(metadata->'refs', '[]'::jsonb)) = 0)
        """)
        rows = cur.fetchall()
        for row in rows:
            text = f"{row.get('title', '')} {row.get('reason', '')}"
            cve_ids = list(dict.fromkeys(_re.findall(r'CVE-\d{4}-\d{4,}', text)))
            edb_ids = list(dict.fromkeys(_re.findall(r'EDB-\d+', text)))
            if not cve_ids and not edb_ids:
                continue
            refs = []
            for cid in cve_ids[:10]:
                refs.append({"label": cid, "url": f"https://nvd.nist.gov/vuln/detail/{cid}", "type": "cve"})
            for eid in edb_ids[:5]:
                refs.append({"label": eid, "url": f"https://www.exploit-db.com/exploits/{eid[4:]}", "type": "edb"})
            # Extract product/version from title pattern "Vulnerable: {product} {version} on {target}"
            product, version = "", ""
            m = _re.match(r'Vulnerable:\s+(.+?)\s+([\d.]+)\s+on\s+', row.get("title", ""))
            if m:
                product, version = m.group(1), m.group(2)
            meta = dict(row.get("metadata") or {})
            meta["refs"] = refs
            meta["cve_ids"] = cve_ids + edb_ids
            if product:
                meta["product"] = product
                meta["version"] = version
                meta["software_link"] = f"/assets?tab=software&search={product}"
            cur.execute("UPDATE follow_up_items SET metadata = %s WHERE id = %s",
                        (Json(meta), row["id"]))
            updated += 1
        conn.commit()
    return {"ok": True, "backfilled": updated}


@app.post("/software/bulk-dismiss", tags=["Assets"])
def bulk_dismiss_software_cves(body: dict, authorized: bool = Depends(auth)):
    """Bulk dismiss software CVE follow-ups by criteria and record feedback for learning.

    Body: {
        rule_id: "software_known_cve" (default),
        product: optional product substring filter,
        cve_year_before: optional — dismiss CVEs published before this year (e.g. 2022),
        title_contains: optional substring match on title,
        reason: required — why these are false positives,
        engagement_id: optional — scope to engagement,
    }
    """
    reason = body.get("reason")
    if not reason:
        raise HTTPException(400, "reason is required — explain why these are false positives")

    rule_id = body.get("rule_id", "software_known_cve")
    product_filter = body.get("product")
    cve_year_before = body.get("cve_year_before")
    title_contains = body.get("title_contains")
    engagement_id = body.get("engagement_id")

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Find matching follow-ups
        where = ["rule_id = %s", "status != 'dismissed'"]
        params: list = [rule_id]
        if product_filter:
            where.append("LOWER(title) LIKE LOWER(%s)")
            params.append(f"%{product_filter}%")
        if title_contains:
            where.append("LOWER(title) LIKE LOWER(%s)")
            params.append(f"%{title_contains}%")
        if cve_year_before:
            # Match CVE-YYYY where YYYY < threshold
            where.append(f"""
                EXISTS (
                    SELECT 1 FROM regexp_matches(title, 'CVE-(\\d{{4}})', 'g') m
                    WHERE m[1]::int < %s
                )
            """)
            params.append(int(cve_year_before))
        if engagement_id:
            where.append("engagement_id = %s::uuid")
            params.append(engagement_id)

        where_sql = " AND ".join(where)
        cur.execute(f"SELECT id, title, target, severity, reason AS orig_reason, confidence FROM follow_up_items WHERE {where_sql}", params)
        items = cur.fetchall()

        if not items:
            return {"ok": True, "dismissed": 0, "feedback_created": 0, "message": "No matching follow-ups found"}

        ids = [str(r["id"]) for r in items]

        # Dismiss all matching items
        cur.execute(
            "UPDATE follow_up_items SET status = 'dismissed', notes = COALESCE(notes || E'\\n', '') || %s, updated_at = now() WHERE id = ANY(%s::uuid[])",
            (f"[bulk-dismiss] {reason}", ids),
        )
        dismissed = cur.rowcount

        # Create feedback entries for RAG learning
        feedback_created = 0
        try:
            embedding = None
            context_text = f"software_known_cve false_positive {reason}"
            if product_filter:
                context_text += f" product={product_filter}"
            try:
                embedding = _embed_text(context_text)
            except Exception:
                pass

            for item in items:
                import uuid as _uuid
                context = {
                    "title": item["title"], "target": item["target"],
                    "severity": item["severity"], "reason": item["orig_reason"],
                    "rule_id": rule_id, "dismiss_reason": reason,
                }
                if cve_year_before:
                    context["cve_year_before"] = cve_year_before
                cur.execute("""
                    INSERT INTO osint_agent_feedback
                        (id, follow_up_id, finding_context, agent_suggestion, agent_reasoning,
                         agent_confidence, user_action, user_notes, embedding)
                    VALUES (%s, %s, %s, %s, %s, %s, 'dismissed', %s, %s)
                """, (
                    str(_uuid.uuid4()), str(item["id"]), Json(context),
                    "software_known_cve", item["orig_reason"], item["confidence"],
                    reason, embedding,
                ))
                feedback_created += 1
        except Exception as e:
            log.warning("Failed to create some feedback entries: %s", e)

        conn.commit()

    return {
        "ok": True,
        "dismissed": dismissed,
        "feedback_created": feedback_created,
        "message": f"Dismissed {dismissed} follow-ups, created {feedback_created} feedback entries for learning",
    }


@app.get("/recon/domains/{domain}/sitemap", tags=["Recon"])
def domain_sitemap(
    domain: str,
    limit: int = Query(2000, ge=1, le=10000),
    authorized: bool = Depends(auth),
):
    """Return a deduplicated sitemap of URLs discovered for a domain/subdomain."""
    url_like = f"%{domain}%"
    with get_db() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        # Get distinct URLs from web_findings + playwright_findings
        cur.execute("""
            SELECT url, source, status_code, first_seen
            FROM (
                SELECT DISTINCT ON (url) url, source, status_code, first_seen
                FROM web_findings
                WHERE url ILIKE %s
                ORDER BY url, first_seen DESC
            ) wf
            UNION
            SELECT DISTINCT ON (url) url, 'playwright' as source, NULL as status_code, created_at as first_seen
            FROM playwright_findings
            WHERE url ILIKE %s
            ORDER BY url
            LIMIT %s
        """, [url_like, url_like, limit])
        urls_raw = cur.fetchall()

    # Build path tree
    from urllib.parse import urlparse
    sitemap = {}
    for row in urls_raw:
        url = row["url"] or ""
        parsed = urlparse(url)
        path = parsed.path or "/"
        # Skip mangled/escaped URLs
        if "\\/" in path or "%5C" in url:
            continue
        # Normalize
        if not path.startswith("/"):
            path = "/" + path
        sitemap[path] = {
            "url": url,
            "path": path,
            "source": row["source"] or "",
            "status_code": row["status_code"],
            "first_seen": row["first_seen"].isoformat() if row.get("first_seen") else "",
        }

    # Sort by path and return
    sorted_paths = sorted(sitemap.values(), key=lambda x: x["path"])
    return {
        "domain": domain,
        "total_urls": len(sorted_paths),
        "urls": sorted_paths,
    }


# ── Parameter Discovery ───────────────────────────────────────────────────────

@app.get("/params", tags=["Params"])
def search_params(
    url_pattern: Optional[str] = Query(None, description="Filter by URL pattern (ILIKE)"),
    param_name: Optional[str] = Query(None, description="Filter by param name (ILIKE)"),
    param_type: Optional[str] = Query(None, description="Filter by param type"),
    min_occurrences: int = Query(1, ge=1, description="Minimum occurrence count"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    authorized: bool = Depends(auth),
):
    """Search discovered parameters from katana crawls."""
    where_clauses: list[str] = []
    params: list = []

    if url_pattern:
        where_clauses.append("dp.url_pattern ILIKE %s")
        params.append(f"%{url_pattern}%")
    if param_name:
        where_clauses.append("dp.param_name ILIKE %s")
        params.append(f"%{param_name}%")
    if param_type:
        where_clauses.append("dp.param_type = %s")
        params.append(param_type)
    if min_occurrences > 1:
        where_clauses.append("dp.occurrence_count >= %s")
        params.append(min_occurrences)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    data_sql = f"""
        SELECT dp.id::text, dp.asset_id::text, dp.url_pattern, dp.param_name,
               dp.param_type, dp.http_method, dp.param_location,
               dp.sample_values, dp.occurrence_count, dp.discovery_source,
               dp.first_seen, dp.last_seen
        FROM discovered_params dp
        {where_sql}
        ORDER BY dp.occurrence_count DESC, dp.last_seen DESC
        LIMIT %s OFFSET %s
    """
    count_sql = f"SELECT COUNT(*) FROM discovered_params dp {where_sql}"

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(data_sql, params + [limit, offset])
        rows = cur.fetchall()
        cur.execute(count_sql, params)
        total = cur.fetchone()["count"]

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "asset_id": r["asset_id"],
            "url_pattern": r["url_pattern"],
            "param_name": r["param_name"],
            "param_type": r["param_type"] or "string",
            "http_method": r["http_method"] or "GET",
            "param_location": r["param_location"] or "query",
            "sample_values": r["sample_values"] or [],
            "occurrence_count": r["occurrence_count"] or 1,
            "discovery_source": r["discovery_source"] or "katana",
            "first_seen": r["first_seen"].isoformat() if r.get("first_seen") else "",
            "last_seen": r["last_seen"].isoformat() if r.get("last_seen") else "",
        })

    return {"params": results, "total": total}


@app.get("/params/summary", tags=["Params"])
def params_summary(
    min_occurrences: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=1000),
    authorized: bool = Depends(auth),
):
    """Summarize discovered params grouped by name with total occurrences across all URLs."""
    where_sql = ""
    sql_params: list = []
    if min_occurrences > 1:
        where_sql = "HAVING SUM(dp.occurrence_count) >= %s"
        sql_params.append(min_occurrences)

    sql = f"""
        SELECT dp.param_name,
               array_agg(DISTINCT dp.param_type) AS types,
               array_agg(DISTINCT dp.param_location) AS locations,
               SUM(dp.occurrence_count)::int AS total_occurrences,
               COUNT(DISTINCT dp.url_pattern)::int AS url_count
        FROM discovered_params dp
        GROUP BY dp.param_name
        {where_sql}
        ORDER BY total_occurrences DESC
        LIMIT %s
    """

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, sql_params + [limit])
        rows = cur.fetchall()

    return {
        "summary": [
            {
                "param_name": r["param_name"],
                "types": r["types"] or [],
                "locations": r["locations"] or [],
                "total_occurrences": r["total_occurrences"],
                "url_count": r["url_count"],
            }
            for r in rows
        ]
    }


# ── Scope Management ──────────────────────────────────────────────────────────

@app.get("/scope/names", tags=["Scope"])
def list_scope_names(authorized: bool = Depends(auth)):
    """List distinct scope names with target counts."""
    sql = """
        SELECT name,
               COUNT(*) AS target_count,
               MAX(added_at) AS last_updated
        FROM scope_targets
        GROUP BY name
        ORDER BY last_updated DESC
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    return {
        "names": [
            {
                "name": r["name"],
                "target_count": r["target_count"],
                "last_updated": r["last_updated"].isoformat() if r.get("last_updated") else "",
            }
            for r in rows
        ]
    }


@app.get("/scope", tags=["Scope"])
def get_scope(
    name: str = Query("default", description="Scope name"),
    limit: int = Query(500, ge=1, le=5000),
    authorized: bool = Depends(auth),
):
    """List targets for a named scope. Match is case-insensitive so the
    operator (or LLM) can pass "Default" / "default" / "DEFAULT" interchangeably."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT COUNT(*) FROM scope_targets WHERE LOWER(name) = LOWER(%s)",
            [name],
        )
        total = cur.fetchone()["count"]

        cur.execute(
            """SELECT id::text, name, target, target_type, source, added_at
               FROM scope_targets
               WHERE LOWER(name) = LOWER(%s)
               ORDER BY added_at DESC
               LIMIT %s""",
            [name, limit],
        )
        rows = cur.fetchall()

    return {
        "name": name,
        "total": total,
        "targets": [
            {
                "id": r["id"],
                "name": r["name"],
                "target": r["target"],
                "target_type": r["target_type"] or "",
                "source": r["source"] or "",
                "added_at": r["added_at"].isoformat() if r.get("added_at") else "",
            }
            for r in rows
        ],
    }


@app.post("/scope/add", tags=["Scope"])
def add_to_scope(
    body: dict,
    authorized: bool = Depends(auth),
):
    """Add targets to a named scope. Body: {name, targets: [{target, target_type, source}]}"""
    name = body.get("name", "default")
    targets = body.get("targets", [])
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided")

    added = 0
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        for t in targets:
            target_val = t.get("target", "").strip()
            if not target_val:
                continue
            cur.execute(
                """INSERT INTO scope_targets (name, target, target_type, source)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (name, target) DO NOTHING""",
                [name, target_val, t.get("target_type"), t.get("source")],
            )
            added += cur.rowcount
        conn.commit()
    return {"ok": True, "name": name, "added": added}


@app.delete("/scope/targets", tags=["Scope"])
def remove_from_scope(
    body: dict,
    authorized: bool = Depends(auth),
):
    """Remove targets from a scope. Body: {name, targets: [str]}"""
    name = body.get("name", "default")
    targets = body.get("targets", [])
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided")

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "DELETE FROM scope_targets WHERE name = %s AND target = ANY(%s)",
            [name, targets],
        )
        removed = cur.rowcount
        conn.commit()
    return {"ok": True, "name": name, "removed": removed}


@app.post("/scope/auto-assign-unknown", tags=["Scope"])
def auto_assign_unknown_scope(authorized: bool = Depends(auth)):
    """Find all assets/hostnames not in any scope and assign them to 'unknown_scope'.

    This gives visibility into discovered items that haven't been explicitly triaged
    into a named scope. Items remain in unknown_scope until manually moved.
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get all existing scope targets
        cur.execute("SELECT DISTINCT target FROM scope_targets")
        scoped = set(r["target"] for r in cur.fetchall())

        # Find unscoped hostnames from assets
        cur.execute("SELECT DISTINCT hostname FROM assets WHERE hostname IS NOT NULL")
        all_hosts = set(r["hostname"] for r in cur.fetchall())

        # Find unscoped IPs from assets
        cur.execute("SELECT DISTINCT host(ip)::text FROM assets WHERE ip IS NOT NULL")
        all_ips = set(r["host"] for r in cur.fetchall())

        # Find unscoped domains from recon_findings (subfinder targets)
        cur.execute("""
            SELECT DISTINCT target FROM recon_findings
            WHERE source IN ('subfinder', 'dnsx', 'httpx') AND target IS NOT NULL
        """)
        all_recon_targets = set(r["target"] for r in cur.fetchall())

        # Combine all discovered items
        all_discovered = all_hosts | all_ips | all_recon_targets
        unscoped = all_discovered - scoped

        if not unscoped:
            return {"ok": True, "added": 0, "message": "All items already in a scope"}

        # Add to unknown_scope
        added = 0
        for target in unscoped:
            if not target or not target.strip():
                continue
            # Determine type
            target_type = "domain"
            t = target.strip()
            if t.replace(".", "").isdigit() or ":" in t:
                target_type = "ip"
            elif "/" in t and any(c.isdigit() for c in t.split("/")[-1]):
                target_type = "cidr"

            cur.execute("""
                INSERT INTO scope_targets (id, name, target, target_type, source)
                VALUES (gen_random_uuid(), 'unknown_scope', %s, %s, 'auto-discovery')
                ON CONFLICT (name, target) DO NOTHING
            """, [t, target_type])
            added += cur.rowcount
        conn.commit()

    return {"ok": True, "added": added, "total_unscoped": len(unscoped),
            "message": f"Added {added} items to unknown_scope"}


def _gather_target_context(target: str, cur) -> dict:
    """Gather all available recon context for a target (WHOIS, ASN, TLS, HTTP, DNS)."""
    ctx = {"target": target}
    try:
        # WHOIS
        cur.execute("""
            SELECT data FROM recon_findings
            WHERE (target = %s OR target ILIKE %s) AND (finding_type = 'whois_record' OR source = 'whois')
            ORDER BY created_at DESC LIMIT 1
        """, (target, f"%.{target}"))
        row = cur.fetchone()
        if row and row[0]:
            d = row[0] if isinstance(row[0], dict) else {}
            ctx["whois_org"] = d.get("org") or d.get("registrant_org") or ""
            ctx["whois_registrant"] = d.get("registrant_name") or ""
            ctx["whois_country"] = d.get("registrant_country") or ""

        # ASN
        cur.execute("""
            SELECT data FROM recon_findings
            WHERE (target = %s OR target ILIKE %s) AND (finding_type = 'asn_mapping' OR source = 'asnmap')
            ORDER BY created_at DESC LIMIT 1
        """, (target, f"%.{target}"))
        row = cur.fetchone()
        if row and row[0]:
            d = row[0] if isinstance(row[0], dict) else {}
            ctx["asn_number"] = d.get("as_number") or ""
            ctx["asn_name"] = d.get("as_name") or ""

        # TLS
        cur.execute("""
            SELECT data FROM recon_findings
            WHERE (target = %s OR target ILIKE %s) AND (finding_type = 'tls_cert' OR source = 'tlsx')
            ORDER BY created_at DESC LIMIT 1
        """, (target, f"%.{target}"))
        row = cur.fetchone()
        if row and row[0]:
            d = row[0] if isinstance(row[0], dict) else {}
            ctx["tls_issuer"] = d.get("issuer_org") or d.get("issuer") or ""
            ctx["tls_subject"] = d.get("subject_cn") or ""

        # HTTP
        cur.execute("""
            SELECT data FROM recon_findings
            WHERE (target = %s OR target ILIKE %s) AND (finding_type = 'web_service' OR source = 'httpx')
            ORDER BY created_at DESC LIMIT 1
        """, (target, f"%.{target}"))
        row = cur.fetchone()
        if row and row[0]:
            d = row[0] if isinstance(row[0], dict) else {}
            ctx["http_title"] = d.get("title") or ""
            ctx["http_server"] = d.get("webserver") or d.get("server") or ""
            ctx["http_tech"] = d.get("tech") or []
            ctx["http_status"] = d.get("status_code") or ""

        # DNS
        cur.execute("""
            SELECT finding_type, data FROM recon_findings
            WHERE (target = %s OR target ILIKE %s) AND finding_type LIKE 'dns_%%'
            ORDER BY created_at DESC LIMIT 5
        """, (target, f"%.{target}"))
        dns = {}
        for row in cur.fetchall():
            dns[row[0]] = row[1] if isinstance(row[1], dict) else {}
        if dns:
            ctx["dns"] = dns

    except Exception as e:
        ctx["_gather_error"] = str(e)
    return ctx


def _build_context_text(ctx: dict) -> str:
    """Flatten context dict into a text string for embedding."""
    parts = [f"target={ctx.get('target', '')}"]
    for key in ("whois_org", "whois_registrant", "whois_country",
                "asn_number", "asn_name", "tls_issuer", "tls_subject",
                "http_title", "http_server", "http_status"):
        val = ctx.get(key)
        if val:
            parts.append(f"{key}={val}")
    tech = ctx.get("http_tech")
    if tech and isinstance(tech, list):
        parts.append(f"tech={','.join(str(t) for t in tech[:10])}")
    return " ".join(parts)


def _capture_scope_decisions(targets: list, from_scope: str, to_scope: str, cur):
    """Record scope decisions with recon context and embeddings for future classification."""
    import requests as _req
    embedder_url = os.environ.get("EMBEDDER_URL", "https://embedder:8030")

    for t in targets:
        t = t.strip()
        if not t:
            continue
        ctx = _gather_target_context(t, cur)
        ctx_text = _build_context_text(ctx)

        # Embed context (optional — graceful failure)
        embedding = None
        try:
            resp = _req.post(f"{embedder_url}/embed", json={"text": ctx_text}, timeout=5)
            if resp.status_code == 200:
                embedding = resp.json().get("embedding")
        except Exception:
            pass

        target_type = "ip" if t.replace(".", "").isdigit() or ":" in t else "domain"
        cur.execute("""
            INSERT INTO scope_decisions (id, target, target_type, from_scope, to_scope, context, context_text, embedding)
            VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s)
        """, (t, target_type, from_scope, to_scope,
              json.dumps(ctx), ctx_text,
              embedding if embedding else None))


@app.post("/scope/move", tags=["Scope"])
def move_scope_targets(body: dict, authorized: bool = Depends(auth)):
    """Move targets from one scope to another. Body: {from_scope, to_scope, targets: [str]}
    Matches exact targets AND targets that are in the source scope that the given items are subdomains of.
    E.g. moving ['testdw.convio.com'] from unknown_scope will also move 'convio.com' if it's in unknown_scope.
    """
    from_scope = body.get("from_scope")
    to_scope = body.get("to_scope")
    targets = body.get("targets", [])
    if not from_scope or not to_scope or not targets:
        raise HTTPException(400, "Provide from_scope, to_scope, and targets")
    removed = 0
    added = 0
    with get_db() as conn, conn.cursor() as cur:
        # Build the full set of scope targets to move:
        # 1. Exact matches from the targets list
        # 2. Targets in the source scope that the given items are subdomains of
        to_move = set(t.strip() for t in targets if t.strip())

        # Get all targets currently in the source scope
        cur.execute("SELECT target FROM scope_targets WHERE name = %s", [from_scope])
        source_targets = [r[0] for r in cur.fetchall()]

        # For each selected item, find any source scope targets it's a subdomain of
        for item in list(to_move):
            for st in source_targets:
                # If source scope has 'convio.com' and we're moving 'testdw.convio.com'
                # then also move 'convio.com'
                if item.endswith('.' + st) or item == st:
                    to_move.add(st)

        # Remove all matched targets from source scope
        move_list = list(to_move)
        cur.execute("DELETE FROM scope_targets WHERE name = %s AND target = ANY(%s)", [from_scope, move_list])
        removed = cur.rowcount
        # Add to destination scope
        for t in move_list:
            t = t.strip()
            if not t:
                continue
            target_type = "domain"
            if t.replace(".", "").isdigit() or ":" in t:
                target_type = "ip"
            cur.execute("""
                INSERT INTO scope_targets (id, name, target, target_type, source)
                VALUES (gen_random_uuid(), %s, %s, %s, 'moved')
                ON CONFLICT (name, target) DO NOTHING
            """, [to_scope, t, target_type])
            added += cur.rowcount

        # Capture decisions for auto-classification learning
        try:
            _capture_scope_decisions(targets, from_scope, to_scope, cur)
        except Exception as e:
            logging.warning(f"scope decision capture failed: {e}")

        conn.commit()
    return {"ok": True, "from_scope": from_scope, "to_scope": to_scope,
            "removed": removed, "added": added, "decisions_captured": len(targets)}


@app.post("/scope/cleanup-unknown", tags=["Scope"])
def cleanup_unknown_scope(authorized: bool = Depends(auth)):
    """Remove targets from unknown_scope if the exact same target already exists in any other named scope.
    Only removes exact matches — blog.example.com in a named scope does NOT remove example.com from unknown_scope.
    """
    with get_db() as conn, conn.cursor() as cur:
        # Remove exact duplicates only: targets in unknown_scope that also exist in another scope
        cur.execute("""
            DELETE FROM scope_targets
            WHERE name = 'unknown_scope'
            AND target IN (
                SELECT target FROM scope_targets WHERE name != 'unknown_scope'
            )
        """)
        removed = cur.rowcount
        conn.commit()

    return {
        "ok": True,
        "exact_duplicates_removed": removed,
        "total_removed": removed,
    }


# ── Scope Auto-Classification ─────────────────────────────────────────────

@app.get("/scope/classify/{target}", tags=["Scope Classification"])
def classify_single_target(target: str, authorized: bool = Depends(auth)):
    """Classify a single target — returns suggested scope with confidence and reasoning."""
    from scope_classifier import get_classifier
    classifier = get_classifier()
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        classifier.load_rules(cur)
        ctx = _gather_target_context(target, cur)
        result = classifier.classify_target(target, ctx, cur)
    if not result:
        return {"target": target, "suggestion": None, "context": ctx}
    return {
        "target": target,
        "suggestion": {
            "scope": result.scope, "confidence": result.confidence,
            "reasoning": result.reasoning, "method": result.method,
        },
        "context": ctx,
    }


@app.post("/scope/classify-unknown", tags=["Scope Classification"])
def classify_unknown_scope(
    body: dict = None,
    authorized: bool = Depends(auth),
):
    """Run classifier on all unknown_scope items. Creates suggestions for user review.
    Body (optional): {auto_apply_threshold: 0.95, limit: 500}
    """
    body = body or {}
    auto_threshold = float(body.get("auto_apply_threshold", 0.95))
    limit = int(body.get("limit", 500))

    from scope_classifier import get_classifier
    classifier = get_classifier()

    auto_assigned = 0
    suggested = 0
    unclassified = 0

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        classifier.load_rules(cur)

        # Get unknown_scope targets
        cur.execute("SELECT target FROM scope_targets WHERE name = 'unknown_scope' LIMIT %s", (limit,))
        targets = [r["target"] for r in cur.fetchall()]

        for target in targets:
            ctx = _gather_target_context(target, cur)
            result = classifier.classify_target(target, ctx, cur)

            if not result or result.confidence < 0.5:
                unclassified += 1
                continue

            # Auto-apply if high confidence and rule allows it
            if result.method == "rule" and result.confidence >= auto_threshold:
                # Check if rule has auto_apply
                if result.rule_id:
                    cur.execute("SELECT auto_apply FROM scope_classification_rules WHERE id = %s", (result.rule_id,))
                    row = cur.fetchone()
                    if row and row["auto_apply"]:
                        # Auto-move
                        cur.execute("DELETE FROM scope_targets WHERE name = 'unknown_scope' AND target = %s", (target,))
                        cur.execute("""
                            INSERT INTO scope_targets (id, name, target, target_type, source)
                            VALUES (gen_random_uuid(), %s, %s, 'domain', 'auto-classified')
                            ON CONFLICT (name, target) DO NOTHING
                        """, (result.scope, target))
                        _capture_scope_decisions([target], "unknown_scope", result.scope, cur)
                        auto_assigned += 1
                        continue

            # Create suggestion for user review
            cur.execute("""
                INSERT INTO scope_suggestions (id, target, suggested_scope, confidence, reasoning, method, rule_id, similar_decisions, status)
                VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s, 'pending')
                ON CONFLICT (target) DO UPDATE SET
                    suggested_scope = EXCLUDED.suggested_scope,
                    confidence = EXCLUDED.confidence,
                    reasoning = EXCLUDED.reasoning,
                    method = EXCLUDED.method,
                    status = 'pending',
                    created_at = now()
            """, (target, result.scope, result.confidence, result.reasoning, result.method,
                  result.rule_id,
                  result.similar_decision_ids if result.similar_decision_ids else None))
            suggested += 1

        conn.commit()

    return {
        "ok": True, "total_processed": len(targets),
        "auto_assigned": auto_assigned, "suggested": suggested,
        "unclassified": unclassified,
    }


@app.get("/scope/suggestions", tags=["Scope Classification"])
def list_suggestions(
    status: str = Query("pending"),
    limit: int = Query(100, ge=1, le=1000),
    authorized: bool = Depends(auth),
):
    """List scope classification suggestions."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if status == "all":
            cur.execute("SELECT * FROM scope_suggestions ORDER BY confidence DESC LIMIT %s", (limit,))
        else:
            cur.execute("SELECT * FROM scope_suggestions WHERE status = %s ORDER BY confidence DESC LIMIT %s", (status, limit))
        rows = cur.fetchall()
    return {"suggestions": [{k: str(v) if k == "id" else v for k, v in r.items()} for r in rows], "total": len(rows)}


@app.post("/scope/suggestions/{suggestion_id}/accept", tags=["Scope Classification"])
def accept_suggestion(suggestion_id: str, authorized: bool = Depends(auth)):
    """Accept a suggestion: move target to suggested scope and record decision."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM scope_suggestions WHERE id = %s", (suggestion_id,))
        sug = cur.fetchone()
        if not sug:
            raise HTTPException(404, "Suggestion not found")
        if sug["status"] != "pending":
            raise HTTPException(400, f"Suggestion already {sug['status']}")

        target = sug["target"]
        scope = sug["suggested_scope"]

        # Move target
        cur.execute("DELETE FROM scope_targets WHERE name = 'unknown_scope' AND target = %s", (target,))
        cur.execute("""
            INSERT INTO scope_targets (id, name, target, target_type, source)
            VALUES (gen_random_uuid(), %s, %s, 'domain', 'auto-classified')
            ON CONFLICT (name, target) DO NOTHING
        """, (scope, target))

        # Record decision
        _capture_scope_decisions([target], "unknown_scope", scope, cur)

        # Mark suggestion accepted
        cur.execute("UPDATE scope_suggestions SET status = 'accepted', reviewed_at = now() WHERE id = %s", (suggestion_id,))
        conn.commit()

    return {"ok": True, "target": target, "scope": scope}


@app.post("/scope/suggestions/{suggestion_id}/reject", tags=["Scope Classification"])
def reject_suggestion(suggestion_id: str, body: dict = None, authorized: bool = Depends(auth)):
    """Reject a suggestion. Optionally provide {correct_scope} to record the right answer."""
    body = body or {}
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM scope_suggestions WHERE id = %s", (suggestion_id,))
        sug = cur.fetchone()
        if not sug:
            raise HTTPException(404, "Suggestion not found")

        cur.execute("UPDATE scope_suggestions SET status = 'rejected', reviewed_at = now() WHERE id = %s", (suggestion_id,))

        # If user provided correct scope, record decision for learning
        correct_scope = body.get("correct_scope")
        if correct_scope:
            _capture_scope_decisions([sug["target"]], "unknown_scope", correct_scope, cur)

        conn.commit()
    return {"ok": True, "target": sug["target"]}


@app.post("/scope/suggestions/bulk-accept", tags=["Scope Classification"])
def bulk_accept_suggestions(body: dict, authorized: bool = Depends(auth)):
    """Accept all pending suggestions above a confidence threshold.
    Body: {min_confidence: 0.85}
    """
    min_conf = float(body.get("min_confidence", 0.85))
    accepted = 0
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM scope_suggestions WHERE status = 'pending' AND confidence >= %s", (min_conf,))
        for sug in cur.fetchall():
            target = sug["target"]
            scope = sug["suggested_scope"]
            cur.execute("DELETE FROM scope_targets WHERE name = 'unknown_scope' AND target = %s", (target,))
            cur.execute("""
                INSERT INTO scope_targets (id, name, target, target_type, source)
                VALUES (gen_random_uuid(), %s, %s, 'domain', 'auto-classified')
                ON CONFLICT (name, target) DO NOTHING
            """, (scope, target))
            _capture_scope_decisions([target], "unknown_scope", scope, cur)
            cur.execute("UPDATE scope_suggestions SET status = 'accepted', reviewed_at = now() WHERE id = %s", (sug["id"],))
            accepted += 1
        conn.commit()
    return {"ok": True, "accepted": accepted, "min_confidence": min_conf}


@app.get("/scope/classification-rules", tags=["Scope Classification"])
def list_classification_rules(authorized: bool = Depends(auth)):
    """List all classification rules (YAML + DB)."""
    from scope_classifier import get_classifier
    classifier = get_classifier()
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        classifier.load_rules(cur)
    return {"rules": classifier.get_rules(), "total": len(classifier.get_rules())}


@app.post("/scope/classification-rules", tags=["Scope Classification"])
def create_classification_rule(body: dict, authorized: bool = Depends(auth)):
    """Create a new DB-based classification rule."""
    required = ("name", "scope_name", "rule_type", "conditions")
    for f in required:
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO scope_classification_rules (id, name, scope_name, priority, rule_type, conditions, auto_apply)
            VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (body["name"], body["scope_name"], body.get("priority", 100),
              body["rule_type"], json.dumps(body["conditions"]), body.get("auto_apply", False)))
        rule_id = str(cur.fetchone()["id"])
        conn.commit()
    return {"ok": True, "id": rule_id}


@app.delete("/scope/classification-rules/{rule_id}", tags=["Scope Classification"])
def delete_classification_rule(rule_id: str, authorized: bool = Depends(auth)):
    """Delete a DB classification rule."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM scope_classification_rules WHERE id = %s", (rule_id,))
        conn.commit()
    return {"ok": True}


@app.post("/scope/rules/learn", tags=["Scope Classification"])
def learn_rules_from_decisions(authorized: bool = Depends(auth)):
    """Analyze past scope decisions and suggest new classification rules."""
    suggested_rules = []
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Group decisions by to_scope
        cur.execute("""
            SELECT to_scope, COUNT(*) as cnt
            FROM scope_decisions
            GROUP BY to_scope
            HAVING COUNT(*) >= 3
            ORDER BY cnt DESC
        """)
        scopes = cur.fetchall()

        for scope_row in scopes:
            scope_name = scope_row["to_scope"]
            cur.execute("""
                SELECT target, context FROM scope_decisions WHERE to_scope = %s
            """, (scope_name,))
            decisions = cur.fetchall()

            if len(decisions) < 3:
                continue

            # Analyze domain patterns
            targets = [d["target"] for d in decisions]
            # Find common domain suffix
            suffixes = {}
            for t in targets:
                parts = t.split(".")
                if len(parts) >= 2:
                    suffix = ".".join(parts[-2:])
                    suffixes[suffix] = suffixes.get(suffix, 0) + 1
            for suffix, count in suffixes.items():
                if count >= len(decisions) * 0.6:  # 60% threshold
                    suggested_rules.append({
                        "rule_type": "domain_pattern",
                        "scope_name": scope_name,
                        "name": f"Domain pattern: *.{suffix} → {scope_name}",
                        "conditions": {"pattern": f"*.{suffix}"},
                        "evidence_count": count,
                        "total_decisions": len(decisions),
                        "confidence": round(count / len(decisions), 2),
                    })

            # Analyze WHOIS org patterns
            orgs = {}
            for d in decisions:
                ctx = d["context"] if isinstance(d["context"], dict) else {}
                org = ctx.get("whois_org", "")
                if org:
                    orgs[org] = orgs.get(org, 0) + 1
            for org, count in orgs.items():
                if count >= len(decisions) * 0.5:
                    suggested_rules.append({
                        "rule_type": "whois_org",
                        "scope_name": scope_name,
                        "name": f"WHOIS org: {org} → {scope_name}",
                        "conditions": {"field": "whois_org", "op": "contains", "value": org},
                        "evidence_count": count,
                        "total_decisions": len(decisions),
                        "confidence": round(count / len(decisions), 2),
                    })

            # Analyze ASN patterns
            asns = {}
            for d in decisions:
                ctx = d["context"] if isinstance(d["context"], dict) else {}
                asn = ctx.get("asn_name", "")
                if asn:
                    asns[asn] = asns.get(asn, 0) + 1
            for asn, count in asns.items():
                if count >= len(decisions) * 0.5:
                    suggested_rules.append({
                        "rule_type": "asn",
                        "scope_name": scope_name,
                        "name": f"ASN: {asn} → {scope_name}",
                        "conditions": {"field": "asn_name", "op": "contains", "value": asn},
                        "evidence_count": count,
                        "total_decisions": len(decisions),
                        "confidence": round(count / len(decisions), 2),
                    })

    return {"suggested_rules": suggested_rules, "total": len(suggested_rules)}


@app.get("/scope/decisions", tags=["Scope Classification"])
def list_scope_decisions(
    limit: int = Query(50, ge=1, le=500),
    authorized: bool = Depends(auth),
):
    """List recent scope decisions (training data)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT id, target, from_scope, to_scope, context, decided_at, decided_by FROM scope_decisions ORDER BY decided_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
    return {"decisions": [{k: str(v) if k == "id" else v for k, v in r.items()} for r in rows], "total": len(rows)}


@app.post("/scope/exclude", tags=["Scope"])
def exclude_from_scope(
    body: dict,
    authorized: bool = Depends(auth),
):
    """Mark domains/targets as out of scope. Adds to 'not_in_scope' list.

    Body: {targets: ["domain1.com", "domain2.com"], source?: "manual"}
    """
    targets = body.get("targets", [])
    source = body.get("source", "manual")
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided")

    added = 0
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        for t in targets:
            target_val = t.strip() if isinstance(t, str) else ""
            if not target_val:
                continue
            cur.execute(
                """INSERT INTO scope_targets (name, target, target_type, source)
                   VALUES ('not_in_scope', %s, 'domain', %s)
                   ON CONFLICT (name, target) DO NOTHING""",
                [target_val, source],
            )
            added += cur.rowcount
        conn.commit()
    return {"ok": True, "added": added, "scope": "not_in_scope"}


@app.delete("/scope/exclude", tags=["Scope"])
def remove_exclusion(
    body: dict,
    authorized: bool = Depends(auth),
):
    """Remove domains from the not_in_scope list (restore to scope).

    Body: {targets: ["domain1.com"]}
    """
    targets = body.get("targets", [])
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided")

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "DELETE FROM scope_targets WHERE name = 'not_in_scope' AND target = ANY(%s)",
            [targets],
        )
        removed = cur.rowcount
        conn.commit()
    return {"ok": True, "removed": removed}


@app.get("/scope/excluded", tags=["Scope"])
def list_excluded(authorized: bool = Depends(auth)):
    """List all domains/targets marked as not_in_scope."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT target, source, added_at FROM scope_targets WHERE name = 'not_in_scope' ORDER BY added_at DESC"
        )
        rows = [dict(r) for r in cur.fetchall()]
    return {"targets": rows, "total": len(rows)}


# ── Wordlist Management ──────────────────────────────────────────────────────

WORDLISTS_DIR = "/wordlists"
WORDLIST_EXTENSIONS = {".txt", ".lst", ".dict", ".wordlist"}

def _count_lines(path: str) -> int:
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def _auto_register_host_files(conn):
    """Scan /wordlists/ directory and register any unregistered files."""
    if not os.path.isdir(WORDLISTS_DIR):
        return
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT path FROM wordlists")
    known_paths = {row["path"] for row in cur.fetchall()}
    for fname in os.listdir(WORDLISTS_DIR):
        fpath = os.path.join(WORDLISTS_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        ext = os.path.splitext(fname)[1].lower()
        if ext not in WORDLIST_EXTENSIONS:
            continue
        if fpath in known_paths:
            continue
        size = os.path.getsize(fpath)
        lines = _count_lines(fpath)
        cur.execute(
            """INSERT INTO wordlists (name, path, source, list_type, line_count, size_bytes)
               VALUES (%s, %s, 'host', 'passwords', %s, %s)
               ON CONFLICT (name) DO NOTHING""",
            [fname, fpath, lines, size],
        )
    conn.commit()

@app.get("/wordlists", tags=["Wordlists"])
def list_wordlists(authorized: bool = Depends(auth)):
    """List all registered wordlists, auto-registering host files."""
    with get_db() as conn:
        _auto_register_host_files(conn)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM wordlists ORDER BY created_at DESC")
        rows = cur.fetchall()
    for r in rows:
        r["id"] = str(r["id"])
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
    return {"ok": True, "wordlists": rows}

@app.post("/wordlists/upload", tags=["Wordlists"])
def upload_wordlist(
    file: UploadFile = File(...),
    list_type: str = "passwords",
    description: str = None,
    authorized: bool = Depends(auth),
):
    """Upload a wordlist file, save to /wordlists/, register in DB."""
    os.makedirs(WORDLISTS_DIR, exist_ok=True)
    fname = file.filename or "uploaded_wordlist.txt"
    dest = os.path.join(WORDLISTS_DIR, fname)
    with open(dest, "wb") as f:
        data = file.file.read()
        f.write(data)
    size = len(data)
    lines = _count_lines(dest)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO wordlists (name, path, source, list_type, line_count, size_bytes, description)
               VALUES (%s, %s, 'upload', %s, %s, %s, %s)
               ON CONFLICT (name) DO UPDATE SET
                 path = EXCLUDED.path, line_count = EXCLUDED.line_count,
                 size_bytes = EXCLUDED.size_bytes, description = EXCLUDED.description
               RETURNING id""",
            [fname, dest, list_type, lines, size, description],
        )
        row = cur.fetchone()
        conn.commit()
    return {"ok": True, "id": str(row["id"]), "name": fname, "line_count": lines, "size_bytes": size}

@app.get("/wordlists/{wordlist_id}", tags=["Wordlists"])
def get_wordlist(wordlist_id: str, authorized: bool = Depends(auth)):
    """Get single wordlist metadata."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM wordlists WHERE id = %s", [wordlist_id])
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Wordlist not found")
    row["id"] = str(row["id"])
    row["created_at"] = row["created_at"].isoformat() if row.get("created_at") else None
    return {"ok": True, "wordlist": row}

@app.delete("/wordlists/{wordlist_id}", tags=["Wordlists"])
def delete_wordlist(wordlist_id: str, authorized: bool = Depends(auth)):
    """Remove wordlist record (and file if source='upload')."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM wordlists WHERE id = %s", [wordlist_id])
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Wordlist not found")
        if row["source"] == "upload" and os.path.exists(row["path"]):
            os.remove(row["path"])
        cur.execute("DELETE FROM wordlists WHERE id = %s", [wordlist_id])
        conn.commit()
    return {"ok": True, "deleted": str(row["id"])}


## --- Content Extractions + Wordlist Generation endpoints ---

@app.get("/content-extractions", tags=["Content Intel"])
def list_content_extractions(
    asset_id: str = None,
    scan_id: str = None,
    search: str = None,
    limit: int = 100,
    authorized: bool = Depends(auth),
):
    """List content extractions with optional filters. search matches IP or hostname."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        conditions = []
        params = []
        if asset_id:
            conditions.append("ce.asset_id = %s")
            params.append(asset_id)
        if scan_id:
            conditions.append("ce.scan_id = %s")
            params.append(scan_id)
        if search:
            conditions.append(
                "(ce.asset_id IN (SELECT id FROM assets WHERE hostname ILIKE %s OR host(ip)::text ILIKE %s)"
                " OR ce.url ILIKE %s)"
            )
            like = f"%{search}%"
            params.extend([like, like, like])
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur.execute(
            f"SELECT ce.* FROM content_extractions ce {where} ORDER BY ce.created_at DESC LIMIT %s",
            params,
        )
        rows = cur.fetchall()
    for r in rows:
        r["id"] = str(r["id"])
        if r.get("scan_id"):
            r["scan_id"] = str(r["scan_id"])
        if r.get("asset_id"):
            r["asset_id"] = str(r["asset_id"])
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
        # Truncate word_corpus in list view
        if r.get("word_corpus") and len(r["word_corpus"]) > 500:
            r["word_corpus"] = r["word_corpus"][:500] + "..."
    return {"ok": True, "extractions": rows, "count": len(rows)}


@app.get("/content-extractions/summary", tags=["Content Intel"])
def content_extraction_summary(
    asset_id: str = None,
    search: str = None,
    authorized: bool = Depends(auth),
):
    """Aggregated counts of extracted content intelligence."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        conditions = []
        params = []
        if asset_id:
            conditions.append("asset_id = %s")
            params.append(asset_id)
        if search:
            like = f"%{search}%"
            conditions.append(
                "(asset_id IN (SELECT id FROM assets WHERE hostname ILIKE %s OR host(ip)::text ILIKE %s)"
                " OR url ILIKE %s)"
            )
            params.extend([like, like, like])
        condition = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        cur.execute(
            f"""SELECT
                count(*) as total_extractions,
                coalesce(sum(jsonb_array_length(emails)), 0) as total_emails,
                coalesce(sum(jsonb_array_length(names)), 0) as total_names,
                coalesce(sum(jsonb_array_length(internal_paths)), 0) as total_paths,
                coalesce(sum(jsonb_array_length(api_endpoints)), 0) as total_api_endpoints,
                coalesce(sum(jsonb_array_length(exposed_keys)), 0) as total_exposed_keys,
                coalesce(sum(jsonb_array_length(tech_indicators)), 0) as total_tech_indicators,
                coalesce(sum(jsonb_array_length(comments)), 0) as total_comments,
                coalesce(sum(jsonb_array_length(hidden_inputs)), 0) as total_hidden_inputs,
                coalesce(sum(jsonb_array_length(interesting_files)), 0) as total_interesting_files,
                coalesce(sum(jsonb_array_length(file_metadata)), 0) as total_file_metadata,
                coalesce(sum(jsonb_array_length(login_pages)), 0) as total_login_pages
            FROM content_extractions {condition}""",
            params,
        )
        row = cur.fetchone()
    return {"ok": True, "summary": {k: int(v) for k, v in row.items()}}


## --- Sitemap / URL inventory ---

@app.get("/content-intel/sitemap", tags=["Content Intel"])
def content_intel_sitemap(
    domain: str = None,
    asset_id: str = None,
    search: str = None,
    authorized: bool = Depends(auth),
):
    """Unified sitemap: all discovered URLs for a domain from every source.

    Merges URLs from web_findings, content_extractions (internal_paths, api_endpoints),
    discovered_params, playwright_scans, and dom_analysis into a deduplicated list
    with source attribution, method, status code, and finding counts.
    """
    # Resolve search to domain if provided
    if search and not domain:
        domain = search
    if not domain and not asset_id:
        raise HTTPException(400, "Provide 'domain', 'search', or 'asset_id' parameter")

    like = f"%{domain}%" if domain else None

    urls: dict = {}  # path -> {methods, sources, status_codes, findings, params}

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # 1. web_findings
        if like:
            cur.execute("""
                SELECT url, source, method, status_code, severity, name
                FROM web_findings WHERE url ILIKE %s
                ORDER BY url""", [like])
        else:
            cur.execute("""
                SELECT wf.url, wf.source, wf.method, wf.status_code, wf.severity, wf.name
                FROM web_findings wf
                WHERE wf.asset_id = %s ORDER BY wf.url""", [asset_id])
        for r in cur.fetchall():
            u = r["url"] or ""
            if u not in urls:
                urls[u] = {"url": u, "methods": set(), "sources": set(),
                           "status_codes": set(), "findings": 0, "params": [],
                           "severities": set()}
            if r["method"]:
                urls[u]["methods"].add(r["method"])
            urls[u]["sources"].add(r["source"] or "unknown")
            if r["status_code"]:
                urls[u]["status_codes"].add(r["status_code"])
            urls[u]["findings"] += 1
            if r["severity"]:
                urls[u]["severities"].add(r["severity"])

        # 2. content_extractions — internal_paths and api_endpoints
        if like:
            cur.execute("""
                SELECT url, internal_paths, api_endpoints
                FROM content_extractions WHERE url ILIKE %s""", [like])
        else:
            cur.execute("""
                SELECT url, internal_paths, api_endpoints
                FROM content_extractions WHERE asset_id = %s""", [asset_id])
        for r in cur.fetchall():
            base = r["url"] or ""
            from urllib.parse import urlparse as _up
            parsed = _up(base)
            base_prefix = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else ""
            for path in (r.get("internal_paths") or []):
                full = f"{base_prefix}{path}" if path.startswith("/") else path
                if full not in urls:
                    urls[full] = {"url": full, "methods": set(), "sources": set(),
                                  "status_codes": set(), "findings": 0, "params": [],
                                  "severities": set()}
                urls[full]["sources"].add("content-extraction")
            for ep in (r.get("api_endpoints") or []):
                full = f"{base_prefix}{ep}" if ep.startswith("/") else ep
                if full not in urls:
                    urls[full] = {"url": full, "methods": set(), "sources": set(),
                                  "status_codes": set(), "findings": 0, "params": [],
                                  "severities": set()}
                urls[full]["sources"].add("content-extraction")

        # 3. discovered_params
        if like:
            cur.execute("""
                SELECT url_pattern, param_name, http_method, param_location, param_type
                FROM discovered_params WHERE url_pattern ILIKE %s""", [like])
        else:
            cur.execute("""
                SELECT url_pattern, param_name, http_method, param_location, param_type
                FROM discovered_params WHERE asset_id = %s""", [asset_id])
        for r in cur.fetchall():
            u = r["url_pattern"]
            if u not in urls:
                urls[u] = {"url": u, "methods": set(), "sources": set(),
                           "status_codes": set(), "findings": 0, "params": [],
                           "severities": set()}
            urls[u]["methods"].add(r["http_method"])
            urls[u]["sources"].add("param-discovery")
            urls[u]["params"].append({
                "name": r["param_name"],
                "type": r["param_type"],
                "location": r["param_location"],
            })

        # 4. playwright_scans
        if like:
            cur.execute("SELECT DISTINCT url FROM playwright_scans WHERE url ILIKE %s", [like])
        else:
            cur.execute("SELECT DISTINCT url FROM playwright_scans WHERE asset_id = %s", [asset_id])
        for r in cur.fetchall():
            u = r["url"]
            if u not in urls:
                urls[u] = {"url": u, "methods": {"GET"}, "sources": set(),
                           "status_codes": set(), "findings": 0, "params": [],
                           "severities": set()}
            urls[u]["sources"].add("playwright")

    # Serialize sets to lists
    result = []
    for u, data in sorted(urls.items()):
        result.append({
            "url": data["url"],
            "methods": sorted(data["methods"]),
            "sources": sorted(data["sources"]),
            "status_codes": sorted(data["status_codes"]),
            "findings": data["findings"],
            "params": data["params"],
            "severities": sorted(data["severities"]),
        })

    return {"ok": True, "urls": result, "total": len(result), "domain": domain}


@app.get("/content-intel/sitemap/export/burp", tags=["Content Intel"])
def export_sitemap_burp_xml(
    domain: str = None,
    asset_id: str = None,
    authorized: bool = Depends(auth),
):
    """Export sitemap as Burp Suite-compatible XML for import."""
    data = content_intel_sitemap(domain=domain, asset_id=asset_id, authorized=True)
    urls_list = data.get("urls", [])

    from xml.sax.saxutils import escape as xml_escape
    import base64

    lines = ['<?xml version="1.0"?>', '<items burpVersion="2024.0" exportTime="">']
    for entry in urls_list:
        url = entry["url"]
        method = entry["methods"][0] if entry["methods"] else "GET"
        from urllib.parse import urlparse as _up2
        p = _up2(url)
        host = p.hostname or p.netloc or domain or ""
        port = p.port or (443 if p.scheme == "https" else 80)
        protocol = p.scheme or "https"
        path = p.path or "/"
        if p.query:
            path += f"?{p.query}"

        req_str = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        req_b64 = base64.b64encode(req_str.encode()).decode()

        comment_parts = []
        if entry["sources"]:
            comment_parts.append(f"Sources: {', '.join(entry['sources'])}")
        if entry["findings"]:
            comment_parts.append(f"Findings: {entry['findings']}")
        if entry["params"]:
            param_names = [pr["name"] for pr in entry["params"]]
            comment_parts.append(f"Params: {', '.join(param_names)}")
        comment = " | ".join(comment_parts)

        lines.append("  <item>")
        lines.append(f"    <url>{xml_escape(url)}</url>")
        lines.append(f"    <host ip=\"\">{xml_escape(host)}</host>")
        lines.append(f"    <port>{port}</port>")
        lines.append(f"    <protocol>{protocol}</protocol>")
        lines.append(f"    <method>{xml_escape(method)}</method>")
        lines.append(f"    <path>{xml_escape(path)}</path>")
        lines.append(f"    <request base64=\"true\">{req_b64}</request>")
        lines.append(f"    <status>200</status>")
        lines.append(f"    <responselength>0</responselength>")
        lines.append(f"    <mimetype>text/html</mimetype>")
        lines.append(f"    <comment>{xml_escape(comment)}</comment>")
        lines.append("  </item>")
    lines.append("</items>")

    xml_content = "\n".join(lines)
    fname = f"sitemap_{domain or 'export'}.xml"
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/content-intel/sitemap/export/urls", tags=["Content Intel"])
def export_sitemap_urls_txt(
    domain: str = None,
    asset_id: str = None,
    authorized: bool = Depends(auth),
):
    """Export sitemap as plain text URL list (one per line) for ZAP/tools import."""
    data = content_intel_sitemap(domain=domain, asset_id=asset_id, authorized=True)
    urls_list = data.get("urls", [])
    text = "\n".join(entry["url"] for entry in urls_list)
    fname = f"urls_{domain or 'export'}.txt"
    return Response(
        content=text,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


## --- Content Intel Patterns CRUD ---

@app.get("/content-intel/patterns", tags=["Content Intel"])
def list_patterns(category: str = None, authorized: bool = Depends(auth)):
    """List content intel extraction patterns."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if category:
            cur.execute(
                "SELECT * FROM content_intel_patterns WHERE category = %s ORDER BY category, name",
                [category],
            )
        else:
            cur.execute("SELECT * FROM content_intel_patterns ORDER BY category, name")
        rows = cur.fetchall()
    for r in rows:
        r["id"] = str(r["id"])
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
        r["updated_at"] = r["updated_at"].isoformat() if r.get("updated_at") else None
    return {"ok": True, "patterns": rows}


@app.post("/content-intel/patterns", tags=["Content Intel"])
def create_pattern(body: dict, authorized: bool = Depends(auth)):
    """Create a custom content extraction pattern."""
    category = body.get("category")
    name = body.get("name")
    pattern = body.get("pattern")
    if not all([category, name, pattern]):
        raise HTTPException(400, "category, name, and pattern are required")
    # Validate regex
    try:
        import re as _re
        _re.compile(pattern)
    except _re.error as e:
        raise HTTPException(400, f"Invalid regex pattern: {e}")
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO content_intel_patterns
               (category, name, pattern, label, enabled, description)
               VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
            (category, name, pattern,
             body.get("label", name),
             body.get("enabled", True),
             body.get("description")),
        )
        row = cur.fetchone()
        conn.commit()
    return {"ok": True, "id": str(row["id"])}


@app.put("/content-intel/patterns/{pattern_id}", tags=["Content Intel"])
def update_pattern(pattern_id: str, body: dict, authorized: bool = Depends(auth)):
    """Update a content extraction pattern."""
    if body.get("pattern"):
        try:
            import re as _re
            _re.compile(body["pattern"])
        except _re.error as e:
            raise HTTPException(400, f"Invalid regex pattern: {e}")
    updates = []
    params = []
    for field in ("category", "name", "pattern", "label", "enabled", "description"):
        if field in body:
            updates.append(f"{field} = %s")
            params.append(body[field])
    if not updates:
        raise HTTPException(400, "No fields to update")
    updates.append("updated_at = now()")
    params.append(pattern_id)
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            f"UPDATE content_intel_patterns SET {', '.join(updates)} WHERE id = %s",
            params,
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Pattern not found")
        conn.commit()
    return {"ok": True}


@app.delete("/content-intel/patterns/{pattern_id}", tags=["Content Intel"])
def delete_pattern(pattern_id: str, authorized: bool = Depends(auth)):
    """Delete a content extraction pattern."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM content_intel_patterns WHERE id = %s", [pattern_id])
        if cur.rowcount == 0:
            raise HTTPException(404, "Pattern not found")
        conn.commit()
    return {"ok": True}


## --- Content Extraction manual editing ---

@app.patch("/content-extractions/{extraction_id}", tags=["Content Intel"])
def update_extraction(extraction_id: str, body: dict, authorized: bool = Depends(auth)):
    """Manually edit a content extraction's data fields."""
    allowed = ("emails", "names", "internal_paths", "api_endpoints",
               "exposed_keys", "tech_indicators", "comments", "hidden_inputs",
               "interesting_files", "file_metadata", "js_configs")
    updates = []
    params = []
    for field in allowed:
        if field in body:
            updates.append(f"{field} = %s")
            params.append(Json(body[field]))
    if not updates:
        raise HTTPException(400, f"No editable fields provided. Allowed: {', '.join(allowed)}")
    params.append(extraction_id)
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            f"UPDATE content_extractions SET {', '.join(updates)} WHERE id = %s",
            params,
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Extraction not found")
        conn.commit()
    return {"ok": True}


@app.delete("/content-extractions/{extraction_id}", tags=["Content Intel"])
def delete_extraction(extraction_id: str, authorized: bool = Depends(auth)):
    """Delete a content extraction."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM content_extractions WHERE id = %s", [extraction_id])
        if cur.rowcount == 0:
            raise HTTPException(404, "Extraction not found")
        conn.commit()
    return {"ok": True}


@app.post("/wordlists/generate", tags=["Wordlists"])
def generate_wordlist_endpoint(
    body: dict,
    authorized: bool = Depends(auth),
):
    """Generate CeWL-style wordlist from content extractions."""
    from wordlist_generator import generate_wordlist

    try:
        result = generate_wordlist(
            asset_id=body.get("asset_id"),
            scan_id=body.get("scan_id"),
            list_type=body.get("list_type", "passwords"),
            min_word_length=body.get("min_word_length", 5),
            max_lines=body.get("max_lines", 50000),
            enable_mutations=body.get("enable_mutations", True),
            mutations=body.get("mutations"),
            include_sources=body.get("include_sources"),
        )
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"Generation failed: {e}")

    return {"ok": True, **result}


## --- Data Export / Import endpoints ---

import csv
import io
import zipfile
import hashlib

# Category → table mapping for export
EXPORT_CATEGORIES = {
    "assets":      ["assets", "ports"],
    "findings":    ["vulns", "web_findings", "playwright_findings"],
    "recon":       ["recon_findings"],
    "credentials": ["credential_findings"],
    "params":      ["discovered_params"],
    "exploits":    ["pending_exploits", "exploit_results"],
    "screenshots": ["screenshot_metadata"],
}


def _severity_to_nessus(sev: str) -> int:
    """Map severity string to Nessus numeric risk level."""
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        (sev or "info").lower(), 0
    )


def _serialize_value(val):
    """Serialize a single value for JSON export (handles datetimes, inet, etc.)."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    if hasattr(val, "__str__") and type(val).__name__ in ("IPv4Address", "IPv6Address"):
        return str(val)
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, (int, float, bool, str)):
        return val
    # psycopg2 inet type, UUID, Decimal, etc.
    return str(val)


def _export_table_rows(cur, table: str, limit: int = 50000) -> list:
    """Generic SELECT * from a table with safe serialization."""
    cur.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT %s", [limit])
    cols = [desc[0] for desc in cur.description]
    rows = []
    for row in cur.fetchall():
        rows.append({col: _serialize_value(row[col]) for col in cols})
    return rows


def _build_nessus_xml(data: dict) -> str:
    """Build a .nessus XML document from findings tables."""
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report")
    report.set("name", "pentest-export")

    # Group findings by IP
    host_findings: Dict[str, list] = {}
    finding_tables = ["vulns", "web_findings", "playwright_findings", "credential_findings"]
    for tbl in finding_tables:
        for row in data.get(tbl, []):
            ip = None
            if tbl == "vulns":
                ip = row.get("metadata", {}).get("ip") if isinstance(row.get("metadata"), dict) else None
            elif tbl == "credential_findings":
                ip = str(row.get("ip", "")) if row.get("ip") else None
            if not ip:
                ip = str(row.get("ip", "unknown"))
            host_findings.setdefault(ip, []).append((tbl, row))

    for ip, items in host_findings.items():
        host_el = ET.SubElement(report, "ReportHost")
        host_el.set("name", ip)
        props = ET.SubElement(host_el, "HostProperties")
        tag = ET.SubElement(props, "tag")
        tag.set("name", "host-ip")
        tag.text = ip

        for tbl, row in items:
            sev = _severity_to_nessus(row.get("severity", "info"))
            title = row.get("script") or row.get("name") or row.get("title") or row.get("exploit_title") or "Finding"
            rid = row.get("id", "")
            plugin_id = str(abs(int(hashlib.md5(rid.encode()).hexdigest()[:8], 16)) % 900000 + 100000)

            item = ET.SubElement(host_el, "ReportItem")
            item.set("port", str(row.get("port", 0) or 0))
            item.set("svc_name", row.get("service", "") or row.get("protocol", "") or "")
            item.set("protocol", row.get("proto", "tcp") or "tcp")
            item.set("severity", str(sev))
            item.set("pluginID", plugin_id)
            item.set("pluginName", title[:200])
            item.set("pluginFamily", "Pentest Export")

            def _sub(tag_name, text):
                el = ET.SubElement(item, tag_name)
                el.text = str(text) if text else ""
                return el

            _sub("description", row.get("output") or row.get("evidence") or row.get("description") or "")
            _sub("solution", row.get("solution", "N/A"))
            risk_map = {0: "None", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
            _sub("risk_factor", risk_map.get(sev, "None"))

            cves = row.get("cve", [])
            if isinstance(cves, list):
                for c in cves:
                    _sub("cve", c)

            cvss = row.get("cvss")
            if cvss is not None:
                _sub("cvss_base_score", str(cvss))

    return '<?xml version="1.0" ?>\n' + ET.tostring(root, encoding="unicode")


@app.get("/export/sarif", tags=["Export"])
def export_sarif(
    severity: Optional[List[str]] = Query(None),
    source: Optional[List[str]] = Query(None),
    limit: int = Query(5000, ge=1, le=50000),
    authorized: bool = Depends(auth),
):
    """
    Export findings in SARIF v2.1.0 format (Static Analysis Results Interchange Format).

    Maps vulnerability and web findings to SARIF results with:
    - tool/driver per source (nmap, nuclei, zap, nessus, etc.)
    - rules from scripts/templates
    - results with severity levels, messages, locations, and fingerprints
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }

    # SARIF severity mapping
    sev_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # --- Collect vuln findings ---
        vuln_sql = """
            SELECT v.id, v.script, v.output, v.severity, v.cve, v.cvss, v.fingerprint,
                   v.metadata, v.created_at,
                   host(a.ip)::text as ip, a.hostname, p.port, p.proto
            FROM vulns v
            LEFT JOIN assets a ON v.asset_id = a.id
            LEFT JOIN ports p ON v.port_id = p.id
            WHERE 1=1
        """
        params = []
        if severity:
            vuln_sql += " AND v.severity = ANY(%s)"
            params.append(severity)
        if source:
            # Match source prefix in script field (e.g., 'nmap:', 'nessus:', 'nuclei:')
            patterns = [f"{s}:%" for s in source]
            vuln_sql += " AND (" + " OR ".join(["v.script LIKE %s"] * len(patterns)) + ")"
            params.extend(patterns)
        vuln_sql += f" ORDER BY v.created_at DESC LIMIT {int(limit)}"
        cur.execute(vuln_sql, params)
        vuln_rows = cur.fetchall()

        # --- Collect web findings ---
        web_sql = """
            SELECT id, url, source, name, severity, issue_type, evidence,
                   description, cwe, fingerprint, first_seen
            FROM web_findings WHERE 1=1
        """
        web_params = []
        if severity:
            web_sql += " AND severity = ANY(%s)"
            web_params.append(severity)
        if source:
            web_sql += " AND source = ANY(%s)"
            web_params.append(source)
        web_sql += f" ORDER BY first_seen DESC LIMIT {int(limit)}"
        cur.execute(web_sql, web_params)
        web_rows = cur.fetchall()

    # Group by tool for SARIF runs
    tool_results: dict = {}

    # Process vulns
    for row in vuln_rows:
        script = row.get("script") or "unknown"
        tool_name = script.split(":")[0] if ":" in script else script
        if tool_name not in tool_results:
            tool_results[tool_name] = {"rules": {}, "results": []}

        rule_id = script
        if rule_id not in tool_results[tool_name]["rules"]:
            tool_results[tool_name]["rules"][rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": script},
            }

        result = {
            "ruleId": rule_id,
            "level": sev_map.get(row.get("severity", "info"), "note"),
            "message": {"text": (row.get("output") or script)[:2000]},
            "locations": [],
            "properties": {
                "severity": row.get("severity"),
                "created_at": str(row.get("created_at")),
            },
        }

        # Physical location
        ip = row.get("ip") or "unknown"
        port = row.get("port")
        uri = f"tcp://{ip}:{port}" if port else f"tcp://{ip}"
        result["locations"].append({
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
            }
        })

        # Fingerprint
        if row.get("fingerprint"):
            result["fingerprints"] = {"finding/v1": row["fingerprint"]}

        # CVEs as partial fingerprints
        cves = row.get("cve") or []
        if cves:
            result["properties"]["cve"] = cves

        if row.get("cvss") is not None:
            result["properties"]["cvss"] = float(row["cvss"])

        tool_results[tool_name]["results"].append(result)

    # Process web findings
    for row in web_rows:
        tool_name = row.get("source") or "web"
        if tool_name not in tool_results:
            tool_results[tool_name] = {"rules": {}, "results": []}

        rule_id = f"{tool_name}:{row.get('issue_type') or 'finding'}"
        name = row.get("name") or rule_id
        if rule_id not in tool_results[tool_name]["rules"]:
            tool_results[tool_name]["rules"][rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": name},
            }

        result = {
            "ruleId": rule_id,
            "level": sev_map.get(row.get("severity", "info"), "note"),
            "message": {"text": (row.get("description") or name)[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": row.get("url") or ""},
                }
            }],
            "properties": {
                "severity": row.get("severity"),
                "created_at": str(row.get("first_seen")),
            },
        }

        if row.get("fingerprint"):
            result["fingerprints"] = {"finding/v1": row["fingerprint"]}

        cwes = row.get("cwe") or []
        if cwes:
            result["properties"]["cwe"] = cwes

        tool_results[tool_name]["results"].append(result)

    # Build SARIF runs
    for tool_name, data in tool_results.items():
        run = {
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/raptordoug/rag_scan_stack",
                    "rules": list(data["rules"].values()),
                }
            },
            "results": data["results"],
        }
        sarif["runs"].append(run)

    return Response(
        content=json.dumps(sarif, default=str, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="pentest_findings.sarif"'},
    )


@app.get("/export/data", tags=["Export"])
def export_data(
    format: str = Query("json", description="Export format: json, csv, nessus"),
    categories: str = Query("assets,findings,recon,credentials,params,exploits,screenshots",
                            description="Comma-separated categories"),
    authorized: bool = Depends(auth),
):
    """
    Export collected pentest data.

    Formats:
    - json: Full data envelope with all selected categories
    - csv: ZIP file with one CSV per table
    - nessus: Nessus-compatible XML (findings tables only)
    """
    selected = [c.strip() for c in categories.split(",") if c.strip() in EXPORT_CATEGORIES]
    if not selected:
        raise HTTPException(400, "No valid categories selected")

    # Collect tables to query
    tables_to_query = []
    for cat in selected:
        tables_to_query.extend(EXPORT_CATEGORIES[cat])

    # Query all data
    data: Dict[str, list] = {}
    counts: Dict[str, int] = {}
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        for tbl in tables_to_query:
            try:
                rows = _export_table_rows(cur, tbl)
                data[tbl] = rows
                counts[tbl] = len(rows)
            except Exception:
                conn.rollback()
                data[tbl] = []
                counts[tbl] = 0

    if format == "nessus":
        xml_str = _build_nessus_xml(data)
        return Response(
            content=xml_str,
            media_type="application/xml",
            headers={"Content-Disposition": 'attachment; filename="pentest_export.nessus"'},
        )

    if format == "csv":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for tbl, rows in data.items():
                if not rows:
                    continue
                csv_buf = io.StringIO()
                cols = list(rows[0].keys())
                writer = csv.DictWriter(csv_buf, fieldnames=cols)
                writer.writeheader()
                for row in rows:
                    safe_row = {}
                    for k, v in row.items():
                        if isinstance(v, (dict, list)):
                            safe_row[k] = json.dumps(v)
                        else:
                            safe_row[k] = v
                    writer.writerow(safe_row)
                zf.writestr(f"{tbl}.csv", csv_buf.getvalue())
        buf.seek(0)
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": 'attachment; filename="pentest_export_csv.zip"'},
        )

    # Default: JSON
    envelope = {
        "schema_version": "1.1",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "categories": selected,
        "data": data,
        "counts": counts,
    }
    return Response(
        content=json.dumps(envelope, default=str),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="pentest_export.json"'},
    )


@app.post("/import/data", tags=["Import"])
def import_data(file: UploadFile = File(...), authorized: bool = Depends(auth)):
    """
    Import pentest data from a previous JSON export.

    Inserts records in dependency order. Existing records (by id) are skipped.
    """
    try:
        raw = file.file.read()
        payload = json.loads(raw)
    except Exception as e:
        raise HTTPException(400, f"Invalid JSON file: {e}")

    if payload.get("schema_version") not in ("1.0", "1.1"):
        raise HTTPException(400, "Unsupported schema_version (expected '1.0')")

    data = payload.get("data", {})
    if not data:
        raise HTTPException(400, "No data found in export file")

    # Insert order (respects FK dependencies)
    insert_order = [
        "assets", "ports",
        "vulns", "web_findings", "playwright_findings",
        "recon_findings", "credential_findings", "discovered_params",
        "pending_exploits", "exploit_results",
        "screenshot_metadata",
    ]

    inserted: Dict[str, int] = {}

    with get_db() as conn, conn.cursor() as cur:
        for tbl in insert_order:
            rows = data.get(tbl, [])
            if not rows:
                continue
            count = 0
            cols = list(rows[0].keys())
            col_list = ", ".join(cols)
            placeholders = ", ".join(["%s"] * len(cols))
            sql = f"INSERT INTO {tbl} ({col_list}) VALUES ({placeholders}) ON CONFLICT (id) DO NOTHING"

            for row in rows:
                vals = []
                for c in cols:
                    v = row.get(c)
                    if isinstance(v, (dict, list)):
                        vals.append(Json(v))
                    else:
                        vals.append(v)
                try:
                    cur.execute(sql, vals)
                    if cur.rowcount > 0:
                        count += 1
                except Exception:
                    conn.rollback()
                    continue
            inserted[tbl] = count
        conn.commit()

    return {"ok": True, "inserted": inserted, "total": sum(inserted.values())}


# ============================================================================
# Scan Runs + Delta Comparison
# ============================================================================

@app.get("/scan-runs", tags=["Delta"])
def list_scan_runs(
    tool: str = None,
    limit: int = Query(50, le=200),
    authorized: bool = Depends(auth),
):
    """List scan runs, optionally filtered by tool."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if tool:
            cur.execute(
                "SELECT * FROM scan_runs WHERE tool = %s ORDER BY started_at DESC LIMIT %s",
                (tool, limit),
            )
        else:
            cur.execute(
                "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT %s", (limit,)
            )
        rows = cur.fetchall()
    return {"runs": [dict(r) for r in rows]}


@app.post("/scan-runs/backfill", tags=["Delta"])
def backfill_scan_runs(authorized: bool = Depends(auth)):
    """Generate scan_runs + scan_run_findings from existing findings.

    Groups findings by source/tool and date, creating one run per tool per day,
    then links each finding to its run via scan_run_findings.
    Clears existing data and rebuilds from scratch.
    """
    import uuid as _uuid
    created = []
    linked = 0
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Clear existing backfilled data
        cur.execute("DELETE FROM scan_run_findings")
        cur.execute("DELETE FROM scan_runs")

        # ── Vulns: group by script + day ──
        cur.execute("""
            SELECT v.id AS finding_id, v.fingerprint,
                   COALESCE(v.script, 'nmap') AS tool,
                   date_trunc('day', v.created_at) AS day,
                   v.created_at
            FROM vulns v
        """)
        vuln_rows = cur.fetchall()

        # ── Web findings: group by source + day ──
        cur.execute("""
            SELECT id AS finding_id, fingerprint, source AS tool,
                   date_trunc('day', first_seen) AS day,
                   first_seen AS created_at
            FROM web_findings
            WHERE source IS NOT NULL
        """)
        web_rows = cur.fetchall()

        # ── Recon findings: group by source + day ──
        cur.execute("""
            SELECT id AS finding_id, fingerprint, source AS tool,
                   date_trunc('day', created_at) AS day,
                   created_at
            FROM recon_findings
            WHERE source IS NOT NULL
        """)
        recon_rows = cur.fetchall()

        # Group into runs and create entries
        from collections import defaultdict

        # key: (finding_type, tool, day_str) → list of findings
        groups = defaultdict(list)
        for row in vuln_rows:
            key = ("vuln", row["tool"], str(row["day"]))
            groups[key].append(row)
        for row in web_rows:
            key = ("web", row["tool"], str(row["day"]))
            groups[key].append(row)
        for row in recon_rows:
            key = ("recon", row["tool"], str(row["day"]))
            groups[key].append(row)

        for (finding_type, tool, _day), findings in groups.items():
            run_id = str(_uuid.uuid4())
            timestamps = [f["created_at"] for f in findings]
            first = min(timestamps)
            last = max(timestamps)
            cur.execute(
                """INSERT INTO scan_runs (id, tool, started_at, finished_at, finding_count)
                   VALUES (%s, %s, %s, %s, %s)""",
                (run_id, tool, first, last, len(findings)),
            )
            created.append({
                "id": run_id,
                "tool": tool,
                "finding_count": len(findings),
                "started_at": str(first),
            })

            # Link findings to this run
            for f in findings:
                if f.get("fingerprint"):
                    cur.execute(
                        """INSERT INTO scan_run_findings (run_id, finding_type, finding_id, fingerprint)
                           VALUES (%s, %s, %s, %s)""",
                        (run_id, finding_type, str(f["finding_id"]), f["fingerprint"]),
                    )
                    linked += 1

        conn.commit()
    return {"created": len(created), "linked": linked, "runs": created}


@app.post("/scan-runs", tags=["Delta"])
def create_scan_run(
    tool: str = Query(...),
    target: str = Query(None),
    job_id: str = Query(None),
    profile: str = Query(None),
    authorized: bool = Depends(auth),
):
    """Register a new scan run (call before ingestion)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        run_id = str(__import__("uuid").uuid4())
        cur.execute(
            """INSERT INTO scan_runs (id, tool, target, job_id, profile)
               VALUES (%s, %s, %s, %s, %s) RETURNING *""",
            (run_id, tool, target, job_id, profile),
        )
        run = dict(cur.fetchone())
        conn.commit()
    return run


@app.patch("/scan-runs/{run_id}", tags=["Delta"])
def finish_scan_run(run_id: str, authorized: bool = Depends(auth)):
    """Mark a scan run as finished and count its findings."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT count(*) as cnt FROM scan_run_findings WHERE run_id = %s",
            (run_id,),
        )
        cnt = cur.fetchone()["cnt"]
        cur.execute(
            """UPDATE scan_runs SET finished_at = now(), finding_count = %s
               WHERE id = %s RETURNING *""",
            (cnt, run_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Run not found")
        conn.commit()
    return dict(row)


@app.post("/scan-runs/{run_id}/link", tags=["Delta"])
def link_findings_to_run(
    run_id: str,
    finding_type: str = Query(..., description="vuln, web, or recon"),
    authorized: bool = Depends(auth),
):
    """
    Link all findings with fingerprints that were created since the run started
    to this scan run. Call after ingestion completes.
    """
    table_map = {
        "vuln": "vulns",
        "web": "web_findings",
        "recon": "recon_findings",
    }
    tbl = table_map.get(finding_type)
    if not tbl:
        raise HTTPException(400, "finding_type must be vuln, web, or recon")

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get run start time
        cur.execute("SELECT started_at FROM scan_runs WHERE id = %s", (run_id,))
        run = cur.fetchone()
        if not run:
            raise HTTPException(404, "Run not found")

        # Link findings created after run started that have fingerprints
        ts_col = "created_at" if tbl in ("vulns", "recon_findings") else "first_seen"
        cur.execute(f"""
            INSERT INTO scan_run_findings (id, run_id, finding_type, finding_id, fingerprint)
            SELECT gen_random_uuid(), %s, %s, id, fingerprint
            FROM {tbl}
            WHERE fingerprint IS NOT NULL AND {ts_col} >= %s
            ON CONFLICT DO NOTHING
        """, (run_id, finding_type, run["started_at"]))
        linked = cur.rowcount
        conn.commit()

    return {"linked": linked}


@app.get("/scan-runs/compare", tags=["Delta"])
def compare_scan_runs(
    run_a: str = Query(..., description="Older run ID"),
    run_b: str = Query(..., description="Newer run ID"),
    authorized: bool = Depends(auth),
):
    """
    Compare two scan runs and return delta (new, resolved, unchanged findings).

    - new: fingerprints in run_b but not in run_a
    - resolved: fingerprints in run_a but not in run_b
    - unchanged: fingerprints in both
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get fingerprints for each run
        cur.execute(
            "SELECT fingerprint, finding_type, finding_id FROM scan_run_findings WHERE run_id = %s",
            (run_a,),
        )
        fps_a = {r["fingerprint"]: r for r in cur.fetchall()}

        cur.execute(
            "SELECT fingerprint, finding_type, finding_id FROM scan_run_findings WHERE run_id = %s",
            (run_b,),
        )
        fps_b = {r["fingerprint"]: r for r in cur.fetchall()}

        set_a = set(fps_a.keys())
        set_b = set(fps_b.keys())

        new_fps = set_b - set_a
        resolved_fps = set_a - set_b
        unchanged_fps = set_a & set_b

        # Fetch finding details for new and resolved
        def _fetch_details(fingerprints, fp_map):
            results = []
            for fp in fingerprints:
                info = fp_map[fp]
                tbl_map = {"vuln": "vulns", "web": "web_findings", "recon": "recon_findings"}
                tbl = tbl_map.get(info["finding_type"], "vulns")

                if tbl == "vulns":
                    cur.execute(
                        """SELECT v.id, v.script, v.severity, v.cve, v.cvss, v.fingerprint,
                                  host(a.ip)::text as ip, p.port
                           FROM vulns v
                           LEFT JOIN assets a ON v.asset_id = a.id
                           LEFT JOIN ports p ON v.port_id = p.id
                           WHERE v.id = %s""",
                        (info["finding_id"],),
                    )
                elif tbl == "web_findings":
                    cur.execute(
                        """SELECT id, url, source, name, severity, issue_type, fingerprint
                           FROM web_findings WHERE id = %s""",
                        (info["finding_id"],),
                    )
                elif tbl == "recon_findings":
                    cur.execute(
                        """SELECT id, source, finding_type, target, severity, fingerprint
                           FROM recon_findings WHERE id = %s""",
                        (info["finding_id"],),
                    )
                row = cur.fetchone()
                if row:
                    results.append(dict(row))
            return results

        new_details = _fetch_details(new_fps, fps_b)
        resolved_details = _fetch_details(resolved_fps, fps_a)

    return {
        "run_a": run_a,
        "run_b": run_b,
        "summary": {
            "new": len(new_fps),
            "resolved": len(resolved_fps),
            "unchanged": len(unchanged_fps),
        },
        "new": new_details,
        "resolved": resolved_details,
        "unchanged_count": len(unchanged_fps),
    }


@app.post("/findings/backfill-fingerprints", tags=["Delta"])
def backfill_fingerprints(authorized: bool = Depends(auth)):
    """Compute fingerprints for all findings that are missing them."""
    from etl.fingerprint import vuln_fingerprint, web_fingerprint, recon_fingerprint
    updated = {"vulns": 0, "web_findings": 0, "recon_findings": 0}
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Vulns (join through ports → assets to get ip + port)
        cur.execute("""
            SELECT v.id, a.ip::text AS ip, p.port, v.script, v.cve
            FROM vulns v
            LEFT JOIN ports p ON v.port_id = p.id
            LEFT JOIN assets a ON p.asset_id = a.id
            WHERE v.fingerprint IS NULL
        """)
        for row in cur.fetchall():
            fp = vuln_fingerprint(row.get("ip"), row.get("port"), row.get("script"), row.get("cve"))
            cur.execute("UPDATE vulns SET fingerprint = %s WHERE id = %s", (fp, row["id"]))
            updated["vulns"] += 1

        # Web findings
        cur.execute("SELECT id, url, source, name, issue_type FROM web_findings WHERE fingerprint IS NULL")
        for row in cur.fetchall():
            fp = web_fingerprint(row.get("url"), row.get("source"), row.get("name"), row.get("issue_type"))
            cur.execute("UPDATE web_findings SET fingerprint = %s WHERE id = %s", (fp, row["id"]))
            updated["web_findings"] += 1

        # Recon findings
        cur.execute("SELECT id, source, finding_type, target, data FROM recon_findings WHERE fingerprint IS NULL")
        for row in cur.fetchall():
            data_key = None
            if row.get("data") and isinstance(row["data"], dict):
                data_key = row["data"].get("subdomain") or row["data"].get("host") or str(row["data"])[:100]
            fp = recon_fingerprint(row.get("source"), row.get("finding_type"), row.get("target"), data_key)
            cur.execute("UPDATE recon_findings SET fingerprint = %s WHERE id = %s", (fp, row["id"]))
            updated["recon_findings"] += 1

        conn.commit()
    return {"updated": updated, "total": sum(updated.values())}


@app.get("/findings/dedup-report", tags=["Delta"])
def dedup_report(authorized: bool = Depends(auth)):
    """
    Show duplicate findings (same fingerprint, multiple records).
    Useful for identifying cross-tool overlaps.
    """
    results = []
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Vulns duplicates
        cur.execute("""
            SELECT fingerprint, count(*) as cnt,
                   array_agg(DISTINCT script) as tools,
                   array_agg(DISTINCT severity) as severities
            FROM vulns
            WHERE fingerprint IS NOT NULL
            GROUP BY fingerprint
            HAVING count(*) > 1
            ORDER BY count(*) DESC
            LIMIT 100
        """)
        for row in cur.fetchall():
            results.append({
                "type": "vuln",
                "fingerprint": row["fingerprint"],
                "count": row["cnt"],
                "tools": row["tools"],
                "severities": row["severities"],
            })

        # Web duplicates
        cur.execute("""
            SELECT fingerprint, count(*) as cnt,
                   array_agg(DISTINCT source) as tools,
                   array_agg(DISTINCT severity) as severities
            FROM web_findings
            WHERE fingerprint IS NOT NULL
            GROUP BY fingerprint
            HAVING count(*) > 1
            ORDER BY count(*) DESC
            LIMIT 100
        """)
        for row in cur.fetchall():
            results.append({
                "type": "web",
                "fingerprint": row["fingerprint"],
                "count": row["cnt"],
                "tools": row["tools"],
                "severities": row["severities"],
            })

    return {"duplicates": results, "total": len(results)}


# ============================================================================
# Settings / API Keys Management
# ============================================================================

ALLOWED_KEY_NAMES = {
    "shodan_api_key", "censys_api_id", "censys_api_secret",
    "pdcp_api_key", "greyhatwarfare_api_key", "do_api_token",
    "aws_access_key_id", "aws_secret_access_key",
}

def _is_valid_key_name(name: str) -> bool:
    return name in ALLOWED_KEY_NAMES or name.startswith("other_")

def _mask_value(val: str) -> str:
    if len(val) <= 4:
        return "*" * len(val)
    return "*" * (len(val) - 4) + val[-4:]

class ApiKeyBody(BaseModel):
    value: str = Field(..., min_length=1)

@app.get("/settings/keys", tags=["Settings"])
def list_api_keys(_: bool = Depends(auth)):
    """List stored API keys with masked values (last 4 chars visible)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT key, value, updated_at FROM app_settings WHERE category = 'api_key' ORDER BY key"
        )
        rows = cur.fetchall()
    return {
        "keys": [
            {
                "key": r["key"],
                "masked_value": _mask_value(r["value"]),
                "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
            }
            for r in rows
        ]
    }

@app.put("/settings/keys/{key_name}", tags=["Settings"])
def upsert_api_key(key_name: str, body: ApiKeyBody, _: bool = Depends(auth)):
    """Create or update an API key."""
    if not _is_valid_key_name(key_name):
        raise HTTPException(400, f"Invalid key name: {key_name}")
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO app_settings (key, value, category)
               VALUES (%s, %s, 'api_key')
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()""",
            (key_name, body.value),
        )
        conn.commit()
    return {"ok": True, "key": key_name}

@app.delete("/settings/keys/{key_name}", tags=["Settings"])
def delete_api_key(key_name: str, _: bool = Depends(auth)):
    """Delete an API key."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM app_settings WHERE key = %s AND category = 'api_key'",
            (key_name,),
        )
        deleted = cur.rowcount
        conn.commit()
    if deleted == 0:
        raise HTTPException(404, f"Key not found: {key_name}")
    return {"ok": True, "key": key_name}

@app.get("/settings/keys/raw", tags=["Settings"])
def get_raw_api_keys(_: bool = Depends(auth)):
    """Return unmasked API keys. Intended for internal scanner use only."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT key, value FROM app_settings WHERE category = 'api_key' ORDER BY key"
        )
        rows = cur.fetchall()
    return {"keys": {r["key"]: r["value"] for r in rows}}


# ── Generic app_settings (config category) ─────────────────────────────────

class SettingBody(BaseModel):
    value: str

@app.get("/settings/config/{key_name}", tags=["Settings"])
def get_setting(key_name: str, _: bool = Depends(auth)):
    """Read a config setting by key."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT value, updated_at FROM app_settings WHERE key = %s AND category = 'config'",
            (key_name,),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, f"Setting not found: {key_name}")
    return {"key": key_name, "value": row["value"], "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None}

@app.put("/settings/config/{key_name}", tags=["Settings"])
def upsert_setting(key_name: str, body: SettingBody, _: bool = Depends(auth)):
    """Create or update a config setting."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO app_settings (key, value, category)
               VALUES (%s, %s, 'config')
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()""",
            (key_name, body.value),
        )
        conn.commit()
    return {"ok": True, "key": key_name, "value": body.value}


# ── Per-agent model selection (Settings → LLM Tuning) ──────────────────────
# Storage: app_settings rows with category='agent_model' and key='agent_model:<id>'.
# Helper get_agent_model() reads DB → env → default and is what the agents call.

AGENT_MODEL_REGISTRY = [
    {"id": "cloud_triage_agent",
     "name": "Cloud Triage Agent",
     "description": "Re-ranks open cloud recommendations and produces a top-3 next-actions plan",
     "env_chain": ["CLOUD_TRIAGE_MODEL", "OLLAMA_MODEL", "LLM_MODEL"],
     "default": "gemma4:31b"},
    {"id": "gap_agent",
     "name": "Recon Gap Analysis",
     "description": "Identifies missing recon data per engagement and recommends scans",
     "env_chain": ["GAP_AGENT_MODEL", "OLLAMA_MODEL", "LLM_MODEL"],
     "default": "gemma4:31b"},
    {"id": "osint_agent",
     "name": "OSINT Flagging Agent",
     "description": "Rule-engine + LLM advisory that flags follow-up findings from imported data",
     "env_chain": ["OSINT_AGENT_MODEL", "OLLAMA_MODEL", "LLM_MODEL"],
     "default": "gemma4:latest"},
    {"id": "scan_recommender",
     "name": "Scan Recommender",
     "description": "LLM-powered tool/scan recommendations against discovered services",
     "env_chain": ["SCAN_RECOMMENDER_MODEL", "OLLAMA_MODEL", "LLM_MODEL"],
     "default": "gemma4:31b"},
    {"id": "diagnostic_agent",
     "name": "AI Diagnostic Agent",
     "description": "Pulls service logs and analyzes anomalies for the Services → Health panel",
     "env_chain": ["DIAGNOSTIC_AGENT_MODEL", "OLLAMA_MODEL", "LLM_MODEL"],
     "default": "gemma4:latest"},
    {"id": "vault_import_agent",
     "name": "Vault Import Agent",
     "description": "Extracts credentials from recon_findings (MicroBurst secrets, CloudFox keys, etc.) into the credential vault — replaces 'Navigate to Credentials tab' suggestions with one-click import",
     "env_chain": ["VAULT_IMPORT_MODEL", "OLLAMA_MODEL", "LLM_MODEL"],
     "default": "gemma4:31b"},
    {"id": "takeover_hunter_agent",
     "name": "Subdomain Takeover Hunter",
     "description": "Probes dns_cname / subfinder findings against ~20 cloud-resource fingerprints (S3, Azure WebApps, GitHub Pages, Heroku, etc.) to surface dangling subdomains that could be claimed during the engagement. Routes through the configured proxy.",
     "env_chain": [],
     "default": "(no LLM)"},
]


def get_agent_auto_enabled(agent_id: str, default: bool = False) -> bool:
    """Read the auto-run flag for an agent. Default OFF for everything that
    creates side effects (writes to credential_vault, etc.) — operator must
    explicitly enable. Stored as 'agent_auto:<id>' in app_settings."""
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT value FROM app_settings WHERE key=%s AND category='agent_automation'",
                (f"agent_auto:{agent_id}",),
            )
            row = cur.fetchone()
            if row and row.get("value"):
                return str(row["value"]).strip().lower() in ("1", "true", "yes", "on")
    except Exception:
        pass
    return default


def get_agent_model(agent_id: str) -> str:
    """Resolve an agent's LLM. DB override takes precedence; falls back to env
    chain and finally the registered default. Used by agent code at runtime."""
    spec = next((a for a in AGENT_MODEL_REGISTRY if a["id"] == agent_id), None)
    if spec is None:
        return os.environ.get("OLLAMA_MODEL") or os.environ.get("LLM_MODEL") or "gemma4:latest"
    # 1. DB override
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT value FROM app_settings WHERE key=%s AND category='agent_model'",
                (f"agent_model:{agent_id}",),
            )
            row = cur.fetchone()
            if row and row.get("value"):
                return row["value"]
    except Exception:
        pass
    # 2. Env chain
    for env_key in spec["env_chain"]:
        v = os.environ.get(env_key)
        if v:
            return v
    # 3. Registered default
    return spec["default"]


def _list_available_models() -> List[str]:
    """Hit Ollama /api/tags to enumerate installed (and cloud-routed) models."""
    try:
        base = (os.environ.get("OLLAMA_BASE_URL")
                or os.environ.get("OLLAMA_URL")
                or "http://host.docker.internal:11434").rstrip("/")
        resp = requests.get(f"{base}/api/tags", timeout=5, verify=False)
        if resp.status_code == 200:
            return sorted({m.get("name", "") for m in resp.json().get("models", []) if m.get("name")})
    except Exception:
        pass
    return []


@app.get("/settings/agent-models", tags=["Settings"])
def get_agent_models(_: bool = Depends(auth)):
    """Return registered agents with their currently-resolved model + the list
    of available local/cloud models (from Ollama /api/tags) for dropdown UI."""
    overrides: Dict[str, str] = {}
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT key, value FROM app_settings WHERE category='agent_model'")
            for r in cur.fetchall():
                k = r["key"].split(":", 1)[-1] if r["key"].startswith("agent_model:") else r["key"]
                overrides[k] = r["value"]
    except Exception:
        pass

    agents = []
    for spec in AGENT_MODEL_REGISTRY:
        current = overrides.get(spec["id"])
        source = "custom"
        if not current:
            for env_key in spec["env_chain"]:
                v = os.environ.get(env_key)
                if v:
                    current = v
                    source = f"env:{env_key}"
                    break
            if not current:
                current = spec["default"]
                source = "default"
        agents.append({
            "id": spec["id"], "name": spec["name"], "description": spec["description"],
            "current_model": current, "source": source, "default_model": spec["default"],
            "env_chain": spec["env_chain"],
            # cloud_triage has run unconditionally after ingest historically, so
            # surface its effective default as ON; vault_import is opt-in (writes
            # to credential_vault) and stays OFF until the operator flips it.
            "auto_enabled": get_agent_auto_enabled(
                spec["id"], default=(spec["id"] == "cloud_triage_agent")
            ),
            "auto_capable": spec["id"] in {"vault_import_agent", "cloud_triage_agent", "takeover_hunter_agent"},
        })

    return {"agents": agents, "available_models": _list_available_models()}


class AgentAutoBody(BaseModel):
    enabled: bool


@app.put("/settings/agent-models/{agent_id}/auto", tags=["Settings"])
def put_agent_auto(agent_id: str, body: AgentAutoBody, _: bool = Depends(auth)):
    """Enable / disable auto-run for an agent. Default off for safety; only
    'auto_capable' agents (those with documented post-ingest hooks) are
    actually consulted by the runtime, but we accept any registered agent
    so the registry stays the single source of truth."""
    spec = next((a for a in AGENT_MODEL_REGISTRY if a["id"] == agent_id), None)
    if spec is None:
        raise HTTPException(404, f"Unknown agent: {agent_id}")
    key = f"agent_auto:{agent_id}"
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO app_settings (key, value, category)
               VALUES (%s, %s, 'agent_automation')
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()""",
            (key, "true" if body.enabled else "false"),
        )
        conn.commit()
    try:
        from webhooks import emit_webhook
        emit_webhook("agent_auto_toggled", "settings", {
            "agent_id": agent_id, "enabled": body.enabled,
        })
    except Exception:
        pass
    return {"ok": True, "agent_id": agent_id, "auto_enabled": body.enabled}


class AgentModelBody(BaseModel):
    model: Optional[str] = None  # None / empty string = clear override → fall back to env/default


@app.put("/settings/agent-models/{agent_id}", tags=["Settings"])
def put_agent_model(agent_id: str, body: AgentModelBody, _: bool = Depends(auth)):
    """Set (or clear) an agent's model override."""
    spec = next((a for a in AGENT_MODEL_REGISTRY if a["id"] == agent_id), None)
    if spec is None:
        raise HTTPException(404, f"Unknown agent: {agent_id}")
    key = f"agent_model:{agent_id}"
    with get_db() as conn, conn.cursor() as cur:
        if body.model:
            cur.execute(
                """INSERT INTO app_settings (key, value, category)
                   VALUES (%s, %s, 'agent_model')
                   ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()""",
                (key, body.model.strip()),
            )
        else:
            cur.execute("DELETE FROM app_settings WHERE key=%s AND category='agent_model'", (key,))
        conn.commit()
    return {"ok": True, "agent_id": agent_id, "model": body.model or None,
            "resolved": get_agent_model(agent_id)}


# ── Exploit Watcher Settings ───────────────────────────────────────────────

class ExploitWatcherSettingsBody(BaseModel):
    poll_interval: Optional[int] = Field(default=60, ge=30, le=300)
    lookback_minutes: Optional[int] = Field(default=4320, ge=60, le=10080)
    min_confidence: Optional[float] = Field(default=0.35, ge=0.1, le=1.0)
    max_exploits_per_vuln: Optional[int] = Field(default=2, ge=1, le=10)
    enabled: Optional[bool] = Field(default=True)


@app.get("/settings/exploit-watcher", tags=["Settings"])
def get_exploit_watcher_settings(_: bool = Depends(auth)):
    """Get current exploit watcher configuration."""
    defaults = {
        "poll_interval": 60,
        "lookback_minutes": 4320,
        "min_confidence": 0.35,
        "max_exploits_per_vuln": 2,
        "enabled": True
    }

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT key, value FROM app_settings
            WHERE category = 'exploit_watcher'
        """)
        rows = cur.fetchall()

    # Merge DB values with defaults
    settings = defaults.copy()
    for row in rows:
        key = row["key"]
        value = row["value"]

        if key == "enabled":
            settings[key] = str(value).lower() in ("true", "1", "yes")
        elif key in ["poll_interval", "lookback_minutes", "max_exploits_per_vuln"]:
            settings[key] = int(value)
        elif key == "min_confidence":
            settings[key] = float(value)

    return settings


@app.put("/settings/exploit-watcher", tags=["Settings"])
def update_exploit_watcher_settings(body: ExploitWatcherSettingsBody, _: bool = Depends(auth)):
    """Update exploit watcher configuration."""
    with get_db() as conn, conn.cursor() as cur:
        settings_data = body.model_dump(exclude_unset=True)

        for key, value in settings_data.items():
            cur.execute("""
                INSERT INTO app_settings (key, value, category)
                VALUES (%s, %s, 'exploit_watcher')
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = now()
            """, (key, str(value)))

        conn.commit()

    return {"ok": True, "updated": list(settings_data.keys())}


# ============================================================================
# ENGAGEMENTS (A1)
# ============================================================================

class EngagementCreate(BaseModel):
    name: str
    client: Optional[str] = None
    engagement_type: str = "external_pentest"
    methodology: str = "custom"
    status: str = "planning"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    scope_name: Optional[str] = None
    rules_of_engagement: Optional[str] = None
    notes: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class EngagementUpdate(BaseModel):
    name: Optional[str] = None
    client: Optional[str] = None
    engagement_type: Optional[str] = None
    methodology: Optional[str] = None
    status: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    scope_name: Optional[str] = None
    rules_of_engagement: Optional[str] = None
    notes: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@app.post("/engagements", tags=["Engagements"])
def create_engagement(body: EngagementCreate, _: bool = Depends(auth)):
    """Create a new engagement."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO engagements (name, client, engagement_type, methodology, status,
                start_date, end_date, scope_name, rules_of_engagement, notes, metadata)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (body.name, body.client, body.engagement_type, body.methodology, body.status,
             body.start_date, body.end_date, body.scope_name, body.rules_of_engagement,
             body.notes or '', Json(body.metadata or {})),
        )
        row = cur.fetchone()
        conn.commit()
    return row

@app.get("/engagements", tags=["Engagements"])
def list_engagements(
    status: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """List engagements with optional status filter."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if status:
            cur.execute("SELECT * FROM engagements WHERE status = %s ORDER BY created_at DESC", (status,))
        else:
            cur.execute("SELECT * FROM engagements ORDER BY created_at DESC")
        rows = cur.fetchall()
        # Add scopes to each engagement
        for eng in rows:
            try:
                cur.execute("""
                    SELECT name, COUNT(*) as target_count
                    FROM scope_targets WHERE engagement_id = %s
                    GROUP BY name ORDER BY name
                """, (str(eng["id"]),))
                eng["scopes"] = [dict(r) for r in cur.fetchall()]
            except Exception:
                eng["scopes"] = []
    return {"engagements": rows}

@app.get("/engagements/{eid}", tags=["Engagements"])
def get_engagement(eid: str, _: bool = Depends(auth)):
    """Get engagement detail with summary stats."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM engagements WHERE id = %s", (eid,))
        eng = cur.fetchone()
        if not eng:
            raise HTTPException(404, "Engagement not found")
        # Summary stats
        stats = {"findings_by_severity": {}, "asset_count": 0, "scan_count": 0}
        try:
            cur.execute(
                """SELECT severity, COUNT(*) as cnt FROM vulns WHERE engagement_id = %s
                   GROUP BY severity""", (eid,))
            for r in cur.fetchall():
                stats["findings_by_severity"][r["severity"] or "unknown"] = r["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM assets WHERE engagement_id = %s", (eid,))
            stats["asset_count"] = cur.fetchone()["cnt"]
        except Exception:
            pass
        eng["stats"] = stats
        # Scopes under this engagement
        try:
            cur.execute("""
                SELECT name, COUNT(*) as target_count
                FROM scope_targets WHERE engagement_id = %s
                GROUP BY name ORDER BY name
            """, (eid,))
            eng["scopes"] = [dict(r) for r in cur.fetchall()]
        except Exception:
            eng["scopes"] = []
    return eng

@app.put("/engagements/{eid}", tags=["Engagements"])
def update_engagement(eid: str, body: EngagementUpdate, _: bool = Depends(auth)):
    """Update an engagement."""
    updates, vals = [], []
    for field in ["name","client","engagement_type","methodology","status","start_date",
                  "end_date","scope_name","rules_of_engagement","notes"]:
        v = getattr(body, field, None)
        if v is not None:
            updates.append(f"{field} = %s")
            vals.append(v)
    if body.metadata is not None:
        updates.append("metadata = %s")
        vals.append(Json(body.metadata))
    if not updates:
        raise HTTPException(400, "No fields to update")
    vals.append(eid)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"UPDATE engagements SET {', '.join(updates)} WHERE id = %s RETURNING *", vals)
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Engagement not found")
    return row

@app.delete("/engagements/{eid}", tags=["Engagements"])
def delete_engagement(eid: str, _: bool = Depends(auth)):
    """Archive an engagement (sets status to 'archived')."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("UPDATE engagements SET status = 'archived' WHERE id = %s RETURNING id", (eid,))
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Engagement not found")
    return {"ok": True, "id": eid}


# ── Engagement-Scoped Scopes ────────────────────────────────────────────

_SCOPE_PLACEHOLDER_TARGET = ""  # sentinel marker so an empty scope can exist
_SCOPE_PLACEHOLDER_SOURCE = "__placeholder__"


def _classify_target(target_val: str) -> str:
    """Return one of: 'ip', 'cidr', 'url', 'domain' for a free-text target."""
    if not target_val:
        return "domain"
    if "/" in target_val and target_val.split("/", 1)[0].replace(".", "").replace(":", "").isalnum():
        # Heuristic: looks like CIDR (contains slash, leading is dotted/colon-numeric)
        try:
            ipaddress.ip_network(target_val, strict=False)
            return "cidr"
        except ValueError:
            pass
    if target_val.startswith("http://") or target_val.startswith("https://"):
        return "url"
    try:
        ipaddress.ip_address(target_val)
        return "ip"
    except ValueError:
        return "domain"


@app.get("/engagements/{eid}/scopes", tags=["Engagements"])
def list_engagement_scopes(eid: str, _: bool = Depends(auth)):
    """List all scopes under an engagement with target counts.

    Sentinel placeholder rows (target='') are excluded from target_count but
    still surface the scope itself, so empty-but-named scopes are visible.
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT name,
                   COUNT(*) FILTER (WHERE target <> '' AND source IS DISTINCT FROM %s) AS target_count,
                   MAX(added_at) AS last_updated
            FROM scope_targets
            WHERE engagement_id = %s::uuid
            GROUP BY name
            ORDER BY name
        """, (_SCOPE_PLACEHOLDER_SOURCE, eid))
        return {"scopes": [dict(r) for r in cur.fetchall()]}


@app.get("/engagements/{eid}/scopes/{scope_name}", tags=["Engagements"])
def get_engagement_scope(eid: str, scope_name: str, limit: int = Query(500, le=5000), _: bool = Depends(auth)):
    """Get targets for a scope under an engagement (sentinel rows excluded)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, name, target, target_type, source, added_at, engagement_id::text
            FROM scope_targets
            WHERE engagement_id = %s::uuid AND name = %s
              AND target <> '' AND source IS DISTINCT FROM %s
            ORDER BY added_at DESC LIMIT %s
        """, (eid, scope_name, _SCOPE_PLACEHOLDER_SOURCE, limit))
        targets = [dict(r) for r in cur.fetchall()]
    return {"name": scope_name, "engagement_id": eid, "total": len(targets), "targets": targets}


class ScopeTargetsAdd(BaseModel):
    targets: list
    source: Optional[str] = "manual"


@app.post("/engagements/{eid}/scopes/{scope_name}/targets", tags=["Engagements"])
def add_engagement_scope_targets(eid: str, scope_name: str, body: ScopeTargetsAdd, _: bool = Depends(auth)):
    """Add targets to a scope under an engagement.

    - Empty `targets` list → creates the scope (sentinel placeholder row),
      enabling an "empty scope" to be visible in the UI.
    - Each target insert is wrapped in its own SAVEPOINT so a duplicate or
      validation error doesn't poison the whole batch.
    """
    added = 0
    skipped = 0
    errors: list[str] = []
    with get_db() as conn, conn.cursor() as cur:
        # Always ensure a placeholder row so the scope exists even with 0 targets
        try:
            cur.execute("SAVEPOINT sp_placeholder")
            cur.execute("""
                INSERT INTO scope_targets (engagement_id, name, target, target_type, source)
                VALUES (%s::uuid, %s, %s, 'domain', %s)
                ON CONFLICT (engagement_id, name, target) DO NOTHING
            """, (eid, scope_name, _SCOPE_PLACEHOLDER_TARGET, _SCOPE_PLACEHOLDER_SOURCE))
            cur.execute("RELEASE SAVEPOINT sp_placeholder")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT sp_placeholder")
            cur.execute("RELEASE SAVEPOINT sp_placeholder")
            errors.append(f"placeholder: {type(e).__name__}: {e}")

        for t in body.targets:
            if isinstance(t, dict):
                target_val = str(t.get("target", "")).strip()
                target_type = t.get("target_type") or _classify_target(target_val)
                source = t.get("source") or body.source
            else:
                target_val = str(t).strip()
                if not target_val:
                    continue
                target_type = _classify_target(target_val)
                source = body.source

            if not target_val:
                continue

            try:
                cur.execute("SAVEPOINT sp_t")
                cur.execute("""
                    INSERT INTO scope_targets (engagement_id, name, target, target_type, source)
                    VALUES (%s::uuid, %s, %s, %s, %s)
                    ON CONFLICT (engagement_id, name, target) DO NOTHING
                """, (eid, scope_name, target_val, target_type, source))
                if cur.rowcount > 0:
                    added += 1
                else:
                    skipped += 1
                cur.execute("RELEASE SAVEPOINT sp_t")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp_t")
                cur.execute("RELEASE SAVEPOINT sp_t")
                errors.append(f"{target_val}: {type(e).__name__}: {e}")
        conn.commit()

    resp = {"ok": True, "added": added, "skipped": skipped,
            "scope": scope_name, "engagement_id": eid}
    if errors:
        resp["errors"] = errors
    return resp


@app.delete("/engagements/{eid}/scopes/{scope_name}", tags=["Engagements"])
def delete_engagement_scope(eid: str, scope_name: str, _: bool = Depends(auth)):
    """Delete an entire scope and all its targets from an engagement."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM scope_targets WHERE engagement_id = %s::uuid AND name = %s",
            (eid, scope_name)
        )
        deleted = cur.rowcount
        conn.commit()
    return {"ok": True, "deleted": deleted, "scope": scope_name}


class ScopeRename(BaseModel):
    new_name: str


@app.put("/engagements/{eid}/scopes/{scope_name}", tags=["Engagements"])
def rename_engagement_scope(eid: str, scope_name: str, body: ScopeRename, _: bool = Depends(auth)):
    """Rename a scope under an engagement."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE scope_targets SET name = %s WHERE engagement_id = %s::uuid AND name = %s",
            (body.new_name, eid, scope_name)
        )
        updated = cur.rowcount
        conn.commit()
    return {"ok": True, "updated": updated, "old_name": scope_name, "new_name": body.new_name}


class ScopeMoveTargets(BaseModel):
    targets: List[str]
    to_engagement_id: str
    to_scope_name: str


@app.post("/engagements/{eid}/scopes/{scope_name}/move", tags=["Engagements"])
def move_scope_targets(eid: str, scope_name: str, body: ScopeMoveTargets, _: bool = Depends(auth)):
    """Move specific targets to a different scope/engagement."""
    moved = 0
    with get_db() as conn, conn.cursor() as cur:
        for target in body.targets:
            try:
                # Delete from source
                cur.execute(
                    "DELETE FROM scope_targets WHERE engagement_id = %s::uuid AND name = %s AND target = %s RETURNING id",
                    (eid, scope_name, target)
                )
                if cur.rowcount > 0:
                    # Insert into destination
                    cur.execute("""
                        INSERT INTO scope_targets (engagement_id, name, target, target_type, source)
                        VALUES (%s::uuid, %s, %s, 'domain', 'moved')
                        ON CONFLICT (engagement_id, name, target) DO NOTHING
                    """, (body.to_engagement_id, body.to_scope_name, target))
                    moved += 1
            except Exception:
                conn.rollback()
        conn.commit()
    return {"ok": True, "moved": moved, "from": f"{eid}/{scope_name}", "to": f"{body.to_engagement_id}/{body.to_scope_name}"}


class ScopeMoveAll(BaseModel):
    to_engagement_id: str


@app.post("/engagements/{eid}/scopes/{scope_name}/move-all", tags=["Engagements"])
def move_entire_scope(eid: str, scope_name: str, body: ScopeMoveAll, _: bool = Depends(auth)):
    """Move an entire scope (all targets) to a different engagement."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE scope_targets SET engagement_id = %s::uuid WHERE engagement_id = %s::uuid AND name = %s",
            (body.to_engagement_id, eid, scope_name)
        )
        moved = cur.rowcount
        conn.commit()
    return {"ok": True, "moved": moved, "scope": scope_name, "from_engagement": eid, "to_engagement": body.to_engagement_id}


# ============================================================================
# FINDING WORKFLOW (C1)
# ============================================================================

_WORKFLOW_TABLES = {"vuln": "vulns", "web": "web_findings", "playwright": "playwright_findings"}

class WorkflowUpdate(BaseModel):
    workflow_status: Optional[str] = None
    assigned_to: Optional[str] = None
    verified_by: Optional[str] = None
    tester_notes: Optional[str] = None
    original_severity: Optional[str] = None
    report_ready: Optional[bool] = None

@app.patch("/findings/{source}/{fid}/workflow", tags=["Findings"])
def update_finding_workflow(source: str, fid: str, body: WorkflowUpdate, _: bool = Depends(auth)):
    """Update workflow status for a finding."""
    table = _WORKFLOW_TABLES.get(source)
    if not table:
        raise HTTPException(400, f"Invalid source: {source}. Use: vuln, web, playwright")
    updates, vals = [], []
    if body.workflow_status is not None:
        updates.append("workflow_status = %s")
        vals.append(body.workflow_status)
    if body.assigned_to is not None:
        updates.append("assigned_to = %s")
        vals.append(body.assigned_to)
    if body.verified_by is not None:
        updates.append("verified_by = %s")
        vals.append(body.verified_by)
        updates.append("verified_at = now()")
    if body.tester_notes is not None:
        updates.append("tester_notes = %s")
        vals.append(body.tester_notes)
    if body.original_severity is not None:
        updates.append("original_severity = %s")
        vals.append(body.original_severity)
    if body.report_ready is not None:
        updates.append("report_ready = %s")
        vals.append(body.report_ready)
    if not updates:
        raise HTTPException(400, "No fields to update")
    vals.append(fid)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"UPDATE {table} SET {', '.join(updates)} WHERE id = %s RETURNING id", vals)
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(404, "Finding not found")
        # Auto-create activity records for status/severity changes
        if body.workflow_status is not None:
            cur.execute(
                """INSERT INTO finding_activity (finding_source, finding_id, activity_type, actor, new_value)
                   VALUES (%s, %s, 'status_change', %s, %s)""",
                (source, fid, body.verified_by or body.assigned_to, body.workflow_status))
        if body.original_severity is not None:
            cur.execute(
                """INSERT INTO finding_activity (finding_source, finding_id, activity_type, actor, new_value)
                   VALUES (%s, %s, 'severity_change', %s, %s)""",
                (source, fid, body.verified_by or body.assigned_to, body.original_severity))
        if body.assigned_to is not None:
            cur.execute(
                """INSERT INTO finding_activity (finding_source, finding_id, activity_type, new_value)
                   VALUES (%s, %s, 'assignment', %s)""",
                (source, fid, body.assigned_to))
        conn.commit()
    return {"ok": True, "id": fid}


# ============================================================================
# FINDING COMMENTS & ACTIVITY LOG (C2)
# ============================================================================

class CommentCreate(BaseModel):
    comment: str
    actor: Optional[str] = None

@app.post("/findings/{source}/{fid}/comments", tags=["Findings"])
def add_finding_comment(source: str, fid: str, body: CommentCreate, _: bool = Depends(auth)):
    """Add a comment to a finding."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO finding_activity (finding_source, finding_id, activity_type, actor, comment)
               VALUES (%s, %s, 'comment', %s, %s) RETURNING *""",
            (source, fid, body.actor, body.comment))
        row = cur.fetchone()
        conn.commit()
    return row

@app.get("/findings/{source}/{fid}/activity", tags=["Findings"])
def get_finding_activity(source: str, fid: str, _: bool = Depends(auth)):
    """Get activity log for a finding."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT * FROM finding_activity
               WHERE finding_source = %s AND finding_id = %s
               ORDER BY created_at DESC""",
            (source, fid))
        rows = cur.fetchall()
    return {"activity": rows}


# ============================================================================
# EXPLOIT MATCHING (J2)
# ============================================================================

@app.get("/findings/{source}/{fid}/exploit-matches", tags=["Findings"])
def get_finding_exploit_matches(source: str, fid: str, _: bool = Depends(auth)):
    """Find exploits matching a finding's CVE, title, and service info."""
    table = _WORKFLOW_TABLES.get(source)
    if not table:
        raise HTTPException(400, f"Invalid source: {source}. Use: vuln, web, playwright")
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get finding details
        if table == "vulns":
            cur.execute(
                """SELECT v.script as title, v.cve, v.severity, v.output,
                          p.port, p.service, p.product, p.version
                   FROM vulns v LEFT JOIN ports p ON p.id = v.port_id
                   WHERE v.id = %s""", (fid,))
        elif table == "web_findings":
            cur.execute(
                "SELECT name as title, url, severity, issue_type, cwe, description, evidence "
                "FROM web_findings WHERE id = %s", (fid,))
        else:
            cur.execute(
                "SELECT title, url, severity, finding_type as issue_type, cwe, description "
                "FROM playwright_findings WHERE id = %s", (fid,))
        finding = cur.fetchone()
        if not finding:
            raise HTTPException(404, "Finding not found")
    # Query exploit search
    params = {"top_k": 5, "min_confidence": 0.2}
    cves = finding.get("cve") or []
    if cves and len(cves) > 0:
        params["cve"] = cves[0]
    # For web findings, also check CWE array
    cwes = finding.get("cwe") or []
    if isinstance(cwes, list) and cwes:
        # CWE values like "CWE-79" — pass as search context
        cwe_str = cwes[0] if isinstance(cwes[0], str) else str(cwes[0])
        if cwe_str and not params.get("cve"):
            params["cve"] = cwe_str  # RAG search can match on CWE too
    if finding.get("service"):
        params["service"] = finding["service"]
    if finding.get("version"):
        params["version"] = finding["version"]
    # Build richer query for web findings: include issue_type and description
    query_parts = []
    if finding.get("title"):
        query_parts.append(finding["title"])
    if finding.get("issue_type") and finding["issue_type"] not in ("zap-alert", "scan_execution", "scan-note"):
        query_parts.append(finding["issue_type"])
    if finding.get("description"):
        query_parts.append(finding["description"][:200])
    if query_parts:
        params["query"] = " ".join(query_parts)[:500]
    if finding.get("port"):
        params["port"] = finding["port"]
    try:
        resp = requests.get(f"{SCAN_RECOMMENDER_URL}/rag/search/enhanced", params=params, verify=False, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("exploitdb", [])[:5] + data.get("metasploit", [])[:5]
            return {"matches": matches, "finding": finding}
    except Exception:
        pass
    return {"matches": [], "finding": finding}


# ── Web PoC Generation + Queueing ─────────────────────────────────────────

class GeneratePocsRequest(BaseModel):
    max_payloads: int = Field(5, description="Maximum payloads to return")
    use_llm: bool = Field(True, description="Augment templates with LLM-generated payloads")


@app.post("/findings/{source}/{fid}/generate-pocs", tags=["Findings"])
def generate_pocs_for_finding(
    source: str, fid: str, body: GeneratePocsRequest = None,
    _: bool = Depends(auth),
):
    """
    Generate PoC payloads for a web finding using templates + LLM.

    Calls the exploit-runner's web_payload_generator to produce a list of
    targeted payloads the user can review and select.
    """
    if body is None:
        body = GeneratePocsRequest()

    table = _WORKFLOW_TABLES.get(source)
    if not table:
        raise HTTPException(400, f"Invalid source: {source}")

    # Fetch finding details
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if table == "web_findings":
            cur.execute(
                "SELECT id, name, url, issue_type, severity, evidence, method, payload, parameter "
                "FROM web_findings WHERE id = %s", (fid,))
        elif table == "playwright_findings":
            cur.execute(
                "SELECT id, title as name, url, finding_type as issue_type, severity, "
                "description as evidence, location as parameter "
                "FROM playwright_findings WHERE id = %s", (fid,))
        else:
            raise HTTPException(400, "PoC generation only supports web/playwright findings")
        finding = cur.fetchone()
        if not finding:
            raise HTTPException(404, "Finding not found")

    # Call exploit-runner payload generation endpoint
    try:
        resp = requests.post(
            f"{EXPLOIT_RUNNER_URL}/generate-payloads",
            json={
                "issue_type": finding.get("issue_type", ""),
                "url": finding.get("url", ""),
                "parameter": finding.get("parameter", ""),
                "evidence": finding.get("evidence", ""),
                "name": finding.get("name", ""),
                "max_payloads": body.max_payloads,
                "use_llm": body.use_llm,
            },
            timeout=120,
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        payloads = resp.json().get("payloads", [])
    except requests.exceptions.ConnectionError:
        # Fallback: return empty if exploit-runner not reachable
        payloads = []
    except requests.exceptions.Timeout:
        payloads = []

    return {"payloads": payloads, "finding": dict(finding)}


class QueuePocRequest(BaseModel):
    payloads: List[Dict[str, Any]] = Field(..., description="Selected payloads to queue")


@app.post("/findings/{source}/{fid}/queue-poc", tags=["Findings"])
def queue_poc_for_finding(
    source: str, fid: str, body: QueuePocRequest,
    _: bool = Depends(auth),
):
    """
    Queue selected PoC payloads as pending_exploits for approval.

    Each selected payload creates one pending_exploit with
    exploit_category='webapp' and the payload details in metadata.
    """
    table = _WORKFLOW_TABLES.get(source)
    if not table:
        raise HTTPException(400, f"Invalid source: {source}")

    # Fetch finding for context
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if table == "web_findings":
            cur.execute(
                "SELECT id, name, url, issue_type, severity, asset_id "
                "FROM web_findings WHERE id = %s", (fid,))
        elif table == "playwright_findings":
            cur.execute(
                "SELECT id, title as name, url, finding_type as issue_type, severity, asset_id "
                "FROM playwright_findings WHERE id = %s", (fid,))
        else:
            raise HTTPException(400, "PoC queueing only supports web/playwright findings")
        finding = cur.fetchone()
        if not finding:
            raise HTTPException(404, "Finding not found")

        # Determine target IP from asset
        target_ip = "0.0.0.0"
        if finding.get("asset_id"):
            cur.execute("SELECT host(ip)::text as ip FROM assets WHERE id = %s", (finding["asset_id"],))
            asset_row = cur.fetchone()
            if asset_row:
                target_ip = asset_row["ip"]

        # Extract port from URL if possible
        from urllib.parse import urlparse
        parsed_url = urlparse(finding.get("url", ""))
        target_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

        # Map issue_type to exploit_type
        issue_type = (finding.get("issue_type") or "").lower()
        type_map = {
            "xss": "xss", "sqli": "sqli", "sql-injection": "sqli",
            "command-injection": "command_injection", "ssrf": "ssrf",
            "lfi": "lfi", "path-traversal": "lfi", "xxe": "xxe",
            "csrf": "csrf", "open-redirect": "open_redirect",
        }
        exploit_type = type_map.get(issue_type, "other")

        queued_ids = []
        for payload_item in body.payloads:
            pending_id = str(uuid.uuid4())
            metadata = {
                "payload": payload_item.get("payload", ""),
                "injection_point": payload_item.get("injection_point", "query_param"),
                "parameter": payload_item.get("target_parameter", ""),
                "success_indicator": payload_item.get("success_indicator", "response_content"),
                "target_url": finding.get("url", ""),
                "finding_id": str(fid),
                "finding_source": source,
                "confidence": payload_item.get("confidence", 0.5),
                "auto_triggered": False,
            }

            cur.execute("""
                INSERT INTO pending_exploits
                (id, source, exploit_id, exploit_title, exploit_type, exploit_category,
                 target_ip, target_port, target_service,
                 customized_command, parameters, match_confidence,
                 match_reasoning, status, requested_by, metadata)
                VALUES (%s, 'web_poc', %s, %s, %s, 'webapp',
                        %s::inet, %s, %s,
                        %s, %s, %s,
                        %s, 'pending', 'user', %s)
            """, (
                pending_id,
                f"poc-{fid[:8]}",
                payload_item.get("description", finding.get("name", "Web PoC")),
                exploit_type,
                target_ip,
                target_port,
                issue_type,
                payload_item.get("payload", "")[:500],
                Json({}),
                payload_item.get("confidence", 0.5),
                payload_item.get("description", "User-selected web PoC payload"),
                Json(metadata),
            ))
            queued_ids.append(pending_id)

        conn.commit()

    return {"queued": queued_ids, "count": len(queued_ids)}


# ============================================================================
# EVIDENCE STORE (B1)
# ============================================================================

@app.post("/evidence/upload", tags=["Evidence"])
def upload_evidence(
    file: UploadFile = File(...),
    title: str = Query(...),
    evidence_type: str = Query("file"),
    engagement_id: Optional[str] = Query(None),
    description: Optional[str] = Query(None),
    uploaded_by: Optional[str] = Query(None),
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    _: bool = Depends(auth),
):
    """Upload evidence file (screenshot, request/response, terminal output, etc.)."""
    import hashlib
    content = file.file.read()
    content_hash = hashlib.sha256(content).hexdigest()
    file_size = len(content)
    content_type = file.content_type or "application/octet-stream"
    tag_list = [t.strip() for t in tags.split(",")] if tags else []
    thumbnail = None
    # Generate thumbnail for images
    if content_type.startswith("image/"):
        try:
            from PIL import Image
            import io
            img = Image.open(io.BytesIO(content))
            img.thumbnail((200, 200))
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            thumbnail = buf.getvalue()
        except Exception:
            pass
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO evidence_store (engagement_id, evidence_type, title, description,
                content_type, content, thumbnail, file_size, content_hash, tags, uploaded_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id, title, evidence_type,
                content_type, file_size, content_hash, tags, uploaded_by, created_at""",
            (engagement_id, evidence_type, title, description, content_type,
             psycopg2.Binary(content), psycopg2.Binary(thumbnail) if thumbnail else None,
             file_size, content_hash, tag_list, uploaded_by))
        row = cur.fetchone()
        conn.commit()
    return row

@app.get("/evidence", tags=["Evidence"])
def list_evidence(
    engagement_id: Optional[str] = Query(None),
    evidence_type: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """List evidence, filterable by engagement, type, tags."""
    clauses, params = [], []
    if engagement_id:
        clauses.append("engagement_id = %s")
        params.append(engagement_id)
    if evidence_type:
        clauses.append("evidence_type = %s")
        params.append(evidence_type)
    if tags:
        clauses.append("tags && %s")
        params.append([t.strip() for t in tags.split(",")])
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"""SELECT id, engagement_id, evidence_type, title, description, content_type,
                file_size, content_hash, tags, uploaded_by, created_at
                FROM evidence_store {where} ORDER BY created_at DESC""", params)
        rows = cur.fetchall()
    return {"evidence": rows}

@app.get("/evidence/{eid}", tags=["Evidence"])
def get_evidence_meta(eid: str, _: bool = Depends(auth)):
    """Get evidence metadata."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT id, engagement_id, evidence_type, title, description, content_type,
                file_size, content_hash, tags, uploaded_by, metadata, created_at
                FROM evidence_store WHERE id = %s""", (eid,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Evidence not found")
    return row

@app.get("/evidence/{eid}/content", tags=["Evidence"])
def get_evidence_content(eid: str, _: bool = Depends(auth)):
    """Stream raw evidence file bytes."""
    from fastapi.responses import StreamingResponse
    import io
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT content, content_type FROM evidence_store WHERE id = %s", (eid,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Evidence not found")
    return StreamingResponse(io.BytesIO(bytes(row[0])), media_type=row[1])

@app.get("/evidence/{eid}/thumbnail", tags=["Evidence"])
def get_evidence_thumbnail(eid: str, _: bool = Depends(auth)):
    """Get evidence thumbnail (for images)."""
    from fastapi.responses import StreamingResponse
    import io
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT thumbnail FROM evidence_store WHERE id = %s", (eid,))
        row = cur.fetchone()
    if not row or not row[0]:
        raise HTTPException(404, "No thumbnail available")
    return StreamingResponse(io.BytesIO(bytes(row[0])), media_type="image/png")

@app.post("/evidence/{eid}/link", tags=["Evidence"])
def link_evidence(eid: str, entity_type: str = Query(...), entity_id: str = Query(...), _: bool = Depends(auth)):
    """Link evidence to a finding, asset, or other entity."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO evidence_links (evidence_id, entity_type, entity_id)
               VALUES (%s, %s, %s) ON CONFLICT DO NOTHING RETURNING *""",
            (eid, entity_type, entity_id))
        row = cur.fetchone()
        conn.commit()
    return row or {"ok": True, "message": "Link already exists"}

@app.get("/findings/{source}/{fid}/evidence", tags=["Evidence"])
def get_finding_evidence(source: str, fid: str, _: bool = Depends(auth)):
    """Get all evidence linked to a finding."""
    entity_type_map = {"vuln": "finding", "web": "web_finding", "playwright": "playwright_finding"}
    et = entity_type_map.get(source, source)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT es.id, es.evidence_type, es.title, es.description, es.content_type,
                es.file_size, es.tags, es.uploaded_by, es.created_at
               FROM evidence_store es
               JOIN evidence_links el ON el.evidence_id = es.id
               WHERE el.entity_type = %s AND el.entity_id = %s
               ORDER BY es.created_at DESC""",
            (et, fid))
        rows = cur.fetchall()
    return {"evidence": rows}

@app.delete("/evidence/{eid}", tags=["Evidence"])
def delete_evidence(eid: str, _: bool = Depends(auth)):
    """Delete evidence."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM evidence_store WHERE id = %s", (eid,))
        deleted = cur.rowcount
        conn.commit()
    if deleted == 0:
        raise HTTPException(404, "Evidence not found")
    return {"ok": True}


# ============================================================================
# SCOPE INTELLIGENCE (E1)
# ============================================================================

@app.get("/scope/{scope_name}/intelligence", tags=["Scope"])
def scope_intelligence(scope_name: str, _: bool = Depends(auth)):
    """Unified scope intelligence view — aggregates all recon data for scope targets."""
    from collections import defaultdict

    empty = {
        "scope_name": scope_name,
        "stats": {"total_findings": 0, "first_seen": None, "last_seen": None, "by_source": {}},
        "domains": [], "subdomains": [], "dns_records": {},
        "http_services": [], "tls_certs": [], "ct_certs": [],
        "ip_addresses": [], "technologies": [], "open_services": {},
    }

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get scope targets — case-insensitive match.
        cur.execute("SELECT target, target_type FROM scope_targets WHERE LOWER(name) = LOWER(%s)", (scope_name,))
        scope_targets = cur.fetchall()
        if not scope_targets:
            return empty

        # Build LIKE patterns for all scope targets
        # For URL targets, extract hostname so recon findings (which store bare
        # hostnames) are matched.  Keep the full URL pattern too for findings
        # that do store the full URL (e.g. httpx, whatweb).
        from urllib.parse import urlparse as _urlparse
        like_set: set = set()
        for r in scope_targets:
            target = r["target"]
            like_set.add(f"%{target}%")
            if target.startswith(("http://", "https://")):
                try:
                    host = _urlparse(target).hostname
                    if host:
                        like_set.add(f"%{host}%")
                except Exception:
                    pass
        like_patterns = list(like_set)
        like_sql = " OR ".join(["rf.target ILIKE %s"] * len(like_patterns))

        # 1. Subdomains
        cur.execute(f"""
            SELECT DISTINCT ON (rf.target) rf.target, host(a.ip)::text as resolved_ip, rf.created_at
            FROM recon_findings rf
            LEFT JOIN assets a ON a.id = rf.asset_id
            WHERE ({like_sql})
              AND (rf.finding_type = 'subdomain' OR rf.source = 'subfinder')
            ORDER BY rf.target, rf.created_at
            LIMIT 500
        """, like_patterns)
        subdomains = []
        for r in cur.fetchall():
            subdomains.append({
                "name": r["target"] or "",
                "resolved_ip": r["resolved_ip"] or "",
                "first_seen": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 2. DNS records grouped by type
        cur.execute(f"""
            SELECT rf.target, rf.finding_type, rf.data
            FROM recon_findings rf
            WHERE ({like_sql}) AND rf.finding_type LIKE 'dns_%%'
            ORDER BY rf.finding_type, rf.target
            LIMIT 500
        """, like_patterns)
        dns_records: dict = {}
        for r in cur.fetchall():
            ft = r["finding_type"] or "dns_other"
            if ft not in dns_records:
                dns_records[ft] = []
            data = r["data"] if isinstance(r["data"], dict) else {}
            dns_records[ft].append({
                "target": r["target"] or "",
                "values": data.get(ft.replace("dns_", ""), data.get("a", [])),
                "data": data,
            })

        # 3. HTTP services
        cur.execute(f"""
            SELECT rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE ({like_sql})
              AND (rf.finding_type = 'web_service' OR rf.source = 'httpx')
            ORDER BY rf.created_at DESC
            LIMIT 200
        """, like_patterns)
        http_services = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            http_services.append({
                "url": data.get("url", r["target"] or ""),
                "status_code": data.get("status_code", ""),
                "title": data.get("title", ""),
                "webserver": data.get("webserver", ""),
                "tech": data.get("tech", []),
                "content_length": data.get("content_length", ""),
                "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 4. TLS certs
        cur.execute(f"""
            SELECT rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE ({like_sql})
              AND (rf.finding_type = 'tls_cert' OR rf.source = 'tlsx')
            ORDER BY rf.created_at DESC
            LIMIT 100
        """, like_patterns)
        tls_certs = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            tls_certs.append({
                "host": data.get("host", r["target"] or ""),
                "subject_cn": data.get("subject_cn", ""),
                "issuer": data.get("issuer_org", data.get("issuer", "")),
                "not_after": data.get("not_after", ""),
                "not_before": data.get("not_before", ""),
                "serial": data.get("serial", ""),
            })

        # 5. CT log certs
        cur.execute(f"""
            SELECT rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE ({like_sql})
              AND (rf.finding_type = 'ct_cert' OR rf.source = 'crtsh')
            ORDER BY rf.created_at DESC
            LIMIT 100
        """, like_patterns)
        ct_certs = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            ct_certs.append({
                "common_name": data.get("common_name", r["target"] or ""),
                "issuer_name": data.get("issuer_name", ""),
                "not_after": data.get("not_after", ""),
                "serial": data.get("serial_number", data.get("serial", "")),
            })

        # 6. ASN mappings — collect resolved IPs, then find matching ASN entries
        resolved_ips = set()
        for s in subdomains:
            if s.get("resolved_ip"):
                resolved_ips.add(s["resolved_ip"])
        for entries in dns_records.values():
            for e in entries:
                vals = e.get("values", [])
                if isinstance(vals, list):
                    for v in vals:
                        if isinstance(v, str) and v.count(".") == 3:
                            resolved_ips.add(v)

        asn_mappings = []
        if resolved_ips:
            ip_list = list(resolved_ips)[:500]
            cur.execute("""
                SELECT rf.target, rf.data, rf.created_at
                FROM recon_findings rf
                WHERE (rf.finding_type = 'asn_mapping' OR rf.source = 'asnmap')
                  AND rf.target = ANY(%s)
                ORDER BY rf.created_at DESC
                LIMIT 200
            """, [ip_list])
            for r in cur.fetchall():
                data = r["data"] if isinstance(r["data"], dict) else {}
                asn_mappings.append({
                    "ip": data.get("input", r["target"] or ""),
                    "asn": data.get("as_number", data.get("asn", "")),
                    "org": data.get("as_name", data.get("org", "")),
                    "country": data.get("as_country", data.get("country", "")),
                    "cidr": data.get("as_range", data.get("cidr", "")),
                })

        # 7. WHOIS records
        cur.execute(f"""
            SELECT rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE ({like_sql})
              AND (rf.finding_type = 'whois_record' OR rf.source = 'whois')
            ORDER BY rf.created_at DESC
            LIMIT 50
        """, like_patterns)
        whois_records = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            whois_records.append({
                "domain": data.get("domain", r["target"] or ""),
                "registrar": data.get("registrar", ""),
                "org": data.get("org", ""),
                "creation_date": data.get("creation_date", ""),
                "expiry_date": data.get("expiry_date", ""),
                "name_servers": data.get("name_servers", []),
                "registrant_name": data.get("registrant_name", ""),
                "registrant_email": data.get("registrant_email", ""),
                "registrant_country": data.get("registrant_country", ""),
                "dnssec": data.get("dnssec", ""),
                "status": data.get("status", []),
                "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 8. WAF detections
        cur.execute(f"""
            SELECT rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE ({like_sql})
              AND (rf.finding_type = 'waf_detection' OR rf.source = 'wafw00f')
            ORDER BY rf.created_at DESC
            LIMIT 100
        """, like_patterns)
        waf_detections = []
        for r in cur.fetchall():
            data = r["data"] if isinstance(r["data"], dict) else {}
            waf_detections.append({
                "url": data.get("url", r["target"] or ""),
                "detected": data.get("detected", False),
                "firewall": data.get("firewall", ""),
                "manufacturer": data.get("manufacturer", ""),
                "created_at": r["created_at"].isoformat() if r.get("created_at") else "",
            })

        # 8. Stats
        cur.execute(f"""
            SELECT COUNT(*) as total,
                   MIN(rf.created_at) as first_seen,
                   MAX(rf.created_at) as last_seen
            FROM recon_findings rf WHERE ({like_sql})
        """, like_patterns)
        stats_row = cur.fetchone()

        cur.execute(f"""
            SELECT rf.source, COUNT(*) as cnt
            FROM recon_findings rf WHERE ({like_sql})
            GROUP BY rf.source ORDER BY cnt DESC
        """, like_patterns)
        by_source = {r["source"]: r["cnt"] for r in cur.fetchall()}

        # 9. Extract parent domains from scope targets only
        #    (don't include domains from subdomains found via LIKE — that causes scope leakage)
        domains = set()
        scope_root_domains = set()
        for t in scope_targets:
            target = t["target"]
            if t["target_type"] == "domain":
                domains.add(target)
                # Extract root domain for subdomain filtering
                parts = target.rstrip(".").split(".")
                if len(parts) >= 2:
                    root = ".".join(parts[-2:])
                    if len(parts) > 2 and parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
                        root = ".".join(parts[-3:]) if len(parts) > 2 else root
                    scope_root_domains.add(root)
            elif t["target_type"] == "url":
                try:
                    host = _urlparse(target).hostname
                    if host:
                        domains.add(host)
                        parts = host.rstrip(".").split(".")
                        if len(parts) >= 2:
                            scope_root_domains.add(".".join(parts[-2:]))
                except Exception:
                    pass
            elif t["target_type"] == "ip":
                pass  # IPs don't have a domain
        # Add root domains from scope targets
        domains.update(scope_root_domains)

        # 8. IP addresses from assets
        like_asset_sql = " OR ".join(["(a.hostname ILIKE %s OR host(a.ip)::text ILIKE %s)"] * len(like_patterns))
        asset_params = []
        for p in like_patterns:
            asset_params.extend([p, p])
        cur.execute(f"""
            SELECT DISTINCT host(a.ip)::text as ip FROM assets a
            WHERE a.ip IS NOT NULL AND ({like_asset_sql})
        """, asset_params)
        ip_addresses = [r["ip"] for r in cur.fetchall()]

        # 9. Technologies from httpx/whatweb data
        techs: dict = {}
        for svc in http_services:
            for t in (svc.get("tech") or []):
                if t:
                    techs[t] = techs.get(t, 0) + 1

        # 10. Open services from ports
        open_services: dict = {}
        if ip_addresses:
            cur.execute("""
                SELECT p.service, COUNT(*) as cnt FROM ports p
                JOIN assets a ON a.id = p.asset_id
                WHERE p.service IS NOT NULL AND host(a.ip)::text = ANY(%s)
                GROUP BY p.service ORDER BY cnt DESC
            """, (ip_addresses,))
            for r in cur.fetchall():
                open_services[r["service"]] = r["cnt"]

    return {
        "scope_name": scope_name,
        "stats": {
            "total_findings": stats_row["total"] if stats_row else 0,
            "first_seen": stats_row["first_seen"].isoformat() if stats_row and stats_row["first_seen"] else None,
            "last_seen": stats_row["last_seen"].isoformat() if stats_row and stats_row["last_seen"] else None,
            "by_source": by_source,
        },
        "domains": sorted(domains),
        "subdomains": subdomains,
        "dns_records": dns_records,
        "http_services": http_services,
        "tls_certs": tls_certs,
        "ct_certs": ct_certs,
        "asn_mappings": asn_mappings,
        "whois_records": whois_records,
        "waf_detections": waf_detections,
        "ip_addresses": ip_addresses,
        "technologies": [{"name": k, "count": v} for k, v in sorted(techs.items(), key=lambda x: -x[1])],
        "open_services": open_services,
    }


# ============================================================================
# SCOPE ANALYSIS — Red Team Recon Intelligence
# ============================================================================

_INTERESTING_PORTS = {
    21: "FTP — file transfer, often misconfigured",
    22: "SSH — remote access, brute-force target",
    23: "Telnet — cleartext remote access",
    25: "SMTP — email relay, user enumeration",
    53: "DNS — zone transfer, cache poisoning",
    110: "POP3 — cleartext email",
    135: "MSRPC — Windows RPC, lateral movement",
    139: "NetBIOS — SMB legacy, enumeration",
    389: "LDAP — directory services, user enumeration",
    443: "HTTPS — web application testing",
    445: "SMB — file shares, lateral movement",
    1433: "MSSQL — database, credential testing",
    1521: "Oracle DB — database, credential testing",
    2049: "NFS — network file shares",
    3306: "MySQL — database, credential testing",
    3389: "RDP — remote desktop, brute-force target",
    5432: "PostgreSQL — database, credential testing",
    5900: "VNC — remote desktop, weak auth",
    5985: "WinRM — remote management, lateral movement",
    6379: "Redis — in-memory store, often unauthenticated",
    8080: "HTTP-alt — secondary web service",
    8443: "HTTPS-alt — secondary web service",
    9200: "Elasticsearch — often unauthenticated",
    27017: "MongoDB — often unauthenticated",
}

_ADMIN_TITLE_PATTERNS = [
    "admin", "login", "dashboard", "panel", "console", "manager",
    "swagger", "api doc", "graphql", "jenkins", "grafana", "kibana",
    "phpmyadmin", "webmin", "portainer", "tomcat", "jmx", "actuator",
    "debug", "config", "setup", "install", "wp-admin", "wp-login",
]

_CDN_ASN_ORGS = [
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
    "sucuri", "stackpath", "limelight", "edgecast", "imperva",
]

_SENSITIVE_PARAM_NAMES = [
    "token", "key", "secret", "password", "passwd", "pass", "auth",
    "api_key", "apikey", "access_token", "session", "jwt", "debug",
    "admin", "redirect", "url", "callback", "next", "return",
]


@app.get("/scope/{scope_name}/analysis", tags=["Scope"])
def scope_analysis(scope_name: str, _: bool = Depends(auth)):
    """Red team recon analysis — identifies targets, gaps, and next steps for low-and-slow engagement."""
    from urllib.parse import urlparse as _urlparse
    import re

    empty = {
        "scope_name": scope_name,
        "prioritized_targets": [], "suggested_next_steps": [],
        "interesting_services": [], "sensitive_pages": [],
        "login_pages": [], "out_of_scope_candidates": [],
        "technology_index": {},
    }

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # ── Scope targets + LIKE patterns (reuse from intelligence) ──
        cur.execute("SELECT target, target_type FROM scope_targets WHERE LOWER(name) = LOWER(%s)", (scope_name,))
        scope_targets = cur.fetchall()
        if not scope_targets:
            return empty

        like_set: set = set()
        scope_ips: set = set()
        scope_domains: set = set()
        for r in scope_targets:
            target = r["target"]
            like_set.add(f"%{target}%")
            if r["target_type"] == "ip":
                scope_ips.add(target)
            elif r["target_type"] == "domain":
                scope_domains.add(target)
            if target.startswith(("http://", "https://")):
                try:
                    host = _urlparse(target).hostname
                    if host:
                        like_set.add(f"%{host}%")
                        scope_domains.add(host)
                except Exception:
                    pass
        like_patterns = list(like_set)
        if not like_patterns:
            return empty
        like_sql = " OR ".join(["rf.target ILIKE %s"] * len(like_patterns))

        # ── Get already-excluded targets ──
        cur.execute("SELECT target FROM scope_targets WHERE name = 'not_in_scope'")
        excluded = {r["target"] for r in cur.fetchall()}

        # ── 1. HTTP services from recon_findings ──
        cur.execute(f"""
            SELECT rf.target, rf.data, rf.created_at
            FROM recon_findings rf
            WHERE ({like_sql})
              AND (rf.finding_type = 'web_service' OR rf.source = 'httpx')
            ORDER BY rf.created_at DESC LIMIT 300
        """, like_patterns)
        http_services_raw = cur.fetchall()

        # ── 2. Ports + assets for scope IPs ──
        asset_like_sql = " OR ".join(["(a.hostname ILIKE %s OR host(a.ip)::text ILIKE %s)"] * len(like_patterns))
        asset_params = []
        for p in like_patterns:
            asset_params.extend([p, p])
        cur.execute(f"""
            SELECT host(a.ip)::text as ip, a.hostname, p.port, p.proto, p.service, p.product, p.version, p.banner
            FROM ports p
            JOIN assets a ON a.id = p.asset_id
            WHERE ({asset_like_sql})
            ORDER BY p.port
        """, asset_params)
        ports_raw = cur.fetchall()

        # ── 3. Vulns in scope ──
        cur.execute(f"""
            SELECT v.script, v.output, v.severity, v.cve, v.cvss, host(a.ip)::text as ip, p.port, p.service
            FROM vulns v
            JOIN ports p ON p.id = v.port_id
            JOIN assets a ON a.id = p.asset_id
            WHERE ({" OR ".join(["host(a.ip)::text ILIKE %s"] * len(like_patterns))})
            ORDER BY v.cvss DESC NULLS LAST, v.severity
            LIMIT 100
        """, like_patterns)
        vulns_raw = cur.fetchall()

        # ── 4. Credential findings in scope ──
        cur.execute(f"""
            SELECT cf.ip, cf.port, cf.protocol, cf.username, cf.status
            FROM credential_findings cf
            WHERE ({" OR ".join(["host(cf.ip)::text ILIKE %s"] * len(like_patterns))})
            ORDER BY cf.status, cf.discovered_at DESC
            LIMIT 50
        """, like_patterns)
        creds_raw = cur.fetchall()

        # ── 5. Content extractions in scope ──
        cur.execute(f"""
            SELECT ce.url, ce.login_pages, ce.api_endpoints, ce.exposed_keys,
                   ce.internal_paths, ce.emails, ce.comments, ce.tech_indicators
            FROM content_extractions ce
            WHERE ({" OR ".join(["ce.url ILIKE %s"] * len(like_patterns))})
            LIMIT 200
        """, like_patterns)
        content_raw = cur.fetchall()

        # ── 6. Playwright findings in scope ──
        cur.execute(f"""
            SELECT pf.url, pf.finding_type, pf.title, pf.description, pf.evidence,
                   pf.dom_element, pf.severity
            FROM playwright_findings pf
            WHERE ({" OR ".join(["pf.url ILIKE %s"] * len(like_patterns))})
            LIMIT 100
        """, like_patterns)
        playwright_raw = cur.fetchall()

        # ── 7. DOM analysis in scope ──
        cur.execute(f"""
            SELECT da.url, da.forms, da.cookies, da.javascript_libs,
                   da.security_headers, da.cors_enabled, da.external_scripts
            FROM dom_analysis da
            WHERE ({" OR ".join(["da.url ILIKE %s"] * len(like_patterns))})
            LIMIT 200
        """, like_patterns)
        dom_raw = cur.fetchall()

        # ── 8. Discovered params in scope ──
        cur.execute(f"""
            SELECT dp.url_pattern, dp.param_name, dp.method, dp.location,
                   dp.sample_values, dp.occurrence_count
            FROM discovered_params dp
            WHERE ({" OR ".join(["dp.url_pattern ILIKE %s"] * len(like_patterns))})
            ORDER BY dp.occurrence_count DESC
            LIMIT 200
        """, like_patterns)
        params_raw = cur.fetchall()

        # ── 9. ASN mappings ──
        cur.execute(f"""
            SELECT rf.target, rf.data FROM recon_findings rf
            WHERE ({like_sql})
              AND (rf.finding_type = 'asn_mapping' OR rf.source = 'asnmap')
            LIMIT 200
        """, like_patterns)
        asn_raw = cur.fetchall()

        # ── 10. WHOIS for org detection ──
        cur.execute(f"""
            SELECT rf.target, rf.data FROM recon_findings rf
            WHERE ({like_sql})
              AND (rf.finding_type = 'whois_record' OR rf.source = 'whois')
            LIMIT 20
        """, like_patterns)
        whois_raw = cur.fetchall()

    # =========================================================================
    # ANALYSIS COMPUTATION (all in-memory from here)
    # =========================================================================

    prioritized_targets = []
    suggested_next_steps = []
    interesting_services = []
    sensitive_pages = []
    login_pages = []
    out_of_scope_candidates = []
    technology_index: dict = {}  # tech_name → {urls, ips, subdomains}

    # -- Build technology index from HTTP services --
    for r in http_services_raw:
        data = r["data"] if isinstance(r["data"], dict) else {}
        url = data.get("url", r["target"] or "")
        techs = data.get("tech", [])
        # Extract IP from URL if possible
        ip = ""
        try:
            host = _urlparse(url).hostname or ""
            if host and host[0].isdigit():
                ip = host
        except Exception:
            pass
        for t in (techs or []):
            if not t:
                continue
            if t not in technology_index:
                technology_index[t] = {"urls": [], "ips": [], "subdomains": []}
            if url and url not in technology_index[t]["urls"]:
                technology_index[t]["urls"].append(url)
            if ip and ip not in technology_index[t]["ips"]:
                technology_index[t]["ips"].append(ip)

    # Add DOM javascript_libs to tech index
    for r in dom_raw:
        libs = r.get("javascript_libs") or []
        url = r.get("url", "")
        for lib in (libs if isinstance(libs, list) else []):
            lib_name = lib if isinstance(lib, str) else str(lib)
            if not lib_name:
                continue
            if lib_name not in technology_index:
                technology_index[lib_name] = {"urls": [], "ips": [], "subdomains": []}
            if url and url not in technology_index[lib_name]["urls"]:
                technology_index[lib_name]["urls"].append(url)

    # -- Prioritized targets from vulns --
    seen_targets = set()
    for v in vulns_raw:
        sev = (v.get("severity") or "").lower()
        cvss = v.get("cvss") or 0
        if sev in ("critical", "high") or (cvss and float(cvss) >= 7.0):
            target_key = f"{v['ip']}:{v['port']}"
            if target_key not in seen_targets:
                seen_targets.add(target_key)
                cves = v.get("cve") or []
                reasons = [f"Vulnerability: {v['script']} ({sev})"]
                if cves:
                    reasons.append(f"CVE: {', '.join(cves[:3])}")
                prioritized_targets.append({
                    "target": target_key,
                    "ip": v["ip"], "port": v["port"],
                    "service": v.get("service", ""),
                    "reasons": reasons,
                    "priority": "high" if sev == "critical" or (cvss and float(cvss) >= 9.0) else "medium",
                    "category": "vuln",
                    "tech": [],
                })

    # -- Prioritized targets from valid credentials --
    for c in creds_raw:
        if (c.get("status") or "").lower() == "valid":
            target_key = f"{c['ip']}:{c['port']}"
            if target_key not in seen_targets:
                seen_targets.add(target_key)
                prioritized_targets.append({
                    "target": target_key,
                    "ip": c["ip"], "port": c["port"],
                    "service": c.get("protocol", ""),
                    "reasons": [f"Valid credentials found ({c.get('protocol', 'unknown')})"],
                    "priority": "high",
                    "category": "credential",
                    "tech": [],
                })

    # -- Prioritized targets from HTTP services with interesting titles --
    for r in http_services_raw:
        data = r["data"] if isinstance(r["data"], dict) else {}
        url = data.get("url", r["target"] or "")
        title = (data.get("title") or "").lower()
        techs = data.get("tech", [])
        for pattern in _ADMIN_TITLE_PATTERNS:
            if pattern in title:
                if url not in seen_targets:
                    seen_targets.add(url)
                    cat = "login" if pattern in ("login", "wp-login") else \
                          "admin" if pattern in ("admin", "panel", "console", "manager", "wp-admin", "phpmyadmin", "webmin", "portainer") else \
                          "api" if pattern in ("swagger", "api doc", "graphql", "actuator") else "exposed_service"
                    prioritized_targets.append({
                        "target": url,
                        "ip": None, "port": None,
                        "service": data.get("webserver", ""),
                        "reasons": [f"Page title contains '{pattern}'", f"Title: {data.get('title', '')}"],
                        "priority": "high" if cat in ("admin", "credential") else "medium",
                        "category": cat,
                        "tech": techs or [],
                    })
                break

    # -- Interesting services from ports --
    for p in ports_raw:
        port_num = p.get("port") or 0
        svc = p.get("service") or ""
        product = p.get("product") or ""
        version = p.get("version") or ""
        banner = p.get("banner") or ""
        host = p.get("ip") or p.get("hostname") or ""

        interest_reason = ""
        if port_num in _INTERESTING_PORTS:
            interest_reason = _INTERESTING_PORTS[port_num]
        elif port_num > 1024 and svc in ("http", "https"):
            interest_reason = f"Non-standard HTTP on port {port_num}"
        elif any(kw in banner.lower() for kw in ("debug", "test", "dev", "staging")):
            interest_reason = f"Debug/test indicator in banner"
        elif version and any(c.isdigit() for c in version):
            interest_reason = f"Version detected: {product} {version} — check for CVEs"

        if interest_reason:
            interesting_services.append({
                "host": host, "port": port_num, "service": svc,
                "product": product or None, "version": version or None,
                "banner": (banner[:120] + "...") if len(banner) > 120 else (banner or None),
                "interest_reason": interest_reason,
                "tech": [],
            })

    # -- Sensitive pages from content_extractions --
    for ce in content_raw:
        url = ce.get("url", "")
        techs_for_url = []
        for t, idx in technology_index.items():
            if url in idx.get("urls", []):
                techs_for_url.append(t)

        # Login pages
        lp_data = ce.get("login_pages")
        if lp_data and (isinstance(lp_data, list) and len(lp_data) > 0 or isinstance(lp_data, str) and lp_data.strip()):
            items = lp_data if isinstance(lp_data, list) else [lp_data]
            for item in items[:5]:
                page_url = item.get("url", url) if isinstance(item, dict) else url
                fields = item.get("fields", []) if isinstance(item, dict) else []
                login_pages.append({
                    "url": page_url,
                    "form_action": item.get("action") if isinstance(item, dict) else None,
                    "fields": fields if isinstance(fields, list) else [],
                    "has_csrf": False,
                    "source": "content_extraction",
                    "tech": techs_for_url,
                })

        # API endpoints
        api_eps = ce.get("api_endpoints")
        if api_eps and isinstance(api_eps, list):
            for ep in api_eps[:10]:
                ep_url = ep if isinstance(ep, str) else (ep.get("url", "") if isinstance(ep, dict) else str(ep))
                if ep_url:
                    sensitive_pages.append({
                        "url": ep_url, "page_type": "api_doc",
                        "evidence": f"API endpoint discovered on {url}",
                        "source": "content_extraction", "tech": techs_for_url,
                    })

        # Exposed keys
        keys = ce.get("exposed_keys")
        if keys and isinstance(keys, list):
            for key in keys[:5]:
                key_str = key if isinstance(key, str) else (key.get("key", str(key)) if isinstance(key, dict) else str(key))
                sensitive_pages.append({
                    "url": url, "page_type": "exposed_key",
                    "evidence": f"Exposed key/secret: {key_str[:80]}",
                    "source": "content_extraction", "tech": techs_for_url,
                })

        # Internal paths
        paths = ce.get("internal_paths")
        if paths and isinstance(paths, list):
            for path in paths[:10]:
                path_str = path if isinstance(path, str) else str(path)
                sensitive_pages.append({
                    "url": url, "page_type": "internal_path",
                    "evidence": f"Internal path: {path_str}",
                    "source": "content_extraction", "tech": techs_for_url,
                })

    # -- Login pages from playwright findings --
    for pf in playwright_raw:
        ft = (pf.get("finding_type") or "").lower()
        if ft in ("credentials", "auth_bypass", "login_form"):
            login_pages.append({
                "url": pf.get("url", ""),
                "form_action": None,
                "fields": [],
                "has_csrf": False,
                "source": f"playwright ({ft})",
                "tech": [],
            })

    # -- Login pages from DOM analysis (forms with password fields) --
    for da in dom_raw:
        forms = da.get("forms")
        if not forms or not isinstance(forms, list):
            continue
        for form in forms:
            if not isinstance(form, dict):
                continue
            fields = form.get("fields", form.get("inputs", []))
            if not isinstance(fields, list):
                continue
            field_types = [f.get("type", "").lower() if isinstance(f, dict) else "" for f in fields]
            if "password" in field_types:
                field_names = [f.get("name", f.get("id", "")) if isinstance(f, dict) else "" for f in fields]
                has_csrf = any("csrf" in (n or "").lower() or "token" in (n or "").lower() for n in field_names)
                login_pages.append({
                    "url": da.get("url", ""),
                    "form_action": form.get("action"),
                    "fields": [n for n in field_names if n],
                    "has_csrf": has_csrf,
                    "source": "dom_analysis",
                    "tech": [],
                })

    # -- Sensitive params --
    for dp in params_raw:
        param_name = (dp.get("param_name") or "").lower()
        if any(s in param_name for s in _SENSITIVE_PARAM_NAMES):
            sensitive_pages.append({
                "url": dp.get("url_pattern", ""),
                "page_type": "sensitive_param",
                "evidence": f"Parameter '{dp['param_name']}' ({dp.get('method','?')} {dp.get('location','?')})",
                "source": "discovered_params",
                "tech": [],
            })

    # -- Out-of-scope candidates from ASN mismatch --
    primary_orgs: set = set()
    for w in whois_raw:
        data = w["data"] if isinstance(w["data"], dict) else {}
        org = (data.get("org") or data.get("registrant_name") or "").lower().strip()
        if org:
            primary_orgs.add(org)

    for a in asn_raw:
        data = a["data"] if isinstance(a["data"], dict) else {}
        asn_org = (data.get("as_name") or data.get("org") or "").lower().strip()
        target_ip = data.get("input", a["target"] or "")

        if target_ip in excluded:
            continue

        # CDN detection
        if any(cdn in asn_org for cdn in _CDN_ASN_ORGS):
            out_of_scope_candidates.append({
                "target": target_ip,
                "reason": f"CDN IP ({asn_org}) — may be shared infrastructure",
            })
        # Org mismatch
        elif primary_orgs and asn_org and not any(
            org in asn_org or asn_org in org for org in primary_orgs
        ):
            out_of_scope_candidates.append({
                "target": target_ip,
                "reason": f"ASN org '{asn_org}' differs from WHOIS registrant",
            })

    # -- Suggested next steps (gap analysis) --
    http_urls = {(r["data"] if isinstance(r["data"], dict) else {}).get("url", r["target"] or "")
                 for r in http_services_raw}
    playwright_urls = {pf.get("url", "") for pf in playwright_raw}
    content_urls = {ce.get("url", "") for ce in content_raw}
    cred_ips = {c.get("ip", "") for c in creds_raw}
    login_urls = {lp["url"] for lp in login_pages}

    # HTTP services not yet crawled by Playwright
    uncrawled = http_urls - playwright_urls - content_urls
    if uncrawled:
        sample = list(uncrawled)[:3]
        suggested_next_steps.append({
            "scan_type": "playwright_crawl",
            "target": ", ".join(sample) + (f" (+{len(uncrawled) - 3} more)" if len(uncrawled) > 3 else ""),
            "rationale": f"{len(uncrawled)} HTTP service(s) not yet crawled — discover login forms, API endpoints, exposed secrets, and JS-rendered content",
            "stealth_level": "passive",
            "tool": "Playwright",
        })

    # Login pages with no credential testing
    login_hosts_untested = set()
    for lp in login_pages:
        try:
            host = _urlparse(lp["url"]).hostname or ""
            if host and host not in cred_ips:
                login_hosts_untested.add(host)
        except Exception:
            pass
    if login_hosts_untested:
        suggested_next_steps.append({
            "scan_type": "credential_test",
            "target": ", ".join(list(login_hosts_untested)[:3]),
            "rationale": f"{len(login_hosts_untested)} host(s) with login pages but no credential testing — try default/common creds",
            "stealth_level": "low",
            "tool": "Brutus / Hydra",
        })

    # Hosts with no vuln scanning
    scanned_vuln_ips = {v.get("ip", "") for v in vulns_raw}
    port_ips = {p.get("ip", "") for p in ports_raw}
    unscanned = port_ips - scanned_vuln_ips
    if unscanned:
        suggested_next_steps.append({
            "scan_type": "nuclei_targeted",
            "target": ", ".join(list(unscanned)[:3]) + (f" (+{len(unscanned) - 3} more)" if len(unscanned) > 3 else ""),
            "rationale": f"{len(unscanned)} host(s) with open ports but no vulnerability scan results — run targeted Nuclei templates",
            "stealth_level": "low",
            "tool": "Nuclei",
        })

    # Discovered params not fuzzed
    if params_raw:
        sensitive_params = [dp for dp in params_raw if any(s in (dp.get("param_name") or "").lower() for s in _SENSITIVE_PARAM_NAMES)]
        if sensitive_params:
            suggested_next_steps.append({
                "scan_type": "parameter_fuzz",
                "target": ", ".join(set(dp.get("url_pattern", "") for dp in sensitive_params[:3])),
                "rationale": f"{len(sensitive_params)} sensitive parameter(s) discovered (token, key, auth, etc.) — fuzz for injection/bypass",
                "stealth_level": "medium",
                "tool": "ffuf / Burp Intruder",
            })

    # HTTP services with no content extraction
    no_content = http_urls - content_urls
    if no_content and len(no_content) > 3:
        suggested_next_steps.append({
            "scan_type": "content_discovery",
            "target": ", ".join(list(no_content)[:3]),
            "rationale": f"{len(no_content)} URL(s) with no directory/content discovery — find hidden paths, backups, configs",
            "stealth_level": "low",
            "tool": "ffuf / Katana",
        })

    # If we have interesting services but no deep scan
    db_services = [s for s in interesting_services if any(kw in (s.get("service") or "") for kw in ("mysql", "postgres", "mssql", "oracle", "redis", "mongo"))]
    if db_services:
        suggested_next_steps.append({
            "scan_type": "database_enum",
            "target": ", ".join(f"{s['host']}:{s['port']}" for s in db_services[:3]),
            "rationale": f"{len(db_services)} database service(s) exposed — enumerate databases, test default credentials",
            "stealth_level": "low",
            "tool": "NetExec / Nmap scripts",
        })

    # Deduplicate login pages by URL
    seen_login_urls: set = set()
    deduped_logins = []
    for lp in login_pages:
        if lp["url"] not in seen_login_urls:
            seen_login_urls.add(lp["url"])
            deduped_logins.append(lp)
    login_pages = deduped_logins

    return {
        "scope_name": scope_name,
        "prioritized_targets": prioritized_targets[:50],
        "suggested_next_steps": suggested_next_steps,
        "interesting_services": interesting_services[:50],
        "sensitive_pages": sensitive_pages[:50],
        "login_pages": login_pages[:30],
        "out_of_scope_candidates": out_of_scope_candidates[:30],
        "technology_index": technology_index,
    }


# ============================================================================
# CAMPAIGN EVENTS / KILL CHAIN (H1)
# ============================================================================

class CampaignEventCreate(BaseModel):
    kill_chain_phase: str
    title: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    description: Optional[str] = None
    target_asset_id: Optional[str] = None
    exploit_result_id: Optional[str] = None
    node_id: Optional[str] = None
    timestamp: Optional[str] = None
    detected: bool = False
    detection_time: Optional[str] = None
    operator: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class CampaignEventUpdate(BaseModel):
    kill_chain_phase: Optional[str] = None
    title: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    description: Optional[str] = None
    detected: Optional[bool] = None
    detection_time: Optional[str] = None
    operator: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@app.post("/engagements/{eid}/campaign-events", tags=["Campaign"])
def create_campaign_event(eid: str, body: CampaignEventCreate, _: bool = Depends(auth)):
    """Create a campaign event in the kill chain."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO campaign_events (engagement_id, kill_chain_phase, title, mitre_tactic,
                mitre_technique, description, target_asset_id, exploit_result_id, node_id,
                timestamp, detected, detection_time, operator, metadata)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,COALESCE(%s::timestamptz, now()),%s,%s,%s,%s) RETURNING *""",
            (eid, body.kill_chain_phase, body.title, body.mitre_tactic, body.mitre_technique,
             body.description, body.target_asset_id, body.exploit_result_id, body.node_id,
             body.timestamp, body.detected, body.detection_time, body.operator,
             Json(body.metadata or {})))
        row = cur.fetchone()
        conn.commit()
    return row

@app.get("/engagements/{eid}/campaign-events", tags=["Campaign"])
def list_campaign_events(
    eid: str,
    kill_chain_phase: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """List campaign events for an engagement."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if kill_chain_phase:
            cur.execute(
                """SELECT * FROM campaign_events WHERE engagement_id = %s AND kill_chain_phase = %s
                   ORDER BY timestamp ASC""", (eid, kill_chain_phase))
        else:
            cur.execute(
                "SELECT * FROM campaign_events WHERE engagement_id = %s ORDER BY timestamp ASC", (eid,))
        rows = cur.fetchall()
    return {"events": rows}

@app.put("/campaign-events/{event_id}", tags=["Campaign"])
def update_campaign_event(event_id: str, body: CampaignEventUpdate, _: bool = Depends(auth)):
    """Update a campaign event."""
    updates, vals = [], []
    for field in ["kill_chain_phase","title","mitre_tactic","mitre_technique","description",
                  "detected","detection_time","operator"]:
        v = getattr(body, field, None)
        if v is not None:
            updates.append(f"{field} = %s")
            vals.append(v)
    if body.metadata is not None:
        updates.append("metadata = %s")
        vals.append(Json(body.metadata))
    if not updates:
        raise HTTPException(400, "No fields to update")
    vals.append(event_id)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"UPDATE campaign_events SET {', '.join(updates)} WHERE id = %s RETURNING *", vals)
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Campaign event not found")
    return row

@app.delete("/campaign-events/{event_id}", tags=["Campaign"])
def delete_campaign_event(event_id: str, _: bool = Depends(auth)):
    """Delete a campaign event."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM campaign_events WHERE id = %s", (event_id,))
        deleted = cur.rowcount
        conn.commit()
    if deleted == 0:
        raise HTTPException(404, "Campaign event not found")
    return {"ok": True}

@app.get("/engagements/{eid}/campaign-summary", tags=["Campaign"])
def campaign_summary(eid: str, _: bool = Depends(auth)):
    """Kill chain coverage stats and MITRE technique usage."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT kill_chain_phase, COUNT(*) as cnt, SUM(CASE WHEN detected THEN 1 ELSE 0 END) as detected_count
               FROM campaign_events WHERE engagement_id = %s GROUP BY kill_chain_phase""", (eid,))
        phases = {r["kill_chain_phase"]: {"count": r["cnt"], "detected": r["detected_count"]} for r in cur.fetchall()}
        cur.execute(
            """SELECT mitre_technique, mitre_tactic, COUNT(*) as cnt
               FROM campaign_events WHERE engagement_id = %s AND mitre_technique IS NOT NULL
               GROUP BY mitre_technique, mitre_tactic""", (eid,))
        techniques = cur.fetchall()
    return {"phases": phases, "techniques": techniques}


# ============================================================================
# CREDENTIAL VAULT (H2)
# ============================================================================

class CredentialCreate(BaseModel):
    username: str
    domain: Optional[str] = None
    credential_type: str
    credential_value: Optional[str] = None
    cracked_value: Optional[str] = None
    source: str
    source_entity_id: Optional[str] = None
    status: str = "active"
    access_level: Optional[str] = None
    grants_access_to: Optional[List[str]] = None
    notes: Optional[str] = None
    engagement_id: Optional[str] = None
    expires_at: Optional[str] = None
    cloud_metadata: Optional[Dict[str, Any]] = None
    permissions_summary: Optional[str] = None

class CredentialUpdate(BaseModel):
    status: Optional[str] = None
    cracked_value: Optional[str] = None
    access_level: Optional[str] = None
    notes: Optional[str] = None
    grants_access_to: Optional[List[str]] = None
    expires_at: Optional[str] = None
    cloud_metadata: Optional[Dict[str, Any]] = None
    permissions_summary: Optional[str] = None

@app.post("/credential-vault", tags=["Credentials"])
def create_credential_vault(body: CredentialCreate, _: bool = Depends(auth)):
    """Add a credential to the vault."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO credential_vault (engagement_id, username, domain, credential_type,
                credential_value, cracked_value, source, source_entity_id, status,
                access_level, grants_access_to, notes, expires_at, cloud_metadata, permissions_summary)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (body.engagement_id, body.username, body.domain, body.credential_type,
             body.credential_value, body.cracked_value, body.source, body.source_entity_id,
             body.status, body.access_level, body.grants_access_to, body.notes,
             body.expires_at, Json(body.cloud_metadata) if body.cloud_metadata else None,
             body.permissions_summary))
        row = cur.fetchone()
        conn.commit()
    return row

@app.get("/credential-vault", tags=["Credentials"])
def list_credentials_vault(
    engagement_id: Optional[str] = Query(None),
    credential_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """List credentials, filterable by engagement, type, status, domain."""
    clauses, params = [], []
    if engagement_id:
        clauses.append("engagement_id = %s")
        params.append(engagement_id)
    if credential_type:
        clauses.append("credential_type = %s")
        params.append(credential_type)
    if status:
        clauses.append("status = %s")
        params.append(status)
    if domain:
        clauses.append("domain ILIKE %s")
        params.append(f"%{domain}%")
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT * FROM credential_vault {where} ORDER BY created_at DESC", params)
        rows = cur.fetchall()
    return {"credentials": rows}

@app.patch("/credential-vault/{cid}", tags=["Credentials"])
def update_credential_vault(cid: str, body: CredentialUpdate, _: bool = Depends(auth)):
    """Update a credential."""
    updates, vals = [], []
    if body.status is not None:
        updates.append("status = %s")
        vals.append(body.status)
    if body.cracked_value is not None:
        updates.append("cracked_value = %s")
        vals.append(body.cracked_value)
    if body.access_level is not None:
        updates.append("access_level = %s")
        vals.append(body.access_level)
    if body.notes is not None:
        updates.append("notes = %s")
        vals.append(body.notes)
    if body.grants_access_to is not None:
        updates.append("grants_access_to = %s")
        vals.append(body.grants_access_to)
    if body.expires_at is not None:
        updates.append("expires_at = %s")
        vals.append(body.expires_at)
    if body.cloud_metadata is not None:
        updates.append("cloud_metadata = %s")
        vals.append(Json(body.cloud_metadata))
    if body.permissions_summary is not None:
        updates.append("permissions_summary = %s")
        vals.append(body.permissions_summary)
    if not updates:
        raise HTTPException(400, "No fields to update")
    vals.append(cid)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"UPDATE credential_vault SET {', '.join(updates)} WHERE id = %s RETURNING *", vals)
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Credential not found")
    return row

@app.get("/credential-vault/expiring", tags=["Credentials"])
def credentials_expiring(
    minutes: int = Query(30, description="Minutes until expiry threshold"),
    _: bool = Depends(auth),
):
    """List credentials expiring within N minutes."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT * FROM credential_vault
               WHERE expires_at IS NOT NULL
                 AND expires_at <= now() + interval '1 minute' * %s
                 AND status NOT IN ('revoked','expired')
               ORDER BY expires_at ASC""",
            (minutes,))
        rows = cur.fetchall()
    return {"credentials": rows, "threshold_minutes": minutes}

@app.patch("/credential-vault/{cid}/refresh-expiry", tags=["Credentials"])
def refresh_credential_expiry(cid: str, body: dict, _: bool = Depends(auth)):
    """Update expiry timestamp when a cloud token is refreshed."""
    new_expiry = body.get("expires_at")
    if not new_expiry:
        raise HTTPException(400, "expires_at required")
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "UPDATE credential_vault SET expires_at = %s WHERE id = %s RETURNING *",
            (new_expiry, cid))
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Credential not found")
    return row

@app.get("/credential-vault/cloud-summary", tags=["Credentials"])
def credential_cloud_summary(_: bool = Depends(auth)):
    """Grouped credential summary by cloud account/tenant."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                credential_type,
                cloud_metadata->>'account_id' as account_id,
                cloud_metadata->>'tenant_id' as tenant_id,
                count(*) as count,
                count(*) FILTER (WHERE status = 'active') as active_count,
                count(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at < now()) as expired_count
            FROM credential_vault
            WHERE credential_type IN ('aws_access_key','aws_sts','azure_oauth','azure_sp','gcp_sa_key')
            GROUP BY credential_type, cloud_metadata->>'account_id', cloud_metadata->>'tenant_id'
            ORDER BY count DESC
        """)
        rows = cur.fetchall()
    return {"summary": rows}

# ── Credential Access Map CRUD ──

class AccessMapCreate(BaseModel):
    credential_id: str
    resource_type: str
    resource_id: str
    access_level: Optional[str] = None
    verified: bool = False
    source: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@app.post("/credential-access-map", tags=["Credentials"])
def create_access_map(body: AccessMapCreate, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO credential_access_map
                (credential_id, resource_type, resource_id, access_level, verified, source, metadata)
               VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (body.credential_id, body.resource_type, body.resource_id,
             body.access_level, body.verified, body.source,
             Json(body.metadata) if body.metadata else None))
        row = cur.fetchone()
        conn.commit()
    return row

@app.get("/credential-access-map/{credential_id}", tags=["Credentials"])
def list_access_map(credential_id: str, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM credential_access_map WHERE credential_id = %s ORDER BY created_at DESC",
            (credential_id,))
        rows = cur.fetchall()
    return {"access_map": rows}

@app.delete("/credential-access-map/{map_id}", tags=["Credentials"])
def delete_access_map(map_id: str, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM credential_access_map WHERE id = %s", (map_id,))
        deleted = cur.rowcount
        conn.commit()
    if deleted == 0:
        raise HTTPException(404, "Access map entry not found")
    return {"ok": True}

@app.delete("/credential-vault/{cid}", tags=["Credentials"])
def delete_credential_vault(cid: str, _: bool = Depends(auth)):
    """Delete a credential from the vault."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM credential_vault WHERE id = %s", (cid,))
        deleted = cur.rowcount
        conn.commit()
    if deleted == 0:
        raise HTTPException(404, "Credential not found")
    return {"ok": True}


# ============================================================================
# OPSEC DASHBOARD (I1)
# ============================================================================

@app.get("/opsec/timeline", tags=["OpSec"])
def opsec_timeline(
    hours: int = Query(24, description="How many hours to look back"),
    _: bool = Depends(auth),
):
    """Scan activity timeline bucketed by hour from audit log and DB tables."""
    import pathlib
    buckets = {}
    source_ips = {}
    recent_scans = []  # Detailed scan activity log

    # 1. Parse scan_audit/audit.jsonl
    audit_path = pathlib.Path("/scan_audit/audit.jsonl")
    if audit_path.exists():
        cutoff = datetime.now(timezone.utc).timestamp() - hours * 3600
        for line in audit_path.read_text().strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                ts = entry.get("timestamp") or entry.get("ts")
                if ts:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    else:
                        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                    if dt.timestamp() >= cutoff:
                        hour_key = dt.strftime("%Y-%m-%d %H:00")
                        buckets[hour_key] = buckets.get(hour_key, 0) + 1
                        src = entry.get("source_ip") or entry.get("external_ip") or entry.get("node") or "local"
                        source_ips[src] = source_ips.get(src, 0) + 1
                        # Build detailed scan entry
                        targets = entry.get("targets") or []
                        if isinstance(targets, list):
                            targets = targets[:5]
                        target_url = entry.get("target_url") or entry.get("target") or ""
                        recent_scans.append({
                            "timestamp": ts if isinstance(ts, str) else dt.isoformat(),
                            "event": entry.get("event", "unknown"),
                            "scan_type": entry.get("scan_type", "unknown"),
                            "source_ip": src,
                            "hostname": entry.get("hostname", ""),
                            "job_id": entry.get("job_id", ""),
                            "targets": targets,
                            "target_url": target_url,
                            "execution_mode": entry.get("execution_mode", "local"),
                            "node_id": entry.get("node_id"),
                            "error": entry.get("error"),
                            "duration_s": entry.get("duration_s"),
                        })
            except Exception:
                continue

    # 2. Query all scan-related DB tables for activity
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # tool_executions (detailed) — fix stale 'running' status inline
        try:
            cur.execute(
                """SELECT id::text, tool, target,
                          CASE
                            WHEN status = 'running' AND completed_at IS NOT NULL THEN 'completed'
                            WHEN status = 'running' AND started_at < now() - interval '2 hours' THEN 'lost'
                            ELSE status
                          END as status,
                          started_at, completed_at,
                          EXTRACT(EPOCH FROM (coalesce(completed_at, now()) - started_at)) as duration_s
                   FROM tool_executions WHERE started_at > now() - interval '%s hours'
                   ORDER BY started_at DESC LIMIT 200""", (hours,))
            for r in cur.fetchall():
                hour_key = r["started_at"].strftime("%Y-%m-%d %H:00")
                buckets[hour_key] = buckets.get(hour_key, 0) + 1
                recent_scans.append({
                    "timestamp": r["started_at"].isoformat(),
                    "event": f"tool_{r['status']}",
                    "scan_type": r["tool"],
                    "source_ip": "local",
                    "target_url": r["target"],
                    "job_id": r["id"],
                    "execution_mode": "local",
                    "duration_s": round(r["duration_s"], 1) if r["duration_s"] else None,
                })
        except Exception:
            pass

        # jobs table (detailed)
        try:
            cur.execute(
                """SELECT id::text, type, status, params, created_at,
                          coalesce(started_at, created_at) as started_at,
                          finished_at
                   FROM jobs WHERE coalesce(started_at, created_at) > now() - interval '%s hours'
                   ORDER BY created_at DESC LIMIT 200""", (hours,))
            for r in cur.fetchall():
                hour_key = r["started_at"].strftime("%Y-%m-%d %H:00")
                buckets[hour_key] = buckets.get(hour_key, 0) + 1
                params = r.get("params") or {}
                target = ""
                if isinstance(params, dict):
                    target = params.get("target") or params.get("target_url") or ""
                    if isinstance(params.get("targets"), list):
                        target = ", ".join(str(t) for t in params["targets"][:3])
                recent_scans.append({
                    "timestamp": r["started_at"].isoformat(),
                    "event": f"job_{r['status']}",
                    "scan_type": r["type"],
                    "source_ip": "local",
                    "target_url": target,
                    "job_id": r["id"],
                    "execution_mode": "local",
                })
        except Exception:
            pass

        # playwright_scans (detailed)
        try:
            cur.execute(
                """SELECT id::text, url, status, start_time, end_time
                   FROM playwright_scans
                   WHERE coalesce(start_time, created_at) > now() - interval '%s hours'
                   ORDER BY created_at DESC LIMIT 100""", (hours,))
            for r in cur.fetchall():
                st = r.get("start_time") or r.get("created_at")
                if st:
                    hour_key = st.strftime("%Y-%m-%d %H:00")
                    buckets[hour_key] = buckets.get(hour_key, 0) + 1
                recent_scans.append({
                    "timestamp": st.isoformat() if st else "",
                    "event": f"playwright_{r['status']}",
                    "scan_type": "playwright",
                    "source_ip": "local",
                    "target_url": r["url"],
                    "job_id": r["id"],
                    "execution_mode": "local",
                })
        except Exception:
            pass

    # Merge events by job_id into single rows with started_at / ended_at
    jobs_map: dict = {}  # job_id -> merged row
    for s in recent_scans:
        jid = s.get("job_id", "")
        if not jid:
            continue
        event = s.get("event", "")
        ts = s.get("timestamp", "")

        if jid not in jobs_map:
            jobs_map[jid] = {
                "job_id": jid,
                "scan_type": s.get("scan_type", "unknown"),
                "source_ip": s.get("source_ip", "local"),
                "hostname": s.get("hostname", ""),
                "target_url": s.get("target_url", ""),
                "targets": s.get("targets", []),
                "execution_mode": s.get("execution_mode", "local"),
                "node_id": s.get("node_id"),
                "started_at": None,
                "ended_at": None,
                "status": "unknown",
                "error": None,
                "duration_s": s.get("duration_s"),
            }

        row = jobs_map[jid]
        # Fill in best target if missing
        if not row["target_url"] and s.get("target_url"):
            row["target_url"] = s["target_url"]
        if not row["targets"] and s.get("targets"):
            row["targets"] = s["targets"]
        if s.get("source_ip") and s["source_ip"] != "local" and row["source_ip"] == "local":
            row["source_ip"] = s["source_ip"]
        if s.get("hostname") and not row["hostname"]:
            row["hostname"] = s["hostname"]

        # Determine start/end from event type
        if "started" in event or "running" in event or "queued" in event:
            if not row["started_at"] or ts < row["started_at"]:
                row["started_at"] = ts
        if "completed" in event or "finished" in event or "failed" in event or "stopped" in event:
            if not row["ended_at"] or ts > row["ended_at"]:
                row["ended_at"] = ts
            if "failed" in event:
                row["status"] = "failed"
                row["error"] = s.get("error")
            elif "completed" in event or "finished" in event:
                row["status"] = "completed"
            elif "stopped" in event:
                row["status"] = "stopped"

        # Use explicit duration if available
        if s.get("duration_s") and not row["duration_s"]:
            row["duration_s"] = s["duration_s"]

    # Infer status and duration for rows that only have partial data
    from datetime import datetime as _dt, timezone as _tz
    _now = _dt.now(_tz.utc)
    for row in jobs_map.values():
        if row["status"] == "unknown":
            if row["ended_at"]:
                row["status"] = "completed"
            elif row["started_at"]:
                # If started > 2 hours ago with no completion → lost
                try:
                    from dateutil.parser import isoparse as _iso
                    started = _iso(row["started_at"])
                    if started.tzinfo is None:
                        started = started.replace(tzinfo=_tz.utc)
                    if (_now - started).total_seconds() > 7200:
                        row["status"] = "lost"
                    else:
                        row["status"] = "running"
                except Exception:
                    row["status"] = "running"
            else:
                row["status"] = "queued"
        # Calculate duration from timestamps if not set
        if not row["duration_s"] and row["started_at"] and row["ended_at"]:
            try:
                from dateutil.parser import isoparse
                start = isoparse(row["started_at"])
                end = isoparse(row["ended_at"])
                row["duration_s"] = round((end - start).total_seconds(), 1)
            except Exception:
                pass

    merged = sorted(jobs_map.values(),
                    key=lambda x: x.get("started_at") or x.get("ended_at") or "",
                    reverse=True)[:200]

    return {
        "buckets": [{"hour": k, "count": v} for k, v in sorted(buckets.items())],
        "source_ips": [{"source": k, "count": v} for k, v in sorted(source_ips.items(), key=lambda x: -x[1])],
        "recent_scans": merged,
    }

@app.get("/opsec/alerts", tags=["OpSec"])
def opsec_alerts(
    threshold: int = Query(20, description="Scans per hour that triggers alert"),
    _: bool = Depends(auth),
):
    """Check for rate spikes and suspicious scanning patterns."""
    timeline = opsec_timeline(hours=24, _=True)
    alerts = []
    for bucket in timeline["buckets"]:
        if bucket["count"] > threshold:
            alerts.append({
                "type": "rate_spike",
                "message": f"High scan rate: {bucket['count']} scans at {bucket['hour']}",
                "hour": bucket["hour"],
                "count": bucket["count"],
            })
    # Check for overlapping scans across all scan tables
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # jobs table (type column, status: running/queued)
        try:
            cur.execute(
                """SELECT type, COUNT(*) as cnt FROM jobs
                   WHERE status IN ('running','queued')
                     AND created_at > now() - interval '24 hours'
                   GROUP BY type HAVING COUNT(*) > 1""")
            for r in cur.fetchall():
                alerts.append({
                    "type": "overlapping_scans",
                    "message": f"{r['cnt']} concurrent {r['type']} jobs running/queued",
                    "scan_type": r["type"],
                    "count": r["cnt"],
                })
        except Exception:
            pass

        # playwright_scans (status: running/queued)
        try:
            cur.execute(
                """SELECT COUNT(*) as cnt FROM playwright_scans
                   WHERE status IN ('running','queued')""")
            r = cur.fetchone()
            if r and r["cnt"] > 1:
                alerts.append({
                    "type": "overlapping_scans",
                    "message": f"{r['cnt']} concurrent Playwright scans running/queued",
                    "scan_type": "playwright",
                    "count": r["cnt"],
                })
        except Exception:
            pass

        # tool_executions (status: running/pending, last 24h only to exclude stale)
        try:
            cur.execute(
                """SELECT tool, COUNT(*) as cnt FROM tool_executions
                   WHERE status IN ('running','pending')
                     AND started_at > now() - interval '24 hours'
                   GROUP BY tool HAVING COUNT(*) > 2""")
            for r in cur.fetchall():
                alerts.append({
                    "type": "overlapping_scans",
                    "message": f"{r['cnt']} concurrent {r['tool']} executions running",
                    "scan_type": r["tool"],
                    "count": r["cnt"],
                })
        except Exception:
            pass

    return {"alerts": alerts, "threshold": threshold}


# ============================================================================
# SCHEDULED SCANS (I2)
# ============================================================================

class ScheduledScanCreate(BaseModel):
    scan_type: str
    targets: Dict[str, Any]
    parameters: Optional[Dict[str, Any]] = None
    scheduled_at: str
    jitter_seconds: int = 0
    max_rate: Optional[int] = None
    engagement_id: Optional[str] = None

@app.post("/scheduled-scans", tags=["Scheduling"])
def create_scheduled_scan(body: ScheduledScanCreate, _: bool = Depends(auth)):
    """Create a scheduled scan."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO scheduled_scans (engagement_id, scan_type, targets, parameters,
                scheduled_at, jitter_seconds, max_rate)
               VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (body.engagement_id, body.scan_type, Json(body.targets), Json(body.parameters or {}),
             body.scheduled_at, body.jitter_seconds, body.max_rate))
        row = cur.fetchone()
        conn.commit()
    return row

@app.get("/scheduled-scans", tags=["Scheduling"])
def list_scheduled_scans(
    status: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """List scheduled scans."""
    if status:
        q = "SELECT * FROM scheduled_scans WHERE status = %s ORDER BY scheduled_at ASC"
        p = (status,)
    else:
        q = "SELECT * FROM scheduled_scans ORDER BY scheduled_at ASC"
        p = ()
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(q, p)
        rows = cur.fetchall()
    return {"scheduled_scans": rows}

@app.delete("/scheduled-scans/{sid}", tags=["Scheduling"])
def cancel_scheduled_scan(sid: str, _: bool = Depends(auth)):
    """Cancel a scheduled scan."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "UPDATE scheduled_scans SET status = 'cancelled' WHERE id = %s AND status = 'scheduled' RETURNING id",
            (sid,))
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Scheduled scan not found or already executed")
    return {"ok": True, "id": sid}


# ============================================================================
# TIER 8: Finding Tags + Screenshot Metadata
# ============================================================================

_TAG_COLUMNS = {"vuln": ("vulns", "tags"), "web": ("web_findings", "user_tags"), "playwright": ("playwright_findings", "tags")}

PREDEFINED_TAGS = ["login", "admin", "api", "interesting", "follow-up", "credential", "sensitive", "default-install", "misconfigured"]

class TagUpdate(BaseModel):
    tags: List[str]
    action: str = "set"  # set | add | remove

@app.patch("/findings/{source}/{fid}/tags", tags=["Findings"])
def update_finding_tags(source: str, fid: str, body: TagUpdate, _: bool = Depends(auth)):
    """Set, add, or remove tags on a finding."""
    entry = _TAG_COLUMNS.get(source)
    if not entry:
        raise HTTPException(400, f"Invalid source: {source}. Use: vuln, web, playwright")
    table, col = entry
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if body.action == "set":
            cur.execute(f"UPDATE {table} SET {col} = %s WHERE id = %s RETURNING id", (body.tags, fid))
        elif body.action == "add":
            cur.execute(
                f"UPDATE {table} SET {col} = array_cat(COALESCE({col}, ARRAY[]::text[]), %s) WHERE id = %s RETURNING id",
                (body.tags, fid))
        elif body.action == "remove":
            cur.execute(
                f"UPDATE {table} SET {col} = array(SELECT unnest(COALESCE({col}, ARRAY[]::text[])) EXCEPT SELECT unnest(%s::text[])) WHERE id = %s RETURNING id",
                (body.tags, fid))
        else:
            raise HTTPException(400, "action must be set, add, or remove")
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Finding not found")
        # Log to activity
        cur.execute(
            "INSERT INTO finding_activity (finding_source, finding_id, activity_type, new_value) VALUES (%s, %s, 'comment', %s)",
            (source, fid, f"Tags {body.action}: {', '.join(body.tags)}"))
        conn.commit()
        # Fetch updated tags
        cur.execute(f"SELECT {col} as tags FROM {table} WHERE id = %s", (fid,))
        updated = cur.fetchone()
    return {"ok": True, "tags": updated["tags"] if updated else []}


@app.get("/tags/suggestions", tags=["Findings"])
def get_tag_suggestions(_: bool = Depends(auth)):
    """Return predefined tags + all distinct tags in use."""
    all_tags = set(PREDEFINED_TAGS)
    with get_db() as conn, conn.cursor() as cur:
        for table, col in [("vulns", "tags"), ("web_findings", "user_tags"), ("playwright_findings", "tags"), ("recon_findings", "tags"), ("screenshot_metadata", "tags")]:
            try:
                cur.execute(f"SELECT DISTINCT unnest({col}) as tag FROM {table}")
                for row in cur.fetchall():
                    if row[0]:
                        all_tags.add(row[0])
            except Exception:
                conn.rollback()
    return {"tags": sorted(all_tags), "predefined": PREDEFINED_TAGS}


class ScreenshotMetadataBody(BaseModel):
    path: str
    filename: str
    directory: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    added_to_scope: Optional[str] = None

@app.get("/screenshots/metadata", tags=["Screenshots"])
def get_screenshot_metadata(
    path: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """Get screenshot metadata, optionally filtered by path or tag."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if path:
            cur.execute("SELECT * FROM screenshot_metadata WHERE path = %s", (path,))
            row = cur.fetchone()
            return {"metadata": row}
        elif tag:
            cur.execute("SELECT * FROM screenshot_metadata WHERE tags @> ARRAY[%s] ORDER BY updated_at DESC", (tag,))
            return {"metadata": cur.fetchall()}
        else:
            cur.execute("SELECT * FROM screenshot_metadata ORDER BY updated_at DESC LIMIT 500")
            return {"metadata": cur.fetchall()}


@app.patch("/screenshots/metadata", tags=["Screenshots"])
def upsert_screenshot_metadata(body: ScreenshotMetadataBody, _: bool = Depends(auth)):
    """Create or update screenshot metadata (upsert on path)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO screenshot_metadata (path, filename, directory, tags, notes, added_to_scope)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (path) DO UPDATE SET
                tags = COALESCE(EXCLUDED.tags, screenshot_metadata.tags),
                notes = COALESCE(EXCLUDED.notes, screenshot_metadata.notes),
                added_to_scope = COALESCE(EXCLUDED.added_to_scope, screenshot_metadata.added_to_scope),
                updated_at = now()
            RETURNING *
        """, (body.path, body.filename, body.directory, body.tags or [], body.notes, body.added_to_scope))
        row = cur.fetchone()
        conn.commit()
    return {"ok": True, "metadata": row}


# ============================================================================
# Follow-Up Items (triage panel for pentester workflow)
# ============================================================================

class FollowUpCreate(BaseModel):
    title: str
    target: Optional[str] = None
    severity: Optional[str] = "info"
    reason: Optional[str] = None
    priority: Optional[str] = "medium"
    assigned_to: Optional[str] = None
    flagged_by: Optional[str] = "manual"
    rule_id: Optional[str] = None
    confidence: Optional[float] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    engagement_id: Optional[str] = None
    finding_source: Optional[str] = None
    finding_id: Optional[str] = None

class FollowUpUpdate(BaseModel):
    title: Optional[str] = None
    target: Optional[str] = None
    severity: Optional[str] = None
    reason: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    engagement_id: Optional[str] = None

class FeedbackBody(BaseModel):
    action: str              # accepted, dismissed, modified
    notes: Optional[str] = None


@app.get("/follow-ups/stats", tags=["Follow-Ups"])
def follow_up_stats(
    engagement_id: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """Aggregate counts by status, priority, and flagged_by."""
    eng_clause = ""
    params = []
    if engagement_id:
        eng_clause = "WHERE engagement_id = %s::uuid"
        params.append(engagement_id)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"""
            SELECT
                count(*) FILTER (WHERE status = 'open')        AS open,
                count(*) FILTER (WHERE status = 'in_progress') AS in_progress,
                count(*) FILTER (WHERE status = 'resolved')    AS resolved,
                count(*) FILTER (WHERE status = 'dismissed')   AS dismissed,
                count(*) FILTER (WHERE priority = 'critical')  AS critical,
                count(*) FILTER (WHERE priority = 'high')      AS high,
                count(*) FILTER (WHERE priority = 'medium')    AS medium_pri,
                count(*) FILTER (WHERE priority = 'low')       AS low_pri,
                count(*) FILTER (WHERE flagged_by = 'manual')      AS manual,
                count(*) FILTER (WHERE flagged_by = 'osint_agent') AS agent,
                count(*) FILTER (WHERE flagged_by LIKE 'rule:%%')  AS rule_flagged,
                count(*) AS total
            FROM follow_up_items {eng_clause}
        """, params)
        row = cur.fetchone()
    return {"stats": row}


@app.get("/follow-ups/group-ids", tags=["Follow-Ups"])
def follow_up_group_ids(
    group_key: str = Query(...),
    group_by: str = Query("title"),
    status: Optional[str] = Query(None),
    exclude_status: Optional[str] = Query(None),
    engagement_id: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """Get all follow-up IDs matching a group key (for bulk select)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        clauses = []
        params = []
        if group_by == "title":
            clauses.append("title ILIKE %s")
            params.append(f"%{group_key}%")
        else:
            clauses.append("(target ILIKE %s OR target ILIKE %s)")
            params.extend([f"%{group_key}%", f"%://{group_key}%"])
        if status:
            clauses.append("status = %s"); params.append(status)
        if exclude_status:
            clauses.append("status != %s"); params.append(exclude_status)
        if engagement_id:
            clauses.append("engagement_id = %s::uuid"); params.append(engagement_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cur.execute(f"SELECT id::text FROM follow_up_items {where} LIMIT 5000", params)
        return {"ids": [r["id"] for r in cur.fetchall()]}


@app.get("/follow-ups/grouped", tags=["Follow-Ups"])
def follow_ups_grouped(
    group_by: str = Query("title", description="title or target"),
    status: Optional[str] = Query(None),
    exclude_status: Optional[str] = Query(None),
    engagement_id: Optional[str] = Query(None),
    authorized: bool = Depends(auth),
):
    """Return follow-ups grouped by finding name or target host with counts."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        where_clauses = []
        params = []
        if status:
            where_clauses.append("status = %s")
            params.append(status)
        if exclude_status:
            where_clauses.append("status != %s")
            params.append(exclude_status)
        if engagement_id:
            where_clauses.append("engagement_id = %s::uuid")
            params.append(engagement_id)
        where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        if group_by == "target":
            # Group by hostname extracted from target
            cur.execute(f"""
                SELECT
                    COALESCE(
                        CASE
                            WHEN target LIKE 'http%%' THEN split_part(split_part(target, '://', 2), '/', 1)
                            ELSE split_part(target, '/', 1)
                        END,
                        'No target'
                    ) AS group_key,
                    count(*) AS total,
                    count(*) FILTER (WHERE status = 'open') AS open_count,
                    count(*) FILTER (WHERE status = 'in_progress') AS in_progress_count,
                    count(*) FILTER (WHERE status = 'resolved') AS resolved_count,
                    count(*) FILTER (WHERE status = 'dismissed') AS dismissed_count,
                    array_agg(DISTINCT
                        CASE
                            WHEN title LIKE '%% \u2014 %%' THEN split_part(title, ' \u2014 ', 1)
                            WHEN title LIKE '%% -- %%' THEN split_part(title, ' -- ', 1)
                            ELSE title
                        END
                    ) AS finding_names
                FROM follow_up_items
                {where}
                GROUP BY group_key
                ORDER BY total DESC
            """, params)
        else:
            # Group by finding name (title prefix before separator)
            # For software CVE titles like "Vulnerable: IIS 10.0 on 1.2.3.4 — CVE-..."
            # group by the part before " on " to roll up all hosts under one finding
            cur.execute(f"""
                SELECT
                    CASE
                        WHEN title LIKE 'Vulnerable: %% on %%' THEN trim(split_part(title, ' on ', 1))
                        WHEN title LIKE '%% \u2014 %%' THEN trim(split_part(title, ' \u2014 ', 1))
                        WHEN title LIKE '%% -- %%' THEN trim(split_part(title, ' -- ', 1))
                        WHEN title LIKE '%% \u2013 %%' THEN trim(split_part(title, ' \u2013 ', 1))
                        ELSE trim(title)
                    END AS group_key,
                    count(*) AS total,
                    count(*) FILTER (WHERE status = 'open') AS open_count,
                    count(*) FILTER (WHERE status = 'in_progress') AS in_progress_count,
                    count(*) FILTER (WHERE status = 'resolved') AS resolved_count,
                    count(*) FILTER (WHERE status = 'dismissed') AS dismissed_count,
                    count(DISTINCT
                        CASE
                            WHEN target LIKE 'http%%' THEN split_part(split_part(target, '://', 2), '/', 1)
                            ELSE split_part(COALESCE(target, ''), '/', 1)
                        END
                    ) AS unique_hosts,
                    array_agg(DISTINCT
                        CASE
                            WHEN target LIKE 'http%%' THEN split_part(split_part(target, '://', 2), '/', 1)
                            ELSE split_part(COALESCE(target, ''), '/', 1)
                        END
                    ) AS host_samples
                FROM follow_up_items
                {where}
                GROUP BY group_key
                ORDER BY total DESC
            """, params)

        rows = cur.fetchall()
        # Trim host_samples to max 5
        for r in rows:
            if r.get("host_samples"):
                r["host_samples"] = [h for h in r["host_samples"] if h][:5]
            if r.get("finding_names"):
                r["finding_names"] = [f for f in r["finding_names"] if f][:5]

    return {"groups": rows, "group_by": group_by, "total_groups": len(rows)}


@app.get("/follow-ups", tags=["Follow-Ups"])
def list_follow_ups(
    status: Optional[str] = Query(None),
    exclude_status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    flagged_by: Optional[str] = Query(None),
    engagement_id: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(10000),
    offset: int = Query(0),
    _: bool = Depends(auth),
):
    """List follow-up items with filters."""
    clauses, params = [], []
    if status:
        clauses.append("status = %s"); params.append(status)
    if exclude_status:
        clauses.append("status != %s"); params.append(exclude_status)
    if severity:
        clauses.append("severity = %s"); params.append(severity)
    if priority:
        clauses.append("priority = %s"); params.append(priority)
    if flagged_by:
        clauses.append("flagged_by = %s"); params.append(flagged_by)
    if engagement_id:
        clauses.append("engagement_id = %s::uuid"); params.append(engagement_id)
    if rule_id:
        clauses.append("rule_id = %s"); params.append(rule_id)
    if search:
        clauses.append("(title ILIKE %s OR target ILIKE %s OR reason ILIKE %s OR rule_id ILIKE %s)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.extend([limit, offset])
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"""
            SELECT * FROM follow_up_items {where}
            ORDER BY
                CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                              WHEN 'medium' THEN 2 ELSE 3 END,
                created_at DESC
            LIMIT %s OFFSET %s
        """, params)
        rows = cur.fetchall()
    return {"follow_ups": rows}


@app.post("/follow-ups", tags=["Follow-Ups"])
def create_follow_up(body: FollowUpCreate, _: bool = Depends(auth)):
    """Create a follow-up item (manual or agent-created)."""
    import uuid as _uuid
    fid = str(_uuid.uuid4())
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO follow_up_items
                (id, finding_source, finding_id, title, target, severity, reason,
                 priority, assigned_to, flagged_by, rule_id, confidence,
                 tags, notes, engagement_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (
            fid, body.finding_source,
            body.finding_id if body.finding_id else None,
            body.title, body.target, body.severity or "info",
            body.reason, body.priority or "medium", body.assigned_to,
            body.flagged_by or "manual", body.rule_id, body.confidence,
            body.tags or [], body.notes,
            body.engagement_id if body.engagement_id else None,
        ))
        row = cur.fetchone()
        conn.commit()
    return {"ok": True, "follow_up": row}


@app.patch("/follow-ups/{item_id}", tags=["Follow-Ups"])
def update_follow_up(item_id: str, body: FollowUpUpdate, _: bool = Depends(auth)):
    """Update a follow-up item's fields."""
    sets, params = [], []
    for field in ["title", "target", "severity", "reason", "status", "priority",
                  "assigned_to", "notes", "engagement_id"]:
        val = getattr(body, field, None)
        if val is not None:
            sets.append(f"{field} = %s"); params.append(val)
    if body.tags is not None:
        sets.append("tags = %s"); params.append(body.tags)
    if body.status == "resolved":
        sets.append("resolved_at = now()")
    if not sets:
        raise HTTPException(400, "No fields to update")
    params.append(item_id)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"""
            UPDATE follow_up_items SET {', '.join(sets)}
            WHERE id = %s::uuid RETURNING *
        """, params)
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Follow-up item not found")
        conn.commit()
    return {"ok": True, "follow_up": row}


@app.delete("/follow-ups/{item_id}", tags=["Follow-Ups"])
def delete_follow_up(item_id: str, _: bool = Depends(auth)):
    """Delete a follow-up item."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM follow_up_items WHERE id = %s::uuid", (item_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Follow-up item not found")
        conn.commit()
    return {"ok": True, "deleted": item_id}


@app.post("/follow-ups/{item_id}/feedback", tags=["Follow-Ups"])
def submit_follow_up_feedback(item_id: str, body: FeedbackBody, _: bool = Depends(auth)):
    """Submit user feedback on an agent-flagged follow-up (for learning)."""
    import uuid as _uuid
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Load the follow-up item
        cur.execute("SELECT * FROM follow_up_items WHERE id = %s::uuid", (item_id,))
        fu = cur.fetchone()
        if not fu:
            raise HTTPException(404, "Follow-up item not found")

        # Build finding context snapshot
        context = {
            "title": fu["title"], "target": fu["target"],
            "severity": fu["severity"], "reason": fu["reason"],
            "flagged_by": fu["flagged_by"], "rule_id": fu.get("rule_id"),
        }

        # Generate embedding for RAG retrieval
        embedding = None
        try:
            context_text = f"{fu['title']} {fu.get('target','')} {fu.get('reason','')} action={body.action}"
            embedding = _embed_text(context_text)
        except Exception:
            pass  # embedding is optional — feedback still saved

        cur.execute("""
            INSERT INTO osint_agent_feedback
                (id, follow_up_id, finding_context, agent_suggestion, agent_reasoning,
                 agent_confidence, user_action, user_notes, embedding)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            str(_uuid.uuid4()), item_id, Json(context),
            fu.get("flagged_by"), fu.get("reason"), fu.get("confidence"),
            body.action, body.notes,
            embedding,
        ))
        fb_id = cur.fetchone()["id"]

        # Update the follow-up status based on feedback
        if body.action == "dismissed":
            cur.execute("UPDATE follow_up_items SET status = 'dismissed' WHERE id = %s::uuid", (item_id,))
        elif body.action == "accepted":
            cur.execute("UPDATE follow_up_items SET status = 'in_progress' WHERE id = %s::uuid", (item_id,))

        conn.commit()
    return {"ok": True, "feedback_id": fb_id}


# ============================================================================
# OSINT Agent Control Endpoints
# ============================================================================

class AgentScanRequest(BaseModel):
    since_minutes: int = 0  # 0 = scan all findings (no time filter)


@app.post("/agent/scan", tags=["OSINT Agent"])
def trigger_agent_scan(background_tasks: BackgroundTasks, body: AgentScanRequest = AgentScanRequest(), _: bool = Depends(auth)):
    """Manually trigger the OSINT flagging agent. since_minutes=0 scans all findings."""
    try:
        from osint_agent import scan_new_findings
        # since_minutes=0 → use a very large window to scan everything
        mins = body.since_minutes if body.since_minutes > 0 else 525600  # 1 year
        background_tasks.add_task(scan_new_findings, since_minutes=mins)
        return {"ok": True, "message": f"Agent scan queued (last {mins} min)"}
    except ImportError:
        raise HTTPException(500, "osint_agent module not available")


@app.get("/agent/rules", tags=["OSINT Agent"])
def list_agent_rules(_: bool = Depends(auth)):
    """List all detection rules with their enabled/disabled status."""
    try:
        from rule_engine import get_engine
        engine = get_engine()
        if not engine._loaded:
            with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                engine.load_rules(cur)
        return {"rules": engine.get_rules()}
    except Exception as e:
        raise HTTPException(500, f"Failed to load rules: {e}")


@app.get("/agent/rules/{rule_id}", tags=["OSINT Agent"])
def get_agent_rule(rule_id: str, _: bool = Depends(auth)):
    """Get the full definition of a detection rule (including query, match, templates)."""
    try:
        from rule_engine import get_engine
        import yaml as _yaml
        engine = get_engine()
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            if not engine._loaded:
                engine.load_rules(cur)
        rule = engine.get_rule(rule_id)
        if not rule:
            raise HTTPException(404, f"Rule '{rule_id}' not found")
        # Return the full rule dict + YAML representation
        clean = {k: v for k, v in rule.items() if not k.startswith("_")}
        return {"rule": clean, "yaml": _yaml.dump([clean], default_flow_style=False, sort_keys=False)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to get rule: {e}")


@app.patch("/agent/rules/{rule_id}", tags=["OSINT Agent"])
def toggle_agent_rule(rule_id: str, enabled: bool = Query(True), _: bool = Depends(auth)):
    """Enable or disable a detection rule (persisted across restarts)."""
    try:
        from rule_engine import get_engine
        engine = get_engine()
        if not engine.set_enabled(rule_id, enabled):
            raise HTTPException(404, f"Rule '{rule_id}' not found")
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            engine.persist_enabled(cur, rule_id, enabled)
            conn.commit()
        return {"ok": True, "rule_id": rule_id, "enabled": enabled}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to toggle rule: {e}")


@app.post("/agent/rules/reload", tags=["OSINT Agent"])
def reload_agent_rules(_: bool = Depends(auth)):
    """Hot-reload detection rules from YAML files on disk."""
    try:
        from rule_engine import get_engine
        engine = get_engine()
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            count = engine.reload(cur)
        return {"ok": True, "rules_loaded": count}
    except Exception as e:
        raise HTTPException(500, f"Failed to reload rules: {e}")


class RuleTestRequest(BaseModel):
    rule_id: Optional[str] = None
    rule_yaml: Optional[str] = None
    since_minutes: int = 60
    limit: int = 50

@app.post("/agent/rules/test", tags=["OSINT Agent"])
def test_agent_rule(body: RuleTestRequest, _: bool = Depends(auth)):
    """Dry-run a rule — returns matches without creating follow-ups."""
    try:
        from rule_engine import get_engine
        engine = get_engine()
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            if not engine._loaded:
                engine.load_rules(cur)

            if body.rule_yaml:
                result = engine.dry_run_rule(cur, body.rule_yaml, body.since_minutes, body.limit)
            elif body.rule_id:
                rule = engine.get_rule(body.rule_id)
                if not rule:
                    raise HTTPException(404, f"Rule '{body.rule_id}' not found")
                result = engine.dry_run_rule(cur, rule, body.since_minutes, body.limit)
            else:
                raise HTTPException(400, "Provide rule_id or rule_yaml")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Rule test failed: {e}")


class AdhocRuleRequest(BaseModel):
    rule_yaml: str

def _validate_rule_yaml(rule_data: dict) -> list[str]:
    """Validate a detection rule dict for required structure.

    Returns a list of error messages. Empty list means valid.
    """
    from rule_engine import ALLOWED_TABLES, ALLOWED_COLUMNS
    errors = []

    if not isinstance(rule_data, dict):
        return ["Rule must be a YAML mapping (dict)"]
    if "id" not in rule_data:
        errors.append("Missing required field: 'id'")
    if "type" not in rule_data:
        errors.append("Missing required field: 'type' (simple, pattern, cross_source, or multi_pass)")

    rule_type = rule_data.get("type", "simple")

    if rule_type in ("simple", "pattern"):
        query = rule_data.get("query")
        if not query or not isinstance(query, dict):
            # Check for common flat-YAML mistake: table/column at top level
            if "table" in rule_data and "query" not in rule_data:
                errors.append(
                    "'table' found at top level — it must be nested under 'query:'. "
                    "Example:\n  query:\n    table: web_findings\n    columns: [id, name]"
                )
            else:
                errors.append("Missing required field: 'query' (must be a mapping with 'table' key)")
        else:
            table = query.get("table")
            if not table:
                errors.append("'query.table' is required")
            elif table not in ALLOWED_TABLES:
                errors.append(f"'query.table' = '{table}' is not in the allowed tables: {sorted(ALLOWED_TABLES)}")

            columns = query.get("columns", [])
            if columns and table and table in ALLOWED_COLUMNS:
                bad = [c for c in columns if c not in ALLOWED_COLUMNS[table]]
                if bad:
                    errors.append(f"Invalid columns for {table}: {bad}. Allowed: {sorted(ALLOWED_COLUMNS[table])}")

    elif rule_type == "cross_source":
        sources = rule_data.get("sources", [])
        if not sources or not isinstance(sources, list) or len(sources) < 2:
            errors.append("'cross_source' rules need at least 2 entries in 'sources'")
        for i, src in enumerate(sources):
            if not isinstance(src, dict) or "table" not in src:
                errors.append(f"sources[{i}] missing 'table'")
            elif src["table"] not in ALLOWED_TABLES:
                errors.append(f"sources[{i}].table = '{src['table']}' not in allowed tables")

    elif rule_type == "multi_pass":
        passes = rule_data.get("passes", [])
        if not passes or not isinstance(passes, list):
            errors.append("'multi_pass' rules need at least 1 entry in 'passes'")
        for i, p in enumerate(passes):
            pq = p.get("query", {}) if isinstance(p, dict) else {}
            if not pq.get("table"):
                errors.append(f"passes[{i}].query.table is required")
            elif pq["table"] not in ALLOWED_TABLES:
                errors.append(f"passes[{i}].query.table = '{pq['table']}' not in allowed tables")
    else:
        errors.append(f"Unknown rule type: '{rule_type}'. Must be simple, pattern, cross_source, or multi_pass")

    return errors


@app.post("/agent/rules/adhoc", tags=["OSINT Agent"])
def create_adhoc_rule(body: AdhocRuleRequest, _: bool = Depends(auth)):
    """Create a new ad-hoc detection rule (stored in DB).

    Validates YAML structure before saving to prevent broken rules
    from poisoning the rule engine.
    """
    try:
        import yaml as _yaml
        from rule_engine import get_engine

        # Parse YAML
        try:
            rule_data = _yaml.safe_load(body.rule_yaml)
        except _yaml.YAMLError as e:
            raise HTTPException(400, f"Invalid YAML syntax: {e}")

        if isinstance(rule_data, list):
            rule_data = rule_data[0]

        # Validate structure
        validation_errors = _validate_rule_yaml(rule_data)
        if validation_errors:
            raise HTTPException(400, {
                "message": "Rule validation failed",
                "errors": validation_errors,
            })

        rule_id = rule_data["id"]
        engine = get_engine()

        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO detection_rule_state (rule_id, enabled, source, rule_yaml)
                VALUES (%s, true, 'adhoc', %s)
                ON CONFLICT (rule_id) DO UPDATE
                    SET rule_yaml = EXCLUDED.rule_yaml, source = 'adhoc', updated_at = now()
            """, (rule_id, body.rule_yaml))
            conn.commit()

            # Reload to pick up the new rule
            engine.reload(cur)

        return {"ok": True, "rule_id": rule_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to create adhoc rule: {e}")


@app.delete("/agent/rules/{rule_id}", tags=["OSINT Agent"])
def delete_agent_rule(rule_id: str, _: bool = Depends(auth)):
    """Delete an adhoc detection rule."""
    try:
        from rule_engine import get_engine
        engine = get_engine()
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            deleted = engine.delete_adhoc_rule(cur, rule_id)
            conn.commit()
        if not deleted:
            raise HTTPException(404, f"Adhoc rule '{rule_id}' not found")
        return {"ok": True, "rule_id": rule_id, "deleted": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to delete rule: {e}")


@app.get("/agent/stats", tags=["OSINT Agent"])
def agent_stats(_: bool = Depends(auth)):
    """Agent activity stats: flagged count, feedback accuracy."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                count(*) FILTER (WHERE flagged_by = 'osint_agent') AS total_flagged,
                count(*) FILTER (WHERE flagged_by = 'osint_agent' AND status = 'dismissed') AS dismissed,
                count(*) FILTER (WHERE flagged_by = 'osint_agent' AND status IN ('in_progress','resolved')) AS accepted
            FROM follow_up_items
        """)
        fu_stats = cur.fetchone()
        cur.execute("SELECT count(*) AS feedback_count FROM osint_agent_feedback")
        fb_count = cur.fetchone()["feedback_count"]
    total = fu_stats["total_flagged"] or 0
    accepted = fu_stats["accepted"] or 0
    accuracy = round(accepted / total, 2) if total > 0 else None
    return {"stats": {**fu_stats, "feedback_count": fb_count, "accuracy": accuracy}}


# ============================================================================
# ============================================================================
# Gap Analysis Agent
# ============================================================================


@app.post("/agent/gap-analysis/{engagement_id}", tags=["Gap Analysis"])
def trigger_gap_analysis(engagement_id: str, background_tasks: BackgroundTasks,
                         _: bool = Depends(auth)):
    """Trigger recon gap analysis for an engagement."""
    from gap_agent import run_gap_analysis
    background_tasks.add_task(run_gap_analysis, engagement_id, "manual")
    return {"ok": True, "message": "Gap analysis queued", "engagement_id": engagement_id}


@app.get("/agent/gap-analysis/{engagement_id}", tags=["Gap Analysis"])
def get_gap_report(engagement_id: str, all: bool = Query(False),
                   _: bool = Depends(auth)):
    """Get the latest (or all) gap analysis report(s) for an engagement."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if all:
            cur.execute("""
                SELECT id, engagement_id, status, report, gaps_found,
                       scans_dispatched, recommendations, created_at, completed_at, triggered_by
                FROM gap_analysis_reports
                WHERE engagement_id = %s
                ORDER BY created_at DESC
            """, (engagement_id,))
            rows = cur.fetchall()
            return {"reports": [dict(r) for r in rows]}
        else:
            cur.execute("""
                SELECT id, engagement_id, status, report, gaps_found,
                       scans_dispatched, recommendations, created_at, completed_at, triggered_by
                FROM gap_analysis_reports
                WHERE engagement_id = %s
                ORDER BY created_at DESC LIMIT 1
            """, (engagement_id,))
            row = cur.fetchone()
            return {"report": dict(row) if row else None}


@app.post("/agent/gap-analysis/{engagement_id}/auto-fill", tags=["Gap Analysis"])
def trigger_auto_fill(engagement_id: str, background_tasks: BackgroundTasks,
                      report_id: Optional[str] = Query(None),
                      _: bool = Depends(auth)):
    """Dispatch passive scans to fill gaps from the latest completed report."""
    from gap_agent import auto_fill_gaps
    background_tasks.add_task(auto_fill_gaps, engagement_id, report_id)
    return {"ok": True, "message": "Auto-fill queued", "engagement_id": engagement_id}


class GapScheduleBody(BaseModel):
    enabled: bool = True
    interval_minutes: int = 30
    auto_fill: bool = True


@app.post("/agent/gap-analysis/{engagement_id}/schedule", tags=["Gap Analysis"])
def set_gap_schedule(engagement_id: str, body: GapScheduleBody, _: bool = Depends(auth)):
    """Enable/disable automatic gap analysis for an engagement.

    When enabled, the gap agent auto-runs when no scans are active,
    at the specified interval. If auto_fill is true, passive scans
    are dispatched automatically after each analysis.
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO app_settings (key, value, category)
            VALUES (%s, %s, 'gap_agent')
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """, (
            f"gap_schedule_{engagement_id}",
            json.dumps({
                "enabled": body.enabled,
                "interval_minutes": body.interval_minutes,
                "auto_fill": body.auto_fill,
                "engagement_id": engagement_id,
            }),
        ))
    return {"ok": True, "engagement_id": engagement_id, **body.model_dump()}


@app.get("/agent/gap-analysis/{engagement_id}/schedule", tags=["Gap Analysis"])
def get_gap_schedule(engagement_id: str, _: bool = Depends(auth)):
    """Get the gap analysis schedule config for an engagement."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT value FROM app_settings WHERE key = %s AND category = 'gap_agent'",
            (f"gap_schedule_{engagement_id}",),
        )
        row = cur.fetchone()
        if row:
            return {"schedule": json.loads(row["value"])}
        return {"schedule": {"enabled": False, "interval_minutes": 30, "auto_fill": True}}


@app.get("/nodes", tags=["Nodes"])
def list_nodes(_: bool = Depends(auth)):
    """List remote nodes (for Burp extension and external integrations)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id::text, name, node_type, status, hostname,
                   host(internal_ip)::text AS internal_ip,
                   host(external_ip)::text AS external_ip,
                   proxy_port, proxy_type, metadata
            FROM remote_nodes ORDER BY name
        """)
        nodes = [dict(r) for r in cur.fetchall()]
    return {"nodes": nodes}


@app.get("/agents/status", tags=["AI Agents"])
def get_agents_status(_: bool = Depends(auth)):
    """Aggregate status of all AI agents for the unified agents page."""
    import httpx as _hx

    print("[DEBUG] get_agents_status called")
    agents = []

    def _fast_get(url, timeout=2):
        """HTTP GET with a hard total timeout (not per-socket like requests)."""
        try:
            return _hx.get(url, timeout=timeout, verify=False)
        except Exception:
            return None

    # 1. Pentest Agent (autogen-agents)
    try:
        r = _fast_get("https://autogen-agents:8015/health")
        sessions_count = 0
        if r and r.status_code == 200:
            sr = _fast_get("https://autogen-agents:8015/pentest/sessions")
            if sr and sr.status_code == 200:
                sessions = sr.json().get("sessions", [])
                sessions_count = len([s for s in sessions if s.get("status") == "active"])
        agents.append({
            "id": "pentest-agent", "name": "Pentest Agent",
            "type": "session", "status": "running" if r and r.status_code == 200 else "unreachable",
            "description": "7-agent team for automated penetration testing",
            "active_sessions": sessions_count,
            "service_port": 8015,
        })
    except Exception:
        agents.append({
            "id": "pentest-agent", "name": "Pentest Agent",
            "type": "session", "status": "unreachable",
            "description": "7-agent team for automated penetration testing",
            "service_port": 8015,
        })

    # 2. OSINT Flagging Agent
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT count(*) as cnt, max(created_at) as last_run
                FROM follow_up_items WHERE flagged_by = 'osint_agent'
            """)
            row = cur.fetchone()
            agents.append({
                "id": "osint-agent", "name": "OSINT Flagging Agent",
                "type": "on-demand", "status": "idle",
                "description": "YAML rule engine — scans findings and flags follow-ups",
                "findings_created": row["cnt"] if row else 0,
                "last_run": row["last_run"].isoformat() if row and row["last_run"] else None,
            })
    except Exception:
        agents.append({
            "id": "osint-agent", "name": "OSINT Flagging Agent",
            "type": "on-demand", "status": "error",
            "description": "YAML rule engine — scans findings and flags follow-ups",
        })

    # 3. Scan Recommender
    try:
        r = _fast_get("https://scan-recommender:8013/health")
        last_run = None
        recommendations_count = 0

        # Check for recent scan recommendations activity
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT count(*) as cnt, max(created_at) as last_run
                FROM scan_recommendations
            """)
            row = cur.fetchone()
            if row:
                recommendations_count = row["cnt"] or 0
                last_run = row["last_run"].isoformat() if row["last_run"] else None

        agents.append({
            "id": "scan-recommender", "name": "Scan Recommender",
            "type": "continuous", "status": "running" if r and r.status_code == 200 else "unreachable",
            "description": "LLM-powered tool and scan recommendations",
            "service_port": 8013,
            "findings_created": recommendations_count,
            "last_run": last_run,
        })
    except Exception as e:
        print(f"[DEBUG] Scan recommender agent error: {e}")
        agents.append({
            "id": "scan-recommender", "name": "Scan Recommender",
            "type": "continuous", "status": "unreachable",
            "description": "LLM-powered tool and scan recommendations",
            "service_port": 8013,
        })

    # 4. Recon Agent
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check how many engagements have the recon agent enabled
            cur.execute("""
                SELECT count(*) as enabled_count,
                       count(*) FILTER (WHERE last_run_at > now() - interval '10 minutes') as recently_active,
                       max(last_run_at) as last_run,
                       max(last_dispatch_at) as last_dispatch
                FROM recon_agent_state WHERE enabled = true
            """)
            agent_row = cur.fetchone()
            enabled_count = agent_row["enabled_count"] if agent_row else 0
            recently_active = agent_row["recently_active"] if agent_row else 0
            last_run = agent_row["last_run"] if agent_row else None
            last_dispatch = agent_row["last_dispatch"] if agent_row else None

            # Coverage stats
            cur.execute("""
                SELECT count(*) as total,
                       count(*) FILTER (WHERE status = 'completed') as completed,
                       count(*) FILTER (WHERE status = 'pending') as pending,
                       count(*) FILTER (WHERE status = 'running') as running
                FROM scope_coverage
            """)
            cov = cur.fetchone()

            status = "running" if recently_active > 0 else "idle" if enabled_count > 0 else "idle"
            agents.append({
                "id": "recon-agent", "name": "Recon Agent",
                "type": "continuous", "status": status,
                "description": "Auto-dispatches missing scans per engagement scope",
                "enabled_engagements": enabled_count,
                "coverage_total": cov["total"] if cov else 0,
                "coverage_completed": cov["completed"] if cov else 0,
                "coverage_pending": cov["pending"] if cov else 0,
                "coverage_running": cov["running"] if cov else 0,
                "last_run": last_run.isoformat() if last_run else None,
                "last_dispatch": last_dispatch.isoformat() if last_dispatch else None,
            })
    except Exception:
        agents.append({
            "id": "recon-agent", "name": "Recon Agent",
            "type": "continuous", "status": "error",
            "description": "Auto-dispatches missing scans per engagement scope",
        })

    # 5. Gap Analysis Agent
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, status, gaps_found, completed_at
                FROM gap_analysis_reports
                ORDER BY created_at DESC LIMIT 1
            """)
            row = cur.fetchone()
            agents.append({
                "id": "gap-agent", "name": "Recon Gap Analysis",
                "type": "on-demand", "status": "idle",
                "description": "Identifies missing recon data and recommends scans to fill gaps",
                "last_run": row["completed_at"].isoformat() if row and row["completed_at"] else None,
                "gaps_found": row["gaps_found"] if row else None,
            })
    except Exception:
        agents.append({
            "id": "gap-agent", "name": "Recon Gap Analysis",
            "type": "on-demand", "status": "error",
            "description": "Identifies missing recon data and recommends scans to fill gaps",
        })

    # 6. Cloud Triage Agent
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, open_recs_count, model, created_at, error
                FROM cloud_triage_runs
                ORDER BY created_at DESC LIMIT 1
            """)
            row = cur.fetchone()
            cur.execute("SELECT count(*) AS n FROM cloud_scan_recommendations WHERE status='open'")
            open_recs = (cur.fetchone() or {}).get("n", 0)
            agents.append({
                "id": "cloud-triage-agent", "name": "Cloud Triage Agent",
                "type": "on-demand", "status": "error" if row and row.get("error") else "idle",
                "description": "Re-ranks open cloud recommendations by attack-chain order and produces a top-3 next-actions plan",
                "last_run": row["created_at"].isoformat() if row and row.get("created_at") else None,
                "model": row["model"] if row else None,
                "open_recs": open_recs,
            })
    except Exception:
        agents.append({
            "id": "cloud-triage-agent", "name": "Cloud Triage Agent",
            "type": "on-demand", "status": "error",
            "description": "Re-ranks open cloud recommendations by attack-chain order and produces a top-3 next-actions plan",
        })

    return {"agents": agents}


# API Collections + Test Sessions (Swagger/OpenAPI Ingestion)
# ============================================================================

SWAGGER_DIR = os.environ.get("SWAGGER_DIR", "/app/swagger_files")


class ApiTestSessionCreate(BaseModel):
    name: Optional[str] = None
    collection_id: Optional[str] = None
    jwt_token: Optional[str] = None
    proxy_url: Optional[str] = None
    variables: Optional[Dict[str, Any]] = None


class ApiTestSessionUpdate(BaseModel):
    name: Optional[str] = None
    jwt_token: Optional[str] = None
    proxy_url: Optional[str] = None
    variables: Optional[Dict[str, Any]] = None


class ApiTestExecute(BaseModel):
    session_id: str
    endpoint_id: str
    params: Optional[Dict[str, str]] = None  # {param_name: value}
    body: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None


class ImportUrlRequest(BaseModel):
    url: str


class SendToPipelineRequest(BaseModel):
    collection_id: str
    target_url: Optional[str] = None  # override base_url


class RunAllRequest(BaseModel):
    session_id: str
    collection_id: str
    variables: Optional[Dict[str, str]] = None  # common param values
    headers: Optional[Dict[str, str]] = None


@app.post("/api-collections/import-url", tags=["API Collections"])
def import_swagger_url(body: ImportUrlRequest, _: bool = Depends(auth)):
    """Fetch a Swagger/OpenAPI JSON from a URL and import it."""
    import sys
    sys.path.insert(0, "/app/etl")
    from parse_swagger import parse_swagger
    import tempfile
    import httpx

    try:
        import re as _re
        from urllib.parse import urljoin as _urljoin

        url = body.url.rstrip("/")

        with httpx.Client(timeout=30, verify=False, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code >= 400:
                raise HTTPException(400, f"Failed to fetch URL: HTTP {resp.status_code}")
            content_type = resp.headers.get("content-type", "")

            # If we got HTML (Swagger UI page), try to extract the JSON spec URL
            if "html" in content_type:
                html = resp.text
                json_url = None
                # Common patterns in Swagger UI pages:
                # url: "https://...swagger.json"  or  url: '/v2/api-docs'
                for pattern in [
                    r'''url\s*[:=]\s*["']([^"']+\.json)["']''',
                    r'''url\s*[:=]\s*["']([^"']+swagger[^"']*)["']''',
                    r'''url\s*[:=]\s*["']([^"']+openapi[^"']*)["']''',
                    r'''url\s*[:=]\s*["']([^"']+api-docs[^"']*)["']''',
                    r'''spec-url\s*=\s*["']([^"']+)["']''',
                    r'''"url"\s*:\s*"([^"]+)"''',
                ]:
                    m = _re.search(pattern, html, _re.IGNORECASE)
                    if m:
                        json_url = m.group(1)
                        break

                # Fallback: try appending common spec paths to the original URL
                if not json_url:
                    base = url.rstrip("/")
                    for suffix in ["/swagger.json", "/v2/api-docs", "/v3/api-docs", "/openapi.json"]:
                        try:
                            probe = client.get(base + suffix)
                            if probe.status_code == 200 and "json" in probe.headers.get("content-type", ""):
                                json_url = base + suffix
                                break
                        except Exception:
                            continue

                if not json_url:
                    raise HTTPException(
                        400,
                        "Got an HTML page (Swagger UI?) but could not find the JSON spec URL. "
                        "Try providing the direct URL to the swagger.json file instead.",
                    )

                # Resolve relative URLs
                if not json_url.startswith("http"):
                    json_url = _urljoin(url, json_url)

                print(f"[import-url] Extracted swagger JSON URL from HTML: {json_url}")
                resp = client.get(json_url)
                if resp.status_code >= 400:
                    raise HTTPException(400, f"Failed to fetch extracted JSON URL: HTTP {resp.status_code}")
                content_type = resp.headers.get("content-type", "")

            if "json" not in content_type and "yaml" not in content_type and "text" not in content_type:
                raise HTTPException(400, f"Unexpected content-type: {content_type}")
            data = resp.content

        # Save to import/swagger dir for future re-imports
        url_filename = body.url.rstrip("/").split("/")[-1]
        if not url_filename.endswith(".json"):
            url_filename += ".json"
        save_path = os.path.join(SWAGGER_DIR, url_filename)
        try:
            os.makedirs(SWAGGER_DIR, exist_ok=True)
            with open(save_path, "wb") as f:
                f.write(data)
        except Exception:
            save_path = None  # non-critical if dir is read-only

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="wb") as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        parsed = parse_swagger(tmp_path)
        parsed["source_file"] = url_filename
        parsed["source_url"] = body.url  # original user-provided URL (for re-auth)

        collection_id = _store_collection(parsed)
        os.unlink(tmp_path)

        return {
            "ok": True,
            "collection_id": collection_id,
            "endpoint_count": len(parsed["endpoints"]),
            "source_url": body.url,
            "saved_to": save_path,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to import swagger from URL: {e}")


@app.post("/api-collections/import", tags=["API Collections"])
def import_swagger_file(
    file: UploadFile = File(...),
    _: bool = Depends(auth),
):
    """Import a single OpenAPI/Swagger JSON file."""
    import sys
    sys.path.insert(0, "/app/etl")
    from parse_swagger import parse_swagger
    import tempfile

    try:
        content = file.file.read()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="wb") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        parsed = parse_swagger(tmp_path)
        parsed["source_file"] = file.filename or parsed["source_file"]

        collection_id = _store_collection(parsed)
        os.unlink(tmp_path)

        return {"ok": True, "collection_id": collection_id, "endpoint_count": len(parsed["endpoints"])}
    except Exception as e:
        raise HTTPException(500, f"Failed to import swagger file: {e}")


@app.post("/api-collections/import-dir", tags=["API Collections"])
def import_swagger_dir(_: bool = Depends(auth)):
    """Import all JSON files from the mounted swagger_files directory."""
    import sys
    sys.path.insert(0, "/app/etl")
    from parse_swagger import parse_swagger_dir

    if not os.path.isdir(SWAGGER_DIR):
        raise HTTPException(404, f"Swagger directory not found: {SWAGGER_DIR}")

    results = parse_swagger_dir(SWAGGER_DIR)
    imported = []
    for parsed in results:
        try:
            cid = _store_collection(parsed)
            imported.append({
                "collection_id": cid,
                "name": parsed["name"],
                "source_file": parsed["source_file"],
                "endpoint_count": len(parsed["endpoints"]),
            })
        except Exception as e:
            imported.append({
                "name": parsed.get("name", "unknown"),
                "source_file": parsed.get("source_file", ""),
                "error": str(e),
            })

    return {"ok": True, "imported": imported, "total": len(imported)}


def _store_collection(parsed: dict) -> str:
    """Store a parsed swagger collection + endpoints into the database.
    Upserts by source_file: if a collection with the same source_file exists,
    update it and replace endpoints. Otherwise create a new one.
    """
    source_url = parsed.get("source_url") or None
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Ensure source_url column exists (migration-safe)
        try:
            cur.execute("ALTER TABLE api_collections ADD COLUMN IF NOT EXISTS source_url text")
            conn.commit()
        except Exception:
            conn.rollback()

        # Check if same source_file already exists
        cur.execute("SELECT id FROM api_collections WHERE source_file = %s", (parsed["source_file"],))
        existing = cur.fetchone()

        if existing:
            cid = str(existing["id"])
            # Update collection metadata and clear old endpoints
            cur.execute("DELETE FROM api_endpoints WHERE collection_id = %s", (cid,))
            cur.execute("""
                UPDATE api_collections
                SET name=%s, base_url=%s, openapi_version=%s, auth_type=%s,
                    auth_config=%s, endpoint_count=%s, source_url=COALESCE(%s, source_url)
                WHERE id = %s
            """, (
                parsed["name"], parsed["base_url"], parsed["openapi_version"],
                parsed["auth_type"], Json(parsed["auth_config"]),
                len(parsed["endpoints"]), source_url, cid,
            ))
        else:
            cur.execute("""
                INSERT INTO api_collections (name, base_url, openapi_version, auth_type, auth_config, source_file, source_url, endpoint_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (
                parsed["name"], parsed["base_url"], parsed["openapi_version"],
                parsed["auth_type"], Json(parsed["auth_config"]),
                parsed["source_file"], source_url, len(parsed["endpoints"]),
            ))
            cid = str(cur.fetchone()["id"])

        # Insert endpoints
        for ep in parsed["endpoints"]:
            cur.execute("""
                INSERT INTO api_endpoints
                    (collection_id, method, path, operation_id, summary, parameters, request_body, responses, security, tags)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (collection_id, method, path) DO UPDATE SET
                    operation_id = EXCLUDED.operation_id,
                    summary = EXCLUDED.summary,
                    parameters = EXCLUDED.parameters,
                    request_body = EXCLUDED.request_body,
                    responses = EXCLUDED.responses,
                    security = EXCLUDED.security,
                    tags = EXCLUDED.tags
            """, (
                cid, ep["method"], ep["path"], ep["operation_id"],
                ep["summary"], Json(ep["parameters"]), Json(ep["request_body"]),
                Json(ep["responses"]), Json(ep["security"]),
                ep["tags"] or [],
            ))

        conn.commit()
        return cid


@app.get("/api-collections", tags=["API Collections"])
def list_api_collections(_: bool = Depends(auth)):
    """List all imported API collections."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, name, base_url, openapi_version, auth_type, auth_config,
                   source_file, source_url, endpoint_count, created_at, updated_at
            FROM api_collections ORDER BY name
        """)
        return {"collections": cur.fetchall()}


@app.get("/api-collections/{collection_id}", tags=["API Collections"])
def get_api_collection(collection_id: str, _: bool = Depends(auth)):
    """Get collection detail including auth config."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM api_collections WHERE id = %s", (collection_id,))
        coll = cur.fetchone()
        if not coll:
            raise HTTPException(404, "Collection not found")
        return {"collection": coll}


@app.delete("/api-collections/{collection_id}", tags=["API Collections"])
def delete_api_collection(collection_id: str, _: bool = Depends(auth)):
    """Delete a collection and cascade-delete its endpoints."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("DELETE FROM api_collections WHERE id = %s RETURNING id", (collection_id,))
        deleted = cur.fetchone()
        conn.commit()
        if not deleted:
            raise HTTPException(404, "Collection not found")
        return {"ok": True, "deleted": collection_id}


@app.get("/api-collections/{collection_id}/endpoints", tags=["API Collections"])
def list_api_endpoints(
    collection_id: str,
    method: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    _: bool = Depends(auth),
):
    """List endpoints for a collection with optional filters."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        sql = "SELECT * FROM api_endpoints WHERE collection_id = %s"
        params: list = [collection_id]

        if method:
            sql += " AND method = %s"
            params.append(method.upper())
        if tag:
            sql += " AND %s = ANY(tags)"
            params.append(tag)
        if search:
            sql += " AND (path ILIKE %s OR summary ILIKE %s OR operation_id ILIKE %s)"
            like = f"%{search}%"
            params.extend([like, like, like])

        sql += " ORDER BY path, method"
        cur.execute(sql, params)
        return {"endpoints": cur.fetchall()}


# --- Test Sessions ---

@app.post("/api-test/sessions", tags=["API Test"])
def create_test_session(body: ApiTestSessionCreate, _: bool = Depends(auth)):
    """Create a new API test session."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO api_test_sessions (name, collection_id, jwt_token, proxy_url, variables)
            VALUES (%s, %s, %s, %s, %s) RETURNING *
        """, (
            body.name, body.collection_id, body.jwt_token,
            body.proxy_url, Json(body.variables or {}),
        ))
        session = cur.fetchone()
        conn.commit()
        return {"ok": True, "session": session}


@app.get("/api-test/sessions", tags=["API Test"])
def list_test_sessions(_: bool = Depends(auth)):
    """List all test sessions."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM api_test_sessions ORDER BY updated_at DESC")
        return {"sessions": cur.fetchall()}


@app.patch("/api-test/sessions/{session_id}", tags=["API Test"])
def update_test_session(session_id: str, body: ApiTestSessionUpdate, _: bool = Depends(auth)):
    """Update a test session (JWT, proxy, variables)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        sets, vals = [], []
        if body.name is not None:
            sets.append("name = %s"); vals.append(body.name)
        if body.jwt_token is not None:
            sets.append("jwt_token = %s"); vals.append(body.jwt_token)
        if body.proxy_url is not None:
            sets.append("proxy_url = %s"); vals.append(body.proxy_url)
        if body.variables is not None:
            sets.append("variables = %s"); vals.append(Json(body.variables))
        if not sets:
            raise HTTPException(400, "No fields to update")
        vals.append(session_id)
        cur.execute(
            f"UPDATE api_test_sessions SET {', '.join(sets)} WHERE id = %s RETURNING *",
            vals,
        )
        session = cur.fetchone()
        conn.commit()
        if not session:
            raise HTTPException(404, "Session not found")
        return {"ok": True, "session": session}


@app.delete("/api-test/sessions/{session_id}", tags=["API Test"])
def delete_test_session(session_id: str, _: bool = Depends(auth)):
    """Delete a test session and its history."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("DELETE FROM api_test_sessions WHERE id = %s RETURNING id", (session_id,))
        deleted = cur.fetchone()
        conn.commit()
        if not deleted:
            raise HTTPException(404, "Session not found")
        return {"ok": True, "deleted": session_id}


@app.post("/api-test/execute", tags=["API Test"])
def execute_api_test(body: ApiTestExecute, _: bool = Depends(auth)):
    """Execute a single API endpoint test. Makes the HTTP request server-side."""
    import httpx
    import time

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get session
        cur.execute("SELECT * FROM api_test_sessions WHERE id = %s", (body.session_id,))
        session = cur.fetchone()
        if not session:
            raise HTTPException(404, "Session not found")

        # Get endpoint
        cur.execute("SELECT * FROM api_endpoints WHERE id = %s", (body.endpoint_id,))
        endpoint = cur.fetchone()
        if not endpoint:
            raise HTTPException(404, "Endpoint not found")

        # Get collection for base_url
        cur.execute("SELECT base_url FROM api_collections WHERE id = %s", (endpoint["collection_id"],))
        coll = cur.fetchone()
        base_url = (coll["base_url"] if coll else "").rstrip("/")

        # Resolve path params
        path = endpoint["path"]
        params_dict = body.params or {}
        for pname, pval in params_dict.items():
            path = path.replace(f"{{{pname}}}", str(pval))

        url = f"{base_url}{path}"

        # Build query params
        query_params = {}
        for p in (endpoint["parameters"] or []):
            if p.get("in") == "query" and p["name"] in params_dict:
                query_params[p["name"]] = params_dict[p["name"]]

        # Build headers
        req_headers = {}
        # Add JWT from session
        if session.get("jwt_token"):
            req_headers["Authorization"] = f"Bearer {session['jwt_token']}"
        # Add header params
        for p in (endpoint["parameters"] or []):
            if p.get("in") == "header" and p["name"] in params_dict:
                req_headers[p["name"]] = params_dict[p["name"]]
        # Add custom headers from request
        if body.headers:
            req_headers.update(body.headers)

        # Build request body
        req_body = None
        if body.body and endpoint["method"] in ("POST", "PUT", "PATCH"):
            req_body = json.dumps(body.body)
            req_headers.setdefault("Content-Type", "application/json")

        # Set up proxy
        proxy_url = session.get("proxy_url")

        # Execute the request
        error_msg = None
        status_code = None
        response_headers = {}
        response_body = ""
        start = time.time()

        try:
            client_kwargs = {"timeout": 30.0, "verify": False}
            if proxy_url:
                client_kwargs["proxy"] = proxy_url

            with httpx.Client(**client_kwargs) as client:
                resp = client.request(
                    method=endpoint["method"],
                    url=url,
                    params=query_params or None,
                    headers=req_headers,
                    content=req_body,
                )
                status_code = resp.status_code
                response_headers = dict(resp.headers)
                response_body = resp.text[:50000]  # cap at 50KB
        except Exception as e:
            error_msg = str(e)

        duration_ms = int((time.time() - start) * 1000)

        # Store result
        cur.execute("""
            INSERT INTO api_test_results
                (session_id, endpoint_id, method, url, request_headers, request_body,
                 status_code, response_headers, response_body, duration_ms, error)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (
            body.session_id, body.endpoint_id, endpoint["method"], url,
            Json(req_headers), req_body,
            status_code, Json(response_headers), response_body,
            duration_ms, error_msg,
        ))
        result = cur.fetchone()
        conn.commit()

        return {"ok": True, "result": result}


@app.get("/api-test/sessions/{session_id}/history", tags=["API Test"])
def get_test_history(
    session_id: str,
    endpoint_id: Optional[str] = Query(None),
    limit: int = Query(50),
    _: bool = Depends(auth),
):
    """Get execution history for a session, optionally filtered by endpoint."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        sql = "SELECT * FROM api_test_results WHERE session_id = %s"
        params: list = [session_id]
        if endpoint_id:
            sql += " AND endpoint_id = %s"
            params.append(endpoint_id)
        sql += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        cur.execute(sql, params)
        return {"history": cur.fetchall()}


@app.post("/api-test/send-to-pipeline", tags=["API Test"])
def send_to_pipeline(body: SendToPipelineRequest, _: bool = Depends(auth)):
    """Send collection endpoints to the web scanner pipeline."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM api_collections WHERE id = %s", (body.collection_id,))
        coll = cur.fetchone()
        if not coll:
            raise HTTPException(404, "Collection not found")

        cur.execute("SELECT DISTINCT path FROM api_endpoints WHERE collection_id = %s", (body.collection_id,))
        paths = [r["path"] for r in cur.fetchall()]

        base = (body.target_url or coll["base_url"] or "").rstrip("/")
        urls = [f"{base}{p}" for p in paths]

        # Submit to web-scanner pipeline
        try:
            web_scanner_url = os.environ.get("WEB_SCANNER_URL", "https://web-scanner:8010")
            resp = requests.post(
                f"{web_scanner_url}/scan",
                json={"urls": urls, "source": "api-tester"},
                headers=_outgoing_runner_headers(),
                timeout=15,
            )
            return {
                "ok": True,
                "urls_sent": len(urls),
                "pipeline_response": resp.json() if resp.status_code < 400 else resp.text,
            }
        except Exception as e:
            return {"ok": False, "urls_sent": len(urls), "error": str(e)}


@app.delete("/api-test/sessions/{session_id}/history", tags=["API Test"])
def clear_test_history(session_id: str, _: bool = Depends(auth)):
    """Delete all test results for a session."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM api_test_results WHERE session_id = %s", (session_id,))
        deleted = cur.rowcount
        conn.commit()
        return {"ok": True, "deleted": deleted}


@app.get("/api-collections/{collection_id}/common-params", tags=["API Collections"])
def get_common_params(collection_id: str, _: bool = Depends(auth)):
    """Extract all unique parameters across all endpoints in a collection,
    grouped by name, showing where each is used."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT id, method, path, parameters, request_body FROM api_endpoints WHERE collection_id = %s",
            (collection_id,),
        )
        endpoints = cur.fetchall()

    param_map: Dict[str, dict] = {}  # name -> {info + used_in list}

    for ep in endpoints:
        ep_label = f"{ep['method']} {ep['path']}"
        # Standard parameters (path, query, header)
        for p in (ep["parameters"] or []):
            name = p.get("name", "")
            if not name:
                continue
            key = f"{p.get('in', 'query')}:{name}"
            if key not in param_map:
                param_map[key] = {
                    "name": name,
                    "in": p.get("in", "query"),
                    "type": p.get("type", "string"),
                    "format": p.get("format", ""),
                    "required": p.get("required", False),
                    "description": p.get("description", ""),
                    "used_in": [],
                }
            param_map[key]["used_in"].append(ep_label)
            if p.get("required"):
                param_map[key]["required"] = True

        # Request body fields
        rb = ep.get("request_body")
        if rb and isinstance(rb, dict):
            for field in (rb.get("fields") or []):
                fname = field.get("name", "")
                if not fname:
                    continue
                key = f"body:{fname}"
                if key not in param_map:
                    param_map[key] = {
                        "name": fname,
                        "in": "body",
                        "type": field.get("type", "string"),
                        "format": "",
                        "required": field.get("required", False),
                        "description": field.get("description", ""),
                        "used_in": [],
                    }
                param_map[key]["used_in"].append(ep_label)

    # Sort: required first, then by number of usages (most common first)
    params = sorted(
        param_map.values(),
        key=lambda p: (-int(p["required"]), -len(p["used_in"]), p["name"]),
    )

    return {"collection_id": collection_id, "params": params, "total": len(params)}


# ── Param Config CRUD ──

class ParamConfigCreate(BaseModel):
    name: str
    config: Dict[str, Any] = {}
    auth_header: Optional[str] = None

class ParamConfigUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    auth_header: Optional[str] = None


@app.get("/api-collections/{collection_id}/param-configs", tags=["API Collections"])
def list_param_configs(collection_id: str, _: bool = Depends(auth)):
    """List saved parameter configurations for a collection."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM api_param_configs WHERE collection_id = %s ORDER BY updated_at DESC",
            (collection_id,),
        )
        rows = cur.fetchall()
    return {"configs": rows, "total": len(rows)}


@app.post("/api-collections/{collection_id}/param-configs", tags=["API Collections"])
def create_param_config(collection_id: str, body: ParamConfigCreate, _: bool = Depends(auth)):
    """Save a new parameter configuration."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO api_param_configs (collection_id, name, config, auth_header)
               VALUES (%s, %s, %s, %s) RETURNING *""",
            (collection_id, body.name, Json(body.config), body.auth_header),
        )
        row = cur.fetchone()
        conn.commit()
    return row


@app.put("/api-param-configs/{config_id}", tags=["API Collections"])
def update_param_config(config_id: str, body: ParamConfigUpdate, _: bool = Depends(auth)):
    """Update a saved parameter configuration."""
    updates, vals = [], []
    if body.name is not None:
        updates.append("name = %s"); vals.append(body.name)
    if body.config is not None:
        updates.append("config = %s"); vals.append(Json(body.config))
    if body.auth_header is not None:
        updates.append("auth_header = %s"); vals.append(body.auth_header)
    if not updates:
        raise HTTPException(400, "No fields to update")
    vals.append(config_id)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"UPDATE api_param_configs SET {', '.join(updates)} WHERE id = %s RETURNING *", vals
        )
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Config not found")
    return row


@app.delete("/api-param-configs/{config_id}", tags=["API Collections"])
def delete_param_config(config_id: str, _: bool = Depends(auth)):
    """Delete a saved parameter configuration."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("DELETE FROM api_param_configs WHERE id = %s RETURNING id", (config_id,))
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(404, "Config not found")
    return {"ok": True}


@app.post("/api-collections/{collection_id}/param-configs/import", tags=["API Collections"])
def import_param_configs(collection_id: str, body: dict, _: bool = Depends(auth)):
    """Import parameter configurations from JSON export."""
    configs = body.get("configs", [])
    if not configs:
        raise HTTPException(400, "No configs to import")
    imported = []
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        for cfg in configs:
            name = cfg.get("name", "Imported Config")
            config_data = cfg.get("config", {})
            auth_hdr = cfg.get("auth_header")
            cur.execute(
                """INSERT INTO api_param_configs (collection_id, name, config, auth_header)
                   VALUES (%s, %s, %s, %s) RETURNING *""",
                (collection_id, name, Json(config_data), auth_hdr),
            )
            imported.append(cur.fetchone())
        conn.commit()
    return {"ok": True, "imported": len(imported), "configs": imported}


@app.post("/api-collections/{collection_id}/to-scope", tags=["API Collections"])
def collection_to_scope(collection_id: str, body: dict, _: bool = Depends(auth)):
    """Add all endpoints from a collection as URL targets in a named scope."""
    from urllib.parse import urlparse, urljoin

    scope_name = body.get("scope_name", "").strip()
    if not scope_name:
        raise HTTPException(status_code=400, detail="scope_name is required")

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get collection base_url
        cur.execute(
            "SELECT base_url FROM api_collections WHERE id = %s", (collection_id,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Collection not found")
        base_url = (row["base_url"] or "").rstrip("/")

        # Get all endpoints
        cur.execute(
            "SELECT method, path FROM api_endpoints WHERE collection_id = %s ORDER BY path",
            (collection_id,),
        )
        eps = cur.fetchall()
        if not eps:
            return {"ok": True, "added": 0, "total": 0, "scope_name": scope_name}

        # Also add the base host itself as a url target
        added = 0
        if base_url:
            cur.execute(
                """INSERT INTO scope_targets (name, target, target_type, source)
                   VALUES (%s, %s, 'url', 'swagger-import')
                   ON CONFLICT (name, target) DO NOTHING""",
                [scope_name, base_url],
            )
            added += cur.rowcount

        # Add each endpoint URL
        for ep in eps:
            path = ep["path"] or ""
            if base_url:
                url = f"{base_url}{path}"
            else:
                url = path
            cur.execute(
                """INSERT INTO scope_targets (name, target, target_type, source)
                   VALUES (%s, %s, 'url', 'swagger-import')
                   ON CONFLICT (name, target) DO NOTHING""",
                [scope_name, url],
            )
            added += cur.rowcount

        conn.commit()

    return {"ok": True, "added": added, "total": len(eps) + (1 if base_url else 0), "scope_name": scope_name}


@app.post("/api-test/run-all", tags=["API Test"])
def run_all_endpoints(body: RunAllRequest, _: bool = Depends(auth)):
    """Execute all endpoints in a collection using session auth and common variable values."""
    import time as _time
    import httpx

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM api_test_sessions WHERE id = %s", (body.session_id,))
        session = cur.fetchone()
        if not session:
            raise HTTPException(404, "Session not found")

        cur.execute("SELECT * FROM api_collections WHERE id = %s", (body.collection_id,))
        coll = cur.fetchone()
        if not coll:
            raise HTTPException(404, "Collection not found")

        base_url = (coll["base_url"] or "").rstrip("/")

        cur.execute(
            "SELECT * FROM api_endpoints WHERE collection_id = %s ORDER BY path, method",
            (body.collection_id,),
        )
        endpoints = cur.fetchall()

        # Merge session variables with request variables (request takes priority)
        variables = dict(session.get("variables") or {})
        if body.variables:
            variables.update(body.variables)

        results = []
        for ep in endpoints:
            # Resolve path params from variables
            path = ep["path"]
            params_dict: Dict[str, str] = {}
            for p in (ep["parameters"] or []):
                pname = p.get("name", "")
                if pname in variables:
                    params_dict[pname] = variables[pname]
                    if p.get("in") == "path":
                        path = path.replace(f"{{{pname}}}", str(variables[pname]))

            # Check for unresolved path params — skip endpoint if any remain
            import re as _re
            unresolved = _re.findall(r"\{(\w+)\}", path)
            if unresolved:
                results.append({
                    "endpoint_id": ep["id"],
                    "method": ep["method"],
                    "path": ep["path"],
                    "status": "skipped",
                    "reason": f"Unresolved path params: {', '.join(unresolved)}",
                })
                continue

            url = f"{base_url}{path}"

            # Query params
            query_params = {}
            for p in (ep["parameters"] or []):
                if p.get("in") == "query" and p["name"] in variables:
                    query_params[p["name"]] = variables[p["name"]]

            # Headers
            req_headers: Dict[str, str] = {}
            if session.get("jwt_token"):
                req_headers["Authorization"] = f"Bearer {session['jwt_token']}"
            for p in (ep["parameters"] or []):
                if p.get("in") == "header" and p["name"] in variables:
                    req_headers[p["name"]] = variables[p["name"]]
            if body.headers:
                req_headers.update(body.headers)

            # Body — build from variables for fields in request_body
            req_body = None
            rb = ep.get("request_body")
            if rb and isinstance(rb, dict) and ep["method"] in ("POST", "PUT", "PATCH"):
                body_fields = {}
                for field in (rb.get("fields") or []):
                    fname = field.get("name", "")
                    if fname in variables:
                        body_fields[fname] = variables[fname]
                if body_fields:
                    req_body = json.dumps(body_fields)
                    req_headers.setdefault("Content-Type", "application/json")

            # Execute
            proxy_url = session.get("proxy_url")
            error_msg = None
            status_code = None
            response_headers = {}
            response_body = ""
            start = _time.time()

            try:
                client_kwargs: Dict[str, Any] = {"timeout": 30.0, "verify": False}
                if proxy_url:
                    client_kwargs["proxy"] = proxy_url
                with httpx.Client(**client_kwargs) as client:
                    resp = client.request(
                        method=ep["method"],
                        url=url,
                        params=query_params or None,
                        headers=req_headers,
                        content=req_body,
                    )
                    status_code = resp.status_code
                    response_headers = dict(resp.headers)
                    response_body = resp.text[:50000]
            except Exception as e:
                error_msg = str(e)

            duration_ms = int((_time.time() - start) * 1000)

            # Store result
            cur.execute("""
                INSERT INTO api_test_results
                    (session_id, endpoint_id, method, url, request_headers, request_body,
                     status_code, response_headers, response_body, duration_ms, error)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, status_code, duration_ms, error
            """, (
                body.session_id, ep["id"], ep["method"], url,
                Json(req_headers), req_body,
                status_code, Json(response_headers), response_body,
                duration_ms, error_msg,
            ))
            row = cur.fetchone()
            conn.commit()

            results.append({
                "endpoint_id": ep["id"],
                "method": ep["method"],
                "path": ep["path"],
                "url": url,
                "status": "ok",
                "status_code": status_code,
                "duration_ms": duration_ms,
                "error": error_msg,
                "result_id": row["id"] if row else None,
            })

    return {
        "ok": True,
        "total": len(endpoints),
        "executed": sum(1 for r in results if r["status"] == "ok"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
        "results": results,
    }


# ============================================================================
# Sync — Multi-node offline/online collaboration
# ============================================================================

SYNC_TABLES = [
    "assets", "ports", "vulns", "web_findings", "recon_findings",
    "finding_activity", "evidence_store", "credential_vault",
    "campaign_events", "engagements",
]


@app.post("/sync/register-node", tags=["Sync"])
def register_sync_node(
    node_id: str = Query(...),
    node_name: str = Query(...),
    owner: str = Query(None),
    is_remote: bool = Query(False),
    authorized: bool = Depends(auth),
):
    """Register a sync node (each machine/user that participates)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """INSERT INTO sync_nodes (node_id, node_name, owner, is_remote)
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (node_id) DO UPDATE SET node_name = EXCLUDED.node_name, owner = EXCLUDED.owner, is_remote = EXCLUDED.is_remote
               RETURNING *""",
            (node_id, node_name, owner, is_remote),
        )
        node = dict(cur.fetchone())
        # Initialize sync state if not exists
        for direction in ("push", "pull"):
            cur.execute(
                """INSERT INTO sync_state (node_id, direction, last_lsn)
                   VALUES (%s, %s, 0)
                   ON CONFLICT DO NOTHING""",
                (node_id, direction),
            )
        conn.commit()
    return {"node": node}


@app.get("/sync/nodes", tags=["Sync"])
def list_sync_nodes(authorized: bool = Depends(auth)):
    """List all registered sync nodes."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM sync_nodes ORDER BY created_at")
        nodes = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM sync_state ORDER BY node_id")
        states = [dict(r) for r in cur.fetchall()]
    return {"nodes": nodes, "states": states}


@app.get("/sync/status", tags=["Sync"])
def sync_status(node_id: str = Query("local"), authorized: bool = Depends(auth)):
    """Get sync status: pending changes, last sync times, conflict count."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get last push LSN for this node
        cur.execute(
            "SELECT last_lsn FROM sync_state WHERE node_id = %s AND direction = 'push'",
            (node_id,),
        )
        row = cur.fetchone()
        last_push_lsn = row["last_lsn"] if row else 0

        # Count pending changes (local changes not yet pushed)
        cur.execute(
            "SELECT count(*) AS cnt FROM sync_log WHERE lsn > %s AND node_id = %s",
            (last_push_lsn, node_id),
        )
        pending_push = cur.fetchone()["cnt"]

        # Total log entries
        cur.execute("SELECT count(*) AS cnt, max(lsn) AS max_lsn FROM sync_log")
        log_info = cur.fetchone()

        # Pending conflicts
        cur.execute(
            "SELECT count(*) AS cnt FROM sync_conflicts WHERE resolution = 'pending'"
        )
        pending_conflicts = cur.fetchone()["cnt"]

        # Per-table change counts since last push (same node_id filter as pending_push)
        cur.execute(
            """SELECT table_name, operation, count(*) AS cnt
               FROM sync_log WHERE lsn > %s AND node_id = %s
               GROUP BY table_name, operation
               ORDER BY table_name, operation""",
            (last_push_lsn, node_id),
        )
        changes_by_table = [dict(r) for r in cur.fetchall()]

    return {
        "node_id": node_id,
        "pending_push": pending_push,
        "pending_conflicts": pending_conflicts,
        "total_log_entries": log_info["cnt"],
        "max_lsn": log_info["max_lsn"],
        "last_push_lsn": last_push_lsn,
        "changes_by_table": changes_by_table,
    }


@app.get("/sync/changes", tags=["Sync"])
def get_sync_changes(
    since_lsn: int = Query(0),
    limit: int = Query(1000, le=10000),
    table: str = Query(None),
    authorized: bool = Depends(auth),
):
    """Fetch change log entries since a given LSN (for pull)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if table and table in SYNC_TABLES:
            cur.execute(
                """SELECT lsn, table_name, row_id, operation, node_id, changed_by,
                          changed_at, row_data, old_data
                   FROM sync_log WHERE lsn > %s AND table_name = %s
                   ORDER BY lsn LIMIT %s""",
                (since_lsn, table, limit),
            )
        else:
            cur.execute(
                """SELECT lsn, table_name, row_id, operation, node_id, changed_by,
                          changed_at, row_data, old_data
                   FROM sync_log WHERE lsn > %s
                   ORDER BY lsn LIMIT %s""",
                (since_lsn, limit),
            )
        changes = [dict(r) for r in cur.fetchall()]

    return {
        "since_lsn": since_lsn,
        "count": len(changes),
        "has_more": len(changes) == limit,
        "changes": changes,
    }


@app.post("/sync/apply", tags=["Sync"])
def apply_sync_changes(
    node_id: str = Query(...),
    strategy: str = Query("last_write_wins", regex="^(last_write_wins|remote_wins|local_wins|manual)$"),
    authorized: bool = Depends(auth),
    body: dict = Body(...),
):
    """Apply a batch of changes from a remote node.

    Body: {"changes": [{"table_name", "row_id", "operation", "row_data", "old_data", "changed_at", "changed_by"}]}

    Conflict resolution strategies:
    - last_write_wins: newer changed_at wins
    - remote_wins: incoming changes always win
    - local_wins: local changes always win (conflicts logged only)
    - manual: conflicts saved for manual resolution
    """
    changes = body.get("changes", [])
    applied = 0
    conflicts = 0
    skipped = 0

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Set session variables so triggers attribute changes to the remote node
        cur.execute("SET LOCAL app.node_id = %s", (node_id,))
        cur.execute("SET LOCAL app.user_id = %s", (f"sync:{node_id}",))

        for change in changes:
            tbl = change.get("table_name")
            if tbl not in SYNC_TABLES:
                skipped += 1
                continue

            row_id = change.get("row_id")
            op = change.get("operation")
            row_data = change.get("row_data")
            changed_at = change.get("changed_at")

            # Check for conflict (local row modified since remote's base)
            if op in ("UPDATE", "DELETE"):
                cur.execute(
                    f"SELECT modified_at, node_id FROM {tbl} WHERE id = %s",
                    (row_id,),
                )
                local_row = cur.fetchone()

                if local_row and local_row.get("modified_at") and changed_at:
                    from datetime import datetime, timezone
                    local_ts = local_row["modified_at"]
                    try:
                        remote_ts = datetime.fromisoformat(changed_at) if isinstance(changed_at, str) else changed_at
                    except (ValueError, TypeError):
                        remote_ts = None

                    if remote_ts and local_row.get("node_id") != node_id and local_ts > remote_ts:
                        # Conflict detected
                        if strategy == "local_wins":
                            # Log conflict but keep local
                            cur.execute(
                                """INSERT INTO sync_conflicts
                                   (table_name, row_id, local_data, remote_data,
                                    local_changed_at, remote_changed_at, resolution, resolved_at)
                                   VALUES (%s, %s, to_jsonb(%s::text), %s, %s, %s, 'local_wins', now())""",
                                (tbl, row_id, row_id, json.dumps(row_data), local_ts, remote_ts),
                            )
                            conflicts += 1
                            continue
                        elif strategy == "manual":
                            cur.execute(
                                """INSERT INTO sync_conflicts
                                   (table_name, row_id, local_data, remote_data,
                                    local_changed_at, remote_changed_at, resolution)
                                   VALUES (%s, %s, to_jsonb(%s::text), %s, %s, %s, 'pending')""",
                                (tbl, row_id, row_id, json.dumps(row_data), local_ts, remote_ts),
                            )
                            conflicts += 1
                            continue
                        # else last_write_wins / remote_wins: proceed with apply

            try:
                if op == "INSERT":
                    if row_data:
                        # Use ON CONFLICT to handle existing rows (upsert)
                        cols = [k for k in row_data.keys() if k != "id"]
                        vals = [row_data[k] for k in cols]
                        col_str = ", ".join(cols)
                        ph = ", ".join(["%s"] * len(vals))
                        update_str = ", ".join([f"{c} = EXCLUDED.{c}" for c in cols])
                        cur.execute(
                            f"INSERT INTO {tbl} (id, {col_str}) VALUES (%s, {ph}) "
                            f"ON CONFLICT (id) DO UPDATE SET {update_str}",
                            [row_id] + vals,
                        )
                        applied += 1

                elif op == "UPDATE":
                    if row_data:
                        # Update only the columns present in row_data
                        cols = [k for k in row_data.keys() if k != "id"]
                        sets = ", ".join([f"{c} = %s" for c in cols])
                        vals = [row_data[k] for k in cols]
                        cur.execute(
                            f"UPDATE {tbl} SET {sets} WHERE id = %s",
                            vals + [row_id],
                        )
                        applied += 1

                elif op == "DELETE":
                    cur.execute(f"DELETE FROM {tbl} WHERE id = %s", (row_id,))
                    applied += 1

            except Exception as e:
                import logging
                logging.warning(f"Sync apply error on {tbl}/{row_id}: {e}")
                skipped += 1
                conn.rollback()
                continue

        # Update sync state
        cur.execute(
            """INSERT INTO sync_state (node_id, direction, last_sync_at)
               VALUES (%s, 'pull', now())
               ON CONFLICT (node_id, direction) DO UPDATE SET last_sync_at = now()""",
            (node_id,),
        )
        # Update node last_sync
        cur.execute(
            "UPDATE sync_nodes SET last_sync = now() WHERE node_id = %s",
            (node_id,),
        )
        conn.commit()

    return {
        "applied": applied,
        "conflicts": conflicts,
        "skipped": skipped,
        "total": len(changes),
    }


@app.post("/sync/push", tags=["Sync"])
def push_changes(
    node_id: str = Query(...),
    authorized: bool = Depends(auth),
):
    """Get all local changes since last push for this node (to send to remote)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT last_lsn FROM sync_state WHERE node_id = %s AND direction = 'push'",
            (node_id,),
        )
        row = cur.fetchone()
        last_lsn = row["last_lsn"] if row else 0

        # Get changes made by this node since last push
        cur.execute(
            """SELECT lsn, table_name, row_id, operation, node_id, changed_by,
                      changed_at, row_data, old_data
               FROM sync_log WHERE lsn > %s AND node_id = %s
               ORDER BY lsn""",
            (last_lsn, node_id),
        )
        changes = [dict(r) for r in cur.fetchall()]
        max_lsn = changes[-1]["lsn"] if changes else last_lsn

        # Update push watermark
        cur.execute(
            """INSERT INTO sync_state (node_id, direction, last_lsn, last_sync_at)
               VALUES (%s, 'push', %s, now())
               ON CONFLICT (node_id, direction)
               DO UPDATE SET last_lsn = EXCLUDED.last_lsn, last_sync_at = now()""",
            (node_id, max_lsn),
        )
        conn.commit()

    return {
        "node_id": node_id,
        "since_lsn": last_lsn,
        "max_lsn": max_lsn,
        "count": len(changes),
        "changes": changes,
    }


@app.get("/sync/conflicts", tags=["Sync"])
def list_sync_conflicts(
    status: str = Query("pending"),
    limit: int = Query(50, le=200),
    authorized: bool = Depends(auth),
):
    """List sync conflicts, defaulting to pending ones."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT * FROM sync_conflicts
               WHERE resolution = %s
               ORDER BY created_at DESC LIMIT %s""",
            (status, limit),
        )
        conflicts = [dict(r) for r in cur.fetchall()]
    return {"conflicts": conflicts, "count": len(conflicts)}


@app.patch("/sync/conflicts/{conflict_id}", tags=["Sync"])
def resolve_sync_conflict(
    conflict_id: str,
    resolution: str = Query(..., regex="^(local_wins|remote_wins)$"),
    resolved_by: str = Query("user"),
    authorized: bool = Depends(auth),
):
    """Resolve a sync conflict by choosing local or remote data."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM sync_conflicts WHERE id = %s",
            (conflict_id,),
        )
        conflict = cur.fetchone()
        if not conflict:
            raise HTTPException(404, "Conflict not found")

        if resolution == "remote_wins" and conflict["remote_data"]:
            # Apply the remote data
            tbl = conflict["table_name"]
            row_id = conflict["row_id"]
            row_data = conflict["remote_data"] if isinstance(conflict["remote_data"], dict) else {}
            if row_data:
                cols = [k for k in row_data.keys() if k != "id"]
                sets = ", ".join([f"{c} = %s" for c in cols])
                vals = [row_data[k] for k in cols]
                cur.execute(f"UPDATE {tbl} SET {sets} WHERE id = %s", vals + [row_id])

        cur.execute(
            """UPDATE sync_conflicts
               SET resolution = %s, resolved_at = now(), resolved_by = %s
               WHERE id = %s""",
            (resolution, resolved_by, conflict_id),
        )
        conn.commit()
    return {"ok": True, "resolution": resolution}


@app.post("/sync/snapshot", tags=["Sync"])
def create_sync_snapshot(
    node_id: str = Query(...),
    tables: str = Query(None, description="Comma-separated table names, or all"),
    authorized: bool = Depends(auth),
):
    """Create a full snapshot of specified tables for initial sync / offline pull.

    Returns all rows from requested tables (or all tracked tables).
    Use this for the initial pull when a node first connects.
    """
    target_tables = SYNC_TABLES
    if tables:
        requested = [t.strip() for t in tables.split(",")]
        target_tables = [t for t in requested if t in SYNC_TABLES]

    snapshot = {}
    total_rows = 0
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        for tbl in target_tables:
            cur.execute(f"SELECT * FROM {tbl}")
            rows = [dict(r) for r in cur.fetchall()]
            snapshot[tbl] = rows
            total_rows += len(rows)

        # Record the current max LSN as the pull watermark
        cur.execute("SELECT COALESCE(max(lsn), 0) AS max_lsn FROM sync_log")
        max_lsn = cur.fetchone()["max_lsn"]

        cur.execute(
            """INSERT INTO sync_state (node_id, direction, last_lsn, last_sync_at)
               VALUES (%s, 'pull', %s, now())
               ON CONFLICT (node_id, direction)
               DO UPDATE SET last_lsn = EXCLUDED.last_lsn, last_sync_at = now()""",
            (node_id, max_lsn),
        )
        conn.commit()

    return {
        "node_id": node_id,
        "tables": list(snapshot.keys()),
        "total_rows": total_rows,
        "max_lsn": max_lsn,
        "snapshot": snapshot,
    }


@app.get("/sync/table-stats", tags=["Sync"])
def sync_table_stats(authorized: bool = Depends(auth)):
    """Return row counts and latest modified_at per sync table for DB comparison."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        stats = {}
        for table in SYNC_TABLES:
            try:
                cur.execute(f"SELECT count(*) AS cnt FROM {table}")
                cnt = cur.fetchone()["cnt"]
                # Try to get latest modified_at if column exists
                latest = None
                try:
                    cur.execute(
                        f"SELECT max(modified_at)::text AS latest FROM {table}"
                    )
                    row = cur.fetchone()
                    latest = row["latest"] if row else None
                except Exception:
                    conn.rollback()
                stats[table] = {"count": cnt, "latest_modified": latest}
            except Exception:
                conn.rollback()
                stats[table] = {"count": 0, "latest_modified": None, "error": "table not found"}
        # Also get sync log stats
        try:
            cur.execute("SELECT COALESCE(max(lsn), 0) AS max_lsn, count(*) AS log_entries FROM sync_log")
            row = cur.fetchone()
            sync_info = {"max_lsn": row["max_lsn"], "log_entries": row["log_entries"]}
        except Exception:
            sync_info = {"max_lsn": 0, "log_entries": 0}
        return {"tables": stats, "sync": sync_info}


# ============================================================================
# FINDINGS EXCHANGE FORMAT (Burp Suite Bridge)
# ============================================================================

@app.get("/export/findings-exchange", tags=["Exchange"])
def export_findings_exchange(
    target: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None, description="Comma-separated sources to include (e.g. zap,nikto,nuclei)"),
    exclude_sources: Optional[str] = Query(None, description="Comma-separated sources to exclude (e.g. vulscan,vulners)"),
    web_only: bool = Query(False, description="Only include web findings (exclude nmap vulns)"),
    limit: int = Query(500, le=2000),
    _: bool = Depends(auth),
):
    """Export findings in the exchange format for Burp Suite import."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        findings = []
        include_sources = [s.strip().lower() for s in source.split(",")] if source else None
        exclude_list = [s.strip().lower() for s in exclude_sources.split(",")] if exclude_sources else []

        # Web findings (ZAP, Nikto, Nuclei, etc.)
        clauses, params = [], []
        if target:
            clauses.append("wf.url LIKE %s")
            params.append(f"%{target}%")
        if severity:
            clauses.append("wf.severity = %s")
            params.append(severity)
        if include_sources:
            clauses.append("LOWER(wf.source) = ANY(%s)")
            params.append(include_sources)
        if exclude_list:
            clauses.append("LOWER(wf.source) != ALL(%s)")
            params.append(exclude_list)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        cur.execute(f"""
            SELECT wf.id, wf.url, wf.source, wf.name, wf.issue_type, wf.severity,
                   wf.evidence, wf.method, wf.description, wf.solution, wf.confidence,
                   wf.status_code, wf.payload
            FROM web_findings wf {where}
            ORDER BY CASE wf.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                     WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
            LIMIT %s
        """, params)

        for row in cur.fetchall():
            finding = {
                "id": str(row["id"]),
                "type": row.get("issue_type") or "web_finding",
                "name": row.get("name") or "Unnamed Finding",
                "url": row.get("url", ""),
                "method": row.get("method") or "GET",
                "severity": row.get("severity") or "info",
                "confidence": row.get("confidence") or "tentative",
                "evidence": [row["evidence"]] if row.get("evidence") else [],
                "source": row.get("source") or "unknown",
            }
            if row.get("description"):
                finding["description"] = row["description"]
            if row.get("solution"):
                finding["remediation"] = row["solution"]
            if row.get("status_code"):
                finding["status_code"] = row["status_code"]
            if row.get("payload"):
                finding["payload"] = row["payload"]

            # Build synthetic request from finding data
            if False:
                pass  # placeholder for future request_data column
            else:
                parsed_url = row.get("url", "")
                method = row.get("method") or "GET"
                if parsed_url:
                    from urllib.parse import urlparse
                    p = urlparse(parsed_url)
                    host = p.netloc or p.hostname or ""
                    path = p.path or "/"
                    query = f"?{p.query}" if p.query else ""
                    req_lines = [f"{method} {path}{query} HTTP/1.1",
                                 f"Host: {host}", "User-Agent: RAG-Scan-Stack/1.0",
                                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                 "Accept-Language: en-US,en;q=0.5", "Connection: close"]
                    payload_data = row.get("payload") or ""
                    if method in ("POST", "PUT", "PATCH") and payload_data:
                        req_lines.extend(["Content-Type: application/x-www-form-urlencoded",
                                          f"Content-Length: {len(payload_data)}", "", payload_data])
                    else:
                        req_lines.extend(["", ""])
                    finding["request_raw"] = "\r\n".join(req_lines)

            # Build synthetic response
            if False:
                pass  # placeholder for future response_data column
            else:
                status = row.get("status_code") or 200
                status_text = {200: "OK", 301: "Moved Permanently", 302: "Found",
                               403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}.get(status, "OK")
                evidence_text = row.get("evidence") or ""
                resp_lines = [f"HTTP/1.1 {status} {status_text}",
                              "Content-Type: text/html; charset=utf-8",
                              "Server: Apache/2.2.8 (Ubuntu)", "Connection: close", ""]
                resp_lines.append(f"<!-- Evidence: {evidence_text[:500]} -->" if evidence_text else "")
                finding["response_raw"] = "\r\n".join(resp_lines)

            findings.append(finding)

        # Vulns (nmap/nuclei/ssh-audit/sslscan/etc) -- skip if web_only
        if not web_only:
            v_clauses, v_params = [], []
            if target:
                v_clauses.append("host(a.ip)::text LIKE %s")
                v_params.append(f"%{target}%")
            if severity:
                v_clauses.append("v.severity = %s")
                v_params.append(severity)
            # Filter vulns by source using the same tool detection logic
            if include_sources:
                source_conditions = []
                for src in include_sources:
                    source_conditions.append("v.script LIKE %s")
                    v_params.append(f"{src}:%%")
                    source_conditions.append("v.metadata->>'tool' = %s")
                    v_params.append(src)
                v_clauses.append("(" + " OR ".join(source_conditions) + ")")
            if exclude_list:
                for src in exclude_list:
                    v_clauses.append("v.script NOT LIKE %s")
                    v_params.append(f"{src}:%%")
            v_where = f"WHERE {' AND '.join(v_clauses)}" if v_clauses else ""
            v_params.append(limit)

            cur.execute(f"""
                SELECT v.id, v.script, v.output, v.severity, v.cve, v.title,
                       host(a.ip)::text as ip, p.port, p.service, v.metadata
                FROM vulns v
                JOIN assets a ON v.asset_id = a.id
                LEFT JOIN ports p ON v.port_id = p.id
                {v_where}
                LIMIT %s
            """, v_params)

            for row in cur.fetchall():
                ip = row.get("ip", "")
                port = row.get("port", "")
                service = row.get("service", "")
                url = f"https://{ip}:{port}/" if port else f"https://{ip}/"

                # Detect source tool from metadata or script prefix
                meta = row.get("metadata") or {}
                if isinstance(meta, str):
                    import json as _json
                    try: meta = _json.loads(meta)
                    except: meta = {}
                vuln_source = meta.get("tool") or (row.get("script", "").split(":")[0] if ":" in row.get("script", "") else "nmap")

                finding = {
                    "id": str(row["id"]),
                    "type": "vulnerability",
                    "name": row.get("title") or f"{row.get('script', 'vuln')} on {service}:{port}",
                    "url": url,
                    "severity": row.get("severity") or "info",
                    "confidence": "firm",
                    "evidence": [row.get("output", "")[:500]],
                    "source": vuln_source,
                }
                if row.get("cve"):
                    finding["cve"] = row["cve"]

                # Build service probe request/response for vulns
                finding["request_raw"] = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {ip}:{port}\r\n"
                    f"User-Agent: RAG-Scan-Stack/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                output = row.get("output", "")[:1000]
                finding["response_raw"] = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Server: {service or 'unknown'}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"<!-- {vuln_source} {row.get('script','')} output:\r\n{output}\r\n-->"
                )
                findings.append(finding)

    return {
        "target": target or "all",
        "total": len(findings),
        "findings": findings,
    }


class FindingsExchangeImport(BaseModel):
    source: str = "burpsuite"
    findings: list


@app.post("/import/findings-exchange", tags=["Exchange"])
def import_findings_exchange(body: FindingsExchangeImport, _: bool = Depends(auth)):
    """Import findings from Burp Suite or other tools in exchange format."""
    imported = 0
    skipped = 0

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        for f in body.findings:
            url = f.get("url", "")
            name = f.get("name", "Unnamed")
            severity = f.get("severity", "info")

            # Dedup: check if finding with same URL + name + source exists
            cur.execute(
                "SELECT id FROM web_findings WHERE url = %s AND name = %s AND source = %s LIMIT 1",
                (url, name, body.source)
            )
            if cur.fetchone():
                skipped += 1
                continue

            # Extract evidence text
            evidence = ""
            ev = f.get("evidence", [])
            if isinstance(ev, list):
                evidence = "\n".join(str(e) for e in ev)
            elif isinstance(ev, str):
                evidence = ev

            cur.execute("""
                INSERT INTO web_findings
                    (url, source, name, issue_type, severity, evidence, method,
                     description, confidence, status_code, payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                url, body.source, name,
                f.get("type", "imported"),
                severity, evidence,
                f.get("method"),
                f.get("description"),
                f.get("confidence"),
                f.get("status_code"),
                f.get("payload"),
            ))
            imported += 1

        conn.commit()

    return {
        "ok": True,
        "source": body.source,
        "imported": imported,
        "skipped": skipped,
        "total": len(body.findings),
    }


# ============================================================================
# SCAN PIPELINES (multi-stage parallel orchestration)
# ============================================================================

class PipelineCreate(BaseModel):
    engagement_id: str
    name: str = "default"
    profile: str = "pentest"
    scope_name: Optional[str] = None
    config: Optional[Dict[str, Any]] = None  # skip_stages, rate overrides, max_parallel, proxy, etc.


class PipelineJobRecord(BaseModel):
    pipeline_id: str
    job_id: str
    host: Optional[str] = None
    stage: int = 0
    scan_type: str
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None


@app.post("/pipelines", tags=["Pipelines"])
def create_pipeline(body: PipelineCreate, _: bool = Depends(auth)):
    """Create a scan pipeline for an engagement's scope targets."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Load targets from scope
        if body.scope_name:
            cur.execute("""
                SELECT target FROM scope_targets
                WHERE engagement_id = %s::uuid AND name = %s AND target <> ''
                ORDER BY added_at
            """, (body.engagement_id, body.scope_name))
        else:
            cur.execute("""
                SELECT DISTINCT target FROM scope_targets
                WHERE engagement_id = %s::uuid AND target <> ''
                ORDER BY target
            """, (body.engagement_id,))
        targets = [r["target"] for r in cur.fetchall()]

        if not targets:
            raise HTTPException(400, "No targets in scope — add targets before creating a pipeline")

        config = body.config or {}
        config["profile"] = body.profile
        if body.scope_name:
            config["scope_name"] = body.scope_name

        # Initialize per-host states
        host_states = {t: {"stage": 0, "status": "pending", "jobs": []} for t in targets}

        cur.execute("""
            INSERT INTO scan_pipelines (engagement_id, name, profile, config, targets, target_count, host_states)
            VALUES (%s::uuid, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at
        """, (body.engagement_id, body.name, body.profile,
              Json(config), Json(targets), len(targets), Json(host_states)))
        row = cur.fetchone()
    return {
        "ok": True,
        "pipeline_id": str(row["id"]),
        "target_count": len(targets),
        "targets": targets[:20],
        "profile": body.profile,
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


@app.get("/pipelines/{pipeline_id}", tags=["Pipelines"])
def get_pipeline(pipeline_id: str, _: bool = Depends(auth)):
    """Get pipeline status + per-host progress."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM scan_pipelines WHERE id = %s::uuid", (pipeline_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Pipeline not found")
    for k in ("id", "engagement_id"):
        if row.get(k):
            row[k] = str(row[k])
    for k in ("created_at", "updated_at", "completed_at"):
        if row.get(k):
            row[k] = row[k].isoformat()
    return row


@app.get("/pipelines/{pipeline_id}/jobs", tags=["Pipelines"])
def list_pipeline_jobs(pipeline_id: str, stage: Optional[int] = Query(None),
                       host: Optional[str] = Query(None),
                       _: bool = Depends(auth)):
    """List all jobs spawned by a pipeline, optionally filtered by stage or host."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        clauses = ["pipeline_id = %s::uuid"]
        params: list = [pipeline_id]
        if stage is not None:
            clauses.append("stage = %s")
            params.append(stage)
        if host:
            clauses.append("host = %s")
            params.append(host)
        where = " AND ".join(clauses)
        cur.execute(f"SELECT * FROM scan_pipeline_jobs WHERE {where} ORDER BY created_at", params)
        rows = cur.fetchall()
    for r in rows:
        for k in ("id", "pipeline_id"):
            if r.get(k):
                r[k] = str(r[k])
        for k in ("created_at", "completed_at"):
            if r.get(k):
                r[k] = r[k].isoformat()
    return {"jobs": rows, "count": len(rows)}


@app.patch("/pipelines/{pipeline_id}", tags=["Pipelines"])
def update_pipeline(pipeline_id: str, body: dict = Body(...), _: bool = Depends(auth)):
    """Update pipeline status, progress, host_states, counters."""
    allowed = {"status", "progress", "host_states", "jobs_spawned", "jobs_completed",
               "jobs_failed", "findings_count", "error", "completed_at"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        raise HTTPException(400, "No valid fields to update")
    sets = []
    params = []
    for k, v in updates.items():
        if k in ("progress", "host_states"):
            sets.append(f"{k} = %s::jsonb")
            params.append(Json(v) if not isinstance(v, str) else v)
        elif k == "completed_at":
            sets.append(f"{k} = %s::timestamptz")
            params.append(v)
        else:
            sets.append(f"{k} = %s")
            params.append(v)
    sets.append("updated_at = now()")
    params.append(pipeline_id)
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(f"UPDATE scan_pipelines SET {', '.join(sets)} WHERE id = %s::uuid", params)
        if cur.rowcount == 0:
            raise HTTPException(404, "Pipeline not found")
    return {"ok": True}


@app.post("/pipelines/{pipeline_id}/jobs", tags=["Pipelines"])
def record_pipeline_job(pipeline_id: str, body: PipelineJobRecord, _: bool = Depends(auth)):
    """Record a job spawned by a pipeline."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO scan_pipeline_jobs (pipeline_id, job_id, host, stage, scan_type, status, result)
            VALUES (%s::uuid, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (pipeline_id, job_id) DO UPDATE SET status = EXCLUDED.status, result = EXCLUDED.result
            RETURNING id
        """, (pipeline_id, body.job_id, body.host, body.stage, body.scan_type,
              body.status, Json(body.result) if body.result else None))
        row = cur.fetchone()
    return {"ok": True, "id": str(row["id"]) if row else None}


@app.patch("/pipelines/{pipeline_id}/jobs/{job_id}", tags=["Pipelines"])
def update_pipeline_job(pipeline_id: str, job_id: str, body: dict = Body(...),
                         _: bool = Depends(auth)):
    """Update a pipeline job's status/result."""
    with get_db() as conn, conn.cursor() as cur:
        sets = []
        params = []
        if "status" in body:
            sets.append("status = %s")
            params.append(body["status"])
        if "result" in body:
            sets.append("result = %s::jsonb")
            params.append(Json(body["result"]) if body["result"] else None)
        if body.get("status") in ("completed", "failed", "stopped"):
            sets.append("completed_at = now()")
        if not sets:
            raise HTTPException(400, "No fields to update")
        params.extend([pipeline_id, job_id])
        cur.execute(
            f"UPDATE scan_pipeline_jobs SET {', '.join(sets)} WHERE pipeline_id = %s::uuid AND job_id = %s",
            params,
        )
    return {"ok": True}


@app.get("/pipelines", tags=["Pipelines"])
def list_pipelines(engagement_id: Optional[str] = Query(None),
                   status: Optional[str] = Query(None),
                   limit: int = Query(50, le=200),
                   _: bool = Depends(auth)):
    """List pipelines, optionally filtered by engagement or status."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        clauses = ["TRUE"]
        params: list = []
        if engagement_id:
            clauses.append("engagement_id = %s::uuid")
            params.append(engagement_id)
        if status:
            clauses.append("status = %s")
            params.append(status)
        params.append(limit)
        cur.execute(f"""
            SELECT id, engagement_id, name, status, profile, target_count,
                   jobs_spawned, jobs_completed, jobs_failed, findings_count,
                   created_at, updated_at, completed_at
            FROM scan_pipelines WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC LIMIT %s
        """, params)
        rows = cur.fetchall()
    for r in rows:
        for k in ("id", "engagement_id"):
            if r.get(k):
                r[k] = str(r[k])
        for k in ("created_at", "updated_at", "completed_at"):
            if r.get(k):
                r[k] = r[k].isoformat()
    return {"pipelines": rows}


@app.post("/pipelines/{pipeline_id}/stop", tags=["Pipelines"])
def stop_pipeline(pipeline_id: str, _: bool = Depends(auth)):
    """Mark pipeline as stopped."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE scan_pipelines SET status = 'stopped', updated_at = now(), completed_at = now()
            WHERE id = %s::uuid AND status IN ('pending', 'running')
        """, (pipeline_id,))
        if cur.rowcount == 0:
            raise HTTPException(400, "Pipeline not found or already terminal")
    return {"ok": True, "pipeline_id": pipeline_id, "status": "stopped"}


# ============================================================================
# RECON AGENT STATE + SCOPE COVERAGE
# ============================================================================

@app.get("/recon-agent/{eid}", tags=["ReconAgent"])
def get_recon_agent_state(eid: str, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM recon_agent_state WHERE engagement_id = %s::uuid", (eid,))
        row = cur.fetchone()
    if not row:
        return {"engagement_id": eid, "enabled": False, "interval_sec": 300,
                "config": {}, "stats": {}, "exists": False}
    for k in ("engagement_id",):
        if row.get(k): row[k] = str(row[k])
    for k in ("last_run_at", "last_scan_at", "last_dispatch_at", "pause_until", "created_at", "updated_at"):
        if row.get(k): row[k] = row[k].isoformat()
    row["exists"] = True
    return row


@app.post("/recon-agent/{eid}/enable", tags=["ReconAgent"])
def enable_recon_agent(eid: str, body: dict = Body(default={}), _: bool = Depends(auth)):
    interval = int(body.get("interval_sec", 300))
    config = body.get("config", {})
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO recon_agent_state (engagement_id, enabled, interval_sec, config)
            VALUES (%s::uuid, true, %s, %s)
            ON CONFLICT (engagement_id) DO UPDATE
            SET enabled = true, interval_sec = EXCLUDED.interval_sec,
                config = EXCLUDED.config, pause_until = NULL, updated_at = now()
        """, (eid, interval, Json(config)))
    return {"ok": True, "engagement_id": eid, "enabled": True}


@app.post("/recon-agent/{eid}/disable", tags=["ReconAgent"])
def disable_recon_agent(eid: str, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE recon_agent_state SET enabled = false, updated_at = now()
            WHERE engagement_id = %s::uuid
        """, (eid,))
    return {"ok": True, "engagement_id": eid, "enabled": False}


@app.post("/recon-agent/{eid}/pause", tags=["ReconAgent"])
def pause_recon_agent(eid: str, minutes: int = Query(60), _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE recon_agent_state
            SET pause_until = now() + make_interval(mins := %s), updated_at = now()
            WHERE engagement_id = %s::uuid
        """, (minutes, eid))
    return {"ok": True, "paused_minutes": minutes}


@app.patch("/recon-agent/{eid}", tags=["ReconAgent"])
def update_recon_agent_state(eid: str, body: dict = Body(...), _: bool = Depends(auth)):
    allowed = {"interval_sec", "config", "stats", "last_run_at", "last_scan_at",
               "last_dispatch_at", "pause_until", "enabled"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        raise HTTPException(400, "No valid fields")
    sets, params = [], []
    for k, v in updates.items():
        if k in ("config", "stats"):
            sets.append(f"{k} = %s::jsonb")
            params.append(Json(v) if not isinstance(v, str) else v)
        elif k in ("last_run_at", "last_scan_at", "last_dispatch_at", "pause_until"):
            sets.append(f"{k} = %s::timestamptz")
            params.append(v)
        else:
            sets.append(f"{k} = %s")
            params.append(v)
    sets.append("updated_at = now()")
    params.append(eid)
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(f"UPDATE recon_agent_state SET {', '.join(sets)} WHERE engagement_id = %s::uuid", params)
    return {"ok": True}


@app.get("/recon-agent/{eid}/coverage", tags=["ReconAgent"])
def get_scope_coverage(eid: str, target: Optional[str] = Query(None), _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if target:
            cur.execute("""
                SELECT * FROM scope_coverage
                WHERE engagement_id = %s::uuid AND target = %s
                ORDER BY stage, scan_type
            """, (eid, target))
        else:
            cur.execute("""
                SELECT * FROM scope_coverage
                WHERE engagement_id = %s::uuid
                ORDER BY target, stage, scan_type
            """, (eid,))
        rows = cur.fetchall()
    for r in rows:
        for k in ("id", "engagement_id"):
            if r.get(k): r[k] = str(r[k])
        for k in ("started_at", "completed_at"):
            if r.get(k): r[k] = r[k].isoformat()
    return {"coverage": rows, "count": len(rows)}


@app.post("/recon-agent/{eid}/coverage", tags=["ReconAgent"])
def upsert_scope_coverage(eid: str, body: dict = Body(...), _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO scope_coverage (engagement_id, target, stage, stage_name, scan_type, job_id, status, started_at)
            VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (engagement_id, target, stage, scan_type) DO UPDATE
            SET job_id = EXCLUDED.job_id, status = EXCLUDED.status, started_at = EXCLUDED.started_at
        """, (eid, body["target"], body.get("stage", 0), body.get("stage_name"),
              body["scan_type"], body.get("job_id"), body.get("status", "running")))
    return {"ok": True}


@app.patch("/recon-agent/{eid}/coverage/{cov_id}", tags=["ReconAgent"])
def update_scope_coverage(eid: str, cov_id: str, body: dict = Body(...), _: bool = Depends(auth)):
    sets, params = [], []
    for k in ("status", "job_id", "completed_at"):
        if k in body:
            sets.append(f"{k} = %s")
            params.append(body[k])
    if not sets:
        raise HTTPException(400, "No fields")
    params.extend([cov_id, eid])
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(f"UPDATE scope_coverage SET {', '.join(sets)} WHERE id = %s::uuid AND engagement_id = %s::uuid", params)
    return {"ok": True}


@app.post("/recon-agent/{eid}/coverage/cleanup-stale", tags=["ReconAgent"])
def cleanup_stale_coverage(eid: str, _: bool = Depends(auth)):
    """Reset coverage records stuck in 'running' for >30 min to 'failed'."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE scope_coverage SET status = 'failed'
            WHERE engagement_id = %s::uuid AND status = 'running'
              AND started_at < now() - interval '30 minutes'
        """, (eid,))
        cleaned = cur.rowcount
    return {"ok": True, "cleaned": cleaned}


@app.get("/recon-agent/all/enabled", tags=["ReconAgent"])
def list_enabled_agents(_: bool = Depends(auth)):
    """List all engagements with recon agent enabled (for the background loop)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT r.*, e.name as engagement_name, e.status as engagement_status
            FROM recon_agent_state r
            JOIN engagements e ON e.id = r.engagement_id
            WHERE r.enabled = true AND e.status NOT IN ('archived', 'complete')
            ORDER BY r.updated_at DESC
        """)
        rows = cur.fetchall()
    for r in rows:
        if r.get("engagement_id"): r["engagement_id"] = str(r["engagement_id"])
        for k in ("last_run_at", "last_scan_at", "last_dispatch_at", "pause_until", "created_at", "updated_at"):
            if r.get(k): r[k] = r[k].isoformat()
    return {"agents": rows}


# ============================================================================
# TIER 14 — Burp Follow-Up Queue
# Queue follow-up findings for import into Burp Suite via RagScanBridge.
# Items are enriched with request/response/evidence from the linked finding.
# ============================================================================

class BurpQueueAddBody(BaseModel):
    follow_up_ids: List[str] = Field(..., description="List of follow-up item IDs to queue for Burp")

def _enrich_followup_for_burp(cur, fu: dict) -> dict:
    """Look up the linked finding to extract URL, request, response, evidence."""
    url = None
    method = "GET"
    request_raw = None
    response_raw = None
    evidence_str = None
    description_str = fu.get("reason") or fu.get("title") or ""
    cves: list = []
    finding_data: dict = {}

    src = fu.get("finding_source") or ""
    fid = fu.get("finding_id")
    target = fu.get("target") or ""

    # Try to load the linked finding
    if fid:
        table_map = {
            "web": "web_findings",
            "web_findings": "web_findings",
            "recon": "recon_findings",
            "recon_findings": "recon_findings",
            "vuln": "vulns",
            "vulns": "vulns",
            "playwright": "playwright_findings",
            "playwright_findings": "playwright_findings",
        }
        table = table_map.get(src)
        if table:
            try:
                cur.execute(f"SELECT * FROM {table} WHERE id = %s::uuid LIMIT 1", (str(fid),))
                row = cur.fetchone()
                if row:
                    finding_data = dict(row)
            except Exception:
                pass

    # Extract URL, evidence, CVE from the finding
    if finding_data:
        url = finding_data.get("url") or finding_data.get("target") or target
        evidence_str = finding_data.get("evidence") or finding_data.get("data", {}).get("evidence") if isinstance(finding_data.get("data"), dict) else None
        if isinstance(evidence_str, (list, dict)):
            evidence_str = json.dumps(evidence_str, default=str)[:5000]
        elif evidence_str:
            evidence_str = str(evidence_str)[:5000]

        description_str = finding_data.get("description") or finding_data.get("name") or description_str

        # Method — from web_findings
        method = finding_data.get("method") or "GET"

        # CVEs
        cve_val = finding_data.get("cve") or finding_data.get("cve_id")
        if cve_val:
            if isinstance(cve_val, list):
                cves = [str(c) for c in cve_val if c]
            elif isinstance(cve_val, str) and cve_val:
                cves = [cve_val]

        # Request/response raw if available (e.g. from web_findings data jsonb)
        if isinstance(finding_data.get("data"), dict):
            request_raw = finding_data["data"].get("request") or finding_data["data"].get("request_raw")
            response_raw = finding_data["data"].get("response") or finding_data["data"].get("response_raw")

    # Fallback URL from target
    if not url and target:
        if target.startswith("http"):
            url = target
        else:
            url = f"https://{target}/"

    # Build synthetic request if none
    if not request_raw and url:
        try:
            from urllib.parse import urlparse as _up
            p = _up(url)
            host = p.hostname or target
            path = p.path or "/"
            if p.query:
                path = f"{path}?{p.query}"
            port_str = f":{p.port}" if p.port and p.port not in (80, 443) else ""
            request_raw = (
                f"{method.upper()} {path} HTTP/1.1\r\n"
                f"Host: {host}{port_str}\r\n"
                f"User-Agent: RAG-Scan-Stack/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
        except Exception:
            pass

    # Follow-up metadata enrichment
    fu_meta = fu.get("metadata") or {}
    if isinstance(fu_meta, str):
        try:
            fu_meta = json.loads(fu_meta)
        except Exception:
            fu_meta = {}
    meta_cves = fu_meta.get("cve_ids", [])
    if meta_cves:
        cves = list(set(cves + [str(c) for c in meta_cves]))

    return {
        "url": url,
        "target": target,
        "method": method,
        "request_raw": request_raw,
        "response_raw": response_raw,
        "evidence": evidence_str,
        "description": description_str,
        "cves": cves or [],
        "finding_data": finding_data,
    }


@app.post("/burp-queue", tags=["BurpQueue"])
def add_to_burp_queue(body: BurpQueueAddBody, _: bool = Depends(auth)):
    """Add follow-up items to the Burp import queue with enriched finding data."""
    added = 0
    skipped = 0
    errors = []
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        for fuid in body.follow_up_ids:
            try:
                # Get the follow-up item
                cur.execute("SELECT * FROM follow_up_items WHERE id = %s::uuid", (fuid,))
                fu = cur.fetchone()
                if not fu:
                    skipped += 1
                    continue

                enriched = _enrich_followup_for_burp(cur, dict(fu))

                cur.execute("""
                    INSERT INTO burp_followup_queue
                        (follow_up_id, title, url, target, severity,
                         finding_source, finding_id, method,
                         request_raw, response_raw, evidence, description,
                         cves, metadata, status)
                    VALUES (%s::uuid, %s, %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s::jsonb, 'pending')
                    ON CONFLICT (follow_up_id) WHERE status = 'pending' DO NOTHING
                    RETURNING id
                """, (
                    fuid, fu.get("title") or "Untitled", enriched["url"],
                    enriched["target"], fu.get("severity") or "info",
                    fu.get("finding_source"), str(fu["finding_id"]) if fu.get("finding_id") else None,
                    enriched["method"],
                    enriched["request_raw"], enriched["response_raw"],
                    enriched["evidence"], enriched["description"],
                    enriched["cves"] or [],
                    json.dumps({"tags": fu.get("tags") or [], "priority": fu.get("priority"),
                                "rule_id": fu.get("rule_id"), "reason": fu.get("reason")}, default=str),
                ))
                row = cur.fetchone()
                if row:
                    added += 1
                else:
                    skipped += 1  # already in queue
            except Exception as e:
                errors.append(f"{fuid}: {e}")
                skipped += 1
        conn.commit()

    # Emit webhook
    try:
        from webhooks import emit_webhook
        emit_webhook("burp_queue_items_added", "rag-api", {
            "added": added, "skipped": skipped,
            "follow_up_ids": body.follow_up_ids,
        })
    except Exception:
        pass

    return {"ok": True, "added": added, "skipped": skipped, "errors": errors[:10]}


@app.get("/burp-queue", tags=["BurpQueue"])
def list_burp_queue(
    status: str = Query("pending"),
    limit: int = Query(200),
    _: bool = Depends(auth),
):
    """List items in the Burp follow-up queue. The extension polls this."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT q.*, f.priority as follow_up_priority, f.status as follow_up_status,
                   f.notes as follow_up_notes, f.reason as follow_up_reason,
                   f.tags as follow_up_tags
            FROM burp_followup_queue q
            LEFT JOIN follow_up_items f ON f.id = q.follow_up_id
            WHERE q.status = %s
            ORDER BY q.queued_at DESC
            LIMIT %s
        """, (status, limit))
        rows = cur.fetchall()

    items = []
    for r in rows:
        item = dict(r)
        for k in ("id", "follow_up_id", "finding_id"):
            if item.get(k): item[k] = str(item[k])
        for k in ("queued_at", "imported_at"):
            if item.get(k): item[k] = item[k].isoformat()
        items.append(item)

    return {"items": items, "count": len(items), "status": status}


@app.patch("/burp-queue/{item_id}", tags=["BurpQueue"])
def update_burp_queue_item(
    item_id: str,
    status: str = Query(..., description="New status: imported or dismissed"),
    _: bool = Depends(auth),
):
    """Mark a queue item as imported or dismissed."""
    if status not in ("imported", "dismissed"):
        raise HTTPException(400, "status must be 'imported' or 'dismissed'")
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE burp_followup_queue
            SET status = %s, imported_at = CASE WHEN %s = 'imported' THEN now() ELSE imported_at END
            WHERE id = %s::uuid
        """, (status, status, item_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Queue item not found")
    return {"ok": True, "id": item_id, "status": status}


@app.post("/burp-queue/mark-imported", tags=["BurpQueue"])
def bulk_mark_imported(body: dict = Body(...), _: bool = Depends(auth)):
    """Bulk-mark queue items as imported. Body: {"ids": ["uuid", ...]}"""
    ids = body.get("ids", [])
    if not ids:
        raise HTTPException(400, "ids required")
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE burp_followup_queue
            SET status = 'imported', imported_at = now()
            WHERE id = ANY(%s::uuid[]) AND status = 'pending'
        """, (ids,))
        affected = cur.rowcount
    return {"ok": True, "marked": affected}


@app.delete("/burp-queue/{item_id}", tags=["BurpQueue"])
def delete_burp_queue_item(item_id: str, _: bool = Depends(auth)):
    """Remove an item from the Burp queue entirely."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM burp_followup_queue WHERE id = %s::uuid", (item_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Queue item not found")
    return {"ok": True}


@app.get("/burp-queue/stats", tags=["BurpQueue"])
def burp_queue_stats(_: bool = Depends(auth)):
    """Get counts of pending/imported/dismissed items."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT status, count(*) as cnt
            FROM burp_followup_queue
            GROUP BY status
        """)
        rows = cur.fetchall()
    counts = {r["status"]: r["cnt"] for r in rows}
    return {"pending": counts.get("pending", 0),
            "imported": counts.get("imported", 0),
            "dismissed": counts.get("dismissed", 0),
            "total": sum(counts.values())}


# ============================================================================
# Chat Presets — saved operator prompts for the dashboard chat panel
# ============================================================================

class ChatPresetIn(BaseModel):
    title: str
    prompt_template: str
    engagement_id: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    placeholders: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None
    created_by: Optional[str] = None


class ChatPresetPatch(BaseModel):
    title: Optional[str] = None
    prompt_template: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    placeholders: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None


def _ser_preset(row: dict) -> dict:
    return {
        "id": str(row["id"]),
        "engagement_id": str(row["engagement_id"]) if row.get("engagement_id") else None,
        "title": row["title"],
        "category": row.get("category"),
        "description": row.get("description"),
        "prompt_template": row["prompt_template"],
        "placeholders": row.get("placeholders") or [],
        "tags": row.get("tags") or [],
        # NULL means "no restriction"; the chat treats absence and [] differently.
        "allowed_tools": list(row["allowed_tools"]) if row.get("allowed_tools") else None,
        "created_by": row.get("created_by"),
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "last_used_at": row["last_used_at"].isoformat() if row.get("last_used_at") else None,
        "use_count": row.get("use_count", 0),
    }


@app.get("/chat-presets", tags=["ChatPresets"])
def list_chat_presets(
    engagement_id: Optional[str] = Query(None,
        description="UUID of engagement. If set, returns global (NULL) presets PLUS engagement-scoped ones."),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None, description="Substring match on title / description / tags"),
    _: bool = Depends(auth),
):
    where = []
    params: list = []
    if engagement_id:
        where.append("(engagement_id IS NULL OR engagement_id = %s::uuid)")
        params.append(engagement_id)
    if category:
        where.append("category = %s")
        params.append(category)
    if search:
        where.append("(title ILIKE %s OR description ILIKE %s OR %s = ANY(tags))")
        like = f"%{search}%"
        params.extend([like, like, search])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"SELECT * FROM chat_presets {where_sql} "
            "ORDER BY last_used_at DESC NULLS LAST, use_count DESC, title",
            params,
        )
        rows = cur.fetchall()
    return {"count": len(rows), "results": [_ser_preset(r) for r in rows]}


@app.get("/chat-presets/{preset_id}", tags=["ChatPresets"])
def get_chat_preset(preset_id: str, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM chat_presets WHERE id = %s::uuid", (preset_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Preset not found")
    return _ser_preset(row)


@app.post("/chat-presets", tags=["ChatPresets"])
def create_chat_preset(body: ChatPresetIn, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        try:
            cur.execute(
                """
                INSERT INTO chat_presets (engagement_id, title, category, description,
                                          prompt_template, placeholders, tags,
                                          allowed_tools, created_by)
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (body.engagement_id, body.title, body.category, body.description,
                 body.prompt_template, body.placeholders or [], body.tags or [],
                 body.allowed_tools, body.created_by or "operator"),
            )
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            raise HTTPException(409, f"Preset titled '{body.title}' already exists for this engagement")
        row = cur.fetchone()
        conn.commit()
    try:
        from webhooks import emit_webhook
        emit_webhook("chat_preset_created", "chat_presets",
                     {"id": str(row["id"]), "title": row["title"],
                      "engagement_id": body.engagement_id})
    except Exception:
        pass
    return _ser_preset(row)


@app.patch("/chat-presets/{preset_id}", tags=["ChatPresets"])
def update_chat_preset(preset_id: str, body: ChatPresetPatch, _: bool = Depends(auth)):
    fields, params = [], []
    for col, val in [("title", body.title), ("category", body.category),
                     ("description", body.description),
                     ("prompt_template", body.prompt_template),
                     ("allowed_tools", body.allowed_tools),
                     ("placeholders", body.placeholders),
                     ("tags", body.tags)]:
        if val is not None:
            fields.append(f"{col} = %s")
            params.append(val)
    if not fields:
        raise HTTPException(400, "No fields to update")
    params.append(preset_id)
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"UPDATE chat_presets SET {', '.join(fields)} WHERE id = %s::uuid RETURNING *",
            params,
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Preset not found")
        conn.commit()
    return _ser_preset(row)


@app.delete("/chat-presets/{preset_id}", tags=["ChatPresets"])
def delete_chat_preset(preset_id: str, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM chat_presets WHERE id = %s::uuid", (preset_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Preset not found")
        conn.commit()
    try:
        from webhooks import emit_webhook
        emit_webhook("chat_preset_deleted", "chat_presets", {"id": preset_id})
    except Exception:
        pass
    return {"ok": True}


@app.post("/chat-presets/{preset_id}/render", tags=["ChatPresets"])
def render_chat_preset(preset_id: str, body: dict, _: bool = Depends(auth)):
    """Substitute {placeholder} tokens in the preset's template.
    Body: {"vars": {"engagement": "...", "target": "...", ...}}.
    Engagement name is auto-resolved from preset.engagement_id when not provided.
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM chat_presets WHERE id = %s::uuid", (preset_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Preset not found")
        vars_ = dict(body.get("vars") or {})
        if "engagement" not in vars_ and row.get("engagement_id"):
            cur.execute("SELECT name FROM engagements WHERE id = %s",
                        (row["engagement_id"],))
            er = cur.fetchone()
            if er:
                vars_["engagement"] = er["name"]
    rendered = row["prompt_template"]
    for k, v in vars_.items():
        rendered = rendered.replace("{" + k + "}", str(v))
    return {"id": str(row["id"]), "title": row["title"], "rendered": rendered, "vars_used": vars_}


@app.post("/chat-presets/{preset_id}/use", tags=["ChatPresets"])
def bump_chat_preset_use(preset_id: str, _: bool = Depends(auth)):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE chat_presets SET use_count = use_count + 1, last_used_at = now() "
            "WHERE id = %s::uuid",
            (preset_id,),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Preset not found")
        conn.commit()
    try:
        from webhooks import emit_webhook
        emit_webhook("chat_preset_used", "chat_presets", {"id": preset_id})
    except Exception:
        pass
    return {"ok": True}
