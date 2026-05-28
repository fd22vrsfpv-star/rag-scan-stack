"""
Scan Audit Writer — thread-safe JSONL audit log for Splunk ingestion.

Every scan event (start, complete, fail) is appended as a single JSON line
to AUDIT_FILE (default /scan_audit/audit.jsonl).  The file is safe to tail,
ship via Splunk Universal Forwarder, or parse with jq.

Cross-engagement isolation (Option B / Phase 5):
    Each scanner runner should register an HTTP middleware that captures
    `X-Engagement-Id` from incoming scan-launch requests and sets the
    `current_engagement_id` ContextVar exported by this module.  Then every
    `write_audit()` inside that request's call stack will pick the
    engagement up automatically -- no per-call-site change required.

    Example (one of the scanner runners)::

        from audit_writer import current_engagement_id

        @app.middleware("http")
        async def _capture_engagement(request, call_next):
            eid = request.headers.get("x-engagement-id")
            token = current_engagement_id.set(eid or None)
            try:
                return await call_next(request)
            finally:
                current_engagement_id.reset(token)
"""

import contextvars
import json
import os
import socket
import threading
import time
from datetime import datetime, timezone

_lock = threading.Lock()
AUDIT_FILE = os.environ.get("AUDIT_FILE", "/scan_audit/audit.jsonl")

# Per-request engagement context.  Set by a middleware in each scanner
# runner (see module docstring); read here as the last-resort fallback
# inside write_audit().  Default None = unscoped / legacy entry.
current_engagement_id: contextvars.ContextVar = contextvars.ContextVar(
    "current_engagement_id", default=None,
)

_external_ip_cache: dict = {"ip": None, "ts": 0}


def _get_external_ip() -> str:
    """Cached external IP lookup (refreshes every 5 min)."""
    if time.time() - _external_ip_cache["ts"] < 300 and _external_ip_cache["ip"]:
        return _external_ip_cache["ip"]
    try:
        import urllib.request
        ip = urllib.request.urlopen("https://ifconfig.me", timeout=5).read().decode().strip()
        _external_ip_cache.update(ip=ip, ts=time.time())
        return ip
    except Exception:
        return _external_ip_cache.get("ip") or "unknown"


def write_audit(
    event: str,
    scan_type: str,
    source: str,
    data: dict,
    engagement_id: str = None,
):
    """Append a JSONL line to the audit log.

    Parameters
    ----------
    event : str
        One of: scan_started, scan_completed, scan_failed, scan_stopped
    scan_type : str
        Tool or pipeline name (masscan, nmap, httpx, nuclei, ...)
    source : str
        Container / service name (nmap_scanner, pd_runner, osint_runner, ...)
    data : dict
        Arbitrary payload — job_id, targets, parameters, proxy, duration_s,
        findings_count, error, execution_mode, node_id, etc.
    engagement_id : str, optional
        UUID of the engagement this scan belongs to.  Required for
        cross-engagement isolation: BFF and dashboard views filter audit
        rows by engagement_id, so entries written with engagement_id=None
        are treated as legacy/unscoped and hidden when an engagement is
        active.  Callers may also pass engagement_id inside ``data``;
        ``data["engagement_id"]`` takes precedence over the explicit
        parameter so existing call sites that already include it keep
        working unchanged.
    """
    # Resolve the canonical engagement_id with explicit precedence:
    #   1) data["engagement_id"]          (legacy explicit, highest)
    #   2) engagement_id parameter        (new explicit)
    #   3) current_engagement_id contextvar (per-request middleware capture)
    eid = data.get("engagement_id", engagement_id)
    if eid is None:
        try:
            eid = current_engagement_id.get()
        except LookupError:
            eid = None

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "scan_type": scan_type,
        "source": source,
        "hostname": socket.gethostname(),
        "external_ip": _get_external_ip(),
        **data,
    }
    # Set engagement_id LAST so it can't be silently shadowed by an entry of
    # the same key in ``data`` (the **data spread above already merges it,
    # but we want a single canonical resolution path).
    record["engagement_id"] = eid

    line = json.dumps(record, default=str) + "\n"
    with _lock:
        os.makedirs(os.path.dirname(AUDIT_FILE) or ".", exist_ok=True)
        with open(AUDIT_FILE, "a") as f:
            f.write(line)
