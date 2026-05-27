"""
Scan Audit Writer — thread-safe JSONL audit log for Splunk ingestion.

Every scan event (start, complete, fail) is appended as a single JSON line
to AUDIT_FILE (default /scan_audit/audit.jsonl).  The file is safe to tail,
ship via Splunk Universal Forwarder, or parse with jq.
"""

import json
import os
import socket
import threading
import time
from datetime import datetime, timezone

_lock = threading.Lock()
AUDIT_FILE = os.environ.get("AUDIT_FILE", "/scan_audit/audit.jsonl")

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


def write_audit(event: str, scan_type: str, source: str, data: dict):
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
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "scan_type": scan_type,
        "source": source,
        "hostname": socket.gethostname(),
        "external_ip": _get_external_ip(),
        **data,
    }
    line = json.dumps(record, default=str) + "\n"
    with _lock:
        os.makedirs(os.path.dirname(AUDIT_FILE) or ".", exist_ok=True)
        with open(AUDIT_FILE, "a") as f:
            f.write(line)
