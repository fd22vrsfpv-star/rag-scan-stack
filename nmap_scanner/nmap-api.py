import os
import json
import signal
import shutil
import pathlib
import subprocess
import time
import traceback
import uuid
import threading
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path

import logging
logging.basicConfig(level=logging.INFO)

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Trust self-signed certs for inter-container HTTPS
os.environ.setdefault("CURL_CA_BUNDLE", "")
os.environ.setdefault("REQUESTS_CA_BUNDLE", "")

# Monkey-patch requests.Session to always use verify=False
_orig_session_init = requests.Session.__init__
def _patched_session_init(self, *a, **kw):
    _orig_session_init(self, *a, **kw)
    self.verify = False
requests.Session.__init__ = _patched_session_init
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from log_manager import get_log_handler, setup_log_capture, LOGS_UI_HTML

try:
    from audit_writer import write_audit
except ImportError:
    def write_audit(*a, **kw): pass  # graceful fallback

# Import credential checker
try:
    from cred_checker import (
        check_default_credentials,
        check_all_default_credentials,
        DEFAULT_CREDENTIALS,
        SERVICE_PORTS,
    )
    CRED_CHECKER_AVAILABLE = True
except ImportError:
    CRED_CHECKER_AVAILABLE = False
    logging.warning("cred_checker module not available")

# Import validation utilities
from validation import (
    sanitize_scan_id,
    sanitize_filename,
    validate_output_path,
    validate_scan_target,
    sanitize_port,
    sanitize_command_arg,
    ValidationError
)

app = FastAPI(title="Nmap Scanner", version="1.0.0")

# ── Engagement context (Option B / Phase 5) ──
# Capture X-Engagement-Id from incoming scan-launch requests into the
# audit_writer's ContextVar so write_audit() calls inside the request's
# call stack automatically carry the engagement_id field.  Without this,
# audit lines written by this runner land with engagement_id=null and are
# hidden from any active-engagement view in the dashboard.
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
    pass  # audit_writer not on path — runner runs without engagement scoping

@app.on_event("startup")
async def startup_event():
    """Initialize log capture on startup"""
    setup_log_capture()
    logging.info("[nmap_scanner] Service started, log capture initialized")

API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
OUTDIR = os.environ.get("NMAP_OUT_DIR", "/app/nmap_out")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"
SCAN_RECOMMENDER_URL = os.environ.get("SCAN_RECOMMENDER_URL", "https://scan-recommender:8013")
NUCLEI_URL = os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011")
OSINT_RUNNER_URL = os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024")

# Per-scan nmap options (set by request handler, read by nmap execution)
_nmap_scan_opts: dict = {}

SESSION_DIR = pathlib.Path(os.environ.get("SESSION_RESULTS_DIR", "/scan_results"))


# ── Centralized scan timeouts ───────────────────────────────────────
# All subprocess + ingest timeouts in this service are sourced from here.
# Override at container start with env vars (see docker-compose.yml).
# Per-job override is also accepted via job payload `timeout_seconds`.
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


# Subprocess (nmap binary) timeouts — seconds
NMAP_TIMEOUT_FALLBACK = _env_int("NMAP_TIMEOUT_FALLBACK", 1800)   # nmap fallback after masscan
NMAP_TIMEOUT_PROXIED  = _env_int("NMAP_TIMEOUT_PROXIED", 3600)    # nmap via proxy (long)
NMAP_TIMEOUT_SERVICE  = _env_int("NMAP_TIMEOUT_SERVICE", 600)     # ad-hoc service detect
NMAP_TIMEOUT_UDP      = _env_int("NMAP_TIMEOUT_UDP", 1800)        # udp scan
NMAP_TIMEOUT_SMB      = _env_int("NMAP_TIMEOUT_SMB", 300)         # smb vuln scripts
NMAP_TIMEOUT_RESUME   = _env_int("NMAP_TIMEOUT_RESUME", 7200)     # resumed scans run long

# Ingest HTTP timeouts (rag-api uploads) — seconds
INGEST_TIMEOUT        = _env_int("INGEST_TIMEOUT", 600)
INGEST_TIMEOUT_SHORT  = _env_int("INGEST_TIMEOUT_SHORT", 300)

# Recommender / dispatch HTTP timeouts — seconds
RECOMMENDER_TIMEOUT   = _env_int("RECOMMENDER_TIMEOUT", 15)
DISPATCH_TIMEOUT      = _env_int("DISPATCH_TIMEOUT", 10)

# Process-wait timeouts (graceful kill) — seconds
PROC_WAIT_GRACEFUL    = _env_int("PROC_WAIT_GRACEFUL", 10)
PROC_WAIT_FORCE       = _env_int("PROC_WAIT_FORCE", 5)


def _resolve_timeout(payload_timeout: Any, default: int,
                     setting_key: Optional[str] = None) -> int:
    """Pick effective timeout: positive payload override > admin setting (app_settings) > env default."""
    try:
        v = int(payload_timeout)
        if v > 0:
            return v
    except (TypeError, ValueError):
        pass
    if setting_key:
        v = _admin_setting_int(setting_key)
        if v and v > 0:
            return v
    return int(default)


# In-process cache of admin-configured timeouts (key → (expiry_ts, value)).
# Refreshed on miss / TTL expiry by querying rag-api /settings/config/{key}.
_TIMEOUT_CACHE: Dict[str, tuple] = {}
_TIMEOUT_CACHE_TTL = _env_int("SCAN_TIMEOUT_CACHE_TTL", 60)


def _admin_setting_int(key: str) -> Optional[int]:
    """Best-effort fetch of an integer setting from rag-api app_settings."""
    now = time.time()
    cached = _TIMEOUT_CACHE.get(key)
    if cached and cached[0] > now:
        return cached[1]
    try:
        resp = requests.get(
            f"{API_BASE}/settings/config/{key}",
            headers={"x-api-key": API_KEY},
            timeout=DISPATCH_TIMEOUT,
            verify=False,
        )
        if resp.status_code == 200:
            try:
                v = int(resp.json().get("value", "0"))
            except (TypeError, ValueError):
                v = None
        else:
            v = None
    except Exception:
        v = None
    _TIMEOUT_CACHE[key] = (now + _TIMEOUT_CACHE_TTL, v)
    return v


def _trigger_scan_recommender(nmap_hosts: list, job_id: str = None):
    """
    Call the scan recommender for each discovered host/service after a scan completes.
    nmap_hosts: list of dicts like [{"ip": "x.x.x.x", "ports": [{"port": 80, "service": "http", ...}]}]
    Also dispatches targeted nuclei scans for services that have nuclei tags.
    """
    if not nmap_hosts:
        return
    tag = f"[{job_id[:8]}] " if job_id else ""
    total = 0
    for host in nmap_hosts:
        ip = host.get("ip")
        if not ip:
            continue
        for port_info in host.get("ports", []):
            service = port_info.get("service")
            port = port_info.get("port")
            banner = port_info.get("product")
            if banner and port_info.get("version"):
                banner = f"{banner} {port_info['version']}"
            try:
                params = {"ip": ip, "persist": "true"}
                if service:
                    params["service"] = service
                if banner:
                    params["banner"] = banner
                if port:
                    params["port"] = str(port)
                resp = requests.get(
                    f"{SCAN_RECOMMENDER_URL}/next_scan",
                    params=params,
                    timeout=RECOMMENDER_TIMEOUT,
                    verify=False,
                )
                if resp.status_code == 200:
                    recs = resp.json().get("recommendations", [])
                    total += len(recs)
                    logging.debug(f"{tag}Recommender: {ip}:{port}/{service} → {len(recs)} recs")

                    # Dispatch targeted nuclei scan for services with nuclei tags
                    for rec in recs:
                        if rec.get("scanner") == "nuclei" and rec.get("template") and port:
                            _dispatch_nuclei_targeted(ip, port, rec["template"], job_id)

                    # Dispatch vulnx CVE lookup for services with product info
                    product = port_info.get("product")
                    version = port_info.get("version")
                    if product:
                        _dispatch_vulnx(ip, port, product, version, job_id)
                else:
                    logging.debug(f"{tag}Recommender returned {resp.status_code} for {ip}/{service}")
            except Exception as e:
                logging.warning(f"{tag}Recommender call failed for {ip}/{service}: {type(e).__name__}: {e}")
    logging.info(f"{tag}Scan recommender: generated {total} recommendations for {len(nmap_hosts)} hosts")


def _dispatch_nuclei_targeted(ip: str, port: int, tags: str, job_id: str = None):
    """Dispatch a targeted nuclei scan with specific tags against an IP:port."""
    tag = f"[{job_id[:8]}] " if job_id else ""
    try:
        target = f"{ip}:{port}"
        resp = requests.post(
            f"{NUCLEI_URL}/scan",
            json={
                "targets": [target],
                "tags": tags,
                "severity": "low,medium,high,critical",
            },
            timeout=DISPATCH_TIMEOUT,
            verify=False,
        )
        if resp.status_code < 300:
            logging.info(f"{tag}Nuclei targeted scan dispatched for {target} tags={tags}")
        else:
            logging.debug(f"{tag}Nuclei dispatch returned {resp.status_code} for {target}")
    except Exception as e:
        logging.debug(f"{tag}Nuclei dispatch failed for {ip}:{port}: {e}")


def _dispatch_vulnx(ip: str, port: int, product: str, version: str = None, job_id: str = None):
    """Dispatch a vulnx CVE lookup for a discovered service product/version."""
    tag = f"[{job_id[:8]}] " if job_id else ""
    try:
        payload = {"product": product, "limit": 50}
        if version:
            payload["version"] = version
        resp = requests.post(
            f"{OSINT_RUNNER_URL}/jobs/vulnx",
            json=payload,
            timeout=DISPATCH_TIMEOUT,
            verify=False,
        )
        logging.info(f"{tag}Dispatched vulnx for {product} {version or ''}: {resp.status_code}")
    except Exception as e:
        logging.debug(f"{tag}vulnx dispatch failed for {product}: {e}")


def _trigger_subfinder_for_domains(targets: List[str], job_id: str = None):
    """
    Auto-trigger subfinder for any scan targets that look like domain names (not IPs).
    Fires asynchronously to osint-runner.
    """
    import re
    tag = f"[{job_id[:8]}] " if job_id else ""
    domains = []
    for t in targets:
        t = t.strip()
        # Skip IPs and CIDRs
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', t):
            continue
        if ':' in t:  # IPv6
            continue
        # Looks like a domain
        if '.' in t and not t.replace('.', '').isdigit():
            domains.append(t)
    if not domains:
        return
    try:
        resp = requests.post(
            f"{OSINT_RUNNER_URL}/jobs/subfinder",
            json={"domains": domains},
            timeout=DISPATCH_TIMEOUT,
            verify=False,
        )
        logging.info(f"{tag}Subfinder auto-trigger for {domains} → {resp.status_code}")
    except Exception as e:
        logging.debug(f"{tag}Subfinder auto-trigger failed: {e}")


def _parse_nmap_xml_summary(xml_path):
    """Extract hosts, ports, services, and scripts from nmap XML into a dict."""
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return None
    hosts = []
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") == "down":
            continue
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue
        ports_list = []
        for port in host.findall(".//port"):
            svc = port.find("service")
            port_info = {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol"),
                "state": (port.find("state") or {}).get("state") if port.find("state") is not None else None,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            }
            scripts = []
            for script in port.findall("script"):
                scripts.append({
                    "id": script.get("id"),
                    "output": script.get("output", "")[:2000],
                })
            if scripts:
                port_info["scripts"] = scripts
            ports_list.append(port_info)
        hosts.append({"ip": ip, "ports": ports_list})
    return {"hosts": hosts}


def _save_session_results(job_id, job_type, scanner, files, metadata=None):
    """Copy raw scan output files to a session-based directory."""
    try:
        ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M")
        session_path = SESSION_DIR / f"{job_type}_{ts}_{job_id[:8]}"
        session_path.mkdir(parents=True, exist_ok=True)
        copied = []
        for fp in files:
            fp = pathlib.Path(fp)
            if fp.exists() and fp.is_file():
                dest_name = fp.name.removesuffix(".session_copy")
                shutil.copy2(str(fp), str(session_path / dest_name))
                copied.append(dest_name)
        manifest = {
            "job_id": job_id, "job_type": job_type, "scanner": scanner,
            "created_at": datetime.utcnow().isoformat(), "files": copied,
        }
        if metadata:
            manifest["metadata"] = metadata
        (session_path / "manifest.json").write_text(json.dumps(manifest, indent=2))
        logging.info(f"[session] Saved {len(copied)} files to {session_path}")
    except Exception as e:
        logging.warning(f"[session] Failed to save session results: {e}")

# Build default quick_ports: 1-1000 + any WEB_PORTS above 1000
_WEB_PORTS_STR = os.environ.get("WEB_PORTS", "80,443,8080,8443,8000,8888,3000,5000")
_HIGH_WEB_PORTS = ",".join(
    p.strip() for p in _WEB_PORTS_STR.split(",")
    if p.strip().isdigit() and int(p.strip()) > 1000
)
DEFAULT_QUICK_PORTS = f"1-1000,{_HIGH_WEB_PORTS}" if _HIGH_WEB_PORTS else "1-1000"
DEFAULT_DEEP_SCAN_PORTS = os.environ.get("DEEP_SCAN_PORTS", "1001-65535")


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
            timeout=DISPATCH_TIMEOUT,
            verify=False,
        )
    except Exception as e:
        logging.warning(f"Failed to emit webhook: {e}")

# In-memory job tracking (for production, use Redis or database)
jobs = {}
jobs_lock = threading.Lock()
_JOBS_PERSIST_DIR = SESSION_DIR / ".jobs"
_JOBS_PERSIST_DIR.mkdir(parents=True, exist_ok=True)

# Process registry for running subprocesses (masscan Popen tracking)
_running_processes: Dict[str, subprocess.Popen] = {}
_processes_lock = threading.Lock()


class _MasscanInterruptedError(Exception):
    """Raised when masscan is interrupted via SIGINT and writes a paused.conf."""
    def __init__(self, paused_conf: str):
        self.paused_conf = paused_conf
        super().__init__(f"Masscan interrupted, paused.conf at {paused_conf}")

class MasscanBody(BaseModel):
    targets: List[str] = Field(..., description="List of IPs/CIDRs to scan")
    ports: str = Field("1-65535", description="Ports range or list")
    rate: int = Field(1000, ge=1, le=100000, description="Masscan rate (packets per second)")
    interface: Optional[str] = Field(None, description="Network interface for Masscan (-e)")
    proxy: Optional[str] = Field(None, description="SOCKS proxy URL (e.g. socks5://host:port). When set, skips masscan and uses nmap -sT --proxies")
    # Per-scan nmap options (override env defaults)
    service_detection: Optional[bool] = Field(None, description="Enable -sV service/version detection (default: env NMAP_SERVICE_DETECTION)")
    version_intensity: Optional[int] = Field(None, ge=0, le=9, description="Version intensity 0-9 (default: env NMAP_VERSION_INTENSITY)")
    scripts: Optional[str] = Field(None, description="NSE scripts to run (comma-separated, e.g. 'vuln,auth,default')")
    scan_type_flag: Optional[str] = Field(None, description="Scan type flag: -sS (SYN), -sT (connect), -sU (UDP), -sA (ACK)")
    timing: Optional[str] = Field(None, description="Timing template: T0-T5 (default T4)")
    os_detection: Optional[bool] = Field(None, description="Enable -O OS detection")
    script_args: Optional[str] = Field(None, description="NSE script arguments (--script-args)")
    extra_args: Optional[str] = Field(None, description="Additional raw nmap arguments (advanced)")
    timeout_seconds: Optional[int] = Field(None, ge=0, description="Per-job nmap subprocess timeout (seconds). 0/unset → use env default")

    def validate_inputs(self):
        """Validate all inputs for security"""
        # Validate targets
        validated_targets = []
        for target in self.targets:
            try:
                # Allow private IPs for internal scanning
                validated = validate_scan_target(target, allow_private=True)
                validated_targets.append(validated)
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid target '{target}': {e}")
        self.targets = validated_targets

        # Validate ports format - handle both port ranges and nmap arguments
        self.ports = self.ports.strip()
        try:
            if self.ports.startswith('--top-ports'):
                # Handle nmap --top-ports argument (allow spaces, dashes, letters, numbers)
                sanitize_command_arg(self.ports, allowed_chars=r'^[a-zA-Z0-9\s\-=]+$')
            else:
                # Handle traditional port ranges (numbers, commas, dashes only)
                # Strip spaces for traditional port ranges
                self.ports = self.ports.replace(' ', '')
                sanitize_command_arg(self.ports, allowed_chars=r'^[0-9,\-]+$')
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=f"Invalid ports format: {e}")

        # Validate interface if provided
        if self.interface:
            try:
                sanitize_command_arg(self.interface, allowed_chars=r'^[a-zA-Z0-9_-]+$')
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid interface: {e}")

def create_job(job_type: str, params: Dict) -> str:
    """Create a new job and return job_id"""
    job_id = str(uuid.uuid4())
    with jobs_lock:
        jobs[job_id] = {
            "job_id": job_id,
            "type": job_type,
            "status": "queued",
            "params": params,
            "created_at": datetime.utcnow().isoformat(),
            "started_at": None,
            "completed_at": None,
            "result": None,
            "error": None,
            "progress": {"stage": "queued", "details": None}
        }
    logging.info(f"[{job_id}] Created {job_type} job")
    return job_id

def update_job_status(job_id: str, status: str, stage: str = None, details: str = None, result: Any = None, error: str = None):
    """Update job status. Persists to disk on terminal status."""
    with jobs_lock:
        if job_id not in jobs:
            return
        jobs[job_id]["status"] = status
        if stage:
            jobs[job_id]["progress"]["stage"] = stage
        if details:
            jobs[job_id]["progress"]["details"] = details
        if result is not None:
            jobs[job_id]["result"] = result
        if error:
            jobs[job_id]["error"] = error
        if status == "running" and not jobs[job_id]["started_at"]:
            jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
        if status in ["completed", "failed", "stopped"]:
            jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            # Persist terminal job to disk
            try:
                (_JOBS_PERSIST_DIR / f"{job_id}.json").write_text(
                    json.dumps(jobs[job_id], default=str))
            except Exception as e:
                logging.warning(f"[job-persist] Failed to save {job_id[:8]}: {e}")
    logging.info(f"[{job_id}] Status: {status}, Stage: {stage}, Details: {details}")

def push_job_command(job_id: str, stage: str, command: str):
    """Append a command to progress.commands for live pipeline tracking."""
    with jobs_lock:
        if job_id not in jobs:
            return
        prog = jobs[job_id]["progress"]
        if "commands" not in prog:
            prog["commands"] = []
        prog["commands"].append({
            "stage": stage,
            "command": command,
            "ts": datetime.utcnow().isoformat(),
        })
        prog["stage"] = stage
        prog["command"] = command

def get_job(job_id: str) -> Optional[Dict]:
    """Get job status — checks memory first, then disk."""
    with jobs_lock:
        job = jobs.get(job_id)
    if job:
        return job
    # Fall back to disk
    fp = _JOBS_PERSIST_DIR / f"{job_id}.json"
    if fp.exists():
        try:
            return json.loads(fp.read_text())
        except Exception:
            pass
    return None

@app.get("/health")
def health():
    return {"ok": True, "version": os.environ.get("BUILD_VERSION", "dev")}

@app.get("/jobs/{job_id}")
def get_job_status(job_id: str):
    """Get status of a scan job"""
    # Validate job_id to prevent injection
    try:
        sanitize_scan_id(job_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid job_id: {e}")

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.post("/jobs/{job_id}/stop")
def stop_job(job_id: str):
    """Stop a running scan job. Uses SIGINT for masscan to enable resume."""
    # Validate job_id to prevent injection
    try:
        sanitize_scan_id(job_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid job_id: {e}")

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job["status"] not in ["queued", "running"]:
        raise HTTPException(status_code=400, detail=f"Job is already {job['status']}, cannot stop")

    resumable = False

    # Try to send SIGINT to running process (masscan writes paused.conf)
    with _processes_lock:
        proc = _running_processes.get(job_id)

    if proc and proc.poll() is None:
        logging.info(f"[{job_id}] Sending SIGINT to PID {proc.pid}")
        try:
            proc.send_signal(signal.SIGINT)
        except OSError as e:
            logging.warning(f"[{job_id}] SIGINT failed: {e}")

        # Wait up to PROC_WAIT_GRACEFUL for graceful exit, then SIGKILL
        try:
            proc.wait(timeout=PROC_WAIT_GRACEFUL)
        except subprocess.TimeoutExpired:
            logging.warning(f"[{job_id}] Process didn't exit after SIGINT, sending SIGKILL")
            proc.kill()
            proc.wait(timeout=PROC_WAIT_FORCE)

        # Check for paused.conf (masscan creates it on SIGINT)
        paused = _find_paused_conf("", job_id)
        if paused:
            with jobs_lock:
                if job_id in jobs:
                    jobs[job_id]["paused_conf"] = paused
            resumable = True
            logging.info(f"[{job_id}] Found paused.conf at {paused}, scan is resumable")
    else:
        # No tracked process — just mark stopped
        update_job_status(job_id, "stopped", "user_stopped", "Scan stopped by user request")

    # Emit webhook for scan stop
    emit_webhook_event("scan_stopped", job.get("type", "nmap"), {
        "job_id": job_id,
        "scan_type": job.get("type"),
        "stopped_by": "user",
        "resumable": resumable,
        "previous_status": job["status"],
        "progress": job.get("progress", {})
    })

    logging.info(f"[{job_id}] Scan stopped by user request (resumable={resumable})")
    return {"ok": True, "job_id": job_id, "status": "stopped", "resumable": resumable}

def _ensure_outdir():
    try:
        os.makedirs(OUTDIR, exist_ok=True)
    except Exception:
        pass

def _safe_name(ip: str) -> str:
    """Convert IP address to safe filename component"""
    # Replace dots and colons with underscores for IPv4/IPv6
    return ip.replace('.', '_').replace(':', '_')

def _masscan_results_empty(outfile: str) -> bool:
    """Check if a masscan JSON output file has zero results."""
    try:
        if not os.path.exists(outfile):
            return True
        size = os.path.getsize(outfile)
        if size < 10:
            return True
        with open(outfile) as f:
            data = json.load(f)
        # masscan JSON is a list of objects; empty scan = empty list or only the final status record
        if isinstance(data, list):
            return all(r.get("ports") is None for r in data)
        return True
    except (json.JSONDecodeError, Exception):
        return True


def _run_nmap_fallback(targets: List[str], ports: str, job_id: str = None) -> str:
    """
    Fallback port discovery using nmap -sS (or -sT if -sS fails).
    Produces a masscan-compatible JSON file so downstream ingestion works.
    Used when masscan can't send raw packets (e.g. Docker Desktop on macOS).
    """
    _ensure_outdir()
    ts = int(time.time())
    job_suffix = job_id[:8] if job_id else str(uuid.uuid4())[:8]
    base_path = os.path.join(OUTDIR, f"nmap_fallback_{ts}_{job_suffix}")
    xml_file = base_path + ".xml"
    json_file = os.path.join(OUTDIR, f"masscan_{ts}_{job_suffix}.json")

    target_str = " ".join(targets)

    # Guard against empty ports — use default 1-1000 if not specified
    if not ports or not ports.strip():
        ports = DEFAULT_QUICK_PORTS
        logging.warning("[nmap-fallback] Empty ports string — defaulting to %s", ports)

    if job_id:
        update_job_status(job_id, "running", "nmap_fallback",
                          f"Masscan failed — falling back to nmap port discovery")
        # Record output base so --resume can find the .nmap log
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id]["nmap_log_base"] = base_path

    logging.info("[nmap-fallback] Running nmap -sS on %s ports %s", targets, ports)

    timeout_s = _resolve_timeout(_nmap_scan_opts.get("timeout_seconds"),
                                 NMAP_TIMEOUT_FALLBACK, "scan_timeout_nmap")

    # Try SYN scan first, fall back to connect scan
    # NOTE: -oA writes .nmap + .gnmap + .xml — required for `nmap --resume`.
    for scan_flag in ["-sS", "-sT"]:
        args = ["nmap", scan_flag, "-T4", "--open", "--stats-every", "30s"]
        if ports:
            args.extend(["-p", ports])
        args.extend(["-oA", base_path, "--no-stylesheet"] + targets)
        try:
            start_time = time.time()
            subprocess.run(args, check=True, capture_output=True, timeout=timeout_s)
            duration = time.time() - start_time
            logging.info("[nmap-fallback] nmap %s completed in %.1fs", scan_flag, duration)
            break
        except subprocess.CalledProcessError as e:
            logging.warning("[nmap-fallback] nmap %s failed: %s, trying next", scan_flag, e)
            if scan_flag == "-sT":
                raise HTTPException(status_code=500, detail=f"nmap fallback failed: {e}")
        except subprocess.TimeoutExpired:
            logging.warning("[nmap-fallback] nmap %s timed out after %ds", scan_flag, timeout_s)
            if scan_flag == "-sT":
                raise HTTPException(status_code=500, detail=f"nmap fallback timed out after {timeout_s}s")

    # Convert nmap XML to masscan-compatible JSON
    results = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_file)
        for host_el in tree.findall(".//host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    proto = port_el.get("protocol", "tcp")
                    portnum = int(port_el.get("portid"))
                    results.append({
                        "ip": ip,
                        "timestamp": str(int(time.time())),
                        "ports": [{"port": portnum, "proto": proto, "status": "open"}]
                    })
    except Exception as e:
        logging.error("[nmap-fallback] Failed to parse nmap XML: %s", e)

    with open(json_file, "w") as f:
        json.dump(results, f)

    logging.info("[nmap-fallback] Produced %d open ports in %s", len(results), json_file)

    if job_id:
        update_job_status(job_id, "running", "nmap_fallback_completed",
                          f"Nmap fallback found {len(results)} open ports")

    return json_file


def _find_paused_conf(outfile: str, job_id: str) -> Optional[str]:
    """Look for masscan paused.conf and move it to a stable location."""
    candidates = [
        "/app/paused.conf",
        os.path.join(OUTDIR, "paused.conf"),
        "paused.conf",  # CWD
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            dest = os.path.join(OUTDIR, f"paused_{job_id[:8]}.conf")
            try:
                shutil.move(candidate, dest)
                logging.info(f"[{job_id}] Moved paused.conf to {dest}")
                return dest
            except Exception as e:
                logging.warning(f"[{job_id}] Failed to move paused.conf: {e}")
                return candidate
    return None


def _run_masscan(targets: List[str], ports: str, rate: int, interface: Optional[str] = None, job_id: str = None) -> str:
    # Guard against empty ports
    if not ports or not ports.strip():
        ports = DEFAULT_QUICK_PORTS
        logging.warning("[masscan] Empty ports string — defaulting to %s", ports)
    _ensure_outdir()
    ts = int(time.time())

    # Use job_id in filename to prevent race conditions when multiple scans start simultaneously
    job_suffix = job_id[:8] if job_id else str(uuid.uuid4())[:8]
    filename = f"masscan_{ts}_{job_suffix}.json"
    try:
        outfile = validate_output_path(OUTDIR, filename)
    except ValidationError as e:
        raise HTTPException(status_code=500, detail=f"Invalid output path: {e}")

    args = ["masscan", "--rate", str(rate), "-oJ", outfile, "-p", ports, "--wait", "30"]

    target_str = ", ".join(targets[:3]) + ("..." if len(targets) > 3 else "")
    logging.info("scan cmd: masscan --rate %s -oJ %s -p %s --wait 30 %s",str(rate),outfile,ports,str(targets))

    if job_id:
        update_job_status(job_id, "running", "masscan", f"Scanning {target_str} ports {ports}")

    if interface:
        logging.info("scan cmd: masscan --rate %s -oJ %s -p %s -e %s --wait 30 %s",str(rate),outfile,ports,interface,str(targets))
        args += ["-e", interface]

    # Append targets last
    args += targets

    try:
        start_time = time.time()

        # Use Popen for process tracking (allows SIGINT for pause/resume)
        proc = subprocess.Popen(args)
        if job_id:
            with _processes_lock:
                _running_processes[job_id] = proc

        try:
            proc.communicate()
        finally:
            if job_id:
                with _processes_lock:
                    _running_processes.pop(job_id, None)

        duration = time.time() - start_time
        returncode = proc.returncode

        # SIGINT produces exit code -2 (or 130): masscan writes paused.conf
        if returncode in (-2, 130):
            paused = _find_paused_conf(outfile, job_id or job_suffix)
            if paused:
                raise _MasscanInterruptedError(paused)
            # No paused.conf found — treat as failure
            logging.warning("[%s] Masscan SIGINT but no paused.conf found", job_id or "no-job")

        if returncode != 0 and returncode not in (-2, 130):
            logging.warning("[%s] Masscan exited with code %s — falling back to nmap", job_id or "no-job", returncode)
            return _run_nmap_fallback(targets, ports, job_id)

        # Check if masscan actually found anything — on Docker Desktop/macOS
        # raw SYN packets often silently fail (0.00-kpps, no results)
        if _masscan_results_empty(outfile):
            logging.warning("[%s] Masscan produced empty results after %.1fs — "
                            "raw sockets likely blocked (Docker Desktop). "
                            "Falling back to nmap.", job_id or "no-job", duration)
            return _run_nmap_fallback(targets, ports, job_id)

        if job_id:
            update_job_status(job_id, "running", "masscan_completed", f"Masscan completed in {duration:.1f}s")

        logging.info(f"Masscan completed in {duration:.1f}s, output: {outfile}")
    except _MasscanInterruptedError:
        raise  # Let callers handle this
    except subprocess.CalledProcessError as e:
        logging.warning("[%s] Masscan failed: %s — falling back to nmap", job_id or "no-job", e)
        return _run_nmap_fallback(targets, ports, job_id)

    return outfile

def _run_masscan_then_nmap_async(job_id: str, targets: List[str], ports: str, rate: int, interface: Optional[str]):
    """Background task to run masscan then nmap"""
    try:
        start_time = time.time()
        # Emit webhook for scan start
        emit_webhook_event("scan_started", "nmap", {
            "job_id": job_id,
            "scan_type": "masscan-then-nmap",
            "targets": targets[:10],  # Limit to first 10 for payload size
            "targets_count": len(targets),
            "ports": ports,
            "rate": rate
        })
        masscan_cmd_str = f"masscan --rate {rate} -p {ports} --wait 30 {' '.join(targets[:5])}{'...' if len(targets)>5 else ''}"
        write_audit("scan_started", "masscan-then-nmap", "nmap_scanner", {
            "job_id": job_id, "targets": targets[:20], "targets_count": len(targets),
            "parameters": {"ports": ports, "rate": rate}, "execution_mode": "local",
            "command": masscan_cmd_str,
        })

        # 1) Run Masscan
        push_job_command(job_id, "masscan", masscan_cmd_str)
        update_job_status(job_id, "running", "masscan_starting", f"Starting masscan for {len(targets)} targets")
        path = _run_masscan(targets, ports, rate, interface, job_id)

        # Pre-copy masscan output for session results (enrichment may delete it)
        _masscan_copy = path + ".session_copy"
        try:
            if os.path.exists(path):
                shutil.copy2(path, _masscan_copy)
        except Exception:
            _masscan_copy = None

        # 2) Ingest Masscan JSON to rag-api
        update_job_status(job_id, "running", "ingest_masscan", "Ingesting masscan results to database")
        with open(path, "rb") as fh:
            resp = requests.post(
                f"{API_BASE}/ingest/masscan",
                headers={"x-api-key": API_KEY},
                files={"file": ("masscan.json", fh, "application/json")},
                timeout=INGEST_TIMEOUT,
                verify=False,
            )
        if resp.status_code >= 300:
            update_job_status(job_id, "failed", "ingest_failed", error=f"HTTP {resp.status_code}: {resp.text}")
            return

        ingest_payload = {}
        try:
            ingest_payload = resp.json()
        except Exception:
            pass

        # 3) Run Nmap enrichment
        nmap_cmd_str = f"nmap -Pn -sT -sV -T4 -p <open_ports> {' '.join(targets[:5])}{'...' if len(targets)>5 else ''}"
        push_job_command(job_id, "nmap-enrichment", nmap_cmd_str)
        update_job_status(job_id, "running", "nmap_enrichment", "Running nmap service detection on open ports")
        try:
            from app.run_masscan_nmap import main as mass2nmap
        except Exception as e:
            update_job_status(job_id, "failed", "nmap_import_failed", error=f"Cannot import nmap: {e}")
            return

        def _nmap_progress(pct, eta_sec):
            eta_str = f", ~{eta_sec // 60}m{eta_sec % 60:02d}s left" if eta_sec else ""
            update_job_status(job_id, "running", "nmap_enrichment",
                              f"Nmap enrichment {pct}% complete{eta_str}")

        _ensure_outdir()
        stats = mass2nmap(progress_callback=_nmap_progress)

        # Success!
        duration_s = round(time.time() - start_time, 2)
        result = {"ok": True, "masscan_out": path, "ingest": ingest_payload, "stats": stats,
                  "command": masscan_cmd_str, "duration_s": duration_s}
        update_job_status(job_id, "completed", "done", "Scan completed successfully", result=result)

        # Save session results
        session_files = []
        # Use pre-saved masscan copy (original may have been consumed by enrichment)
        mc = _masscan_copy if _masscan_copy and os.path.exists(_masscan_copy) else path
        session_files.append(mc)
        # Collect nmap XML files generated during this job and parse them
        nmap_parsed = []
        for f in pathlib.Path(OUTDIR).glob("nmap_*.xml"):
            try:
                if f.stat().st_mtime >= start_time:
                    session_files.append(str(f))
                    summary = _parse_nmap_xml_summary(str(f))
                    if summary:
                        nmap_parsed.extend(summary["hosts"])
            except OSError:
                pass
        # Write parsed results JSON
        results_file = pathlib.Path(OUTDIR) / f"scan_results_{job_id[:8]}.json"
        results_file.write_text(json.dumps({
            "job_id": job_id,
            "targets": targets[:10],
            "ports": ports,
            "masscan_results": json.loads(pathlib.Path(mc).read_text()) if os.path.exists(mc) else [],
            "nmap_results": nmap_parsed,
            "stats": stats,
        }, indent=2))
        session_files.append(str(results_file))
        _save_session_results(job_id, "masscan-then-nmap", "nmap_scanner", session_files,
                              metadata={"targets": targets[:10], "ports": ports, "stats": stats})
        # Cleanup temp copy
        if _masscan_copy and os.path.exists(_masscan_copy):
            try: os.remove(_masscan_copy)
            except OSError: pass

        # Emit webhook for scan completion
        emit_webhook_event("scan_completed", "nmap", {
            "job_id": job_id,
            "targets_count": len(targets),
            "stats": stats
        })
        write_audit("scan_completed", "masscan-then-nmap", "nmap_scanner", {
            "job_id": job_id, "duration_s": duration_s,
            "findings_count": stats.get("total_ports", 0) if isinstance(stats, dict) else 0,
            "command": masscan_cmd_str,
        })

        # Trigger scan recommender for discovered services
        try:
            _trigger_scan_recommender(nmap_parsed, job_id)
        except Exception:
            logging.warning(f"[{job_id}] Scan recommender trigger failed (non-fatal)")

        # Auto-trigger subfinder for domain targets
        try:
            _trigger_subfinder_for_domains(targets, job_id)
        except Exception:
            logging.debug(f"[{job_id}] Subfinder auto-trigger failed (non-fatal)")

    except _MasscanInterruptedError as ie:
        logging.info(f"[{job_id}] Masscan interrupted (paused), conf={ie.paused_conf}")
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id]["paused_conf"] = ie.paused_conf
        update_job_status(job_id, "stopped", "paused", f"Masscan paused — resume available")
        emit_webhook_event("scan_stopped", "nmap", {
            "job_id": job_id, "resumable": True, "paused_conf": ie.paused_conf
        })

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[{job_id}] Error: {tb}")
        update_job_status(job_id, "failed", "error", error=f"{type(e).__name__}: {e}\n{tb}")

        # Emit webhook for scan failure
        emit_webhook_event("scan_failed", "nmap", {
            "job_id": job_id,
            "error": str(e)
        })
        write_audit("scan_failed", "masscan-then-nmap", "nmap_scanner", {
            "job_id": job_id, "error": str(e),
        })

def _run_masscan_only_async(job_id: str, targets: List[str], ports: str, rate: int, interface: Optional[str]):
    """Background task to run masscan only"""
    try:
        # Emit webhook for scan start
        emit_webhook_event("scan_started", "masscan", {
            "job_id": job_id,
            "scan_type": "masscan-only",
            "targets": targets[:10],  # Limit to first 10 for payload size
            "targets_count": len(targets),
            "ports": ports,
            "rate": rate
        })
        start_time = time.time()
        write_audit("scan_started", "masscan-only", "nmap_scanner", {
            "job_id": job_id, "targets": targets[:20], "targets_count": len(targets),
            "parameters": {"ports": ports, "rate": rate}, "execution_mode": "local",
        })

        # Run Masscan
        update_job_status(job_id, "running", "masscan_starting", f"Starting masscan for {len(targets)} targets")
        path = _run_masscan(targets, ports, rate, interface, job_id)

        # Ingest Masscan results
        update_job_status(job_id, "running", "ingest_masscan", "Ingesting masscan results to database")
        with open(path, "rb") as fh:
            resp = requests.post(
                f"{API_BASE}/ingest/masscan",
                headers={"x-api-key": API_KEY},
                files={"file": ("masscan.json", fh, "application/json")},
                timeout=INGEST_TIMEOUT,
                verify=False,
            )
        if resp.status_code >= 300:
            update_job_status(job_id, "failed", "ingest_failed", error=f"HTTP {resp.status_code}: {resp.text}")
            return

        ingest_payload = {}
        try:
            ingest_payload = resp.json()
        except Exception:
            pass

        # Success!
        result = {
            "ok": True,
            "masscan_out": path,
            "ingest_masscan": ingest_payload,
            "size": os.path.getsize(path) if os.path.exists(path) else 0
        }
        update_job_status(job_id, "completed", "done", "Masscan completed successfully", result=result)

        # Save session results
        _save_session_results(job_id, "masscan-only", "nmap_scanner", [path],
                              metadata={"targets": targets[:10], "ports": ports})

        # Emit webhook for scan completion
        emit_webhook_event("scan_completed", "masscan", {
            "job_id": job_id,
            "targets_count": len(targets)
        })
        write_audit("scan_completed", "masscan-only", "nmap_scanner", {
            "job_id": job_id, "duration_s": round(time.time() - start_time, 2),
        })

    except _MasscanInterruptedError as ie:
        logging.info(f"[{job_id}] Masscan-only interrupted (paused), conf={ie.paused_conf}")
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id]["paused_conf"] = ie.paused_conf
        update_job_status(job_id, "stopped", "paused", f"Masscan paused — resume available")
        emit_webhook_event("scan_stopped", "masscan", {
            "job_id": job_id, "resumable": True, "paused_conf": ie.paused_conf
        })

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[{job_id}] Error: {tb}")
        update_job_status(job_id, "failed", "error", error=f"{type(e).__name__}: {e}\n{tb}")

        # Emit webhook for scan failure
        emit_webhook_event("scan_failed", "masscan", {
            "job_id": job_id,
            "error": str(e)
        })
        write_audit("scan_failed", "masscan-only", "nmap_scanner", {
            "job_id": job_id, "error": str(e),
        })


def _run_nmap_proxied_async(job_id: str, targets: List[str], ports: str, proxy: str):
    """Background task: run nmap through a SOCKS proxy (no masscan).

    Uses -sT (TCP connect scan) because raw SYN scanning cannot traverse
    a SOCKS proxy.  The --proxies flag was added in nmap 7.x.
    """
    try:
        start_time = time.time()
        _ensure_outdir()
        ts = int(time.time())

        update_job_status(job_id, "running", "nmap_proxied_starting",
                          f"Starting proxied nmap scan for {len(targets)} targets through {proxy}")

        emit_webhook_event("scan_started", "nmap-proxied", {
            "job_id": job_id, "targets": targets[:10], "ports": ports, "proxy": proxy
        })
        write_audit("scan_started", "nmap-proxied", "nmap_scanner", {
            "job_id": job_id, "targets": targets[:20], "targets_count": len(targets),
            "parameters": {"ports": ports}, "proxy": proxy, "execution_mode": "local",
        })

        targets_str = " ".join(targets)
        outbase_name = f"nmap_{ts}_{job_id[:8]}_proxied"
        outbase = validate_output_path(OUTDIR, outbase_name)
        outfile = outbase + ".xml"

        # Record output base for --resume
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id]["nmap_log_base"] = outbase

        # nmap only supports socks4://, not socks5:// — downgrade automatically
        nmap_proxy = proxy.replace("socks5://", "socks4://")

        # Build nmap command: TCP connect scan through SOCKS proxy
        # NOTE: -oA writes .nmap + .gnmap + .xml; required for `nmap --resume`
        opts = _nmap_scan_opts
        timing = opts.get("timing", "T4")
        cmd = [
            "nmap", "-sT", "--proxies", nmap_proxy,
            "-p", ports,
            "-oA", outbase,
            "--open",
            "--stats-every", "30s",
            f"-{timing}",
        ]

        # Service detection: per-scan param overrides env var
        svc_detect_param = opts.get("service_detection")
        svc_detect = svc_detect_param if svc_detect_param is not None else (os.environ.get("NMAP_SERVICE_DETECTION", "1") == "1")
        if svc_detect:
            vi = opts.get("version_intensity")
            version_intensity = str(vi) if vi is not None else os.environ.get("NMAP_VERSION_INTENSITY", "9")
            cmd.extend(["-sV", "--version-intensity", version_intensity])

        # OS detection
        if opts.get("os_detection"):
            cmd.extend(["-O"])

        # NSE scripts: per-scan overrides env
        scripts = opts.get("scripts") or os.environ.get("NMAP_SCRIPTS", "")
        if scripts:
            cmd.extend(["--script", scripts])

        # Script args
        script_args = opts.get("script_args")
        if script_args:
            cmd.extend(["--script-args", script_args])

        # Extra raw args (advanced)
        extra_args = opts.get("extra_args")
        if extra_args:
            cmd.extend(extra_args.split())

        cmd.extend(targets)

        logging.info(f"[{job_id[:8]}] Proxied nmap command: {' '.join(cmd)}")

        update_job_status(job_id, "running", "nmap_proxied_scanning",
                          f"Nmap scanning {len(targets)} targets through proxy")

        timeout_s = _resolve_timeout(opts.get("timeout_seconds"),
                                     NMAP_TIMEOUT_PROXIED, "scan_timeout_nmap_proxied")
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)

        if cp.returncode not in (0, 1):  # nmap returns 1 if some hosts are down
            update_job_status(job_id, "failed", "nmap_error",
                              error=f"nmap exit {cp.returncode}: {cp.stderr[:500]}")
            return

        # Ingest results
        if os.path.exists(outfile):
            update_job_status(job_id, "running", "ingest_nmap", "Ingesting proxied nmap results")
            try:
                with open(outfile, "rb") as fh:
                    resp = requests.post(
                        f"{API_BASE}/ingest/nmap",
                        headers={"x-api-key": API_KEY},
                        files={"file": ("nmap.xml", fh, "application/xml")},
                        params={"job_id": job_id},
                        timeout=INGEST_TIMEOUT,
                        verify=False,
                    )
                if resp.status_code >= 300:
                    logging.warning(f"[{job_id[:8]}] Ingest returned {resp.status_code}")
            except Exception as e:
                logging.error(f"[{job_id[:8]}] Ingest error: {e}")

            # Parse for scan recommender
            summary = _parse_nmap_xml_summary(outfile)
            if summary and summary.get("hosts"):
                _trigger_scan_recommender(summary["hosts"], job_id)

        elapsed = time.time() - start_time
        result = {"ok": True, "nmap_out": outfile, "elapsed_sec": round(elapsed, 1), "proxied": True}
        update_job_status(job_id, "completed", "done", "Proxied scan completed", result=result)

        emit_webhook_event("scan_completed", "nmap-proxied", {
            "job_id": job_id, "elapsed_sec": round(elapsed, 1)
        })
        write_audit("scan_completed", "nmap-proxied", "nmap_scanner", {
            "job_id": job_id, "duration_s": round(elapsed, 2), "proxy": proxy,
        })

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[{job_id}] Proxied scan error: {tb}")
        update_job_status(job_id, "failed", "error", error=f"{type(e).__name__}: {e}")
        emit_webhook_event("scan_failed", "nmap-proxied", {"job_id": job_id, "error": str(e)})
        write_audit("scan_failed", "nmap-proxied", "nmap_scanner", {
            "job_id": job_id, "error": str(e), "proxy": proxy,
        })

### masscan only

@app.post("/jobs/masscan-then-nmap")
def masscan_then_nmap(body: MasscanBody, background_tasks: BackgroundTasks):
    """
    Start an async masscan + nmap scan job.
    Returns immediately with a job_id to track progress.
    Use GET /jobs/{job_id} to check status.

    When `proxy` is set (SOCKS URL), masscan is skipped entirely and nmap runs
    with `-sT --proxies {proxy}` (TCP connect scan through SOCKS proxy).
    """
    # Validate inputs
    body.validate_inputs()

    # Store per-scan nmap options for the background task to pick up
    global _nmap_scan_opts
    _nmap_scan_opts = {
        k: v for k, v in {
            "service_detection": body.service_detection,
            "version_intensity": body.version_intensity,
            "scripts": body.scripts,
            "scan_type_flag": body.scan_type_flag,
            "timing": body.timing,
            "os_detection": body.os_detection,
            "script_args": body.script_args,
            "extra_args": body.extra_args,
            "timeout_seconds": body.timeout_seconds,
        }.items() if v is not None
    }

    if body.proxy:
        # Proxied scan: skip masscan, go straight to nmap -sT --proxies
        job_id = create_job("nmap-proxied", {
            "targets": body.targets,
            "ports": body.ports,
            "proxy": body.proxy,
            **_nmap_scan_opts,
        })
        background_tasks.add_task(
            _run_nmap_proxied_async,
            job_id, body.targets, body.ports, body.proxy
        )
        return {
            "ok": True,
            "job_id": job_id,
            "message": "Proxied nmap scan started (masscan skipped). Use GET /jobs/{job_id} to check status.",
            "status_url": f"/jobs/{job_id}",
            "proxy": body.proxy,
        }

    # Create job
    job_id = create_job("masscan-then-nmap", {
        "targets": body.targets,
        "ports": body.ports,
        "rate": body.rate,
        "interface": body.interface,
        **_nmap_scan_opts,
    })

    # Start background task
    background_tasks.add_task(
        _run_masscan_then_nmap_async,
        job_id, body.targets, body.ports, body.rate, body.interface
    )

    return {
        "ok": True,
        "job_id": job_id,
        "message": "Scan job started. Use GET /jobs/{job_id} to check status.",
        "status_url": f"/jobs/{job_id}"
    }

@app.post("/jobs/nmap-from-masscan")
def nmap_from_masscan():
    try:
        # Import at call-time to avoid startup failures if script is missing
        from app.run_masscan_nmap import main as mass2nmap
    except Exception as e:
        raise HTTPException(status_code=501, detail=f"run_masscan_nmap not available: {type(e).__name__}: {e}")
    try:
        # Ensure output directory exists so raw files can be written to the mounted path
        _ensure_outdir()
        stats = mass2nmap()
        return {"ok": True, "stats": stats}
    except Exception as e:
        tb = traceback.format_exc()
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "traceback": tb}

def run_nmap_batch(ip, ports, batch_idx):
    """Run nmap scan on a batch of ports for a single IP"""
    # Validate IP address
    try:
        validated_ip = validate_scan_target(ip, allow_private=True)
    except ValidationError as e:
        raise RuntimeError(f"Invalid IP address: {e}")

    # Create safe filename from IP with timestamp to prevent overwrites
    safe_ip = _safe_name(validated_ip)
    ts = int(time.time())
    filename = f"nmap_{safe_ip}_{ts}_{batch_idx}.xml"

    try:
        xml_path = validate_output_path(OUTDIR, filename)
    except ValidationError as e:
        raise RuntimeError(f"Invalid output path: {e}")

    # Ensure parent directory exists
    Path(xml_path).parent.mkdir(parents=True, exist_ok=True)

    # Build nmap command — per-scan opts override env defaults
    opts = _nmap_scan_opts
    scan_type = opts.get("scan_type_flag", "-sT")
    timing = opts.get("timing", "T4")
    cmd = ["nmap", "-Pn", scan_type, f"-{timing}", "-p", ",".join(map(str, ports))]

    # Service detection
    svc_param = opts.get("service_detection")
    service_detection = svc_param if svc_param is not None else (os.environ.get("NMAP_SERVICE_DETECTION", "1") == "1")
    vi_param = opts.get("version_intensity")
    version_intensity = str(vi_param) if vi_param is not None else os.environ.get("NMAP_VERSION_INTENSITY", "9")
    extra_scripts = opts.get("scripts") or os.environ.get("NMAP_SCRIPTS", "")

    if service_detection:
        cmd += ["-sV", "--version-intensity", version_intensity]
    if opts.get("os_detection"):
        cmd += ["-O"]
    if extra_scripts:
        cmd += ["--script", extra_scripts]
    if opts.get("script_args"):
        cmd += ["--script-args", opts["script_args"]]
    if opts.get("extra_args"):
        cmd += opts["extra_args"].split()

    base_path = xml_path[:-4] if xml_path.endswith(".xml") else xml_path
    cmd += ["--stats-every", "30s", "-oA", base_path, validated_ip]

    # Record output base for --resume (per-IP batches share via opts)
    job_id_for_log = opts.get("job_id")
    if job_id_for_log:
        with jobs_lock:
            if job_id_for_log in jobs:
                bases = jobs[job_id_for_log].setdefault("nmap_log_bases", [])
                if base_path not in bases:
                    bases.append(base_path)

    timeout_s = _resolve_timeout(opts.get("timeout_seconds"),
                                 NMAP_TIMEOUT_SERVICE, "scan_timeout_nmap_service")
    cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    if cp.returncode != 0:
        raise RuntimeError(f"nmap exit {cp.returncode}: {cp.stderr or cp.stdout}")
    return xml_path

@app.post("/jobs/masscan-only")
def masscan_only(body: MasscanBody, background_tasks: BackgroundTasks):
    """
    Start an async masscan-only scan job.
    Returns immediately with a job_id to track progress.
    Use GET /jobs/{job_id} to check status.
    """
    # Validate inputs
    body.validate_inputs()

    # Create job
    job_id = create_job("masscan-only", {
        "targets": body.targets,
        "ports": body.ports,
        "rate": body.rate,
        "interface": body.interface
    })

    # Start background task
    background_tasks.add_task(
        _run_masscan_only_async,
        job_id, body.targets, body.ports, body.rate, body.interface
    )

    return {
        "ok": True,
        "job_id": job_id,
        "message": "Masscan job started. Use GET /jobs/{job_id} to check status.",
        "status_url": f"/jobs/{job_id}"
    }


def _run_masscan_resume_async(new_job_id: str, paused_conf: str, original_job_id: str):
    """Background task to resume a paused masscan scan."""
    try:
        _ensure_outdir()
        ts = int(time.time())
        outfile = validate_output_path(OUTDIR, f"masscan_{ts}_{new_job_id[:8]}_resumed.json")

        emit_webhook_event("scan_started", "masscan", {
            "job_id": new_job_id,
            "scan_type": "masscan-resume",
            "resumed_from": original_job_id,
        })

        update_job_status(new_job_id, "running", "masscan_resuming",
                          f"Resuming masscan from {os.path.basename(paused_conf)}")

        args = ["masscan", "--resume", paused_conf, "-oJ", outfile]
        logging.info(f"[{new_job_id}] Resuming masscan: {' '.join(args)}")

        proc = subprocess.Popen(args)
        with _processes_lock:
            _running_processes[new_job_id] = proc

        try:
            proc.communicate()
        finally:
            with _processes_lock:
                _running_processes.pop(new_job_id, None)

        returncode = proc.returncode

        # Handle SIGINT again (re-pausable)
        if returncode in (-2, 130):
            paused = _find_paused_conf(outfile, new_job_id)
            if paused:
                raise _MasscanInterruptedError(paused)

        if returncode != 0 and returncode not in (-2, 130):
            update_job_status(new_job_id, "failed", "error",
                              error=f"Masscan resume exited with code {returncode}")
            return

        # Ingest results
        if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
            update_job_status(new_job_id, "running", "ingest_masscan", "Ingesting resumed scan results")
            with open(outfile, "rb") as fh:
                resp = requests.post(
                    f"{API_BASE}/ingest/masscan",
                    headers={"x-api-key": API_KEY},
                    files={"file": ("masscan.json", fh, "application/json")},
                    timeout=INGEST_TIMEOUT,
                    verify=False,
                )
            ingest_payload = {}
            try:
                ingest_payload = resp.json()
            except Exception:
                pass
        else:
            ingest_payload = {"note": "no results file"}

        result = {
            "ok": True,
            "masscan_out": outfile,
            "ingest_masscan": ingest_payload,
            "resumed_from": original_job_id,
        }
        update_job_status(new_job_id, "completed", "done", "Resumed scan completed", result=result)

        # Clean up paused.conf
        try:
            if os.path.exists(paused_conf):
                os.remove(paused_conf)
        except OSError:
            pass

        _save_session_results(new_job_id, "masscan-resume", "nmap_scanner", [outfile],
                              metadata={"resumed_from": original_job_id})

        emit_webhook_event("scan_completed", "masscan", {
            "job_id": new_job_id, "resumed_from": original_job_id
        })

    except _MasscanInterruptedError as ie:
        logging.info(f"[{new_job_id}] Resumed masscan interrupted again, conf={ie.paused_conf}")
        with jobs_lock:
            if new_job_id in jobs:
                jobs[new_job_id]["paused_conf"] = ie.paused_conf
        update_job_status(new_job_id, "stopped", "paused", "Masscan paused again — resume available")
        emit_webhook_event("scan_stopped", "masscan", {
            "job_id": new_job_id, "resumable": True, "paused_conf": ie.paused_conf
        })

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[{new_job_id}] Resume error: {tb}")
        update_job_status(new_job_id, "failed", "error", error=f"{type(e).__name__}: {e}\n{tb}")
        emit_webhook_event("scan_failed", "masscan", {
            "job_id": new_job_id, "error": str(e)
        })


@app.post("/jobs/{job_id}/resume")
def resume_job(job_id: str, background_tasks: BackgroundTasks):
    """Resume a stopped masscan scan from its paused.conf."""
    try:
        sanitize_scan_id(job_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid job_id: {e}")

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] != "stopped":
        raise HTTPException(status_code=400, detail=f"Job is {job['status']}, not stopped")

    paused_conf = job.get("paused_conf")
    if not paused_conf or not os.path.exists(paused_conf):
        raise HTTPException(status_code=400, detail="No paused.conf found for this job — not resumable")

    # Create a new job linked to the original
    new_job_id = create_job("masscan-resume", {
        "resumed_from": job_id,
        "paused_conf": paused_conf,
        "original_params": job.get("params", {}),
    })
    with jobs_lock:
        if new_job_id in jobs:
            jobs[new_job_id]["resumed_from"] = job_id

    background_tasks.add_task(_run_masscan_resume_async, new_job_id, paused_conf, job_id)

    return {
        "ok": True,
        "job_id": new_job_id,
        "resumed_from": job_id,
        "message": "Resume job started. Use GET /jobs/{job_id} to check status.",
        "status_url": f"/jobs/{new_job_id}",
    }


# ===============================
# Nmap --Resume Support
# ===============================

def _list_resumable_nmap_logs(job: dict) -> List[str]:
    """Return list of nmap output bases (no extension) that have a resumable log.

    `nmap --resume` requires a `.nmap` (normal) or `.gnmap` (grepable) log
    that the previous scan was writing to. We track these in jobs[id]["nmap_log_base"]
    (single) or ["nmap_log_bases"] (list — for batched runs).
    """
    candidates: List[str] = []
    base = job.get("nmap_log_base")
    if base:
        candidates.append(base)
    candidates.extend(job.get("nmap_log_bases") or [])
    seen: set = set()
    out: List[str] = []
    for b in candidates:
        if b in seen:
            continue
        seen.add(b)
        # Resume needs at least one of .nmap or .gnmap to exist
        if os.path.exists(b + ".nmap") or os.path.exists(b + ".gnmap"):
            out.append(b)
    return out


_GNMAP_PORT_RE = __import__("re").compile(
    r"^(\d+)/(open|open\|filtered|filtered)/(tcp|udp|sctp)//([^/]*)//([^/]*)/?$"
)


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&apos;"))


def _gnmap_to_xml(gnmap_path: str, out_xml_path: str) -> bool:
    """Convert nmap grepable output to a minimal but valid nmap XML.

    `nmap --resume` writes the .gnmap line-by-line and keeps it well-formed,
    but appends to .xml leaving it malformed. This converter produces a clean
    XML that the existing /ingest/nmap parser can consume.

    Returns True on success.
    """
    if not os.path.exists(gnmap_path):
        return False

    hosts: dict = {}  # ip → {"hostname": str, "ports": [(port, proto, state, service, version)]}
    args_line = ""
    start_ts = "0"

    with open(gnmap_path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("# Nmap") and "scan initiated" in line and not args_line:
                # "# Nmap 7.95 scan initiated Mon Apr 13 ... as: nmap ..."
                if " as: " in line:
                    args_line = line.split(" as: ", 1)[1].strip()
                continue
            if not line.startswith("Host:"):
                continue
            # "Host: 192.168.1.150 (hostname)\tStatus: Up"
            # "Host: 192.168.1.150 (hostname)\tPorts: 53/open/udp//domain//banner/, ...\tIgnored State: ..."
            try:
                head, *rest = line.split("\t")
                ip_part = head[len("Host:"):].strip()
                ip = ip_part.split(" ", 1)[0].strip()
                hostname = ""
                if "(" in ip_part and ip_part.endswith(")"):
                    hostname = ip_part[ip_part.index("(") + 1:-1].strip()
            except Exception:
                continue
            entry = hosts.setdefault(ip, {"hostname": hostname, "ports": []})
            for chunk in rest:
                chunk = chunk.strip()
                if chunk.startswith("Ports:"):
                    body = chunk[len("Ports:"):].strip()
                    if not body:
                        continue
                    for item in body.split(","):
                        item = item.strip()
                        if not item:
                            continue
                        # 53/open/udp//domain//banner/  OR  53/open/udp//domain// (no version)
                        m = _GNMAP_PORT_RE.match(item)
                        if not m:
                            # Tolerate the trailing-fields variant "53/open/udp//domain///"
                            parts = item.split("/")
                            if len(parts) >= 5:
                                try:
                                    port = int(parts[0])
                                except Exception:
                                    continue
                                state = parts[1]
                                proto = parts[2]
                                service = parts[4]
                                version = parts[6] if len(parts) > 6 else ""
                                entry["ports"].append((port, proto, state, service, version))
                            continue
                        port = int(m.group(1))
                        state = m.group(2)
                        proto = m.group(3)
                        service = m.group(4)
                        version = m.group(5)
                        entry["ports"].append((port, proto, state, service, version))

    # Synthesize XML
    parts = ['<?xml version="1.0" encoding="UTF-8"?>']
    parts.append('<!DOCTYPE nmaprun>')
    parts.append(
        f'<nmaprun scanner="nmap" args="{_xml_escape(args_line)}" '
        f'start="{start_ts}" version="resume-fallback" xmloutputversion="1.05">'
    )
    parts.append('<scaninfo type="connect" protocol="tcp" numservices="0" services=""/>')
    parts.append('<verbose level="0"/><debugging level="0"/>')
    for ip, h in hosts.items():
        parts.append('<host>')
        parts.append('<status state="up" reason="user-set" reason_ttl="0"/>')
        parts.append(f'<address addr="{_xml_escape(ip)}" addrtype="ipv4"/>')
        if h["hostname"]:
            parts.append(
                f'<hostnames><hostname name="{_xml_escape(h["hostname"])}" type="user"/></hostnames>'
            )
        else:
            parts.append('<hostnames/>')
        parts.append('<ports>')
        for port, proto, state, service, version in h["ports"]:
            xstate = "open" if "open" in state else "filtered"
            parts.append(f'<port protocol="{proto}" portid="{port}">')
            parts.append(f'<state state="{xstate}" reason="resumed" reason_ttl="0"/>')
            if service or version:
                if version:
                    parts.append(
                        f'<service name="{_xml_escape(service or "")}" '
                        f'product="{_xml_escape(version)}" method="probed" conf="5"/>'
                    )
                else:
                    parts.append(f'<service name="{_xml_escape(service)}" method="probed" conf="3"/>')
            parts.append('</port>')
        parts.append('</ports>')
        parts.append('<times srtt="0" rttvar="0" to="0"/>')
        parts.append('</host>')
    parts.append(
        '<runstats><finished time="0" timestr="" elapsed="0" summary="resume-fallback" exit="success"/>'
        f'<hosts up="{len(hosts)}" down="0" total="{len(hosts)}"/></runstats>'
    )
    parts.append('</nmaprun>')

    try:
        with open(out_xml_path, "w") as f:
            f.write("\n".join(parts))
        return True
    except Exception as e:
        logging.warning(f"gnmap→xml write failed: {e}")
        return False


def _xml_is_valid(xml_path: str) -> bool:
    """Quick XML well-formedness check by attempting to parse."""
    if not os.path.exists(xml_path):
        return False
    try:
        import xml.etree.ElementTree as _ET
        _ET.parse(xml_path)
        return True
    except Exception:
        return False


def _run_nmap_resume_async(new_job_id: str, log_base: str, original_job_id: str,
                            timeout_seconds: Optional[int] = None):
    """Background task to resume an interrupted nmap scan from `<base>.nmap`."""
    try:
        emit_webhook_event("scan_started", "nmap", {
            "job_id": new_job_id,
            "scan_type": "nmap-resume",
            "resumed_from": original_job_id,
            "log_base": log_base,
        })

        update_job_status(new_job_id, "running", "nmap_resuming",
                          f"Resuming nmap from {os.path.basename(log_base)}")

        # nmap --resume picks the .nmap or .gnmap log; prefer .nmap (richer).
        log_file = log_base + ".nmap"
        if not os.path.exists(log_file):
            log_file = log_base + ".gnmap"
        if not os.path.exists(log_file):
            update_job_status(new_job_id, "failed", "no_log",
                              error=f"No .nmap or .gnmap log at {log_base}")
            return

        with jobs_lock:
            if new_job_id in jobs:
                jobs[new_job_id]["nmap_log_base"] = log_base

        cmd = ["nmap", "--resume", log_file]
        logging.info(f"[{new_job_id}] Resuming nmap: {' '.join(cmd)}")

        timeout_s = _resolve_timeout(timeout_seconds,
                                     NMAP_TIMEOUT_RESUME, "scan_timeout_nmap_resume")
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            update_job_status(new_job_id, "failed", "timeout",
                              error=f"nmap --resume exceeded {timeout_s}s")
            return

        if cp.returncode not in (0, 1):
            update_job_status(new_job_id, "failed", "nmap_error",
                              error=f"nmap --resume exit {cp.returncode}: {cp.stderr[:500]}")
            return

        # nmap --resume APPENDS to .xml leaving it malformed (multiple unclosed
        # <nmaprun> tags or a half-written <host>). The .gnmap is line-based and
        # stays well-formed across resume. Strategy:
        #   1. Try the XML as-is
        #   2. If invalid, rebuild a clean XML from the .gnmap and ingest that
        xml_path = log_base + ".xml"
        gnmap_path = log_base + ".gnmap"
        ingest_payload: dict = {}
        ingest_source = "xml"
        ingest_path: Optional[str] = None

        if _xml_is_valid(xml_path):
            ingest_path = xml_path
        elif os.path.exists(gnmap_path):
            rebuilt = log_base + ".resume.xml"
            if _gnmap_to_xml(gnmap_path, rebuilt):
                ingest_path = rebuilt
                ingest_source = "gnmap-fallback"
                logging.info(f"[{new_job_id}] Rebuilt XML from gnmap → {rebuilt}")
            else:
                ingest_payload = {"error": "xml malformed and gnmap rebuild failed"}
        else:
            ingest_payload = {"error": "no usable output file"}

        if ingest_path:
            update_job_status(new_job_id, "running", "ingest_nmap",
                              f"Ingesting resumed nmap results ({ingest_source})")
            try:
                with open(ingest_path, "rb") as fh:
                    resp = requests.post(
                        f"{API_BASE}/ingest/nmap",
                        headers={"x-api-key": API_KEY},
                        files={"file": ("nmap.xml", fh, "application/xml")},
                        params={"job_id": new_job_id},
                        timeout=INGEST_TIMEOUT,
                        verify=False,
                    )
                try:
                    ingest_payload = resp.json()
                except Exception:
                    ingest_payload = {"status_code": resp.status_code}
                ingest_payload["source"] = ingest_source
            except Exception as e:
                logging.error(f"[{new_job_id}] Ingest error: {e}")
                ingest_payload = {"error": str(e), "source": ingest_source}

        result = {
            "ok": True,
            "xml_path": xml_path if os.path.exists(xml_path) else None,
            "log_base": log_base,
            "ingest": ingest_payload,
            "resumed_from": original_job_id,
        }
        update_job_status(new_job_id, "completed", "done",
                          "Resumed nmap scan completed", result=result)

        emit_webhook_event("scan_completed", "nmap", {
            "job_id": new_job_id, "resumed_from": original_job_id
        })

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[{new_job_id}] Nmap resume error: {tb}")
        update_job_status(new_job_id, "failed", "error",
                          error=f"{type(e).__name__}: {e}\n{tb}")
        emit_webhook_event("scan_failed", "nmap", {
            "job_id": new_job_id, "error": str(e)
        })


class NmapResumeBody(BaseModel):
    job_id: Optional[str] = Field(None, description="Original nmap job_id whose log to resume")
    log_base: Optional[str] = Field(None, description="Direct path to nmap output base (no extension). Use instead of job_id if you have the file path")
    timeout_seconds: Optional[int] = Field(None, ge=0, description="Override resume subprocess timeout (seconds)")


@app.get("/jobs/{job_id}/nmap-resume-info")
def nmap_resume_info(job_id: str):
    """Inspect whether an nmap job is resumable and what log files would be used."""
    try:
        sanitize_scan_id(job_id)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid job_id: {e}")
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    bases = _list_resumable_nmap_logs(job)
    return {
        "job_id": job_id,
        "status": job.get("status"),
        "resumable": bool(bases),
        "log_bases": bases,
        "log_files": [
            {"base": b,
             "nmap": (b + ".nmap") if os.path.exists(b + ".nmap") else None,
             "gnmap": (b + ".gnmap") if os.path.exists(b + ".gnmap") else None,
             "xml": (b + ".xml") if os.path.exists(b + ".xml") else None}
            for b in bases
        ],
    }


@app.post("/jobs/nmap-resume")
def nmap_resume(body: NmapResumeBody, background_tasks: BackgroundTasks):
    """Resume an interrupted nmap scan from its `.nmap` log (`nmap --resume <log>`)."""
    log_bases: List[str] = []
    original_job_id = body.job_id

    if body.job_id:
        try:
            sanitize_scan_id(body.job_id)
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=f"Invalid job_id: {e}")
        job = get_job(body.job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        log_bases = _list_resumable_nmap_logs(job)
        if not log_bases:
            raise HTTPException(
                status_code=400,
                detail="No resumable .nmap/.gnmap log for this job. Was the original scan run with -oA?",
            )

    if body.log_base:
        # Confine to OUTDIR to prevent path traversal
        try:
            base = validate_output_path(OUTDIR, os.path.basename(body.log_base))
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=f"Invalid log_base: {e}")
        if not (os.path.exists(base + ".nmap") or os.path.exists(base + ".gnmap")):
            raise HTTPException(status_code=400, detail=f"No .nmap or .gnmap file at {base}")
        log_bases = [base]

    if not log_bases:
        raise HTTPException(status_code=400, detail="Provide either job_id or log_base")

    # If multiple bases (batched original), resume them all in one new job
    new_job_ids = []
    for base in log_bases:
        new_job_id = create_job("nmap-resume", {
            "resumed_from": original_job_id,
            "log_base": base,
            "timeout_seconds": body.timeout_seconds,
        })
        with jobs_lock:
            if new_job_id in jobs:
                jobs[new_job_id]["resumed_from"] = original_job_id
        background_tasks.add_task(
            _run_nmap_resume_async,
            new_job_id, base, original_job_id or "manual", body.timeout_seconds,
        )
        new_job_ids.append(new_job_id)

    primary = new_job_ids[0]
    return {
        "ok": True,
        "job_id": primary,
        "job_ids": new_job_ids,
        "resumed_from": original_job_id,
        "log_bases": log_bases,
        "message": "nmap --resume started. Use GET /jobs/{job_id} to check status.",
        "status_url": f"/jobs/{primary}",
    }


# ===============================
# UDP Scan Support
# ===============================

class UdpScanBody(BaseModel):
    targets: List[str] = Field(..., description="List of IPs/CIDRs to scan")
    ports: str = Field("53,67,68,69,123,137,138,161,162,500,514,520,1434,1900,4500,5353",
                       description="UDP ports to scan (default: common UDP ports)")
    top_ports: Optional[int] = Field(None, ge=1, le=65535, description="Scan top N UDP ports instead of specific ports")
    rate_limit: Optional[str] = Field(None, description="Rate limit (e.g., '100' for 100 packets/sec)")
    timeout_seconds: Optional[int] = Field(None, ge=0, description="Per-job nmap UDP subprocess timeout (seconds). 0/unset → use env default")

    def validate_inputs(self):
        """Validate all inputs for security"""
        validated_targets = []
        for target in self.targets:
            try:
                validated = validate_scan_target(target, allow_private=True)
                validated_targets.append(validated)
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid target '{target}': {e}")
        self.targets = validated_targets

        # Validate ports format - handle both port ranges and nmap arguments
        self.ports = self.ports.strip()
        try:
            if self.ports.startswith('--top-ports'):
                # Handle nmap --top-ports argument (allow spaces, dashes, letters, numbers)
                sanitize_command_arg(self.ports, allowed_chars=r'^[a-zA-Z0-9\s\-=]+$')
            else:
                # Handle traditional port ranges (numbers, commas, dashes only)
                # Strip spaces for traditional port ranges
                self.ports = self.ports.replace(' ', '')
                sanitize_command_arg(self.ports, allowed_chars=r'^[0-9,\-]+$')
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=f"Invalid ports format: {e}")


def _run_udp_scan_async(job_id: str, targets: List[str], ports: str, top_ports: Optional[int], rate_limit: Optional[str]):
    """Background task to run nmap UDP scan"""
    try:
        # Emit webhook for scan start
        emit_webhook_event("scan_started", "nmap-udp", {
            "job_id": job_id,
            "scan_type": "nmap-udp",
            "targets": targets[:10],  # Limit to first 10 for payload size
            "targets_count": len(targets),
            "ports": ports,
            "top_ports": top_ports
        })

        update_job_status(job_id, "running", "udp_scan_starting", f"Starting UDP scan on {len(targets)} targets")

        _ensure_outdir()
        ts = int(time.time())

        all_results = []

        for target in targets:
            try:
                validated_target = validate_scan_target(target, allow_private=True)
            except ValidationError as e:
                logging.error(f"[{job_id}] Invalid target {target}: {e}")
                continue

            safe_target = _safe_name(validated_target)
            base_name = f"nmap_udp_{safe_target}_{ts}"

            try:
                base_path = validate_output_path(OUTDIR, base_name)
            except ValidationError as e:
                logging.error(f"[{job_id}] Invalid output path: {e}")
                continue
            xml_path = base_path + ".xml"

            # Build nmap UDP command — -oA so .nmap log enables --resume
            cmd = ["nmap", "-Pn", "-sU", "-sV", "--version-intensity", "0",
                   "--stats-every", "30s"]

            # Add rate limiting if specified (UDP scans can be slow)
            if rate_limit:
                cmd += ["--max-rate", rate_limit]
            else:
                # Default rate limit for UDP to avoid overwhelming targets
                cmd += ["--max-rate", "100"]

            # Either use top_ports or specific ports
            if top_ports:
                cmd += ["--top-ports", str(top_ports)]
            else:
                cmd += ["-p", ports]

            cmd += ["-oA", base_path, validated_target]

            # Track output base for --resume
            with jobs_lock:
                if job_id in jobs:
                    bases = jobs[job_id].setdefault("nmap_log_bases", [])
                    if base_path not in bases:
                        bases.append(base_path)

            update_job_status(job_id, "running", "udp_scanning", f"UDP scanning {validated_target}")
            logging.info(f"[{job_id}] Running UDP scan: {' '.join(cmd)}")

            timeout_s = _resolve_timeout(_nmap_scan_opts.get("timeout_seconds"),
                                         NMAP_TIMEOUT_UDP, "scan_timeout_nmap_udp")
            try:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)

                if cp.returncode != 0:
                    logging.warning(f"[{job_id}] nmap UDP exit {cp.returncode}: {cp.stderr or cp.stdout}")

                all_results.append({
                    "target": validated_target,
                    "xml_path": xml_path,
                    "log_base": base_path,
                    "return_code": cp.returncode
                })

                # Ingest results to RAG API
                if os.path.exists(xml_path):
                    try:
                        with open(xml_path, "rb") as fh:
                            resp = requests.post(
                                f"{API_BASE}/ingest/nmap",
                                headers={"x-api-key": API_KEY},
                                files={"file": ("nmap_udp.xml", fh, "application/xml")},
                                params={"job_id": job_id, "target": validated_target},
                                timeout=INGEST_TIMEOUT_SHORT,
                                verify=False,
                            )
                        if resp.status_code < 300:
                            logging.info(f"[{job_id}] Ingested UDP results for {validated_target}")
                    except Exception as e:
                        logging.error(f"[{job_id}] Failed to ingest UDP results: {e}")

            except subprocess.TimeoutExpired:
                logging.error(f"[{job_id}] UDP scan timeout for {validated_target}")
                all_results.append({
                    "target": validated_target,
                    "error": "timeout"
                })

        # Success
        result = {
            "ok": True,
            "scan_type": "udp",
            "targets_scanned": len(all_results),
            "results": all_results
        }
        update_job_status(job_id, "completed", "done", "UDP scan completed", result=result)

        # Save session results with parsed findings
        session_files = []
        nmap_parsed = []
        for r in all_results:
            if r.get("xml_path"):
                session_files.append(r["xml_path"])
                summary = _parse_nmap_xml_summary(r["xml_path"])
                if summary:
                    nmap_parsed.extend(summary["hosts"])
        results_file = pathlib.Path(OUTDIR) / f"udp_results_{job_id[:8]}.json"
        results_file.write_text(json.dumps({
            "job_id": job_id, "targets": targets[:10], "ports": ports,
            "nmap_results": nmap_parsed,
        }, indent=2))
        session_files.append(str(results_file))
        _save_session_results(job_id, "nmap-udp", "nmap_scanner", session_files,
                              metadata={"targets": targets[:10], "ports": ports})

        # Emit webhook for scan completion
        emit_webhook_event("scan_completed", "nmap-udp", {
            "job_id": job_id,
            "targets_count": len(targets),
            "targets_scanned": len(all_results)
        })

        # Trigger scan recommender for discovered UDP services
        try:
            _trigger_scan_recommender(nmap_parsed, job_id)
        except Exception:
            logging.warning(f"[{job_id}] Scan recommender trigger failed (non-fatal)")

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[{job_id}] UDP scan error: {tb}")
        update_job_status(job_id, "failed", "error", error=f"{type(e).__name__}: {e}")

        # Emit webhook for scan failure
        emit_webhook_event("scan_failed", "nmap-udp", {
            "job_id": job_id,
            "error": str(e)
        })


@app.post("/jobs/nmap-udp")
def nmap_udp_scan(body: UdpScanBody, background_tasks: BackgroundTasks):
    """
    Start an async nmap UDP scan job.

    UDP scans are slower than TCP scans because UDP doesn't have connection establishment.
    Uses nmap -sU with service detection.

    Returns immediately with a job_id to track progress.
    Use GET /jobs/{job_id} to check status.
    """
    # Validate inputs
    body.validate_inputs()

    # Per-job timeout override (read in subprocess.run via _nmap_scan_opts)
    global _nmap_scan_opts
    _nmap_scan_opts = {"timeout_seconds": body.timeout_seconds} if body.timeout_seconds else {}

    # Create job
    job_id = create_job("nmap-udp", {
        "targets": body.targets,
        "ports": body.ports,
        "top_ports": body.top_ports,
        "rate_limit": body.rate_limit,
        "timeout_seconds": body.timeout_seconds,
    })

    # Start background task
    background_tasks.add_task(
        _run_udp_scan_async,
        job_id, body.targets, body.ports, body.top_ports, body.rate_limit
    )

    return {
        "ok": True,
        "job_id": job_id,
        "message": "UDP scan job started. Note: UDP scans are slower than TCP. Use GET /jobs/{job_id} to check status.",
        "status_url": f"/jobs/{job_id}"
    }


# ===============================
# Logs UI Endpoints
# ===============================

@app.get("/logs/ui", response_class=HTMLResponse)
async def logs_ui():
    """Serve the logs web UI"""
    return HTMLResponse(content=LOGS_UI_HTML)


@app.get("/logs")
async def get_logs(
    level: Optional[str] = Query(None, description="Filter by log level"),
    limit: int = Query(100, ge=1, le=1000, description="Max logs to return"),
    search: Optional[str] = Query(None, description="Search in log messages"),
    job_id: Optional[str] = Query(None, description="Filter by job ID")
):
    """Get logs with optional filtering"""
    handler = get_log_handler()
    logs = await handler.async_get_logs(level=level, limit=limit, search=search, job_id=job_id)
    return {"logs": logs}


@app.get("/logs/stats")
async def get_log_stats():
    """Get logging statistics"""
    handler = get_log_handler()
    stats = await handler.async_get_stats()
    return {"ok": True, "stats": stats}


@app.get("/logs/export")
async def export_logs():
    """Export all logs as JSON file"""
    handler = get_log_handler()
    json_data = await handler.async_export_json()
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=nmap_scanner_logs.json"}
    )


# ===============================
# Full Scan with Parallel Port Discovery
# ===============================

class FullScanRequest(BaseModel):
    targets: List[str] = Field(..., description="List of IPs/CIDRs to scan")
    quick_ports: str = Field(DEFAULT_QUICK_PORTS, description="Ports for quick initial scan")
    full_ports: str = Field("", description="Ports for full scan (empty = skip deep scan)")
    rate: int = Field(1000, ge=1, le=100000, description="Masscan rate (packets per second)")
    interface: Optional[str] = Field(None, description="Network interface for Masscan (-e)")
    run_smb_vuln_scan: bool = Field(False, description="Run SMB vulnerability scan if 139/445 found")
    run_credential_check: bool = Field(False, description="Run credential checking on auth services")
    proxy: Optional[str] = Field(None, description="SOCKS proxy URL. When set, skips masscan phases and uses nmap -sT --proxies")
    timeout_seconds: Optional[int] = Field(None, ge=0, description="Per-batch nmap subprocess timeout (seconds). 0/unset → use env default")

    def validate_inputs(self):
        """Validate all inputs for security"""
        validated_targets = []
        for target in self.targets:
            try:
                validated = validate_scan_target(target, allow_private=True)
                validated_targets.append(validated)
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid target '{target}': {e}")
        self.targets = validated_targets

        # Validate ports format (skip empty full_ports — means no deep scan)
        for ports_field in [self.quick_ports, self.full_ports]:
            if not ports_field.strip():
                continue
            try:
                if ports_field.startswith('--top-ports'):
                    # Handle nmap --top-ports argument (allow spaces, dashes, letters, numbers)
                    sanitize_command_arg(ports_field, allowed_chars=r'^[a-zA-Z0-9\s\-=]+$')
                else:
                    # Handle traditional port ranges (numbers, commas, dashes only)
                    ports_field = ports_field.replace(' ', '')
                    sanitize_command_arg(ports_field, allowed_chars=r'^[0-9,\-]+$')
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid ports format: {e}")

        if self.interface:
            try:
                sanitize_command_arg(self.interface, allowed_chars=r'^[a-zA-Z0-9_-]+$')
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid interface: {e}")


# SMB vulnerability scripts for Samba CVE detection
SAMBA_VULN_SCRIPTS = [
    "smb-vuln-ms17-010",
    "smb-vuln-cve-2017-7494",  # SambaCry
    "smb-vuln-regsvc-dos",
    "smb-vuln-ms08-067",
    "smb-enum-shares",
    "smb-enum-users",
    "smb-os-discovery",
]


def _run_smb_vuln_scan(ip: str, job_id: str = None) -> Dict:
    """Run SMB-specific vulnerability scan including Samba CVE-2007-2447 detection"""
    _ensure_outdir()
    ts = int(time.time())

    safe_ip = _safe_name(ip)
    filename = f"nmap_smb_{safe_ip}_{ts}.xml"

    try:
        xml_path = validate_output_path(OUTDIR, filename)
    except ValidationError as e:
        return {"error": f"Invalid output path: {e}"}

    scripts = ",".join(SAMBA_VULN_SCRIPTS)
    base_path = xml_path[:-4] if xml_path.endswith(".xml") else xml_path
    cmd = [
        "nmap", "-Pn", "-sT", "-sV",
        "-p", "139,445",
        f"--script={scripts}",
        "--stats-every", "30s",
        "-oA", base_path,
        ip
    ]

    if job_id:
        update_job_status(job_id, "running", "smb_vuln_scan", f"Running SMB vulnerability scan on {ip}")
        with jobs_lock:
            if job_id in jobs:
                bases = jobs[job_id].setdefault("nmap_log_bases", [])
                if base_path not in bases:
                    bases.append(base_path)

    logging.info(f"Running SMB vuln scan: {' '.join(cmd)}")

    timeout_s = _resolve_timeout(_nmap_scan_opts.get("timeout_seconds"),
                                 NMAP_TIMEOUT_SMB, "scan_timeout_nmap_smb")
    try:
        start_time = time.time()
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        duration = time.time() - start_time

        result = {
            "target": ip,
            "xml_path": xml_path,
            "duration": duration,
            "return_code": cp.returncode,
            "scripts_run": SAMBA_VULN_SCRIPTS,
        }

        if cp.returncode != 0:
            result["warning"] = f"nmap exit {cp.returncode}: {cp.stderr or cp.stdout}"

        # Parse XML for findings (basic extraction)
        if os.path.exists(xml_path):
            try:
                with open(xml_path, 'r') as f:
                    xml_content = f.read()
                    # Check for CVE mentions
                    import re
                    cves_found = re.findall(r'CVE-\d{4}-\d+', xml_content)
                    if cves_found:
                        result["cves_detected"] = list(set(cves_found))

                    # Check for VULNERABLE keyword
                    if "VULNERABLE" in xml_content.upper():
                        result["vulnerabilities_found"] = True
            except Exception as e:
                logging.warning(f"Failed to parse SMB scan XML: {e}")

        return result

    except subprocess.TimeoutExpired:
        return {"error": "SMB scan timeout", "target": ip}
    except Exception as e:
        return {"error": str(e), "target": ip}


def _run_full_scan_async(
    job_id: str,
    targets: List[str],
    quick_ports: str,
    full_ports: str,
    rate: int,
    interface: Optional[str],
    run_smb_vuln_scan: bool,
    run_credential_check: bool
):
    """
    Background task for phased full scan:
    Phase 1: Quick masscan (1-1000)
    Phase 2: Parallel - Nmap on Phase 1 ports + Masscan (1001-65535)
    Phase 3: Nmap on Phase 2 ports
    Phase 4: SMB vulnerability scan (if enabled and 139/445 found)
    """
    try:
        start_time = time.time()

        # Guard against empty quick_ports
        if not quick_ports or not quick_ports.strip():
            quick_ports = DEFAULT_QUICK_PORTS
            logging.warning(f"[{job_id}] Empty quick_ports — defaulting to {quick_ports}")

        # Emit webhook for scan start
        emit_webhook_event("scan_started", "full-scan", {
            "job_id": job_id,
            "scan_type": "full-scan",
            "targets": targets[:10],
            "targets_count": len(targets),
            "phases": ["quick-discovery", "parallel-enum", "service-detection", "vuln-scan"]
        })

        result = {
            "phases": {},
            "ports_discovered": {"quick": [], "full": []},
            "all_open_ports": [],
            "smb_scan": None,
            "credential_check": None,
        }

        # ========================================
        # PHASE 1: Quick Masscan (1-1000)
        # ========================================
        update_job_status(job_id, "running", "phase1_quick_scan", f"Phase 1: Quick scan ports {quick_ports}")
        logging.info(f"[{job_id}] Phase 1: Quick masscan {quick_ports}")

        quick_path = _run_masscan(targets, quick_ports, rate, interface, job_id)
        quick_ports_found = []

        # Parse masscan results
        try:
            with open(quick_path, 'r') as f:
                masscan_data = json.load(f)
                for entry in masscan_data:
                    if isinstance(entry, dict) and 'ports' in entry:
                        for port_info in entry['ports']:
                            port = port_info.get('port')
                            if port and port not in quick_ports_found:
                                quick_ports_found.append(port)
        except Exception as e:
            logging.warning(f"[{job_id}] Failed to parse quick scan results: {e}")

        result["phases"]["phase1"] = {
            "status": "completed",
            "ports_found": sorted(quick_ports_found),
            "output_file": quick_path
        }
        result["ports_discovered"]["quick"] = sorted(quick_ports_found)

        logging.info(f"[{job_id}] Phase 1 complete. Ports found: {quick_ports_found}")

        # ========================================
        # PHASE 2: Parallel - Nmap + Full Masscan
        # ========================================
        update_job_status(job_id, "running", "phase2_parallel", "Phase 2: Parallel nmap + full port scan")
        logging.info(f"[{job_id}] Phase 2: Starting parallel operations")

        import concurrent.futures

        phase2_nmap_results = []
        phase2_masscan_path = None
        full_ports_found = []

        def run_nmap_on_ports():
            """Run nmap service detection on quick-discovered ports"""
            if not quick_ports_found:
                return []

            results = []
            for target in targets:
                try:
                    validated_target = validate_scan_target(target, allow_private=True)
                    safe_target = _safe_name(validated_target)

                    for batch_idx, batch_start in enumerate(range(0, len(quick_ports_found), 50)):
                        batch_ports = quick_ports_found[batch_start:batch_start + 50]
                        xml_path = run_nmap_batch(validated_target, batch_ports, batch_idx)
                        results.append({
                            "target": validated_target,
                            "ports": batch_ports,
                            "xml_path": xml_path
                        })
                except Exception as e:
                    logging.error(f"[{job_id}] Nmap batch failed for {target}: {e}")
                    results.append({"target": target, "error": str(e)})
            return results

        def run_full_masscan():
            """Run masscan on remaining ports (1001-65535)"""
            nonlocal full_ports_found
            try:
                path = _run_masscan(targets, full_ports, rate, interface)

                # Parse results
                try:
                    with open(path, 'r') as f:
                        masscan_data = json.load(f)
                        for entry in masscan_data:
                            if isinstance(entry, dict) and 'ports' in entry:
                                for port_info in entry['ports']:
                                    port = port_info.get('port')
                                    if port and port not in full_ports_found:
                                        full_ports_found.append(port)
                except Exception as e:
                    logging.warning(f"[{job_id}] Failed to parse full scan results: {e}")

                return path
            except Exception as e:
                logging.error(f"[{job_id}] Full masscan failed: {e}")
                return None

        # Run nmap service detection; only run full masscan if full_ports is specified
        if full_ports.strip():
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                nmap_future = executor.submit(run_nmap_on_ports)
                masscan_future = executor.submit(run_full_masscan)

                phase2_nmap_results = nmap_future.result()
                phase2_masscan_path = masscan_future.result()
        else:
            phase2_nmap_results = run_nmap_on_ports()
            logging.info(f"[{job_id}] Phase 2: Skipping full masscan (full_ports is empty)")

        result["phases"]["phase2"] = {
            "status": "completed",
            "nmap_results": phase2_nmap_results,
            "full_ports_found": sorted(full_ports_found),
            "masscan_output": phase2_masscan_path
        }
        result["ports_discovered"]["full"] = sorted(full_ports_found)

        logging.info(f"[{job_id}] Phase 2 complete. Additional ports found: {full_ports_found}")

        # ========================================
        # PHASE 3: Nmap on newly discovered ports
        # ========================================
        if full_ports_found:
            update_job_status(job_id, "running", "phase3_service_detection", f"Phase 3: Service detection on {len(full_ports_found)} new ports")
            logging.info(f"[{job_id}] Phase 3: Nmap on {len(full_ports_found)} newly discovered ports")

            phase3_results = []
            for target in targets:
                try:
                    validated_target = validate_scan_target(target, allow_private=True)

                    for batch_idx, batch_start in enumerate(range(0, len(full_ports_found), 50)):
                        batch_ports = full_ports_found[batch_start:batch_start + 50]
                        xml_path = run_nmap_batch(validated_target, batch_ports, batch_idx + 100)  # Offset batch index
                        phase3_results.append({
                            "target": validated_target,
                            "ports": batch_ports,
                            "xml_path": xml_path
                        })
                except Exception as e:
                    logging.error(f"[{job_id}] Phase 3 nmap failed for {target}: {e}")
                    phase3_results.append({"target": target, "error": str(e)})

            result["phases"]["phase3"] = {
                "status": "completed",
                "nmap_results": phase3_results
            }
        else:
            result["phases"]["phase3"] = {"status": "skipped", "reason": "No additional ports found"}

        # Combine all discovered ports
        all_ports = sorted(set(quick_ports_found + full_ports_found))
        result["all_open_ports"] = all_ports

        # ========================================
        # PHASE 4: SMB Vulnerability Scan
        # ========================================
        smb_ports = [139, 445]
        has_smb = any(p in all_ports for p in smb_ports)

        if run_smb_vuln_scan and has_smb:
            update_job_status(job_id, "running", "phase4_smb_vuln", "Phase 4: SMB vulnerability scan")
            logging.info(f"[{job_id}] Phase 4: Running SMB vulnerability scan")

            smb_results = []
            for target in targets:
                try:
                    validated_target = validate_scan_target(target, allow_private=True)
                    smb_result = _run_smb_vuln_scan(validated_target, job_id)
                    smb_results.append(smb_result)
                except Exception as e:
                    logging.error(f"[{job_id}] SMB scan failed for {target}: {e}")
                    smb_results.append({"target": target, "error": str(e)})

            result["smb_scan"] = smb_results
            result["phases"]["phase4_smb"] = {"status": "completed", "results": smb_results}
        else:
            result["phases"]["phase4_smb"] = {
                "status": "skipped",
                "reason": "SMB scan disabled" if not run_smb_vuln_scan else "No SMB ports found"
            }

        # ========================================
        # Ingest all results to RAG API
        # ========================================
        update_job_status(job_id, "running", "ingesting", "Ingesting scan results to database")

        # Ingest masscan results (port discovery)
        for masscan_path in [quick_path, phase2_masscan_path]:
            if masscan_path and os.path.exists(masscan_path):
                try:
                    with open(masscan_path, "rb") as fh:
                        resp = requests.post(
                            f"{API_BASE}/ingest/masscan",
                            headers={"x-api-key": API_KEY},
                            files={"file": ("masscan.json", fh, "application/json")},
                            timeout=INGEST_TIMEOUT_SHORT,
                            verify=False,
                        )
                    if resp.status_code >= 300:
                        logging.warning(f"[{job_id}] Failed to ingest {masscan_path}: {resp.text}")
                except Exception as e:
                    logging.error(f"[{job_id}] Failed to ingest {masscan_path}: {e}")

        # Ingest nmap XML results (service detection, vulns, banners)
        all_nmap_results = phase2_nmap_results + (result["phases"].get("phase3", {}).get("nmap_results", []))
        for nmap_result in all_nmap_results:
            xml_path = nmap_result.get("xml_path")
            target = nmap_result.get("target", "unknown")
            if xml_path and os.path.exists(xml_path):
                try:
                    with open(xml_path, "rb") as fh:
                        resp = requests.post(
                            f"{API_BASE}/ingest/nmap",
                            headers={"x-api-key": API_KEY},
                            files={"file": (os.path.basename(xml_path), fh, "application/xml")},
                            params={"job_id": job_id, "target": target},
                            timeout=INGEST_TIMEOUT_SHORT,
                            verify=False,
                        )
                    if resp.status_code < 300:
                        logging.info(f"[{job_id}] Ingested nmap results from {xml_path}")
                    else:
                        logging.warning(f"[{job_id}] Failed to ingest {xml_path}: {resp.text}")
                except Exception as e:
                    logging.error(f"[{job_id}] Failed to ingest {xml_path}: {e}")

        # Ingest SMB vuln scan results if available
        smb_results = result.get("smb_scan") or []
        for smb_entry in smb_results:
            if not isinstance(smb_entry, dict):
                continue
            smb_xml = smb_entry.get("xml_path")
            smb_target = smb_entry.get("target", targets[0] if targets else "unknown")
            if smb_xml and os.path.exists(smb_xml):
                try:
                    with open(smb_xml, "rb") as fh:
                        resp = requests.post(
                            f"{API_BASE}/ingest/nmap",
                            headers={"x-api-key": API_KEY},
                            files={"file": (os.path.basename(smb_xml), fh, "application/xml")},
                            params={"job_id": job_id, "target": smb_target},
                            timeout=INGEST_TIMEOUT_SHORT,
                            verify=False,
                        )
                    if resp.status_code < 300:
                        logging.info(f"[{job_id}] Ingested SMB vuln scan results from {smb_xml}")
                except Exception as e:
                    logging.error(f"[{job_id}] Failed to ingest SMB results: {e}")

        # Success!
        final_result = {
            "ok": True,
            "job_id": job_id,
            "targets": targets,
            "total_ports_discovered": len(all_ports),
            "ports": all_ports,
            "phases": result["phases"],
            "smb_vulns": result.get("smb_scan"),
        }

        update_job_status(job_id, "completed", "done", f"Full scan complete. {len(all_ports)} ports discovered.", result=final_result)

        # Save session results with parsed findings
        session_files = []
        nmap_parsed = []
        if quick_path:
            session_files.append(quick_path)
        if phase2_masscan_path:
            session_files.append(phase2_masscan_path)
        for nr in phase2_nmap_results:
            if nr.get("xml_path") and os.path.exists(nr["xml_path"]):
                session_files.append(nr["xml_path"])
                summary = _parse_nmap_xml_summary(nr["xml_path"])
                if summary:
                    nmap_parsed.extend(summary["hosts"])
        for nr in result["phases"].get("phase3", {}).get("nmap_results", []):
            if nr.get("xml_path") and os.path.exists(nr["xml_path"]):
                session_files.append(nr["xml_path"])
                summary = _parse_nmap_xml_summary(nr["xml_path"])
                if summary:
                    nmap_parsed.extend(summary["hosts"])
        for sr in smb_results:
            if isinstance(sr, dict) and sr.get("xml_path") and os.path.exists(sr["xml_path"]):
                session_files.append(sr["xml_path"])
                summary = _parse_nmap_xml_summary(sr["xml_path"])
                if summary:
                    nmap_parsed.extend(summary["hosts"])
        results_file = pathlib.Path(OUTDIR) / f"full_scan_results_{job_id[:8]}.json"
        results_file.write_text(json.dumps({
            "job_id": job_id, "targets": targets[:10],
            "ports_discovered": all_ports,
            "nmap_results": nmap_parsed,
            "phases": {k: str(v)[:500] for k, v in result.get("phases", {}).items()},
        }, indent=2))
        session_files.append(str(results_file))
        _save_session_results(job_id, "full-scan", "nmap_scanner", session_files,
                              metadata={"targets": targets[:10], "total_ports": len(all_ports)})

        # Emit webhook for scan completion
        emit_webhook_event("scan_completed", "full-scan", {
            "job_id": job_id,
            "targets_count": len(targets),
            "total_ports": len(all_ports),
            "high_value_ports": [p for p in all_ports if p in [1099, 1524, 3306, 3632, 5432, 5900, 6667, 8180]],
            "has_smb": has_smb,
        })

        # Trigger scan recommender for all discovered services
        try:
            _trigger_scan_recommender(nmap_parsed, job_id)
        except Exception:
            logging.warning(f"[{job_id}] Scan recommender trigger failed (non-fatal)")

        # Auto-trigger subfinder for domain targets
        try:
            _trigger_subfinder_for_domains(targets, job_id)
        except Exception:
            logging.debug(f"[{job_id}] Subfinder auto-trigger failed (non-fatal)")

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[{job_id}] Full scan error: {tb}")
        update_job_status(job_id, "failed", "error", error=f"{type(e).__name__}: {e}\n{tb}")

        emit_webhook_event("scan_failed", "full-scan", {
            "job_id": job_id,
            "error": str(e)
        })


@app.post("/jobs/full-scan")
def full_scan(body: FullScanRequest, background_tasks: BackgroundTasks):
    """
    Start a comprehensive full port scan with parallel phases.

    This runs a phased scanning approach for maximum coverage:
    - Phase 1: Quick masscan (ports 1-1000)
    - Phase 2: PARALLEL - Nmap on Phase 1 ports + Masscan (ports 1001-65535)
    - Phase 3: Nmap service detection on Phase 2 ports
    - Phase 4: SMB vulnerability scan (if 139/445 found)

    This approach discovers high-value ports like:
    - 1099 (Java RMI)
    - 1524 (Bindshell)
    - 3306 (MySQL)
    - 3632 (DISTCC)
    - 5432 (PostgreSQL)
    - 5900 (VNC)
    - 6667 (IRC)
    - 8180 (Tomcat)

    Returns immediately with a job_id to track progress.
    Use GET /jobs/{job_id} to check status.
    """
    # Validate inputs
    body.validate_inputs()

    # Per-job timeout override (read in run_nmap_batch / proxied via _nmap_scan_opts)
    global _nmap_scan_opts
    _nmap_scan_opts = {"timeout_seconds": body.timeout_seconds} if body.timeout_seconds else {}

    # When proxy is set, redirect to proxied nmap (skip masscan)
    if body.proxy:
        all_ports = body.quick_ports
        if body.full_ports:
            all_ports = f"{body.quick_ports},{body.full_ports}" if body.quick_ports else body.full_ports
        job_id = create_job("nmap-proxied", {
            "targets": body.targets,
            "ports": all_ports,
            "proxy": body.proxy,
        })
        background_tasks.add_task(
            _run_nmap_proxied_async,
            job_id, body.targets, all_ports, body.proxy
        )
        return {
            "ok": True,
            "job_id": job_id,
            "message": "Proxied full scan started (masscan skipped). Use GET /jobs/{job_id} to check status.",
            "status_url": f"/jobs/{job_id}",
            "proxied": True,
        }

    # Create job
    job_id = create_job("full-scan", {
        "targets": body.targets,
        "quick_ports": body.quick_ports,
        "full_ports": body.full_ports,
        "rate": body.rate,
        "interface": body.interface,
        "run_smb_vuln_scan": body.run_smb_vuln_scan,
        "run_credential_check": body.run_credential_check
    })

    # Start background task
    background_tasks.add_task(
        _run_full_scan_async,
        job_id,
        body.targets,
        body.quick_ports,
        body.full_ports,
        body.rate,
        body.interface,
        body.run_smb_vuln_scan,
        body.run_credential_check
    )

    return {
        "ok": True,
        "job_id": job_id,
        "message": "Full scan job started. Use GET /jobs/{job_id} to check status.",
        "status_url": f"/jobs/{job_id}",
        "phases": ["phase1_quick_scan", "phase2_parallel", "phase3_service_detection", "phase4_smb_vuln"]
    }


@app.post("/jobs/smb-vuln-scan")
def smb_vuln_scan(body: MasscanBody, background_tasks: BackgroundTasks):
    """
    Start an SMB-specific vulnerability scan.

    Runs nmap with SMB vulnerability scripts to detect:
    - CVE-2007-2447 (Samba usermap_script)
    - CVE-2017-7494 (SambaCry)
    - MS17-010 (EternalBlue)
    - MS08-067 (NetAPI)

    Returns immediately with a job_id to track progress.
    """
    body.validate_inputs()

    job_id = create_job("smb-vuln-scan", {"targets": body.targets})

    def run_smb_scans(job_id: str, targets: List[str]):
        try:
            emit_webhook_event("scan_started", "smb-vuln", {
                "job_id": job_id,
                "targets": targets[:10]
            })

            update_job_status(job_id, "running", "smb_scanning", f"Scanning {len(targets)} targets for SMB vulnerabilities")

            results = []
            for target in targets:
                try:
                    validated_target = validate_scan_target(target, allow_private=True)
                    result = _run_smb_vuln_scan(validated_target, job_id)
                    results.append(result)
                except Exception as e:
                    results.append({"target": target, "error": str(e)})

            final_result = {
                "ok": True,
                "targets_scanned": len(targets),
                "results": results,
                "vulnerabilities_found": any(r.get("vulnerabilities_found") for r in results),
                "cves_detected": list(set(
                    cve for r in results
                    for cve in r.get("cves_detected", [])
                ))
            }

            update_job_status(job_id, "completed", "done", "SMB vulnerability scan complete", result=final_result)

            emit_webhook_event("scan_completed", "smb-vuln", {
                "job_id": job_id,
                "vulnerabilities_found": final_result["vulnerabilities_found"],
                "cves": final_result["cves_detected"]
            })

        except Exception as e:
            tb = traceback.format_exc()
            logging.error(f"[{job_id}] SMB scan error: {tb}")
            update_job_status(job_id, "failed", "error", error=str(e))

    background_tasks.add_task(run_smb_scans, job_id, body.targets)

    return {
        "ok": True,
        "job_id": job_id,
        "message": "SMB vulnerability scan started. Use GET /jobs/{job_id} to check status.",
        "status_url": f"/jobs/{job_id}"
    }


# ===============================
# Credential Testing Endpoints
# ===============================

class CredentialCheckRequest(BaseModel):
    targets: List[str] = Field(..., description="List of IPs to check")
    ports: Optional[List[int]] = Field(None, description="Specific ports to check (auto-detects service)")
    services: Optional[List[str]] = Field(None, description="Specific services to check (ssh, ftp, mysql, etc.)")
    method: str = Field("hydra", description="Testing method: 'hydra' or 'nmap'")

    def validate_inputs(self):
        """Validate all inputs for security"""
        validated_targets = []
        for target in self.targets:
            try:
                validated = validate_scan_target(target, allow_private=True)
                validated_targets.append(validated)
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid target '{target}': {e}")
        self.targets = validated_targets

        # Validate services if provided
        valid_services = ["ssh", "ftp", "telnet", "mysql", "postgres", "vnc", "tomcat", "smb", "redis", "mongodb", "mssql"]
        if self.services:
            for svc in self.services:
                if svc.lower() not in valid_services:
                    raise HTTPException(status_code=400, detail=f"Unknown service: {svc}. Valid: {valid_services}")


def _run_credential_check_async(
    job_id: str,
    targets: List[str],
    ports: Optional[List[int]],
    services: Optional[List[str]],
    method: str
):
    """Background task to run credential checking"""
    if not CRED_CHECKER_AVAILABLE:
        update_job_status(job_id, "failed", "error", error="Credential checker module not available")
        return

    try:
        emit_webhook_event("scan_started", "credential-check", {
            "job_id": job_id,
            "targets": targets[:10],
            "services": services,
            "ports": ports
        })

        update_job_status(job_id, "running", "checking_credentials", f"Checking credentials on {len(targets)} targets")

        all_results = []
        total_valid = 0

        for target in targets:
            try:
                validated_target = validate_scan_target(target, allow_private=True)

                update_job_status(job_id, "running", "checking_credentials", f"Checking credentials on {validated_target}")

                result = check_all_default_credentials(
                    validated_target,
                    ports=ports,
                    services=services
                )

                all_results.append(result)
                total_valid += result.get("total_valid", 0)

            except Exception as e:
                logging.error(f"[{job_id}] Credential check failed for {target}: {e}")
                all_results.append({
                    "target": target,
                    "error": str(e),
                    "checks": [],
                    "total_valid": 0
                })

        # Compile final results
        final_result = {
            "ok": True,
            "targets_checked": len(targets),
            "total_valid_credentials": total_valid,
            "results": all_results,
            "valid_credentials": [
                {
                    "target": r["target"],
                    "service": c["service"],
                    "port": c["port"],
                    "credentials": c["valid_credentials"]
                }
                for r in all_results
                for c in r.get("checks", [])
                if c.get("success")
            ]
        }

        # Persist valid credentials into the credential_findings table so
        # they show up in AssetBrowser → Credentials.  Previously this
        # handler only stored results in the in-memory job tracker and on
        # disk (/scan_results/.jobs/<job_id>.json) -- they were findable
        # via the /jobs/{id} API but invisible to the credentials UI.
        #
        # Mirror the brutus runner's pattern: write a JSONL file in the
        # shape parse_brutus.py reads (host/port/protocol/username/success)
        # and POST it to the rag-api /ingest/brutus endpoint.  Best-effort
        # -- a failure here must NOT roll back the job's success status;
        # the credentials are still on disk and retrievable manually.
        ingest_summary = None
        if total_valid > 0:
            try:
                lines = []
                for r in all_results:
                    target_ip = r.get("target")
                    for chk in r.get("checks", []):
                        if not chk.get("success"):
                            continue
                        port_n = chk.get("port")
                        service = chk.get("service") or "unknown"
                        for cred in chk.get("valid_credentials", []) or []:
                            lines.append(json.dumps({
                                "host":     target_ip,
                                "port":     int(port_n) if port_n is not None else 0,
                                "protocol": service,
                                "username": cred.get("username", ""),
                                "success":  True,
                            }))
                if lines:
                    # Write to /scan_results so the path is consistent with
                    # how other /ingest/* calls in this module work.
                    ingest_path = f"/scan_results/.jobs/credcheck_{job_id}.jsonl"
                    with open(ingest_path, "w") as fh:
                        fh.write("\n".join(lines) + "\n")
                    with open(ingest_path, "rb") as fh:
                        resp = requests.post(
                            f"{API_BASE}/ingest/brutus",
                            headers={"x-api-key": API_KEY},
                            files={"file": ("credcheck.jsonl", fh, "application/x-ndjson")},
                            params={"job_id": job_id, "secret_type": "password"},
                            timeout=INGEST_TIMEOUT,
                            verify=False,
                        )
                    try:
                        ingest_summary = resp.json()
                    except Exception:
                        ingest_summary = {"status_code": resp.status_code,
                                          "body": resp.text[:200]}
                    logging.info(
                        f"[{job_id}] credential-check ingested {len(lines)} "
                        f"credentials → credential_findings: {ingest_summary}"
                    )
            except Exception as ingest_err:
                logging.warning(
                    f"[{job_id}] credential-check ingest failed (job result still "
                    f"on disk): {type(ingest_err).__name__}: {ingest_err}"
                )
                ingest_summary = {"error": f"{type(ingest_err).__name__}: {ingest_err}"}

        # Attach the ingest outcome to final_result so the UI / API can
        # surface "credentials persisted" alongside the in-memory list.
        if ingest_summary is not None:
            final_result["ingest"] = ingest_summary

        update_job_status(job_id, "completed", "done",
                         f"Credential check complete. Found {total_valid} valid credentials.",
                         result=final_result)

        emit_webhook_event("scan_completed", "credential-check", {
            "job_id": job_id,
            "targets_checked": len(targets),
            "valid_credentials_found": total_valid
        }, severity="high" if total_valid > 0 else None)

    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"[{job_id}] Credential check error: {tb}")
        update_job_status(job_id, "failed", "error", error=f"{type(e).__name__}: {e}")

        emit_webhook_event("scan_failed", "credential-check", {
            "job_id": job_id,
            "error": str(e)
        })


@app.post("/jobs/credential-check")
def credential_check(body: CredentialCheckRequest, background_tasks: BackgroundTasks):
    """
    Start a credential testing job to check for default/weak passwords.

    Tests common default credentials for services like:
    - SSH: msfadmin:msfadmin, root:root, admin:admin
    - FTP: anonymous, ftp:ftp
    - MySQL: root with empty password
    - PostgreSQL: postgres:postgres
    - VNC: common passwords (password, 1234, etc.)
    - Telnet: default credentials
    - Tomcat: tomcat:tomcat, admin:admin

    Also checks for bindshell on port 1524 (instant root access).

    Args:
        targets: List of IP addresses to check
        ports: Specific ports to check (auto-detects service from port)
        services: Specific services to check (ssh, ftp, mysql, etc.)
        method: Testing method ('hydra' or 'nmap')

    Returns:
        Job information with status URL
    """
    if not CRED_CHECKER_AVAILABLE:
        raise HTTPException(status_code=501, detail="Credential checker module not available")

    body.validate_inputs()

    job_id = create_job("credential-check", {
        "targets": body.targets,
        "ports": body.ports,
        "services": body.services,
        "method": body.method
    })

    background_tasks.add_task(
        _run_credential_check_async,
        job_id,
        body.targets,
        body.ports,
        body.services,
        body.method
    )

    return {
        "ok": True,
        "job_id": job_id,
        "message": "Credential check started. Use GET /jobs/{job_id} to check status.",
        "status_url": f"/jobs/{job_id}",
        "services_available": list(DEFAULT_CREDENTIALS.keys()) if CRED_CHECKER_AVAILABLE else []
    }


@app.get("/credential-check/services")
def list_credential_services():
    """
    List available services for credential checking and their default ports.
    """
    if not CRED_CHECKER_AVAILABLE:
        raise HTTPException(status_code=501, detail="Credential checker module not available")

    return {
        "services": list(DEFAULT_CREDENTIALS.keys()),
        "service_ports": SERVICE_PORTS,
        "credentials_count": {
            service: len(creds)
            for service, creds in DEFAULT_CREDENTIALS.items()
        }
    }
