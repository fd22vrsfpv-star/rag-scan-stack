"""
Brutus Runner - Credential Testing FastAPI Service
Provides a single endpoint for multi-protocol credential testing with Brutus.
Isolated from other scanning tools due to its sensitive security profile.
"""

import os, uuid, pathlib, subprocess, threading, logging, json, tempfile, shutil
from typing import List, Optional, Dict, Any
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
import uvicorn, requests

logging.basicConfig(level=logging.INFO)

from log_manager import get_log_handler, setup_log_capture, LOGS_UI_HTML

try:
    from audit_writer import write_audit
except ImportError:
    def write_audit(*a, **kw): pass

from validation import (
    validate_scan_target,
    sanitize_port,
    validate_output_path,
    sanitize_command_arg,
    validate_cidr,
    ValidationError,
)

DB_DSN      = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
API_BASE    = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY     = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"
REPORT_DIR  = pathlib.Path(os.environ.get("REPORT_DIR", "/reports")); REPORT_DIR.mkdir(parents=True, exist_ok=True)

SESSION_DIR = pathlib.Path(os.environ.get("SESSION_RESULTS_DIR", "/scan_results"))


def _save_session_results(job_id, job_type, scanner, files, metadata=None):
    """Copy raw scan output files to a session-based directory."""
    try:
        ts = datetime.now().strftime("%Y-%m-%d_%H%M")
        session_path = SESSION_DIR / f"{job_type}_{ts}_{job_id[:8]}"
        session_path.mkdir(parents=True, exist_ok=True)
        copied = []
        for fp in files:
            fp = pathlib.Path(fp)
            if fp.exists() and fp.is_file():
                shutil.copy2(str(fp), str(session_path / fp.name))
                copied.append(fp.name)
        manifest = {
            "job_id": job_id, "job_type": job_type, "scanner": scanner,
            "created_at": datetime.now().isoformat(), "files": copied,
        }
        if metadata:
            manifest["metadata"] = metadata
        (session_path / "manifest.json").write_text(json.dumps(manifest, indent=2))
        logging.info(f"[session] Saved {len(copied)} files to {session_path}")
    except Exception as e:
        logging.warning(f"[session] Failed to save session results: {e}")


def emit_webhook_event(event_type: str, source: str, data: dict, severity: str = None):
    """Emit a webhook event via the RAG API."""
    if not WEBHOOK_ENABLED:
        return
    try:
        payload = {"event_type": event_type, "source": source, "data": data}
        if severity:
            payload["severity"] = severity
        requests.post(
            f"{API_BASE}/webhooks/emit",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json=payload, timeout=5
        )
    except Exception as e:
        logging.warning(f"Failed to emit webhook: {e}")


# ===============================
# Job Tracking System
# ===============================

class JobTracker:
    """Thread-safe job tracking for async status queries"""

    def __init__(self, max_jobs: int = 100):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.max_jobs = max_jobs

    def create_job(self, job_type: str = "brutus") -> str:
        job_id = str(uuid.uuid4())
        with self._lock:
            if len(self.jobs) >= self.max_jobs:
                self._cleanup_old_jobs()
            self.jobs[job_id] = {
                "job_id": job_id, "type": job_type, "status": "queued",
                "progress": {"stage": "initializing", "targets_count": 0, "findings_count": 0},
                "result": None, "created_at": datetime.now().isoformat(),
                "started_at": None, "completed_at": None, "error": None,
            }
        return job_id

    def update_job(self, job_id: str, **kwargs):
        with self._lock:
            if job_id in self.jobs:
                self.jobs[job_id].update(kwargs)

    def update_progress(self, job_id: str, **kwargs):
        with self._lock:
            if job_id in self.jobs:
                self.jobs[job_id]["progress"].update(kwargs)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.jobs.get(job_id, None)

    def list_jobs(self, status: Optional[str] = None, limit: int = 50) -> list:
        with self._lock:
            jobs = list(self.jobs.values())
            if status:
                jobs = [j for j in jobs if j["status"] == status]
            jobs.sort(key=lambda x: x["created_at"], reverse=True)
            return jobs[:limit]

    def _cleanup_old_jobs(self):
        completed = [(k, v) for k, v in self.jobs.items() if v["status"] in ("completed", "failed")]
        completed.sort(key=lambda x: x[1].get("completed_at", ""))
        for job_id, _ in completed[:len(completed)//2]:
            del self.jobs[job_id]


_job_tracker = JobTracker(max_jobs=100)


def conn():
    return psycopg2.connect(DB_DSN)


DEFAULT_PORTS = {
    "ssh": 22, "ftp": 21, "telnet": 23, "vnc": 5900,
    "smb": 445, "ldap": 389, "winrm": 5985,
    "mysql": 3306, "postgresql": 5432, "mssql": 1433,
    "mongodb": 27017, "redis": 6379, "neo4j": 7687,
    "cassandra": 9042, "couchdb": 5984, "elasticsearch": 9200,
    "influxdb": 8086,
    "smtp": 25, "imap": 143, "pop3": 110,
    "http": 80, "https": 443, "snmp": 161,
}


def _write_file(items: list) -> str:
    """Write items to a temp file, return path."""
    fd, path = tempfile.mkstemp(suffix=".txt", dir=str(REPORT_DIR))
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(items))
    return path


def _build_fingerprintx_input(targets: list, protocols: list) -> str:
    """Build fingerprintx-style JSON lines for brutus stdin pipeline mode.

    Targets can be 'host' or 'host:port'. When port is omitted, the default
    port for each requested protocol is used.
    """
    lines = []
    for target in targets:
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                host, port = target, None
        else:
            host, port = target, None

        for proto in protocols:
            p = port if port else DEFAULT_PORTS.get(proto)
            if not p:
                continue
            tls = proto in ("https",)
            lines.append(json.dumps({
                "host": host, "ip": host, "port": p,
                "protocol": proto, "tls": tls,
            }))
    return "\n".join(lines)


def _ingest_results(tool: str, output_path: str, job_id: str = None, secret_type: str = "password") -> dict:
    """POST results file to rag-api ingest endpoint."""
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        return {"ok": True, "skipped": "no output"}
    try:
        files = {"file": (f"{tool}.json", open(output_path, "rb"), "application/json")}
        headers = {"x-api-key": API_KEY}
        params = {}
        if job_id:
            params["job_id"] = job_id
        if secret_type and secret_type != "password":
            params["secret_type"] = secret_type
        r = requests.post(f"{API_BASE}/ingest/{tool}", files=files, headers=headers, params=params, timeout=300, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.warning(f"Ingest to /ingest/{tool} failed: {e}")
        return {"ok": False, "error": str(e)}


# ===============================
# FastAPI App
# ===============================

app = FastAPI(title="Brutus Runner")

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


@app.on_event("startup")
async def startup_event():
    setup_log_capture()
    logging.info("[brutus-runner] Service started, log capture initialized")


# --- Request Model ---

class BrutusReq(BaseModel):
    targets: List[str]
    protocols: List[str]
    usernames: Optional[List[str]] = None
    passwords: Optional[List[str]] = None
    wordlist_path: Optional[str] = None
    username_wordlist_path: Optional[str] = None
    secret_type: Optional[str] = "password"


# --- Health ---

@app.get("/health")
def health():
    try:
        with conn() as c, c.cursor() as cur:
            cur.execute("SELECT 1")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --- Job Status ---

@app.get("/jobs/{job_id}")
def get_job_status(job_id: str):
    job = _job_tracker.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/jobs")
def list_jobs(status: Optional[str] = None, limit: int = 50):
    return {"jobs": _job_tracker.list_jobs(status=status, limit=limit)}


@app.post("/jobs/{job_id}/stop")
def stop_job(job_id: str):
    job = _job_tracker.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] not in ["queued", "running"]:
        raise HTTPException(status_code=400, detail=f"Job is already {job['status']}")
    _job_tracker.update_job(job_id, status="stopped", completed_at=datetime.now().isoformat())
    _job_tracker.update_progress(job_id, stage="user_stopped")
    emit_webhook_event("scan_stopped", "brutus-runner", {"job_id": job_id})
    return {"ok": True, "job_id": job_id, "status": "stopped"}


# ===============================
# Brutus Endpoint
# ===============================

@app.post("/jobs/brutus")
def run_brutus(req: BrutusReq, background_tasks: BackgroundTasks):
    """Multi-protocol credential testing via brutus pipeline mode."""
    job_id = _job_tracker.create_job(job_type="brutus")

    output_file = str(REPORT_DIR / f"brutus_{job_id[:8]}.jsonl")
    stdin_data = _build_fingerprintx_input(req.targets, req.protocols)

    cmd = ["brutus", "--nerva", "-o", output_file, "-q"]

    # Usernames — inline list or wordlist file
    if req.username_wordlist_path:
        wl = req.username_wordlist_path
        if not wl.startswith("/wordlists/") or ".." in wl:
            raise HTTPException(status_code=400, detail="username_wordlist_path must be under /wordlists/")
        if not os.path.isfile(wl):
            raise HTTPException(status_code=400, detail=f"Username wordlist not found: {wl}")
        cmd.extend(["-U", wl])
    elif req.usernames:
        cmd.extend(["-u", ",".join(req.usernames)])

    # Passwords — wordlist file, inline list (small), or temp file (large)
    pass_file = None
    if req.wordlist_path:
        wl = req.wordlist_path
        if not wl.startswith("/wordlists/") or ".." in wl:
            raise HTTPException(status_code=400, detail="wordlist_path must be under /wordlists/")
        if not os.path.isfile(wl):
            raise HTTPException(status_code=400, detail=f"Password wordlist not found: {wl}")
        cmd.extend(["-P", wl])
    elif req.passwords:
        if len(req.passwords) <= 20:
            cmd.extend(["-p", ",".join(req.passwords)])
        else:
            pass_file = _write_file(req.passwords)
            cmd.extend(["-P", pass_file])

    _job_tracker.update_progress(job_id, targets_count=len(req.targets))

    def _run_brutus_job():
        try:
            import time as _time
            _t0 = _time.time()
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")
            emit_webhook_event("scan_started", "brutus", {"job_id": job_id})
            write_audit("scan_started", "brutus", "brutus_runner", {
                "job_id": job_id, "targets_count": len(req.targets),
                "execution_mode": "local",
            })

            logging.info(f"[{job_id}] Running brutus on {len(req.targets)} targets, "
                         f"{len(req.protocols)} protocols, cmd: {' '.join(cmd)}")
            logging.info(f"[{job_id}] stdin ({stdin_data.count(chr(10))+1} lines): {stdin_data[:200]}")

            cp = subprocess.run(
                cmd, input=stdin_data, capture_output=True, text=True, timeout=3600,
            )
            if cp.stderr:
                logging.info(f"[{job_id}] brutus stderr: {cp.stderr[:500]}")

            findings_count = 0
            if os.path.exists(output_file):
                with open(output_file) as f:
                    findings_count = sum(1 for line in f if line.strip())
            _job_tracker.update_progress(job_id, findings_count=findings_count)

            # Ingest
            _job_tracker.update_progress(job_id, stage="ingesting")
            ing = _ingest_results("brutus", output_file, job_id=job_id, secret_type=req.secret_type or "password")

            # Emit critical webhooks for valid credentials
            if findings_count > 0:
                emit_webhook_event("finding_critical", "brutus", {
                    "job_id": job_id, "valid_credentials_found": findings_count,
                }, severity="critical")

            _job_tracker.update_progress(job_id, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "findings_count": findings_count, "ingest": ing,
                        "stdout": cp.stdout[-500:] if cp.stdout else "",
                        "stderr": cp.stderr[-500:] if cp.stderr else ""},
                completed_at=datetime.now().isoformat(),
            )
            emit_webhook_event("scan_completed", "brutus", {"job_id": job_id, "findings_count": findings_count})
            write_audit("scan_completed", "brutus", "brutus_runner", {
                "job_id": job_id, "findings_count": findings_count,
                "duration_s": round(_time.time() - _t0, 2),
            })

            # Save session results
            _save_session_results(job_id, "brutus", "brutus-runner", [output_file],
                                  metadata={"findings_count": findings_count})

        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            emit_webhook_event("scan_failed", "brutus", {"job_id": job_id, "error": str(e)})
            write_audit("scan_failed", "brutus", "brutus_runner", {
                "job_id": job_id, "error": str(e),
            })
            logging.error(f"[{job_id}] brutus failed: {e}")
        finally:
            for fp in [pass_file]:
                if fp and os.path.exists(fp):
                    try:
                        os.remove(fp)
                    except OSError:
                        pass

    background_tasks.add_task(_run_brutus_job)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


# ===============================
# Logs UI Endpoints
# ===============================

@app.get("/logs/ui", response_class=HTMLResponse)
async def logs_ui():
    return HTMLResponse(content=LOGS_UI_HTML)


@app.get("/logs")
async def get_logs(
    level: Optional[str] = Query(None),
    limit: int = Query(100),
    search: Optional[str] = Query(None),
    job_id: Optional[str] = Query(None),
):
    handler = get_log_handler()
    logs = await handler.async_get_logs(level=level, limit=limit, search=search, job_id=job_id)
    return {"logs": logs}


@app.get("/logs/stats")
async def get_log_stats():
    handler = get_log_handler()
    stats = await handler.async_get_stats()
    return {"ok": True, "stats": stats}


@app.get("/logs/export")
async def export_logs():
    handler = get_log_handler()
    json_data = await handler.async_export_json()
    return Response(
        content=json_data, media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=brutus_runner_logs.json"},
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8025, log_level="info", ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE"))
