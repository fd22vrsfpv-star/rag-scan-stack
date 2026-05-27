"""
PD Runner - Active Scanning FastAPI Service
Provides endpoints for active scanning tools: httpx, naabu, katana, and tlsx.
Passive OSINT tools are in osint-runner. Credential testing is in brutus-runner.
"""

import os, uuid, pathlib, subprocess, threading, logging, json, tempfile, shutil
from typing import List, Optional, Dict, Any
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, Response, FileResponse
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
WEB_PORTS   = [int(x) for x in os.environ.get("WEB_PORTS", "80,443,8080,8443,8000,8888,3000,5000").split(",") if x]
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

    def __init__(self, max_jobs: int = 200):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.max_jobs = max_jobs

    def create_job(self, job_type: str = "pd-scan") -> str:
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

    def push_command(self, job_id: str, stage: str, command: str):
        """Append a command to progress.commands for live pipeline tracking."""
        with self._lock:
            if job_id in self.jobs:
                prog = self.jobs[job_id]["progress"]
                if "commands" not in prog:
                    prog["commands"] = []
                prog["commands"].append({
                    "stage": stage,
                    "command": command,
                    "ts": datetime.now().isoformat(),
                })
                prog["stage"] = stage
                prog["command"] = command

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


_job_tracker = JobTracker(max_jobs=200)


def conn():
    return psycopg2.connect(DB_DSN)


def get_web_targets():
    """Get open web ports from DB for httpx/katana/tlsx 'from_db' mode."""
    q = """
    SELECT a.id AS asset_id, host(a.ip)::text AS ip, p.port
    FROM ports p
    JOIN assets a ON a.id = p.asset_id
    WHERE p.port = ANY(%s) AND COALESCE(p.is_open, true)
    ORDER BY ip, p.port;
    """
    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(q, (WEB_PORTS,))
        return cur.fetchall()


def get_httpx_tls_targets():
    """Get HTTPS hosts from httpx recon_findings for tlsx auto-feed.

    Priority: httpx HTTPS probes first, then fall back to subfinder/dnsx
    subdomains that have linked assets (i.e., resolved IPs).
    """
    targets = set()
    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        # 1) httpx results with HTTPS URLs
        cur.execute("""
            SELECT DISTINCT (data->>'host') AS host, (data->>'port') AS port
            FROM recon_findings
            WHERE source = 'httpx'
              AND (data->>'url') LIKE 'https://%%'
              AND (data->>'host') IS NOT NULL
        """)
        for r in cur.fetchall():
            h = r["host"]
            p = r["port"] or "443"
            targets.add(f"{h}:{p}")

        # 2) Subfinder/dnsx subdomains that have resolved assets
        cur.execute("""
            SELECT DISTINCT rf.target
            FROM recon_findings rf
            WHERE rf.source IN ('subfinder', 'dnsx')
              AND rf.asset_id IS NOT NULL
            LIMIT 5000
        """)
        for r in cur.fetchall():
            t = r["target"]
            if t and ":" not in t:
                targets.add(f"{t}:443")
            elif t:
                targets.add(t)

    return list(targets)[:5000]


def _write_targets_file(targets: list) -> str:
    """Write targets to a temp file, return path."""
    fd, path = tempfile.mkstemp(suffix=".txt", dir=str(REPORT_DIR))
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(targets))
    return path


def _read_jsonl(path: str) -> list:
    """Read JSONL file, return list of dicts."""
    results = []
    if not os.path.exists(path):
        return results
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results


def _ingest_results(tool: str, output_path: str, job_id: str = None) -> dict:
    """POST results file to rag-api ingest endpoint."""
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        return {"ok": True, "skipped": "no output"}
    try:
        files = {"file": (f"{tool}.json", open(output_path, "rb"), "application/json")}
        headers = {"x-api-key": API_KEY}
        params = {}
        if job_id:
            params["job_id"] = job_id
        r = requests.post(f"{API_BASE}/ingest/{tool}", files=files, headers=headers, params=params, timeout=300, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.warning(f"Ingest to /ingest/{tool} failed: {e}")
        return {"ok": False, "error": str(e)}


# ===============================
# Tool Runner Functions
# ===============================

def _run_tool_job(job_id: str, tool: str, cmd: list, targets_file: str, output_file: str, ingest_as: str = None, env: dict = None, no_ingest: bool = False):
    """Generic background job runner for PD tools."""
    try:
        import time as _time
        _t0 = _time.time()
        cmd_str = " ".join(cmd)
        _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
        _job_tracker.push_command(job_id, tool, cmd_str)
        _job_tracker.update_progress(job_id, stage="running")

        emit_webhook_event("scan_started", tool, {"job_id": job_id, "scan_type": tool})
        write_audit("scan_started", tool, "pd_runner", {
            "job_id": job_id, "execution_mode": "local", "command": cmd_str,
        })

        logging.info(f"[{job_id}] Running {tool}: {cmd_str}")
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=env)

        if cp.returncode not in (0, 1):
            raise RuntimeError(f"{tool} exit {cp.returncode}: {cp.stderr[:500]}")

        # Count results
        findings_count = 0
        raw_output = ""
        if os.path.exists(output_file):
            with open(output_file) as f:
                content = f.read()
                findings_count = sum(1 for line in content.splitlines() if line.strip())
                raw_output = content[:10000]  # cap raw output for test mode
        _job_tracker.update_progress(job_id, findings_count=findings_count)

        # Ingest (skip if no_ingest / test mode)
        ing = None
        if no_ingest:
            logging.info(f"[{job_id}] no_ingest=true, skipping ingestion")
        else:
            _job_tracker.update_progress(job_id, stage="ingesting")
            ingest_tool = ingest_as or tool
            ing = _ingest_results(ingest_tool, output_file, job_id=job_id)

        _job_tracker.update_progress(job_id, stage="done")
        duration_s = round(_time.time() - _t0, 2)
        result_data = {"ok": True, "findings_count": findings_count, "report": output_file, "ingest": ing, "no_ingest": no_ingest, "command": cmd_str, "duration_s": duration_s}
        if no_ingest:
            result_data["raw_output"] = raw_output
            result_data["stdout"] = cp.stdout[-2000:] if cp.stdout else None
            result_data["stderr"] = cp.stderr[-2000:] if cp.stderr else None
        _job_tracker.update_job(
            job_id, status="completed",
            result=result_data,
            completed_at=datetime.now().isoformat(),
        )
        emit_webhook_event("scan_completed", tool, {"job_id": job_id, "findings_count": findings_count})
        write_audit("scan_completed", tool, "pd_runner", {
            "job_id": job_id, "findings_count": findings_count,
            "duration_s": duration_s, "command": cmd_str,
        })

        # Save session results
        if not no_ingest:
            _save_session_results(job_id, tool, "pd-runner", [output_file],
                                  metadata={"findings_count": findings_count})

    except Exception as e:
        _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="failed")
        emit_webhook_event("scan_failed", tool, {"job_id": job_id, "error": str(e)})
        write_audit("scan_failed", tool, "pd_runner", {
            "job_id": job_id, "error": str(e),
        })
        logging.error(f"[{job_id}] {tool} failed: {e}")
    finally:
        # Cleanup targets file
        if targets_file and os.path.exists(targets_file):
            try:
                os.remove(targets_file)
            except OSError:
                pass


# ===============================
# FastAPI App
# ===============================

app = FastAPI(title="PD Runner")


@app.get("/reports/{filename}")
def get_report_file(filename: str):
    """Serve a report file from the reports directory."""
    # Sanitize: only allow alphanumeric, dots, dashes, underscores
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9._-]+$', filename):
        raise HTTPException(400, "Invalid filename")
    fpath = REPORT_DIR / filename
    if not fpath.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(str(fpath), media_type="application/octet-stream")


@app.on_event("startup")
async def startup_event():
    setup_log_capture()
    logging.info("[pd-runner] Service started, log capture initialized")


# --- Request Models ---

class HttpxReq(BaseModel):
    targets: Any = None  # list or "from_db"
    ports: Optional[str] = None
    tech_detect: Optional[bool] = True
    proxy: Optional[str] = None  # e.g. socks5://node-manager:10120
    no_ingest: Optional[bool] = False

class NaabuReq(BaseModel):
    targets: List[str]
    ports: Optional[str] = "1-1000"
    rate: Optional[int] = 1000
    top_ports: Optional[str] = None
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class KatanaReq(BaseModel):
    targets: Any = None  # list or "from_db"
    depth: Optional[int] = 3
    js_crawl: Optional[bool] = True
    xhr_extraction: Optional[bool] = True       # extract XHR request URLs + methods
    form_extraction: Optional[bool] = True      # extract form/input/select elements
    known_files: Optional[str] = "all"          # crawl robots.txt, sitemap.xml, etc. ("all", "robotstxt", "sitemapxml", or None)
    headless: Optional[bool] = False            # enable headless browser crawling
    filter_similar: Optional[bool] = True       # collapse /users/123 and /users/456
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class TlsxReq(BaseModel):
    targets: Any = None  # list or "from_db"
    ports: Optional[str] = "443"
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class WhatwebReq(BaseModel):
    targets: Any = None  # list or "from_db"
    aggression: Optional[int] = 1  # 1=stealthy, 3=aggressive, 4=heavy
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class FfufReq(BaseModel):
    target_url: str                           # must contain FUZZ keyword
    wordlist: Optional[str] = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    method: Optional[str] = "GET"
    extensions: Optional[str] = None          # e.g. ".php,.html,.txt"
    filter_code: Optional[str] = None         # e.g. "404,403"
    match_code: Optional[str] = None          # e.g. "200,301"
    rate: Optional[int] = 100
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

# --- Health ---

@app.get("/health")
def health():
    try:
        with conn() as c, c.cursor() as cur:
            cur.execute("SELECT 1")
        return {"ok": True, "version": os.environ.get("BUILD_VERSION", "dev")}
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
    emit_webhook_event("scan_stopped", "pd-runner", {"job_id": job_id})
    return {"ok": True, "job_id": job_id, "status": "stopped"}


# ===============================
# Tool Endpoints
# ===============================

@app.post("/jobs/httpx")
def run_httpx(req: HttpxReq, background_tasks: BackgroundTasks):
    """HTTP probing and tech detection."""
    job_id = _job_tracker.create_job(job_type="httpx")

    # Resolve targets
    if req.targets == "from_db":
        rows = get_web_targets()
        targets = [f"{r['ip']}:{r['port']}" for r in rows]
    elif isinstance(req.targets, list):
        targets = req.targets
    else:
        raise HTTPException(status_code=400, detail="targets must be a list or 'from_db'")

    if not targets:
        return {"ok": True, "job_id": job_id, "status": "completed", "result": {"findings_count": 0, "message": "no targets"}}

    targets_file = _write_targets_file(targets)
    output_file = str(REPORT_DIR / f"httpx_{job_id[:8]}.jsonl")

    cmd = ["httpx", "-l", targets_file, "-json", "-o", output_file, "-silent",
           "-status-code", "-title", "-web-server", "-content-length", "-follow-redirects"]
    if req.tech_detect:
        cmd.append("-tech-detect")
    if req.ports:
        cmd.extend(["-ports", req.ports])
    if req.proxy:
        cmd.extend(["-proxy", req.proxy])

    _job_tracker.update_progress(job_id, targets_count=len(targets))
    background_tasks.add_task(_run_tool_job, job_id, "httpx", cmd, targets_file, output_file, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/naabu")
def run_naabu(req: NaabuReq, background_tasks: BackgroundTasks):
    """Fast port scanning."""
    job_id = _job_tracker.create_job(job_type="naabu")
    targets_file = _write_targets_file(req.targets)
    output_file = str(REPORT_DIR / f"naabu_{job_id[:8]}.jsonl")

    cmd = ["naabu", "-list", targets_file, "-json", "-o", output_file, "-silent"]
    if req.ports:
        cmd.extend(["-p", req.ports])
    if req.rate:
        cmd.extend(["-rate", str(req.rate)])
    if req.top_ports:
        cmd.extend(["-top-ports", req.top_ports])
    if req.proxy:
        cmd.extend(["-proxy", req.proxy])

    _job_tracker.update_progress(job_id, targets_count=len(req.targets))
    background_tasks.add_task(_run_tool_job, job_id, "naabu", cmd, targets_file, output_file, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/katana")
def run_katana(req: KatanaReq, background_tasks: BackgroundTasks):
    """Web crawling."""
    job_id = _job_tracker.create_job(job_type="katana")

    if req.targets == "from_db":
        rows = get_web_targets()
        scheme_map = {443: "https", 8443: "https"}
        targets = [f"{scheme_map.get(r['port'], 'http')}://{r['ip']}:{r['port']}" for r in rows]
    elif isinstance(req.targets, list):
        targets = req.targets
    else:
        raise HTTPException(status_code=400, detail="targets must be a list or 'from_db'")

    if not targets:
        return {"ok": True, "job_id": job_id, "status": "completed", "result": {"findings_count": 0, "message": "no targets"}}

    targets_file = _write_targets_file(targets)
    output_file = str(REPORT_DIR / f"katana_{job_id[:8]}.jsonl")

    cmd = ["katana", "-list", targets_file, "-jsonl", "-o", output_file, "-silent",
           "-depth", str(req.depth or 3)]
    if req.js_crawl:
        cmd.append("-js-crawl")
    if req.xhr_extraction:
        cmd.append("-xhr-extraction")
    if req.form_extraction:
        cmd.append("-form-extraction")
    if req.known_files:
        cmd.extend(["-known-files", req.known_files])
    if req.headless:
        cmd.append("-headless")
    # -filter-similar not available in katana v1.4.0
    # if req.filter_similar:
    #     cmd.append("-filter-similar")
    if req.proxy:
        cmd.extend(["-proxy", req.proxy])

    _job_tracker.update_progress(job_id, targets_count=len(targets))
    background_tasks.add_task(_run_tool_job, job_id, "katana", cmd, targets_file, output_file, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/tlsx")
def run_tlsx(req: TlsxReq, background_tasks: BackgroundTasks):
    """TLS certificate analysis."""
    job_id = _job_tracker.create_job(job_type="tlsx")

    if req.targets == "from_db":
        rows = get_web_targets()
        targets = [f"{r['ip']}:{r['port']}" for r in rows if r["port"] in (443, 8443)]
    elif req.targets == "from_httpx":
        targets = get_httpx_tls_targets()
    elif isinstance(req.targets, list):
        targets = req.targets
    else:
        raise HTTPException(status_code=400, detail="targets must be a list, 'from_db', or 'from_httpx'")

    if not targets:
        return {"ok": True, "job_id": job_id, "status": "completed", "result": {"findings_count": 0, "message": "no targets"}}

    targets_file = _write_targets_file(targets)
    output_file = str(REPORT_DIR / f"tlsx_{job_id[:8]}.jsonl")

    cmd = ["tlsx", "-l", targets_file, "-json", "-o", output_file, "-silent"]
    if req.ports:
        cmd.extend(["-p", req.ports])

    # tlsx: use ALL_PROXY env var for SOCKS proxy support
    tool_env = None
    if req.proxy:
        tool_env = os.environ.copy()
        tool_env["ALL_PROXY"] = req.proxy

    _job_tracker.update_progress(job_id, targets_count=len(targets))
    background_tasks.add_task(_run_tool_job, job_id, "tlsx", cmd, targets_file, output_file, env=tool_env, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/whatweb")
def run_whatweb(req: WhatwebReq, background_tasks: BackgroundTasks):
    """Web technology fingerprinting."""
    job_id = _job_tracker.create_job(job_type="whatweb")

    # Resolve targets
    if req.targets == "from_db":
        rows = get_web_targets()
        scheme_map = {443: "https", 8443: "https"}
        targets = [f"{scheme_map.get(r['port'], 'http')}://{r['ip']}:{r['port']}" for r in rows]
    elif isinstance(req.targets, list):
        targets = req.targets
    else:
        raise HTTPException(status_code=400, detail="targets must be a list or 'from_db'")

    if not targets:
        return {"ok": True, "job_id": job_id, "status": "completed", "result": {"findings_count": 0, "message": "no targets"}}

    targets_file = _write_targets_file(targets)
    output_file = str(REPORT_DIR / f"whatweb_{job_id[:8]}.json")

    aggression = max(1, min(4, req.aggression or 1))
    cmd = ["whatweb", f"--input-file={targets_file}", f"--log-json={output_file}",
           "--color=never", "-q", f"-a{aggression}"]
    if req.proxy:
        cmd.extend(["--proxy", req.proxy])

    _job_tracker.update_progress(job_id, targets_count=len(targets))
    background_tasks.add_task(_run_tool_job, job_id, "whatweb", cmd, targets_file, output_file, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


# ===============================
# ffuf - Web Fuzzing
# ===============================

@app.post("/jobs/ffuf")
def run_ffuf(req: FfufReq, background_tasks: BackgroundTasks):
    """Web fuzzing with ffuf."""
    job_id = _job_tracker.create_job(job_type="ffuf")

    if "FUZZ" not in req.target_url:
        raise HTTPException(status_code=400, detail="target_url must contain FUZZ keyword")

    output_file = str(REPORT_DIR / f"ffuf_{job_id[:8]}.json")
    wordlist = req.wordlist or "/usr/share/seclists/Discovery/Web-Content/common.txt"

    cmd = ["ffuf", "-u", req.target_url, "-w", wordlist,
           "-o", output_file, "-of", "json",
           "-rate", str(req.rate or 100)]

    if req.method and req.method.upper() != "GET":
        cmd.extend(["-X", req.method.upper()])
    if req.extensions:
        cmd.extend(["-e", req.extensions])
    if req.filter_code:
        cmd.extend(["-fc", req.filter_code])
    if req.match_code:
        cmd.extend(["-mc", req.match_code])
    if req.proxy:
        cmd.extend(["-x", req.proxy])

    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run_tool_job, job_id, "ffuf", cmd, None, output_file, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


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
        headers={"Content-Disposition": "attachment; filename=pd_runner_logs.json"},
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8023, log_level="info", ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE"))
