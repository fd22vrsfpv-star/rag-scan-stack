"""
PD Runner - Active Scanning FastAPI Service
Provides endpoints for active scanning tools: httpx, naabu, katana, and tlsx.
Passive OSINT tools are in osint-runner. Credential testing is in brutus-runner.
"""

import os, uuid, pathlib, subprocess, threading, logging, json, tempfile, shutil
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, Response, FileResponse
from pydantic import BaseModel
import uvicorn, requests
# Shared job runner, delivered by the rag-common base image
# (common/tool_job.py). Both runners previously carried their own copy.
from tool_job import run_tool_job

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


def _ingest_results(tool: str, output_path: str, job_id: str = None,
                    source: str = None) -> dict:
    """POST results file to rag-api ingest endpoint."""
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        return {"ok": True, "skipped": "no output"}
    try:
        files = {"file": (f"{tool}.json", open(output_path, "rb"), "application/json")}
        headers = {"x-api-key": API_KEY}
        params = {}
        if job_id:
            params["job_id"] = job_id
        # Distinguishes the TOOL that produced the file from the PARSER used to
        # read it, when one tool's output is ingested in another's format.
        if source:
            params["source"] = source
        r = requests.post(f"{API_BASE}/ingest/{tool}", files=files, headers=headers, params=params, timeout=300, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.warning(f"Ingest to /ingest/{tool} failed: {e}")
        return {"ok": False, "error": str(e)}


# ===============================
# Tool Runner Functions
# ===============================

# ── Scope gate ────────────────────────────────────────────────────────────
# Shared implementation from etl/scope_gate.py (bind-mounted at /runner/etl).
# This runner writes its targets to a FILE and hands the path to the tool, so
# the file is what actually decides where packets go — that is what gets
# checked, not just the request arguments.
try:
    from etl.scope_gate import check_targets_file, load_dispatch_scope
    SCOPE_GATE_AVAILABLE = True
except Exception as _scope_err:                 # pragma: no cover
    SCOPE_GATE_AVAILABLE = False
    logging.error("scope gate UNAVAILABLE (%s) — jobs will be refused. "
                  "Check the ./etl:/runner/etl mount.", _scope_err)


def _scope_refusal_for_targets(targets_file: str):
    """Refusal string when a targets file is out of scope, else None.

    Fails CLOSED: an unavailable gate or unreadable scope refuses the job. A
    scanner that cannot tell whether it is authorised must not scan.
    """
    if not SCOPE_GATE_AVAILABLE:
        return "scope gate unavailable (etl/scope_gate not importable) — refusing"
    try:
        _c = conn()
        try:
            with _c.cursor() as cur:
                rows, _src = load_dispatch_scope(cur)
        finally:
            _c.close()
    except Exception as exc:
        return f"scope could not be read ({exc}) — refusing"
    return check_targets_file(targets_file, rows)


def _run_tool_job(job_id: str, tool: str, cmd: list, targets_file: str, output_file: str, ingest_as: str = None, env: dict = None, no_ingest: bool = False):
    """Run one tool job. The implementation is shared — see common/tool_job.py.

    This module previously carried its own copy. The two copies had drifted,
    with improvements stranded in one of them, so the shared version is the
    union and this service gains whatever it was missing.
    """
    run_tool_job(
        job_id=job_id, tool=tool, cmd=cmd, targets_file=targets_file,
        output_file=output_file, ingest_as=ingest_as, env=env, no_ingest=no_ingest,
        service_name="pd_runner", session_label="pd-runner",
        job_tracker=_job_tracker,
        emit_webhook_event=emit_webhook_event,
        write_audit=write_audit,
        ingest_results=_ingest_results,
        scope_refusal=_scope_refusal_for_targets,
        save_session_results=_save_session_results,
        on_success=None,
    )


# ===============================
# FastAPI App
# ===============================

app = FastAPI(title="PD Runner")

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

class NmapServiceReq(BaseModel):
    """Service detection over ALREADY-DISCOVERED ports.

    Deliberately not a port scanner: naabu does discovery and does it faster.
    This answers the question naabu cannot — WHAT is listening. Measured on
    Metasploitable2 (2026-10-22): naabu reported 21 open ports and named none;
    `nmap -sV` on those same ports identified 20 and gave exact versions for
    11, including vsftpd 2.3.4 (CVE-2011-2523), UnrealIRCd (CVE-2010-2075) and
    Samba 3.x (CVE-2007-2447). The host had 22 ports recorded and ZERO vulns,
    because the CVE lookup keys on product+version and had neither.
    """
    # 'from_db' resolves each host's OPEN ports from the ports table, so the
    # -sV sweep is bounded by what discovery actually found instead of
    # re-scanning 65535 ports per host.
    targets: Union[List[str], str] = "from_db"
    # Per-host override. Omit it and each target is scanned on its own
    # discovered ports; a shared list here would scan every host for every
    # other host's ports.
    ports: Optional[str] = None
    # -sV intensity. 7 is nmap's default; 0-9 are valid. Lower is faster and
    # identifies less.
    version_intensity: Optional[int] = 7
    # Hosts in these labs do not answer ping, and a host that is up but
    # filtered must not be skipped before we ever ask what it runs.
    skip_host_discovery: Optional[bool] = True
    max_hosts: Optional[int] = 50
    no_ingest: Optional[bool] = False


def get_scanned_hosts(limit: int = 50):
    """Hosts with at least one open port, and the ports themselves.

    Returns [{ip, ports: "21,22,80"}]. One entry per host so each is scanned on
    its OWN ports — a single merged port list would scan every host for every
    other host's services, which is both slower and noisier than the discovery
    that produced it.
    """
    q = """
    SELECT host(a.ip)::text AS ip,
           string_agg(DISTINCT p.port::text, ',' ORDER BY p.port::text) AS ports
    FROM ports p
    JOIN assets a ON a.id = p.asset_id
    WHERE COALESCE(p.is_open, true)
      AND host(a.ip)::text NOT IN ('0.0.0.0', '::')
    GROUP BY 1
    ORDER BY 1
    LIMIT %s;
    """
    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(q, (limit,))
        return cur.fetchall()


class NaabuReq(BaseModel):
    targets: List[str]
    # None means "not specified" — run_naabu then falls back to naabu's own
    # -top-ports 1000, the frequency-ranked list. The previous "1-1000" default
    # was the first 1000 port NUMBERS, which misses mysql 3306, postgresql 5432,
    # vnc 5900 and tomcat 8180, and applied to every caller that omitted the field.
    ports: Optional[str] = None
    rate: Optional[int] = 1000
    top_ports: Optional[str] = None
    proxy: Optional[str] = None
    # RE-SCAN what we already found, instead of sweeping the top-1000 again.
    # A host with known-open ports does not need rediscovering to confirm those
    # ports are still up — and a 1000-port sweep per re-scan is traffic at a
    # customer's estate for an answer already in the database.
    #
    # Opt-in, not the default: a narrowed re-scan CANNOT discover a port that
    # opened since the last run, so making it automatic would quietly convert
    # discovery into verification. Callers that want fresh discovery keep the
    # existing behaviour by leaving this off.
    known_ports_only: Optional[bool] = False
    # SERVICE DETECTION, ON BY DEFAULT.
    #
    # naabu answers "which ports are open" and structurally cannot answer
    # "what is on them" — its JSON has no service/product/version field at
    # all. Measured on Metasploitable2: 21 ports found, 0 named. The CVE rules
    # join on product+version, so a discovery-only scan left that host at 22
    # ports and ZERO vulns while running vsftpd 2.3.4 (CVE-2011-2523),
    # UnrealIRCd (CVE-2010-2075) and Samba 3.x (CVE-2007-2447).
    #
    # So identification is part of a port scan, not a second thing to
    # remember. Chained AFTER naabu and bounded to the ports it just found —
    # FastAPI runs background tasks in order, so the seed query sees them.
    # Set false for discovery-only (a broad sweep where -sV would multiply the
    # traffic for hosts nobody will look at).
    service_detect: Optional[bool] = True
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
    # AUTHENTICATED crawl: custom headers (incl. "Cookie: JSESSIONID=..." or
    # "Authorization: Bearer ...") sent on every request, so katana reaches the
    # logged-in area (e.g. /bank/*). The caller resolves the session from the
    # Auth Profile and passes it here — pd-runner just forwards it to -H.
    headers: Optional[List[str]] = None         # each "Name: value"
    # Automatic form fill (-aff): fills and SUBMITS discovered forms, so a GET
    # form like the account-summary dropdown produces the concrete object-ref URL
    # (showAccount?listAccounts=<value>) that parse_katana turns into a
    # discovered_param the IDOR mutation probe can then mutate. Off by default
    # (experimental in katana); enabled for authenticated web crawls.
    auto_form_fill: Optional[bool] = False
    # Crawl scope. katana's default is "rdn" (root domain), which is far too
    # loose for an engagement: crawling a Metasploitable TWiki instance followed
    # links off-host and issued requests to twiki.org, twitter.com, youtube.com,
    # wikipedia and others — third parties that are not in anyone's scope. "fqdn"
    # keeps the crawler on the exact host it was pointed at.
    field_scope: Optional[str] = "fqdn"          # fqdn | rdn | dn, or a regex

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
    # AUTHENTICATED fuzzing: custom headers (e.g. "Cookie: JSESSIONID=..." or
    # "Authorization: Bearer ...") sent on every request, so ffuf fuzzes the
    # logged-in surface. The caller resolves the session from the Auth Profile.
    headers: Optional[List[str]] = None       # each "Name: value"

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

    # Bound the sweep to ports discovery already found for THESE hosts.
    # Explicit `ports` still wins — an operator naming a list means it.
    _known = None
    if req.known_ports_only and not req.ports:
        _by_host = {r["ip"]: r["ports"] for r in get_scanned_hosts(limit=500)
                    if r.get("ports")}
        _hit = sorted({p for t in req.targets for p in (_by_host.get(t) or "").split(",") if p},
                      key=lambda x: int(x) if x.isdigit() else 0)
        if _hit:
            _known = ",".join(_hit)
        # No hit means these hosts have never been scanned. Falling through to
        # the top-1000 is correct: "we hold no ports for this host" is not
        # "this host has no open ports", and narrowing to an empty list would
        # scan nothing while reporting success.

    if req.ports:
        cmd.extend(["-p", req.ports])
    elif _known:
        cmd.extend(["-p", _known])
    if req.rate:
        cmd.extend(["-rate", str(req.rate)])
    if req.top_ports:
        cmd.extend(["-top-ports", req.top_ports])
    # Neither given: naabu supports -top-ports natively, so the frequency-ranked
    # top-1000 costs nothing to express here and needs no profile lookup — unlike
    # masscan, which has no such flag and forces profiles to resolve to explicit
    # lists. Without this, omitting ports fell through to naabu's own default of
    # its top-100, a tenth of the intended scope.
    if not req.ports and not _known and not req.top_ports:
        cmd.extend(["-top-ports", "1000"])
    if req.proxy:
        cmd.extend(["-proxy", req.proxy])

    _job_tracker.update_progress(job_id, targets_count=len(req.targets))
    background_tasks.add_task(_run_tool_job, job_id, "naabu", cmd, targets_file, output_file, no_ingest=req.no_ingest)

    sd_job = None
    if req.service_detect and not req.no_ingest:
        # Queued second, so it runs after naabu has finished AND ingested —
        # its port seed is a query against what this scan just stored. With
        # no_ingest there is nothing stored to seed from, so it is skipped
        # rather than run against stale rows.
        sd_job = _job_tracker.create_job(job_type="nmap")
        background_tasks.add_task(_service_detect_after_discovery, sd_job,
                                  list(req.targets), req.no_ingest)

    return {"ok": True, "job_id": job_id, "status": "queued",
            "status_url": f"/jobs/{job_id}",
            "service_detect_job_id": sd_job,
            "no_ingest": req.no_ingest}


def _service_detect_after_discovery(job_id: str, targets: List[str], no_ingest: bool):
    """`nmap -sV` over the ports discovery just found for these hosts.

    Runs as the second background task of a naabu job, so the ports table
    already holds this scan's results. A host with nothing stored is skipped,
    not swept: "discovery found no open ports" and "discovery has not run" look
    identical from here, and the second is not a reason to scan 65535 ports.
    """
    try:
        known = {r["ip"]: r["ports"] for r in get_scanned_hosts(limit=500)
                 if r.get("ports")}
        pairs = [(t, known[t]) for t in targets if known.get(t)]
        if not pairs:
            # Distinct from a completed scan: nothing was fingerprinted, and
            # saying so beats a silent "done" that reads as "no services".
            _job_tracker.update_progress(
                job_id, stage="skipped", findings_count=0,
                message="no discovered ports for these targets — nothing to fingerprint")
            return
        ports = sorted({p for _, pl in pairs for p in pl.split(",") if p},
                       key=lambda x: int(x) if x.isdigit() else 0)
        out = str(REPORT_DIR / f"nmap_{job_id[:8]}.xml")
        cmd = ["nmap", "-sV", "--version-intensity", "7", "-Pn", "-oX", out]
        if ports:
            cmd += ["-p", ",".join(ports)]
        cmd += [ip for ip, _ in pairs]
        tf = _write_targets_file([ip for ip, _ in pairs])
        _job_tracker.update_progress(job_id, targets_count=len(pairs))
        _run_tool_job(job_id, "nmap", cmd, tf, out, no_ingest=no_ingest)
    except Exception as e:  # noqa: BLE001
        # Never let the follow-up take the discovery result down with it: the
        # ports are already stored and useful without their service names.
        logging.warning("service detection after discovery failed: %s", e)


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
    # Keep the crawler on the target host. Without this katana uses its default
    # root-domain scope and will follow off-site links out of the engagement —
    # a real authorization problem, not just noisy data, because it means the
    # scanner sends traffic to third-party sites during an engagement.
    if req.field_scope:
        cmd.extend(["-field-scope", req.field_scope])
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
    # Authenticated crawl: forward each header/cookie to katana's -H.
    for h in (req.headers or []):
        if h and ":" in h:
            cmd.extend(["-H", h])
    # Automatic form fill: submit forms so object-ref URLs (e.g.
    # showAccount?listAccounts=<value>) are produced and ingested as params.
    if req.auto_form_fill:
        cmd.append("-aff")
    # NEVER crawl logout/sign-off during an AUTHENTICATED crawl (headers set):
    # katana shares the caller's session cookie, so requesting /logout.jsp
    # invalidates it server-side and logs out everything else using that session
    # (the browser crawl + the IDOR probe). Exclude it from the crawl scope.
    if req.headers:
        cmd.extend(["-crawl-out-scope",
                    r"(?i)(logout|log-?off|log_?off|sign-?off|sign-?out|signout)"])
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


@app.post("/jobs/nmap")
def run_nmap_service_detection(req: NmapServiceReq, background_tasks: BackgroundTasks):
    """Service + version detection over already-discovered ports.

    The pipeline ran naabu and nothing else, so every port landed with a number
    and no service. `etl/parse_nmap.py` and `/ingest/nmap` already existed to
    consume nmap XML — nothing produced any.
    """
    job_id = _job_tracker.create_job(job_type="nmap")

    # One (host, ports) pair per target so each is scanned on its own open
    # ports. A merged list would scan every host for every other host's.
    pairs: List[tuple] = []
    if req.targets == "from_db":
        for row in get_scanned_hosts(limit=max(1, min(500, req.max_hosts or 50))):
            if row.get("ports"):
                pairs.append((row["ip"], row["ports"]))
    elif isinstance(req.targets, list):
        if req.ports:
            pairs = [(t, req.ports) for t in req.targets]
        else:
            # Explicit targets with no ports: look each one up, and fall back
            # to nmap's top-1000 only for a host we have never scanned —
            # "no discovery yet" is not "no open ports".
            known = {r["ip"]: r["ports"] for r in get_scanned_hosts(limit=500)}
            pairs = [(t, known.get(t, "")) for t in req.targets]
    else:
        raise HTTPException(status_code=400, detail="targets must be a list or 'from_db'")

    if not pairs:
        return {"ok": True, "job_id": job_id, "status": "completed",
                "result": {"findings_count": 0,
                           "message": "no scanned hosts with open ports — run naabu first"}}

    output_file = str(REPORT_DIR / f"nmap_{job_id[:8]}.xml")
    # -sV is the point. -Pn because a filtered host that is up must not be
    # skipped before we ask what it runs. --version-intensity is the caller's
    # speed/accuracy dial. No -O: OS detection needs raw sockets and doubles
    # the runtime for a guess the service banners usually settle anyway.
    iv = max(0, min(9, req.version_intensity if req.version_intensity is not None else 7))
    cmd = ["nmap", "-sV", "--version-intensity", str(iv), "-oX", output_file]
    if req.skip_host_discovery:
        cmd.append("-Pn")

    # nmap takes ONE -p list per invocation, so hosts sharing a port list are
    # batched and the rest run as separate targets in the same job.
    by_ports: Dict[str, List[str]] = {}
    for ip, ports in pairs:
        by_ports.setdefault(ports or "", []).append(ip)
    if len(by_ports) == 1:
        ports, hosts = next(iter(by_ports.items()))
        if ports:
            cmd += ["-p", ports]
        cmd += hosts
    else:
        # Mixed port lists: take the union and scan every host over it. Less
        # precise than per-host, but one nmap run, and still bounded by what
        # discovery found rather than by 65535.
        union = sorted({p for ports in by_ports for p in ports.split(",") if p},
                       key=lambda x: int(x) if x.isdigit() else 0)
        if union:
            cmd += ["-p", ",".join(union)]
        cmd += [ip for hosts in by_ports.values() for ip in hosts]

    targets_file = _write_targets_file([ip for ip, _ in pairs])
    _job_tracker.update_progress(job_id, targets_count=len(pairs))
    background_tasks.add_task(_run_tool_job, job_id, "nmap", cmd, targets_file,
                              output_file, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued",
            "status_url": f"/jobs/{job_id}", "hosts": len(pairs),
            "no_ingest": req.no_ingest}


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
    # Authenticated fuzzing: forward each header/cookie to ffuf's -H.
    for h in (req.headers or []):
        if h and ":" in h:
            cmd.extend(["-H", h])

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
    from common.tls_startup import require_tls_or_exit
    _ssl_certfile, _ssl_keyfile = require_tls_or_exit("pd-runner")
    uvicorn.run(app, host="0.0.0.0", port=8023, log_level="info", ssl_certfile=_ssl_certfile, ssl_keyfile=_ssl_keyfile)
