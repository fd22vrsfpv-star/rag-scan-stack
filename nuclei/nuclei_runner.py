import os, uuid, pathlib, subprocess, threading, logging, shutil
from typing import List, Optional, Dict, Any
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
import uvicorn, requests, json

logging.basicConfig(level=logging.INFO)

from log_manager import get_log_handler, setup_log_capture, LOGS_UI_HTML

try:
    from audit_writer import write_audit
except ImportError:
    def write_audit(*a, **kw): pass

# Import validation utilities
from validation import (
    validate_scan_target,
    sanitize_port,
    validate_output_path,
    ValidationError
)

DB_DSN      = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
API_BASE    = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY     = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"


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
            timeout=5,
            verify=False
        )
    except Exception as e:
        logging.warning(f"Failed to emit webhook: {e}")
WEB_PORTS   = [int(x) for x in os.environ.get("WEB_PORTS", "80,443,8080,8443").split(",") if x]
SCHEME_HINT = os.environ.get("SCHEME_HINT", "auto")
TEMPLATES   = os.environ.get("NUCLEI_TEMPLATES", "/opt/nuclei-templates")
SEVERITY    = os.environ.get("NUCLEI_SEVERITY", "low,medium,high,critical")
CONC        = int(os.environ.get("NUCLEI_CONCURRENCY", "50"))
RATELIMIT   = int(os.environ.get("NUCLEI_RATELIMIT", "150"))
TIMEOUT     = int(os.environ.get("NUCLEI_TIMEOUT", "10"))
RETRIES     = int(os.environ.get("NUCLEI_RETRIES", "1"))
# Hard wall-clock cap for the whole nuclei scan subprocess (seconds).
# Prevents a stuck target / dead proxy from hanging a job slot forever.
# Default 2h; set to 0 to disable (not recommended in production).
SCAN_WALLCLOCK_TIMEOUT = int(os.environ.get("NUCLEI_SCAN_WALLCLOCK_TIMEOUT", "7200"))
AUTO_UPDATE = os.environ.get("NUCLEI_AUTO_UPDATE", "1") == "1"
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


# ===============================
# Job Tracking System
# ===============================

class JobTracker:
    """Thread-safe job tracking with disk persistence for completed jobs"""

    PERSIST_DIR = SESSION_DIR / ".jobs"

    def __init__(self, max_jobs: int = 100):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.max_jobs = max_jobs
        self.PERSIST_DIR.mkdir(parents=True, exist_ok=True)

    def create_job(self, job_type: str = "nuclei-scan") -> str:
        """Create a new job and return its ID"""
        job_id = str(uuid.uuid4())
        with self._lock:
            if len(self.jobs) >= self.max_jobs:
                self._cleanup_old_jobs()

            self.jobs[job_id] = {
                "job_id": job_id,
                "type": job_type,
                "status": "queued",
                "progress": {
                    "stage": "initializing",
                    "targets_count": 0,
                    "findings_count": 0
                },
                "result": None,
                "created_at": datetime.now().isoformat(),
                "started_at": None,
                "completed_at": None,
                "error": None
            }
        return job_id

    def update_job(self, job_id: str, **kwargs):
        """Update job fields. Persists to disk on terminal status."""
        with self._lock:
            if job_id in self.jobs:
                self.jobs[job_id].update(kwargs)
                if self.jobs[job_id].get("status") in ("completed", "failed", "stopped"):
                    self._persist(job_id)

    def update_progress(self, job_id: str, **kwargs):
        """Update job progress fields"""
        with self._lock:
            if job_id in self.jobs:
                self.jobs[job_id]["progress"].update(kwargs)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status — checks memory first, then disk."""
        with self._lock:
            job = self.jobs.get(job_id)
        if job:
            return job
        return self._load(job_id)

    def list_jobs(self, status: Optional[str] = None, limit: int = 50) -> list:
        """List jobs with optional status filter (memory + disk)."""
        with self._lock:
            jobs = list(self.jobs.values())
        try:
            disk_files = sorted(self.PERSIST_DIR.glob("*.json"),
                                key=lambda f: f.stat().st_mtime, reverse=True)[:limit * 2]
            seen = {j["job_id"] for j in jobs}
            for fp in disk_files:
                if len(jobs) >= limit:
                    break
                jid = fp.stem
                if jid not in seen:
                    loaded = self._load(jid)
                    if loaded:
                        jobs.append(loaded)
                        seen.add(jid)
        except Exception:
            pass
        if status:
            jobs = [j for j in jobs if j.get("status") == status]
        jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jobs[:limit]

    def _persist(self, job_id: str):
        """Save job state to disk."""
        try:
            data = self.jobs[job_id].copy()
            (self.PERSIST_DIR / f"{job_id}.json").write_text(json.dumps(data, default=str))
        except Exception as e:
            logging.warning(f"[job-persist] Failed to save {job_id[:8]}: {e}")

    def _load(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Load job state from disk."""
        fp = self.PERSIST_DIR / f"{job_id}.json"
        if fp.exists():
            try:
                return json.loads(fp.read_text())
            except Exception:
                pass
        return None

    def _cleanup_old_jobs(self):
        """Remove old completed jobs to stay under max capacity"""
        completed = [(k, v) for k, v in self.jobs.items()
                     if v["status"] in ("completed", "failed")]
        completed.sort(key=lambda x: x[1].get("completed_at", ""))
        for job_id, _ in completed[:len(completed)//2]:
            del self.jobs[job_id]


# Global job tracker
_job_tracker = JobTracker(max_jobs=100)


def conn(): return psycopg2.connect(DB_DSN)

def get_web_targets():
    q = """
    SELECT a.id AS asset_id, host(a.ip)::text AS ip, p.port,
           CASE
             WHEN %s = 'http'  THEN 'http'
             WHEN %s = 'https' THEN 'https'
             WHEN p.port IN (443,8443) THEN 'https'
             ELSE 'http'
           END AS scheme
    FROM ports p
    JOIN assets a ON a.id = p.asset_id
    WHERE p.port = ANY(%s) AND COALESCE(p.is_open, true)
    ORDER BY ip, p.port;
    """
    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(q, (SCHEME_HINT, SCHEME_HINT, WEB_PORTS))
        return cur.fetchall()


# Import protocol mappings from config file (edit protocol_config.py to customize)
from protocol_config import (
    HTTP_PORTS, HTTPS_PORTS,
    SERVICE_PROTOCOL_MAP, PORT_PROTOCOL_MAP,
    get_protocol_for_service, build_target_url
)


def get_all_targets():
    """Get ALL open ports from database for comprehensive Nuclei scanning"""
    q = """
    SELECT a.id AS asset_id, host(a.ip)::text AS ip, p.port, p.service
    FROM ports p
    JOIN assets a ON a.id = p.asset_id
    WHERE COALESCE(p.is_open, true)
    ORDER BY ip, p.port;
    """
    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(q)
        return cur.fetchall()


def build_target(ip: str, port: int, service_name: str = None) -> str:
    """
    Build a target string for Nuclei based on port/service.
    Uses protocol mappings from protocol_config.py to generate proper URLs
    like ssh://host:22, mysql://host:3306, etc.
    """
    try:
        validated_host = validate_scan_target(ip, allow_private=True)
        validated_port = sanitize_port(port)
    except ValidationError as e:
        raise ValueError(f"Invalid target: {e}")

    # Use protocol config to build the target URL
    return build_target_url(validated_host, validated_port, service_name)

def build_url(scheme: str, host: str, port: int) -> str:
    """Build validated URL from components"""
    # Validate scheme
    if scheme not in ('http', 'https'):
        raise ValueError(f"Invalid URL scheme: {scheme}")

    # Validate host
    try:
        validated_host = validate_scan_target(host, allow_private=True)
    except ValidationError as e:
        raise ValueError(f"Invalid host: {e}")

    # Validate port
    try:
        validated_port = sanitize_port(port)
    except ValidationError as e:
        raise ValueError(f"Invalid port: {e}")

    return f"{scheme}://{validated_host}:{validated_port}"

def ensure_templates():
    if AUTO_UPDATE:
        # Bound template refresh so a stuck download can't block scan startup.
        try:
            subprocess.run(
                ["nuclei", "-ut", "-ud", TEMPLATES],
                check=False,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            logging.warning("nuclei template update exceeded 600s — continuing with existing templates")

def run_nuclei(urls: List[str], tags: Optional[str] = None, proxy: Optional[str] = None) -> pathlib.Path:
    """Run nuclei scan on list of URLs.

    Args:
        proxy: SOCKS proxy URL (e.g., 'socks5://host:port') for scanning through remote nodes.
    """
    ensure_templates()

    # Create safe filenames with uuid
    urls_filename = f"urls_{uuid.uuid4().hex[:8]}.txt"
    output_filename = f"nuclei_{uuid.uuid4().hex[:8]}.json"

    # Validate output paths
    try:
        urls_file_path = validate_output_path(str(REPORT_DIR), urls_filename)
        out_json_path = validate_output_path(str(REPORT_DIR), output_filename)
    except ValidationError as e:
        raise RuntimeError(f"Invalid output path: {e}")

    # Convert to Path objects
    urls_file = pathlib.Path(urls_file_path)
    out_json = pathlib.Path(out_json_path)

    urls_file.write_text("\n".join(urls), encoding="utf-8")
    cmd = ["nuclei","-list",str(urls_file),"-jsonl","-o",str(out_json),
           "-t",TEMPLATES,"-severity",SEVERITY,"-c",str(CONC),"-rl",str(RATELIMIT),
           "-timeout",str(TIMEOUT),"-retries",str(RETRIES),"-silent"]

    # Add tags filter if specified
    if tags:
        cmd.extend(["-tags", tags])

    # Add SOCKS proxy if specified (for scanning through remote nodes)
    if proxy:
        cmd.extend(["-proxy", proxy])
        logging.info("[nuclei] Using proxy: %s", proxy)

    try:
        # Wall-clock cap prevents a stuck proxy / unreachable target from
        # hanging this worker forever. Use timeout=None to opt out.
        timeout_arg = SCAN_WALLCLOCK_TIMEOUT if SCAN_WALLCLOCK_TIMEOUT > 0 else None
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_arg)
    except subprocess.TimeoutExpired as te:
        logging.error(
            "nuclei scan exceeded %ds wall-clock cap — aborting (targets=%d)",
            SCAN_WALLCLOCK_TIMEOUT, len(urls),
        )
        # Surface a typed failure so callers can mark the job failed instead
        # of silently producing an empty output file.
        raise RuntimeError(
            f"nuclei scan timed out after {SCAN_WALLCLOCK_TIMEOUT}s "
            f"(targets={len(urls)}, proxy={'yes' if proxy else 'no'})"
        ) from te
    if cp.returncode not in (0, 1):
        logging.warning("nuclei exit %d: %s", cp.returncode, (cp.stderr or cp.stdout)[:500])
    # nuclei may not create the file if zero matches — create empty file to avoid downstream errors
    if not out_json.exists():
        out_json.write_text("")
        logging.info("nuclei produced no output file — created empty %s", out_json)
    return out_json

def ingest_results(path: pathlib.Path, job_id: str = None, target: str = None) -> dict:
    if not path.exists() or path.stat().st_size == 0:
        return {"ok": True, "findings": 0, "message": "no findings to ingest"}
    files = {"file": ("nuclei.json", path.read_bytes(), "application/json")}
    headers = {"x-api-key": API_KEY}
    params = {}
    if job_id:
        params["job_id"] = job_id
    if target:
        params["target"] = target
    r = requests.post(f"{API_BASE}/ingest/nuclei", files=files, headers=headers, params=params, timeout=300, verify=False)
    r.raise_for_status()
    try: return r.json()
    except Exception: return {"ok": True, "raw": r.text}

app = FastAPI(title="Nuclei Runner")

@app.on_event("startup")
async def startup_event():
    setup_log_capture()
    logging.info("[nuclei-runner] Service started, log capture initialized")

class JobReq(BaseModel):
    target: Optional[str] = None  # Direct target URL/IP to scan (e.g., 'http://192.168.1.150' or '192.168.1.150')
    targets: Optional[list[str]] = None  # Multiple targets (takes priority over target)
    limit: Optional[int] = None
    severity: Optional[str] = None
    all_ports: Optional[bool] = False  # Scan ALL open ports, not just web ports
    tags: Optional[str] = None  # Template tags filter (e.g., 'cve,rce')
    proxy: Optional[str] = None  # SOCKS proxy URL for scanning through remote nodes (e.g., 'socks5://host:port')


def _run_nuclei_scan_job(job_id: str, limit: Optional[int], severity: Optional[str], all_ports: bool = False, direct_targets: Optional[list[str]] = None, tags: Optional[str] = None, proxy: Optional[str] = None):
    """Background task to run nuclei scan with progress tracking"""
    global SEVERITY
    orig_severity = SEVERITY

    try:
        import time as _time
        _t0 = _time.time()
        target = direct_targets[0] if direct_targets and len(direct_targets) == 1 else None
        # Emit webhook for scan start
        emit_webhook_event("scan_started", "nuclei", {
            "job_id": job_id,
            "scan_type": "nuclei-scan",
            "target": target or (direct_targets[:3] if direct_targets else None),
            "all_ports": all_ports,
            "severity": severity or SEVERITY,
            "tags": tags,
            "limit": limit
        })
        write_audit("scan_started", "nuclei", "nuclei_runner", {
            "job_id": job_id, "targets": direct_targets or [],
            "parameters": {"severity": severity or SEVERITY, "tags": tags},
            "proxy": proxy, "execution_mode": "local",
        })

        _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="fetching_targets")

        # If direct targets provided, use them instead of database targets
        if direct_targets:
            logging.info(f"[nuclei-runner] Using {len(direct_targets)} direct target(s)")
            targets = []
            for t in direct_targets:
                if t.startswith('http://') or t.startswith('https://'):
                    targets.append(t)
                else:
                    targets.append(f"http://{t}")
            raw_targets = []  # Skip database lookup
        else:
            # Get targets based on all_ports flag
            if all_ports:
                logging.info("[nuclei-runner] Scanning ALL open ports (not just web ports)")
                raw_targets = get_all_targets()
            else:
                raw_targets = get_web_targets()

            if limit:
                raw_targets = raw_targets[:max(1, int(limit))]

        # Build targets with validation (only if not using direct target)
        _job_tracker.update_progress(job_id, stage="validating_targets")
        skipped = 0
        if not target:  # Only build from raw_targets if no direct target
            targets = []
            for t in raw_targets:
                try:
                    if all_ports:
                        # Use build_target for all ports (handles HTTP and non-HTTP)
                        tgt = build_target(t["ip"], t["port"], t.get("service"))
                    else:
                        # Use build_url for web-only (legacy behavior)
                        tgt = build_url(t["scheme"], t["ip"], t["port"])
                    targets.append(tgt)
                except (ValueError, ValidationError) as e:
                    print(f"[WARN] Skipping invalid target {t}: {e}")
                    skipped += 1

        _job_tracker.update_progress(job_id, targets_count=len(targets))

        if not targets:
            _job_tracker.update_job(
                job_id,
                status="completed",
                result={"ok": True, "targets": 0, "skipped": skipped or "no open ports found"},
                completed_at=datetime.now().isoformat()
            )
            _job_tracker.update_progress(job_id, stage="done")
            return

        # Update severity if specified
        if severity:
            SEVERITY = severity

        # Update templates
        _job_tracker.update_progress(job_id, stage="template_update")
        ensure_templates()

        # Run nuclei scan
        _job_tracker.update_progress(job_id, stage="scanning")
        out_json = run_nuclei(targets, tags=tags, proxy=proxy)

        # Count findings from output file
        findings_count = 0
        if out_json.exists():
            try:
                with open(out_json) as f:
                    findings_count = sum(1 for _ in f)
            except Exception:
                pass
        _job_tracker.update_progress(job_id, findings_count=findings_count)

        # Ingest results
        _job_tracker.update_progress(job_id, stage="ingesting")
        # Pass target info: use explicit target if provided, otherwise summarize targets list
        target_info = target if target else (targets[0] if len(targets) == 1 else f"{len(targets)} targets")
        ing = ingest_results(out_json, job_id=job_id, target=target_info)

        _job_tracker.update_progress(job_id, stage="done")
        _job_tracker.update_job(
            job_id,
            status="completed",
            result={"ok": True, "targets": len(targets), "skipped": skipped, "all_ports": all_ports, "report": str(out_json), "ingest": ing},
            completed_at=datetime.now().isoformat()
        )

        # Insert info finding if nuclei found nothing
        if findings_count == 0:
            try:
                target_label = target if target else (targets[0] if targets else "unknown")
                with conn() as _c, _c.cursor() as _cur:
                    _cur.execute("""
                        INSERT INTO web_findings (id, url, source, issue_type, name, severity, evidence, first_seen, last_seen)
                        VALUES (gen_random_uuid(), %s, 'nuclei', 'scan-note',
                                'Nuclei scan completed — no vulnerabilities found', 'info',
                                %s, now(), now())
                    """, (target_label,
                          f"Scanned {len(targets)} target(s) with nuclei template-based detection. "
                          "No CVEs, misconfigurations, or known vulnerabilities matched."))
                    _c.commit()
                logging.info(f"[nuclei] Inserted info finding for zero-result scan on {target_label}")
            except Exception as _e:
                logging.warning(f"[nuclei] Failed to insert info finding: {_e}")

        # Save session results
        session_files = [str(out_json)]
        # Also grab the most recent urls file
        url_files = sorted(REPORT_DIR.glob("urls_*.txt"), key=lambda f: f.stat().st_mtime, reverse=True)
        if url_files:
            session_files.append(str(url_files[0]))
        _save_session_results(job_id, "nuclei-scan", "nuclei-runner", session_files,
                              metadata={"targets_count": len(targets), "findings_count": findings_count})

        # Emit webhook for scan completion
        emit_webhook_event("scan_completed", "nuclei", {
            "job_id": job_id,
            "targets_count": len(targets),
            "findings_count": findings_count,
            "all_ports": all_ports
        })
        write_audit("scan_completed", "nuclei", "nuclei_runner", {
            "job_id": job_id, "findings_count": findings_count,
            "duration_s": round(_time.time() - _t0, 2),
        })

    except Exception as e:
        _job_tracker.update_job(
            job_id,
            status="failed",
            error=str(e),
            completed_at=datetime.now().isoformat()
        )
        _job_tracker.update_progress(job_id, stage="failed")

        # Emit webhook for scan failure
        emit_webhook_event("scan_failed", "nuclei", {
            "job_id": job_id,
            "error": str(e)
        })
        write_audit("scan_failed", "nuclei", "nuclei_runner", {
            "job_id": job_id, "error": str(e),
        })

    finally:
        SEVERITY = orig_severity


@app.post("/update-templates")
def update_templates():
    """Force update nuclei templates."""
    try:
        result = subprocess.run(["nuclei", "-update-templates"], capture_output=True, text=True, timeout=120)
        return {"ok": True, "stdout": result.stdout[-500:], "stderr": result.stderr[-500:], "exit_code": result.returncode}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/update-binary")
def update_binary():
    """Update nuclei binary to latest version."""
    try:
        result = subprocess.run(["nuclei", "-update"], capture_output=True, text=True, timeout=120)
        return {"ok": True, "stdout": result.stdout[-500:], "stderr": result.stderr[-500:], "exit_code": result.returncode}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/version")
def get_version():
    """Get nuclei and template versions."""
    try:
        r = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=10)
        return {"ok": True, "output": (r.stdout + r.stderr)[:500]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/templates/search")
def search_templates(q: str = Query(..., description="Product name or keyword to search"),
                     limit: int = Query(20, le=100)):
    """Search nuclei templates by product/keyword. Returns matching template IDs and metadata."""
    import os, yaml as _yaml
    results = []
    q_lower = q.lower().replace(" ", "").replace("-", "")
    # Also build individual search terms
    q_terms = [t.lower() for t in q.split() if len(t) >= 3]

    templates_dir = TEMPLATES
    if not os.path.isdir(templates_dir):
        return {"ok": False, "error": f"Templates directory not found: {templates_dir}", "results": []}

    # Walk template directories looking for matches in filename and YAML metadata
    for root, dirs, files in os.walk(templates_dir):
        if len(results) >= limit:
            break
        for fname in files:
            if not fname.endswith('.yaml'):
                continue
            fname_lower = fname.lower().replace("-", "")
            # Quick filename check
            if q_lower in fname_lower or any(t in fname_lower for t in q_terms):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath) as f:
                        # Only read first 2KB for metadata
                        head = f.read(2048)
                    tmpl = _yaml.safe_load(head)
                    if not isinstance(tmpl, dict):
                        continue
                    info = tmpl.get("info", {})
                    rel_path = os.path.relpath(fpath, templates_dir)
                    results.append({
                        "id": info.get("name", fname.replace(".yaml", "")),
                        "template_path": rel_path,
                        "severity": info.get("severity", "unknown"),
                        "tags": info.get("tags", ""),
                        "description": (info.get("description") or "")[:200],
                        "reference": info.get("reference", [])[:3] if isinstance(info.get("reference"), list) else [],
                        "cve": [r for r in (info.get("reference") or []) if isinstance(r, str) and r.startswith("CVE-")][:5] if isinstance(info.get("reference"), list) else [],
                    })
                except Exception:
                    pass
                if len(results) >= limit:
                    break

    # If few filename matches, also search by YAML content (tags, description)
    if len(results) < 5:
        for root, dirs, files in os.walk(templates_dir):
            if len(results) >= limit:
                break
            for fname in files:
                if not fname.endswith('.yaml'):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, templates_dir)
                if any(r["template_path"] == rel_path for r in results):
                    continue
                try:
                    with open(fpath) as f:
                        head = f.read(2048)
                    head_lower = head.lower()
                    if q_lower not in head_lower and not any(t in head_lower for t in q_terms):
                        continue
                    tmpl = _yaml.safe_load(head)
                    if not isinstance(tmpl, dict):
                        continue
                    info = tmpl.get("info", {})
                    results.append({
                        "id": info.get("name", fname.replace(".yaml", "")),
                        "template_path": rel_path,
                        "severity": info.get("severity", "unknown"),
                        "tags": info.get("tags", ""),
                        "description": (info.get("description") or "")[:200],
                        "reference": info.get("reference", [])[:3] if isinstance(info.get("reference"), list) else [],
                        "cve": [r for r in (info.get("reference") or []) if isinstance(r, str) and r.startswith("CVE-")][:5] if isinstance(info.get("reference"), list) else [],
                    })
                except Exception:
                    pass
                if len(results) >= limit:
                    break

    return {"ok": True, "query": q, "count": len(results), "results": results}


@app.get("/health")
def health():
    try:
        with conn() as c, c.cursor() as cur: cur.execute("SELECT 1")
        return {"ok": True, "version": os.environ.get("BUILD_VERSION", "dev")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/jobs/{job_id}")
def get_job_status(job_id: str):
    """Get the status of a nuclei scan job"""
    job = _job_tracker.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.post("/jobs/{job_id}/stop")
def stop_job(job_id: str):
    """Stop a running nuclei scan job"""
    job = _job_tracker.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job["status"] not in ["queued", "running"]:
        raise HTTPException(status_code=400, detail=f"Job is already {job['status']}, cannot stop")

    # Update job status to stopped
    _job_tracker.update_job(job_id, status="stopped", completed_at=datetime.now().isoformat())
    _job_tracker.update_progress(job_id, stage="user_stopped")

    # Emit webhook for scan stop
    emit_webhook_event("scan_stopped", "nuclei", {
        "job_id": job_id,
        "scan_type": "nuclei-scan",
        "stopped_by": "user",
        "previous_status": job["status"],
        "progress": job.get("progress", {})
    })

    logging.info(f"[nuclei-runner] Scan {job_id} stopped by user request")
    return {"ok": True, "job_id": job_id, "status": "stopped", "message": "Scan stop requested"}


@app.get("/jobs")
def list_jobs(status: Optional[str] = None, limit: int = 50):
    """List all nuclei scan jobs"""
    return {"jobs": _job_tracker.list_jobs(status=status, limit=limit)}


@app.post("/jobs/nuclei-scan")
def nuclei_scan(req: JobReq, background_tasks: BackgroundTasks):
    """Start a Nuclei vulnerability scan job (returns immediately with job_id).
    Set all_ports=true to scan ALL open ports, not just web ports (80, 443, etc.).
    Set target/targets to scan specific URL(s) directly instead of using database targets."""
    job_id = _job_tracker.create_job(job_type="nuclei-scan")
    # Merge target + targets into a single target string or list
    direct_targets = req.targets or ([req.target] if req.target else None)
    background_tasks.add_task(_run_nuclei_scan_job, job_id, req.limit, req.severity, req.all_ports or False,
                              direct_targets, req.tags, req.proxy)
    return {
        "ok": True,
        "job_id": job_id,
        "status": "queued",
        "target": req.target,
        "proxy": req.proxy,
        "status_url": f"/jobs/{job_id}"
    }


@app.post("/jobs/nuclei-scan/sync")
def nuclei_scan_sync(req: JobReq):
    """Run Nuclei vulnerability scan synchronously (blocking, returns when done).
    Set all_ports=true to scan ALL open ports, not just web ports (80, 443, etc.)."""
    all_ports = req.all_ports or False

    # Get targets based on all_ports flag
    if all_ports:
        logging.info("[nuclei-runner] Sync scan: Scanning ALL open ports")
        raw_targets = get_all_targets()
    else:
        raw_targets = get_web_targets()

    if req.limit:
        raw_targets = raw_targets[:max(1, int(req.limit))]

    # Build targets with validation
    targets = []
    skipped = 0
    for t in raw_targets:
        try:
            if all_ports:
                target = build_target(t["ip"], t["port"], t.get("service"))
            else:
                target = build_url(t["scheme"], t["ip"], t["port"])
            targets.append(target)
        except (ValueError, ValidationError) as e:
            print(f"[WARN] Skipping invalid target {t}: {e}")
            skipped += 1

    if not targets:
        return {"ok": True, "targets": 0, "skipped": skipped or "no open ports found"}
    global SEVERITY; orig = SEVERITY
    if req.severity: SEVERITY = req.severity
    try:
        out_json = run_nuclei(targets, tags=req.tags)
        # Generate a job_id for sync scans for webhook tracking
        sync_job_id = f"sync-{uuid.uuid4()}"
        target_info = req.target if req.target else (targets[0] if len(targets) == 1 else f"{len(targets)} targets")
        ing = ingest_results(out_json, job_id=sync_job_id, target=target_info)
        return {"ok": True, "targets": len(targets), "all_ports": all_ports, "report": str(out_json), "ingest": ing}
    finally:
        SEVERITY = orig


# ===============================
# Logs UI Endpoints
# ===============================

@app.get("/logs/ui", response_class=HTMLResponse)
async def logs_ui():
    """Serve the logs viewer web interface"""
    return HTMLResponse(content=LOGS_UI_HTML)


@app.get("/logs")
async def get_logs(
    level: Optional[str] = Query(None, description="Filter by log level"),
    limit: int = Query(100, description="Max logs to return"),
    search: Optional[str] = Query(None, description="Search in message"),
    job_id: Optional[str] = Query(None, description="Filter by job ID")
):
    """Get captured logs with optional filtering"""
    handler = get_log_handler()
    logs = await handler.async_get_logs(level=level, limit=limit, search=search, job_id=job_id)
    return {"logs": logs}


@app.get("/logs/stats")
async def get_log_stats():
    """Get log capture statistics"""
    handler = get_log_handler()
    stats = await handler.async_get_stats()
    return {"ok": True, "stats": stats}


@app.get("/logs/export")
async def export_logs():
    """Export all captured logs as JSON"""
    handler = get_log_handler()
    json_data = await handler.async_export_json()
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=nuclei_logs.json"}
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8011, log_level="info", ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE"))
