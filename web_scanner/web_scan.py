import os, time, subprocess, pathlib, re, uuid, threading, logging, shutil, json
from typing import Optional, Dict, Any, List
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import HTMLResponse, Response, FileResponse
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO)

from log_manager import get_log_handler, setup_log_capture, LOGS_UI_HTML

try:
    from audit_writer import write_audit
except ImportError:
    def write_audit(*a, **kw): pass

# Create logger for web scanning - attach to CircularLogHandler
logger = logging.getLogger("web_scanner")
logger.setLevel(logging.INFO)
# Attach CircularLogHandler directly to ensure logs go to UI
_circular_handler = get_log_handler()
if _circular_handler not in logger.handlers:
    logger.addHandler(_circular_handler)

# Import validation utilities
from validation import (
    validate_scan_target,
    sanitize_port,
    sanitize_url_path,
    ValidationError
)

DB_DSN      = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
WORDLIST    = os.environ.get("WORDLIST", "/opt/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt")
API_BASE    = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY     = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"


def emit_webhook_event(event_type: str, source: str, data: dict, severity: str = None):
    """Emit a webhook event via the RAG API."""
    if not WEBHOOK_ENABLED:
        return
    try:
        import requests
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
            timeout=5
        )
    except Exception as e:
        logger.warning(f"Failed to emit webhook: {e}")
WEB_PORTS   = [int(x) for x in os.environ.get("WEB_PORTS", "80,443,8080,8443,8000,8888,3000,5000").split(",") if x]

# Available wordlists for gobuster (mapped to full paths)
WORDLISTS = {
    "small": "/opt/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
    "medium": "/opt/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "big": "/opt/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",
    "common": "/opt/seclists/Discovery/Web-Content/common.txt",
    "raft-small": "/opt/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "raft-medium": "/opt/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "raft-large": "/opt/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "quickhits": "/opt/seclists/Discovery/Web-Content/quickhits.txt",
    "api": "/opt/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
}
REPORT_DIR  = pathlib.Path(os.environ.get("REPORT_DIR", "/reports"))
SCHEME_HINT = os.environ.get("SCHEME_HINT", "auto")
ZAP_ADDR    = os.environ.get("ZAP_ADDR", "zap")
ZAP_PORT    = int(os.environ.get("ZAP_PORT", "8090"))
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "changeme")
PLAYWRIGHT_URL = os.environ.get("PLAYWRIGHT_URL", "https://playwright-scanner:8014")
PD_RUNNER_URL = os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SESSION_DIR = pathlib.Path(os.environ.get("SESSION_RESULTS_DIR", "/scan_results"))


def _insert_info_finding(source: str, url: str, name: str, evidence: str):
    """Insert an informational finding into web_findings when a scanner reports zero results."""
    try:
        with conn() as c, c.cursor() as cur:
            cur.execute("""
                INSERT INTO web_findings (id, url, source, issue_type, name, severity, evidence, first_seen, last_seen)
                VALUES (gen_random_uuid(), %s, %s, 'scan-note', %s, 'info', %s, now(), now())
            """, (url, source, name, evidence))
            c.commit()
        logger.info(f"[{source}] Inserted info finding: {name}")
    except Exception as e:
        logger.warning(f"[{source}] Failed to insert info finding: {e}")


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
        logger.info(f"[session] Saved {len(copied)} files to {session_path}")
    except Exception as e:
        logger.warning(f"[session] Failed to save session results: {e}")


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

    def create_job(self, job_type: str = "web-scan") -> str:
        """Create a new job and return its ID"""
        job_id = str(uuid.uuid4())
        with self._lock:
            # Clean up old completed jobs if at capacity
            if len(self.jobs) >= self.max_jobs:
                self._cleanup_old_jobs()

            self.jobs[job_id] = {
                "job_id": job_id,
                "type": job_type,
                "status": "queued",
                "progress": {
                    "stage": "initializing",
                    "targets_total": 0,
                    "targets_completed": 0,
                    "current_target": None
                },
                "stats": {},
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
                # Keep progress.stage in sync with top-level stage
                if "stage" in kwargs and "progress" in self.jobs[job_id]:
                    self.jobs[job_id]["progress"]["stage"] = kwargs["stage"]
                if self.jobs[job_id].get("status") in ("completed", "failed", "stopped"):
                    self._persist(job_id)

    def push_command(self, job_id: str, stage: str, command: str):
        """Append a command to the progress.commands array (live updates for pipelines)."""
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
                prog["command"] = command  # Also set current command

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
        # Also load recent persisted jobs not in memory
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
            logger.warning(f"[job-persist] Failed to save {job_id[:8]}: {e}")

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
        # Sort by completion time, oldest first
        completed.sort(key=lambda x: x[1].get("completed_at", ""))
        # Remove oldest half of completed jobs
        for job_id, _ in completed[:len(completed)//2]:
            del self.jobs[job_id]


# Global job tracker
_job_tracker = JobTracker(max_jobs=100)


def conn(): return psycopg2.connect(DB_DSN)

def get_web_targets():
    """Build web targets using actual port/service data from scans.

    Scheme detection priority:
    1. SCHEME_HINT env override ('http' or 'https') — forces all targets
    2. service column from nmap: 'https', 'ssl/http', 'https-alt' → https
    3. banner/product containing 'SSL' or 'TLS' → https
    4. Well-known TLS ports (443, 8443, 4443, 9443) → https
    5. Default → http
    """
    q = """
    SELECT a.id AS asset_id, host(a.ip)::text AS ip, p.port,
           p.service, p.product, p.banner,
           CASE
             WHEN %s = 'http'  THEN 'http'
             WHEN %s = 'https' THEN 'https'
             WHEN lower(p.service) IN ('https', 'ssl/http', 'https-alt', 'ssl')
               THEN 'https'
             WHEN lower(p.service) LIKE '%%ssl%%' OR lower(p.service) LIKE '%%tls%%'
               THEN 'https'
             WHEN lower(coalesce(p.product,'')) LIKE '%%ssl%%'
               OR lower(coalesce(p.product,'')) LIKE '%%tls%%'
               OR lower(coalesce(p.banner,'')) LIKE '%%ssl%%'
               OR lower(coalesce(p.banner,'')) LIKE '%%tls%%'
               THEN 'https'
             WHEN p.port IN (443, 8443, 4443, 9443) THEN 'https'
             ELSE 'http'
           END AS scheme
    FROM ports p
    JOIN assets a ON a.id = p.asset_id
    WHERE p.port = ANY(%s) AND COALESCE(p.is_open, true)
          AND NOT (a.ip << '127.0.0.0/8'::inet)
    ORDER BY ip, p.port;
    """
    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(q, (SCHEME_HINT, SCHEME_HINT, WEB_PORTS))
        return cur.fetchall()

def ensure_zap_ready(timeout=60):
    import socket, time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((ZAP_ADDR, ZAP_PORT), timeout=1)
            s.close(); return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f"ZAP not reachable at {ZAP_ADDR}:{ZAP_PORT}")

def gobuster_dir(url: str, wordlist: Optional[str] = None, timeout_sec=600):
    """Run gobuster directory brute force on target URL

    Args:
        url: Target URL to scan
        wordlist: Wordlist name (small, medium, big, common, raft-small, raft-medium,
                  raft-large, quickhits, api) or full path to custom wordlist file
        timeout_sec: Timeout in seconds
    """
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL scheme: {url}")

    # Extract and validate host from URL
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    try:
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise ValueError(f"Invalid target in URL: {e}")

    # Resolve wordlist path
    ALLOWED_WORDLIST_BASE = "/opt/seclists"

    if wordlist:
        if wordlist in WORDLISTS:
            wordlist_path = WORDLISTS[wordlist]
        elif wordlist.startswith('/'):
            # Resolve to absolute path and check for path traversal
            resolved_path = str(pathlib.Path(wordlist).resolve())
            if not resolved_path.startswith(ALLOWED_WORDLIST_BASE):
                raise ValueError(f"Custom wordlists must be under {ALLOWED_WORDLIST_BASE}. Got: {resolved_path}")
            wordlist_path = resolved_path
        else:
            raise ValueError(f"Invalid wordlist: {wordlist}. Use one of: {', '.join(WORDLISTS.keys())} or a full path under {ALLOWED_WORDLIST_BASE}")
    else:
        wordlist_path = WORDLIST  # Default from env

    if not pathlib.Path(wordlist_path).exists():
        raise RuntimeError(f"wordlist not found: {wordlist_path}")

    logger.info(f"[gobuster] Using wordlist: {wordlist_path}")
    cmd = ["gobuster","dir","-u",url,"-w",wordlist_path,"-q","-t","50","-k",
           "-x","php,html,txt","-s","200,301,302,403","-b",""]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate(timeout=timeout_sec)
    if proc.returncode not in (0,1):
        raise RuntimeError(f"gobuster exit {proc.returncode}: {err or out}")
    # Strip ANSI escape codes from output
    out = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', out)
    items = []
    for line in out.splitlines():
        m = re.match(r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d+)\).*?(?:Size:\s*(?P<size>\d+))?", line.strip())
        if m:
            items.append((m.group('path'), int(m.group('status')), int(m.group('size') or 0)))
    with conn() as c, c.cursor() as cur:
        for path, status, size in items:
            cur.execute("""
              INSERT INTO web_findings (id, asset_id, url, source, issue_type, name, severity, evidence, status_code, first_seen, last_seen)
              VALUES (gen_random_uuid(), NULL, %s, 'gobuster','dir', %s, NULL, %s, %s, now(), now())
            """, (url, path, f"size={size}", status))
        c.commit()
    return len(items)


def gobuster_dir_with_paths(url: str, wordlist: Optional[str] = None, timeout_sec=600,
                            progress_callback=None, proxy: Optional[str] = None) -> Dict[str, Any]:
    """Run gobuster directory brute force and return discovered paths for pipeline use.

    This is a variant of gobuster_dir that returns structured path data for
    use in the sequential scan pipeline.

    Args:
        url: Target URL to scan
        wordlist: Wordlist name or full path to custom wordlist file
        timeout_sec: Timeout in seconds
        progress_callback: Optional fn(pct: int, eta_sec: int|None) called every ~90s

    Returns:
        Dict with 'paths' list of {path, status_code, size} and 'findings_saved' count
    """
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL scheme: {url}")

    # Extract and validate host from URL
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    try:
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise ValueError(f"Invalid target in URL: {e}")

    # Resolve wordlist path
    ALLOWED_WORDLIST_BASE = "/opt/seclists"

    if wordlist:
        if wordlist in WORDLISTS:
            wordlist_path = WORDLISTS[wordlist]
        elif wordlist.startswith('/'):
            resolved_path = str(pathlib.Path(wordlist).resolve())
            if not resolved_path.startswith(ALLOWED_WORDLIST_BASE):
                raise ValueError(f"Custom wordlists must be under {ALLOWED_WORDLIST_BASE}. Got: {resolved_path}")
            wordlist_path = resolved_path
        else:
            raise ValueError(f"Invalid wordlist: {wordlist}. Use one of: {', '.join(WORDLISTS.keys())} or a full path under {ALLOWED_WORDLIST_BASE}")
    else:
        wordlist_path = WORDLIST  # Default from env

    if not pathlib.Path(wordlist_path).exists():
        raise RuntimeError(f"wordlist not found: {wordlist_path}")

    logger.info(f"[gobuster] Using wordlist: {wordlist_path}")
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist_path, "-t", "50", "-k",
           "-x", "php,html,txt", "-s", "200,301,302,403", "-b", ""]
    if proxy:
        cmd.extend(["--proxy", proxy])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Read stdout/stderr in threads so we can parse progress from stderr
    stdout_lines = []
    def _read_stdout():
        for line in proc.stdout:
            stdout_lines.append(line)
    stderr_buf = []
    _last_progress_time = [time.time()]
    _gobuster_start = time.time()
    def _read_stderr():
        for line in proc.stderr:
            stderr_buf.append(line)
            if progress_callback:
                # Parse: "Progress: 1234 / 9876 (12.50%)"
                pm = re.search(r'Progress:\s*(\d+)\s*/\s*(\d+)\s*\((\d+(?:\.\d+)?)%\)', line)
                if pm and time.time() - _last_progress_time[0] >= 90:
                    _last_progress_time[0] = time.time()
                    done, total, pct = int(pm.group(1)), int(pm.group(2)), float(pm.group(3))
                    elapsed = time.time() - _gobuster_start
                    eta = int(elapsed / max(done, 1) * (total - done)) if done > 0 else None
                    progress_callback(int(pct), eta)

    t_out = threading.Thread(target=_read_stdout, daemon=True)
    t_err = threading.Thread(target=_read_stderr, daemon=True)
    t_out.start()
    t_err.start()
    proc.wait(timeout=timeout_sec)
    t_out.join(timeout=5)
    t_err.join(timeout=5)

    out = "".join(stdout_lines)
    err = "".join(stderr_buf)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"gobuster exit {proc.returncode}: {err or out}")

    # Strip ANSI escape codes from output
    out = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', out)
    paths = []
    for line in out.splitlines():
        m = re.match(r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d+)\).*?(?:Size:\s*(?P<size>\d+))?", line.strip())
        if m:
            paths.append({
                "path": m.group('path'),
                "status_code": int(m.group('status')),
                "size": int(m.group('size') or 0)
            })

    # Save to database
    with conn() as c, c.cursor() as cur:
        for p in paths:
            cur.execute("""
              INSERT INTO web_findings (id, asset_id, url, source, issue_type, name, severity, evidence, status_code, first_seen, last_seen)
              VALUES (gen_random_uuid(), NULL, %s, 'gobuster','dir', %s, NULL, %s, %s, now(), now())
            """, (url, p["path"], f"size={p['size']}", p["status_code"]))
        c.commit()

    return {
        "paths": paths,
        "findings_saved": len(paths)
    }


def nikto_scan(url: str, timeout_sec=1800, tuning: Optional[str] = None) -> Dict[str, Any]:
    """Run Nikto web server scanner and save findings to database.

    Args:
        url: Target URL to scan (e.g., http://example.com or https://example.com:8443)
        timeout_sec: Timeout in seconds (default: 1800 = 30 minutes)
        tuning: Nikto tuning options (e.g., '1' for interesting files, '2' for misconfig,
                '3' for info disclosure, '4' for injection, '6' for XSS, '9' for SQL injection,
                'x' for reverse tuning to skip tests. Examples: '123' or 'x6' to skip XSS)

    Returns:
        Number of findings saved to database

    Nikto scans for:
    - Outdated server versions and components
    - Server misconfigurations
    - Default/insecure files and programs
    - Common vulnerabilities (XSS, SQL injection indicators)
    - Security headers issues
    - SSL/TLS problems
    - Information disclosure
    """
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL scheme: {url}")

    # Extract and validate host from URL
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    try:
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise ValueError(f"Invalid target in URL: {e}")

    logger.info(f"[nikto] Starting scan on {url}")

    # Build Nikto command
    # -h: target host
    # -ssl: force SSL mode if https
    # -Format xml: output in XML for easier parsing
    # -o: output file
    # -Tuning: test tuning (optional)
    # -timeout: connection timeout (default 10s)
    output_file = REPORT_DIR / f"nikto_{int(time.time())}.xml"

    cmd = ["nikto", "-h", url, "-Format", "xml", "-o", str(output_file), "-timeout", "10"]

    # Add SSL flag if https
    if url.startswith('https://'):
        cmd.append("-ssl")

    # Add tuning if specified
    if tuning:
        cmd.extend(["-Tuning", tuning])

    logger.info(f"[nikto] Running command: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = proc.communicate(timeout=timeout_sec)

        # Nikto returns 0 on success
        if proc.returncode != 0:
            logger.warning(f"[nikto] Non-zero exit code {proc.returncode}: {err or out}")

    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError(f"Nikto scan timed out after {timeout_sec}s")

    # Parse XML output
    findings = []
    if output_file.exists():
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(output_file)
            root = tree.getroot()

            # Nikto XML structure:
            # <niktoscan>
            #   <scandetails targetip="..." targethostname="..." targetport="..." />
            #   <item>
            #     <description>Finding description</description>
            #     <uri>Path/URI</uri>
            #     <namelink>OSVDB-ID or reference</namelink>
            #     <iplink>IP address info</iplink>
            #   </item>
            # </niktoscan>

            for item in root.findall('.//item'):
                description_elem = item.find('description')
                uri_elem = item.find('uri')
                namelink_elem = item.find('namelink')
                method_elem = item.find('method')

                description = description_elem.text if description_elem is not None else "No description"
                uri = uri_elem.text if uri_elem is not None else "/"
                reference = namelink_elem.text if namelink_elem is not None else None
                method = method_elem.text if method_elem is not None else "GET"

                # Determine severity based on keywords in description
                severity = "info"
                desc_lower = description.lower()
                if any(kw in desc_lower for kw in ['vulnerability', 'vulnerable', 'exploit', 'injection', 'xss', 'sql']):
                    severity = "high"
                elif any(kw in desc_lower for kw in ['misconfiguration', 'outdated', 'insecure', 'weak', 'default']):
                    severity = "medium"
                elif any(kw in desc_lower for kw in ['disclosure', 'exposed', 'banner', 'version']):
                    severity = "low"

                findings.append({
                    'url': f"{url}{uri}" if uri.startswith('/') else f"{url}/{uri}",
                    'issue_type': 'nikto_finding',
                    'name': uri,
                    'severity': severity,
                    'evidence': description,
                    'reference': reference,
                    'method': method
                })

        except Exception as e:
            logger.error(f"[nikto] Failed to parse XML output: {e}")
            raise RuntimeError(f"Failed to parse Nikto output: {e}")
    else:
        logger.warning(f"[nikto] Output file not found: {output_file}")
        return {"count": 0, "output_file": str(output_file)}

    # Save findings to database
    with conn() as c, c.cursor() as cur:
        for finding in findings:
            cur.execute("""
                INSERT INTO web_findings (id, asset_id, url, source, issue_type, name, severity, evidence, first_seen, last_seen)
                VALUES (gen_random_uuid(), NULL, %s, 'nikto', %s, %s, %s, %s, now(), now())
            """, (
                finding['url'],
                finding['issue_type'],
                finding['name'],
                finding['severity'],
                finding['evidence']
            ))
        c.commit()

    logger.info(f"[nikto] Scan complete: {len(findings)} findings saved")

    # Emit webhook event
    emit_webhook_event(
        event_type="scan.completed",
        source="nikto",
        data={
            "url": url,
            "findings_count": len(findings),
            "high_severity": sum(1 for f in findings if f['severity'] == 'high'),
            "medium_severity": sum(1 for f in findings if f['severity'] == 'medium'),
            "low_severity": sum(1 for f in findings if f['severity'] == 'low')
        },
        severity="high" if any(f['severity'] == 'high' for f in findings) else "medium"
    )

    return {"count": len(findings), "output_file": str(output_file)}


def zap_scan(url: str, max_wait=900):
    """Run ZAP spider and active scan on target URL, then parse via ETL"""
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL scheme: {url}")

    # Extract and validate host from URL
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    try:
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise ValueError(f"Invalid target in URL: {e}")

    ensure_zap_ready()
    from zapv2 import ZAPv2
    proxies = {"http": f"http://{ZAP_ADDR}:{ZAP_PORT}", "https": f"http://{ZAP_ADDR}:{ZAP_PORT}"}
    zap = ZAPv2(apikey=ZAP_API_KEY, proxies=proxies)

    # Run spider
    logger.info(f"[ZAP] Starting spider on {url}")
    sid = zap.spider.scan(url)
    while int(zap.spider.status(sid)) < 100:
        time.sleep(3)  # Poll every 3s to reduce overhead
    logger.info(f"[ZAP] Spider complete on {url}")

    # Run active scan
    logger.info(f"[ZAP] Starting active scan on {url}")
    aid = zap.ascan.scan(url)
    waited = 0
    while int(zap.ascan.status(aid)) < 100 and waited < max_wait:
        time.sleep(10)  # Poll every 10s to reduce overhead
        waited += 10
        if waited % 60 == 0:
            progress = zap.ascan.status(aid)
            logger.info(f"[ZAP] Active scan progress: {progress}% ({waited}s elapsed)")

    logger.info(f"[ZAP] Active scan complete on {url}")

    # Use ETL to parse and ingest ZAP findings
    count = 0
    try:
        import sys
        sys.path.append("/scanner/etl")
        from etl.parse_zap import parse_zap_alerts
        stats = parse_zap_alerts(base_url=url, dedupe=True)
        count = stats.get("inserted", 0)
    except ImportError:
        logger.warning("[ZAP] ETL not available")

    # Fallback: if ETL inserted 0, try direct insertion via ZAP API
    if count == 0:
        try:
            alerts = zap.core.alerts(baseurl=url)
            if alerts:
                logger.warning(f"[ZAP] ETL returned 0 but {len(alerts)} raw alerts found — inserting directly")
                sev_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
                with conn() as c, c.cursor() as cur:
                    for a in alerts:
                        sev = sev_map.get(a.get("risk"))
                        if not sev:
                            continue
                        cur.execute("""
                          INSERT INTO web_findings (id, asset_id, url, source, issue_type, name, severity,
                            evidence, method, description, solution, reference, confidence, first_seen, last_seen)
                          VALUES (gen_random_uuid(), NULL, %s, 'zap', 'zap-alert', %s, %s, %s, %s, %s, %s, %s, %s, now(), now())
                          ON CONFLICT DO NOTHING
                        """, (a.get("url"), a.get("alert"), sev,
                              a.get("evidence") or a.get("param") or a.get("attack"),
                              a.get("method"), a.get("description"), a.get("solution"),
                              a.get("reference"), a.get("confidence")))
                    c.commit()
                count = len([a for a in alerts if sev_map.get(a.get("risk"))])
                logger.info(f"[ZAP] Direct insertion: {count} findings saved")
        except Exception as e:
            logger.error(f"[ZAP] Direct insertion fallback failed: {e}")

    return count


def zap_scan_with_urls(url: str, discovered_urls: Optional[List[str]] = None, max_wait=900,
                       progress_callback=None) -> Dict[str, Any]:
    """Run ZAP scan with pre-seeded URLs from Gobuster/Playwright.

    This variant accepts discovered URLs and seeds them into ZAP's site tree
    before running the spider and active scan, improving coverage.

    Args:
        url: Base URL for the scan
        discovered_urls: List of URLs discovered by Gobuster/Playwright to seed
        max_wait: Maximum wait time in seconds for active scan
        progress_callback: Optional fn(pct: int, eta_sec: int|None) called every ~90s

    Returns:
        Dict with 'count' (alerts inserted) and 'alerts' (raw alert details)
    """
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL scheme: {url}")

    # Extract and validate host from URL
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    try:
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise ValueError(f"Invalid target in URL: {e}")

    ensure_zap_ready()
    from zapv2 import ZAPv2
    proxies = {"http": f"http://{ZAP_ADDR}:{ZAP_PORT}", "https": f"http://{ZAP_ADDR}:{ZAP_PORT}"}
    zap = ZAPv2(apikey=ZAP_API_KEY, proxies=proxies)

    # Seed ZAP with discovered URLs to improve coverage
    if discovered_urls:
        logger.info(f"[ZAP] Seeding {len(discovered_urls)} discovered URLs into site tree")
        for disc_url in discovered_urls:
            try:
                # Access URL through ZAP to add it to the site tree
                zap.urlopen(disc_url)
                logger.debug(f"[ZAP] Seeded: {disc_url}")
            except Exception as e:
                logger.debug(f"[ZAP] Failed to seed {disc_url}: {e}")

    # Run spider
    logger.info(f"[ZAP] Starting spider on {url}")
    sid = zap.spider.scan(url)
    while int(zap.spider.status(sid)) < 100:
        time.sleep(3)  # Poll every 3s to reduce overhead
    logger.info(f"[ZAP] Spider complete on {url}")

    # Run active scan
    logger.info(f"[ZAP] Starting active scan on {url}")
    aid = zap.ascan.scan(url)
    waited = 0
    _last_cb_time = 0
    while int(zap.ascan.status(aid)) < 100 and waited < max_wait:
        time.sleep(10)  # Poll every 10s to reduce overhead
        waited += 10
        if waited % 60 == 0:
            pct = int(zap.ascan.status(aid))
            logger.info(f"[ZAP] Active scan progress: {pct}% ({waited}s elapsed)")
            if progress_callback and waited - _last_cb_time >= 90:
                _last_cb_time = waited
                eta = int(waited / max(pct, 1) * (100 - pct)) if pct > 0 else None
                progress_callback(pct, eta)

    logger.info(f"[ZAP] Active scan complete on {url}")

    # Fetch raw alerts via ZAP Python API (reliable, doesn't use HTTP requests)
    raw_alerts = []
    try:
        for a in zap.core.alerts(baseurl=url):
            raw_alerts.append({
                "alert": a.get("alert"),
                "risk": a.get("risk"),
                "confidence": a.get("confidence"),
                "url": a.get("url"),
                "method": a.get("method"),
                "param": a.get("param"),
                "attack": a.get("attack"),
                "evidence": (a.get("evidence") or "")[:500],
                "cweid": a.get("cweid"),
                "description": a.get("description"),
                "solution": a.get("solution"),
                "reference": a.get("reference"),
            })
    except Exception as e:
        logger.warning(f"[ZAP] Failed to fetch raw alerts: {e}")

    # Use ETL to parse and ingest ZAP findings
    count = 0
    try:
        import sys
        sys.path.append("/scanner/etl")
        from etl.parse_zap import parse_zap_alerts
        stats = parse_zap_alerts(base_url=url, dedupe=True)
        count = stats.get("inserted", 0)
    except ImportError:
        logger.warning("[ZAP] ETL not available, using direct insertion")

    # Fallback: if ETL inserted 0 but we have raw alerts, insert directly
    if count == 0 and raw_alerts:
        logger.warning(f"[ZAP] ETL returned 0 but {len(raw_alerts)} raw alerts found — inserting directly")
        sev_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
        with conn() as c, c.cursor() as cur:
            for a in raw_alerts:
                sev = sev_map.get(a.get("risk"))
                if not sev:
                    continue
                cur.execute("""
                  INSERT INTO web_findings (id, asset_id, url, source, issue_type, name, severity,
                    evidence, method, description, solution, reference, confidence, first_seen, last_seen)
                  VALUES (gen_random_uuid(), NULL, %s, 'zap', 'zap-alert', %s, %s, %s, %s, %s, %s, %s, %s, now(), now())
                  ON CONFLICT DO NOTHING
                """, (a.get("url"), a.get("alert"), sev,
                      a.get("evidence") or a.get("param") or a.get("attack"),
                      a.get("method"), a.get("description"), a.get("solution"),
                      a.get("reference"), a.get("confidence")))
            c.commit()
            count = len([a for a in raw_alerts if sev_map.get(a.get("risk"))])
        logger.info(f"[ZAP] Direct insertion: {count} findings saved")

    return {"count": count, "alerts": raw_alerts}


app = FastAPI(title="Web Scanner")

@app.on_event("startup")
async def startup_event():
    setup_log_capture()
    logging.info("[web-scanner] Service started, log capture initialized")

ALLOWED_WORDLIST_BASE = "/opt/seclists"

def validate_wordlist(wordlist: Optional[str]) -> Optional[str]:
    """Validate and resolve wordlist path. Returns resolved path or raises ValueError."""
    if not wordlist:
        return None

    if wordlist in WORDLISTS:
        return WORDLISTS[wordlist]

    if wordlist.startswith('/'):
        resolved_path = str(pathlib.Path(wordlist).resolve())
        if not resolved_path.startswith(ALLOWED_WORDLIST_BASE):
            raise ValueError(f"Custom wordlists must be under {ALLOWED_WORDLIST_BASE}. Got: {resolved_path}")
        if not pathlib.Path(resolved_path).exists():
            raise ValueError(f"Wordlist not found: {resolved_path}")
        return resolved_path

    raise ValueError(f"Invalid wordlist: {wordlist}. Use one of: {', '.join(WORDLISTS.keys())} or a full path under {ALLOWED_WORDLIST_BASE}")


class JobReq(BaseModel):
    target_url: Optional[str] = None  # Direct URL to scan (e.g., 'http://192.168.1.150' or 'http://192.168.1.150:8080')
    target_urls: Optional[List[str]] = None  # Multiple URLs to scan (overrides target_url)
    do_gobuster: bool = True
    do_playwright: bool = True
    do_katana: bool = True
    do_zap: bool = True
    limit: Optional[int] = None
    wordlist: Optional[str] = None  # small, medium, big, common, raft-small, raft-medium, raft-large, quickhits, api, or full path
    proxy: Optional[str] = None  # SOCKS proxy URL for scanning through remote nodes (e.g., 'socks5://host:port')


class PipelineReq(BaseModel):
    """Request model for sequential scan pipeline"""
    target_url: str  # Target URL (required, e.g., 'http://192.168.1.150')
    wordlist: Optional[str] = None  # Wordlist for Gobuster
    max_paths_to_visit: int = 50  # Max paths to visit with Playwright
    skip_gobuster: bool = False
    skip_playwright: bool = False
    skip_zap: bool = False
    skip_nuclei: bool = False
    skip_nikto: bool = False
    skip_katana: bool = False
    skip_wafw00f: bool = False


class NiktoReq(BaseModel):
    """Request model for Nikto scan"""
    target_url: str  # Target URL (required, e.g., 'http://192.168.1.150' or 'https://example.com')
    tuning: Optional[str] = None  # Nikto tuning options (e.g., '123' for tests 1,2,3 or 'x6' to skip XSS tests)
    timeout_sec: int = 1800  # Timeout in seconds (default 30 minutes)


def _run_web_scan_job(job_id: str, do_gobuster: bool, do_playwright: bool, do_katana: bool, do_zap: bool, limit: Optional[int], wordlist: Optional[str] = None, target_url: Optional[str] = None, target_urls: Optional[List[str]] = None, proxy: Optional[str] = None):
    """Background task to run web scan with progress tracking.

    When proxy is set (SOCKS URL), Gobuster gets --proxy flag and ZAP gets
    an upstream proxy configured via API before scanning.
    """
    try:
        _t0 = time.time()
        # Emit webhook for scan start
        emit_webhook_event("scan_started", "web-scanner", {
            "job_id": job_id,
            "scan_type": "web-scan",
            "target_url": target_url,
            "target_urls": target_urls,
            "do_gobuster": do_gobuster,
            "do_playwright": do_playwright,
            "do_katana": do_katana,
            "do_zap": do_zap,
            "wordlist": wordlist or "medium",
            "limit": limit
        })
        write_audit("scan_started", "web-scan", "web_scanner", {
            "job_id": job_id, "targets": [target_url] if target_url else (target_urls or []),
            "proxy": proxy, "execution_mode": "local",
        })

        logger.info(f"[{job_id[:8]}] Starting web scan job (gobuster={do_gobuster}, playwright={do_playwright}, katana={do_katana}, zap={do_zap}, wordlist={wordlist or 'default'}, target_url={target_url}, target_urls={target_urls}, proxy={proxy})")
        _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="fetching_targets")

        # Configure SOCKS proxy for sub-tools if set
        if proxy:
            logger.info(f"[{job_id[:8]}] Using proxy: {proxy}")
            # Set ALL_PROXY env for gobuster/katana/curl-based tools
            os.environ["ALL_PROXY"] = proxy
            os.environ["all_proxy"] = proxy
            # Configure ZAP upstream proxy via API
            try:
                import urllib.parse as _urlparse
                _pp = _urlparse.urlparse(proxy)
                _proxy_host = _pp.hostname or ""
                _proxy_port = str(_pp.port or 1080)
                import requests as _req
                _zap_base = f"http://{ZAP_ADDR}:{ZAP_PORT}"
                _req.get(f"{_zap_base}/JSON/network/action/setConnectionTimeout/", params={"apikey": ZAP_API_KEY, "timeout": "120"}, timeout=5)
                _req.get(f"{_zap_base}/JSON/network/action/setSocksProxy/", params={
                    "apikey": ZAP_API_KEY, "host": _proxy_host, "port": _proxy_port,
                    "version": "5", "useDns": "true"
                }, timeout=5)
                _req.get(f"{_zap_base}/JSON/network/action/setUseSocksProxy/", params={"apikey": ZAP_API_KEY, "useSocksProxy": "true"}, timeout=5)
                logger.info(f"[{job_id[:8]}] ZAP upstream SOCKS proxy configured: {_proxy_host}:{_proxy_port}")
            except Exception as _ze:
                logger.warning(f"[{job_id[:8]}] Could not configure ZAP proxy: {_ze}")

        # Merge target sources: target_urls > target_url > DB fallback
        urls_to_scan = target_urls or ([target_url] if target_url else None)

        if urls_to_scan:
            from urllib.parse import urlparse
            targets = []
            for u in urls_to_scan:
                # Auto-prepend scheme if the user entered a bare IP/hostname
                if not u.startswith(('http://', 'https://')):
                    u = f"http://{u}"
                parsed = urlparse(u)
                scheme = parsed.scheme or 'http'
                host = parsed.hostname or parsed.netloc
                port = parsed.port or (443 if scheme == 'https' else 80)
                if not host:
                    logger.warning(f"[{job_id[:8]}] Skipping unparseable target URL: {u}")
                    continue
                targets.append({'ip': host, 'port': port, 'scheme': scheme})
            logger.info(f"[{job_id[:8]}] Using {len(targets)} direct target(s)")
        else:
            logger.warning(f"[{job_id[:8]}] No target_url/target_urls provided, falling back to DB targets")
            targets = get_web_targets()
            if limit:
                targets = targets[:max(1, int(limit))]

        logger.info(f"[{job_id[:8]}] Found {len(targets)} web targets to scan")
        _job_tracker.update_progress(job_id, stage="scanning", targets_total=len(targets))

        stats = {"targets": 0, "gobuster_paths": 0, "playwright_urls": 0, "katana_urls": 0, "zap_alerts": 0, "errors": 0, "skipped": 0}
        target_results = []  # Per-target findings for session output

        for idx, t in enumerate(targets):
            try:
                ip = t['ip']
                port = t['port']
                scheme = t['scheme']

                # Validate IP address
                try:
                    validated_ip = validate_scan_target(ip, allow_private=True)
                except ValidationError as e:
                    logger.warning(f"[{job_id[:8]}] Skipping invalid IP {ip}: {e}")
                    stats["skipped"] += 1
                    _job_tracker.update_progress(job_id, targets_completed=idx + 1)
                    continue

                # Validate port
                try:
                    validated_port = sanitize_port(port)
                except ValidationError as e:
                    logger.warning(f"[{job_id[:8]}] Skipping invalid port {port}: {e}")
                    stats["skipped"] += 1
                    _job_tracker.update_progress(job_id, targets_completed=idx + 1)
                    continue

                # Validate scheme
                if scheme not in ('http', 'https'):
                    logger.warning(f"[{job_id[:8]}] Skipping invalid scheme {scheme}")
                    stats["skipped"] += 1
                    _job_tracker.update_progress(job_id, targets_completed=idx + 1)
                    continue

                # Construct URL with validated components
                url = f"{scheme}://{validated_ip}:{validated_port}"
                _job_tracker.update_progress(job_id, current_target=url)
                logger.info(f"[{job_id[:8]}] Scanning target: {url}")

                target_data = {"url": url, "gobuster_paths": [], "playwright_urls": 0, "katana_urls": 0, "zap_alerts": []}

                def _update_scan_progress(stage_name):
                    """Return a progress callback that updates the job tracker."""
                    def _cb(pct, eta_sec):
                        eta_str = f", ~{eta_sec // 60}m{eta_sec % 60:02d}s left" if eta_sec else ""
                        _job_tracker.update_progress(job_id, stage=stage_name,
                                                     detail=f"{pct}% complete{eta_str}")
                    return _cb

                # Run scans — feed gobuster-discovered paths into ZAP
                discovered_urls = []
                if do_gobuster:
                    _job_tracker.update_progress(job_id, stage="gobuster")
                    logger.info(f"[{job_id[:8]}] Running gobuster on {url}")
                    result = gobuster_dir_with_paths(url, wordlist=wordlist,
                                                     progress_callback=_update_scan_progress("gobuster"))
                    paths_found = result["findings_saved"]
                    stats["gobuster_paths"] += paths_found
                    target_data["gobuster_paths"] = result["paths"]
                    logger.info(f"[{job_id[:8]}] Gobuster found {paths_found} paths on {url}")
                    # Build full URLs from discovered paths for downstream stages
                    for p in result["paths"]:
                        path = p.get("path", "")
                        if path:
                            if not path.startswith("/"):
                                path = "/" + path
                            discovered_urls.append(f"{url.rstrip('/')}{path}")
                if do_playwright:
                    _job_tracker.update_progress(job_id, stage="playwright")
                    pw_urls = [url] + discovered_urls[:49]
                    logger.info(f"[{job_id[:8]}] Running Playwright on {url} ({len(pw_urls)} URLs)")
                    try:
                        import requests as _req
                        pw_visited = 0
                        for pw_url in pw_urls:
                            try:
                                resp = _req.post(
                                    f"{PLAYWRIGHT_URL}/scan",
                                    json={
                                        "url": pw_url,
                                        "use_zap_proxy": True,
                                        "capture_screenshots": True,
                                        "run_security_checks": True,
                                        "zap_spider": False,
                                        "zap_active_scan": False,
                                    },
                                    timeout=60,
                                )
                                if resp.status_code == 200:
                                    pw_visited += 1
                            except Exception as e:
                                logger.debug(f"[{job_id[:8]}] Playwright error for {pw_url}: {e}")
                        stats["playwright_urls"] += pw_visited
                        target_data["playwright_urls"] = pw_visited
                        logger.info(f"[{job_id[:8]}] Playwright visited {pw_visited} URLs on {url}")
                        # Check if playwright found any security issues
                        try:
                            with conn() as _c, _c.cursor() as _cur:
                                _cur.execute("SELECT count(*) FROM playwright_findings WHERE url LIKE %s AND created_at > now() - interval '1 hour'", (f"%{ip}%",))
                                pw_finding_count = _cur.fetchone()[0]
                            if pw_finding_count == 0:
                                _insert_info_finding("playwright", url, "Playwright scan completed — no vulnerabilities found",
                                    f"Scanned {pw_visited} URLs with browser-based security checks. No XSS, form injection, cookie, or DOM-based issues detected.")
                        except Exception:
                            pass
                    except Exception as e:
                        logger.warning(f"[{job_id[:8]}] Playwright stage failed: {e}")
                if do_katana:
                    _job_tracker.update_progress(job_id, stage="katana")
                    katana_targets = list(set([url] + discovered_urls))
                    logger.info(f"[{job_id[:8]}] Running Katana on {url} ({len(katana_targets)} seed URLs)")
                    try:
                        import requests as _req
                        resp = _req.post(
                            f"{PD_RUNNER_URL}/jobs/katana",
                            json={"targets": katana_targets, "depth": 3, "js_crawl": True},
                            timeout=30,
                        )
                        if resp.status_code == 200:
                            katana_jid = resp.json().get("job_id")
                            if katana_jid:
                                deadline = time.time() + 600
                                while time.time() < deadline:
                                    sr = _req.get(f"{PD_RUNNER_URL}/jobs/{katana_jid}", timeout=10)
                                    if sr.status_code == 200 and sr.json().get("status") in ("completed", "failed"):
                                        new_urls = []
                                        for line in (sr.json().get("output", "") or "").splitlines():
                                            line = line.strip()
                                            if line.startswith(("http://", "https://")) and line not in discovered_urls:
                                                new_urls.append(line)
                                        discovered_urls.extend(new_urls)
                                        stats["katana_urls"] += len(new_urls)
                                        target_data["katana_urls"] = len(new_urls)
                                        logger.info(f"[{job_id[:8]}] Katana discovered {len(new_urls)} new URLs on {url}")
                                        break
                                    time.sleep(10)
                    except Exception as e:
                        logger.warning(f"[{job_id[:8]}] Katana stage failed: {e}")
                if do_zap:
                    _job_tracker.update_progress(job_id, stage="zap")
                    logger.info(f"[{job_id[:8]}] Running ZAP scan on {url} (seeding {len(discovered_urls)} discovered URLs)")
                    zap_result = zap_scan_with_urls(url, discovered_urls=discovered_urls or None,
                                                    progress_callback=_update_scan_progress("zap"))
                    stats["zap_alerts"] += zap_result["count"]
                    target_data["zap_alerts"] = zap_result["alerts"]
                    logger.info(f"[{job_id[:8]}] ZAP found {zap_result['count']} alerts on {url}")
                stats["targets"] += 1
                target_results.append(target_data)

            except Exception as e:
                stats["errors"] += 1
                logger.error(f"[{job_id[:8]}] Error scanning {url if 'url' in locals() else t}: {type(e).__name__}: {e}")

            _job_tracker.update_progress(job_id, targets_completed=idx + 1)
            _job_tracker.update_job(job_id, stats=stats)

        _job_tracker.update_progress(job_id, stage="done", current_target=None)
        _job_tracker.update_job(
            job_id,
            status="completed",
            stats=stats,
            completed_at=datetime.now().isoformat()
        )
        logger.info(f"[{job_id[:8]}] Web scan completed: {stats['targets']} targets, {stats['gobuster_paths']} paths, {stats['zap_alerts']} alerts, {stats['errors']} errors")

        # Save session results — per-stage raw outputs + summary
        session_files = []
        jid8 = job_id[:8]

        # Per-target raw outputs
        for tr in target_results:
            target_tag = tr["url"].replace("://", "_").replace("/", "_").replace(":", "_")
            if tr.get("gobuster_paths"):
                f = REPORT_DIR / f"gobuster_{target_tag}_{jid8}.json"
                f.write_text(json.dumps(tr["gobuster_paths"], indent=2))
                session_files.append(str(f))
            if tr.get("zap_alerts"):
                f = REPORT_DIR / f"zap_alerts_{target_tag}_{jid8}.json"
                f.write_text(json.dumps(tr["zap_alerts"], indent=2))
                session_files.append(str(f))

        # Summary (without duplicating raw alert data)
        summary_targets = []
        for tr in target_results:
            summary_targets.append({
                "url": tr["url"],
                "gobuster_paths_count": len(tr.get("gobuster_paths", [])),
                "playwright_urls": tr.get("playwright_urls", 0),
                "katana_urls": tr.get("katana_urls", 0),
                "zap_alerts_count": len(tr.get("zap_alerts", [])),
            })
        results_file = REPORT_DIR / f"web_scan_results_{jid8}.json"
        results_file.write_text(json.dumps({
            "job_id": job_id,
            "stats": stats,
            "targets": summary_targets,
            "completed_at": datetime.now().isoformat(),
        }, indent=2))
        session_files.append(str(results_file))
        _save_session_results(job_id, "web-scan", "web-scanner", session_files, metadata=stats)

        # Emit webhook for scan completion
        emit_webhook_event("scan_completed", "web-scanner", {
            "job_id": job_id,
            "targets_count": stats["targets"],
            "gobuster_paths": stats["gobuster_paths"],
            "zap_alerts": stats["zap_alerts"],
            "errors": stats["errors"]
        })
        write_audit("scan_completed", "web-scan", "web_scanner", {
            "job_id": job_id, "duration_s": round(time.time() - _t0, 2),
            "findings_count": stats.get("gobuster_paths", 0) + stats.get("zap_alerts", 0),
        })

    except Exception as e:
        logger.error(f"[{job_id[:8]}] Web scan failed: {type(e).__name__}: {e}")
        _job_tracker.update_job(
            job_id,
            status="failed",
            error=str(e),
            completed_at=datetime.now().isoformat()
        )
        _job_tracker.update_progress(job_id, stage="failed")

        # Emit webhook for scan failure
        emit_webhook_event("scan_failed", "web-scanner", {
            "job_id": job_id,
            "error": str(e)
        })
        write_audit("scan_failed", "web-scan", "web_scanner", {
            "job_id": job_id, "error": str(e),
        })


@app.get("/health")
def health():
    try:
        with conn() as c, c.cursor() as cur: cur.execute("SELECT 1")
        return {"ok": True, "version": os.environ.get("BUILD_VERSION", "dev")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/reports/zap-xml")
def get_latest_zap_xml():
    """Return the most recent ZAP XML report file for download."""
    import glob as _glob
    files = sorted(
        _glob.glob(str(REPORT_DIR / "zap_report_*.xml")),
        key=os.path.getmtime,
        reverse=True,
    )
    if not files:
        raise HTTPException(404, "No ZAP XML reports found")
    return FileResponse(
        files[0],
        media_type="application/xml",
        filename=os.path.basename(files[0]),
    )


@app.get("/wordlists")
def list_wordlists():
    """List available wordlists for gobuster scans"""
    available = []
    for name, path in WORDLISTS.items():
        exists = pathlib.Path(path).exists()
        size = pathlib.Path(path).stat().st_size if exists else 0
        available.append({
            "name": name,
            "path": path,
            "exists": exists,
            "size_kb": round(size / 1024, 1) if exists else 0
        })
    return {
        "wordlists": available,
        "default": WORDLIST,
        "usage": "Pass wordlist name (e.g., 'small', 'big') or full path in the 'wordlist' field"
    }


@app.get("/jobs/{job_id}")
def get_job_status(job_id: str):
    """Get the status of a web scan job"""
    job = _job_tracker.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.post("/jobs/{job_id}/stop")
def stop_job(job_id: str):
    """Stop a running web scan job"""
    job = _job_tracker.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job["status"] not in ["queued", "running"]:
        raise HTTPException(status_code=400, detail=f"Job is already {job['status']}, cannot stop")

    # Update job status to stopped
    _job_tracker.update_job(job_id, status="stopped", completed_at=datetime.now().isoformat())
    _job_tracker.update_progress(job_id, stage="user_stopped")

    # Emit webhook for scan stop
    emit_webhook_event("scan_stopped", "web-scanner", {
        "job_id": job_id,
        "scan_type": "web-scan",
        "stopped_by": "user",
        "previous_status": job["status"],
        "progress": job.get("progress", {}),
        "stats": job.get("stats", {})
    })

    logger.info(f"[{job_id[:8]}] Web scan stopped by user request")
    return {"ok": True, "job_id": job_id, "status": "stopped", "message": "Scan stop requested"}


@app.get("/jobs")
def list_jobs(status: Optional[str] = None, limit: int = 50):
    """List all web scan jobs"""
    return {"jobs": _job_tracker.list_jobs(status=status, limit=limit)}


@app.post("/jobs/web-scan")
def run_web_scan(req: JobReq, background_tasks: BackgroundTasks):
    """Start a web vulnerability scan job (returns immediately with job_id)

    Wordlist options: small, medium (default), big, common, raft-small, raft-medium, raft-large, quickhits, api
    Or provide a full path to a custom wordlist file under /opt/seclists.
    """
    # Validate wordlist upfront
    try:
        validated_wordlist = validate_wordlist(req.wordlist)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    job_id = _job_tracker.create_job(job_type="web-scan")
    background_tasks.add_task(_run_web_scan_job, job_id, req.do_gobuster, req.do_playwright, req.do_katana, req.do_zap, req.limit, req.wordlist, req.target_url, req.target_urls, req.proxy)
    return {
        "ok": True,
        "job_id": job_id,
        "status": "queued",
        "target_url": req.target_url,
        "target_urls": req.target_urls,
        "wordlist": req.wordlist or "medium (default)",
        "status_url": f"/jobs/{job_id}"
    }


@app.post("/jobs/web-scan/sync")
def run_web_scan_sync(req: JobReq):
    """Run web vulnerability scans synchronously (blocking, returns when done)

    Wordlist options: small, medium (default), big, common, raft-small, raft-medium, raft-large, quickhits, api
    Or provide a full path to a custom wordlist file under /opt/seclists.
    """
    # Validate wordlist upfront
    try:
        validated_wordlist = validate_wordlist(req.wordlist)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    urls_to_scan = req.target_urls or ([req.target_url] if req.target_url else None)
    if urls_to_scan:
        from urllib.parse import urlparse
        targets = []
        for u in urls_to_scan:
            if not u.startswith(('http://', 'https://')):
                u = f"http://{u}"
            parsed = urlparse(u)
            scheme = parsed.scheme or 'http'
            host = parsed.hostname or parsed.netloc
            port = parsed.port or (443 if scheme == 'https' else 80)
            if host:
                targets.append({'ip': host, 'port': port, 'scheme': scheme})
        logger.info(f"[sync] Using {len(targets)} direct target(s)")
    else:
        targets = get_web_targets()
        if req.limit: targets = targets[:max(1,int(req.limit))]
    stats = {"targets": 0, "gobuster_paths": 0, "zap_alerts": 0, "errors": 0, "skipped": 0, "wordlist": req.wordlist or "medium (default)"}

    for t in targets:
        try:
            ip = t['ip']
            port = t['port']
            scheme = t['scheme']

            try:
                validated_ip = validate_scan_target(ip, allow_private=True)
            except ValidationError as e:
                logger.warning(f"[sync] Skipping invalid IP {ip}: {e}")
                stats["skipped"] += 1
                continue

            try:
                validated_port = sanitize_port(port)
            except ValidationError as e:
                logger.warning(f"[sync] Skipping invalid port {port}: {e}")
                stats["skipped"] += 1
                continue

            if scheme not in ('http', 'https'):
                logger.warning(f"[sync] Skipping invalid scheme {scheme}")
                stats["skipped"] += 1
                continue

            url = f"{scheme}://{validated_ip}:{validated_port}"
            logger.info(f"[sync] Scanning target: {url}")

            if req.do_gobuster:
                logger.info(f"[sync] Running gobuster on {url} with wordlist={req.wordlist or 'default'}")
                paths_found = gobuster_dir(url, wordlist=req.wordlist)
                stats["gobuster_paths"] += paths_found
                logger.info(f"[sync] Gobuster found {paths_found} paths")
            if req.do_zap:
                logger.info(f"[sync] Running ZAP scan on {url}")
                alerts_found = zap_scan(url)
                stats["zap_alerts"] += alerts_found
                logger.info(f"[sync] ZAP found {alerts_found} alerts")
            stats["targets"] += 1

        except Exception as e:
            stats["errors"] += 1
            logger.error(f"[sync] Error: {url if 'url' in locals() else t}: {type(e).__name__}: {e}")

    return {"ok": True, "stats": stats}


# ===============================
# Nikto Scan Endpoints
# ===============================

def _run_nikto_scan_job(job_id: str, target_url: str, tuning: Optional[str], timeout_sec: int):
    """Background task to run Nikto scan with progress tracking"""
    try:
        logger.info(f"[{job_id[:8]}] Starting Nikto scan on {target_url}")
        _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="nikto", current_target=target_url)

        # Emit webhook for scan start
        emit_webhook_event("scan_started", "nikto", {
            "job_id": job_id,
            "target_url": target_url,
            "tuning": tuning
        })

        # Run Nikto scan
        nikto_result = nikto_scan(url=target_url, timeout_sec=timeout_sec, tuning=tuning)
        findings_count = nikto_result["count"]

        stats = {
            "target_url": target_url,
            "findings_count": findings_count,
            "tuning": tuning or "default"
        }

        _job_tracker.update_progress(job_id, stage="done", current_target=None)
        _job_tracker.update_job(
            job_id,
            status="completed",
            stats=stats,
            completed_at=datetime.now().isoformat()
        )
        logger.info(f"[{job_id[:8]}] Nikto scan completed: {findings_count} findings")

        # Save session results
        session_files = []
        if nikto_result.get("output_file"):
            session_files.append(nikto_result["output_file"])
        _save_session_results(job_id, "nikto-scan", "nikto", session_files,
                              metadata={"target_url": target_url, "findings_count": findings_count})

        # Emit webhook for scan completion
        emit_webhook_event("scan_completed", "nikto", {
            "job_id": job_id,
            "target_url": target_url,
            "findings_count": findings_count
        })

    except Exception as e:
        logger.error(f"[{job_id[:8]}] Nikto scan failed: {type(e).__name__}: {e}")
        _job_tracker.update_job(
            job_id,
            status="failed",
            error=str(e),
            completed_at=datetime.now().isoformat()
        )
        _job_tracker.update_progress(job_id, stage="failed")

        # Emit webhook for scan failure
        emit_webhook_event("scan_failed", "nikto", {
            "job_id": job_id,
            "target_url": target_url,
            "error": str(e)
        })


class GobusterReq(BaseModel):
    """Request model for standalone Gobuster directory scan"""
    target_url: str  # Target URL (required)
    wordlist: Optional[str] = None  # small, medium, big, common, raft-small, etc.
    timeout_sec: int = 600  # Timeout per target in seconds


def _run_gobuster_job(job_id: str, target_url: str, wordlist: Optional[str], timeout_sec: int):
    """Background task for standalone gobuster scan."""
    try:
        _job_tracker.update_job(job_id, status="running", stage="gobuster")

        write_audit("scan_started", "gobuster", "web_scanner", {
            "job_id": job_id, "target_url": target_url,
            "parameters": {"wordlist": wordlist or "medium"},
            "execution_mode": "local",
        })

        validated_wordlist = validate_wordlist(wordlist) if wordlist else None
        result = gobuster_dir_with_paths(
            target_url,
            wordlist=validated_wordlist,
            timeout_sec=timeout_sec,
        )

        paths_count = result.get("findings_saved", 0)
        _job_tracker.update_job(
            job_id, status="completed", stage="done",
            result={"paths_found": paths_count, "url": target_url},
        )

        emit_webhook_event("scan_completed", "gobuster", {
            "job_id": job_id,
            "target_url": target_url,
            "paths_found": paths_count,
        })
        write_audit("scan_completed", "gobuster", "web_scanner", {
            "job_id": job_id, "target_url": target_url,
            "paths_found": paths_count,
        })

    except Exception as e:
        logger.exception(f"[{job_id[:8]}] Gobuster failed: {e}")
        _job_tracker.update_job(job_id, status="failed", error=str(e))
        emit_webhook_event("scan_failed", "gobuster", {
            "job_id": job_id, "target_url": target_url, "error": str(e),
        })


@app.post("/jobs/gobuster")
def run_gobuster_scan(req: GobusterReq, background_tasks: BackgroundTasks):
    """Start a standalone Gobuster directory brute-force scan.

    Discovers hidden directories and files on web servers using wordlist-based
    brute forcing. Findings are saved to the database automatically.

    Args:
        target_url: Full URL to scan (e.g., 'https://demo.testfire.net')
        wordlist: Wordlist name (small, medium, big, common, raft-small, etc.) or full path
        timeout_sec: Scan timeout in seconds (default: 600)

    Returns:
        job_id for polling status via GET /jobs/{job_id}
    """
    if req.target_url and not req.target_url.startswith(('http://', 'https://')):
        req.target_url = f"https://{req.target_url}"

    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(req.target_url)
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {e}")

    if req.wordlist:
        try:
            validate_wordlist(req.wordlist)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    job_id = _job_tracker.create_job(job_type="gobuster")
    background_tasks.add_task(
        _run_gobuster_job, job_id, req.target_url, req.wordlist, req.timeout_sec,
    )
    return {
        "ok": True,
        "job_id": job_id,
        "status": "queued",
        "target_url": req.target_url,
        "wordlist": req.wordlist or "medium (default)",
        "timeout_sec": req.timeout_sec,
        "status_url": f"/jobs/{job_id}",
    }


class ContentReconReq(BaseModel):
    """Request model for content recon pipeline (Spider → Gobuster → Playwright → PDF → Wordlist → Screenshots → ZAP)"""
    target_url: str
    wordlist: Optional[str] = None
    max_playwright_urls: int = 50
    zap_checkpoint: bool = True
    skip_gobuster: bool = True
    include_spider: bool = False
    spider_depth: int = 3
    extract_pdfs: bool = False
    generate_wordlist: bool = False
    include_screenshots: bool = True
    extract_exif: bool = False
    proxy: Optional[str] = None
    screenshot_all: bool = False


def _run_content_recon(job_id: str, target_url: str, wordlist: Optional[str],
                       max_pw_urls: int, zap_checkpoint: bool,
                       skip_gobuster: bool = False, include_spider: bool = False,
                       spider_depth: int = 3, extract_pdfs: bool = False,
                       generate_wordlist: bool = False, include_screenshots: bool = True,
                       extract_exif: bool = False, proxy: Optional[str] = None,
                       screenshot_all: bool = False):
    """Background: Spider → Gobuster → Playwright → PDF extract → Wordlist → Screenshots → ZAP checkpoint."""
    import requests as _req

    try:
        _job_tracker.update_job(job_id, status="running", stage="starting")
        exec_mode = "proxied" if proxy else "local"
        write_audit("scan_started", "content-recon", "web_scanner", {
            "job_id": job_id, "target_url": target_url, "execution_mode": exec_mode,
            "proxy": proxy or "none",
        })

        discovered_urls = []
        all_page_text = []  # Collected text for wordlist generation
        pdf_texts = []      # Extracted PDF content
        stats = {"gobuster_paths": 0, "playwright_scans": 0, "zap_seeded": 0,
                 "content_extractions": 0, "params_found": 0, "content_intel": {},
                 "gobuster_skipped": skip_gobuster, "spider_urls": 0,
                 "pdfs_extracted": 0, "wordlist_size": 0, "screenshots": 0,
                 "exif_extracted": 0}

        # ── Stage 0: Katana spider (optional) ──
        if include_spider:
            _job_tracker.update_job(job_id, status="running", stage="katana-spider")
            katana_cmd = f"katana -u {target_url} -d {spider_depth} -js-crawl -xhr-extraction -form-extraction -jsonl -silent"
            if proxy:
                katana_cmd += f" -proxy {proxy}"
            _job_tracker.push_command(job_id, "katana-spider", katana_cmd)
            logger.info(f"[{job_id[:8]}] Stage 0: Katana spider (depth={spider_depth}) on {target_url}")
            try:
                katana_payload = {
                    "targets": [target_url], "depth": spider_depth,
                    "xhr_extraction": True, "form_extraction": True,
                    "known_files": "all",
                }
                if proxy:
                    katana_payload["proxy"] = proxy
                katana_resp = _req.post(
                    f"{PD_RUNNER_URL}/jobs/katana",
                    json=katana_payload,
                    headers={"x-api-key": API_KEY},
                    timeout=30,
                )
                if katana_resp.status_code == 200:
                    katana_data = katana_resp.json()
                    katana_job_id = katana_data.get("job_id")
                    if katana_job_id:
                        import time as _time_k
                        deadline_k = _time_k.time() + 300  # 5 min max
                        while _time_k.time() < deadline_k:
                            kr = _req.get(f"{PD_RUNNER_URL}/jobs/{katana_job_id}",
                                          headers={"x-api-key": API_KEY}, timeout=10)
                            if kr.status_code == 200:
                                kd = kr.json()
                                if kd.get("status") in ("completed", "failed"):
                                    katana_result = kd.get("result", {})
                                    # Try to read URLs from the raw output via pd_runner (stream to avoid loading huge files)
                                    report_path = katana_result.get("report", "")
                                    if report_path:
                                        try:
                                            raw_resp = _req.get(
                                                f"{PD_RUNNER_URL}/reports/{report_path.split('/')[-1]}",
                                                headers={"x-api-key": API_KEY}, timeout=60, stream=True)
                                            if raw_resp.status_code == 200:
                                                line_count = 0
                                                for line in raw_resp.iter_lines(decode_unicode=True):
                                                    if line_count >= 500:
                                                        break
                                                    line_count += 1
                                                    if not line:
                                                        continue
                                                    try:
                                                        entry = json.loads(line)
                                                        req_url = entry.get("request", {}).get("endpoint", "")
                                                        if req_url.startswith(("http://", "https://")):
                                                            discovered_urls.append(req_url)
                                                    except (json.JSONDecodeError, AttributeError):
                                                        if line.startswith(("http://", "https://")):
                                                            discovered_urls.append(line.strip())
                                                raw_resp.close()
                                                logger.info(f"[{job_id[:8]}] Read {line_count} lines from katana report, got {len(discovered_urls)} URLs")
                                        except Exception as e:
                                            logger.warning(f"[{job_id[:8]}] Could not fetch katana report: {e}")
                                    # Dedupe
                                    discovered_urls = list(dict.fromkeys(discovered_urls))
                                    break
                            _time_k.sleep(3)
                    stats["spider_urls"] = len(discovered_urls)
                    logger.info(f"[{job_id[:8]}] Katana spider found {len(discovered_urls)} URLs")
                else:
                    logger.warning(f"[{job_id[:8]}] Katana returned {katana_resp.status_code}")
            except Exception as e:
                logger.warning(f"[{job_id[:8]}] Katana spider failed: {e}")
        else:
            logger.info(f"[{job_id[:8]}] Stage 0: Katana spider SKIPPED")

        # ── Stage 1: Gobuster directory discovery ──
        if skip_gobuster:
            logger.info(f"[{job_id[:8]}] Stage 1: Gobuster SKIPPED (skip_gobuster=true)")
            _job_tracker.update_job(job_id, status="running", stage="gobuster-skipped")
        else:
            _job_tracker.update_job(job_id, status="running", stage="gobuster")
            wl_name = wordlist or "medium"
            wl_path = WORDLISTS.get(wl_name, wl_name)
            gb_cmd = f"gobuster dir -u {target_url} -w {wl_path} -t 50 -k -x php,html,txt -s 200,301,302,403"
            if proxy:
                gb_cmd += f" --proxy {proxy}"
            _job_tracker.push_command(job_id, "gobuster", gb_cmd)
            logger.info(f"[{job_id[:8]}] Stage 1: Gobuster on {target_url}")
            try:
                validated_wl = validate_wordlist(wordlist) if wordlist else None
                gb_result = gobuster_dir_with_paths(target_url, wordlist=validated_wl, timeout_sec=600, proxy=proxy)
                for p in gb_result.get("paths", []):
                    path = p.get("path", "")
                    if path:
                        if not path.startswith("/"):
                            path = "/" + path
                        discovered_urls.append(f"{target_url.rstrip('/')}{path}")
                stats["gobuster_paths"] = len(discovered_urls)
                logger.info(f"[{job_id[:8]}] Gobuster found {len(discovered_urls)} paths")
            except Exception as e:
                logger.warning(f"[{job_id[:8]}] Gobuster failed: {e}")

        # ── Stage 2: Playwright with content capture on each URL ──
        _job_tracker.update_job(job_id, status="running", stage="playwright")
        pw_urls = [target_url] + discovered_urls[:max_pw_urls - 1]
        pw_urls = list(dict.fromkeys(pw_urls))  # dedupe preserving order
        _job_tracker.push_command(job_id, "playwright", f"# Playwright browser scan: {len(pw_urls)} URLs\n# DOM capture, content extraction, parameter discovery\ncurl -X POST https://playwright-scanner:8014/scan -d '{{\"url\": \"{target_url}\", \"capture_dom\": true, \"capture_screenshots\": true}}'")
        logger.info(f"[{job_id[:8]}] Stage 2: Playwright content scan")

        for i, pw_url in enumerate(pw_urls):
            logger.info(f"[{job_id[:8]}] Playwright [{i+1}/{len(pw_urls)}]: {pw_url}")
            try:
                resp = _req.post(
                    f"{PLAYWRIGHT_URL}/scan",
                    json={
                        "url": pw_url,
                        "capture_dom": True,
                        "capture_screenshots": True,
                        "run_security_checks": True,
                        "use_zap_proxy": zap_checkpoint,  # Route through ZAP for passive observation only
                        "zap_spider": False,               # Never run ZAP spider in content recon
                        "zap_active_scan": False,           # Never run ZAP active scan in content recon
                        "timeout": 30,
                    },
                    headers={"x-api-key": API_KEY},
                    timeout=90,
                )
                if resp.status_code == 200:
                    scan_data = resp.json()
                    pw_scan_id = scan_data.get("scan_id")
                    stats["playwright_scans"] += 1

                    # Wait for scan to complete (max 60s)
                    if pw_scan_id:
                        import time as _time
                        deadline = _time.time() + 60
                        while _time.time() < deadline:
                            sr = _req.get(f"{PLAYWRIGHT_URL}/scan/{pw_scan_id}",
                                          headers={"x-api-key": API_KEY}, timeout=10)
                            if sr.status_code == 200:
                                sd = sr.json()
                                if sd.get("status") in ("completed", "failed"):
                                    break
                            _time.sleep(3)

                else:
                    logger.warning(f"[{job_id[:8]}] Playwright returned {resp.status_code} for {pw_url}")
            except Exception as e:
                logger.warning(f"[{job_id[:8]}] Playwright failed for {pw_url}: {e}")

            _job_tracker.update_progress(job_id, targets_completed=i + 1,
                                         total_targets=len(pw_urls))

        # ── Stage 3: Gather content intel summary ──
        _job_tracker.update_job(job_id, status="running", stage="content-summary")
        try:
            ci_resp = _req.get(
                f"{API_BASE}/content-extractions/summary",
                headers={"x-api-key": API_KEY}, timeout=10,
            )
            if ci_resp.status_code == 200:
                ci_data = ci_resp.json()
                stats["content_intel"] = ci_data.get("summary", {})
                stats["content_extractions"] = ci_data.get("summary", {}).get("total_extractions", 0)
        except Exception:
            pass

        # Count discovered params
        try:
            with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM discovered_params WHERE discovery_source LIKE '%%playwright%%'")
                stats["params_found"] = cur.fetchone()["cnt"]
        except Exception:
            pass

        # ── Stage 4: PDF extraction (optional) ──
        if extract_pdfs:
            _job_tracker.update_job(job_id, status="running", stage="pdf-extraction")
            _job_tracker.push_command(job_id, "pdf-extraction", f"# Download PDFs from {target_url} and extract text\npython3 -c \"import pdfplumber; pdf=pdfplumber.open('file.pdf'); print(pdf.pages[0].extract_text())\"")
            logger.info(f"[{job_id[:8]}] Stage 4: Extracting PDF content")
            try:
                # Find PDF links from discovered URLs and content extractions
                pdf_links = [u for u in discovered_urls if u.lower().endswith(".pdf")]
                # Also query content_extractions for PDF links found by Playwright
                try:
                    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
                        # internal_paths is a JSONB array — unnest and filter for .pdf
                        cur.execute("""
                            SELECT DISTINCT path_val FROM (
                                SELECT jsonb_array_elements_text(internal_paths) AS path_val
                                FROM content_extractions
                                WHERE internal_paths IS NOT NULL
                                AND created_at > now() - interval '1 hour'
                            ) sub WHERE path_val LIKE '%%.pdf'
                            LIMIT 50
                        """)
                        for row in cur.fetchall():
                            pdf_val = row["path_val"]
                            if pdf_val.startswith(("http://", "https://")):
                                pdf_links.append(pdf_val)
                            elif pdf_val.startswith("/"):
                                from urllib.parse import urlparse as _up
                                p = _up(target_url)
                                pdf_links.append(f"{p.scheme}://{p.netloc}{pdf_val}")
                except Exception:
                    pass

                pdf_links = list(dict.fromkeys(pdf_links))[:20]  # Cap at 20 PDFs
                logger.info(f"[{job_id[:8]}] Found {len(pdf_links)} PDF links to extract")

                for pdf_url in pdf_links:
                    try:
                        pdf_resp = _req.get(pdf_url, timeout=30, stream=True,
                                            headers={"User-Agent": "Mozilla/5.0 (pentest-recon)"})
                        if pdf_resp.status_code == 200 and len(pdf_resp.content) < 50_000_000:  # 50MB cap
                            pdf_path = REPORT_DIR / f"pdf_{job_id[:8]}_{uuid.uuid4().hex[:6]}.pdf"
                            with open(pdf_path, "wb") as pf:
                                pf.write(pdf_resp.content)
                            try:
                                import pdfplumber
                                with pdfplumber.open(str(pdf_path)) as pdf:
                                    text_parts = []
                                    metadata = pdf.metadata or {}
                                    for page in pdf.pages[:100]:  # Cap pages
                                        page_text = page.extract_text()
                                        if page_text:
                                            text_parts.append(page_text)
                                    full_text = "\n".join(text_parts)
                                    if full_text.strip():
                                        pdf_texts.append(full_text)
                                        all_page_text.append(full_text)
                                        stats["pdfs_extracted"] += 1
                                        # Store PDF extraction as content_extraction
                                        with conn() as c, c.cursor() as cur:
                                            meta_obj = {k: str(v) for k, v in metadata.items() if v}
                                            meta_obj["type"] = "pdf_content"
                                            meta_obj["text_length"] = len(full_text)
                                            # Extract names from PDF metadata (Author, Creator)
                                            pdf_names = [metadata[k] for k in ("Author", "Creator", "Producer") if metadata.get(k)]
                                            cur.execute("""
                                                INSERT INTO content_extractions
                                                (id, url, file_metadata, names, word_corpus, metadata, created_at)
                                                VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, now())
                                            """, (pdf_url,
                                                  json.dumps(meta_obj),
                                                  json.dumps(pdf_names) if pdf_names else None,
                                                  full_text[:10000],
                                                  json.dumps({"source": "pdf_extraction", "job_id": job_id[:8]})))
                                            c.commit()
                                        # Also create an info finding for visibility in Findings Explorer
                                        pdf_evidence_parts = []
                                        for pk in ("Author", "Creator", "Producer", "Title", "Subject"):
                                            if metadata.get(pk):
                                                pdf_evidence_parts.append(f"{pk}: {metadata[pk]}")
                                        pdf_evidence_parts.append(f"{len(full_text)} chars extracted, {len(pdf.pages)} pages")
                                        pdf_finding_name = f"PDF metadata: {metadata.get('Author', metadata.get('Creator', 'unknown'))}" if metadata.get('Author') or metadata.get('Creator') else f"PDF content extracted ({len(pdf.pages)} pages)"
                                        with conn() as c2, c2.cursor() as cur2:
                                            cur2.execute("""
                                                INSERT INTO web_findings (id, url, source, issue_type, name, severity, evidence, first_seen, last_seen)
                                                VALUES (gen_random_uuid(), %s, 'pdf', 'metadata', %s, 'recon', %s, now(), now())
                                            """, (pdf_url, pdf_finding_name[:500], "; ".join(pdf_evidence_parts)[:2000]))
                                            c2.commit()
                                        logger.info(f"[{job_id[:8]}] Extracted {len(full_text)} chars from {pdf_url}")
                            except ImportError:
                                logger.warning(f"[{job_id[:8]}] pdfplumber not installed, skipping PDF extraction")
                            finally:
                                try:
                                    os.remove(pdf_path)
                                except OSError:
                                    pass
                    except Exception as e:
                        logger.warning(f"[{job_id[:8]}] PDF extraction failed for {pdf_url}: {e}")

            except Exception as e:
                logger.warning(f"[{job_id[:8]}] PDF extraction stage failed: {e}")
        else:
            logger.info(f"[{job_id[:8]}] Stage 4: PDF extraction SKIPPED")

        # ── Stage 5: Wordlist generation (optional) ──
        if generate_wordlist:
            _job_tracker.update_job(job_id, status="running", stage="wordlist-gen")
            _job_tracker.push_command(job_id, "wordlist-gen", f"cewl {target_url} -d 3 -m 3 -w wordlist_{job_id[:8]}.txt")
            logger.info(f"[{job_id[:8]}] Stage 5: Generating wordlist from crawled content")
            try:
                # Collect page text from content extractions (uses JSONB columns)
                try:
                    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute("""
                            SELECT internal_paths, tech_indicators, word_corpus, api_endpoints
                            FROM content_extractions
                            WHERE created_at > now() - interval '1 hour'
                            LIMIT 200
                        """)
                        for row in cur.fetchall():
                            for col in ("internal_paths", "tech_indicators", "api_endpoints"):
                                val = row.get(col)
                                if val and isinstance(val, list):
                                    all_page_text.extend([str(v) for v in val])
                                elif val and isinstance(val, str):
                                    all_page_text.append(val)
                            if row.get("word_corpus"):
                                all_page_text.append(str(row["word_corpus"])[:5000])
                except Exception:
                    pass

                # Also fetch DOM text from recent Playwright findings
                try:
                    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute("""
                            SELECT evidence FROM playwright_findings
                            WHERE created_at > now() - interval '1 hour'
                            LIMIT 100
                        """)
                        for row in cur.fetchall():
                            if row.get("evidence"):
                                all_page_text.append(row["evidence"][:2000])
                except Exception:
                    pass

                # Tokenize and build wordlist
                raw_text = " ".join(all_page_text)
                # Extract words: alphanumeric, min 3 chars, max 50
                words = set()
                for token in re.findall(r'[a-zA-Z][a-zA-Z0-9_-]{2,49}', raw_text):
                    words.add(token.lower())
                    # Also add CamelCase splits
                    parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)', token)
                    for part in parts:
                        if len(part) >= 3:
                            words.add(part.lower())

                # Add discovered paths as wordlist entries
                for url in discovered_urls:
                    from urllib.parse import urlparse as _up2
                    path = _up2(url).path
                    for segment in path.strip("/").split("/"):
                        cleaned = segment.split(".")[0]  # Remove extensions
                        if len(cleaned) >= 3:
                            words.add(cleaned.lower())

                # Sort and write
                sorted_words = sorted(words)
                wordlist_path = REPORT_DIR / f"wordlist_{job_id[:8]}.txt"
                with open(wordlist_path, "w") as wf:
                    wf.write("\n".join(sorted_words))

                stats["wordlist_size"] = len(sorted_words)
                stats["wordlist_path"] = str(wordlist_path)

                # Store wordlist info in DB
                try:
                    with conn() as c, c.cursor() as cur:
                        cur.execute("""
                            INSERT INTO content_extractions
                            (id, url, word_corpus, metadata, created_at)
                            VALUES (gen_random_uuid(), %s, %s, %s, now())
                        """, (target_url, "\n".join(sorted_words[:2000]),
                              json.dumps({"source": "wordlist_gen", "job_id": job_id[:8],
                                          "path": str(wordlist_path), "word_count": len(sorted_words)})))
                        c.commit()
                except Exception:
                    pass

                logger.info(f"[{job_id[:8]}] Generated wordlist: {len(sorted_words)} words → {wordlist_path}")
            except Exception as e:
                logger.warning(f"[{job_id[:8]}] Wordlist generation failed: {e}")
        else:
            logger.info(f"[{job_id[:8]}] Stage 5: Wordlist generation SKIPPED")

        # ── Stage 6: GoWitness screenshots (optional) ──
        if include_screenshots:
            _job_tracker.update_job(job_id, status="running", stage="gowitness")
            gw_cmd = f"gowitness scan single -u {target_url} -s ./screenshots -T 10 --screenshot-format png" if not screenshot_all else f"gowitness scan file -f targets.txt -s ./screenshots -T 10 --screenshot-format png  # {len(discovered_urls)+1} URLs"
            if proxy:
                gw_cmd += f" --chrome-proxy {proxy}"
            _job_tracker.push_command(job_id, "gowitness", gw_cmd)
            logger.info(f"[{job_id[:8]}] Stage 6: GoWitness screenshots")
            try:
                osint_runner_url = os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024")
                gw_targets = list(dict.fromkeys([target_url] + discovered_urls[:99])) if screenshot_all else [target_url]
                gw_payload = {"targets": gw_targets, "timeout": 10, "resolution": "1440x900"}
                if proxy:
                    gw_payload["proxy"] = proxy
                gw_resp = _req.post(
                    f"{osint_runner_url}/jobs/gowitness",
                    json=gw_payload,
                    headers={"x-api-key": API_KEY},
                    timeout=30,
                )
                if gw_resp.status_code == 200:
                    gw_data = gw_resp.json()
                    gw_job_id = gw_data.get("job_id")
                    if gw_job_id:
                        import time as _time_gw
                        deadline_gw = _time_gw.time() + 600  # 10 min max
                        while _time_gw.time() < deadline_gw:
                            gr = _req.get(f"{osint_runner_url}/jobs/{gw_job_id}",
                                          headers={"x-api-key": API_KEY}, timeout=10)
                            if gr.status_code == 200:
                                gd = gr.json()
                                if gd.get("status") in ("completed", "failed"):
                                    gw_result = gd.get("result", {})
                                    stats["screenshots"] = gw_result.get("screenshots", 0)
                                    stats["screenshots_dir"] = gw_result.get("dir", "")
                                    break
                            _time_gw.sleep(3)
                    logger.info(f"[{job_id[:8]}] GoWitness captured {stats['screenshots']} screenshots")
                else:
                    logger.warning(f"[{job_id[:8]}] GoWitness returned {gw_resp.status_code}")
            except Exception as e:
                logger.warning(f"[{job_id[:8]}] GoWitness failed: {e}")
        else:
            logger.info(f"[{job_id[:8]}] Stage 6: GoWitness screenshots SKIPPED")

        # ── Stage 7: EXIF metadata extraction from images (optional) ──
        if extract_exif:
            _job_tracker.update_job(job_id, status="running", stage="exif-extraction")
            _job_tracker.push_command(job_id, "exif-extraction", f"exiftool -json *.jpg *.png *.jpeg 2>/dev/null | python3 -c \"import sys,json; [print(json.dumps({{k:v for k,v in img.items() if k in ('Artist','Copyright','GPSLatitude','GPSLongitude','Make','Model','Software')}}, indent=2)) for img in json.load(sys.stdin)]\"")
            logger.info(f"[{job_id[:8]}] Stage 7: EXIF metadata extraction")
            try:
                # Find image URLs from discovered URLs and content extractions
                img_extensions = (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".gif", ".bmp", ".webp")
                img_links = [u for u in discovered_urls if any(u.lower().endswith(ext) for ext in img_extensions)]

                # Also look for image links in content extractions (internal_paths is JSONB array)
                try:
                    with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute("""
                            SELECT DISTINCT path_val FROM (
                                SELECT jsonb_array_elements_text(internal_paths) AS path_val
                                FROM content_extractions
                                WHERE internal_paths IS NOT NULL
                                AND created_at > now() - interval '1 hour'
                            ) sub WHERE path_val ~ '\\.(jpe?g|png|tiff?|gif|bmp|webp)$'
                            LIMIT 50
                        """)
                        for row in cur.fetchall():
                            img_val = row["path_val"]
                            if img_val.startswith(("http://", "https://")):
                                img_links.append(img_val)
                            elif img_val.startswith("/"):
                                from urllib.parse import urlparse as _up3
                                p = _up3(target_url)
                                img_links.append(f"{p.scheme}://{p.netloc}{img_val}")
                except Exception:
                    pass

                img_links = list(dict.fromkeys(img_links))[:30]  # Cap at 30 images
                logger.info(f"[{job_id[:8]}] Found {len(img_links)} images for EXIF extraction")

                for img_url in img_links:
                    try:
                        img_resp = _req.get(img_url, timeout=15, stream=True,
                                            headers={"User-Agent": "Mozilla/5.0 (pentest-recon)"})
                        if img_resp.status_code == 200 and len(img_resp.content) < 20_000_000:  # 20MB cap
                            img_path = REPORT_DIR / f"exif_{job_id[:8]}_{uuid.uuid4().hex[:6]}.img"
                            with open(img_path, "wb") as imgf:
                                imgf.write(img_resp.content)
                            try:
                                from PIL import Image
                                from PIL.ExifTags import TAGS, GPSTAGS
                                img = Image.open(str(img_path))
                                exif_data = {}
                                raw_exif = img.getexif()
                                if raw_exif:
                                    for tag_id, value in raw_exif.items():
                                        tag_name = TAGS.get(tag_id, str(tag_id))
                                        # Convert bytes to string for JSON serialization
                                        if isinstance(value, bytes):
                                            try:
                                                value = value.decode("utf-8", errors="replace")
                                            except Exception:
                                                value = str(value)
                                        exif_data[tag_name] = str(value)

                                    # Extract GPS data if present
                                    gps_info = raw_exif.get(0x8825)  # GPSInfo tag
                                    if gps_info:
                                        gps_data = {}
                                        for gps_tag_id, gps_val in gps_info.items():
                                            gps_tag_name = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                                            gps_data[gps_tag_name] = str(gps_val)
                                        exif_data["GPSInfo"] = gps_data

                                if exif_data:
                                    stats["exif_extracted"] += 1
                                    # Flag interesting fields for scope identification
                                    scope_fields = {}
                                    for key in ("Software", "Make", "Model", "Artist",
                                                 "Copyright", "CameraOwnerName", "BodySerialNumber",
                                                 "LensModel", "GPSInfo", "HostComputer",
                                                 "ImageDescription", "XPAuthor", "XPComment"):
                                        if key in exif_data:
                                            scope_fields[key] = exif_data[key]
                                    # Extract names from EXIF (artist, author, copyright owner)
                                    exif_names = [exif_data[k] for k in ("Artist", "XPAuthor", "Copyright", "CameraOwnerName") if exif_data.get(k)]
                                    # Store EXIF as content_extraction
                                    with conn() as c, c.cursor() as cur:
                                        cur.execute("""
                                            INSERT INTO content_extractions
                                            (id, url, file_metadata, names, metadata, created_at)
                                            VALUES (gen_random_uuid(), %s, %s, %s, %s, now())
                                        """, (img_url,
                                              json.dumps(exif_data)[:5000],
                                              json.dumps(exif_names) if exif_names else None,
                                              json.dumps({"source": "exif_extraction", "job_id": job_id[:8],
                                                          "scope_intel": scope_fields if scope_fields else None,
                                                          "fields_found": list(exif_data.keys())})))
                                        c.commit()
                                    # Also create an info finding for visibility in Findings Explorer
                                    interesting_parts = []
                                    for ek in ("Artist", "XPAuthor", "Copyright", "CameraOwnerName", "Software", "Make", "Model"):
                                        if ek in exif_data:
                                            interesting_parts.append(f"{ek}: {exif_data[ek]}")
                                    if exif_data.get("GPSInfo") or exif_data.get("GPSLatitude"):
                                        interesting_parts.append("GPS coordinates present")
                                    evidence_str = "; ".join(interesting_parts) if interesting_parts else f"{len(exif_data)} EXIF tags"
                                    finding_name = f"EXIF metadata: {', '.join(exif_names)}" if exif_names else f"EXIF metadata ({len(exif_data)} tags)"
                                    with conn() as c, c.cursor() as cur:
                                        cur.execute("""
                                            INSERT INTO web_findings (id, url, source, issue_type, name, severity, evidence, first_seen, last_seen)
                                            VALUES (gen_random_uuid(), %s, 'exif', 'metadata', %s, 'recon', %s, now(), now())
                                        """, (img_url, finding_name[:500], evidence_str[:2000]))
                                        c.commit()
                                    logger.info(f"[{job_id[:8]}] EXIF: {len(exif_data)} tags from {img_url}")
                            except ImportError:
                                logger.warning(f"[{job_id[:8]}] Pillow not installed, skipping EXIF extraction")
                                break  # No point trying more images
                            finally:
                                try:
                                    os.remove(img_path)
                                except OSError:
                                    pass
                    except Exception as e:
                        logger.warning(f"[{job_id[:8]}] EXIF extraction failed for {img_url}: {e}")

            except Exception as e:
                logger.warning(f"[{job_id[:8]}] EXIF extraction stage failed: {e}")
        else:
            logger.info(f"[{job_id[:8]}] Stage 7: EXIF extraction SKIPPED")

        # ── Stage 8: ZAP checkpoint (seed URLs into ZAP context for later active scan) ──
        if zap_checkpoint:
            _job_tracker.update_job(job_id, status="running", stage="zap-checkpoint")
            logger.info(f"[{job_id[:8]}] Stage 4: Seeding {len(pw_urls)} URLs into ZAP")
            try:
                ensure_zap_ready(timeout=30)
                from zapv2 import ZAPv2
                proxies = {"http": f"http://{ZAP_ADDR}:{ZAP_PORT}",
                           "https": f"http://{ZAP_ADDR}:{ZAP_PORT}"}
                zap = ZAPv2(apikey=ZAP_API_KEY, proxies=proxies)

                # Create a named context for this recon
                context_name = f"content-recon-{job_id[:8]}"
                ctx_id = zap.context.new_context(context_name)
                from urllib.parse import urlparse as _urlparse
                parsed_target = _urlparse(target_url)
                base_pattern = f"{parsed_target.scheme}://{parsed_target.netloc}.*"
                zap.context.include_in_context(context_name, base_pattern)

                # Seed all discovered URLs into ZAP site tree
                all_urls = list(dict.fromkeys([target_url] + discovered_urls))
                for seed_url in all_urls:
                    try:
                        zap.urlopen(seed_url)
                        stats["zap_seeded"] += 1
                    except Exception:
                        pass

                # Record ZAP session in DB
                with conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        INSERT INTO zap_sessions
                        (web_scan_job_id, session_name, zap_api_key, context_name, sites)
                        VALUES (%s, %s, %s, %s, %s) RETURNING id
                    """, (job_id, context_name, ZAP_API_KEY, context_name,
                          json.dumps(all_urls[:100])))
                    zap_session_id = str(cur.fetchone()["id"])
                    c.commit()

                stats["zap_context"] = context_name
                stats["zap_session_id"] = zap_session_id
                logger.info(f"[{job_id[:8]}] ZAP checkpoint: {stats['zap_seeded']} URLs in context '{context_name}'")

            except Exception as e:
                logger.warning(f"[{job_id[:8]}] ZAP checkpoint failed: {e}")
                stats["zap_error"] = str(e)

        # ── Done ──
        _job_tracker.update_job(job_id, status="completed", stage="done", result=stats)
        emit_webhook_event("scan_completed", "content-recon", {
            "job_id": job_id, "target_url": target_url, **stats,
        })
        write_audit("scan_completed", "content-recon", "web_scanner", {
            "job_id": job_id, "target_url": target_url, **stats,
        })

    except Exception as e:
        logger.exception(f"[{job_id[:8]}] Content recon pipeline failed: {e}")
        _job_tracker.update_job(job_id, status="failed", error=str(e))
        emit_webhook_event("scan_failed", "content-recon", {
            "job_id": job_id, "target_url": target_url, "error": str(e),
        })


@app.post("/jobs/content-recon")
def run_content_recon(req: ContentReconReq, background_tasks: BackgroundTasks):
    """Content-focused recon pipeline: Gobuster → Playwright (content+params) → ZAP passive checkpoint.

    Discovers directories with Gobuster (unless skip_gobuster=true), then visits each
    with Playwright to capture:
    - DOM snapshots + content intelligence (emails, keys, paths, tech, comments)
    - URL/form/POST parameters saved to discovered_params
    - Network request interception for full parameter mapping

    If zap_checkpoint=true (default), Playwright routes traffic through ZAP proxy for
    passive observation and all discovered URLs are seeded into a named ZAP context.
    No active scanning or spider is performed — ZAP only observes passively.

    Returns:
        job_id with progress tracking. Final result includes:
        - gobuster_paths: directories found (0 if skip_gobuster)
        - playwright_scans: pages analyzed
        - params_found: parameters discovered
        - content_intel: summary of extracted intelligence
        - zap_context: ZAP context name (passive observation only)
        - zap_session_id: DB ID of the ZAP session checkpoint
    """
    if req.target_url and not req.target_url.startswith(('http://', 'https://')):
        req.target_url = f"https://{req.target_url}"

    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(req.target_url)
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {e}")

    if req.wordlist:
        try:
            validate_wordlist(req.wordlist)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    job_id = _job_tracker.create_job(job_type="content-recon")
    background_tasks.add_task(
        _run_content_recon, job_id, req.target_url, req.wordlist,
        req.max_playwright_urls, req.zap_checkpoint, req.skip_gobuster,
        req.include_spider, req.spider_depth, req.extract_pdfs,
        req.generate_wordlist, req.include_screenshots, req.extract_exif,
        req.proxy, req.screenshot_all,
    )
    return {
        "ok": True,
        "job_id": job_id,
        "status": "queued",
        "target_url": req.target_url,
        "wordlist": req.wordlist or "medium (default)",
        "max_playwright_urls": req.max_playwright_urls,
        "zap_checkpoint": req.zap_checkpoint,
        "skip_gobuster": req.skip_gobuster,
        "include_spider": req.include_spider,
        "spider_depth": req.spider_depth,
        "extract_pdfs": req.extract_pdfs,
        "generate_wordlist": req.generate_wordlist,
        "include_screenshots": req.include_screenshots,
        "extract_exif": req.extract_exif,
        "status_url": f"/jobs/{job_id}",
    }


@app.post("/jobs/nikto-scan")
def run_nikto_scan(req: NiktoReq, background_tasks: BackgroundTasks):
    """Start a Nikto web server scan job (returns immediately with job_id)

    Nikto performs comprehensive web server security testing including:
    - Outdated server versions and components
    - Server misconfigurations
    - Default/insecure files and programs
    - Common vulnerabilities (XSS, SQL injection, etc.)
    - Security headers analysis
    - SSL/TLS configuration issues

    Args:
        target_url: Full URL to scan (e.g., 'http://192.168.1.150' or 'https://example.com:8443')
        tuning: Optional test tuning (e.g., '1' for interesting files, '123' for multiple tests, 'x6' to skip XSS)
        timeout_sec: Scan timeout in seconds (default: 1800 = 30 minutes)

    Returns:
        job_id for polling status via GET /jobs/{job_id}
    """
    # Validate URL
    if req.target_url and not req.target_url.startswith(('http://', 'https://')):
        req.target_url = f"https://{req.target_url}"

    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(req.target_url)
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {e}")

    job_id = _job_tracker.create_job(job_type="nikto-scan")
    background_tasks.add_task(_run_nikto_scan_job, job_id, req.target_url, req.tuning, req.timeout_sec)

    return {
        "ok": True,
        "job_id": job_id,
        "status": "queued",
        "target_url": req.target_url,
        "tuning": req.tuning or "default (all tests)",
        "timeout_sec": req.timeout_sec,
        "status_url": f"/jobs/{job_id}"
    }


@app.post("/jobs/nikto-scan/sync")
def run_nikto_scan_sync(req: NiktoReq):
    """Run Nikto web server scan synchronously (blocking, returns when done)

    Same as /jobs/nikto-scan but waits for completion and returns results directly.
    """
    # Validate URL
    if req.target_url and not req.target_url.startswith(('http://', 'https://')):
        req.target_url = f"https://{req.target_url}"

    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(req.target_url)
        validate_scan_target(parsed.hostname or parsed.netloc, allow_private=True)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {e}")

    logger.info(f"[sync] Starting Nikto scan on {req.target_url}")

    try:
        nikto_result = nikto_scan(url=req.target_url, timeout_sec=req.timeout_sec, tuning=req.tuning)
        findings_count = nikto_result["count"]

        return {
            "ok": True,
            "target_url": req.target_url,
            "findings_count": findings_count,
            "tuning": req.tuning or "default"
        }
    except Exception as e:
        logger.error(f"[sync] Nikto scan failed: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail=f"Nikto scan failed: {str(e)}")


# ===============================
# Pipeline Scan (Sequential: Katana → Playwright → Gobuster → Nikto → Nuclei → ZAP)
# ===============================

def _run_pipeline_scan_job(
    job_id: str,
    target_url: str,
    wordlist: Optional[str],
    max_paths_to_visit: int,
    skip_gobuster: bool,
    skip_playwright: bool,
    skip_zap: bool,
    skip_nuclei: bool,
    skip_nikto: bool = False,
    skip_katana: bool = False,
    skip_wafw00f: bool = False
):
    """Background task to run sequential scan pipeline with progress tracking"""
    try:
        # Emit webhook for pipeline scan start
        emit_webhook_event("scan_started", "web-scanner", {
            "job_id": job_id,
            "scan_type": "pipeline-scan",
            "target_url": target_url,
            "stages": ["wafw00f", "katana", "playwright", "gobuster", "nikto", "nuclei", "zap"],
            "wordlist": wordlist or "medium"
        })

        logger.info(f"[{job_id[:8]}] Starting pipeline scan on {target_url}")
        _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())

        # Import and create pipeline
        from scan_pipeline import WebScanPipeline
        pipeline = WebScanPipeline(
            job_tracker=_job_tracker,
            gobuster_func=gobuster_dir_with_paths,
            zap_func=zap_scan_with_urls,
            nikto_func=nikto_scan
        )

        # Run the pipeline
        result = pipeline.run_pipeline(
            target_url=target_url,
            job_id=job_id,
            wordlist=wordlist,
            max_paths_to_visit=max_paths_to_visit,
            skip_gobuster=skip_gobuster,
            skip_playwright=skip_playwright,
            skip_zap=skip_zap,
            skip_nuclei=skip_nuclei,
            skip_nikto=skip_nikto,
            skip_katana=skip_katana,
            skip_wafw00f=skip_wafw00f
        )

        # Update job with results
        _job_tracker.update_job(
            job_id,
            status=result.get("status", "completed"),
            completed_at=datetime.now().isoformat()
        )

        # Store summary stats
        stats = {
            "target": target_url,
            "paths_discovered": len(result.get("paths", [])),
            "urls_scanned": len(result.get("urls", [])),
            "stages": result.get("stages", {}),
            "errors": result.get("errors", [])
        }
        _job_tracker.update_job(job_id, stats=stats)
        _job_tracker.update_progress(job_id, stage="done")

        logger.info(f"[{job_id[:8]}] Pipeline scan completed: {stats}")

        # Insert info findings for scanners that completed with zero results
        stages_data = result.get("stages", {})
        pw_stage = stages_data.get("playwright", {})
        if pw_stage.get("status") == "completed":
            pw_urls_visited = pw_stage.get("urls_visited", 0)
            # Check if playwright stored any findings
            try:
                with conn() as _c, _c.cursor() as _cur:
                    _cur.execute("SELECT count(*) FROM playwright_findings WHERE created_at > now() - interval '1 hour'")
                    pw_count = _cur.fetchone()[0]
                if pw_count == 0:
                    _insert_info_finding("playwright", target_url,
                        "Playwright scan completed — no vulnerabilities found",
                        f"Scanned {pw_urls_visited} URLs with browser-based security checks. "
                        "No XSS, form injection, cookie, or DOM-based issues detected.")
            except Exception:
                pass

        nuclei_stage = stages_data.get("nuclei", {})
        if nuclei_stage.get("status") == "completed" and nuclei_stage.get("findings_count", 0) == 0:
            _insert_info_finding("nuclei", target_url,
                "Nuclei scan completed — no vulnerabilities found",
                f"Scanned target with nuclei template-based detection. "
                "No CVEs, misconfigurations, or known vulnerabilities matched.")

        # Save session results — write per-stage raw outputs
        session_files = []
        stages = result.get("stages", {})
        jid8 = job_id[:8]

        # Gobuster paths
        gobuster_paths = result.get("paths", [])
        if gobuster_paths:
            f = REPORT_DIR / f"gobuster_{jid8}.json"
            f.write_text(json.dumps(gobuster_paths, indent=2))
            session_files.append(str(f))

        # Nikto XML
        nikto_output = stages.get("nikto", {}).get("output_file")
        if nikto_output:
            session_files.append(nikto_output)

        # Playwright results
        pw_stage = stages.get("playwright", {})
        if pw_stage.get("status") == "completed":
            f = REPORT_DIR / f"playwright_{jid8}.json"
            f.write_text(json.dumps(pw_stage, indent=2))
            session_files.append(str(f))

        # Katana discovered URLs
        katana_urls = stages.get("katana", {}).get("urls", result.get("urls", []))
        if katana_urls:
            f = REPORT_DIR / f"katana_urls_{jid8}.txt"
            f.write_text("\n".join(str(u) for u in katana_urls))
            session_files.append(str(f))

        # ZAP alerts
        zap_stage = stages.get("zap", {})
        zap_alerts = zap_stage.get("alerts", [])
        if zap_alerts:
            f = REPORT_DIR / f"zap_alerts_{jid8}.json"
            f.write_text(json.dumps(zap_alerts, indent=2))
            session_files.append(str(f))

        # ZAP XML report (exported by pipeline after active scan)
        zap_xml_report = zap_stage.get("xml_report")
        if zap_xml_report and os.path.exists(zap_xml_report):
            session_files.append(zap_xml_report)

        # Nuclei results
        nuclei_stage = stages.get("nuclei", {})
        if nuclei_stage.get("status") == "completed" and nuclei_stage.get("findings"):
            f = REPORT_DIR / f"nuclei_{jid8}.json"
            f.write_text(json.dumps(nuclei_stage, indent=2))
            session_files.append(str(f))

        # Pipeline summary (compact — stage summaries without raw alert data)
        summary = {
            "job_id": job_id, "target": target_url,
            "paths_discovered": len(gobuster_paths),
            "urls_scanned": len(result.get("urls", [])),
            "stages": {k: {sk: sv for sk, sv in v.items() if sk != "alerts"} for k, v in stages.items()},
            "completed_at": datetime.now().isoformat(),
        }
        pipeline_summary = REPORT_DIR / f"pipeline_summary_{jid8}.json"
        pipeline_summary.write_text(json.dumps(summary, indent=2))
        session_files.append(str(pipeline_summary))

        _save_session_results(job_id, "pipeline-scan", "web-scanner", session_files, metadata=stats)

        # Emit webhook for scan completion
        emit_webhook_event("scan_completed", "web-scanner", {
            "job_id": job_id,
            "scan_type": "pipeline-scan",
            "target_url": target_url,
            "stats": stats
        })

        pipeline.close()

    except Exception as e:
        logger.error(f"[{job_id[:8]}] Pipeline scan failed: {type(e).__name__}: {e}")
        _job_tracker.update_job(
            job_id,
            status="failed",
            error=str(e),
            completed_at=datetime.now().isoformat()
        )
        _job_tracker.update_progress(job_id, stage="failed")

        # Emit webhook for scan failure
        emit_webhook_event("scan_failed", "web-scanner", {
            "job_id": job_id,
            "scan_type": "pipeline-scan",
            "error": str(e)
        })


@app.post("/jobs/pipeline-scan")
def run_pipeline_scan(req: PipelineReq, background_tasks: BackgroundTasks):
    """Run full sequential pipeline: Katana → Playwright → Gobuster → Nikto → Nuclei → ZAP

    All discovery tools run first so their URLs seed into ZAP, which runs
    last as the comprehensive aggregation scanner.  ZAP exports an XML
    report at the end.

    1. **Katana** - JS-aware crawling for endpoints, forms, JS URLs
    2. **Playwright** - Browser-based scanning of discovered paths
    3. **Gobuster** - Directory/file brute force discovery
    4. **Nikto** - Web server scanning (URIs merged into URL list for ZAP)
    5. **Nuclei** - CVE and misconfiguration detection
    6. **ZAP** - Final active scan seeded with ALL URLs from stages 1-4, exports XML

    Args:
        target_url: Target URL (required, e.g., 'http://192.168.1.150')
        wordlist: Wordlist for Gobuster (small, medium, big, etc.)
        max_paths_to_visit: Max paths for Playwright to visit (default: 50)
        skip_gobuster: Skip Gobuster stage
        skip_nikto: Skip Nikto stage
        skip_playwright: Skip Playwright stage
        skip_katana: Skip Katana stage
        skip_zap: Skip ZAP stage
        skip_nuclei: Skip Nuclei stage

    Returns:
        Job ID and status URL for tracking progress
    """
    # Validate target URL
    if req.target_url and not req.target_url.startswith(('http://', 'https://')):
        req.target_url = f"https://{req.target_url}"

    # Validate wordlist if provided
    if req.wordlist:
        try:
            validate_wordlist(req.wordlist)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    job_id = _job_tracker.create_job(job_type="pipeline-scan")
    background_tasks.add_task(
        _run_pipeline_scan_job,
        job_id,
        req.target_url,
        req.wordlist,
        req.max_paths_to_visit,
        req.skip_gobuster,
        req.skip_playwright,
        req.skip_zap,
        req.skip_nuclei,
        req.skip_nikto,
        req.skip_katana,
        req.skip_wafw00f
    )

    return {
        "ok": True,
        "job_id": job_id,
        "status": "queued",
        "target_url": req.target_url,
        "stages": ["wafw00f", "katana", "playwright", "gobuster", "nikto", "nuclei", "zap"],
        "status_url": f"/jobs/{job_id}"
    }


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
        headers={"Content-Disposition": "attachment; filename=web_scanner_logs.json"}
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8010, log_level="info", ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE"))
