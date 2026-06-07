"""
OSINT Runner - Passive Reconnaissance FastAPI Service
Provides endpoints for passive recon tools: subfinder, dnsx, asnmap, uncover,
cloudlist, alterx, and mapcidr.
"""

import os, uuid, pathlib, subprocess, threading, logging, json, tempfile, shutil, ipaddress, re
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, UploadFile, File
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


# Optional API keys for uncover/cloudlist/chaos (env var fallbacks)
_ENV_SHODAN_API_KEY      = os.environ.get("SHODAN_API_KEY", "")
_ENV_CENSYS_API_ID       = os.environ.get("CENSYS_API_ID", "")
_ENV_CENSYS_API_SECRET   = os.environ.get("CENSYS_API_SECRET", "")
_ENV_PDCP_API_KEY        = os.environ.get("PDCP_API_KEY", "")
# Certspotter is the crt.sh fallback for CT log lookups -- works without a
# key (100 issuances/day, 1 req/s) but a free Sectigo account key raises
# the quota to 5000/day.  See https://sslmate.com/certspotter/api
_ENV_CERTSPOTTER_API_KEY = os.environ.get("CERTSPOTTER_API_KEY", "")


def _fetch_db_api_keys() -> dict:
    """Fetch API keys from the rag-api /settings/keys/raw endpoint.
    Returns a dict like {"shodan_api_key": "...", ...} or {} on failure."""
    try:
        resp = requests.get(
            f"{API_BASE}/settings/keys/raw",
            headers={"x-api-key": API_KEY},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get("keys", {})
        logging.warning(f"[api-keys] Failed to fetch DB keys: HTTP {resp.status_code}")
    except Exception as e:
        logging.warning(f"[api-keys] Failed to fetch DB keys: {e}")
    return {}


def _get_api_keys() -> dict:
    """Return merged API keys: DB values take precedence over env vars."""
    keys = {
        "SHODAN_API_KEY":      _ENV_SHODAN_API_KEY,
        "CENSYS_API_ID":       _ENV_CENSYS_API_ID,
        "CENSYS_API_SECRET":   _ENV_CENSYS_API_SECRET,
        "PDCP_API_KEY":        _ENV_PDCP_API_KEY,
        "CERTSPOTTER_API_KEY": _ENV_CERTSPOTTER_API_KEY,
    }
    db_keys = _fetch_db_api_keys()
    # DB keys are lowercase, env vars are uppercase — map accordingly
    db_to_env = {
        "shodan_api_key":      "SHODAN_API_KEY",
        "censys_api_id":       "CENSYS_API_ID",
        "censys_api_secret":   "CENSYS_API_SECRET",
        "pdcp_api_key":        "PDCP_API_KEY",
        "certspotter_api_key": "CERTSPOTTER_API_KEY",
    }
    for db_name, env_name in db_to_env.items():
        val = db_keys.get(db_name, "")
        if val:
            keys[env_name] = val
    return keys


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
            json=payload, timeout=5, verify=False,
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

    def create_job(self, job_type: str = "osint-scan") -> str:
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


def _query_crtsh(domain: str, proxy: str = None, timeout: int = 60,
                  max_retries: int = 3, output: str = "json") -> list:
    """CT log lookup -- now backed by Certspotter, not crt.sh.

    crt.sh has been chronically flaky (frequent 502/503/timeouts; entire-
    site outages lasting hours) which made every CT-log-dependent scan
    unreliable.  We dropped direct crt.sh queries in favour of Certspotter
    (https://sslmate.com/certspotter), a Sectigo-operated independent CT
    log monitor that returns the same data with much better availability.

    Function name + signature preserved so the three existing callers
    (the /jobs/crtsh handler, the passive-recon pipeline, and the cert-
    chain expander) don't have to change.  ``max_retries`` and ``output``
    are accepted but ignored -- Certspotter is JSON-only and has its own
    retry budget inside _query_certspotter.

    See _query_certspotter for the upstream details, API key support,
    and the (common_name, not_after) normalization that matches the shape
    the downstream consumers already expect.
    """
    return _query_certspotter(domain, proxy=proxy, timeout=timeout)


def _query_certspotter(domain: str, proxy: str = None, timeout: int = 60,
                        max_retries: int = 3) -> list:
    """CT log lookup via Certspotter -- the public Sectigo-run alternative to
    crt.sh.  Used as a fallback when crt.sh is degraded (it 502s frequently).

    The response shape is normalized to match crt.sh's per-cert dict so the
    crtsh-job consumer at /jobs/crtsh and the other two callers don't need
    to change.  Specifically: each Certspotter issuance lists every SAN
    under ``dns_names``, so one issuance becomes N synthetic crt.sh-style
    rows (one per dns_name), each with ``common_name``, ``not_after``,
    ``not_before``, and ``issuer_name`` populated.

    API key (optional): if ``certspotter_api_key`` is set in app_settings
    (Settings page in the dashboard) or CERTSPOTTER_API_KEY is in the
    container's env, it's sent as ``Authorization: Bearer <token>`` -- the
    free tier without a key allows 100 issuances/day and 1 req/sec; with
    a free Sectigo account key it's 5000/day.

    Returns:
        List of normalized cert dicts, or a single-element error sentinel
        list on persistent failure (matches _query_crtsh's contract so the
        wrapper's "did the fallback work?" check is uniform).
    """
    import time as _time

    # Certspotter expects the *base* domain; subdomain expansion is on by
    # default via include_subdomains=true.  expand= controls which fields
    # the response includes -- dns_names + issuer is enough for our schema.
    url = (
        f"https://api.certspotter.com/v1/issuances?"
        f"domain={domain}"
        f"&include_subdomains=true"
        f"&expand=dns_names&expand=issuer"
    )

    # Pull the optional API key from app_settings (preferred) or env var.
    api_key = ""
    try:
        all_keys = _get_api_keys()  # already merges DB → env precedence
        api_key = all_keys.get("CERTSPOTTER_API_KEY", "")
    except Exception:
        api_key = os.environ.get("CERTSPOTTER_API_KEY", "")

    headers = {"User-Agent": "Mozilla/5.0 (recon-scanner)"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    proxies = {"https": proxy, "http": proxy} if proxy else None

    for attempt in range(max_retries):
        try:
            resp = requests.get(url, timeout=timeout, proxies=proxies, headers=headers)
            if resp.status_code == 200:
                try:
                    issuances = resp.json()
                except (json.JSONDecodeError, ValueError) as e:
                    logging.warning("Certspotter invalid JSON for %s: %s", domain, e)
                    return []
                # Normalize each issuance into N crt.sh-style rows, one
                # per dns_name SAN.  Skip wildcard-only entries that have
                # no concrete dns_names (rare).
                out = []
                for iss in issuances or []:
                    dns_names = iss.get("dns_names") or []
                    issuer = (iss.get("issuer") or {}).get("name") or ""
                    not_before = iss.get("not_before") or ""
                    not_after = iss.get("not_after") or ""
                    for name in dns_names:
                        out.append({
                            "common_name":  name,
                            "name_value":   name,
                            "not_before":   not_before,
                            "not_after":    not_after,
                            "issuer_name":  issuer,
                            "_source":      "certspotter",
                        })
                return out
            elif resp.status_code == 429:
                wait = (2 ** attempt) * 10  # 10s, 20s, 40s -- Certspotter is rate-sensitive
                logging.warning(
                    "Certspotter 429 (rate-limited) for %s (attempt %d/%d), retrying in %ds",
                    domain, attempt + 1, max_retries, wait,
                )
                _time.sleep(wait)
                continue
            elif resp.status_code in (502, 503, 504):
                wait = (2 ** attempt) * 5
                logging.warning(
                    "Certspotter %d for %s (attempt %d/%d), retrying in %ds",
                    resp.status_code, domain, attempt + 1, max_retries, wait,
                )
                _time.sleep(wait)
                continue
            else:
                logging.warning("Certspotter %d for %s: %s",
                                resp.status_code, domain, resp.text[:200])
                return []
        except requests.exceptions.Timeout:
            wait = (2 ** attempt) * 5
            logging.warning(
                "Certspotter timeout for %s (attempt %d/%d), retrying in %ds",
                domain, attempt + 1, max_retries, wait,
            )
            _time.sleep(wait)
            continue
        except requests.exceptions.ConnectionError as e:
            wait = (2 ** attempt) * 5
            logging.warning(
                "Certspotter connection error for %s (attempt %d/%d): %s, retrying in %ds",
                domain, attempt + 1, max_retries, e, wait,
            )
            _time.sleep(wait)
            continue
        except Exception as e:
            logging.error("Certspotter unexpected error for %s: %s", domain, e)
            return []

    logging.error("Certspotter failed after %d attempts for %s", max_retries, domain)
    return [{"_error": f"Certspotter unavailable after {max_retries} attempts"}]


def _query_crtsh_serial(serial: str, timeout: int = 30, max_retries: int = 2) -> list:
    """Query crt.sh by certificate serial number with retry logic."""
    import time as _time

    hex_serial = serial if all(c in '0123456789abcdefABCDEF' for c in serial) else serial
    url = f"https://crt.sh/?serial={hex_serial}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (recon-scanner)"}

    for attempt in range(max_retries):
        try:
            resp = requests.get(url, timeout=timeout, headers=headers)
            if resp.status_code == 200:
                try:
                    return resp.json()
                except (json.JSONDecodeError, ValueError):
                    return []
            elif resp.status_code in (502, 503, 504, 429):
                wait = (2 ** attempt) * 3
                _time.sleep(wait)
                continue
            else:
                return []
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            wait = (2 ** attempt) * 3
            _time.sleep(wait)
            continue
        except Exception:
            return []
    return []


def _ingest_results(tool: str, output_path: str, job_id: str = None, source: str = None) -> dict:
    """POST results file to rag-api ingest endpoint."""
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        return {"ok": True, "skipped": "no output"}
    try:
        files = {"file": (f"{tool}.json", open(output_path, "rb"), "application/json")}
        headers = {"x-api-key": API_KEY}
        params = {}
        if job_id:
            params["job_id"] = job_id
        if source:
            params["source"] = source
        r = requests.post(f"{API_BASE}/ingest/{tool}", files=files, headers=headers,
                          params=params, timeout=300, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.warning(f"Ingest to /ingest/{tool} failed: {e}")
        return {"ok": False, "error": str(e)}


# ===============================
# Tool Runner Functions
# ===============================

def _build_proxy_env(proxy: str = None) -> dict:
    """Build an env dict with API keys and optional SOCKS proxy vars."""
    env = os.environ.copy()
    api_keys = _get_api_keys()
    for k, v in api_keys.items():
        if v:
            env[k] = v
    if proxy:
        env["ALL_PROXY"] = proxy
        env["HTTP_PROXY"] = proxy
        env["HTTPS_PROXY"] = proxy
    return env


def _run_tool_job(job_id: str, tool: str, cmd: list, targets_file: str, output_file: str, ingest_as: str = None, env: dict = None, no_ingest: bool = False):
    """Generic background job runner for OSINT tools."""
    try:
        import time as _time
        _t0 = _time.time()
        cmd_str = " ".join(cmd)
        _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
        _job_tracker.push_command(job_id, tool, cmd_str)
        _job_tracker.update_progress(job_id, stage="running")

        emit_webhook_event("scan_started", tool, {"job_id": job_id, "scan_type": tool})
        write_audit("scan_started", tool, "osint_runner", {
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
                raw_output = content[:10000]
        _job_tracker.update_progress(job_id, findings_count=findings_count)

        # Ingest (skip if no_ingest / test mode)
        ing = None
        if no_ingest:
            logging.info(f"[{job_id}] no_ingest=true, skipping ingestion")
        else:
            _job_tracker.update_progress(job_id, stage="ingesting")
            ingest_tool = ingest_as or tool
            ingest_source = tool if ingest_as and ingest_as != tool else None
            ing = _ingest_results(ingest_tool, output_file, job_id=job_id, source=ingest_source)

        duration_s = round(_time.time() - _t0, 2)
        _job_tracker.update_progress(job_id, stage="done")
        result_data = {
            "ok": True, "findings_count": findings_count,
            "report": output_file, "ingest": ing,
            "command": cmd_str,
            "duration_s": duration_s,
            "no_ingest": no_ingest,
        }
        if no_ingest:
            result_data["raw_output"] = raw_output
            result_data["stdout"] = cp.stdout[-2000:] if cp.stdout else None
            result_data["stderr"] = cp.stderr[-2000:] if cp.stderr else None
        else:
            result_data["stdout"] = cp.stdout[-500:] if cp.stdout else None
            result_data["stderr"] = cp.stderr[-500:] if cp.stderr else None
        _job_tracker.update_job(
            job_id, status="completed",
            result=result_data,
            completed_at=datetime.now().isoformat(),
        )
        emit_webhook_event("scan_completed", tool, {"job_id": job_id, "findings_count": findings_count})
        write_audit("scan_completed", tool, "osint_runner", {
            "job_id": job_id, "findings_count": findings_count,
            "duration_s": duration_s, "command": cmd_str,
        })

        # Save session results
        if not no_ingest:
            _save_session_results(job_id, tool, "osint-runner", [output_file],
                              metadata={"findings_count": findings_count})

        # Auto-trigger dnsx after subfinder completes with findings
        if tool == "subfinder" and findings_count > 0:
            try:
                results = _read_jsonl(output_file)
                hosts = [r.get("host", "").strip() for r in results if r.get("host", "").strip()]
                hosts = hosts[:500]  # Cap at 500 to avoid overload
                if hosts:
                    logging.info(f"[{job_id}] Auto-triggering dnsx for {len(hosts)} subdomains")
                    requests.post(
                        "http://localhost:8024/jobs/dnsx",
                        json={"domains": hosts},
                        timeout=10,
                    )
            except Exception as e:
                logging.debug(f"[{job_id}] dnsx auto-trigger failed (non-fatal): {e}")

    except Exception as e:
        _job_tracker.update_job(job_id, status="failed", error=str(e),
                                result={"command": cmd_str, "error": str(e)},
                                completed_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="failed")
        emit_webhook_event("scan_failed", tool, {"job_id": job_id, "error": str(e)})
        write_audit("scan_failed", tool, "osint_runner", {
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

app = FastAPI(title="OSINT Runner")

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
    logging.info("[osint-runner] Service started, log capture initialized")


# --- Request Models ---

class SubfinderReq(BaseModel):
    domains: List[str]
    sources: Optional[str] = None
    max_time: Optional[int] = None
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class DnsxReq(BaseModel):
    domains: List[str]
    record_types: Optional[str] = "A,AAAA,CNAME,MX,NS"
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class AsnmapReq(BaseModel):
    targets: List[str]
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class UncoverReq(BaseModel):
    query: str
    engine: Optional[str] = "shodan"
    limit: Optional[int] = 100
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class CloudlistReq(BaseModel):
    provider: str
    config: Optional[Dict[str, Any]] = None

class AlterxReq(BaseModel):
    domains: List[str]
    patterns: Optional[List[str]] = None

class MapcidrReq(BaseModel):
    cidrs: List[str]
    operation: Optional[str] = "expand"  # expand, aggregate, count

class ChaosReq(BaseModel):
    domain: str
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class CrtshReq(BaseModel):
    domain: str
    include_expired: Optional[bool] = True
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class CloudTenantReq(BaseModel):
    domain: str
    engagement_id: Optional[str] = None
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class ShuffleDNSReq(BaseModel):
    domains: List[str]
    wordlist: Optional[str] = "/usr/share/massdns/lists/resolvers.txt"
    resolvers: Optional[str] = None
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class VulnxReq(BaseModel):
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    keyword: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    severity: Optional[str] = None

class SubdomainTakeoverReq(BaseModel):
    subdomains: List[str]
    timeout: Optional[int] = 30
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False
    limit: Optional[int] = 100
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class VulnxScopeReq(BaseModel):
    engagement_id: Optional[str] = None  # specific engagement scope
    asset_ids: Optional[List[str]] = None  # specific assets
    severity: Optional[str] = None
    limit: Optional[int] = 100
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class ReconPipelineReq(BaseModel):
    targets: List[str]                       # mixed domains, IPs, ASNs, CIDRs
    skip_phases: Optional[List[str]] = None  # e.g. ["alterx","shuffledns"] to skip
    uncover_engine: Optional[str] = "shodan"
    uncover_limit: Optional[int] = 100
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class AmassReq(BaseModel):
    domains: List[str]
    passive: Optional[bool] = True
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class GauReq(BaseModel):
    domains: List[str]
    providers: Optional[str] = None  # comma-sep: wayback,commoncrawl,otx,urlscan
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class WaybackurlsReq(BaseModel):
    domains: List[str]
    no_subs: Optional[bool] = False
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class TrufflehogReq(BaseModel):
    target: str                          # repo URL, org, or filesystem path
    scan_type: Optional[str] = "git"     # git, github, filesystem, s3
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class CensysReq(BaseModel):
    query: str                           # Censys search query or target
    search_type: Optional[str] = "hosts" # hosts, certs, subdomains
    per_page: Optional[int] = 100
    pages: Optional[int] = 1
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class GoWitnessReq(BaseModel):
    targets: List[str]                   # URLs to screenshot
    timeout: Optional[int] = 10          # per-URL timeout (seconds)
    resolution: Optional[str] = "1440x900"
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class Wafw00fReq(BaseModel):
    targets: List[str]                   # URLs (http://...) or domains
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class GHWReq(BaseModel):
    search_query: str                    # keyword, domain, company name
    search_type: Optional[str] = "buckets"  # buckets | files
    limit: Optional[int] = 100
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False

class PassiveReconReq(BaseModel):
    targets: List[str]                              # domains to enumerate passively
    scope_name: Optional[str] = None                # scope name for auto-adding domains
    include_spider: Optional[bool] = False          # enable katana crawl
    spider_depth: Optional[int] = 2                 # katana depth (1-5)
    include_cert_chain: Optional[bool] = True       # cert serial chaining via crt.sh
    cert_chain_max_iterations: Optional[int] = 2    # max cert chain rounds (1-3)
    plan_only: Optional[bool] = False               # return plan without executing
    proxy: Optional[str] = None
    no_ingest: Optional[bool] = False


# --- Helpers ---

def _classify_targets(targets: list) -> dict:
    """Split targets into domains, IPs, ASNs, and URLs.

    Full URLs (http/https) are stored in the 'urls' list AND their hostname
    is extracted into 'domains' so domain-only tools (subfinder, dnsx, etc.)
    receive bare hostnames while URL-aware tools (httpx, gowitness, whatweb)
    can use the original URLs directly.
    """
    classified = {"domains": [], "ips": [], "asns": [], "urls": []}
    seen_domains = set()
    for t in targets:
        t = t.strip()
        if not t:
            continue
        # URL check — extract hostname for domain tools, keep full URL separately
        if re.match(r"^https?://", t, re.IGNORECASE):
            classified["urls"].append(t)
            try:
                host = urlparse(t).hostname or ""
            except Exception:
                host = ""
            if host and host not in seen_domains:
                # Check if the host part is an IP
                try:
                    ipaddress.ip_address(host)
                    classified["ips"].append(host)
                except ValueError:
                    classified["domains"].append(host)
                    seen_domains.add(host)
            continue
        # ASN check
        if re.match(r"^AS\d+$", t, re.IGNORECASE):
            classified["asns"].append(t)
            continue
        # IP or CIDR check
        try:
            ipaddress.ip_network(t, strict=False)
            classified["ips"].append(t)
            continue
        except ValueError:
            pass
        try:
            ipaddress.ip_address(t)
            classified["ips"].append(t)
            continue
        except ValueError:
            pass
        # Fallback: treat as domain
        if t not in seen_domains:
            classified["domains"].append(t)
            seen_domains.add(t)
    return classified


def _read_plain_lines(path: str) -> list:
    """Read a plain text file (one entry per line), return list of non-empty strings."""
    lines = []
    if not os.path.exists(path):
        return lines
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(line)
    return lines


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
    emit_webhook_event("scan_stopped", "osint-runner", {"job_id": job_id})
    return {"ok": True, "job_id": job_id, "status": "stopped"}


# ===============================
# Tool Endpoints
# ===============================

@app.post("/jobs/subfinder")
def run_subfinder(req: SubfinderReq, background_tasks: BackgroundTasks):
    """Passive subdomain enumeration."""
    job_id = _job_tracker.create_job(job_type="subfinder")
    targets_file = _write_targets_file(req.domains)
    output_file = str(REPORT_DIR / f"subfinder_{job_id[:8]}.jsonl")

    cmd = ["subfinder", "-dL", targets_file, "-json", "-o", output_file, "-silent"]
    if req.sources:
        cmd.extend(["-sources", req.sources])
    if req.max_time:
        cmd.extend(["-timeout", str(req.max_time)])
    if req.proxy:
        cmd.extend(["-proxy", req.proxy])

    env = _build_proxy_env(req.proxy)
    _job_tracker.update_progress(job_id, targets_count=len(req.domains))
    background_tasks.add_task(_run_tool_job, job_id, "subfinder", cmd, targets_file, output_file, env=env, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/dnsx")
def run_dnsx(req: DnsxReq, background_tasks: BackgroundTasks):
    """DNS resolution and enumeration."""
    job_id = _job_tracker.create_job(job_type="dnsx")
    targets_file = _write_targets_file(req.domains)
    output_file = str(REPORT_DIR / f"dnsx_{job_id[:8]}.jsonl")

    cmd = ["dnsx", "-l", targets_file, "-json", "-o", output_file, "-silent"]
    if req.record_types:
        for rt in req.record_types.split(","):
            rt = rt.strip().lower()
            if rt == "a":
                cmd.append("-a")
            elif rt == "aaaa":
                cmd.append("-aaaa")
            elif rt == "cname":
                cmd.append("-cname")
            elif rt == "mx":
                cmd.append("-mx")
            elif rt == "ns":
                cmd.append("-ns")

    env = _build_proxy_env()  # DNS is direct; proxy not applicable but ensure API keys in env
    _job_tracker.update_progress(job_id, targets_count=len(req.domains))
    background_tasks.add_task(_run_tool_job, job_id, "dnsx", cmd, targets_file, output_file, env=env, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/asnmap")
def run_asnmap(req: AsnmapReq, background_tasks: BackgroundTasks):
    """ASN to CIDR mapping."""
    job_id = _job_tracker.create_job(job_type="asnmap")
    targets_file = _write_targets_file(req.targets)
    output_file = str(REPORT_DIR / f"asnmap_{job_id[:8]}.jsonl")

    cmd = ["asnmap", "-l", targets_file, "-json", "-o", output_file, "-silent"]

    env = _build_proxy_env(req.proxy)
    _job_tracker.update_progress(job_id, targets_count=len(req.targets))
    background_tasks.add_task(_run_tool_job, job_id, "asnmap", cmd, targets_file, output_file, ingest_as="recon", env=env)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/uncover")
def run_uncover(req: UncoverReq, background_tasks: BackgroundTasks):
    """Shodan/Censys/Fofa queries."""
    job_id = _job_tracker.create_job(job_type="uncover")
    output_file = str(REPORT_DIR / f"uncover_{job_id[:8]}.jsonl")

    cmd = ["uncover", "-q", req.query, "-json", "-o", output_file, "-silent",
           "-limit", str(req.limit or 100)]
    if req.engine:
        cmd.extend(["-e", req.engine])

    env = _build_proxy_env(req.proxy)

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")
            emit_webhook_event("scan_started", "uncover", {"job_id": job_id})

            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)

            findings_count = 0
            if os.path.exists(output_file):
                with open(output_file) as f:
                    findings_count = sum(1 for line in f if line.strip())
            _job_tracker.update_progress(job_id, findings_count=findings_count)

            _job_tracker.update_progress(job_id, stage="ingesting")
            ing = _ingest_results("recon", output_file, job_id=job_id)

            _job_tracker.update_progress(job_id, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "findings_count": findings_count, "ingest": ing},
                completed_at=datetime.now().isoformat(),
            )
            emit_webhook_event("scan_completed", "uncover", {"job_id": job_id, "findings_count": findings_count})

            # Save session results
            _save_session_results(job_id, "uncover", "osint-runner", [output_file],
                                  metadata={"findings_count": findings_count})
        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            logging.error(f"[{job_id}] uncover failed: {e}")

    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/cloudlist")
def run_cloudlist(req: CloudlistReq, background_tasks: BackgroundTasks):
    """Cloud provider IP enumeration."""
    job_id = _job_tracker.create_job(job_type="cloudlist")
    output_file = str(REPORT_DIR / f"cloudlist_{job_id[:8]}.jsonl")

    cmd = ["cloudlist", "-provider", req.provider, "-json", "-o", output_file, "-silent"]

    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run_tool_job, job_id, "cloudlist", cmd, None, output_file, ingest_as="recon")
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/alterx")
def run_alterx(req: AlterxReq, background_tasks: BackgroundTasks):
    """Subdomain wordlist generation."""
    job_id = _job_tracker.create_job(job_type="alterx")
    targets_file = _write_targets_file(req.domains)
    output_file = str(REPORT_DIR / f"alterx_{job_id[:8]}.txt")

    cmd = ["alterx", "-l", targets_file, "-o", output_file, "-silent"]
    if req.patterns:
        for p in req.patterns:
            cmd.extend(["-p", p])

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")

            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            count = 0
            if os.path.exists(output_file):
                with open(output_file) as f:
                    count = sum(1 for line in f if line.strip())
            _job_tracker.update_progress(job_id, findings_count=count, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "wordlist_size": count, "output_file": output_file},
                completed_at=datetime.now().isoformat(),
            )

            # Save session results
            _save_session_results(job_id, "alterx", "osint-runner", [output_file],
                                  metadata={"wordlist_size": count})
        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            logging.error(f"[{job_id}] alterx failed: {e}")
        finally:
            if os.path.exists(targets_file):
                try: os.remove(targets_file)
                except OSError: pass

    _job_tracker.update_progress(job_id, targets_count=len(req.domains))
    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/mapcidr")
def run_mapcidr(req: MapcidrReq, background_tasks: BackgroundTasks):
    """CIDR aggregation/expansion/count."""
    job_id = _job_tracker.create_job(job_type="mapcidr")
    targets_file = _write_targets_file(req.cidrs)
    output_file = str(REPORT_DIR / f"mapcidr_{job_id[:8]}.txt")

    cmd = ["mapcidr", "-l", targets_file, "-o", output_file, "-silent"]
    op = req.operation or "expand"
    if op == "aggregate":
        cmd.append("-aggregate")
    elif op == "count":
        cmd.append("-count")
    # expand is the default

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")

            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            count = 0
            if os.path.exists(output_file):
                with open(output_file) as f:
                    count = sum(1 for line in f if line.strip())
            _job_tracker.update_progress(job_id, findings_count=count, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "output_lines": count, "operation": op, "output_file": output_file},
                completed_at=datetime.now().isoformat(),
            )

            # Save session results
            _save_session_results(job_id, "mapcidr", "osint-runner", [output_file],
                                  metadata={"output_lines": count, "operation": op})
        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            logging.error(f"[{job_id}] mapcidr failed: {e}")
        finally:
            if os.path.exists(targets_file):
                try: os.remove(targets_file)
                except OSError: pass

    _job_tracker.update_progress(job_id, targets_count=len(req.cidrs))
    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/chaos")
def run_chaos(req: ChaosReq, background_tasks: BackgroundTasks):
    """Passive subdomain discovery via Chaos dataset."""
    job_id = _job_tracker.create_job(job_type="chaos")
    output_file = str(REPORT_DIR / f"chaos_{job_id[:8]}.jsonl")

    cmd = ["chaos", "-d", req.domain, "-json", "-o", output_file, "-silent"]

    env = _build_proxy_env(req.proxy)

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")
            emit_webhook_event("scan_started", "chaos", {"job_id": job_id})

            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)

            findings_count = 0
            if os.path.exists(output_file):
                with open(output_file) as f:
                    findings_count = sum(1 for line in f if line.strip())
            _job_tracker.update_progress(job_id, findings_count=findings_count)

            _job_tracker.update_progress(job_id, stage="ingesting")
            ing = _ingest_results("subfinder", output_file, job_id=job_id)

            _job_tracker.update_progress(job_id, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "findings_count": findings_count, "ingest": ing},
                completed_at=datetime.now().isoformat(),
            )
            emit_webhook_event("scan_completed", "chaos", {"job_id": job_id, "findings_count": findings_count})
            _save_session_results(job_id, "chaos", "osint-runner", [output_file],
                                  metadata={"findings_count": findings_count})
        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            logging.error(f"[{job_id}] chaos failed: {e}")

    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/crtsh")
def run_crtsh(req: CrtshReq, background_tasks: BackgroundTasks):
    """Passive certificate transparency lookup via crt.sh."""
    job_id = _job_tracker.create_job(job_type="crtsh")
    output_file = str(REPORT_DIR / f"crtsh_{job_id[:8]}.jsonl")
    proxy = req.proxy

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")
            emit_webhook_event("scan_started", "crtsh", {"job_id": job_id})

            # Query crt.sh JSON API (with retry logic)
            certs = _query_crtsh(req.domain, proxy=proxy, timeout=60)

            # Deduplicate by common_name and filter
            seen = set()
            unique_certs = []
            for cert in certs:
                cn = cert.get("common_name", "").strip()
                if not cn:
                    continue
                if cn in seen:
                    continue
                seen.add(cn)
                # Optionally skip expired certs
                if not req.include_expired:
                    not_after = cert.get("not_after", "")
                    if not_after:
                        try:
                            expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00").replace(" ", "T"))
                            if expiry < datetime.now(expiry.tzinfo):
                                continue
                        except Exception:
                            pass
                cert["queried_domain"] = req.domain
                unique_certs.append(cert)

            # Write JSONL
            with open(output_file, "w") as f:
                for cert in unique_certs:
                    f.write(json.dumps(cert) + "\n")

            findings_count = len(unique_certs)
            _job_tracker.update_progress(job_id, findings_count=findings_count)

            # Ingest
            _job_tracker.update_progress(job_id, stage="ingesting")
            ing = _ingest_results("crtsh", output_file, job_id=job_id)

            _job_tracker.update_progress(job_id, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "findings_count": findings_count, "ingest": ing},
                completed_at=datetime.now().isoformat(),
            )
            emit_webhook_event("scan_completed", "crtsh", {"job_id": job_id, "findings_count": findings_count})
            _save_session_results(job_id, "crtsh", "osint-runner", [output_file],
                                  metadata={"domain": req.domain, "findings_count": findings_count})
        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            logging.error(f"[{job_id}] crtsh failed: {e}")

    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/shuffledns")
def run_shuffledns(req: ShuffleDNSReq, background_tasks: BackgroundTasks):
    """Active DNS bruteforce with ShuffleDNS."""
    job_id = _job_tracker.create_job(job_type="shuffledns")
    targets_file = _write_targets_file(req.domains)
    output_file = str(REPORT_DIR / f"shuffledns_{job_id[:8]}.jsonl")

    resolvers = req.resolvers or "/runner/resolvers.txt"
    wordlist = req.wordlist or "/usr/share/massdns/lists/resolvers.txt"

    cmd = ["shuffledns", "-list", targets_file, "-w", wordlist,
           "-r", resolvers, "-json", "-o", output_file, "-silent"]

    env = _build_proxy_env(req.proxy)
    _job_tracker.update_progress(job_id, targets_count=len(req.domains))
    background_tasks.add_task(_run_tool_job, job_id, "shuffledns", cmd, targets_file, output_file, ingest_as="subfinder", env=env)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/vulnx")
def run_vulnx(req: VulnxReq, background_tasks: BackgroundTasks):
    """CVE lookup via vulnx (replacement for cvemap)."""
    job_id = _job_tracker.create_job(job_type="vulnx")
    output_file = str(REPORT_DIR / f"vulnx_{job_id[:8]}.jsonl")

    # Build command
    if req.cve_ids:
        cmd = ["vulnx", "id", ",".join(req.cve_ids), "--json", "-o", output_file]
    else:
        # Build search query from product+version or banner/keyword
        product = (req.product or "").strip()
        version = (req.version or "").strip()
        banner = (req.banner or "").strip()
        keyword = (req.keyword or "").strip()
        query = f"{product} {version}".strip() if product else (banner or keyword)
        if not query:
            query = "cve"  # fallback

        cmd = ["vulnx", "search", query, "--json", "-o", output_file,
               "--limit", str(req.limit or 100)]
        if product:
            cmd.extend(["--product", product])
        if req.severity:
            cmd.extend(["--severity", req.severity])

    env = _build_proxy_env(req.proxy)

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")
            emit_webhook_event("scan_started", "vulnx", {"job_id": job_id})

            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)

            findings_count = 0
            if os.path.exists(output_file):
                with open(output_file) as f:
                    findings_count = sum(1 for line in f if line.strip())
            _job_tracker.update_progress(job_id, findings_count=findings_count)

            _job_tracker.update_progress(job_id, stage="ingesting")
            ing = _ingest_results("vulnx", output_file, job_id=job_id)

            _job_tracker.update_progress(job_id, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "findings_count": findings_count, "ingest": ing},
                completed_at=datetime.now().isoformat(),
            )
            emit_webhook_event("scan_completed", "vulnx", {"job_id": job_id, "findings_count": findings_count})
            _save_session_results(job_id, "vulnx", "osint-runner", [output_file],
                                  metadata={"findings_count": findings_count})
        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            logging.error(f"[{job_id}] vulnx failed: {e}")

    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


def _check_vulnx_auth() -> bool:
    """Check if VulnX API key is configured."""
    try:
        cp = subprocess.run(["vulnx", "healthcheck"], capture_output=True, text=True, timeout=10)
        return "✅ Authentication: PASS" in cp.stdout
    except Exception:
        return False

@app.post("/jobs/vulnx-scope")
def run_vulnx_scope(req: VulnxScopeReq, background_tasks: BackgroundTasks):
    """CVE lookup via vulnx for all software detected in scope/assets."""

    # Check VulnX authentication
    if not _check_vulnx_auth():
        raise HTTPException(status_code=400, detail="VulnX API key not configured. Run 'vulnx auth' to set up authentication for CVE lookups.")

    job_id = _job_tracker.create_job(job_type="vulnx-scope")

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="discovering_software")
            emit_webhook_event("scan_started", "vulnx-scope", {"job_id": job_id})

            # Get software from database based on scope
            with psycopg2.connect(DB_DSN) as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                if req.engagement_id:
                    # Get assets from specific engagement (include NULL engagement_id assets as fallback)
                    cur.execute("""
                        SELECT DISTINCT p.product, p.version, a.ip
                        FROM ports p
                        JOIN assets a ON p.asset_id = a.id
                        WHERE (a.engagement_id = %s OR a.engagement_id IS NULL)
                        AND p.product IS NOT NULL
                        AND p.product != ''
                    """, (req.engagement_id,))
                elif req.asset_ids:
                    # Get software from specific assets
                    placeholders = ','.join(['%s'] * len(req.asset_ids))
                    cur.execute(f"""
                        SELECT DISTINCT p.product, p.version, a.ip
                        FROM ports p
                        JOIN assets a ON p.asset_id = a.id
                        WHERE a.id IN ({placeholders})
                        AND p.product IS NOT NULL
                        AND p.product != ''
                    """, req.asset_ids)
                else:
                    # Get all detected software
                    cur.execute("""
                        SELECT DISTINCT p.product, p.version, a.ip
                        FROM ports p
                        JOIN assets a ON p.asset_id = a.id
                        WHERE p.product IS NOT NULL
                        AND p.product != ''
                        ORDER BY p.product, p.version
                    """)

                software_list = cur.fetchall()

            if not software_list:
                raise ValueError("No software assets found in scope")

            _job_tracker.update_progress(job_id, targets_count=len(software_list), stage="scanning_software")
            logging.info(f"[{job_id}] Found {len(software_list)} software products to scan")

            total_findings = 0
            processed = 0

            # Process each software product
            for software in software_list:
                product = software['product']
                version = software['version']
                ip = software['ip']

                processed += 1
                _job_tracker.update_progress(job_id,
                    stage=f"scanning_{product}_{version}".replace(' ', '_'),
                    current_target=f"{product} {version} on {ip}",
                    targets_processed=processed
                )

                # Build vulnx command for this software
                query = f"{product} {version}".strip()
                output_filename = f"vulnx_{job_id[:8]}_{processed}.json"
                output_file = str(REPORT_DIR / output_filename)

                cmd = ["vulnx", "search", query, "--json", "-o", output_filename,
                       "--limit", str(req.limit or 100)]
                cmd.extend(["--product", product])
                if req.severity:
                    cmd.extend(["--severity", req.severity])

                env = _build_proxy_env(req.proxy)

                try:
                    logging.info(f"[{job_id}] Scanning {product} {version}")
                    logging.info(f"[{job_id}] Command: {' '.join(cmd)}")

                    # Run vulnx from /reports directory with relative filename
                    cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env, cwd=str(REPORT_DIR))

                    # Log command results
                    logging.info(f"[{job_id}] VulnX exit code: {cp.returncode}")
                    if cp.stdout:
                        logging.info(f"[{job_id}] VulnX stdout: {cp.stdout[:500]}...")
                    if cp.stderr:
                        logging.warning(f"[{job_id}] VulnX stderr: {cp.stderr[:500]}...")

                    # Check if command succeeded
                    if cp.returncode != 0:
                        logging.error(f"[{job_id}] VulnX failed for {product} {version} with exit code {cp.returncode}")
                        continue

                    # Count findings in this output file
                    if os.path.exists(output_file):
                        with open(output_file) as f:
                            file_findings = sum(1 for line in f if line.strip())
                        total_findings += file_findings
                        logging.info(f"[{job_id}] {product} {version}: {file_findings} vulnerabilities found")

                        # Ingest results for this software
                        if not req.no_ingest:
                            _ingest_results("vulnx", output_file, job_id=job_id)
                    else:
                        logging.warning(f"[{job_id}] Output file not created: {output_file}")

                except subprocess.TimeoutExpired:
                    logging.warning(f"[{job_id}] Timeout scanning {product} {version}")
                except Exception as e:
                    logging.error(f"[{job_id}] Error scanning {product} {version}: {e}")

            _job_tracker.update_progress(job_id, stage="completed", findings_count=total_findings)
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "software_scanned": len(software_list), "findings_count": total_findings},
                completed_at=datetime.now().isoformat(),
            )
            emit_webhook_event("scan_completed", "vulnx-scope", {
                "job_id": job_id,
                "software_scanned": len(software_list),
                "findings_count": total_findings
            })

        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            logging.error(f"[{job_id}] vulnx-scope failed: {e}")

    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


# ===============================
# Cloud Tenant Discovery
# ===============================
# Passive lookups that map a domain → cloud-provider tenant identifiers.
# Azure produces a deterministic tenant GUID via the public OpenID config
# endpoint; AWS exposes no equivalent so we surface DNS indicators only
# (SES verification TXT, SPF amazonses include, AWS-pointing CNAMEs).

def _discover_azure_tenant(domain: str, proxy: Optional[str] = None) -> Optional[dict]:
    """Hit login.microsoftonline.com OpenID config + GetUserRealm. Returns
    None when the domain is not registered with Entra ID."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    out: dict = {"domain": domain, "provider": "azure"}

    # 1. OpenID configuration — issuer carries the tenant GUID.
    try:
        url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
        r = requests.get(url, proxies=proxies, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        issuer = data.get("issuer", "")
        # issuer looks like "https://sts.windows.net/<TENANT-GUID>/" or
        # "https://login.microsoftonline.com/<TENANT-GUID>/v2.0"
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", issuer)
        if not m:
            return None
        out["tenant_id"] = m.group(1)
        out["cloud_instance"] = data.get("cloud_instance_name") or "microsoftonline.com"
        out["openid_issuer"] = issuer
        out["tenant_region_scope"] = data.get("tenant_region_scope")
    except Exception as e:
        logging.debug(f"Azure openid lookup failed for {domain}: {e}")
        return None

    # 2. GetUserRealm — federation type + STS endpoint (best-effort).
    try:
        url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&xml=1"
        r = requests.get(url, proxies=proxies, timeout=10)
        if r.status_code == 200:
            text = r.text
            ns = re.search(r"<NameSpaceType>([^<]+)</NameSpaceType>", text)
            sts = re.search(r"<STSAuthURL>([^<]+)</STSAuthURL>", text)
            fed_brand = re.search(r"<FederationBrandName>([^<]+)</FederationBrandName>", text)
            if ns:
                out["name_space_type"] = ns.group(1)
                out["federation_type"] = ns.group(1)
            if sts:
                out["sts_auth_url"] = sts.group(1)
            if fed_brand:
                out["federation_brand_name"] = fed_brand.group(1)
    except Exception as e:
        logging.debug(f"Azure GetUserRealm lookup failed for {domain}: {e}")
    return out


def _discover_aws_indicators(domain: str) -> Optional[dict]:
    """DNS-only AWS indicator sweep. Returns None when no AWS hosting signal
    is detected. AWS account IDs are not surfaced — they're not exposed
    publicly via domain (caller can cross-reference cloud_scan_recommendations
    on the rag-api side)."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return None

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    indicators: dict = {}

    # SES verification TXT record
    try:
        ans = resolver.resolve(f"_amazonses.{domain}", "TXT")
        indicators["ses_verification_token"] = [r.strings[0].decode("utf-8", "replace")
                                                for r in ans][:5]
    except Exception:
        pass

    # SPF / TXT root — look for AWS-related includes
    try:
        ans = resolver.resolve(domain, "TXT")
        spf_aws_terms = []
        for r in ans:
            txt = b" ".join(r.strings).decode("utf-8", "replace")
            for needle in ("include:amazonses.com", "include:_spf.amazon.com",
                           "include:amazon.com", "include:awssite.com"):
                if needle in txt.lower():
                    spf_aws_terms.append(needle)
            if spf_aws_terms:
                indicators.setdefault("spf_includes", []).extend(spf_aws_terms)
                indicators["spf_record"] = txt
    except Exception:
        pass

    # MX → SES inbound endpoint
    try:
        ans = resolver.resolve(domain, "MX")
        aws_mx = [str(r.exchange).rstrip(".") for r in ans
                  if "amazonses" in str(r.exchange).lower()
                  or "amazonaws.com" in str(r.exchange).lower()]
        if aws_mx:
            indicators["aws_mx"] = aws_mx
    except Exception:
        pass

    # CNAME on apex/www → CloudFront / ELB / S3 website
    for prefix in ("", "www."):
        host = f"{prefix}{domain}"
        try:
            ans = resolver.resolve(host, "CNAME")
            for r in ans:
                cn = str(r.target).rstrip(".").lower()
                if any(s in cn for s in ("cloudfront.net", "amazonaws.com",
                                          "elb.amazonaws.com", "s3-website")):
                    indicators.setdefault("aws_cnames", {})[host] = cn
        except Exception:
            pass

    if not indicators:
        return None
    return {"domain": domain, "provider": "aws", "indicators": indicators}


@app.post("/jobs/cloud-tenant")
def run_cloud_tenant(req: CloudTenantReq, background_tasks: BackgroundTasks):
    """Passive cloud-tenant discovery for a single domain.

    Azure: deterministic tenant GUID via OpenID configuration +
    federation type via GetUserRealm.
    AWS: best-effort DNS indicators (SES TXT, SPF includes, CNAMEs).
    Cross-references existing identities.tenant_id and
    cloud_scan_recommendations.account_id rag-api side."""
    job_id = _job_tracker.create_job(job_type="cloud-tenant")
    output_file = str(REPORT_DIR / f"cloud_tenant_{job_id[:8]}.jsonl")
    proxy = req.proxy
    domain = (req.domain or "").strip().lower()
    if not domain:
        raise HTTPException(400, "domain is required")

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")
            emit_webhook_event("scan_started", "cloud-tenant",
                               {"job_id": job_id, "domain": domain})

            results = []
            azure = _discover_azure_tenant(domain, proxy=proxy)
            if azure:
                if req.engagement_id:
                    azure["engagement_id"] = req.engagement_id
                results.append(azure)
            aws = _discover_aws_indicators(domain)
            if aws:
                if req.engagement_id:
                    aws["engagement_id"] = req.engagement_id
                results.append(aws)

            with open(output_file, "w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")

            findings_count = len(results)
            _job_tracker.update_progress(job_id, findings_count=findings_count)

            ing = {"ok": True, "skipped": "no_ingest"}
            if not req.no_ingest and findings_count > 0:
                _job_tracker.update_progress(job_id, stage="ingesting")
                ing = _ingest_results("cloud-tenant", output_file, job_id=job_id)

            _job_tracker.update_progress(job_id, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "domain": domain, "findings_count": findings_count,
                        "results": results, "ingest": ing},
                completed_at=datetime.now().isoformat(),
            )
            emit_webhook_event("scan_completed", "cloud-tenant",
                               {"job_id": job_id, "domain": domain,
                                "findings_count": findings_count,
                                "providers": [r["provider"] for r in results]})
            _save_session_results(job_id, "cloud-tenant", "osint-runner", [output_file],
                                  metadata={"domain": domain,
                                            "findings_count": findings_count})
        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e),
                                    completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            emit_webhook_event("scan_failed", "cloud-tenant",
                               {"job_id": job_id, "domain": domain, "error": str(e)})
            logging.error(f"[{job_id}] cloud-tenant failed: {e}")

    _job_tracker.update_progress(job_id, targets_count=1, domain=domain)
    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued",
            "domain": domain, "status_url": f"/jobs/{job_id}"}


# ===============================
# Recon Pipeline
# ===============================

@app.post("/jobs/recon-pipeline")
def run_recon_pipeline(req: ReconPipelineReq, background_tasks: BackgroundTasks):
    """Full recon pipeline: auto-detects target types and chains tools."""
    job_id = _job_tracker.create_job(job_type="recon-pipeline")
    classified = _classify_targets(req.targets)
    skip = set(req.skip_phases or [])

    _job_tracker.update_progress(job_id, targets_count=len(req.targets),
                                  stage="queued", domains=len(classified["domains"]),
                                  ips=len(classified["ips"]), asns=len(classified["asns"]),
                                  urls=len(classified["urls"]))

    background_tasks.add_task(
        _run_recon_pipeline, job_id, classified, skip,
        req.uncover_engine or "shodan", req.uncover_limit or 100,
        req.proxy,
    )
    return {"ok": True, "job_id": job_id, "status": "queued",
            "classified": classified, "status_url": f"/jobs/{job_id}"}


# ===============================
# Passive Recon Pipeline
# ===============================

@app.post("/jobs/passive-recon")
def run_passive_recon(req: PassiveReconReq, background_tasks: BackgroundTasks):
    """Passive-only recon pipeline: no port scanning, no brute force, no vuln scanning.
    Chains: subfinder → findomain → dnsdumpster → whois → reverse-whois → dnsx → crtsh → httpx → tlsx → cert-chain → gau → katana → gowitness → whatweb"""
    domains = [t.strip() for t in req.targets if t.strip()]
    if not domains:
        raise HTTPException(status_code=400, detail="No targets provided")

    # Build the phase plan
    phases_plan = ["subfinder", "findomain", "dnsdumpster", "whois", "reverse-whois", "dnsx", "crtsh", "httpx", "tlsx"]
    if req.include_cert_chain:
        phases_plan.append(f"cert-chain (max {req.cert_chain_max_iterations or 2} iterations)")
    phases_plan.append("gau")
    if req.include_spider:
        phases_plan.append(f"katana (depth {req.spider_depth or 2})")
    phases_plan.extend(["gowitness", "whatweb"])

    if req.plan_only:
        return {
            "ok": True,
            "plan_only": True,
            "targets": domains,
            "phases": phases_plan,
            "skipped_tools": ["alterx", "shuffledns", "naabu", "masscan", "nmap", "nuclei", "ffuf", "brutus"],
            "note": "Passive recon only — no active scanning tools will be used",
        }

    job_id = _job_tracker.create_job(job_type="passive-recon")
    _job_tracker.update_progress(job_id, targets_count=len(domains), stage="queued",
                                  domains=len(domains))

    background_tasks.add_task(
        _run_passive_recon, job_id, domains,
        include_spider=req.include_spider or False,
        spider_depth=min(max(req.spider_depth or 2, 1), 5),
        include_cert_chain=req.include_cert_chain if req.include_cert_chain is not None else True,
        cert_chain_max_iterations=min(max(req.cert_chain_max_iterations or 2, 1), 3),
        scope_name=req.scope_name,
        proxy=req.proxy,
    )
    return {"ok": True, "job_id": job_id, "status": "queued",
            "phases": phases_plan, "status_url": f"/jobs/{job_id}"}


def _cert_serial_chain(job_id: str, tlsx_output_file: str, original_domains: list,
                        max_iterations: int = 2) -> dict:
    """Extract cert serials from tlsx results, query crt.sh for related domains.
    Returns dict with new_domains (set), iterations performed, and per-serial results."""
    import time as _time

    all_new_domains = set()
    iteration_results = []
    # Build parent domain set for filtering (e.g. example.com from sub.example.com)
    parent_domains = set()
    for d in original_domains:
        parts = d.strip().split(".")
        if len(parts) >= 2:
            parent_domains.add(".".join(parts[-2:]))

    current_serials = set()
    tlsx_results = _read_jsonl(tlsx_output_file)
    for r in tlsx_results:
        serial = r.get("serial", "")
        if serial:
            current_serials.add(serial)

    seen_serials = set()
    for iteration in range(max_iterations):
        new_serials = current_serials - seen_serials
        if not new_serials:
            logging.info(f"[{job_id}] cert-chain: no new serials at iteration {iteration+1}")
            break
        seen_serials.update(new_serials)

        iter_domains = set()
        for serial in list(new_serials)[:50]:  # Cap serials per iteration
            certs = _query_crtsh_serial(serial, timeout=30)
            for cert in certs:
                for field in ("common_name", "name_value"):
                    val = cert.get(field, "")
                    if not val:
                        continue
                    for name in val.replace("\n", " ").split():
                        name = name.strip().lstrip("*.")
                        if name and "." in name:
                            name_parts = name.split(".")
                            if len(name_parts) >= 2:
                                name_parent = ".".join(name_parts[-2:])
                                if name_parent in parent_domains:
                                    iter_domains.add(name)
            _time.sleep(1)  # Rate limit crt.sh

        new_found = iter_domains - all_new_domains - set(original_domains)
        all_new_domains.update(new_found)
        iteration_results.append({
            "iteration": iteration + 1,
            "serials_queried": len(new_serials),
            "new_domains_found": len(new_found),
        })
        logging.info(f"[{job_id}] cert-chain iteration {iteration+1}: "
                     f"queried {len(new_serials)} serials, found {len(new_found)} new domains")

        # No new serials to chase from this iteration
        current_serials = set()  # Would need another tlsx pass for new serials

    return {
        "new_domains": all_new_domains,
        "iterations": iteration_results,
        "total_new": len(all_new_domains),
    }


def _run_passive_recon(job_id: str, domains: list, include_spider: bool = False,
                        spider_depth: int = 2, include_cert_chain: bool = True,
                        cert_chain_max_iterations: int = 2, scope_name: str = None,
                        proxy: str = None):
    """Background: passive-only recon pipeline."""
    import time as _time
    _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
    emit_webhook_event("scan_started", "passive-recon", {"job_id": job_id})

    phases = {}
    all_output_files = []
    all_hosts = set()
    short = job_id[:8]
    env = _build_proxy_env(proxy)

    total_phases = 14  # subfinder, findomain, dnsdumpster, whois, reverse-whois, dnsx, crtsh, httpx, tlsx, cert-chain, gau, katana, gowitness, whatweb
    phase_num = 0
    pipeline_start = _time.time()

    def _checkpoint(stage_name, detail=""):
        """Update progress with rich checkpoint data."""
        elapsed = round(_time.time() - pipeline_start, 1)
        _job_tracker.update_progress(
            job_id,
            stage=stage_name,
            phase_number=phase_num,
            total_phases=total_phases,
            total_hosts_discovered=len(all_hosts),
            input_domains=len(domains),
            elapsed_seconds=elapsed,
            phases_completed=dict(phases),
            detail=detail,
        )

    try:
        # ---- Phase 0: whois (domain registration & org intel) ----
        phase_num = 0
        _checkpoint("whois", f"Running WHOIS lookup for {len(domains)} domain(s)")
        logging.info(f"[{job_id}] passive-recon phase: whois ({len(domains)} domains)")
        whois_results = {}
        whois_out = str(REPORT_DIR / f"passive_whois_{short}.json")
        for domain in domains:
            try:
                # Strip subdomains — whois needs the registered domain
                parts = domain.strip().split(".")
                if len(parts) > 2:
                    # Handle TLDs like .co.uk, .com.au
                    reg_domain = ".".join(parts[-2:])
                    if parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
                        reg_domain = ".".join(parts[-3:]) if len(parts) > 2 else reg_domain
                else:
                    reg_domain = domain.strip()

                wp = subprocess.run(
                    ["whois", reg_domain],
                    capture_output=True, text=True, timeout=30,
                )
                raw = wp.stdout or ""
                if not raw.strip():
                    whois_results[domain] = {"error": "empty response"}
                    continue

                # Parse key fields from raw WHOIS output
                parsed = {"raw_length": len(raw), "domain": reg_domain}
                field_map = {
                    "registrar": ["Registrar:", "registrar:"],
                    "org": ["Registrant Organization:", "org:", "OrgName:"],
                    "creation_date": ["Creation Date:", "created:", "Registration Date:"],
                    "expiry_date": ["Registry Expiry Date:", "Expiry Date:", "paid-till:"],
                    "updated_date": ["Updated Date:", "last-modified:"],
                    "registrant_country": ["Registrant Country:", "Registrant State/Province:"],
                    "name_servers": ["Name Server:", "nserver:"],
                    "registrant_name": ["Registrant Name:"],
                    "registrant_email": ["Registrant Email:", "e-mail:"],
                    "dnssec": ["DNSSEC:"],
                    "status": ["Domain Status:", "status:"],
                }
                for key, patterns in field_map.items():
                    values = []
                    for pat in patterns:
                        for line in raw.splitlines():
                            if line.strip().lower().startswith(pat.lower()):
                                val = line.split(":", 1)[1].strip()
                                if val and val not in values:
                                    values.append(val)
                    if values:
                        parsed[key] = values if key in ("name_servers", "status") else values[0]

                whois_results[domain] = parsed
                logging.info(f"[{job_id}] whois {domain}: registrar={parsed.get('registrar', '?')}, "
                             f"org={parsed.get('org', '?')}, created={parsed.get('creation_date', '?')}")

            except subprocess.TimeoutExpired:
                whois_results[domain] = {"error": "timeout"}
                logging.warning(f"[{job_id}] whois {domain}: timed out")
            except FileNotFoundError:
                whois_results[domain] = {"error": "whois not installed"}
                logging.warning(f"[{job_id}] whois not found in PATH")
                break
            except Exception as e:
                whois_results[domain] = {"error": str(e)}
                logging.warning(f"[{job_id}] whois {domain}: {e}")

        # Save WHOIS results
        import json as _json
        with open(whois_out, "w") as f:
            _json.dump(whois_results, f, indent=2)
        all_output_files.append(whois_out)

        # Ingest WHOIS as recon_findings
        try:
            conn = __import__("psycopg2").connect(DB_DSN)
            with conn.cursor() as cur:
                for domain, wdata in whois_results.items():
                    if wdata.get("error"):
                        continue
                    cur.execute(
                        """INSERT INTO recon_findings (source, finding_type, target, data, severity)
                           VALUES ('whois', 'whois_record', %s, %s, 'info')
                           ON CONFLICT DO NOTHING""",
                        (domain, _json.dumps(wdata)),
                    )
                conn.commit()
            conn.close()
        except Exception as e:
            logging.warning(f"[{job_id}] whois ingest failed: {e}")

        phases["whois"] = {
            "domains_queried": len(domains),
            "results": {d: {"registrar": r.get("registrar"), "org": r.get("org")}
                        for d, r in whois_results.items() if not r.get("error")},
            "errors": {d: r.get("error") for d, r in whois_results.items() if r.get("error")},
        }
        _checkpoint("whois:done", f"WHOIS complete for {len(whois_results)} domain(s)")

        # ---- Phase 1a: subfinder (passive subdomain enumeration) ----
        phase_num = 1
        _checkpoint("subfinder", f"Enumerating subdomains for {len(domains)} domain(s)")
        logging.info(f"[{job_id}] passive-recon phase: subfinder ({len(domains)} domains)")
        domains_file = _write_targets_file(domains)
        subfinder_out = str(REPORT_DIR / f"passive_subfinder_{short}.jsonl")
        cmd = ["subfinder", "-dL", domains_file, "-json", "-o", subfinder_out, "-silent"]
        if proxy:
            cmd.extend(["-proxy", proxy])
        sf_proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=env)
        sf_results = _read_jsonl(subfinder_out)
        sf_error = None
        if sf_proc.returncode != 0 and not sf_results:
            sf_stderr = (sf_proc.stderr or "").strip()[:200]
            if "rosetta" in sf_stderr.lower() or "elf" in sf_stderr.lower():
                sf_error = "subfinder binary incompatible (ARM/x86 mismatch)"
            elif sf_stderr:
                sf_error = f"subfinder failed: {sf_stderr}"
            else:
                sf_error = "subfinder returned no results"
            logging.warning(f"[{job_id}] subfinder error: {sf_error}")
        for r in sf_results:
            h = r.get("host", "").strip()
            if h:
                all_hosts.add(h)
        _ingest_results("subfinder", subfinder_out, job_id=job_id)
        sf_phase = {"subdomains": len(sf_results)}
        if sf_error:
            sf_phase["error"] = sf_error
        phases["subfinder"] = sf_phase
        all_output_files.append(subfinder_out)
        if sf_error:
            logging.warning(f"[{job_id}] subfinder completed with error: {sf_error}")
            _checkpoint("subfinder:error", f"Subfinder error: {sf_error}. Trying findomain...")
        else:
            logging.info(f"[{job_id}] subfinder done: {len(sf_results)} subdomains")
            _checkpoint("subfinder:done", f"Found {len(sf_results)} subdomains, {len(all_hosts)} unique hosts")
        try:
            os.remove(domains_file)
        except OSError:
            pass

        # ---- Phase 1b: findomain (additional passive subdomain enumeration) ----
        _checkpoint("findomain", f"Running findomain for {len(domains)} domain(s)")
        logging.info(f"[{job_id}] passive-recon phase: findomain ({len(domains)} domains)")
        findomain_hosts = set()
        fd_error = None
        for domain in domains:
            try:
                fd_proc = subprocess.run(
                    ["findomain", "-t", domain, "-q"],
                    capture_output=True, text=True, timeout=300, env=env,
                )
                if fd_proc.returncode == 0 and fd_proc.stdout:
                    for line in fd_proc.stdout.strip().splitlines():
                        h = line.strip()
                        if h and "." in h:
                            findomain_hosts.add(h)
                elif fd_proc.returncode != 0:
                    stderr = (fd_proc.stderr or "").strip()[:200]
                    if "rosetta" in stderr.lower() or "elf" in stderr.lower():
                        fd_error = "findomain binary incompatible (ARM/x86 mismatch)"
                    elif stderr:
                        fd_error = f"findomain failed: {stderr}"
            except FileNotFoundError:
                fd_error = "findomain not installed"
                break
            except subprocess.TimeoutExpired:
                fd_error = "findomain timed out"
            except Exception as e:
                fd_error = f"findomain error: {e}"

        fd_new = len(findomain_hosts - all_hosts)
        all_hosts.update(findomain_hosts)
        fd_phase = {"subdomains": len(findomain_hosts), "new_unique": fd_new}
        if fd_error:
            fd_phase["error"] = fd_error
        phases["findomain"] = fd_phase
        # Ingest findomain results as subfinder format
        if findomain_hosts:
            fd_out = str(REPORT_DIR / f"passive_findomain_{short}.jsonl")
            with open(fd_out, "w") as f:
                for h in findomain_hosts:
                    f.write(json.dumps({"host": h, "source": "findomain"}) + "\n")
            _ingest_results("subfinder", fd_out, job_id=job_id)
            all_output_files.append(fd_out)
        if fd_error:
            logging.warning(f"[{job_id}] findomain error: {fd_error}")
            _checkpoint("findomain:error", f"Findomain: {fd_error}. {fd_new} new hosts added.")
        else:
            logging.info(f"[{job_id}] findomain done: {len(findomain_hosts)} subdomains, {fd_new} new")
            _checkpoint("findomain:done", f"Found {len(findomain_hosts)} subdomains ({fd_new} new) → {len(all_hosts)} total")

        # ---- Phase 1c: dnsdumpster (DNS intelligence) ----
        _checkpoint("dnsdumpster", f"Querying DNSDumpster for {len(domains)} domain(s)")
        logging.info(f"[{job_id}] passive-recon phase: dnsdumpster ({len(domains)} domains)")
        dd_hosts = set()
        dd_records = []
        dd_error = None
        try:
            from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
            dumper = DNSDumpsterAPI()
            for domain in domains:
                try:
                    dd_result = dumper.search(domain)
                    if dd_result:
                        # Extract hosts from DNS records
                        for record_type in ("dns_records", "mx_records", "host_records"):
                            for rec in dd_result.get(record_type, {}).get("dns", []) if isinstance(dd_result.get(record_type), dict) else dd_result.get(record_type, []):
                                host = rec.get("domain", rec.get("host", "")).strip()
                                if host and "." in host:
                                    dd_hosts.add(host)
                                dd_records.append(rec)
                except Exception as e:
                    logging.warning(f"[{job_id}] dnsdumpster failed for {domain}: {e}")
                    dd_error = f"dnsdumpster query failed: {e}"
        except ImportError:
            dd_error = "dnsdumpster package not installed"
        except Exception as e:
            dd_error = f"dnsdumpster error: {e}"

        dd_new = len(dd_hosts - all_hosts)
        all_hosts.update(dd_hosts)
        dd_phase = {"hosts": len(dd_hosts), "new_unique": dd_new, "records": len(dd_records)}
        if dd_error:
            dd_phase["error"] = dd_error
        phases["dnsdumpster"] = dd_phase
        # Ingest dnsdumpster hosts as subfinder format
        if dd_hosts:
            dd_out = str(REPORT_DIR / f"passive_dnsdumpster_{short}.jsonl")
            with open(dd_out, "w") as f:
                for h in dd_hosts:
                    f.write(json.dumps({"host": h, "source": "dnsdumpster"}) + "\n")
            _ingest_results("subfinder", dd_out, job_id=job_id)
            all_output_files.append(dd_out)
        if dd_error:
            logging.warning(f"[{job_id}] dnsdumpster error: {dd_error}")
            _checkpoint("dnsdumpster:error", f"DNSDumpster: {dd_error}")
        else:
            logging.info(f"[{job_id}] dnsdumpster done: {len(dd_hosts)} hosts ({dd_new} new), {len(dd_records)} records")
            _checkpoint("dnsdumpster:done", f"Found {len(dd_hosts)} hosts ({dd_new} new), {len(dd_records)} DNS records → {len(all_hosts)} total")

        # ---- Phase 1d: whois (domain registration data) ----
        _checkpoint("whois", f"Running WHOIS lookups for {len(domains)} domain(s)")
        logging.info(f"[{job_id}] passive-recon phase: whois ({len(domains)} domains)")
        whois_data = {}
        whois_error = None
        for domain in domains:
            try:
                whois_proc = subprocess.run(
                    ["whois", domain],
                    capture_output=True, text=True, timeout=30,
                )
                raw = whois_proc.stdout or ""
                if raw:
                    # Parse key fields
                    parsed = {}
                    for line in raw.splitlines():
                        line = line.strip()
                        if not line or line.startswith("%") or line.startswith("#"):
                            continue
                        if ":" in line:
                            key, _, val = line.partition(":")
                            key = key.strip().lower().replace(" ", "_")
                            val = val.strip()
                            if val and key not in parsed:
                                parsed[key] = val
                    whois_data[domain] = {
                        "registrar": parsed.get("registrar", ""),
                        "creation_date": parsed.get("creation_date", parsed.get("created", "")),
                        "updated_date": parsed.get("updated_date", parsed.get("last_updated", "")),
                        "expiry_date": parsed.get("registry_expiry_date", parsed.get("expiry_date", "")),
                        "name_servers": [v for k, v in parsed.items() if "name_server" in k or "nserver" in k],
                        "registrant_org": parsed.get("registrant_organization", parsed.get("org", "")),
                        "registrant_name": parsed.get("registrant_name", ""),
                        "registrant_email": parsed.get("registrant_email", ""),
                        "registrant_country": parsed.get("registrant_country", parsed.get("country", "")),
                        "tech_email": parsed.get("tech_email", ""),
                        "admin_email": parsed.get("admin_email", ""),
                        "dnssec": parsed.get("dnssec", ""),
                        "status": [v for k, v in parsed.items() if "status" in k][:5],
                        "raw_length": len(raw),
                    }
                    # Also extract name servers as potential hosts
                    for ns in whois_data[domain]["name_servers"]:
                        ns = ns.strip().rstrip(".")
                        if ns and "." in ns:
                            all_hosts.add(ns)
            except subprocess.TimeoutExpired:
                whois_error = f"whois timed out for {domain}"
                logging.warning(f"[{job_id}] whois timeout for {domain}")
            except Exception as e:
                whois_error = f"whois error: {e}"
                logging.warning(f"[{job_id}] whois error for {domain}: {e}")

        # Save whois data
        whois_out = str(REPORT_DIR / f"passive_whois_{short}.json")
        with open(whois_out, "w") as f:
            json.dump(whois_data, f, indent=2)
        all_output_files.append(whois_out)
        whois_phase = {"domains_queried": len(domains), "results": len(whois_data)}
        if whois_error:
            whois_phase["error"] = whois_error
        phases["whois"] = whois_phase
        if whois_data:
            # Build summary for checkpoint
            sample = list(whois_data.values())[0]
            summary = f"Registrar: {sample.get('registrar', '?')}, Org: {sample.get('registrant_org', '?')}, NS: {len(sample.get('name_servers', []))}"
            logging.info(f"[{job_id}] whois done: {summary}")
            _checkpoint("whois:done", f"WHOIS for {len(whois_data)} domain(s) — {summary}")
        else:
            _checkpoint("whois:done", "WHOIS lookup returned no data")

        # ---- Phase 1e: reverse WHOIS (discover related domains by org/email) ----
        import re as _re
        reverse_whois_domains = set()
        rw_queries = []

        # Collect org names and company emails from WHOIS data
        for domain, wd in whois_data.items():
            org = wd.get("registrant_org", "").strip()
            if org and len(org) > 2:
                rw_queries.append(("org", org))

            email = wd.get("registrant_email", "").strip()
            if email and "@" in email:
                # Only use the email if it belongs to the target company domain
                email_domain = email.split("@", 1)[1].lower()
                if any(email_domain.endswith(d.lower()) for d in domains):
                    rw_queries.append(("email", email))

        if rw_queries:
            _checkpoint("reverse-whois", f"Searching for related domains via {len(rw_queries)} WHOIS query(ies)")
            logging.info(f"[{job_id}] passive-recon phase: reverse-whois ({len(rw_queries)} queries)")

            rw_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            rw_error = None
            TLD_PATTERN = r'>([a-z0-9][\w.-]+\.(?:com|net|org|io|co|us|info|biz|edu|gov|tech|cloud|dev|app|xyz|me|tv|cc|uk|de|fr|au|ca|eu|nl|ch|in|jp))<'

            for query_type, query_value in rw_queries:
                try:
                    resp = requests.get(
                        "https://viewdns.info/reversewhois/",
                        params={"q": query_value},
                        headers=rw_headers,
                        timeout=20,
                    )
                    if resp.status_code == 200:
                        found = _re.findall(TLD_PATTERN, resp.text, _re.I)
                        # Filter out noise
                        found = [d.lower() for d in found
                                 if "viewdns" not in d.lower()
                                 and "godaddy" not in d.lower()
                                 and len(d) > 4]
                        reverse_whois_domains.update(found)
                        logging.info(f"[{job_id}] reverse-whois ({query_type}={query_value[:30]}): {len(found)} domains")
                    else:
                        logging.warning(f"[{job_id}] reverse-whois returned {resp.status_code} for {query_type}={query_value[:30]}")
                    # Rate limit between queries
                    import time as _rw_time
                    _rw_time.sleep(2)
                except Exception as e:
                    rw_error = f"reverse-whois failed: {e}"
                    logging.warning(f"[{job_id}] reverse-whois error for {query_value[:30]}: {e}")

            # Add discovered domains to all_hosts
            rw_new = len(reverse_whois_domains - all_hosts)
            all_hosts.update(reverse_whois_domains)

            # Save results
            rw_out = str(REPORT_DIR / f"passive_reverse_whois_{short}.json")
            with open(rw_out, "w") as f:
                json.dump({
                    "queries": [{"type": t, "value": v} for t, v in rw_queries],
                    "domains": sorted(reverse_whois_domains),
                    "total": len(reverse_whois_domains),
                    "new_unique": rw_new,
                }, f, indent=2)
            all_output_files.append(rw_out)

            rw_phase = {"queries": len(rw_queries), "domains_found": len(reverse_whois_domains), "new_unique": rw_new}
            if rw_error:
                rw_phase["error"] = rw_error
            phases["reverse_whois"] = rw_phase
            # Ingest reverse-whois domains as subfinder format
            if reverse_whois_domains:
                rw_jsonl = str(REPORT_DIR / f"passive_reverse_whois_{short}.jsonl")
                with open(rw_jsonl, "w") as f:
                    for h in reverse_whois_domains:
                        f.write(json.dumps({"host": h, "source": "reverse-whois"}) + "\n")
                _ingest_results("subfinder", rw_jsonl, job_id=job_id)
                all_output_files.append(rw_jsonl)
            logging.info(f"[{job_id}] reverse-whois done: {len(reverse_whois_domains)} domains ({rw_new} new)")
            _checkpoint("reverse-whois:done",
                        f"Found {len(reverse_whois_domains)} related domains ({rw_new} new) → {len(all_hosts)} total hosts")
        else:
            phases["reverse_whois"] = "skipped (no org/email in WHOIS)"
            _checkpoint("reverse-whois:skipped", "No usable org name or company email in WHOIS data")

        # ---- Phase 2: dnsx (DNS resolution only) ----
        phase_num = 2
        dnsx_out = None
        if all_hosts:
            _checkpoint("dnsx", f"Resolving DNS for {min(len(all_hosts), 2000)} hosts")
            hosts_list = list(all_hosts)[:2000]
            logging.info(f"[{job_id}] passive-recon phase: dnsx ({len(hosts_list)} hosts)")
            hosts_file = _write_targets_file(hosts_list)
            dnsx_out = str(REPORT_DIR / f"passive_dnsx_{short}.jsonl")
            cmd = ["dnsx", "-l", hosts_file, "-json", "-o", dnsx_out, "-silent",
                   "-a", "-aaaa", "-cname", "-mx", "-ns"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            dnsx_results = _read_jsonl(dnsx_out)
            _ingest_results("dnsx", dnsx_out, job_id=job_id)
            phases["dnsx"] = {"resolved": len(dnsx_results)}
            all_output_files.append(dnsx_out)
            logging.info(f"[{job_id}] dnsx done: {len(dnsx_results)} resolved")
            _checkpoint("dnsx:done", f"Resolved {len(dnsx_results)} DNS records")
            try:
                os.remove(hosts_file)
            except OSError:
                pass
        else:
            phases["dnsx"] = "skipped (no hosts)"
            _checkpoint("dnsx:skipped", "No hosts to resolve")

        # ---- Phase 3: crtsh (CT log search) ----
        phase_num = 3
        _checkpoint("crtsh", f"Searching certificate transparency logs for {len(domains)} domain(s)")
        logging.info(f"[{job_id}] passive-recon phase: crtsh ({len(domains)} domains)")
        crtsh_out = str(REPORT_DIR / f"passive_crtsh_{short}.json")
        crtsh_results = []
        crtsh_errors = []
        new_hosts = set()
        for domain in domains:
            certs = _query_crtsh(domain, timeout=60)
            # Check for error sentinel
            if certs and isinstance(certs[0], dict) and "_error" in certs[0]:
                crtsh_errors.append(certs[0]["_error"])
                logging.warning(f"[{job_id}] crtsh failed for {domain}: {certs[0]['_error']}")
                continue
            seen_ids = set()
            for cert in certs:
                cid = cert.get("id")
                if cid in seen_ids:
                    continue
                seen_ids.add(cid)
                crtsh_results.append(cert)
                for field in ("common_name", "name_value"):
                    val = cert.get(field, "")
                    if not val:
                        continue
                    for name in val.replace("\n", " ").split():
                        name = name.strip().lstrip("*.")
                        if name and "." in name:
                            new_hosts.add(name)
        with open(crtsh_out, "w") as f:
            json.dump(crtsh_results, f)
        _ingest_results("crtsh", crtsh_out, job_id=job_id)
        added = len(new_hosts - all_hosts)
        all_hosts.update(new_hosts)
        crtsh_phase = {"certs": len(crtsh_results), "new_hosts": added}
        if crtsh_errors:
            crtsh_phase["errors"] = crtsh_errors
        phases["crtsh"] = crtsh_phase
        all_output_files.append(crtsh_out)
        if crtsh_errors:
            logging.warning(f"[{job_id}] crtsh completed with errors: {crtsh_errors}")
            _checkpoint("crtsh:error", f"crt.sh service unavailable — {'; '.join(crtsh_errors)}. Found {len(crtsh_results)} certs from working queries.")
        else:
            logging.info(f"[{job_id}] crtsh done: {len(crtsh_results)} certs, {added} new hosts")
            _checkpoint("crtsh:done", f"Found {len(crtsh_results)} certs, {added} new hosts → {len(all_hosts)} total")

        # ---- Phase 4: httpx (HTTP probe discovered hosts, cap 2000) ----
        phase_num = 4
        httpx_out = None
        if all_hosts:
            _checkpoint("httpx", f"Probing {min(len(all_hosts), 2000)} hosts for HTTP services")
            httpx_targets = list(all_hosts)[:2000]
            logging.info(f"[{job_id}] passive-recon phase: httpx ({len(httpx_targets)} targets)")
            hosts_file = _write_targets_file(httpx_targets)
            httpx_out = str(REPORT_DIR / f"passive_httpx_{short}.jsonl")
            cmd = ["httpx", "-l", hosts_file, "-json", "-o", httpx_out, "-silent",
                   "-status-code", "-title", "-web-server", "-content-length",
                   "-follow-redirects", "-tech-detect"]
            if proxy:
                cmd.extend(["-proxy", proxy])
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=env)
            httpx_results = _read_jsonl(httpx_out)
            _ingest_results("httpx", httpx_out, job_id=job_id)
            phases["httpx"] = {"probed": len(httpx_results)}
            all_output_files.append(httpx_out)
            logging.info(f"[{job_id}] httpx done: {len(httpx_results)} probed")
            _checkpoint("httpx:done", f"Probed {len(httpx_results)} live HTTP services")
            try:
                os.remove(hosts_file)
            except OSError:
                pass
        else:
            phases["httpx"] = "skipped (no hosts)"
            _checkpoint("httpx:skipped", "No hosts to probe")

        # ---- Phase 5: tlsx (TLS cert analysis on HTTPS hosts) ----
        phase_num = 5
        tlsx_out = None
        if httpx_out and os.path.exists(httpx_out):
            httpx_results = _read_jsonl(httpx_out)
            tls_hosts = set()
            for r in httpx_results:
                url = r.get("url", "")
                if url.startswith("https://"):
                    host_part = url.replace("https://", "").split("/")[0]
                    tls_hosts.add(host_part)
            tls_hosts = list(tls_hosts)[:1000]
            if tls_hosts:
                _checkpoint("tlsx", f"Analyzing TLS certs for {len(tls_hosts)} HTTPS hosts")
                logging.info(f"[{job_id}] passive-recon phase: tlsx ({len(tls_hosts)} HTTPS hosts)")
                tls_file = _write_targets_file(tls_hosts)
                tlsx_out = str(REPORT_DIR / f"passive_tlsx_{short}.jsonl")
                cmd = ["tlsx", "-l", tls_file, "-json", "-o", tlsx_out, "-silent"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=env)
                tlsx_results = _read_jsonl(tlsx_out)
                _ingest_results("tlsx", tlsx_out, job_id=job_id)
                phases["tlsx"] = {"certs_analyzed": len(tlsx_results)}
                all_output_files.append(tlsx_out)
                logging.info(f"[{job_id}] tlsx done: {len(tlsx_results)} certs")
                _checkpoint("tlsx:done", f"Analyzed {len(tlsx_results)} TLS certificates")
                try:
                    os.remove(tls_file)
                except OSError:
                    pass
            else:
                phases["tlsx"] = "skipped (no HTTPS hosts)"
                _checkpoint("tlsx:skipped", "No HTTPS hosts found")
        else:
            phases["tlsx"] = "skipped"
            _checkpoint("tlsx:skipped", "No httpx results")

        # ---- Phase 6: cert-chain (cert serial number chaining via crt.sh) ----
        phase_num = 6
        if include_cert_chain and tlsx_out and os.path.exists(tlsx_out):
            _checkpoint("cert-chain", "Chaining TLS cert serial numbers via crt.sh")
            logging.info(f"[{job_id}] passive-recon phase: cert-chain")
            chain_result = _cert_serial_chain(job_id, tlsx_out, domains,
                                               max_iterations=cert_chain_max_iterations)
            chain_domains = chain_result["new_domains"]
            phases["cert_chain"] = {
                "new_domains": len(chain_domains),
                "iterations": chain_result["iterations"],
            }
            # Add new domains to scope if scope_name is set
            if chain_domains and scope_name:
                try:
                    for d in list(chain_domains)[:100]:
                        requests.post(
                            f"{API_BASE}/scope/add",
                            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
                            json={"scope_name": scope_name, "target": d,
                                  "target_type": "domain", "source": "cert-chain"},
                            timeout=10,
                        )
                    logging.info(f"[{job_id}] cert-chain: added {len(chain_domains)} domains to scope '{scope_name}'")
                except Exception as e:
                    logging.warning(f"[{job_id}] cert-chain: failed to add domains to scope: {e}")
            # Merge into all_hosts for downstream phases
            all_hosts.update(chain_domains)
            logging.info(f"[{job_id}] cert-chain done: {len(chain_domains)} new domains")
            _checkpoint("cert-chain:done", f"Discovered {len(chain_domains)} new domains via cert chaining → {len(all_hosts)} total")
        else:
            phases["cert_chain"] = "skipped"
            _checkpoint("cert-chain:skipped", "Cert chaining not applicable")

        # ---- Phase 7: gau (historical URLs from Wayback Machine) ----
        phase_num = 7
        _checkpoint("gau", f"Fetching historical URLs from Wayback Machine for {len(domains)} domain(s)")
        logging.info(f"[{job_id}] passive-recon phase: gau ({len(domains)} domains)")
        gau_out = str(REPORT_DIR / f"passive_gau_{short}.txt")
        all_gau = []
        for domain in domains:
            try:
                cmd = ["gau", "--threads", "2", "--o", gau_out, domain]
                subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
            except Exception as e:
                logging.warning(f"[{job_id}] gau {domain} failed: {e}")
        if os.path.exists(gau_out):
            with open(gau_out) as f:
                all_gau = [line.strip() for line in f if line.strip()]
        phases["gau"] = {"urls": len(all_gau)}
        all_output_files.append(gau_out)
        logging.info(f"[{job_id}] gau done: {len(all_gau)} URLs")
        _checkpoint("gau:done", f"Found {len(all_gau)} historical URLs")

        # ---- Phase 8: katana (spider, if enabled) ----
        phase_num = 8
        if include_spider and all_hosts:
            _checkpoint("katana", f"Crawling {min(len(all_hosts), 200)} hosts (depth={spider_depth})")
            katana_targets = [f"https://{h}" for h in list(all_hosts)[:200]]
            logging.info(f"[{job_id}] passive-recon phase: katana ({len(katana_targets)} targets, depth={spider_depth})")
            katana_file = _write_targets_file(katana_targets)
            katana_out = str(REPORT_DIR / f"passive_katana_{short}.jsonl")
            cmd = ["katana", "-list", katana_file, "-json", "-o", katana_out, "-silent",
                   "-d", str(spider_depth), "-js-crawl",
                   "-xhr-extraction", "-form-extraction",
                   "-known-files", "all"]
            if proxy:
                cmd.extend(["-proxy", proxy])
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=env)
            katana_results = _read_jsonl(katana_out)
            phases["katana"] = {"urls_crawled": len(katana_results)}
            all_output_files.append(katana_out)
            logging.info(f"[{job_id}] katana done: {len(katana_results)} URLs crawled")
            _checkpoint("katana:done", f"Crawled {len(katana_results)} URLs")
            try:
                os.remove(katana_file)
            except OSError:
                pass
        else:
            phases["katana"] = "skipped" if not include_spider else "skipped (no hosts)"
            _checkpoint("katana:skipped", "Spider not enabled or no hosts")

        # ---- Phase 9: gowitness (screenshots, cap 200) ----
        phase_num = 9
        if httpx_out and os.path.exists(httpx_out):
            httpx_results = _read_jsonl(httpx_out)
            gw_urls = [r["url"] for r in httpx_results
                       if r.get("url", "").startswith(("http://", "https://"))]
            gw_urls = gw_urls[:200]
            if gw_urls:
                _checkpoint("gowitness", f"Taking screenshots of {len(gw_urls)} live URLs")
                logging.info(f"[{job_id}] passive-recon phase: gowitness ({len(gw_urls)} URLs)")
                gw_dir = str(REPORT_DIR / "screenshots" / f"passive_{short}")
                os.makedirs(gw_dir, exist_ok=True)
                gw_file = _write_targets_file(gw_urls)
                gw_jsonl = str(REPORT_DIR / f"gowitness_passive_{short}.jsonl")
                cmd = ["gowitness", "scan", "file", "-f", gw_file,
                       "-s", gw_dir, "-T", "10",
                       "--screenshot-format", "png",
                       "--write-jsonl", "--write-jsonl-file", gw_jsonl,
                       "--chrome-path", os.environ.get("CHROME_PATH", "/usr/bin/chromium")]
                if proxy:
                    cmd.extend(["--chrome-proxy", proxy])
                subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=env)
                gw_count = len([f for f in os.listdir(gw_dir) if f.endswith(".png")])
                gw_ingested = 0
                if os.path.exists(gw_jsonl):
                    try:
                        gw_ingested = _ingest_gowitness_jsonl(gw_jsonl, gw_dir, job_id)
                    except Exception as e:
                        logging.warning(f"[{job_id}] gowitness ingest failed: {e}")
                phases["gowitness"] = {"screenshots": gw_count, "dir": gw_dir, "findings_ingested": gw_ingested}
                all_output_files.append(gw_dir)
                logging.info(f"[{job_id}] gowitness done: {gw_count} screenshots")
                _checkpoint("gowitness:done", f"Captured {gw_count} screenshots")
                try:
                    os.remove(gw_file)
                except OSError:
                    pass
            else:
                phases["gowitness"] = "skipped (no URLs)"
                _checkpoint("gowitness:skipped", "No live URLs to screenshot")
        else:
            phases["gowitness"] = "skipped"
            _checkpoint("gowitness:skipped", "No httpx results")

        # ---- Phase 10: whatweb (tech fingerprinting, cap 100) ----
        phase_num = 10
        web_targets = set()
        for h in all_hosts:
            web_targets.add(f"http://{h}")
        if web_targets:
            targets_list = list(web_targets)[:100]
            _checkpoint("whatweb", f"Fingerprinting {len(targets_list)} web targets (25 threads, capped from {len(web_targets)})")
            logging.info(f"[{job_id}] passive-recon phase: whatweb ({len(targets_list)} targets, capped from {len(web_targets)})")
            targets_file = _write_targets_file(targets_list)
            whatweb_out = str(REPORT_DIR / f"passive_whatweb_{short}.json")
            cmd = ["whatweb", f"--input-file={targets_file}", f"--log-json={whatweb_out}",
                   "--color=never", "-q", "-a1", "--max-threads=25", "--open-timeout=8", "--read-timeout=10"]
            if proxy:
                cmd.extend(["--proxy", proxy])
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            whatweb_count = 0
            if os.path.exists(whatweb_out):
                try:
                    with open(whatweb_out) as f:
                        whatweb_count = len(json.load(f))
                except Exception:
                    pass
            _ingest_results("whatweb", whatweb_out, job_id=job_id)
            phases["whatweb"] = {"fingerprinted": whatweb_count}
            all_output_files.append(whatweb_out)
            logging.info(f"[{job_id}] whatweb done: {whatweb_count} fingerprinted")
            _checkpoint("whatweb:done", f"Fingerprinted {whatweb_count} web services")
            try:
                os.remove(targets_file)
            except OSError:
                pass
        else:
            phases["whatweb"] = "skipped (no hosts)"
            _checkpoint("whatweb:skipped", "No hosts to fingerprint")

        # ---- Done ----
        elapsed_total = round(_time.time() - pipeline_start, 1)
        _job_tracker.update_progress(
            job_id, stage="done", findings_count=len(all_hosts),
            phase_number=total_phases, total_phases=total_phases,
            total_hosts_discovered=len(all_hosts),
            elapsed_seconds=elapsed_total,
            phases_completed=dict(phases),
            detail=f"Complete: {len(all_hosts)} unique hosts discovered in {elapsed_total}s",
        )
        # Collect errors from phases for the result summary
        phase_errors = []
        for pname, pval in phases.items():
            if isinstance(pval, dict):
                if pval.get("error"):
                    phase_errors.append(f"{pname}: {pval['error']}")
                if pval.get("errors"):
                    for e in pval["errors"]:
                        phase_errors.append(f"{pname}: {e}")

        result = {
            "ok": True,
            "phases": phases,
            "total_unique_hosts": len(all_hosts),
            "reports": all_output_files,
        }
        if phase_errors:
            result["errors"] = phase_errors
            result["warning"] = f"{len(phase_errors)} phase(s) had errors: {'; '.join(phase_errors)}"
        _job_tracker.update_job(job_id, status="completed", result=result,
                                completed_at=datetime.now().isoformat())
        emit_webhook_event("scan_completed", "passive-recon",
                           {"job_id": job_id, "total_unique_hosts": len(all_hosts)})
        _save_session_results(job_id, "passive-recon", "osint-runner",
                              all_output_files, metadata=phases)

    except Exception as e:
        _job_tracker.update_job(job_id, status="failed", error=str(e),
                                completed_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="failed")
        emit_webhook_event("scan_failed", "passive-recon", {"job_id": job_id, "error": str(e)})
        logging.error(f"[{job_id}] passive-recon failed: {e}")


def _run_recon_pipeline(job_id: str, classified: dict, skip: set,
                        uncover_engine: str, uncover_limit: int,
                        proxy: str = None):
    """Background: run the full recon pipeline."""
    _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
    emit_webhook_event("scan_started", "recon-pipeline", {"job_id": job_id})

    phases = {}
    all_output_files = []
    all_hosts = set()

    env = _build_proxy_env(proxy)

    try:
        # --- Domain sub-pipeline and IP/ASN sub-pipeline run in parallel ---
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {}
            if classified["domains"]:
                futures[pool.submit(_pipeline_domains, job_id, classified["domains"], skip, env, proxy)] = "domains"
            if classified["ips"] or classified["asns"]:
                futures[pool.submit(_pipeline_ips_asns, job_id, classified["ips"],
                                    classified["asns"], skip, uncover_engine,
                                    uncover_limit, env)] = "ips_asns"

            for fut in as_completed(futures):
                label = futures[fut]
                try:
                    result = fut.result()
                    phases.update(result.get("phases", {}))
                    all_output_files.extend(result.get("files", []))
                    all_hosts.update(result.get("hosts", set()))
                except Exception as e:
                    logging.error(f"[{job_id}] Pipeline {label} failed: {e}")
                    phases[label + "_error"] = str(e)

        # --- httpx: HTTP probe all discovered hosts ---
        short = job_id[:8]
        httpx_out = None
        original_urls = classified.get("urls", [])
        if "httpx" not in skip and (all_hosts or original_urls):
            _job_tracker.update_progress(job_id, stage="httpx")
            httpx_targets = list(all_hosts)[:2000]
            # Include original IPs too
            for ip in classified.get("ips", []):
                if ip not in httpx_targets:
                    httpx_targets.append(ip)
            # Include original URLs so httpx probes them directly
            for url in original_urls:
                if url not in httpx_targets:
                    httpx_targets.append(url)
            logging.info(f"[{job_id}] Pipeline phase: httpx ({len(httpx_targets)} targets)")
            hosts_file = _write_targets_file(httpx_targets)
            httpx_out = str(REPORT_DIR / f"pipeline_httpx_{short}.jsonl")
            cmd = ["httpx", "-l", hosts_file, "-json", "-o", httpx_out, "-silent",
                   "-status-code", "-title", "-web-server", "-content-length",
                   "-follow-redirects", "-tech-detect"]
            if proxy:
                cmd.extend(["-proxy", proxy])
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600,
                           env=_build_proxy_env(proxy))
            httpx_results = _read_jsonl(httpx_out)
            _ingest_results("httpx", httpx_out, job_id=job_id)
            phases["httpx"] = {"probed": len(httpx_results)}
            all_output_files.append(httpx_out)
            logging.info(f"[{job_id}] httpx done: probed={len(httpx_results)}")
            try:
                os.remove(hosts_file)
            except OSError:
                pass
        else:
            phases["httpx"] = "skipped"

        # --- tlsx: TLS cert analysis on HTTPS hosts from httpx ---
        if "tlsx" not in skip and httpx_out and os.path.exists(httpx_out):
            httpx_results = _read_jsonl(httpx_out)
            tls_hosts = set()
            for r in httpx_results:
                url = r.get("url", "")
                if url.startswith("https://"):
                    # Extract host:port from URL
                    host_part = url.replace("https://", "").split("/")[0]
                    tls_hosts.add(host_part)
            tls_hosts = list(tls_hosts)[:1000]
            if tls_hosts:
                _job_tracker.update_progress(job_id, stage="tlsx")
                logging.info(f"[{job_id}] Pipeline phase: tlsx ({len(tls_hosts)} HTTPS hosts)")
                tls_file = _write_targets_file(tls_hosts)
                tlsx_out = str(REPORT_DIR / f"pipeline_tlsx_{short}.jsonl")
                cmd = ["tlsx", "-l", tls_file, "-json", "-o", tlsx_out, "-silent"]
                tls_env = _build_proxy_env(proxy)
                subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=tls_env)
                tlsx_results = _read_jsonl(tlsx_out)
                _ingest_results("tlsx", tlsx_out, job_id=job_id)
                phases["tlsx"] = {"certs_analyzed": len(tlsx_results)}
                all_output_files.append(tlsx_out)
                logging.info(f"[{job_id}] tlsx done: certs_analyzed={len(tlsx_results)}")
                try:
                    os.remove(tls_file)
                except OSError:
                    pass
            else:
                phases["tlsx"] = "skipped (no HTTPS hosts)"
        else:
            phases["tlsx"] = "skipped"

        # --- GoWitness: screenshot all HTTP services from httpx ---
        if "gowitness" not in skip and httpx_out and os.path.exists(httpx_out):
            httpx_results = _read_jsonl(httpx_out)
            gw_urls = [r["url"] for r in httpx_results
                       if r.get("url", "").startswith(("http://", "https://"))]
            gw_urls = gw_urls[:200]  # cap to avoid timeouts

            if gw_urls:
                _job_tracker.update_progress(job_id, stage="gowitness")
                logging.info(f"[{job_id}] Pipeline phase: gowitness ({len(gw_urls)} URLs)")
                gw_dir = str(REPORT_DIR / "screenshots" / f"pipeline_{short}")
                os.makedirs(gw_dir, exist_ok=True)
                gw_file = _write_targets_file(gw_urls)
                gw_jsonl_pipe = str(REPORT_DIR / f"gowitness_pipeline_{short}.jsonl")
                cmd = ["gowitness", "scan", "file", "-f", gw_file,
                       "-s", gw_dir, "-T", "10",
                       "--screenshot-format", "png",
                       "--write-jsonl", "--write-jsonl-file", gw_jsonl_pipe,
                       "--chrome-path", os.environ.get("CHROME_PATH", "/usr/bin/chromium")]
                if proxy:
                    cmd.extend(["--chrome-proxy", proxy])
                subprocess.run(cmd, capture_output=True, text=True, timeout=3600,
                               env=_build_proxy_env(proxy))
                gw_count = len([f for f in os.listdir(gw_dir) if f.endswith(".png")])
                gw_ingested_pipe = 0
                if os.path.exists(gw_jsonl_pipe):
                    try:
                        gw_ingested_pipe = _ingest_gowitness_jsonl(gw_jsonl_pipe, gw_dir, job_id)
                    except Exception as e:
                        logging.warning(f"[{job_id}] pipeline gowitness ingest failed: {e}")
                phases["gowitness"] = {"screenshots": gw_count, "dir": gw_dir, "findings_ingested": gw_ingested_pipe}
                all_output_files.append(gw_dir)
                logging.info(f"[{job_id}] gowitness done: screenshots={gw_count}, ingested={gw_ingested_pipe}")
                try:
                    os.remove(gw_file)
                except OSError:
                    pass
            else:
                phases["gowitness"] = "skipped (no URLs)"
        else:
            phases["gowitness"] = "skipped"

        # --- WhatWeb: fingerprint all discovered hosts + original IPs + original URLs ---
        web_targets = set()
        for h in all_hosts:
            web_targets.add(f"http://{h}")
        for ip in classified.get("ips", []):
            web_targets.add(f"http://{ip}")
        for url in original_urls:
            web_targets.add(url)

        if "whatweb" not in skip and web_targets:
            _job_tracker.update_progress(job_id, stage="whatweb")
            targets_list = list(web_targets)[:200]
            logging.info(f"[{job_id}] Pipeline phase: whatweb ({len(targets_list)} targets, capped from {len(web_targets)})")

            targets_file = _write_targets_file(targets_list)
            whatweb_out = str(REPORT_DIR / f"pipeline_whatweb_{short}.json")

            cmd = ["whatweb", f"--input-file={targets_file}", f"--log-json={whatweb_out}",
                   "--color=never", "-q", "-a1", "--max-threads=25", "--open-timeout=8", "--read-timeout=10"]
            if proxy:
                cmd.extend(["--proxy", proxy])
            subprocess.run(cmd, capture_output=True, text=True, timeout=900)

            whatweb_count = 0
            if os.path.exists(whatweb_out):
                try:
                    with open(whatweb_out) as f:
                        whatweb_count = len(json.load(f))
                except Exception:
                    pass
            _ingest_results("whatweb", whatweb_out, job_id=job_id)
            phases["whatweb"] = {"fingerprinted": whatweb_count}
            all_output_files.append(whatweb_out)
            logging.info(f"[{job_id}] whatweb done: fingerprinted={whatweb_count}")

            try:
                os.remove(targets_file)
            except OSError:
                pass
        else:
            phases["whatweb"] = "skipped"

        _job_tracker.update_progress(job_id, stage="done",
                                      findings_count=len(all_hosts))

        result = {
            "ok": True,
            "phases": phases,
            "total_unique_subdomains": len(all_hosts),
            "reports": all_output_files,
        }
        _job_tracker.update_job(job_id, status="completed", result=result,
                                completed_at=datetime.now().isoformat())
        emit_webhook_event("scan_completed", "recon-pipeline",
                           {"job_id": job_id, "total_unique_subdomains": len(all_hosts)})

        _save_session_results(job_id, "recon-pipeline", "osint-runner",
                              all_output_files, metadata=phases)

    except Exception as e:
        _job_tracker.update_job(job_id, status="failed", error=str(e),
                                completed_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="failed")
        emit_webhook_event("scan_failed", "recon-pipeline", {"job_id": job_id, "error": str(e)})
        logging.error(f"[{job_id}] recon-pipeline failed: {e}")


def _cymru_asn_lookup(ips: list) -> list:
    """Bulk ASN lookup via Team Cymru DNS (free, no API key needed).
    Queries {reversed_ip}.origin.asn.cymru.com TXT records."""
    import subprocess as _sp
    results = []
    for ip in ips:
        try:
            parts = ip.strip().split(".")
            if len(parts) != 4:
                continue
            reversed_ip = ".".join(reversed(parts))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            cp = _sp.run(["dig", "+short", "TXT", query], capture_output=True, text=True, timeout=10)
            for line in cp.stdout.strip().splitlines():
                line = line.strip().strip('"')
                if not line:
                    continue
                # Format: "ASN | CIDR | CC | RIR | Date"
                fields = [f.strip() for f in line.split("|")]
                if len(fields) >= 3:
                    results.append({
                        "input": ip,
                        "as_number": f"AS{fields[0]}" if fields[0] and not fields[0].startswith("AS") else fields[0],
                        "as_range": fields[1] if len(fields) > 1 else "",
                        "as_country": fields[2] if len(fields) > 2 else "",
                    })
                    break  # Take first result per IP
        except Exception:
            continue
    # Deduplicate by IP
    seen = set()
    deduped = []
    for r in results:
        if r["input"] not in seen:
            seen.add(r["input"])
            deduped.append(r)
    return deduped


# Now look up AS names for the ASN numbers via peer.asn.cymru.com
def _cymru_enrich_as_names(results: list) -> list:
    """Enrich ASN results with org names from Team Cymru."""
    import subprocess as _sp
    asn_names = {}
    for r in results:
        asn = r.get("as_number", "").replace("AS", "")
        if asn and asn not in asn_names:
            try:
                query = f"AS{asn}.asn.cymru.com"
                cp = _sp.run(["dig", "+short", "TXT", query], capture_output=True, text=True, timeout=10)
                for line in cp.stdout.strip().splitlines():
                    line = line.strip().strip('"')
                    fields = [f.strip() for f in line.split("|")]
                    if len(fields) >= 5:
                        asn_names[asn] = fields[4]
                        break
            except Exception:
                pass
    for r in results:
        asn = r.get("as_number", "").replace("AS", "")
        if asn in asn_names:
            r["as_name"] = asn_names[asn]
    return results


def _pipeline_domains(job_id: str, domains: list, skip: set, env: dict, proxy: str = None) -> dict:
    """Domain sub-pipeline: subfinder+chaos → alterx → shuffledns → dnsx."""
    phases = {}
    files = []
    all_hosts = set()
    short = job_id[:8]

    # ---- Phase 1: passive-enum (subfinder + chaos in parallel) ----
    if "passive-enum" not in skip:
        _job_tracker.update_progress(job_id, stage="passive-enum")
        logging.info(f"[{job_id}] Pipeline phase: passive-enum")

        domains_file = _write_targets_file(domains)
        subfinder_out = str(REPORT_DIR / f"pipeline_subfinder_{short}.jsonl")
        chaos_merged = str(REPORT_DIR / f"pipeline_chaos_{short}.jsonl")

        subfinder_count = 0
        chaos_count = 0

        with ThreadPoolExecutor(max_workers=2) as pool:
            def _run_subfinder():
                cmd = ["subfinder", "-dL", domains_file, "-json", "-o", subfinder_out, "-silent"]
                if proxy:
                    cmd.extend(["-proxy", proxy])
                subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=env)
                return _read_jsonl(subfinder_out)

            def _run_chaos():
                all_results = []
                for domain in domains:
                    out = str(REPORT_DIR / f"pipeline_chaos_{short}_{domain}.jsonl")
                    cmd = ["chaos", "-d", domain, "-json", "-o", out, "-silent"]
                    subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
                    all_results.extend(_read_jsonl(out))
                    files.append(out)
                # Write merged chaos output
                with open(chaos_merged, "w") as f:
                    for r in all_results:
                        f.write(json.dumps(r) + "\n")
                return all_results

            sf_future = pool.submit(_run_subfinder)
            ch_future = pool.submit(_run_chaos)

            sf_results = sf_future.result()
            ch_results = ch_future.result()

        subfinder_count = len(sf_results)
        chaos_count = len(ch_results)

        # Merge and deduplicate hosts
        for r in sf_results:
            h = r.get("host", "").strip()
            if h:
                all_hosts.add(h)
        for r in ch_results:
            h = r.get("domain", r.get("host", "")).strip()
            if h:
                all_hosts.add(h)

        files.extend([subfinder_out, chaos_merged])

        # Ingest subfinder results
        _ingest_results("subfinder", subfinder_out, job_id=job_id)
        if os.path.exists(chaos_merged) and os.path.getsize(chaos_merged) > 0:
            _ingest_results("subfinder", chaos_merged, job_id=job_id)

        phases["passive_enum"] = {"subfinder": subfinder_count, "chaos": chaos_count}
        logging.info(f"[{job_id}] passive-enum done: subfinder={subfinder_count}, chaos={chaos_count}")

        # Clean up temp file
        try:
            os.remove(domains_file)
        except OSError:
            pass
    else:
        phases["passive_enum"] = "skipped"

    # ---- Phase 2: alterx ----
    if "alterx" not in skip and all_hosts:
        _job_tracker.update_progress(job_id, stage="alterx")
        logging.info(f"[{job_id}] Pipeline phase: alterx ({len(all_hosts)} hosts)")

        hosts_file = _write_targets_file(list(all_hosts))
        alterx_out = str(REPORT_DIR / f"pipeline_alterx_{short}.txt")

        cmd = ["alterx", "-l", hosts_file, "-o", alterx_out, "-silent"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        wordlist = _read_plain_lines(alterx_out)
        phases["alterx"] = {"wordlist_size": len(wordlist)}
        files.append(alterx_out)
        logging.info(f"[{job_id}] alterx done: wordlist_size={len(wordlist)}")

        try:
            os.remove(hosts_file)
        except OSError:
            pass
    else:
        alterx_out = None
        phases["alterx"] = "skipped"

    # ---- Phase 3: shuffledns ----
    if "shuffledns" not in skip and alterx_out and os.path.exists(alterx_out):
        wordlist = _read_plain_lines(alterx_out)
        if wordlist:
            _job_tracker.update_progress(job_id, stage="shuffledns")
            logging.info(f"[{job_id}] Pipeline phase: shuffledns (wordlist={len(wordlist)})")

            domains_file = _write_targets_file(domains)
            shuffledns_out = str(REPORT_DIR / f"pipeline_shuffledns_{short}.jsonl")
            resolvers = "/runner/resolvers.txt"

            cmd = ["shuffledns", "-list", domains_file, "-w", alterx_out,
                   "-r", resolvers, "-json", "-o", shuffledns_out, "-silent"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

            shuf_results = _read_jsonl(shuffledns_out)
            for r in shuf_results:
                h = r.get("host", r.get("hostname", "")).strip()
                if h:
                    all_hosts.add(h)

            _ingest_results("subfinder", shuffledns_out, job_id=job_id)
            phases["shuffledns"] = {"findings": len(shuf_results)}
            files.append(shuffledns_out)
            logging.info(f"[{job_id}] shuffledns done: findings={len(shuf_results)}")

            try:
                os.remove(domains_file)
            except OSError:
                pass
        else:
            phases["shuffledns"] = "skipped (empty wordlist)"
    else:
        phases["shuffledns"] = "skipped"

    # ---- Phase 4: dnsx ----
    dnsx_out = None
    dnsx_results = []
    if "dnsx" not in skip and all_hosts:
        _job_tracker.update_progress(job_id, stage="dnsx")
        hosts_list = list(all_hosts)[:2000]  # Cap at 2000
        logging.info(f"[{job_id}] Pipeline phase: dnsx ({len(hosts_list)} hosts)")

        hosts_file = _write_targets_file(hosts_list)
        dnsx_out = str(REPORT_DIR / f"pipeline_dnsx_{short}.jsonl")

        cmd = ["dnsx", "-l", hosts_file, "-json", "-o", dnsx_out, "-silent",
               "-a", "-aaaa", "-cname", "-mx", "-ns"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

        dnsx_results = _read_jsonl(dnsx_out)
        _ingest_results("dnsx", dnsx_out, job_id=job_id)
        phases["dnsx"] = {"resolved": len(dnsx_results)}
        files.append(dnsx_out)
        logging.info(f"[{job_id}] dnsx done: resolved={len(dnsx_results)}")

        try:
            os.remove(hosts_file)
        except OSError:
            pass
    else:
        phases["dnsx"] = "skipped"

    # ---- Phase 5: crtsh (CT log search) ----
    if "crtsh" not in skip and domains:
        _job_tracker.update_progress(job_id, stage="crtsh")
        logging.info(f"[{job_id}] Pipeline phase: crtsh ({len(domains)} domains)")
        crtsh_out = str(REPORT_DIR / f"pipeline_crtsh_{short}.json")
        crtsh_results = []
        new_hosts = set()
        for domain in domains:
            certs = _query_crtsh(domain, timeout=60)
            seen_ids = set()
            for cert in certs:
                cid = cert.get("id")
                if cid in seen_ids:
                    continue
                seen_ids.add(cid)
                crtsh_results.append(cert)
                for field in ("common_name", "name_value"):
                    val = cert.get(field, "")
                    if not val:
                        continue
                    for name in val.replace("\n", " ").split():
                        name = name.strip().lstrip("*.")
                        if name and "." in name:
                            new_hosts.add(name)
            if certs:
                logging.info(f"[{job_id}] crtsh {domain}: {len(seen_ids)} unique certs")

        with open(crtsh_out, "w") as f:
            json.dump(crtsh_results, f)
        _ingest_results("crtsh", crtsh_out, job_id=job_id)
        added = len(new_hosts - all_hosts)
        all_hosts.update(new_hosts)
        phases["crtsh"] = {"certs": len(crtsh_results), "new_hosts": added}
        files.append(crtsh_out)
        logging.info(f"[{job_id}] crtsh done: certs={len(crtsh_results)}, new_hosts={added}")
    else:
        phases["crtsh"] = "skipped"

    # ---- Phase 6: censys (subdomain discovery via API) ----
    api_keys = _get_api_keys()
    censys_id = api_keys.get("CENSYS_API_ID", "")
    censys_secret = api_keys.get("CENSYS_API_SECRET", "")
    if "censys" not in skip and domains and censys_id and censys_secret:
        _job_tracker.update_progress(job_id, stage="censys")
        logging.info(f"[{job_id}] Pipeline phase: censys ({len(domains)} domains)")
        censys_out = str(REPORT_DIR / f"pipeline_censys_{short}.json")
        censys_results = []
        new_hosts = set()
        try:
            from censys.search import CensysHosts
            kwargs = {"api_id": censys_id, "api_secret": censys_secret}
            if proxy:
                kwargs["proxies"] = {"https": proxy, "http": proxy}
            h = CensysHosts(**kwargs)
            for domain in domains:
                try:
                    query = f"services.tls.certificates.leaf.names: {domain}"
                    for page in h.search(query, per_page=100, pages=2):
                        for hit in page:
                            censys_results.append(hit)
                            name = hit.get("name", "")
                            if name and "." in name:
                                new_hosts.add(name.lstrip("*."))
                except Exception as e:
                    logging.warning(f"[{job_id}] censys search {domain} failed: {e}")
        except ImportError:
            logging.warning(f"[{job_id}] censys python module not available, skipping")

        with open(censys_out, "w") as f:
            json.dump(censys_results, f)
        _ingest_results("censys", censys_out, job_id=job_id)
        added = len(new_hosts - all_hosts)
        all_hosts.update(new_hosts)
        phases["censys"] = {"results": len(censys_results), "new_hosts": added}
        files.append(censys_out)
        logging.info(f"[{job_id}] censys done: results={len(censys_results)}, new_hosts={added}")
    else:
        reason = "skipped"
        if "censys" not in skip and not (censys_id and censys_secret):
            reason = "skipped (no API keys)"
        phases["censys"] = reason

    # ---- Phase 7: asnmap (ASN mapping for resolved IPs) ----
    if "asnmap" not in skip and dnsx_results:
        resolved_ips = set()
        for r in dnsx_results:
            for ip in r.get("a", []):
                resolved_ips.add(ip)
        resolved_ips = list(resolved_ips)[:500]  # Cap at 500
        if resolved_ips:
            _job_tracker.update_progress(job_id, stage="asnmap")
            logging.info(f"[{job_id}] Pipeline phase: asnmap ({len(resolved_ips)} IPs)")
            ips_file = _write_targets_file(resolved_ips)
            asnmap_out = str(REPORT_DIR / f"pipeline_asnmap_{short}.jsonl")
            cmd = ["asnmap", "-l", ips_file, "-json", "-o", asnmap_out, "-silent"]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
            asnmap_results = _read_jsonl(asnmap_out)

            # Fallback: if asnmap returned 0 results (e.g. PDCP auth required),
            # use Team Cymru DNS for ASN lookups
            if not asnmap_results:
                logging.info(f"[{job_id}] asnmap returned 0 results, using Team Cymru DNS fallback")
                asnmap_results = _cymru_asn_lookup(resolved_ips)
                asnmap_results = _cymru_enrich_as_names(asnmap_results)
                if asnmap_results:
                    with open(asnmap_out, "w") as f:
                        for rec in asnmap_results:
                            f.write(json.dumps(rec) + "\n")

            _ingest_results("recon", asnmap_out, job_id=job_id, source="asnmap")
            phases["asnmap"] = {"mappings": len(asnmap_results)}
            files.append(asnmap_out)
            logging.info(f"[{job_id}] asnmap done: mappings={len(asnmap_results)}")
            try:
                os.remove(ips_file)
            except OSError:
                pass
        else:
            phases["asnmap"] = "skipped (no resolved IPs)"
    else:
        phases.setdefault("asnmap", "skipped")

    return {"phases": phases, "files": files, "hosts": all_hosts}


def _pipeline_ips_asns(job_id: str, ips: list, asns: list, skip: set,
                       uncover_engine: str, uncover_limit: int, env: dict) -> dict:
    """IP/ASN sub-pipeline: asnmap + uncover in parallel."""
    phases = {}
    files = []
    hosts = set()
    short = job_id[:8]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}

        # ---- asnmap for ASNs ----
        if asns and "asnmap" not in skip:
            def _run_asnmap():
                _job_tracker.update_progress(job_id, stage="asnmap")
                logging.info(f"[{job_id}] Pipeline phase: asnmap ({len(asns)} ASNs)")
                targets_file = _write_targets_file(asns)
                asnmap_out = str(REPORT_DIR / f"pipeline_asnmap_{short}.jsonl")
                cmd = ["asnmap", "-l", targets_file, "-json", "-o", asnmap_out, "-silent"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results = _read_jsonl(asnmap_out)
                _ingest_results("recon", asnmap_out, job_id=job_id, source="asnmap")
                try:
                    os.remove(targets_file)
                except OSError:
                    pass
                return {"phase": "asnmap", "count": len(results), "file": asnmap_out}

            futures[pool.submit(_run_asnmap)] = "asnmap"

        # ---- uncover for IPs ----
        if ips and "uncover" not in skip:
            def _run_uncover():
                _job_tracker.update_progress(job_id, stage="uncover")
                logging.info(f"[{job_id}] Pipeline phase: uncover ({len(ips)} IPs)")
                all_results = []
                out_files = []
                for ip in ips:
                    out = str(REPORT_DIR / f"pipeline_uncover_{short}_{ip.replace('/', '_')}.jsonl")
                    cmd = ["uncover", "-q", ip, "-json", "-o", out, "-silent",
                           "-limit", str(uncover_limit), "-e", uncover_engine]
                    subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
                    all_results.extend(_read_jsonl(out))
                    out_files.append(out)
                # Merge
                merged = str(REPORT_DIR / f"pipeline_uncover_{short}.jsonl")
                with open(merged, "w") as f:
                    for r in all_results:
                        f.write(json.dumps(r) + "\n")
                _ingest_results("recon", merged, job_id=job_id)
                return {"phase": "uncover", "count": len(all_results),
                        "file": merged, "extra_files": out_files}

            futures[pool.submit(_run_uncover)] = "uncover"

        for fut in as_completed(futures):
            label = futures[fut]
            try:
                result = fut.result()
                phases[result["phase"]] = {"findings": result["count"]}
                files.append(result["file"])
                files.extend(result.get("extra_files", []))
            except Exception as e:
                logging.error(f"[{job_id}] Pipeline {label} failed: {e}")
                phases[label] = {"error": str(e)}

    if not asns or "asnmap" in skip:
        phases.setdefault("asnmap", "skipped")
    if not ips or "uncover" in skip:
        phases.setdefault("uncover", "skipped")

    return {"phases": phases, "files": files, "hosts": hosts}


# ===============================
# New Tool Endpoints: Amass, GAU, Waybackurls, TruffleHog
# ===============================

@app.post("/jobs/amass")
def run_amass(req: AmassReq, background_tasks: BackgroundTasks):
    """Passive subdomain enumeration with Amass."""
    job_id = _job_tracker.create_job(job_type="amass")
    short = job_id[:8]
    output_prefix = str(REPORT_DIR / f"amass_{short}")
    output_file = output_prefix + ".json"

    # amass v4: -d domain (one per flag), -o output prefix
    cmd = ["amass", "enum"]
    for d in req.domains:
        cmd.extend(["-d", d])
    cmd.extend(["-o", output_prefix])
    if req.passive:
        cmd.append("-passive")

    env = _build_proxy_env(req.proxy)
    _job_tracker.update_progress(job_id, targets_count=len(req.domains))
    # amass writes output_prefix.json automatically
    background_tasks.add_task(_run_tool_job, job_id, "amass", cmd, "", output_file, env=env, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/gau")
def run_gau(req: GauReq, background_tasks: BackgroundTasks):
    """Fetch known URLs from web archives (GAU)."""
    job_id = _job_tracker.create_job(job_type="gau")
    targets_file = _write_targets_file(req.domains)
    output_file = str(REPORT_DIR / f"gau_{job_id[:8]}.txt")

    # gau reads domains from stdin: cat domains.txt | gau --subs --o output.txt
    cmd = ["sh", "-c", f"cat {targets_file} | gau --subs --o {output_file}"]
    if req.providers:
        cmd[-1] = f"cat {targets_file} | gau --subs --o {output_file} --providers {req.providers}"

    env = _build_proxy_env(req.proxy)
    _job_tracker.update_progress(job_id, targets_count=len(req.domains))
    background_tasks.add_task(_run_tool_job, job_id, "gau", cmd, targets_file, output_file, env=env, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/waybackurls")
def run_waybackurls(req: WaybackurlsReq, background_tasks: BackgroundTasks):
    """Fetch historical URLs from Wayback Machine."""
    job_id = _job_tracker.create_job(job_type="waybackurls")
    targets_file = _write_targets_file(req.domains)
    output_file = str(REPORT_DIR / f"waybackurls_{job_id[:8]}.txt")

    # waybackurls reads from stdin, so use shell pipe: cat targets | waybackurls > output
    cmd = ["sh", "-c", f"cat {targets_file} | waybackurls > {output_file}"]

    env = _build_proxy_env(req.proxy)
    _job_tracker.update_progress(job_id, targets_count=len(req.domains))
    background_tasks.add_task(_run_tool_job, job_id, "waybackurls", cmd, targets_file, output_file,
                              ingest_as="waybackurls", env=env, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/trufflehog")
def run_trufflehog(req: TrufflehogReq, background_tasks: BackgroundTasks):
    """Scan for leaked secrets with TruffleHog."""
    job_id = _job_tracker.create_job(job_type="trufflehog")
    output_file = str(REPORT_DIR / f"trufflehog_{job_id[:8]}.jsonl")

    scan_type = req.scan_type or "git"
    allowed_types = {"git", "github", "filesystem", "s3"}
    if scan_type not in allowed_types:
        raise HTTPException(status_code=400, detail=f"scan_type must be one of: {allowed_types}")

    cmd = ["trufflehog", scan_type, req.target, "--json", "--output", output_file]

    env = _build_proxy_env(req.proxy)
    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run_tool_job, job_id, "trufflehog", cmd, None, output_file, env=env, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.post("/jobs/censys")
def run_censys(req: CensysReq, background_tasks: BackgroundTasks):
    """Search Censys for hosts, certificates, or subdomains."""
    job_id = _job_tracker.create_job(job_type="censys")
    output_file = str(REPORT_DIR / f"censys_{job_id[:8]}.jsonl")

    search_type = req.search_type or "hosts"
    allowed_types = {"hosts", "certs", "subdomains"}
    if search_type not in allowed_types:
        raise HTTPException(status_code=400, detail=f"search_type must be one of: {allowed_types}")

    def _run_censys_job():
        try:
            import time as _time
            _t0 = _time.time()
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")

            emit_webhook_event("scan_started", "censys", {"job_id": job_id, "scan_type": "censys"})
            write_audit("scan_started", "censys", "osint_runner", {
                "job_id": job_id, "execution_mode": "local",
            })

            env_keys = _get_api_keys()
            api_id = env_keys.get("CENSYS_API_ID", "")
            api_secret = env_keys.get("CENSYS_API_SECRET", "")
            if not api_id or not api_secret:
                raise ValueError("CENSYS_API_ID and CENSYS_API_SECRET must be configured (Settings > API Keys)")

            # Set proxy env vars so the censys SDK (uses requests) routes through SOCKS tunnel
            _old_proxy = {}
            if req.proxy:
                for var in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
                    _old_proxy[var] = os.environ.get(var)
                    os.environ[var] = req.proxy

            results = []

            if search_type == "subdomains":
                from censys.search import CensysHosts
                h = CensysHosts(api_id=api_id, api_secret=api_secret)
                hostnames = h.aggregate(
                    f"services.tls.certificates.leaf.names: {req.query}",
                    "dns.names", num_buckets=req.per_page or 100,
                )
                for bucket in hostnames.get("buckets", []):
                    name = bucket.get("key", "")
                    if name:
                        results.append({
                            "type": "subdomain",
                            "name": name,
                            "count": bucket.get("doc_count", 0),
                            "query": req.query,
                        })

            elif search_type == "certs":
                from censys.search import CensysCerts
                c = CensysCerts(api_id=api_id, api_secret=api_secret)
                pages_fetched = 0
                for page in c.search(req.query, per_page=min(req.per_page or 100, 100), pages=req.pages or 1):
                    for cert in page:
                        results.append({
                            "type": "certificate",
                            "fingerprint": cert.get("fingerprint_sha256", ""),
                            "names": cert.get("names", []),
                            "issuer": cert.get("parsed", {}).get("issuer_dn", ""),
                            "not_before": cert.get("parsed", {}).get("validity", {}).get("start", ""),
                            "not_after": cert.get("parsed", {}).get("validity", {}).get("end", ""),
                            "query": req.query,
                        })
                    pages_fetched += 1
                    if pages_fetched >= (req.pages or 1):
                        break

            else:  # hosts
                from censys.search import CensysHosts
                h = CensysHosts(api_id=api_id, api_secret=api_secret)
                query = h.search(req.query, per_page=min(req.per_page or 100, 100), pages=req.pages or 1)
                pages_fetched = 0
                for page in query:
                    for host in page:
                        results.append({
                            "type": "host",
                            "ip": host.get("ip", ""),
                            "services": [
                                {
                                    "port": svc.get("port", 0),
                                    "service_name": svc.get("service_name", ""),
                                    "transport_protocol": svc.get("transport_protocol", ""),
                                    "banner": svc.get("banner", "")[:500] if svc.get("banner") else "",
                                }
                                for svc in host.get("services", [])
                            ],
                            "location": host.get("location", {}),
                            "autonomous_system": host.get("autonomous_system", {}),
                            "operating_system": host.get("operating_system", {}),
                            "query": req.query,
                        })
                    pages_fetched += 1
                    if pages_fetched >= (req.pages or 1):
                        break

            # Restore proxy env vars
            if req.proxy:
                for var, old_val in _old_proxy.items():
                    if old_val is None:
                        os.environ.pop(var, None)
                    else:
                        os.environ[var] = old_val

            # Write results to JSONL
            with open(output_file, "w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")

            logging.info(f"[{job_id}] Censys {search_type} returned {len(results)} results")

            # Ingest results
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                try:
                    with open(output_file, "rb") as uf:
                        resp = requests.post(
                            f"{API_BASE}/ingest/censys",
                            files={"file": (f"censys_{job_id[:8]}.jsonl", uf, "application/x-ndjson")},
                            params={"job_id": job_id, "search_type": search_type},
                            headers={"x-api-key": API_KEY},
                            timeout=120,
                        )
                    logging.info(f"[{job_id}] Censys ingest response: {resp.status_code}")
                except Exception as e:
                    logging.warning(f"[{job_id}] Censys ingest failed: {e}")

            _save_session_results(job_id, "censys", "censys", [output_file])
            elapsed = _time.time() - _t0
            _job_tracker.update_job(job_id, status="done", completed_at=datetime.now().isoformat(),
                                     result={"records": len(results), "output_file": output_file})
            emit_webhook_event("scan_completed", "censys", {
                "job_id": job_id, "scan_type": "censys", "records": len(results), "elapsed_sec": round(elapsed, 1),
            })
            write_audit("scan_completed", "censys", "osint_runner", {
                "job_id": job_id, "execution_mode": "local", "records": len(results),
            })
        except Exception as e:
            logging.error(f"[{job_id}] Censys error: {e}")
            _job_tracker.update_job(job_id, status="error", error=str(e))
            emit_webhook_event("scan_failed", "censys", {"job_id": job_id, "error": str(e)})
            write_audit("scan_failed", "censys", "osint_runner", {"job_id": job_id, "error": str(e)})

    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run_censys_job)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


# ===============================
# GoWitness Screenshot Endpoints
# ===============================

def _ingest_gowitness_jsonl(jsonl_path: str, screenshot_dir: str, job_id: str) -> int:
    """Ingest GoWitness JSONL results into web_findings and screenshot_metadata.

    GoWitness JSONL contains per-URL records with:
    - url, final_url (after redirects), status_code, title
    - headers, tls info, console logs
    - screenshot filename, content length
    """
    import psycopg2 as _pg
    from psycopg2.extras import RealDictCursor as _RDC
    from urllib.parse import urlparse as _up

    ingested = 0
    try:
        conn = _pg.connect(DB_DSN)
        with conn.cursor(cursor_factory=_RDC) as cur:
            with open(jsonl_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    url = rec.get("url") or rec.get("final_url") or ""
                    if not url or rec.get("failed"):
                        continue

                    status_code = rec.get("response_code") or rec.get("status_code")
                    title = rec.get("title") or ""
                    final_url = rec.get("final_url") or url
                    content_length = rec.get("content_length") or 0
                    screenshot_file = rec.get("file_name") or rec.get("screenshot") or rec.get("filename") or ""

                    # GoWitness v3: headers is a list of {key, value} dicts
                    raw_headers = rec.get("headers") or []
                    headers = {}
                    if isinstance(raw_headers, list):
                        for h in raw_headers:
                            if isinstance(h, dict) and h.get("key"):
                                headers[h["key"]] = h.get("value", "")
                    elif isinstance(raw_headers, dict):
                        headers = raw_headers

                    # GoWitness v3: technologies is a list of {value} dicts
                    raw_tech = rec.get("technologies") or []
                    technologies = []
                    if isinstance(raw_tech, list):
                        for t in raw_tech:
                            if isinstance(t, dict) and t.get("value"):
                                technologies.append(t["value"])
                            elif isinstance(t, str):
                                technologies.append(t)

                    tls_info = rec.get("tls") or {}
                    console_logs = rec.get("console") or []

                    # Build evidence string
                    evidence_parts = []
                    if status_code:
                        evidence_parts.append(f"Status: {status_code}")
                    if title:
                        evidence_parts.append(f"Title: {title}")
                    server = headers.get("server") or headers.get("Server") or ""
                    if server:
                        evidence_parts.append(f"Server: {server}")
                    if technologies:
                        evidence_parts.append(f"Tech: {', '.join(technologies[:5])}")
                    if final_url != url:
                        evidence_parts.append(f"Redirected: {final_url}")
                    evidence = " | ".join(evidence_parts) if evidence_parts else None

                    # Extract interesting headers for refs
                    refs = {}
                    for hdr_key in ("x-powered-by", "x-aspnet-version", "x-generator",
                                    "server", "via", "x-frame-options", "content-security-policy",
                                    "strict-transport-security", "x-content-type-options"):
                        val = headers.get(hdr_key)
                        if val:
                            refs[hdr_key] = val
                    if technologies:
                        refs["technologies"] = technologies
                    if tls_info and isinstance(tls_info, dict):
                        refs["tls"] = {k: v for k, v in tls_info.items() if k != "id" and k != "resultid" and v}
                    if console_logs:
                        refs["console_logs"] = console_logs[:10] if isinstance(console_logs, list) else []
                    if final_url != url:
                        refs["redirect_to"] = final_url

                    # Resolve or create asset
                    asset_id = None
                    try:
                        parsed = _up(url)
                        hostname = parsed.hostname
                        if hostname:
                            cur.execute("SELECT id FROM assets WHERE hostname = %s LIMIT 1", (hostname,))
                            row = cur.fetchone()
                            if row:
                                asset_id = str(row["id"])
                            else:
                                # Resolve and create asset
                                import socket as _sock
                                try:
                                    resolved_ip = _sock.gethostbyname(hostname)
                                except _sock.gaierror:
                                    resolved_ip = "0.0.0.0"
                                import uuid as _uuid
                                _aid = str(_uuid.uuid4())
                                cur.execute("""INSERT INTO assets (id, ip, hostname)
                                              VALUES (%s, %s::inet, %s)
                                              ON CONFLICT (ip, COALESCE(hostname, '')) DO UPDATE SET last_seen = now()
                                              RETURNING id""",
                                            (_aid, resolved_ip, hostname))
                                r = cur.fetchone()
                                if r:
                                    asset_id = str(r["id"])
                    except Exception:
                        pass

                    # Determine screenshot relative path
                    screenshot_path = ""
                    if screenshot_file:
                        # GoWitness puts screenshots in the -s dir
                        dir_name = os.path.basename(screenshot_dir)
                        fname = os.path.basename(screenshot_file)
                        screenshot_path = f"{dir_name}/{fname}"

                    # Build data JSONB for recon_findings
                    finding_data = {
                        "url": url,
                        "final_url": final_url,
                        "status_code": status_code,
                        "title": title,
                        "server": server,
                        "content_length": content_length,
                        "screenshot": screenshot_path,
                        "technologies": technologies,
                        "protocol": rec.get("protocol", ""),
                        "headers": {k: v for k, v in headers.items()},
                    }
                    if tls_info and isinstance(tls_info, dict):
                        finding_data["tls"] = {k: v for k, v in tls_info.items() if k not in ("id", "resultid") and v}
                    if final_url != url:
                        finding_data["redirect_to"] = final_url
                    if console_logs:
                        finding_data["console_logs"] = console_logs[:5]

                    # Resolve target (hostname from URL)
                    target_host = ""
                    try:
                        target_host = _up(url).hostname or ""
                    except Exception:
                        pass

                    # Insert into recon_findings (OSINT Explorer source)
                    cur.execute("""
                        INSERT INTO recon_findings
                        (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (gen_random_uuid(), %s, 'gowitness', 'screenshot', %s, %s, 'recon')
                    """, (asset_id, target_host or url, json.dumps(finding_data)))

                    # Also insert into web_findings for findings explorer
                    cur.execute("""
                        INSERT INTO web_findings
                        (id, asset_id, url, source, status_code, name, severity, evidence, method, refs)
                        VALUES (gen_random_uuid(), %s, %s, 'gowitness', %s, %s, 'recon', %s, 'GET', %s)
                    """, (asset_id, url, status_code, title or None, evidence,
                          json.dumps(refs) if refs else None))

                    # Create port record for this web service
                    if asset_id:
                        try:
                            gw_port = int(parsed.port) if parsed.port else (443 if url.startswith('https') else 80)
                            gw_svc = 'https' if url.startswith('https') else 'http'
                            gw_product = headers.get('server') or headers.get('Server') or None
                            cur.execute("""INSERT INTO ports (id, asset_id, proto, port, service, product, is_open)
                                          VALUES (gen_random_uuid(), %s, 'tcp', %s, %s, %s, true)
                                          ON CONFLICT DO NOTHING""",
                                        (asset_id, gw_port, gw_svc, gw_product))
                        except Exception:
                            pass

                    # Upsert screenshot_metadata
                    if screenshot_path:
                        cur.execute("""
                            INSERT INTO screenshot_metadata (id, path, filename, directory)
                            VALUES (gen_random_uuid(), %s, %s, %s)
                            ON CONFLICT (path) DO NOTHING
                        """, (screenshot_path,
                              os.path.basename(screenshot_file) if screenshot_file else "",
                              os.path.basename(screenshot_dir)))

                    ingested += 1

            conn.commit()
    except Exception as e:
        logging.error(f"gowitness ingest error: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return ingested


def _run_gowitness_job(job_id, targets, timeout=10, resolution="1440x900", proxy=None):
    """Run gowitness screenshots, save to /reports/screenshots/{job_id[:8]}/"""
    import time as _time
    _t0 = _time.time()
    try:
        _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="running")
        out_dir = str(REPORT_DIR / "screenshots" / job_id[:8])
        os.makedirs(out_dir, exist_ok=True)

        targets_file = _write_targets_file(targets)
        w, h = resolution.split("x") if "x" in resolution else ("1440", "900")

        jsonl_out = str(REPORT_DIR / f"gowitness_{job_id[:8]}.jsonl")
        cmd = ["gowitness", "scan", "file",
               "-f", targets_file,
               "-s", out_dir,
               "-T", str(timeout),
               "--chrome-window-x", w, "--chrome-window-y", h,
               "--screenshot-format", "png",
               "--write-jsonl", "--write-jsonl-file", jsonl_out,
               "--chrome-path", os.environ.get("CHROME_PATH", "/usr/bin/chromium")]
        if proxy:
            cmd.extend(["--chrome-proxy", proxy])

        cmd_str = " ".join(cmd)
        _job_tracker.push_command(job_id, "gowitness", cmd_str)
        write_audit("scan_started", "gowitness", "osint_runner", {
            "job_id": job_id, "execution_mode": "proxied" if proxy else "local",
            "targets": targets[:10], "targets_count": len(targets),
            "command": cmd_str, "proxy": proxy or None,
        })
        env = _build_proxy_env(proxy)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200, env=env)
        logging.info(f"[{job_id}] gowitness stdout: {result.stdout[:500]}")
        if result.stderr:
            logging.info(f"[{job_id}] gowitness stderr: {result.stderr[:500]}")

        screenshots = [f for f in os.listdir(out_dir) if f.endswith(".png")]
        elapsed = round(_time.time() - _t0, 2)

        # Ingest GoWitness JSONL metadata into DB
        gw_ingested = 0
        if os.path.exists(jsonl_out):
            try:
                gw_ingested = _ingest_gowitness_jsonl(jsonl_out, out_dir, job_id)
                logging.info(f"[{job_id}] gowitness: ingested {gw_ingested} findings from JSONL")
            except Exception as e:
                logging.warning(f"[{job_id}] gowitness ingest failed: {e}")

        _job_tracker.update_job(job_id, status="completed",
            result={"ok": True, "screenshots": len(screenshots),
                    "dir": out_dir, "elapsed_sec": elapsed,
                    "findings_ingested": gw_ingested},
            completed_at=datetime.now().isoformat())
        emit_webhook_event("scan_completed", "gowitness",
                           {"job_id": job_id, "screenshots": len(screenshots)})
        write_audit("scan_completed", "gowitness", "osint_runner",
                    {"job_id": job_id, "screenshots": len(screenshots), "elapsed_sec": elapsed,
                     "targets": targets[:10], "targets_count": len(targets),
                     "command": cmd_str, "proxy": proxy or None,
                     "findings_ingested": gw_ingested})

        try:
            os.remove(targets_file)
        except OSError:
            pass
    except Exception as e:
        _job_tracker.update_job(job_id, status="failed", error=str(e),
                                completed_at=datetime.now().isoformat())
        emit_webhook_event("scan_failed", "gowitness", {"job_id": job_id, "error": str(e)})
        logging.error(f"[{job_id}] gowitness failed: {e}")


@app.post("/jobs/gowitness")
def run_gowitness(req: GoWitnessReq, background_tasks: BackgroundTasks):
    """Screenshot web pages with GoWitness."""
    job_id = _job_tracker.create_job(job_type="gowitness")
    _job_tracker.update_progress(job_id, targets_count=len(req.targets))
    background_tasks.add_task(_run_gowitness_job, job_id, req.targets,
                              req.timeout, req.resolution, req.proxy)
    return {"ok": True, "job_id": job_id, "status": "queued",
            "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/greyhatwarfare")
def run_greyhatwarfare(req: GHWReq, background_tasks: BackgroundTasks):
    """Search GreyHatWarfare for exposed S3 buckets and files."""
    job_id = _job_tracker.create_job(job_type="greyhatwarfare")
    output_file = str(REPORT_DIR / f"ghw_{job_id[:8]}.jsonl")

    keys = _get_api_keys()
    api_key = keys.get("greyhatwarfare_api_key", "")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Configure greyhatwarfare_api_key in Settings > API Keys",
        )

    search_type = req.search_type or "buckets"
    if search_type not in ("buckets", "files"):
        raise HTTPException(400, "search_type must be 'buckets' or 'files'")

    def _run_ghw_job():
        import time as _time
        try:
            _t0 = _time.time()
            _job_tracker.update_job(job_id, status="running",
                                    started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="running")

            emit_webhook_event("scan_started", "greyhatwarfare",
                               {"job_id": job_id, "scan_type": "greyhatwarfare"})
            write_audit("scan_started", "greyhatwarfare", "osint_runner",
                        {"job_id": job_id, "execution_mode": "local"})

            session = requests.Session()
            session.headers["Authorization"] = f"Bearer {api_key}"
            if req.proxy:
                session.proxies = {"http": req.proxy, "https": req.proxy}

            limit = min(req.limit or 100, 1000)
            base_url = "https://buckets.grayhatwarfare.com/api/v2"

            results = []
            page_start = 0
            page_size = min(limit, 100)

            while len(results) < limit:
                if search_type == "buckets":
                    url = f"{base_url}/buckets/{page_start}/{page_size}"
                else:
                    url = f"{base_url}/files/{page_start}/{page_size}"

                resp = session.get(url, params={"keywords": req.search_query}, timeout=30)
                resp.raise_for_status()
                data = resp.json()

                items = data.get("buckets", data.get("files", []))
                if not items:
                    break

                for item in items:
                    item["type"] = "bucket" if search_type == "buckets" else "file"
                    item["keyword"] = req.search_query
                    results.append(item)

                if len(items) < page_size:
                    break
                page_start += page_size

            # Write JSONL output
            with open(output_file, "w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")

            elapsed = _time.time() - _t0
            _job_tracker.update_job(
                job_id, status="completed",
                result_path=output_file,
                completed_at=datetime.now().isoformat(),
            )
            _job_tracker.update_progress(
                job_id, stage="completed",
                results_count=len(results),
                elapsed=round(elapsed, 1),
            )

            # Auto-ingest into rag-api
            _ingest_results("greyhatwarfare", output_file, job_id=job_id)

            emit_webhook_event("scan_completed", "greyhatwarfare", {
                "job_id": job_id, "results_count": len(results),
                "elapsed": round(elapsed, 1),
            })

        except Exception as e:
            log.error("GHW job %s failed: %s", job_id, e)
            _job_tracker.update_job(job_id, status="failed", error=str(e))
            emit_webhook_event("scan_failed", "greyhatwarfare",
                               {"job_id": job_id, "error": str(e)})

    _job_tracker.update_progress(job_id, targets_count=1)
    background_tasks.add_task(_run_ghw_job)
    return {"ok": True, "job_id": job_id, "status": "queued",
            "status_url": f"/jobs/{job_id}"}


class WhoisReq(BaseModel):
    targets: List[str]
    proxy: Optional[str] = None
    engagement_id: Optional[str] = None


def _is_ip(target: str) -> bool:
    """Check if target looks like an IP address."""
    import re
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target.strip()))


def _whois_query(target: str, proxy: str = None, timeout: int = 30) -> str:
    """Run a WHOIS query via TCP port 43, optionally through a SOCKS proxy.

    Falls back to the `whois` CLI command if no proxy is set.
    """
    if not proxy:
        # No proxy — use CLI (faster, handles referrals)
        wp = subprocess.run(["whois", target], capture_output=True, text=True, timeout=timeout)
        return wp.stdout or ""

    # Route through SOCKS proxy via PySocks
    import socks
    from urllib.parse import urlparse

    parsed = urlparse(proxy)
    proxy_type = socks.SOCKS5
    if "socks4" in (parsed.scheme or ""):
        proxy_type = socks.SOCKS4
    proxy_host = parsed.hostname or "127.0.0.1"
    proxy_port = parsed.port or 1080

    # Determine WHOIS server
    is_ip = _is_ip(target)
    if is_ip:
        whois_server = "whois.arin.net"
    else:
        tld = target.rsplit(".", 1)[-1].lower()
        tld_servers = {
            "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
            "org": "whois.pir.org", "io": "whois.nic.io",
            "co": "whois.nic.co", "info": "whois.afilias.net",
            "uk": "whois.nic.uk", "de": "whois.denic.de",
            "au": "whois.auda.org.au",
        }
        whois_server = tld_servers.get(tld, f"whois.nic.{tld}")

    try:
        s = socks.socksocket()
        s.set_proxy(proxy_type, proxy_host, proxy_port)
        s.settimeout(timeout)
        s.connect((whois_server, 43))
        query = target + "\r\n"
        s.sendall(query.encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()

        raw = response.decode("utf-8", errors="replace")

        # Follow referrals (e.g., verisign → registrar whois)
        for line in raw.splitlines():
            if line.strip().lower().startswith("whois server:") or line.strip().lower().startswith("refer:"):
                referral = line.split(":", 1)[1].strip()
                if referral and referral != whois_server:
                    try:
                        s2 = socks.socksocket()
                        s2.set_proxy(proxy_type, proxy_host, proxy_port)
                        s2.settimeout(timeout)
                        s2.connect((referral, 43))
                        s2.sendall(query.encode())
                        ref_response = b""
                        while True:
                            chunk = s2.recv(4096)
                            if not chunk:
                                break
                            ref_response += chunk
                        s2.close()
                        raw += "\n\n--- Referral: %s ---\n" % referral
                        raw += ref_response.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    break

        return raw
    except Exception as e:
        logging.warning("WHOIS via proxy %s failed for %s: %s", proxy, target, e)
        # Fall back to CLI without proxy
        try:
            wp = subprocess.run(["whois", target], capture_output=True, text=True, timeout=timeout)
            return wp.stdout or ""
        except Exception:
            return ""


def _parse_whois_domain(raw: str, domain: str) -> dict:
    """Parse WHOIS output for a domain."""
    parsed = {"raw_length": len(raw), "domain": domain, "type": "domain"}
    field_map = {
        "registrar": ["Registrar:", "registrar:"],
        "org": ["Registrant Organization:", "org:", "OrgName:"],
        "creation_date": ["Creation Date:", "created:", "Registration Date:"],
        "expiry_date": ["Registry Expiry Date:", "Expiry Date:", "paid-till:"],
        "updated_date": ["Updated Date:", "last-modified:"],
        "name_servers": ["Name Server:", "nserver:"],
        "registrant_name": ["Registrant Name:"],
        "registrant_email": ["Registrant Email:", "e-mail:"],
        "registrant_country": ["Registrant Country:", "Registrant State/Province:"],
        "dnssec": ["DNSSEC:"],
        "status": ["Domain Status:", "status:"],
    }
    for key, patterns in field_map.items():
        values = []
        for pat in patterns:
            for line in raw.splitlines():
                if line.strip().lower().startswith(pat.lower()):
                    val = line.split(":", 1)[1].strip()
                    if val and val not in values:
                        values.append(val)
        if values:
            parsed[key] = values if key in ("name_servers", "status") else values[0]
    return parsed


def _parse_whois_ip(raw: str, ip: str) -> dict:
    """Parse WHOIS output for an IP address (ARIN/RIPE/APNIC format)."""
    parsed = {"raw_length": len(raw), "ip": ip, "type": "ip"}
    field_map = {
        "org": ["OrgName:", "org-name:", "Organization:", "org:", "descr:"],
        "org_id": ["OrgId:", "org:"],
        "net_range": ["NetRange:", "inetnum:"],
        "cidr": ["CIDR:", "route:"],
        "net_name": ["NetName:", "netname:"],
        "country": ["Country:", "country:"],
        "abuse_email": ["OrgAbuseEmail:", "abuse-mailbox:"],
        "tech_email": ["OrgTechEmail:", "tech-c:"],
        "ref": ["Ref:", "source:"],
        "asn": ["OriginAS:", "origin:"],
        "net_handle": ["NetHandle:"],
        "parent": ["Parent:"],
    }
    for key, patterns in field_map.items():
        values = []
        for pat in patterns:
            for line in raw.splitlines():
                if line.strip().lower().startswith(pat.lower()):
                    val = line.split(":", 1)[1].strip()
                    if val and val not in values:
                        values.append(val)
        if values:
            parsed[key] = values[0] if key not in ("country",) else values[0]
    return parsed


@app.post("/jobs/whois")
def run_whois(req: WhoisReq, background_tasks: BackgroundTasks):
    """Standalone WHOIS lookup for domains and/or IP addresses.

    Supports both domain WHOIS (registrar, org, nameservers) and
    IP WHOIS (netblock, ASN, org, abuse contact). Auto-detects type.
    """
    targets = [t.strip() for t in req.targets if t.strip()]
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided")
    job_id = _job_tracker.create_job(job_type="whois")
    _job_tracker.update_progress(job_id, targets_count=len(targets), stage="queued")

    def _run():
        import json as _json
        _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
        results = {}
        short = job_id[:8]

        for target in targets:
            target = target.strip()
            is_ip = _is_ip(target)

            try:
                if is_ip:
                    lookup_target = target
                else:
                    # Strip subdomains — whois needs the registered domain
                    parts = target.split(".")
                    if len(parts) > 2:
                        lookup_target = ".".join(parts[-2:])
                        if parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
                            lookup_target = ".".join(parts[-3:]) if len(parts) > 2 else lookup_target
                    else:
                        lookup_target = target

                raw = _whois_query(lookup_target, proxy=req.proxy, timeout=30)
                if not raw.strip():
                    results[target] = {"error": "empty response", "type": "ip" if is_ip else "domain"}
                    continue

                if is_ip:
                    parsed = _parse_whois_ip(raw, target)
                else:
                    parsed = _parse_whois_domain(raw, lookup_target)

                results[target] = parsed
                if is_ip:
                    logging.info(f"[{job_id}] whois {target}: org={parsed.get('org', '?')}, "
                                 f"net={parsed.get('net_range', '?')}, asn={parsed.get('asn', '?')}")
                else:
                    logging.info(f"[{job_id}] whois {target}: registrar={parsed.get('registrar', '?')}, "
                                 f"org={parsed.get('org', '?')}")

            except subprocess.TimeoutExpired:
                results[target] = {"error": "timeout"}
            except FileNotFoundError:
                results[target] = {"error": "whois not installed"}
                break
            except Exception as e:
                results[target] = {"error": str(e)}

        # Save and ingest
        out_file = str(REPORT_DIR / f"whois_{short}.json")
        with open(out_file, "w") as f:
            _json.dump(results, f, indent=2)

        try:
            conn = __import__("psycopg2").connect(DB_DSN)
            with conn.cursor() as cur:
                for tgt, wdata in results.items():
                    if wdata.get("error"):
                        continue
                    finding_type = "whois_ip" if wdata.get("type") == "ip" else "whois_record"
                    cur.execute(
                        """INSERT INTO recon_findings (source, finding_type, target, data, severity)
                           VALUES ('whois', %s, %s, %s, 'info')
                           ON CONFLICT DO NOTHING""",
                        (finding_type, tgt, _json.dumps(wdata)),
                    )
                conn.commit()
            conn.close()
        except Exception as e:
            logging.warning(f"[{job_id}] whois ingest failed: {e}")

        # Emit webhook
        try:
            from audit_writer import write_audit
            write_audit("scan_completed", "whois", "osint-runner", {
                "job_id": job_id, "targets": len(targets),
                "results": len([r for r in results.values() if not r.get("error")]),
                "engagement_id": req.engagement_id,
            })
        except Exception:
            pass

        _job_tracker.update_job(job_id, status="completed", completed_at=datetime.now().isoformat())
        _job_tracker.update_progress(job_id, stage="done", result=results)

    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}"}


@app.post("/jobs/wafw00f")
def run_wafw00f(req: Wafw00fReq, background_tasks: BackgroundTasks):
    """WAF detection via wafw00f."""
    job_id = _job_tracker.create_job(job_type="wafw00f")
    targets_file = _write_targets_file(req.targets)
    output_file = str(REPORT_DIR / f"wafw00f_{job_id[:8]}.json")

    cmd = ["wafw00f", "-i", targets_file, "-o", output_file, "-f", "json"]
    if req.proxy:
        cmd.extend(["-p", req.proxy])

    env = _build_proxy_env(req.proxy)
    _job_tracker.update_progress(job_id, targets_count=len(req.targets))
    background_tasks.add_task(_run_tool_job, job_id, "wafw00f", cmd, targets_file, output_file, env=env, no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued",
            "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


@app.get("/screenshots/list")
def list_screenshots(search: Optional[str] = None):
    """List all screenshot files across all screenshot directories."""
    screenshots_root = REPORT_DIR / "screenshots"
    results = []
    if not screenshots_root.exists():
        return {"screenshots": results, "total": 0}
    for dir_entry in sorted(screenshots_root.iterdir()):
        if not dir_entry.is_dir():
            continue
        for f in sorted(dir_entry.iterdir()):
            if f.suffix == ".png":
                rel_path = f"{dir_entry.name}/{f.name}"
                if search:
                    # Match against filename (URL-encoded) and also original domain
                    fname_lower = f.name.lower()
                    search_lower = search.lower()
                    # GoWitness filenames use --- for :// and - for / and .
                    search_dashed = search_lower.replace(".", "-").replace("://", "---")
                    if search_lower not in fname_lower and search_dashed not in fname_lower:
                        continue
                results.append({
                    "path": rel_path,
                    "filename": f.name,
                    "directory": dir_entry.name,
                    "size": f.stat().st_size,
                })
    return {"screenshots": results, "total": len(results)}


@app.get("/screenshots/{path:path}")
def serve_screenshot(path: str):
    """Serve screenshot files from /reports/screenshots/."""
    from fastapi.responses import FileResponse
    full_path = REPORT_DIR / "screenshots" / path
    if not full_path.exists() or not str(full_path.resolve()).startswith(str(REPORT_DIR.resolve())):
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(str(full_path), media_type="image/png")


@app.put("/screenshots/upload/{path:path}")
async def upload_screenshot(path: str, file: UploadFile = File(...)):
    """Restore a screenshot PNG during import (multipart upload)."""
    screenshots_root = (REPORT_DIR / "screenshots").resolve()
    full_path = (REPORT_DIR / "screenshots" / path).resolve()
    # Path traversal guard
    if not str(full_path).startswith(str(screenshots_root)):
        raise HTTPException(status_code=400, detail="Invalid path")
    if full_path.exists():
        return {"ok": True, "skipped": True, "path": path}
    full_path.parent.mkdir(parents=True, exist_ok=True)
    content = await file.read()
    full_path.write_bytes(content)
    return {"ok": True, "written": len(content), "path": path}


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
        headers={"Content-Disposition": "attachment; filename=osint_runner_logs.json"},
    )


# ══════════════════════════════════════════════════════════════════════════
#  Service-Specific Enumeration Endpoints
# ══════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════
#  Subzy — Subdomain Takeover Detection
# ══════════════════════════════════════════════════════════════════════════

class SubzyReq(BaseModel):
    targets: List[str]
    proxy: Optional[str] = None
    no_ingest: bool = False


@app.post("/jobs/subzy")
def run_subzy(req: SubzyReq, background_tasks: BackgroundTasks):
    """Check subdomains for takeover vulnerabilities."""
    job_id = _job_tracker.create_job(job_type="subzy")
    targets_file = _write_targets_file(req.targets)
    output_file = str(REPORT_DIR / f"subzy_{job_id[:8]}.json")

    cmd = ["subzy", "run", "--targets", targets_file, "--output", output_file]
    if req.proxy:
        cmd.extend(["--proxy", req.proxy])

    _job_tracker.update_progress(job_id, targets_count=len(req.targets))
    _job_tracker.push_command(job_id, "subzy", f"subzy run --targets <{len(req.targets)} subdomains>")
    background_tasks.add_task(_run_tool_job, job_id, "subzy", cmd, targets_file, output_file,
                              env=_build_proxy_env(req.proxy), no_ingest=req.no_ingest)
    return {"ok": True, "job_id": job_id, "status": "queued"}


# ══════════════════════════════════════════════════════════════════════════
#  GoLinkFinder — JavaScript Endpoint Extraction
# ══════════════════════════════════════════════════════════════════════════

class GoLinkFinderReq(BaseModel):
    target: str  # URL to analyze
    proxy: Optional[str] = None
    no_ingest: bool = False


@app.post("/jobs/golinkfinder")
def run_golinkfinder(req: GoLinkFinderReq, background_tasks: BackgroundTasks):
    """Extract API endpoints and links from JavaScript files."""
    job_id = _job_tracker.create_job(job_type="golinkfinder")
    output_file = str(REPORT_DIR / f"golinkfinder_{job_id[:8]}.txt")

    cmd = ["GoLinkFinder", "-d", req.target, "-o", output_file]

    _job_tracker.update_progress(job_id, targets_count=1)
    _job_tracker.push_command(job_id, "golinkfinder", f"GoLinkFinder -d {req.target}")

    def _run_glf():
        try:
            _job_tracker.update_job(job_id, status="running")
            env = _build_proxy_env(req.proxy)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)

            endpoints = []
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            endpoints.append(line)

            # Ingest as web_findings
            if not req.no_ingest and endpoints:
                try:
                    with conn() as c, c.cursor() as cur:
                        for ep in endpoints[:500]:  # cap at 500
                            cur.execute("""INSERT INTO web_findings
                                (id, url, source, issue_type, name, severity, evidence, first_seen, last_seen)
                                VALUES (gen_random_uuid(), %s, 'golinkfinder', 'js_endpoint', %s, 'recon', %s, now(), now())
                            """, (req.target, f"JS endpoint: {ep[:200]}", ep[:2000]))
                        c.commit()
                except Exception as e:
                    logging.error(f"[{job_id[:8]}] GoLinkFinder ingest failed: {e}")

            _job_tracker.update_job(job_id, status="completed", result={
                "endpoints_found": len(endpoints),
                "target": req.target,
                "sample": endpoints[:20],
            })
            try:
                write_audit("scan_completed", "golinkfinder", "osint_runner", {
                    "job_id": job_id, "target": req.target, "endpoints_found": len(endpoints)})
            except Exception:
                pass
        except Exception as e:
            logging.exception(f"[{job_id}] GoLinkFinder failed")
            _job_tracker.update_job(job_id, status="failed", error=str(e))

    background_tasks.add_task(_run_glf)
    return {"ok": True, "job_id": job_id, "status": "queued"}


# ══════════════════════════════════════════════════════════════════════════
#  Service-Specific Enumeration Endpoints
# ══════════════════════════════════════════════════════════════════════════

from service_enum import (
    run_full_email_enum, run_full_dns_enum,
    check_spf, check_dmarc, check_dkim, enumerate_mx,
    enumerate_dns_records, attempt_zone_transfer, reverse_dns_sweep,
    fingerprint_nameservers,
)


class EmailEnumReq(BaseModel):
    domain: str
    dkim_selectors: Optional[List[str]] = None


class DnsEnumReq(BaseModel):
    domain: str
    reverse_cidr: Optional[str] = None


class ServiceEnumReq(BaseModel):
    domain: str
    services: Optional[List[str]] = None  # email, dns, all
    reverse_cidr: Optional[str] = None
    dkim_selectors: Optional[List[str]] = None


@app.post("/jobs/email-enum")
def run_email_enum(req: EmailEnumReq, background_tasks: BackgroundTasks):
    """Enumerate email infrastructure: SPF, DKIM, DMARC, MX servers."""
    job_id = _job_tracker.create_job(job_type="email-enum")

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running")
            _job_tracker.push_command(job_id, "spf-check", f"dig TXT {req.domain} | grep 'v=spf1'")
            _job_tracker.push_command(job_id, "dmarc-check", f"dig TXT _dmarc.{req.domain}")
            _job_tracker.push_command(job_id, "dkim-check", f"dig TXT <selector>._domainkey.{req.domain}")
            _job_tracker.push_command(job_id, "mx-enum", f"dig MX {req.domain} && smtp-banner-grab")

            results = run_full_email_enum(req.domain)
            if req.dkim_selectors:
                results["dkim"] = check_dkim(req.domain, req.dkim_selectors)

            # Ingest findings
            _ingest_email_findings(job_id, results)

            _job_tracker.update_job(job_id, status="completed", result=results)
            try:
                write_audit("scan_completed", "email-enum", "osint_runner", {
                    "job_id": job_id, "domain": req.domain,
                    "score": results.get("email_security_score"),
                    "providers": results.get("providers", [])})
            except Exception:
                pass
        except Exception as e:
            logging.exception(f"[{job_id}] email-enum failed")
            _job_tracker.update_job(job_id, status="failed", error=str(e))

    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued"}


@app.post("/jobs/dns-enum")
def run_dns_enum(req: DnsEnumReq, background_tasks: BackgroundTasks):
    """DNS infrastructure enumeration: records, zone transfer, nameserver fingerprinting."""
    job_id = _job_tracker.create_job(job_type="dns-enum")

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running")
            _job_tracker.push_command(job_id, "dns-records", f"dig ANY {req.domain}")
            _job_tracker.push_command(job_id, "zone-transfer", f"dig @ns AXFR {req.domain}")
            _job_tracker.push_command(job_id, "ns-fingerprint", f"dig CH TXT version.bind @ns")
            if req.reverse_cidr:
                _job_tracker.push_command(job_id, "reverse-dns", f"reverse-dns-sweep {req.reverse_cidr}")

            results = run_full_dns_enum(req.domain, req.reverse_cidr)

            # Ingest findings
            _ingest_dns_findings(job_id, results)

            _job_tracker.update_job(job_id, status="completed", result=results)
            try:
                write_audit("scan_completed", "dns-enum", "osint_runner", {
                    "job_id": job_id, "domain": req.domain,
                    "zone_transfer_vulnerable": results.get("zone_transfer", {}).get("vulnerable", False)})
            except Exception:
                pass
        except Exception as e:
            logging.exception(f"[{job_id}] dns-enum failed")
            _job_tracker.update_job(job_id, status="failed", error=str(e))

    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued"}


@app.post("/jobs/service-enum")
def run_service_enum(req: ServiceEnumReq, background_tasks: BackgroundTasks):
    """Full service enumeration: email + DNS infrastructure for a domain."""
    job_id = _job_tracker.create_job(job_type="service-enum")
    services = req.services or ["email", "dns"]

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running")
            results = {"domain": req.domain, "services_run": services}

            if "email" in services or "all" in services:
                _job_tracker.push_command(job_id, "email-enum", f"email-infrastructure-audit {req.domain}")
                results["email"] = run_full_email_enum(req.domain)
                if req.dkim_selectors:
                    results["email"]["dkim"] = check_dkim(req.domain, req.dkim_selectors)
                _ingest_email_findings(job_id, results["email"])

            if "dns" in services or "all" in services:
                _job_tracker.push_command(job_id, "dns-enum", f"dns-infrastructure-audit {req.domain}")
                results["dns"] = run_full_dns_enum(req.domain, req.reverse_cidr)
                _ingest_dns_findings(job_id, results["dns"])

            _job_tracker.update_job(job_id, status="completed", result=results)
            try:
                write_audit("scan_completed", "service-enum", "osint_runner", {
                    "job_id": job_id, "domain": req.domain, "services": services})
            except Exception:
                pass
        except Exception as e:
            logging.exception(f"[{job_id}] service-enum failed")
            _job_tracker.update_job(job_id, status="failed", error=str(e))

    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued"}


# ── Individual service checks (synchronous, for quick lookups) ──

@app.get("/service-enum/spf/{domain}")
def get_spf(domain: str):
    return check_spf(domain)

@app.get("/service-enum/dmarc/{domain}")
def get_dmarc(domain: str):
    return check_dmarc(domain)

@app.get("/service-enum/dkim/{domain}")
def get_dkim(domain: str, selectors: str = None):
    sel_list = selectors.split(",") if selectors else None
    return check_dkim(domain, sel_list)

@app.get("/service-enum/mx/{domain}")
def get_mx(domain: str):
    return enumerate_mx(domain)

@app.get("/service-enum/dns/{domain}")
def get_dns_records(domain: str):
    return enumerate_dns_records(domain)

@app.get("/service-enum/zone-transfer/{domain}")
def get_zone_transfer(domain: str):
    return attempt_zone_transfer(domain)

@app.get("/service-enum/reverse-dns/{cidr}")
def get_reverse_dns(cidr: str, limit: int = 256):
    return reverse_dns_sweep(cidr, limit)

@app.get("/service-enum/nameservers/{domain}")
def get_nameservers(domain: str):
    return fingerprint_nameservers(domain)


# ── Ingestion helpers ──

def _ingest_email_findings(job_id: str, results: dict):
    """Store email enumeration results as recon_findings."""
    domain = results.get("domain", "unknown")
    try:
        with conn() as c, c.cursor() as cur:
            # SPF finding
            spf = results.get("spf", {})
            if spf.get("exists") or spf.get("error"):
                severity = "info" if spf.get("assessment") == "strict" else "low" if spf.get("exists") else "medium"
                name = f"SPF: {spf.get('assessment', 'missing')}" if spf.get("exists") else "SPF record missing"
                cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                    VALUES (gen_random_uuid(), 'email-enum', 'spf', %s, %s, %s, now())""",
                    (domain, json.dumps(spf), severity))

            # DMARC finding
            dmarc = results.get("dmarc", {})
            if dmarc.get("exists") or dmarc.get("error"):
                severity = "info" if dmarc.get("assessment") == "strict" else "low" if dmarc.get("exists") else "medium"
                cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                    VALUES (gen_random_uuid(), 'email-enum', 'dmarc', %s, %s, %s, now())""",
                    (domain, json.dumps(dmarc), severity))

            # DKIM finding
            dkim = results.get("dkim", {})
            severity = "info" if dkim.get("exists") else "low"
            cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                VALUES (gen_random_uuid(), 'email-enum', 'dkim', %s, %s, %s, now())""",
                (domain, json.dumps(dkim), severity))

            # MX findings
            mx = results.get("mx", {})
            for server in mx.get("servers", []):
                cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                    VALUES (gen_random_uuid(), 'email-enum', 'mx_server', %s, %s, 'info', now())""",
                    (domain, json.dumps(server)))

            # Email security score as summary finding
            cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                VALUES (gen_random_uuid(), 'email-enum', 'email_security', %s, %s, %s, now())""",
                (domain, json.dumps({
                    "score": results.get("email_security_score"),
                    "providers": results.get("providers", []),
                }),
                "info" if results.get("email_security_score", "").startswith("5") else "low"))

            c.commit()
            logging.info(f"[{job_id[:8]}] Ingested email findings for {domain}")
    except Exception as e:
        logging.error(f"[{job_id[:8]}] Failed to ingest email findings: {e}")


def _ingest_dns_findings(job_id: str, results: dict):
    """Store DNS enumeration results as recon_findings."""
    domain = results.get("domain", "unknown")
    try:
        with conn() as c, c.cursor() as cur:
            # Zone transfer finding (high severity if vulnerable)
            zt = results.get("zone_transfer", {})
            if zt.get("vulnerable"):
                cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                    VALUES (gen_random_uuid(), 'dns-enum', 'zone_transfer', %s, %s, 'high', now())""",
                    (domain, json.dumps(zt)))

            # Nameserver fingerprints
            ns = results.get("nameservers", {})
            for srv in ns.get("nameservers", []):
                cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                    VALUES (gen_random_uuid(), 'dns-enum', 'nameserver', %s, %s, 'info', now())""",
                    (domain, json.dumps(srv)))

            # DNS records summary
            records = results.get("records", {})
            if records.get("records"):
                cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                    VALUES (gen_random_uuid(), 'dns-enum', 'dns_records', %s, %s, 'info', now())""",
                    (domain, json.dumps(records)))

            # Reverse DNS
            rdns = results.get("reverse_dns", {})
            if rdns.get("records"):
                cur.execute("""INSERT INTO recon_findings (id, source, finding_type, target, data, severity, created_at)
                    VALUES (gen_random_uuid(), 'dns-enum', 'reverse_dns', %s, %s, 'info', now())""",
                    (domain, json.dumps(rdns)))

            c.commit()
            logging.info(f"[{job_id[:8]}] Ingested DNS findings for {domain}")
    except Exception as e:
        logging.error(f"[{job_id[:8]}] Failed to ingest DNS findings: {e}")


@app.post("/jobs/subdomain-takeover")
def run_subdomain_takeover(req: SubdomainTakeoverReq, background_tasks: BackgroundTasks):
    """Detect subdomain takeover vulnerabilities."""
    job_id = _job_tracker.create_job(job_type="subdomain_takeover")

    # Write subdomains to file
    subdomains_file = str(REPORT_DIR / f"subdomains_{job_id[:8]}.txt")
    with open(subdomains_file, 'w') as f:
        for subdomain in req.subdomains:
            f.write(f"{subdomain}\n")

    output_file = str(REPORT_DIR / f"subdomain_takeover_{job_id[:8]}.json")

    def _run():
        try:
            _job_tracker.update_job(job_id, status="running", started_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="checking_subdomains")
            emit_webhook_event("scan_started", "subdomain_takeover", {"job_id": job_id, "subdomains_count": len(req.subdomains)})

            # Build command
            env = os.environ.copy()
            if req.timeout:
                env["TAKEOVER_TIMEOUT"] = str(req.timeout)
            if req.proxy:
                env["HTTPS_PROXY"] = req.proxy
                env["HTTP_PROXY"] = req.proxy

            # Run subdomain takeover detection
            cmd = ["python3", "/app/subdomain_takeover.py", subdomains_file, output_file]
            logging.info(f"[{job_id}] Running: {' '.join(cmd)}")

            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=req.timeout * 10, env=env)

            if cp.returncode != 0:
                raise RuntimeError(f"Subdomain takeover scan failed: {cp.stderr}")

            # Count findings
            findings_count = 0
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        findings_count = len(data.get("findings", []))
                except Exception as e:
                    logging.warning(f"Could not parse results file: {e}")

            _job_tracker.update_progress(job_id, findings_count=findings_count)

            # Ingest results if not disabled
            ing = None
            if not req.no_ingest:
                _job_tracker.update_progress(job_id, stage="ingesting")
                ing = _ingest_results("subdomain_takeover", output_file, job_id=job_id)

            _job_tracker.update_progress(job_id, stage="done")
            _job_tracker.update_job(
                job_id, status="completed",
                result={"ok": True, "findings_count": findings_count, "ingest": ing},
                completed_at=datetime.now().isoformat(),
            )
            emit_webhook_event("scan_completed", "subdomain_takeover", {"job_id": job_id, "findings_count": findings_count})
            _save_session_results(job_id, "subdomain_takeover", "osint-runner", [output_file],
                                  metadata={"findings_count": findings_count, "subdomains_scanned": len(req.subdomains)})

        except Exception as e:
            _job_tracker.update_job(job_id, status="failed", error=str(e), completed_at=datetime.now().isoformat())
            _job_tracker.update_progress(job_id, stage="failed")
            logging.error(f"[{job_id}] Subdomain takeover scan failed: {e}")

    _job_tracker.update_progress(job_id, targets_count=len(req.subdomains))
    background_tasks.add_task(_run)
    return {"ok": True, "job_id": job_id, "status": "queued", "status_url": f"/jobs/{job_id}", "no_ingest": req.no_ingest}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8024, log_level="info", ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE"))
