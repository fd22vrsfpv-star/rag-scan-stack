"""
Session output collector — gathers raw scan files, conversation logs,
and the final report into a session-named directory on disk.

Best-effort: logs warnings on failure, never raises.
"""

import json
import logging
import os
import re
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("session_collector")

# Base path where session output directories are created
SESSIONS_BASE = Path(os.environ.get("SCAN_SESSIONS_DIR", "/app/scan_sessions"))

# Scanner output directories (container paths)
SCANNER_DIRS: Dict[str, Path] = {
    "nmap_out":                Path("/app/scanner_data/nmap_out"),
    "nuclei_reports":          Path("/app/scanner_data/nuclei_reports"),
    "web_reports":             Path("/app/scanner_data/web_reports"),
    "playwright_reports":      Path("/app/scanner_data/playwright_reports"),
    "playwright_screenshots":  Path("/app/scanner_data/playwright_screenshots"),
    "brutus_reports":          Path("/app/scanner_data/brutus_reports"),
    "osint_reports":           Path("/app/scanner_data/osint_reports"),
    "pd_reports":              Path("/app/scanner_data/pd_reports"),
}

# Map scan types to the scanner output directory they write to
SCAN_TYPE_DIR: Dict[str, str] = {
    "masscan":          "nmap_out",
    "nmap":             "nmap_out",
    "full_scan":        "nmap_out",
    "smb_vuln":         "nmap_out",
    "udp":              "nmap_out",
    "nuclei":           "nuclei_reports",
    "web_scan":         "web_reports",
    "playwright":       "playwright_reports",
    "brutus":           "brutus_reports",
    "credential_check": "brutus_reports",
    "subfinder":        "osint_reports",
    "dnsx":             "osint_reports",
    "asnmap":           "osint_reports",
    "uncover":          "osint_reports",
    "cloudlist":        "osint_reports",
    "httpx":            "pd_reports",
    "naabu":            "pd_reports",
    "katana":           "pd_reports",
    "tlsx":             "pd_reports",
}

# Scan types where we can match files by job_id prefix in filename
JOB_ID_MATCH_TYPES = {
    "masscan", "brutus", "credential_check",
    "subfinder", "dnsx", "asnmap", "uncover", "cloudlist",
    "httpx", "naabu", "katana", "tlsx",
}

# Scan types where we fall back to time-window matching
TIME_WINDOW_TYPES = {
    "nmap", "full_scan", "smb_vuln", "udp",
    "nuclei", "web_scan", "playwright",
}


def sanitize_session_name(name: str) -> str:
    """Replace spaces/special chars with underscores, truncate to 128 chars."""
    sanitized = re.sub(r"[^\w\-.]", "_", name.strip())
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    return sanitized[:128] if sanitized else "unnamed"


def _collect_by_job_id(
    scan_entry: Dict[str, Any],
    session_dir: Path,
) -> int:
    """
    Copy files matching ``{tool}_{job_id[:8]}*`` from the scanner output dir.

    Returns the number of files copied.
    """
    scan_type = scan_entry.get("type", "")
    job_id = scan_entry.get("job_id", "")
    if not job_id:
        return 0

    dir_key = SCAN_TYPE_DIR.get(scan_type)
    if not dir_key:
        return 0
    src_dir = SCANNER_DIRS.get(dir_key)
    if not src_dir or not src_dir.is_dir():
        return 0

    prefix = job_id[:8]
    dest_subdir = session_dir / dir_key
    copied = 0
    for f in src_dir.iterdir():
        if f.is_file() and prefix in f.name:
            dest_subdir.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(f, dest_subdir / f.name)
                copied += 1
            except Exception as e:
                logger.warning(f"Failed to copy {f}: {e}")
    return copied


def _collect_by_time_window(
    scan_entry: Dict[str, Any],
    session_start: datetime,
    session_end: datetime,
    session_dir: Path,
    already_collected: set,
) -> int:
    """
    Copy files modified during the session window (±60 s buffer)
    that haven't already been collected.

    Returns the number of files copied.
    """
    scan_type = scan_entry.get("type", "")
    dir_key = SCAN_TYPE_DIR.get(scan_type)
    if not dir_key:
        return 0
    src_dir = SCANNER_DIRS.get(dir_key)
    if not src_dir or not src_dir.is_dir():
        return 0

    window_start = session_start - timedelta(seconds=60)
    window_end = session_end + timedelta(seconds=60)

    dest_subdir = session_dir / dir_key
    copied = 0
    for f in src_dir.iterdir():
        if not f.is_file():
            continue
        if f.name in already_collected:
            continue
        mtime = datetime.utcfromtimestamp(f.stat().st_mtime)
        if window_start <= mtime <= window_end:
            dest_subdir.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(f, dest_subdir / f.name)
                already_collected.add(f.name)
                copied += 1
            except Exception as e:
                logger.warning(f"Failed to copy {f}: {e}")
    # Also collect screenshots that fall in the time window
    if scan_type == "playwright":
        ss_dir = SCANNER_DIRS.get("playwright_screenshots")
        if ss_dir and ss_dir.is_dir():
            ss_dest = session_dir / "playwright_screenshots"
            for f in ss_dir.iterdir():
                if not f.is_file():
                    continue
                if f.name in already_collected:
                    continue
                mtime = datetime.utcfromtimestamp(f.stat().st_mtime)
                if window_start <= mtime <= window_end:
                    ss_dest.mkdir(parents=True, exist_ok=True)
                    try:
                        shutil.copy2(f, ss_dest / f.name)
                        already_collected.add(f.name)
                        copied += 1
                    except Exception as e:
                        logger.warning(f"Failed to copy {f}: {e}")
    return copied


def collect_session_outputs(
    session_id: str,
    session_name: str,
    scans_metadata: List[Dict[str, Any]],
    session_started_at: str,
    conversation_messages: List[Dict[str, Any]],
    final_report: Optional[str],
) -> Optional[str]:
    """
    Collect all raw scan outputs, conversation log, and final report
    into a session-named directory.

    Returns the output directory path, or None on failure.
    """
    try:
        safe_name = sanitize_session_name(session_name)
        dir_name = f"{safe_name}_{session_id[:8]}"
        session_dir = SESSIONS_BASE / dir_name
        session_dir.mkdir(parents=True, exist_ok=True)

        # Parse session start time
        try:
            started = datetime.fromisoformat(session_started_at.rstrip("Z"))
        except Exception:
            started = datetime.utcnow() - timedelta(hours=4)
        ended = datetime.utcnow()

        # Track already-collected filenames to avoid duplicates
        already_collected: set = set()
        total_files = 0

        # Pass 1: job_id matching
        for scan in scans_metadata:
            scan_type = scan.get("type", "")
            if scan_type in JOB_ID_MATCH_TYPES:
                n = _collect_by_job_id(scan, session_dir)
                total_files += n
                # Record collected filenames to skip in pass 2
                job_id = scan.get("job_id", "")
                if job_id:
                    dir_key = SCAN_TYPE_DIR.get(scan_type, "")
                    src_dir = SCANNER_DIRS.get(dir_key)
                    if src_dir and src_dir.is_dir():
                        prefix = job_id[:8]
                        for f in src_dir.iterdir():
                            if f.is_file() and prefix in f.name:
                                already_collected.add(f.name)

        # Pass 2: time-window matching for remaining types
        for scan in scans_metadata:
            scan_type = scan.get("type", "")
            if scan_type in TIME_WINDOW_TYPES:
                n = _collect_by_time_window(
                    scan, started, ended, session_dir, already_collected
                )
                total_files += n

        # Write conversation log
        try:
            conv_path = session_dir / "conversation.json"
            conv_path.write_text(
                json.dumps(conversation_messages, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning(f"Failed to write conversation.json: {e}")

        # Write final report
        if final_report:
            try:
                report_path = session_dir / "final_report.md"
                report_path.write_text(final_report, encoding="utf-8")
            except Exception as e:
                logger.warning(f"Failed to write final_report.md: {e}")

        # Build manifest
        dir_listing = {}
        for child in sorted(session_dir.iterdir()):
            if child.is_dir():
                dir_listing[child.name] = sorted(f.name for f in child.iterdir() if f.is_file())
            else:
                dir_listing.setdefault("_root", []).append(child.name)

        manifest = {
            "session_id": session_id,
            "session_name": session_name,
            "directory": str(session_dir),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "session_started_at": session_started_at,
            "scan_count": len(scans_metadata),
            "files_collected": total_files,
            "conversation_messages": len(conversation_messages),
            "has_final_report": final_report is not None,
            "contents": dir_listing,
        }
        try:
            manifest_path = session_dir / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning(f"Failed to write manifest.json: {e}")

        logger.info(
            f"Session outputs collected: {total_files} scan files, "
            f"{len(conversation_messages)} messages → {session_dir}"
        )
        return str(session_dir)

    except Exception as e:
        logger.warning(f"Session output collection failed: {e}")
        return None
