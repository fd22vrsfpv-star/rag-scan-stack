from typing import Optional
import httpx
from fastapi import APIRouter, Query, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
import io
import os
import json
import zipfile
import tempfile
import logging
from pathlib import Path
from config import get_settings
from utils import safe_json

router = APIRouter()
log = logging.getLogger("maintenance")

CLEANUP_CATEGORIES = {"findings", "jobs", "sessions", "scans", "assets", "recommendations", "exploits", "followups", "engagements"}

# Paths for file-based exports (mounted volumes)
SCREENSHOTS_DIR = Path("/osint_reports/screenshots")
SCAN_RESULTS_DIR = Path("/scan_results")
AUDIT_LOG_PATH = Path("/scan_audit/audit.jsonl")

# Cap per section to avoid massive ZIPs
MAX_SECTION_BYTES = 500 * 1024 * 1024  # 500 MB


def _human_size(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    if b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    return f"{b / (1024 * 1024 * 1024):.1f} GB"


def _dir_stats(root: Path, extensions: set | None = None) -> dict:
    """Count files and total bytes in a directory tree."""
    count = 0
    total = 0
    if not root.exists():
        return {"file_count": 0, "total_bytes": 0, "human": "0 B"}
    for dirpath, _, filenames in os.walk(root):
        for f in filenames:
            if extensions and not any(f.endswith(ext) for ext in extensions):
                continue
            fp = os.path.join(dirpath, f)
            try:
                total += os.path.getsize(fp)
                count += 1
            except OSError:
                pass
    return {"file_count": count, "total_bytes": total, "human": _human_size(total)}


@router.get("/api/maintenance/stats")
async def maintenance_stats():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/maintenance/stats",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/maintenance/nodes/analysis")
async def analyze_nodes():
    """Analyze nodes for cleanup opportunities."""
    s = get_settings()

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            # Get nodes
            nodes_resp = await client.get(f"{s.tunnel_manager_url}/nodes")
            nodes_resp.raise_for_status()
            nodes = nodes_resp.json().get("nodes", [])

            # Get WireGuard peers
            wg_resp = await client.get(f"{s.tunnel_manager_url}/api/wg/peers")
            wg_resp.raise_for_status()
            peers = wg_resp.json().get("peers", [])

        # Analyze for cleanup opportunities
        analysis = {
            "total_nodes": len(nodes),
            "offline_nodes": [n for n in nodes if n.get("status") == "offline"],
            "error_nodes": [n for n in nodes if n.get("status") == "error"],
            "stale_nodes": [n for n in nodes if n.get("status") in ["offline", "error"]],
            "total_wg_peers": len(peers),
            "inactive_wg_peers": [p for p in peers if p.get("status") == "inactive"],
            "duplicate_ips": _find_duplicate_ips(nodes),
            "orphaned_wg_peers": _find_orphaned_peers(nodes, peers),
        }

        # Add counts for easy reference
        analysis.update({
            "offline_count": len(analysis["offline_nodes"]),
            "error_count": len(analysis["error_nodes"]),
            "stale_count": len(analysis["stale_nodes"]),
            "inactive_wg_count": len(analysis["inactive_wg_peers"]),
            "duplicate_count": len(analysis["duplicate_ips"]),
            "orphaned_count": len(analysis["orphaned_wg_peers"]),
        })

        return analysis

    except httpx.RequestError as e:
        raise HTTPException(500, f"Failed to analyze nodes: {str(e)}")


@router.post("/api/maintenance/nodes/cleanup")
async def cleanup_nodes(cleanup_options: dict):
    """Execute node cleanup operations based on selected options."""
    s = get_settings()
    results = {"success": [], "failed": [], "summary": ""}

    try:
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            # Get current analysis
            analysis_resp = await client.get("http://localhost:8050/api/maintenance/nodes/analysis")
            analysis_resp.raise_for_status()
            analysis = analysis_resp.json()

            # Cleanup offline nodes
            if cleanup_options.get("remove_offline", False):
                for node in analysis["offline_nodes"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/nodes/{node['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed offline node: {node['name']}")
                        else:
                            results["failed"].append(f"Failed to remove offline node {node['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing offline node {node['name']}: {str(e)}")

            # Cleanup error nodes
            if cleanup_options.get("remove_error", False):
                for node in analysis["error_nodes"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/nodes/{node['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed error node: {node['name']}")
                        else:
                            results["failed"].append(f"Failed to remove error node {node['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing error node {node['name']}: {str(e)}")

            # Cleanup inactive WireGuard peers
            if cleanup_options.get("remove_inactive_wg", False):
                for peer in analysis["inactive_wg_peers"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/api/wg/peers/{peer['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed inactive WG peer: {peer['name']}")
                        else:
                            results["failed"].append(f"Failed to remove inactive WG peer {peer['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing inactive WG peer {peer['name']}: {str(e)}")

            # Cleanup orphaned peers (peers without corresponding nodes)
            if cleanup_options.get("remove_orphaned_wg", False):
                for peer in analysis["orphaned_wg_peers"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/api/wg/peers/{peer['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed orphaned WG peer: {peer['name']}")
                        else:
                            results["failed"].append(f"Failed to remove orphaned WG peer {peer['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing orphaned WG peer {peer['name']}: {str(e)}")

            # Generate summary
            success_count = len(results["success"])
            failed_count = len(results["failed"])
            results["summary"] = f"Cleanup completed: {success_count} successful, {failed_count} failed"

            return results

    except httpx.RequestError as e:
        raise HTTPException(500, f"Cleanup operation failed: {str(e)}")


def _find_duplicate_ips(nodes: list) -> list:
    """Find nodes with duplicate IP assignments."""
    ip_map = {}
    duplicates = []

    for node in nodes:
        wg_ip = node.get("wg_assigned_ip")
        if wg_ip:
            if wg_ip in ip_map:
                # Mark both as duplicates
                if ip_map[wg_ip] not in duplicates:
                    duplicates.append(ip_map[wg_ip])
                duplicates.append(node)
            else:
                ip_map[wg_ip] = node

    return duplicates


def _find_orphaned_peers(nodes: list, peers: list) -> list:
    """Find WireGuard peers without corresponding nodes."""
    node_ids = {node["id"] for node in nodes}
    return [peer for peer in peers if peer["id"] not in node_ids]


@router.post("/api/maintenance/cleanup/{category}")
async def cleanup_category(
    category: str,
    older_than_hours: Optional[int] = Query(default=None, ge=1),
    status: Optional[str] = Query(default=None),
    dry_run: bool = Query(default=False),
    sources: Optional[str] = Query(default=None),
):
    if category not in CLEANUP_CATEGORIES:
        raise HTTPException(400, f"Unknown category: {category}")

    s = get_settings()
    params: dict = {"dry_run": dry_run}
    if older_than_hours is not None:
        params["older_than_hours"] = older_than_hours
    if status is not None:
        params["status"] = status
    if sources is not None:
        params["sources"] = sources

    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/cleanup/{category}",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ---- Follow-up bulk update ----

@router.post("/api/followups/bulk-update")
async def followups_bulk_update(body: dict):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/followups/bulk-update",
            json=body,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ---- Size estimation ----

@router.get("/api/maintenance/export/estimate")
async def export_estimate():
    """Return size estimates for file-based export sections."""
    screenshots = _dir_stats(SCREENSHOTS_DIR, {".png", ".jpg", ".jpeg"})
    scan_results = _dir_stats(SCAN_RESULTS_DIR)
    audit_size = 0
    audit_lines = 0
    if AUDIT_LOG_PATH.exists():
        audit_size = AUDIT_LOG_PATH.stat().st_size
        try:
            with open(AUDIT_LOG_PATH) as f:
                audit_lines = sum(1 for _ in f)
        except Exception:
            pass
    return {
        "screenshots": screenshots,
        "scan_results": scan_results,
        "audit_log": {
            "total_bytes": audit_size,
            "human": _human_size(audit_size),
            "line_count": audit_lines,
        },
    }


# ---- Audit log ----

@router.get("/api/maintenance/audit-log")
async def audit_log(
    limit: int = Query(500, ge=1, le=10000),
    scan_type: Optional[str] = Query(default=None),
    event: Optional[str] = Query(default=None),
    job_id: Optional[str] = Query(default=None),
    engagement_id: Optional[str] = Query(default=None),
):
    """Read and return scan audit log entries.

    When ``engagement_id`` is provided, only entries that explicitly carry
    that engagement_id are returned -- legacy entries written before Phase 2
    (no engagement_id field) are treated as unscoped and hidden when an
    engagement is active.  This enforces the cross-engagement isolation
    guarantee at the audit-log read path.
    """
    if not AUDIT_LOG_PATH.exists():
        return {"entries": [], "total": 0}
    entries = []
    try:
        with open(AUDIT_LOG_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if scan_type and entry.get("scan_type") != scan_type:
                    continue
                if event and entry.get("event") != event:
                    continue
                if job_id and entry.get("job_id") != job_id:
                    continue
                # Cross-engagement isolation filter (Phase 6).  Strict
                # equality means legacy NULL entries are excluded when an
                # engagement is active -- the safer default.
                if engagement_id and entry.get("engagement_id") != engagement_id:
                    continue
                entries.append(entry)
    except Exception as e:
        log.warning(f"Failed to read audit log: {e}")
        return {"entries": [], "total": 0, "error": str(e)}
    # Most recent first, apply limit
    entries.reverse()
    return {"entries": entries[:limit], "total": len(entries)}


# ---- Export ----

EXPORT_FILENAMES = {
    "json": "pentest_export.json",
    "csv": "pentest_export_csv.zip",
    "nessus": "pentest_export.nessus",
}
EXPORT_MIMETYPES = {
    "json": "application/json",
    "csv": "application/zip",
    "nessus": "application/xml",
}


def _add_dir_to_zip(zf: zipfile.ZipFile, src_dir: Path, zip_prefix: str, cap: int = MAX_SECTION_BYTES):
    """Add files from src_dir into ZIP under zip_prefix, respecting cap."""
    if not src_dir.exists():
        return 0
    written = 0
    for dirpath, _, filenames in os.walk(src_dir):
        for fname in sorted(filenames):
            fp = os.path.join(dirpath, fname)
            try:
                fsize = os.path.getsize(fp)
            except OSError:
                continue
            if written + fsize > cap:
                zf.writestr(
                    f"{zip_prefix}/_TRUNCATED.txt",
                    f"Export truncated at {_human_size(cap)} cap. "
                    f"Some files were omitted.\n"
                )
                return written
            rel = os.path.relpath(fp, src_dir)
            zf.write(fp, f"{zip_prefix}/{rel}")
            written += fsize
    return written


@router.get("/api/maintenance/export")
async def export_data(
    format: str = Query("json"),
    categories: str = Query("assets,findings,recon,credentials,params,exploits,screenshots"),
    include_screenshots: bool = Query(False),
    include_scan_results: bool = Query(False),
    include_audit_log: bool = Query(False),
):
    s = get_settings()
    any_files = include_screenshots or include_scan_results or include_audit_log

    if not any_files:
        # Backwards compatible: proxy to rag-api as before
        async with httpx.AsyncClient(verify=False, timeout=120) as c:
            resp = await c.get(
                f"{s.rag_api_url}/export/data",
                params={"format": format, "categories": categories},
                headers={"x-api-key": s.api_key},
            )
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code, resp.text)
        fname = EXPORT_FILENAMES.get(format, "pentest_export.json")
        mime = EXPORT_MIMETYPES.get(format, "application/octet-stream")
        return StreamingResponse(
            io.BytesIO(resp.content),
            media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    # ---- Build ZIP with DB data + requested file sections ----
    # Always fetch DB data as JSON for the data.json envelope
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.get(
            f"{s.rag_api_url}/export/data",
            params={"format": "json", "categories": categories},
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
    db_json = resp.content

    # Build ZIP to temp file (avoid memory issues with large exports)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            # DB data envelope
            zf.writestr("data.json", db_json)

            # Screenshots
            if include_screenshots:
                _add_dir_to_zip(zf, SCREENSHOTS_DIR, "screenshots")

            # Scan results
            if include_scan_results:
                _add_dir_to_zip(zf, SCAN_RESULTS_DIR, "scan_results")

            # Audit log
            if include_audit_log and AUDIT_LOG_PATH.exists():
                try:
                    fsize = AUDIT_LOG_PATH.stat().st_size
                    if fsize <= MAX_SECTION_BYTES:
                        zf.write(str(AUDIT_LOG_PATH), "audit.jsonl")
                    else:
                        zf.writestr(
                            "audit_TRUNCATED.txt",
                            f"Audit log ({_human_size(fsize)}) exceeds {_human_size(MAX_SECTION_BYTES)} cap.\n"
                        )
                except Exception as e:
                    log.warning(f"Failed to add audit log to ZIP: {e}")

        tmp.close()

        def iter_file():
            with open(tmp.name, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    yield chunk
            os.unlink(tmp.name)

        return StreamingResponse(
            iter_file(),
            media_type="application/zip",
            headers={"Content-Disposition": 'attachment; filename="pentest_export.zip"'},
        )
    except Exception:
        os.unlink(tmp.name)
        raise


# ---- Import ----

ZIP_MAGIC = b"PK\x03\x04"


@router.post("/api/maintenance/import")
async def import_data(file: UploadFile = File(...)):
    s = get_settings()
    content = await file.read()

    # Detect ZIP vs legacy JSON
    if not content[:4] == ZIP_MAGIC:
        # Legacy JSON import — proxy to rag-api
        async with httpx.AsyncClient(verify=False, timeout=120) as c:
            resp = await c.post(
                f"{s.rag_api_url}/import/data",
                files={"file": (file.filename or "import.json", content, "application/json")},
                headers={"x-api-key": s.api_key},
            )
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code, resp.text)
            return safe_json(resp)

    # ---- ZIP import ----
    result = {
        "ok": True,
        "db_import": None,
        "screenshots_restored": 0,
        "scan_results_restored": 0,
        "audit_entries_appended": 0,
    }

    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid ZIP file")

    names = zf.namelist()

    # 1. Import data.json → rag-api
    if "data.json" in names:
        data_bytes = zf.read("data.json")
        async with httpx.AsyncClient(verify=False, timeout=120) as c:
            resp = await c.post(
                f"{s.rag_api_url}/import/data",
                files={"file": ("data.json", data_bytes, "application/json")},
                headers={"x-api-key": s.api_key},
            )
            if resp.status_code < 400:
                result["db_import"] = resp.json()
            else:
                result["db_import"] = {"error": resp.text, "status": resp.status_code}

    # 2. Restore screenshots → osint-runner
    screenshot_files = [n for n in names if n.startswith("screenshots/") and not n.endswith("/")]
    for sf in screenshot_files:
        rel_path = sf[len("screenshots/"):]  # strip prefix
        file_bytes = zf.read(sf)
        try:
            async with httpx.AsyncClient(verify=False, timeout=30) as c:
                resp = await c.put(
                    f"{s.osint_runner_url}/screenshots/upload/{rel_path}",
                    files={"file": (os.path.basename(rel_path), file_bytes, "image/png")},
                )
                if resp.status_code < 400:
                    result["screenshots_restored"] += 1
        except Exception as e:
            log.warning(f"Failed to restore screenshot {rel_path}: {e}")

    # 3. Restore scan results → local /scan_results/
    scan_files = [n for n in names if n.startswith("scan_results/") and not n.endswith("/")]
    for sf in scan_files:
        rel_path = sf[len("scan_results/"):]
        dest = SCAN_RESULTS_DIR / rel_path
        # Path traversal guard
        if not str(dest.resolve()).startswith(str(SCAN_RESULTS_DIR.resolve())):
            continue
        if dest.exists():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zf.read(sf))
        result["scan_results_restored"] += 1

    # 4. Append audit log
    if "audit.jsonl" in names:
        audit_bytes = zf.read("audit.jsonl")
        lines = [l for l in audit_bytes.decode("utf-8", errors="replace").splitlines() if l.strip()]
        if lines:
            AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(AUDIT_LOG_PATH, "a") as f:
                for line in lines:
                    f.write(line + "\n")
            result["audit_entries_appended"] = len(lines)

    zf.close()
    return result


# ---- Node and WireGuard Cleanup ----

@router.get("/api/maintenance/test")
async def test_route():
    """Test route to verify registration."""
    return {"test": "working"}

@router.get("/api/maintenance/nodes/analysis")
async def analyze_nodes():
    """Analyze nodes for cleanup opportunities."""
    s = get_settings()

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            # Get nodes
            nodes_resp = await client.get(f"{s.tunnel_manager_url}/nodes")
            nodes_resp.raise_for_status()
            nodes = nodes_resp.json().get("nodes", [])

            # Get WireGuard peers
            wg_resp = await client.get(f"{s.tunnel_manager_url}/api/wg/peers")
            wg_resp.raise_for_status()
            peers = wg_resp.json().get("peers", [])

        # Analyze for cleanup opportunities
        analysis = {
            "total_nodes": len(nodes),
            "offline_nodes": [n for n in nodes if n.get("status") == "offline"],
            "error_nodes": [n for n in nodes if n.get("status") == "error"],
            "stale_nodes": [n for n in nodes if n.get("status") in ["offline", "error"]],
            "total_wg_peers": len(peers),
            "inactive_wg_peers": [p for p in peers if p.get("status") == "inactive"],
            "duplicate_ips": _find_duplicate_ips(nodes),
            "orphaned_wg_peers": _find_orphaned_peers(nodes, peers),
        }

        # Add counts for easy reference
        analysis.update({
            "offline_count": len(analysis["offline_nodes"]),
            "error_count": len(analysis["error_nodes"]),
            "stale_count": len(analysis["stale_nodes"]),
            "inactive_wg_count": len(analysis["inactive_wg_peers"]),
            "duplicate_count": len(analysis["duplicate_ips"]),
            "orphaned_count": len(analysis["orphaned_wg_peers"]),
        })

        return analysis

    except httpx.RequestError as e:
        raise HTTPException(500, f"Failed to analyze nodes: {str(e)}")


@router.post("/api/maintenance/nodes/cleanup")
async def cleanup_nodes(cleanup_options: dict):
    """Execute node cleanup operations based on selected options."""
    s = get_settings()
    results = {"success": [], "failed": [], "summary": ""}

    try:
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            # Get current analysis
            analysis_resp = await client.get("http://localhost:8050/api/maintenance/nodes/analysis")
            analysis = analysis_resp.json()

            # Cleanup offline nodes
            if cleanup_options.get("remove_offline"):
                for node in analysis["offline_nodes"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/nodes/{node['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed offline node: {node['name']}")
                        else:
                            results["failed"].append(f"Failed to remove {node['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing {node['name']}: {str(e)}")

            # Cleanup error nodes
            if cleanup_options.get("remove_error"):
                for node in analysis["error_nodes"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/nodes/{node['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed error node: {node['name']}")
                        else:
                            results["failed"].append(f"Failed to remove {node['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing {node['name']}: {str(e)}")

            # Cleanup inactive WireGuard peers
            if cleanup_options.get("remove_inactive_wg"):
                for peer in analysis["inactive_wg_peers"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/api/wg/peers/{peer['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed inactive WG peer: {peer['name']}")
                        else:
                            results["failed"].append(f"Failed to remove WG peer {peer['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing WG peer {peer['name']}: {str(e)}")

            # Cleanup orphaned peers (peers without corresponding nodes)
            if cleanup_options.get("remove_orphaned_wg"):
                for peer in analysis["orphaned_wg_peers"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/api/wg/peers/{peer['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed orphaned WG peer: {peer['name']}")
                        else:
                            results["failed"].append(f"Failed to remove orphaned peer {peer['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing orphaned peer {peer['name']}: {str(e)}")

        # Generate summary
        success_count = len(results["success"])
        failed_count = len(results["failed"])
        results["summary"] = f"Cleanup completed: {success_count} successful, {failed_count} failed operations"

        return results

    except Exception as e:
        log.error(f"Cleanup failed: {e}")
        raise HTTPException(500, f"Cleanup operation failed: {str(e)}")


def _find_duplicate_ips(nodes: list) -> list:
    """Find nodes with duplicate IP assignments."""
    ip_map = {}
    duplicates = []

    for node in nodes:
        wg_ip = node.get("wg_assigned_ip")
        if wg_ip:
            if wg_ip in ip_map:
                # Mark both as duplicates
                if ip_map[wg_ip] not in duplicates:
                    duplicates.append(ip_map[wg_ip])
                duplicates.append(node)
            else:
                ip_map[wg_ip] = node

    return duplicates


def _find_orphaned_peers(nodes: list, peers: list) -> list:
    """Find WireGuard peers without corresponding nodes."""
    node_ids = {node["id"] for node in nodes}
    return [peer for peer in peers if peer["id"] not in node_ids]
