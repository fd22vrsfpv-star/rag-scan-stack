"""
Node Manager Service — manages remote scan nodes (Sliver C2 + Chisel tunnels).

Each connected node gets a unique SOCKS proxy port.
Scanners route traffic through these proxies to scan remote networks.
"""

import asyncio
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, Union
import secrets
import base64

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from pydantic_settings import BaseSettings

from proxy_allocator import ProxyAllocator
from sliver_client import SliverClient
from ad_executor import ADExecutor, get_attack_types, AD_ATTACKS
from ssh_manager import SSHManager, SSHTunnel, WGTunnel

try:
    from audit_writer import write_audit
except ImportError:
    def write_audit(*a, **kw): pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-18s %(levelname)-5s %(message)s",
)
log = logging.getLogger("node_manager")


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
class Settings(BaseSettings):
    db_dsn: str = "postgresql://app:app@rag-postgres:5432/scans"
    # Remote database settings (override local DSN when provided)
    remote_db_host: str = ""
    remote_db_port: int = 5432
    remote_db_user: str = "app"
    remote_db_password: str = ""
    remote_db_name: str = "scans"
    sliver_config: str = "/root/.sliver-client/configs/node-manager.cfg"
    chisel_url: str = "http://chisel-server:8443"
    sliver_c2_host: str = ""  # External host for implant callbacks
    sliver_c2_port: int = 31337
    # SSH auto-connect from .env
    ssh_remote_host: str = ""
    ssh_remote_user: str = "root"
    ssh_remote_port: int = 22
    ssh_key_name: str = "id_rsa"
    ssh_tunnel_name: str = "ssh-tunnel"
    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------
sliver = SliverClient(settings.sliver_config)
allocator: Optional[ProxyAllocator] = None
ad_executor: Optional[ADExecutor] = None
ssh_manager: Optional[SSHManager] = None
wg_processes: dict[str, asyncio.subprocess.Process] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global allocator, ad_executor, ssh_manager
    log.info("Node Manager starting up")
    allocator = ProxyAllocator(settings.db_dsn)
    ad_executor = ADExecutor(sliver, settings.db_dsn)
    ssh_manager = SSHManager()
    # Wait for DB to be ready, then reload/auto-connect SSH
    for _attempt in range(15):
        try:
            conn = _get_conn()
            conn.close()
            break
        except Exception:
            log.info("Waiting for database... (attempt %d/15)", _attempt + 1)
            await asyncio.sleep(2)
    # Ensure DB schema constraints exist (idempotent)
    _ensure_db_constraints()
    # Check for duplicate port assignments in DB and fix them
    _deconflict_db_ports()
    # Reload SSH tunnels that were online in DB
    await _reload_ssh_tunnels()
    # Reload WireGuard tunnels that were online in DB
    await _reload_wg_tunnels()
    # Sync WireGuard server configuration with database
    _sync_wg_server_to_database()
    # Auto-create SSH tunnel from .env if configured
    await _auto_connect_env_ssh()
    # Try to connect to Sliver (non-blocking; may not be ready yet)
    asyncio.create_task(_connect_sliver_retry())
    # Start tunnel health watchdog
    asyncio.create_task(_tunnel_health_watchdog())
    # Start background installation task processor
    asyncio.create_task(_installation_task_processor())
    yield
    log.info("Node Manager shutting down")
    if ssh_manager:
        await ssh_manager.cleanup()


# Cache of the last (event, detail) we logged per node so identical
# back-to-back events (e.g. "Key file X not found" every watchdog tick) don't
# spam the UI. Reset on container restart.
_last_event_per_node: dict = {}


def _log_tunnel_event(node_id: str, event: str, detail: str = "",
                      dedup_window_s: int = 0):
    """Log a tunnel lifecycle event to the DB for UI display.

    `dedup_window_s` — when set, skip logging if the same (event, detail) was
    just logged for this node in-process. Prevents repeating identical errors
    on every watchdog tick (e.g. permanently-missing key file) which buries
    real events in the operator log.
    """
    sig = (event, detail or "")
    if dedup_window_s:
        prev = _last_event_per_node.get(node_id)
        if prev == sig:
            return
    _last_event_per_node[node_id] = sig
    try:
        _safe_db_execute(
            "INSERT INTO tunnel_events (node_id, event, detail) VALUES (%s, %s, %s)",
            (node_id, event, detail[:500] if detail else ""),
        )
    except Exception:
        pass  # table may not exist yet


def _verify_key_file(key_file: str) -> tuple[bool, str]:
    """Existence + readability check with a one-shot retry to absorb transient
    stat failures on WSL2/9p volumes. Returns (ok, reason)."""
    key_path = os.path.join("/ssh-keys", key_file)
    for attempt in range(2):
        try:
            if os.path.isfile(key_path):
                # Cheap read — confirms permissions are OK too.
                with open(key_path, "rb") as fh:
                    fh.read(1)
                return True, ""
            return False, "missing"
        except PermissionError:
            return False, "permission_denied"
        except FileNotFoundError:
            return False, "missing"
        except OSError as e:
            if attempt == 0:
                # Transient — retry once
                continue
            return False, f"io_error: {e}"
    return False, "unknown"


# ── IP history helpers ─────────────────────────────────────────────────

def _record_ip_assignment(node_id: str, ip: str, provider: str,
                          resource_id: str = None, region: str = None,
                          proxy_port: int = None, metadata: dict = None):
    """Record a new IP assignment in node_ip_history."""
    try:
        import json as _json
        meta = dict(metadata or {})
        if proxy_port:
            meta["proxy_port"] = proxy_port
        _safe_db_execute(
            "INSERT INTO node_ip_history "
            "(node_id, ip_address, cloud_provider, cloud_resource_id, region, metadata) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (node_id, ip, provider, resource_id, region, _json.dumps(meta)),
        )
        log.info("IP history: assigned %s to node %s (%s, SOCKS:%s)", ip, node_id[:12], provider, proxy_port)
    except Exception as e:
        log.warning("Failed to record IP assignment: %s", e)


def _release_current_ip(node_id: str, reason: str = "manual"):
    """Release the active IP for a node (set released_at, compute scan_count)."""
    try:
        # Find the active IP record
        rows = _safe_db_execute(
            "SELECT id::text, assigned_at FROM node_ip_history "
            "WHERE node_id = %s AND released_at IS NULL ORDER BY assigned_at DESC LIMIT 1",
            (node_id,), fetch=True,
        )
        if not rows:
            return
        hist_id, assigned_at = rows[0]

        # Count scans that ran through this node during this IP's lifetime
        scan_rows = _safe_db_execute(
            "SELECT id::text FROM node_scan_jobs "
            "WHERE node_id = %s AND created_at >= %s",
            (node_id, assigned_at), fetch=True,
        ) or []
        scan_ids = [r[0] for r in scan_rows]

        _safe_db_execute(
            "UPDATE node_ip_history SET released_at = now(), release_reason = %s, "
            "scan_count = %s, scan_job_ids = %s::uuid[] WHERE id = %s",
            (reason, len(scan_ids), scan_ids, hist_id),
        )
        log.info("IP history: released node %s IP (reason=%s, scans=%d)",
                 node_id[:12], reason, len(scan_ids))
    except Exception as e:
        log.warning("Failed to release IP record: %s", e)


def _emit_ip_event(event_type: str, node_id: str, data: dict = None):
    """Fire-and-forget webhook event for IP changes."""
    try:
        import requests as _req
        api_base = os.environ.get("API_BASE", "https://rag-api:8000")
        api_key = os.environ.get("API_KEY", "")
        _req.post(
            f"{api_base}/webhooks/emit",
            json={"event_type": event_type, "source": "node_manager",
                  "data": {"node_id": node_id, **(data or {})}},
            headers={"x-api-key": api_key},
            timeout=5, verify=False,
        )
    except Exception:
        pass


def _emit_wireguard_event(event_type: str, node_id: str, data: dict = None):
    """Fire-and-forget webhook event for WireGuard operations."""
    try:
        import requests as _req
        api_base = os.environ.get("API_BASE", "https://rag-api:8000")
        api_key = os.environ.get("API_KEY", "")
        _req.post(
            f"{api_base}/webhooks/emit",
            json={"event_type": event_type, "source": "node_manager",
                  "data": {"node_id": node_id, **(data or {})}},
            headers={"x-api-key": api_key},
            timeout=5, verify=False,
        )
    except Exception:
        pass  # Silent failure for fire-and-forget


def _create_tunnel(node_id: str, name: str, tunnel_method: str, metadata: dict,
                  wg_assigned_ip: str = None, socks_port: int = None) -> Union[SSHTunnel, WGTunnel]:
    """Create appropriate tunnel type based on tunnel_method."""
    if tunnel_method == 'wireguard' and wg_assigned_ip:
        return WGTunnel(
            node_id=node_id,
            name=name,
            wg_assigned_ip=wg_assigned_ip,
            socks_port=socks_port
        )
    else:
        # Default to SSH (including 'ssh', 'hybrid', and fallback cases)
        return SSHTunnel(
            node_id=node_id,
            name=name,
            host=metadata.get("host", ""),
            user=metadata.get("user", "root"),
            ssh_port=metadata.get("port", 22),
            key_file=metadata.get("key_file", ""),
            socks_port=socks_port
        )


def _check_wg_tunnel_process(node_id: str) -> bool:
    """Check if a WireGuard tunnel process is running for a node."""
    if node_id not in wg_processes:
        return False

    proc = wg_processes[node_id]
    if proc.returncode is not None:
        # Process has terminated
        del wg_processes[node_id]
        return False

    return True


_reconnect_failures: dict = {}     # node_id -> consecutive failure count
_keyfile_missing_count: dict = {}  # node_id -> consecutive watchdog ticks the key was missing

WATCHDOG_INTERVAL = 90   # seconds between health checks (was 240)
BACKOFF_THRESHOLD = 3    # failures before backing off
BACKOFF_CYCLES = 6       # skip this many cycles when backed off (~9 min at 90s)
KEY_MISSING_THRESHOLD = 3  # disable a node after this many consecutive missing-key checks


async def _tunnel_health_watchdog():
    """Check all SSH and WireGuard nodes every 90s: update last_seen, auto-reconnect with backoff."""
    await asyncio.sleep(60)  # Wait for initial connections to settle
    while True:
        try:
            conn = _get_conn()
            cur = conn.cursor()
            cur.execute("""
                SELECT id::text, name, status, proxy_port, metadata,
                       COALESCE(tunnel_method, 'ssh') as tunnel_method,
                       wg_assigned_ip, installation_status
                FROM remote_nodes
                WHERE (node_type = 'ssh' OR tunnel_method = 'wireguard')
                  AND COALESCE(status, '') <> 'disabled'
            """)
            rows = cur.fetchall()
            cur.close()
            conn.close()

            for node_id, name, db_status, port, meta, tunnel_method, wg_assigned_ip, installation_status in rows:
                # Check tunnel health based on type
                if tunnel_method == "wireguard":
                    actual = "online" if _check_wg_tunnel_process(node_id) else "offline"
                else:
                    actual = ssh_manager.check_tunnel(node_id)

                if actual == "online":
                    if db_status != "online":
                        log.info("Watchdog: %s came back online", name)
                        _log_tunnel_event(node_id, "recovered",
                                          f"Node back online (was {db_status})")
                    _safe_db_execute(
                        "UPDATE remote_nodes SET status = 'online', last_seen = now() WHERE id = %s",
                        (node_id,))
                    # Reset failure counter on success
                    _reconnect_failures.pop(node_id, None)
                    continue

                # Tunnel is not online
                if db_status == "online":
                    log.warning("Watchdog: %s (:%s) went DOWN (was online)", name, port)
                    _log_tunnel_event(node_id, "dropped",
                                      f"Tunnel went {actual} (was online)")

                # Check backoff before attempting reconnect
                fails = _reconnect_failures.get(node_id, 0)
                if fails >= BACKOFF_THRESHOLD:
                    # Back off — only retry every BACKOFF_CYCLES watchdog ticks
                    if fails % BACKOFF_CYCLES != 0:
                        _reconnect_failures[node_id] = fails + 1
                        if fails == BACKOFF_THRESHOLD:
                            log.info("Watchdog: %s backing off after %d failures (retry every %ds)",
                                     name, fails, WATCHDOG_INTERVAL * BACKOFF_CYCLES)
                            _log_tunnel_event(node_id, "backoff",
                                              f"Backing off after {fails} failures")
                        continue

                # Try to auto-reconnect based on tunnel type
                if tunnel_method == "wireguard":
                    # WireGuard auto-reconnect logic
                    if db_status in ("online", "error", "connecting") and wg_assigned_ip and installation_status == "success":
                        log.info("Watchdog: auto-reconnecting WireGuard %s -> %s:1080 (attempt %d)",
                                 name, wg_assigned_ip, fails + 1)
                        _log_tunnel_event(node_id, "reconnecting",
                                          f"Auto-reconnecting WireGuard to {wg_assigned_ip} (attempt {fails + 1})")
                        _safe_db_execute(
                            "UPDATE remote_nodes SET status = 'connecting' WHERE id = %s",
                            (node_id,))

                        # Use existing port or allocate new one
                        try:
                            existing_port = allocator.get_node_port(node_id)
                            if existing_port:
                                socks_port = existing_port
                            else:
                                socks_port = allocator.allocate("ssh", node_id)  # Use SSH port range

                            # Start WireGuard tunnel using same logic as manual start
                            socat_cmd = [
                                "socat",
                                f"TCP-LISTEN:{socks_port},fork",
                                f"TCP:{wg_assigned_ip}:1080"
                            ]

                            proc = await asyncio.create_subprocess_exec(
                                *socat_cmd,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )

                            # Store process reference for tracking
                            wg_processes[node_id] = proc

                            # Give it a moment to start
                            await asyncio.sleep(0.5)

                            # Check if process is still running
                            if proc.returncode is None:
                                _safe_db_execute(
                                    "UPDATE remote_nodes SET status = 'online', proxy_port = %s, last_seen = now() WHERE id = %s",
                                    (socks_port, node_id))
                                _log_tunnel_event(node_id, "reconnected",
                                                  f"WireGuard back online on port {socks_port}")
                                log.info("Watchdog: WireGuard %s reconnected", name)
                                _reconnect_failures.pop(node_id, None)
                            else:
                                # Process failed
                                stdout, stderr = await proc.communicate()
                                error_msg = f"socat failed: {stderr.decode().strip()}"
                                _reconnect_failures[node_id] = fails + 1
                                _safe_db_execute(
                                    "UPDATE remote_nodes SET status = 'error' WHERE id = %s",
                                    (node_id,))
                                _log_tunnel_event(node_id, "error", f"WireGuard reconnect failed: {error_msg}")
                                if existing_port != socks_port:  # Only release if we allocated it
                                    allocator.release(socks_port)

                        except Exception as e:
                            _reconnect_failures[node_id] = fails + 1
                            _safe_db_execute(
                                "UPDATE remote_nodes SET status = 'error' WHERE id = %s",
                                (node_id,))
                            _log_tunnel_event(node_id, "error", f"WireGuard reconnect exception: {e}")
                            log.error("Watchdog: WireGuard %s reconnect failed: %s", name, e)

                elif db_status in ("online", "error", "connecting") and meta and isinstance(meta, dict) and meta.get("host"):
                    host = meta["host"]
                    key_file = meta.get("key_file", "id_rsa")
                    key_ok, key_reason = _verify_key_file(key_file)
                    if not key_ok:
                        misses = _keyfile_missing_count.get(node_id, 0) + 1
                        _keyfile_missing_count[node_id] = misses
                        if misses >= KEY_MISSING_THRESHOLD:
                            # Permanently disable so we stop spamming. Operator
                            # has to upload the key (or delete the node) and
                            # then flip status back to 'error' / 'online' to
                            # re-enable the watchdog.
                            _safe_db_execute(
                                "UPDATE remote_nodes SET status = 'disabled' WHERE id = %s",
                                (node_id,))
                            _log_tunnel_event(
                                node_id, "disabled",
                                f"Disabled after {misses} consecutive missing-key checks "
                                f"(key '{key_file}', reason={key_reason}). "
                                f"Upload the key or delete this node to re-enable.")
                            _keyfile_missing_count.pop(node_id, None)
                        else:
                            _safe_db_execute(
                                "UPDATE remote_nodes SET status = 'error' WHERE id = %s",
                                (node_id,))
                            # dedup_window_s suppresses identical repeat logs
                            _log_tunnel_event(
                                node_id, "error",
                                f"Key file '{key_file}' not found ({key_reason}) — "
                                f"attempt {misses}/{KEY_MISSING_THRESHOLD} before disabling",
                                dedup_window_s=1)
                        continue
                    # File is back — clear the missing-key counter
                    _keyfile_missing_count.pop(node_id, None)

                    # TCP pre-flight to the remote sshd port — skip the autossh
                    # spawn when the target is powered off / IP-rotated /
                    # firewalled. Saves a 10-15s SSH timeout AND avoids the
                    # exit-code-1 / "Permission denied" log spam every cycle.
                    ssh_port = int(meta.get("ssh_port", 22) or 22)
                    if not ssh_manager.remote_ssh_port_open(host, ssh_port):
                        _reconnect_failures[node_id] = fails + 1
                        _safe_db_execute(
                            "UPDATE remote_nodes SET status = 'error' WHERE id = %s",
                            (node_id,))
                        _log_tunnel_event(
                            node_id, "unreachable",
                            f"Remote {host}:{ssh_port} not reachable (TCP) — "
                            f"skipping reconnect attempt",
                            dedup_window_s=1)
                        continue

                    log.info("Watchdog: auto-reconnecting %s -> %s:%s (attempt %d)",
                             name, host, meta.get("ssh_port", 22), fails + 1)
                    _log_tunnel_event(node_id, "reconnecting",
                                      f"Auto-reconnecting to {host} (attempt {fails + 1})")
                    _safe_db_execute(
                        "UPDATE remote_nodes SET status = 'connecting' WHERE id = %s",
                        (node_id,))

                    tunnel = _create_tunnel(
                        node_id=node_id,
                        name=name,
                        tunnel_method=tunnel_method,
                        metadata={**meta, "key_file": key_file, "host": host},
                        wg_assigned_ip=wg_assigned_ip,
                        socks_port=port,
                    )
                    result = await ssh_manager.start_tunnel(tunnel)
                    if result.get("ok"):
                        _safe_db_execute(
                            "UPDATE remote_nodes SET status = 'online', last_seen = now() WHERE id = %s",
                            (node_id,))
                        _log_tunnel_event(node_id, "reconnected",
                                          f"Back online on port {port}")
                        log.info("Watchdog: %s reconnected", name)
                        _reconnect_failures.pop(node_id, None)
                    else:
                        err = result.get("error", "unknown")
                        _safe_db_execute(
                            "UPDATE remote_nodes SET status = 'error' WHERE id = %s",
                            (node_id,))
                        _log_tunnel_event(node_id, "error",
                                          f"Reconnect failed: {err}")
                        log.warning("Watchdog: %s reconnect failed: %s", name, err)
                        _reconnect_failures[node_id] = fails + 1
                else:
                    _safe_db_execute(
                        "UPDATE remote_nodes SET status = %s, last_seen = now() WHERE id = %s",
                        (actual, node_id))

        except Exception as e:
            log.debug("Tunnel watchdog error: %s", e)

        # Sync WireGuard server config with database (periodic maintenance)
        try:
            _sync_wg_server_to_database()
        except Exception as e:
            log.debug("WireGuard sync error: %s", e)

        await asyncio.sleep(WATCHDOG_INTERVAL)


# ── Background Installation System ────────────────────────────────────────
# Allows installations to run independently of HTTP requests

_background_tasks: dict[str, dict] = {}  # task_id -> task info

async def _installation_task_processor():
    """Background processor for installation tasks. Runs continuously."""
    await asyncio.sleep(5)  # Wait for startup
    while True:
        try:
            # Get pending tasks from database
            conn = _get_conn()
            cur = conn.cursor()
            cur.execute("""
                SELECT id::text, node_id::text, task_type, tools, progress_log
                FROM installation_tasks
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT 5
            """)
            tasks = cur.fetchall()
            cur.close()
            conn.close()

            for task_id, node_id, task_type, tools, progress_log in tasks:
                if task_id not in _background_tasks:
                    # Start new background task
                    log.info("Starting background installation task %s for node %s", task_id[:8], node_id[:8])
                    asyncio.create_task(_execute_installation_task(task_id, node_id, task_type, tools or []))
                    _background_tasks[task_id] = {
                        "node_id": node_id,
                        "type": task_type,
                        "status": "running"
                    }

        except Exception as e:
            log.error("Installation task processor error: %s", e)

        await asyncio.sleep(10)  # Check for new tasks every 10 seconds

async def _execute_installation_task(task_id: str, node_id: str, task_type: str, tools: list):
    """Execute a single installation task in background."""
    try:
        # Update task status to running
        _safe_db_execute("""
            UPDATE installation_tasks
            SET status = 'running', started_at = now(), updated_at = now()
            WHERE id = %s
        """, (task_id,))

        if task_type == "software":
            await _background_software_install(task_id, node_id, tools)
        elif task_type == "wireguard":
            await _background_wireguard_install(task_id, node_id)
        else:
            raise ValueError(f"Unknown task type: {task_type}")

        # Mark as completed
        _safe_db_execute("""
            UPDATE installation_tasks
            SET status = 'completed', completed_at = now(), updated_at = now()
            WHERE id = %s
        """, (task_id,))

        log.info("Background installation task %s completed successfully", task_id[:8])

    except Exception as e:
        error_msg = str(e)
        log.error("Background installation task %s failed: %s", task_id[:8], error_msg)

        # Mark as failed
        _safe_db_execute("""
            UPDATE installation_tasks
            SET status = 'failed', error_message = %s, completed_at = now(), updated_at = now()
            WHERE id = %s
        """, (error_msg, task_id))
    finally:
        _background_tasks.pop(task_id, None)

async def _background_software_install(task_id: str, node_id: str, tools: list):
    """Execute software installation in background."""
    # Get node info
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT metadata FROM remote_nodes WHERE id = %s AND node_type = 'ssh'
    """, (node_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise Exception("Node not found or not SSH type")

    meta = row[0] or {}
    os_type = meta.get("os_type", "ubuntu")

    def log_progress(event: str, details: dict = None):
        progress = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event}
        if details:
            progress.update(details)
        _safe_db_execute("""
            UPDATE installation_tasks
            SET progress_log = progress_log || %s::jsonb, updated_at = now()
            WHERE id = %s
        """, (json.dumps([progress]), task_id))

    # Install tools one by one
    results = {}
    log_progress("start", {"os_type": os_type, "tools": tools})

    for tool_name in tools:
        if tool_name not in _PROVISION_TOOLS:
            log_progress("tool", {"tool": tool_name, "status": "skipped", "reason": "unknown tool"})
            continue

        spec = _PROVISION_TOOLS[tool_name]
        log_progress("checking", {"tool": tool_name})

        # Check if already installed
        check_result = await ssh_manager.provision_exec(
            node_id=node_id, host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            command=spec["check"], timeout=10,
        )

        if check_result.get("ok") and check_result.get("exit_code", 1) == 0:
            log_progress("tool", {"tool": tool_name, "status": "already_installed"})
            results[tool_name] = {"status": "already_installed"}

            # Update installation status for WireGuard when detected as already installed
            if tool_name == "wireguard":
                _safe_db_execute("""
                    UPDATE remote_nodes
                    SET installation_status = 'success', tunnel_method = 'wireguard', updated_at = now()
                    WHERE id = %s
                """, (node_id,))
                log.info("Updated WireGuard installation status to 'success' for node %s (already installed)", node_id)

            continue

        # Install the tool
        install_cmd = spec.get(os_type)
        if not install_cmd:
            log_progress("tool", {"tool": tool_name, "status": "skipped", "reason": f"unsupported on {os_type}"})
            continue

        log_progress("installing", {"tool": tool_name, "cmd": install_cmd[:100] + "..."})

        install_result = await ssh_manager.provision_exec(
            node_id=node_id, host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            command=install_cmd, timeout=300,  # 5 minute timeout
        )

        if install_result.get("ok") and install_result.get("exit_code", 1) == 0:
            log_progress("tool", {"tool": tool_name, "status": "installed"})
            results[tool_name] = {"status": "installed"}
        else:
            error = install_result.get("error") or install_result.get("stderr", "unknown error")
            log_progress("tool", {"tool": tool_name, "status": "failed", "error": error})
            results[tool_name] = {"status": "failed", "error": error}

    # Update provisioned tools in node metadata
    installed = [t for t, r in results.items() if r.get("status") in ("installed", "already_installed")]
    if installed:
        _safe_db_execute("""
            UPDATE remote_nodes
            SET metadata = metadata || %s,
                capabilities = (SELECT array_agg(DISTINCT elem) FROM unnest(capabilities || %s::text[]) elem)
            WHERE id = %s
        """, (json.dumps({"provisioned_tools": installed}), installed, node_id))

    log_progress("completed", {"installed": installed, "results": results})

async def _background_wireguard_install(task_id: str, node_id: str):
    """Execute WireGuard installation in background."""
    # Get node info
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT metadata, wg_assigned_ip FROM remote_nodes WHERE id = %s
    """, (node_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise Exception("Node not found")

    meta, wg_assigned_ip = row
    meta = meta or {}

    def log_progress(event: str, details: dict = None):
        progress = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event}
        if details:
            progress.update(details)
        _safe_db_execute("""
            UPDATE installation_tasks
            SET progress_log = progress_log || %s::jsonb, updated_at = now()
            WHERE id = %s
        """, (json.dumps([progress]), task_id))

    log_progress("start", {"type": "wireguard"})

    # Install WireGuard tools with automatic cleanup
    install_cmd = f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' wireguard-tools"

    log_progress("installing", {"step": "wireguard-tools"})

    install_result = await ssh_manager.provision_exec(
        node_id=node_id, host=meta["host"],
        user=meta.get("user", "root"),
        ssh_port=meta.get("ssh_port", 22),
        key_file=meta.get("key_file", "id_rsa"),
        command=install_cmd, timeout=300,  # 5 minute timeout
    )

    if not (install_result.get("ok") and install_result.get("exit_code", 1) == 0):
        error = install_result.get("error") or install_result.get("stderr", "Installation failed")
        raise Exception(f"WireGuard installation failed: {error}")

    log_progress("installed", {"step": "wireguard-tools"})

    # Update installation status in database
    _safe_db_execute("""
        UPDATE remote_nodes
        SET installation_status = 'success', tunnel_method = 'wireguard', updated_at = now()
        WHERE id = %s
    """, (node_id,))

    log_progress("completed", {"status": "WireGuard installed successfully"})

    # Emit webhook for successful WireGuard installation
    try:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute("SELECT name FROM remote_nodes WHERE id = %s", (node_id,))
        node_name = cur.fetchone()[0] if cur.rowcount > 0 else "unknown"
        cur.close()
        conn.close()

        _emit_wireguard_event("wireguard_installation_completed", node_id, {
            "node_name": node_name,
            "tunnel_method": "wireguard",
            "operation": "installation",
            "status": "success"
        })
    except Exception:
        pass  # Don't fail installation for webhook issues

# Start the background task processor (moved to startup event below)

async def _connect_sliver_retry():
    """Retry Sliver connection in background."""
    for attempt in range(30):
        if await sliver.connect():
            log.info("Sliver connected on attempt %d", attempt + 1)
            return
        await asyncio.sleep(5)
    log.warning("Could not connect to Sliver after retries; Sliver features disabled")


async def _auto_connect_env_ssh():
    """Auto-create SSH tunnel from .env settings on startup."""
    if not settings.ssh_remote_host:
        log.info("No SSH_REMOTE_HOST set — skipping env auto-connect")
        return

    host = settings.ssh_remote_host
    log.info("SSH_REMOTE_HOST=%s — checking for existing tunnel", host)

    try:
        # Check ALL nodes for this host — skip if any are online
        rows = _safe_db_execute(
            "SELECT id::text, name, status, proxy_port FROM remote_nodes "
            "WHERE node_type = 'ssh' AND (metadata->>'host' = %s OR hostname = %s) "
            "ORDER BY status = 'online' DESC, created_at DESC",
            (host, host), fetch=True,
        ) or []

        has_online = False
        for node_id, name, status, port in rows:
            if status == "online":
                log.info("Env SSH tunnel to %s already online (node %s '%s' :%s) — skipping env auto-connect",
                         host, node_id[:12], name, port)
                has_online = True
                break

        if has_online:
            return

        # Clean ALL stale records for this host
        for node_id, name, status, port in rows:
            if status != "online":
                log.info("Env SSH: removing stale node %s (%s, status=%s) for %s", node_id[:12], name, status, host)
                _safe_db_execute("DELETE FROM remote_nodes WHERE id = %s", (node_id,))
                if allocator:
                    try:
                        allocator.release(port)
                    except Exception:
                        pass

        # Create new tunnel from env vars
        available_keys = SSHManager.list_keys()
        key_name = settings.ssh_key_name
        if key_name not in available_keys:
            log.warning("SSH key '%s' not found in /ssh-keys/ (available: %s) — skipping env auto-connect", key_name, available_keys)
            return

        node_id = str(uuid.uuid4())
        try:
            port = _allocate_port_safe("ssh", node_id)
        except RuntimeError as e:
            log.error("Env SSH: no available port for %s: %s", host, e)
            return

        meta = {
            "host": host,
            "user": settings.ssh_remote_user,
            "ssh_port": settings.ssh_remote_port,
            "key_file": key_name,
            "source": "env",
        }
        # Clean any remaining records holding this port
        _safe_db_execute("DELETE FROM remote_nodes WHERE proxy_port = %s AND status != 'online'", (port,))

        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO remote_nodes
               (id, name, node_type, status, hostname, proxy_port, proxy_type,
                capabilities, metadata, last_seen, first_seen)
               VALUES (%s, %s, 'ssh', 'connecting', %s, %s, 'socks5', %s, %s, %s, %s)""",
            (
                node_id, settings.ssh_tunnel_name,
                host, port,
                psycopg2.extras.Json(["ssh", "scp", "exec"]),
                psycopg2.extras.Json(meta),
                datetime.now(timezone.utc), datetime.now(timezone.utc),
            ),
        )
        conn.commit()
        cur.close()
        conn.close()

        tunnel = SSHTunnel(
            node_id=node_id,
            name=settings.ssh_tunnel_name,
            host=host,
            user=settings.ssh_remote_user,
            ssh_port=settings.ssh_remote_port,
            key_file=key_name,
            socks_port=port,
        )
        ok = await ssh_manager.start_tunnel(tunnel)

        new_status = "online" if ok else "error"
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE remote_nodes SET status = %s, last_seen = %s WHERE id = %s",
            (new_status, datetime.now(timezone.utc), node_id),
        )
        conn.commit()
        cur.close()
        conn.close()

        if ok:
            log.info("Env SSH tunnel '%s' -> %s connected (SOCKS :%d)", settings.ssh_tunnel_name, host, port)
        else:
            allocator.release(port)
            log.error("Env SSH tunnel '%s' -> %s FAILED to connect", settings.ssh_tunnel_name, host)

    except Exception as e:
        log.error("Error in env SSH auto-connect: %s", e)


def _ensure_db_constraints():
    """Ensure required DB indexes and tables exist (idempotent). Runs once at startup."""
    try:
        _safe_db_execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_remote_nodes_ssh_host "
            "ON public.remote_nodes(hostname) WHERE node_type = 'ssh'"
        )
        _safe_db_execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_remote_nodes_proxy_port "
            "ON public.remote_nodes(proxy_port) WHERE proxy_port IS NOT NULL"
        )
        # Tunnel event log for UI display
        conn = _get_conn()
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tunnel_events (
                id          serial PRIMARY KEY,
                node_id     uuid NOT NULL REFERENCES remote_nodes(id) ON DELETE CASCADE,
                event       text NOT NULL,
                detail      text DEFAULT '',
                created_at  timestamptz NOT NULL DEFAULT now()
            )
        """)
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_tunnel_events_node "
            "ON tunnel_events(node_id, created_at DESC)"
        )
        # IP history table for tracking IP assignments/releases per node
        cur.execute("""
            CREATE TABLE IF NOT EXISTS node_ip_history (
                id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                node_id           uuid NOT NULL REFERENCES remote_nodes(id) ON DELETE CASCADE,
                ip_address        inet NOT NULL,
                cloud_provider    text NOT NULL,
                cloud_resource_id text,
                region            text,
                assigned_at       timestamptz NOT NULL DEFAULT now(),
                released_at       timestamptz,
                release_reason    text,
                scan_count        integer DEFAULT 0,
                scan_job_ids      uuid[] DEFAULT '{}',
                metadata          jsonb DEFAULT '{}'::jsonb,
                created_at        timestamptz NOT NULL DEFAULT now()
            )
        """)
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_node_ip_history_node_id "
            "ON node_ip_history(node_id, assigned_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_node_ip_history_active "
            "ON node_ip_history(node_id) WHERE released_at IS NULL"
        )
        # Ensure 'rotating' status is allowed
        try:
            cur.execute("""
                ALTER TABLE remote_nodes DROP CONSTRAINT IF EXISTS remote_nodes_status_check;
                ALTER TABLE remote_nodes ADD CONSTRAINT remote_nodes_status_check
                    CHECK (status IN ('online','offline','degraded','provisioning','connecting','error','rotating'))
            """)
        except Exception:
            pass
        cur.close()
        conn.close()
        log.info("DB constraints verified")
    except Exception as e:
        log.warning("Could not verify DB constraints: %s", e)


def _deconflict_db_ports():
    """Detect and fix duplicate port assignments in the DB at startup.
    Keeps the most recently seen node on each port, NULLs the rest."""
    try:
        # Find ports assigned to multiple nodes
        dupes = _safe_db_execute(
            "SELECT proxy_port, count(*) FROM remote_nodes "
            "WHERE proxy_port IS NOT NULL GROUP BY proxy_port HAVING count(*) > 1",
            fetch=True,
        ) or []
        if not dupes:
            return
        log.warning("Found %d duplicate port assignments — deconflicting", len(dupes))
        for port, count in dupes:
            # Keep the most recently seen node, NULL the port on others
            rows = _safe_db_execute(
                "SELECT id::text, name, status, last_seen FROM remote_nodes "
                "WHERE proxy_port = %s ORDER BY last_seen DESC NULLS LAST",
                (port,), fetch=True,
            ) or []
            for i, (node_id, name, status, _) in enumerate(rows):
                if i == 0:
                    log.info("  Port %d: keeping %s (%s)", port, name, node_id[:12])
                else:
                    log.info("  Port %d: clearing from %s (%s, status=%s)", port, name, node_id[:12], status)
                    _safe_db_execute(
                        "UPDATE remote_nodes SET proxy_port = NULL WHERE id = %s", (node_id,)
                    )
                    if allocator:
                        allocator.release(port)

        # Also check .env SSH_REMOTE_HOST for port collision with existing DB nodes
        if settings.ssh_remote_host:
            env_host = settings.ssh_remote_host
            rows = _safe_db_execute(
                "SELECT proxy_port FROM remote_nodes WHERE hostname = %s AND proxy_port IS NOT NULL",
                (env_host,), fetch=True,
            ) or []
            if rows:
                env_port = rows[0][0]
                # Check if this port is assigned to a different host
                conflict = _safe_db_execute(
                    "SELECT id::text, name, hostname FROM remote_nodes "
                    "WHERE proxy_port = %s AND hostname != %s",
                    (env_port, env_host), fetch=True,
                ) or []
                for node_id, name, hostname in conflict:
                    log.warning("Env SSH host %s port %d conflicts with %s (%s) — clearing conflict",
                                env_host, env_port, name, hostname)
                    _safe_db_execute(
                        "UPDATE remote_nodes SET proxy_port = NULL WHERE id = %s", (node_id,)
                    )
    except Exception as e:
        log.warning("Port deconfliction failed: %s", e)


async def _reload_ssh_tunnels():
    """Reload/reconnect ALL SSH tunnels from DB on startup.

    Reconnects nodes that were online, connecting, or errored before the restart.
    This ensures manually-added tunnels survive container rebuilds.

    Port deconfliction:
      1. Kill orphan SSH processes for hosts no longer in DB
      2. For each node, verify its assigned port is actually free
      3. If port is held by another process/node, reassign to next available
      4. Update DB with new port if changed
    """
    try:
        conn = _get_conn()
        cur = conn.cursor()
        # Reconnect any SSH node that wasn't explicitly decommissioned (exclude WireGuard nodes)
        cur.execute(
            "SELECT id::text, name, proxy_port, metadata, status FROM remote_nodes "
            "WHERE node_type = 'ssh' AND COALESCE(tunnel_method, 'ssh') != 'wireguard' "
            "AND status IN ('online', 'connecting', 'error', 'offline')"
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        # Collect valid hosts from DB so we can kill orphan processes
        valid_hosts = set()
        tunnels_meta = []
        for row in rows:
            node_id, name, socks_port, meta, status = row
            if not meta or not isinstance(meta, dict):
                continue
            host = meta.get("host", "")
            key_file = meta.get("key_file", "id_rsa")
            if not host:
                continue
            valid_hosts.add(host)
            # Verify the key file exists
            key_path = os.path.join("/ssh-keys", key_file)
            if not os.path.isfile(key_path):
                log.warning("Skipping %s (%s): SSH key '%s' not found", name, host, key_file)
                continue
            tunnels_meta.append({
                "node_id": node_id,
                "name": name,
                "host": host,
                "user": meta.get("user", "root"),
                "ssh_port": meta.get("ssh_port", 22),
                "key_file": key_file,
                "socks_port": socks_port,
            })

        # Phase 1: Kill orphan SSH processes for hosts no longer in DB
        if valid_hosts:
            ssh_manager.kill_orphan_tunnels(valid_hosts)

        # Phase 2: Deconflict ports — ensure each node's port is free
        for tm in tunnels_meta:
            old_port = tm["socks_port"]
            new_port = allocator.ensure_port_free(old_port, tm["node_id"], "ssh")
            if new_port != old_port:
                log.info("Port deconfliction: %s reassigned %d -> %d", tm["name"], old_port, new_port)
                tm["socks_port"] = new_port
                # Update DB with new port
                _safe_db_execute(
                    "UPDATE remote_nodes SET proxy_port = %s WHERE id = %s",
                    (new_port, tm["node_id"])
                )
            log.info("Auto-reconnecting SSH tunnel: %s -> %s:%s (port %d)",
                     tm["name"], tm["host"], tm.get("ssh_port", 22), tm["socks_port"])

        if tunnels_meta:
            await ssh_manager.reload_tunnels(tunnels_meta)
            log.info("Reloaded %d SSH tunnels from DB", len(tunnels_meta))
            # Log reload events for each tunnel
            for tm in tunnels_meta:
                rows = _safe_db_execute(
                    "SELECT status FROM remote_nodes WHERE id = %s", (tm["node_id"],), fetch=True
                )
                status = rows[0][0] if rows else "unknown"
                _log_tunnel_event(tm["node_id"], "reconnected" if status == "online" else "error",
                                  f"Startup reload: {status} on port {tm['socks_port']}")
        else:
            log.info("No SSH tunnels to reload from DB")
    except Exception as e:
        log.error("Failed to reload SSH tunnels: %s", e)


async def _reload_wg_tunnels():
    """Reload/reconnect ALL WireGuard tunnels from DB on startup.

    Starts WireGuard tunnels for nodes with successful WireGuard installation.
    Uses socat to forward local SOCKS port to remote microsocks.
    """
    try:
        conn = _get_conn()
        cur = conn.cursor()
        # Reconnect WireGuard nodes with successful installation
        cur.execute("""
            SELECT id::text, name, proxy_port, wg_assigned_ip, status
            FROM remote_nodes
            WHERE tunnel_method = 'wireguard'
            AND installation_status = 'success'
            AND wg_assigned_ip IS NOT NULL
            AND status IN ('online', 'connecting', 'error', 'offline')
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()

        if not rows:
            log.info("No WireGuard tunnels to reload from DB")
            return

        tunnels_meta = []
        for node_id, name, proxy_port, wg_assigned_ip, status in rows:
            tunnels_meta.append({
                "node_id": node_id,
                "name": name,
                "socks_port": proxy_port,
                "wg_assigned_ip": wg_assigned_ip,
                "status": status
            })

        # Start all WireGuard tunnels
        for tm in tunnels_meta:
            node_id = tm["node_id"]
            name = tm["name"]
            socks_port = tm["socks_port"]
            wg_assigned_ip = tm["wg_assigned_ip"]

            # Port deconfliction - check if node already has a port assigned
            existing_port = allocator.get_node_port(node_id)
            if existing_port:
                socks_port = existing_port
            else:
                # Check if the port from DB is already allocated to another node
                current_ports = allocator.allocated_ports
                if socks_port in current_ports and current_ports[socks_port] != node_id:
                    log.warning("Port %d assigned to %s in DB but owned by %s in memory, reallocating",
                               socks_port, name, current_ports[socks_port])
                    # Allocate a new port
                    try:
                        new_port = allocator.allocate("ssh", node_id)  # Use SSH port range for WireGuard
                        _safe_db_execute("UPDATE remote_nodes SET proxy_port = %s WHERE id = %s", (new_port, node_id))
                        socks_port = new_port
                    except RuntimeError as e:
                        log.error("Failed to allocate port for WireGuard tunnel %s: %s", name, e)
                        continue

            # Start WireGuard tunnel using socat
            try:
                # Create socat process to forward local SOCKS port to remote microsocks
                socat_cmd = [
                    "socat",
                    f"TCP-LISTEN:{socks_port},fork",
                    f"TCP:{wg_assigned_ip}:1080"
                ]

                log.info("Starting WireGuard tunnel %s: %s", name, " ".join(socat_cmd))

                proc = await asyncio.create_subprocess_exec(
                    *socat_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                # Store process reference for tracking
                wg_processes[node_id] = proc

                # Give it a moment to start
                await asyncio.sleep(0.5)

                # Check if process is still running
                if proc.returncode is None:
                    # Success
                    _safe_db_execute(
                        "UPDATE remote_nodes SET status = 'online', last_seen = now() WHERE id = %s",
                        (node_id,))
                    _log_tunnel_event(node_id, "reconnected",
                                      f"WireGuard online on port {socks_port}")
                    log.info("Reloaded WireGuard tunnel %s -> %s:1080 (SOCKS :%d)", name, wg_assigned_ip, socks_port)
                else:
                    # Process failed
                    stdout, stderr = await proc.communicate()
                    err = f"socat failed: {stderr.decode().strip()}"
                    _safe_db_execute(
                        "UPDATE remote_nodes SET status = 'error', last_seen = now() WHERE id = %s",
                        (node_id,))
                    _log_tunnel_event(node_id, "error", f"WireGuard startup: {err}")
                    log.warning("Failed to reload WireGuard tunnel %s: %s", name, err)
            except Exception as e:
                log.error("Exception reloading WireGuard tunnel %s: %s", name, e)
                _log_tunnel_event(node_id, "error", f"WireGuard startup exception: {e}")

        if tunnels_meta:
            log.info("Reloaded %d WireGuard tunnels from DB", len(tunnels_meta))
        else:
            log.info("No WireGuard tunnels to reload from DB")
    except Exception as e:
        log.error("Failed to reload WireGuard tunnels: %s", e)


app = FastAPI(title="Node Manager", version="1.0.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_conn():
    """Get a database connection. Retries once on failure."""
    # Build DSN - use remote database if configured
    if settings.remote_db_host:
        if settings.remote_db_password:
            dsn = f"postgresql://{settings.remote_db_user}:{settings.remote_db_password}@{settings.remote_db_host}:{settings.remote_db_port}/{settings.remote_db_name}"
        else:
            dsn = f"postgresql://{settings.remote_db_user}@{settings.remote_db_host}:{settings.remote_db_port}/{settings.remote_db_name}"
    else:
        dsn = settings.db_dsn

    try:
        return psycopg2.connect(dsn)
    except psycopg2.OperationalError:
        import time
        time.sleep(1)
        return psycopg2.connect(dsn)


def _safe_db_execute(sql, params=None, fetch=False, autocommit=True):
    """Execute a DB query safely with connection handling. Returns rows if fetch=True."""
    conn = None
    try:
        conn = _get_conn()
        if autocommit:
            conn.autocommit = True
        cur = conn.cursor()
        cur.execute(sql, params)
        result = cur.fetchall() if fetch else None
        if not autocommit:
            conn.commit()
        cur.close()
        return result
    except Exception as e:
        log.warning("DB query failed: %s — %s", sql[:80], e)
        if conn and not autocommit:
            try:
                conn.rollback()
            except Exception:
                pass
        return [] if fetch else None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _allocate_port_safe(node_type: str, node_id: str, max_retries: int = 3) -> int:
    """Allocate a SOCKS port with retry on UniqueViolation.
    The allocator now skips OS-bound ports automatically."""
    for attempt in range(max_retries):
        try:
            port = allocator.allocate(node_type, node_id)
            return port
        except RuntimeError as e:
            if attempt < max_retries - 1:
                # Port might be held by stale DB record — clean up and retry
                log.warning("Port allocation failed (attempt %d/%d): %s", attempt + 1, max_retries, e)
                _safe_db_execute(
                    "DELETE FROM remote_nodes WHERE status IN ('error', 'connecting') AND last_seen < now() - interval '5 minutes'"
                )
                # Re-sync allocator from DB after cleanup
                allocator._load_from_db()
                import time
                time.sleep(0.5)
            else:
                raise


def _node_row_to_dict(row, columns) -> dict:
    d = dict(zip(columns, row))
    # Serialize special types
    for k in ("id", "internal_ip", "external_ip"):
        if k in d and d[k] is not None:
            d[k] = str(d[k])
    for k in ("created_at", "updated_at", "last_seen", "first_seen"):
        if k in d and d[k] is not None:
            d[k] = d[k].isoformat()
    return d


NODE_COLUMNS = [
    "id", "name", "node_type", "status", "os", "hostname",
    "internal_ip", "external_ip", "network_segment", "proxy_port",
    "proxy_type", "sliver_session_id", "chisel_client_id",
    "capabilities", "metadata", "last_seen", "first_seen",
    "created_at", "updated_at", "tunnel_method", "wg_public_key", "wg_assigned_ip",
    "installation_status", "installation_logs",
]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class NodeRegisterRequest(BaseModel):
    name: str
    node_type: str  # sliver | chisel
    os: Optional[str] = None
    hostname: Optional[str] = None
    internal_ip: Optional[str] = None
    external_ip: Optional[str] = None
    network_segment: Optional[str] = None
    capabilities: Optional[list[str]] = None
    metadata: Optional[dict] = None
    sliver_session_id: Optional[str] = None
    chisel_client_id: Optional[str] = None


class SocksStartRequest(BaseModel):
    session_id: Optional[str] = None  # Override auto-detect


class ImplantRequest(BaseModel):
    name: str
    os: str = "windows"     # windows, linux, darwin
    arch: str = "amd64"     # amd64, arm64
    c2_host: str = ""       # External callback host
    format: str = "exe"     # exe, shared, service, shellcode


class ADAttackRequest(BaseModel):
    target_domain: Optional[str] = None
    custom_args: Optional[str] = None


class SSHConnectRequest(BaseModel):
    name: str
    host: str
    user: str = "root"
    ssh_port: int = 22
    key_name: str = "id_rsa"
    network_segment: Optional[str] = None
    os_type: Optional[str] = "kali"  # kali, ubuntu, debian
    provider: Optional[str] = None  # digitalocean, aws, private, unknown
    tunnel_method: Optional[str] = "ssh"  # ssh, wireguard, hybrid
    wg_assigned_ip: Optional[str] = None  # WireGuard peer IP


class SSHExecRequest(BaseModel):
    command: str
    timeout: int = 30


class SSHUploadRequest(BaseModel):
    remote_path: str


class SSHDownloadRequest(BaseModel):
    remote_path: str


class RemoteScanRequest(BaseModel):
    scan_type: str       # masscan, nmap, nuclei, httpx, etc.
    targets: list[str]   # IPs, CIDRs, or URLs
    ports: Optional[str] = None
    rate: Optional[int] = None
    extra_args: Optional[list[str]] = None  # additional CLI flags
    timeout: int = 600


class ChiselConfigRequest(BaseModel):
    server_host: str  # External address of the chisel server
    node_name: str = "node-1"
    socks_port: Optional[int] = None  # Will be auto-allocated if not set


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    # Collect tunnel statuses
    tunnel_errors = []
    tunnel_summary = {"online": 0, "offline": 0, "error": 0, "connecting": 0}
    try:
        rows = _safe_db_execute(
            "SELECT name, status, hostname, proxy_port FROM remote_nodes "
            "WHERE node_type = 'ssh' ORDER BY name",
            fetch=True,
        ) or []
        for name, status, host, port in rows:
            tunnel_summary[status] = tunnel_summary.get(status, 0) + 1
            if status in ("error", "offline"):
                tunnel_errors.append({
                    "name": name,
                    "host": host,
                    "port": port,
                    "status": status,
                })
    except Exception:
        pass
    return {
        "status": "ok",
        "version": os.environ.get("BUILD_VERSION", "dev"),
        "sliver_connected": sliver.connected,
        "allocated_ports": len(allocator.allocated_ports) if allocator else 0,
        "tunnels": tunnel_summary,
        "tunnel_errors": tunnel_errors,
    }


# ---------------------------------------------------------------------------
# Node CRUD
# ---------------------------------------------------------------------------
@app.get("/nodes")
async def list_nodes():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(f"SELECT {', '.join(NODE_COLUMNS)} FROM remote_nodes ORDER BY created_at DESC")
    rows = cur.fetchall()
    nodes = [_node_row_to_dict(r, NODE_COLUMNS) for r in rows]

    # Attach last error from tunnel_events for each node
    try:
        cur.execute("""
            SELECT DISTINCT ON (node_id) node_id::text, event, detail, created_at
            FROM tunnel_events
            WHERE event IN ('error', 'dropped')
            ORDER BY node_id, created_at DESC
        """)
        error_map = {}
        for nid, event, detail, ts in cur.fetchall():
            error_map[nid] = {"event": event, "detail": detail,
                              "at": ts.isoformat() if ts else None}
        for n in nodes:
            n["last_error"] = error_map.get(n["id"])
    except Exception:
        pass  # tunnel_events table may not exist yet

    cur.close()
    conn.close()
    return {"nodes": nodes}


@app.get("/nodes/{node_id}")
async def get_node(node_id: str):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        f"SELECT {', '.join(NODE_COLUMNS)} FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(404, "Node not found")
    return _node_row_to_dict(row, NODE_COLUMNS)


@app.post("/nodes/register")
async def register_node(req: NodeRegisterRequest):
    if req.node_type not in ("sliver", "chisel", "ssh"):
        raise HTTPException(400, "node_type must be 'sliver', 'chisel', or 'ssh'")

    node_id = str(uuid.uuid4())

    # Allocate proxy port
    try:
        port = allocator.allocate(req.node_type, node_id)
    except RuntimeError as e:
        raise HTTPException(503, str(e))

    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO remote_nodes
           (id, name, node_type, status, os, hostname, internal_ip, external_ip,
            network_segment, proxy_port, sliver_session_id, chisel_client_id,
            capabilities, metadata, last_seen, first_seen)
           VALUES (%s, %s, %s, 'provisioning', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            node_id, req.name, req.node_type,
            req.os, req.hostname,
            req.internal_ip, req.external_ip,
            req.network_segment, port,
            req.sliver_session_id, req.chisel_client_id,
            psycopg2.extras.Json(req.capabilities or []),
            psycopg2.extras.Json(req.metadata or {}),
            datetime.now(timezone.utc), datetime.now(timezone.utc),
        ),
    )
    conn.commit()
    cur.close()
    conn.close()

    log.info("Registered node %s (%s) on port %d", req.name, req.node_type, port)
    return {"id": node_id, "name": req.name, "proxy_port": port, "status": "provisioning"}


@app.delete("/nodes/{node_id}")
async def decommission_node(node_id: str):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT proxy_port FROM remote_nodes WHERE id = %s", (node_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    port = row[0]
    if port:
        allocator.release(port)

    cur.execute("DELETE FROM remote_nodes WHERE id = %s", (node_id,))
    conn.commit()
    cur.close()
    conn.close()
    log.info("Decommissioned node %s (port %s)", node_id, port)
    return {"ok": True, "released_port": port}


class NodePatchRequest(BaseModel):
    os_type: Optional[str] = None  # kali, ubuntu, debian
    tunnel_method: Optional[str] = None  # ssh, wireguard, hybrid


@app.patch("/nodes/{node_id}")
async def patch_node(node_id: str, req: NodePatchRequest):
    """Update node metadata (e.g. os_type)."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT metadata FROM remote_nodes WHERE id = %s", (node_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    updates = {}
    db_updates = {}

    if req.os_type:
        if req.os_type not in ("kali", "ubuntu", "debian"):
            cur.close()
            conn.close()
            raise HTTPException(400, f"Invalid os_type: {req.os_type}")
        updates["os_type"] = req.os_type

    if req.tunnel_method:
        if req.tunnel_method not in ("ssh", "wireguard", "hybrid"):
            cur.close()
            conn.close()
            raise HTTPException(400, f"Invalid tunnel_method: {req.tunnel_method}")
        db_updates["tunnel_method"] = req.tunnel_method

    if updates:
        cur.execute(
            "UPDATE remote_nodes SET metadata = metadata || %s WHERE id = %s",
            (psycopg2.extras.Json(updates), node_id),
        )

    if db_updates:
        if db_updates.get("tunnel_method"):
            try:
                cur.execute(
                    "UPDATE remote_nodes SET tunnel_method = %s WHERE id = %s",
                    (db_updates["tunnel_method"], node_id),
                )
                log.info(f"Updated tunnel_method to {db_updates['tunnel_method']} for node {node_id}")
            except Exception as e:
                log.error(f"Failed to update tunnel_method: {e}")
                db_updates.pop("tunnel_method", None)  # Remove from updates if failed

    if updates or db_updates:
        conn.commit()
        updates.update(db_updates)

    cur.close()
    conn.close()
    return {"ok": True, "updated": updates}


# ---------------------------------------------------------------------------
# Proxy info
# ---------------------------------------------------------------------------
@app.get("/nodes/{node_id}/proxy")
async def get_node_proxy(node_id: str):
    """Get the SOCKS proxy address for routing scans through this node."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT proxy_port, proxy_type, status, node_type, name FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        logging.warning("Node %s not found in DB — may still be reconnecting", node_id[:12])
        raise HTTPException(404, f"Node not found: {node_id[:12]}. Node may still be connecting after restart.")

    port, ptype, status, ntype, name = row
    if status != "online":
        logging.info("Node %s (%s) is %s, not online yet", node_id[:12], name, status)
        raise HTTPException(400, f"Node '{name}' is {status}, not online. Wait for it to reconnect.")
    if not port:
        raise HTTPException(400, "No proxy port allocated")

    # For Sliver nodes, proxy runs on sliver-server container
    # For Chisel nodes, proxy runs on chisel-server container
    # For SSH nodes, proxy runs on node-manager itself (autossh subprocess)
    if ntype == "sliver":
        host = "sliver-server"
    elif ntype == "chisel":
        host = "chisel-server"
    else:
        host = "node-manager"
    return {
        "proxy": f"{ptype}://{host}:{port}",
        "host": host,
        "port": port,
        "type": ptype,
        "node_type": ntype,
    }


# ---------------------------------------------------------------------------
# SOCKS management (Sliver)
# ---------------------------------------------------------------------------
@app.post("/nodes/{node_id}/socks/start")
async def start_socks(node_id: str, req: SocksStartRequest = SocksStartRequest()):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT proxy_port, sliver_session_id, node_type FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    port, db_session_id, ntype = row
    if ntype != "sliver":
        cur.close()
        conn.close()
        raise HTTPException(400, "SOCKS start only supported for Sliver nodes")

    session_id = req.session_id or db_session_id
    if not session_id:
        cur.close()
        conn.close()
        raise HTTPException(400, "No Sliver session ID available")

    ok = await sliver.start_socks(session_id, port)
    if not ok:
        cur.close()
        conn.close()
        raise HTTPException(500, "Failed to start SOCKS proxy")

    cur.execute(
        "UPDATE remote_nodes SET status='online', sliver_session_id=%s, last_seen=%s WHERE id=%s",
        (session_id, datetime.now(timezone.utc), node_id),
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True, "port": port, "session_id": session_id}


@app.post("/nodes/{node_id}/socks/stop")
async def stop_socks(node_id: str):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT sliver_session_id, node_type FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    session_id, ntype = row
    if ntype != "sliver" or not session_id:
        cur.close()
        conn.close()
        raise HTTPException(400, "No active Sliver session")

    await sliver.stop_socks(session_id)
    cur.execute(
        "UPDATE remote_nodes SET status='offline' WHERE id=%s", (node_id,)
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Implant generation
# ---------------------------------------------------------------------------
@app.post("/implants/generate")
async def generate_implant(req: ImplantRequest):
    c2_host = req.c2_host or settings.sliver_c2_host
    if not c2_host:
        raise HTTPException(400, "c2_host required (or set SLIVER_C2_HOST env var)")

    c2_url = f"https://{c2_host}:{settings.sliver_c2_port}"
    data = await sliver.generate_implant(req.os, req.arch, c2_url, req.name, req.format)
    if not data:
        raise HTTPException(500, "Failed to generate implant")

    # Return metadata (actual binary download via separate endpoint)
    return {
        "ok": True,
        "name": req.name,
        "os": req.os,
        "arch": req.arch,
        "c2_url": c2_url,
        "size_bytes": len(data),
        "format": req.format,
    }


@app.get("/implants/list")
async def list_implants():
    """List generated implants from Sliver."""
    # This would query Sliver's implant builds; for now return sessions as proxy
    sessions = await sliver.list_sessions()
    return {"implants": sessions}


# ---------------------------------------------------------------------------
# Sliver sessions
# ---------------------------------------------------------------------------
@app.get("/sessions")
async def list_sessions():
    sessions = await sliver.list_sessions()
    return {"sessions": sessions}


# ---------------------------------------------------------------------------
# AD Attacks
# ---------------------------------------------------------------------------
@app.get("/ad/attacks")
async def list_attack_types():
    return {"attacks": get_attack_types()}


@app.post("/nodes/{node_id}/ad/{attack_type}")
async def execute_ad_attack(node_id: str, attack_type: str, req: ADAttackRequest = ADAttackRequest()):
    if attack_type not in AD_ATTACKS:
        raise HTTPException(400, f"Unknown attack: {attack_type}")

    # Get node's Sliver session
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT sliver_session_id, node_type, status FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise HTTPException(404, "Node not found")
    session_id, ntype, status = row

    if ntype != "sliver":
        raise HTTPException(400, "AD attacks require a Sliver node")
    if status != "online":
        raise HTTPException(400, f"Node is {status}, must be online")
    if not session_id:
        raise HTTPException(400, "No active Sliver session on this node")

    result = await ad_executor.execute_attack(
        node_id, session_id, attack_type,
        target_domain=req.target_domain,
        custom_args=req.custom_args,
    )
    if "error" in result and "result_id" not in result:
        raise HTTPException(500, result["error"])
    return result


@app.get("/nodes/{node_id}/ad/results")
async def get_ad_results(node_id: str):
    results = await ad_executor.get_results(node_id)
    return {"results": results}


@app.get("/ad/results/{result_id}")
async def get_ad_result_detail(result_id: str):
    result = await ad_executor.get_result_detail(result_id)
    if not result:
        raise HTTPException(404, "Result not found")
    return result


# ---------------------------------------------------------------------------
# Chisel config helper
# ---------------------------------------------------------------------------
@app.post("/chisel/config")
async def generate_chisel_config(req: ChiselConfigRequest):
    """Generate a Chisel client command for connecting a remote node."""
    chisel_user = os.environ.get("CHISEL_USER", "pentest")
    chisel_pass = os.environ.get("CHISEL_PASSWORD", "changeme")

    # Auto-allocate port if not provided
    port = req.socks_port
    if not port:
        try:
            temp_id = str(uuid.uuid4())
            port = allocator.allocate("chisel", temp_id)
            # Release immediately — actual allocation happens on register
            allocator.release(port)
        except RuntimeError:
            raise HTTPException(503, "No available Chisel ports")

    command = (
        f"chisel client "
        f"--auth {chisel_user}:{chisel_pass} "
        f"https://{req.server_host}:8443 "
        f"R:{port}:socks"
    )

    return {
        "command": command,
        "server_host": req.server_host,
        "socks_port": port,
        "note": f"After connecting, register the node via POST /nodes/register with chisel_client_id",
    }


# ---------------------------------------------------------------------------
# SSH Tunnel Management
# ---------------------------------------------------------------------------
@app.get("/tunnel-events")
async def get_tunnel_events(node_id: Optional[str] = None, limit: int = 50):
    """Get recent tunnel lifecycle events, optionally filtered by node."""
    if node_id:
        rows = _safe_db_execute(
            "SELECT te.id, te.node_id::text, rn.name, te.event, te.detail, te.created_at "
            "FROM tunnel_events te JOIN remote_nodes rn ON te.node_id = rn.id "
            "WHERE te.node_id = %s ORDER BY te.created_at DESC LIMIT %s",
            (node_id, limit), fetch=True,
        ) or []
    else:
        rows = _safe_db_execute(
            "SELECT te.id, te.node_id::text, rn.name, te.event, te.detail, te.created_at "
            "FROM tunnel_events te JOIN remote_nodes rn ON te.node_id = rn.id "
            "ORDER BY te.created_at DESC LIMIT %s",
            (limit,), fetch=True,
        ) or []
    return {"events": [
        {"id": r[0], "node_id": r[1], "node_name": r[2], "event": r[3],
         "detail": r[4], "created_at": r[5].isoformat() if r[5] else None}
        for r in rows
    ]}


@app.get("/ssh/keys")
async def list_ssh_keys():
    """List available SSH private key files in /ssh-keys/."""
    keys = SSHManager.list_keys()
    return {"keys": keys}


@app.get("/ssh/public-keys")
async def list_ssh_public_keys():
    """List SSH public key files (for cloud provider droplet creation)."""
    keys = SSHManager.list_public_keys()
    return {"keys": keys}


@app.post("/ssh/connect")
async def ssh_connect(req: SSHConnectRequest):
    """Create an SSH tunnel: register node + start autossh SOCKS proxy."""
    # Validate key exists
    available_keys = SSHManager.list_keys()
    if req.key_name not in available_keys:
        raise HTTPException(400, f"SSH key '{req.key_name}' not found. Available: {available_keys}")

    # Check for duplicate: same host + user already connected
    try:
        conn_dup = psycopg2.connect(settings.db_dsn)
        conn_dup.autocommit = True
        cur_dup = conn_dup.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur_dup.execute("""
            SELECT id, name, status, proxy_port FROM remote_nodes
            WHERE node_type = 'ssh' AND hostname = %s
              AND metadata->>'user' = %s
        """, (req.host, req.user))
        existing = cur_dup.fetchone()
        if existing:
            if existing['status'] == 'online':
                cur_dup.close(); conn_dup.close()
                raise HTTPException(409,
                    f"SSH tunnel to {req.user}@{req.host} already exists: "
                    f"'{existing['name']}' (status={existing['status']}, SOCKS:{existing['proxy_port']}). "
                    f"Disconnect it first or use reconnect.")
            else:
                # Stale record (connecting/error/offline) — clean it up and proceed
                logging.info("Cleaning stale node %s (%s) in status '%s' for %s@%s",
                             existing['id'][:12], existing['name'], existing['status'], req.user, req.host)
                cur_dup.execute("DELETE FROM remote_nodes WHERE id = %s", (existing['id'],))
        cur_dup.close(); conn_dup.close()
    except HTTPException:
        raise
    except Exception:
        pass  # DB error — proceed anyway

    node_id = str(uuid.uuid4())

    # Allocate SOCKS port (with retry on port conflicts)
    try:
        port = _allocate_port_safe("ssh", node_id)
    except RuntimeError as e:
        raise HTTPException(503, f"No available SOCKS ports: {e}")

    # Upsert node into DB (unique on hostname for SSH)
    meta = {
        "host": req.host,
        "user": req.user,
        "ssh_port": req.ssh_port,
        "key_file": req.key_name,
        "os_type": req.os_type or "kali",
        "provider": req.provider or "unknown",
    }
    now = datetime.now(timezone.utc)
    conn = _get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO remote_nodes
               (id, name, node_type, status, hostname, network_segment,
                proxy_port, proxy_type, capabilities, metadata, tunnel_method, wg_assigned_ip,
                last_seen, first_seen)
               VALUES (%s, %s, 'ssh', 'connecting', %s, %s, %s, 'socks5', %s, %s, %s, %s, %s, %s)
               ON CONFLICT (hostname) WHERE node_type = 'ssh'
               DO UPDATE SET name = EXCLUDED.name, status = 'connecting',
                   proxy_port = EXCLUDED.proxy_port, network_segment = EXCLUDED.network_segment,
                   metadata = EXCLUDED.metadata, tunnel_method = EXCLUDED.tunnel_method,
                   wg_assigned_ip = EXCLUDED.wg_assigned_ip, last_seen = EXCLUDED.last_seen""",
            (
                node_id, req.name,
                req.host, req.network_segment,
                port,
                psycopg2.extras.Json(["ssh", "scp", "exec"]),
                psycopg2.extras.Json(meta),
                req.tunnel_method or "ssh",
                req.wg_assigned_ip,
                now, now,
            ),
        )
        # Get the actual node details (may differ if upserted)
        cur.execute("""
            SELECT id::text, COALESCE(tunnel_method, 'ssh'), wg_assigned_ip
            FROM remote_nodes WHERE hostname = %s AND node_type = 'ssh'
        """, (req.host,))
        row = cur.fetchone()
        if row:
            node_id, tunnel_method, wg_assigned_ip = row
        conn.commit()
    except Exception as e:
        conn.rollback()
        log.error("Failed to upsert node: %s", e)
        raise HTTPException(500, f"DB error: {e}")
    finally:
        cur.close()
        conn.close()

    # Start the tunnel (SSH or WireGuard)
    tunnel = _create_tunnel(
        node_id=node_id,
        name=req.name,
        tunnel_method=tunnel_method,
        metadata={
            "host": req.host,
            "user": req.user,
            "ssh_port": req.ssh_port,
            "key_file": req.key_name,
        },
        wg_assigned_ip=wg_assigned_ip,
        socks_port=port,
    )
    result = await ssh_manager.start_tunnel(tunnel)

    # Update DB status — always runs, even if start_tunnel failed
    new_status = "online" if result.get("ok") else "error"
    _safe_db_execute(
        "UPDATE remote_nodes SET status = %s, last_seen = %s WHERE id = %s",
        (new_status, datetime.now(timezone.utc), node_id),
    )

    if not result.get("ok"):
        allocator.release(port)
        detail = {
            "error": result.get("error", "Failed to establish SSH tunnel"),
            "stderr": result.get("stderr"),
            "hint": result.get("hint"),
            "host": req.host,
            "port": req.ssh_port,
            "user": req.user,
            "key": req.key_name,
        }
        raise HTTPException(500, detail)

    log.info("SSH tunnel %s connected -> %s (SOCKS :%d)", req.name, req.host, port)
    _log_tunnel_event(node_id, "connected", f"Connected to {req.host} on port {port}")

    # Record IP assignment in history
    provider = (meta.get("provider") or "manual").lower()
    if provider not in ("digitalocean", "aws", "azure"):
        provider = "manual"
    _record_ip_assignment(node_id, req.host, provider, None, req.network_segment, proxy_port=port)

    return {"id": node_id, "name": req.name, "proxy_port": port, "status": "online"}


@app.post("/ssh/{node_id}/disconnect")
async def ssh_disconnect(node_id: str):
    """Stop an SSH tunnel and set node offline."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, status FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    ntype, status = row
    if ntype != "ssh":
        cur.close()
        conn.close()
        raise HTTPException(400, "Node is not an SSH tunnel")

    await ssh_manager.stop_tunnel(node_id)
    cur.execute(
        "UPDATE remote_nodes SET status = 'offline', last_seen = %s WHERE id = %s",
        (datetime.now(timezone.utc), node_id),
    )
    conn.commit()
    cur.close()
    conn.close()
    log.info("SSH tunnel %s disconnected", node_id)
    _log_tunnel_event(node_id, "disconnected", "Manually disconnected")
    return {"ok": True, "status": "offline"}


@app.post("/ssh/{node_id}/reconnect")
async def ssh_reconnect(node_id: str):
    """Reconnect an existing offline SSH tunnel using its stored metadata."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, status, hostname, proxy_port, metadata, name, network_segment FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    ntype, status, hostname, proxy_port, meta, name, network_segment = row
    cur.close()
    conn.close()

    if ntype != "ssh":
        raise HTTPException(400, "Node is not an SSH tunnel")

    if status == "online":
        # Already online — check if process is alive
        actual = ssh_manager.check_tunnel(node_id)
        if actual == "online":
            return {"ok": True, "status": "online", "message": "Already connected"}

    # Extract connection details from metadata
    host = meta.get("host", hostname)
    user = meta.get("user", "root")
    ssh_port = meta.get("ssh_port", 22)
    key_file = meta.get("key_file", "id_rsa")

    # Validate key exists
    available_keys = SSHManager.list_keys()
    if key_file not in available_keys:
        raise HTTPException(400, f"SSH key '{key_file}' not found. Available: {available_keys}")

    # Re-allocate the same port or get a new one
    existing_port = allocator.get_node_port(node_id)
    if existing_port:
        socks_port = existing_port
    else:
        try:
            socks_port = allocator.allocate("ssh", node_id)
        except RuntimeError as e:
            raise HTTPException(503, str(e))
        # Update port in DB if it changed
        if socks_port != proxy_port:
            conn = _get_conn()
            cur = conn.cursor()
            cur.execute(
                "UPDATE remote_nodes SET proxy_port = %s WHERE id = %s",
                (socks_port, node_id),
            )
            conn.commit()
            cur.close()
            conn.close()

    # Update status to connecting
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE remote_nodes SET status = 'connecting', last_seen = %s WHERE id = %s",
        (datetime.now(timezone.utc), node_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    # Start the tunnel
    tunnel = SSHTunnel(
        node_id=node_id,
        name=name,
        host=host,
        user=user,
        ssh_port=ssh_port,
        key_file=key_file,
        socks_port=socks_port,
    )
    result = await ssh_manager.start_tunnel(tunnel)

    new_status = "online" if result.get("ok") else "error"
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE remote_nodes SET status = %s, last_seen = %s WHERE id = %s",
        (new_status, datetime.now(timezone.utc), node_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    if not result.get("ok"):
        allocator.release(socks_port)
        detail = {
            "error": result.get("error", "Failed to re-establish SSH tunnel"),
            "stderr": result.get("stderr"),
            "hint": result.get("hint"),
            "host": host,
            "port": ssh_port,
            "user": user,
            "key": key_file,
        }
        raise HTTPException(500, detail)

    log.info("SSH tunnel %s reconnected -> %s (SOCKS :%d)", name, host, socks_port)
    _log_tunnel_event(node_id, "reconnected", f"Reconnected to {host} on port {socks_port}")
    return {"ok": True, "status": "online", "proxy_port": socks_port}


@app.post("/ssh/{node_id}/exec")
async def ssh_exec(node_id: str, req: SSHExecRequest):
    """Execute a command on a remote host via SSH (supports WireGuard nodes with SSH fallback)."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, status, metadata, tunnel_method FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    ntype, status, meta, tunnel_method = row
    cur.close()
    conn.close()

    # Allow SSH commands on SSH nodes and WireGuard nodes (with SSH fallback)
    if ntype != "ssh" and tunnel_method not in ("wireguard", "hybrid"):
        raise HTTPException(400, "Node does not support SSH execution")

    if not meta or not isinstance(meta, dict):
        raise HTTPException(500, "Node metadata missing")

    # Check if we need to use SSH tunnel or direct SSH
    use_tunnel = False
    if tunnel_method == "ssh" or (tunnel_method in ("hybrid", "wireguard") and status == "online"):
        # For SSH nodes or online hybrid/WireGuard nodes, verify tunnel is alive
        tunnel_status = ssh_manager.check_tunnel(node_id)
        if tunnel_status == "online":
            use_tunnel = True
        elif tunnel_method == "ssh":
            # Pure SSH nodes must have working tunnel
            dbc = _get_conn()
            dbc.cursor().execute("UPDATE remote_nodes SET status='offline' WHERE id=%s", (node_id,))
            dbc.commit()
            dbc.close()
            raise HTTPException(503, f"SSH tunnel is {tunnel_status}. The connection has dropped — reconnect before running commands.")

    # For WireGuard/hybrid nodes with failed tunnels, try direct SSH as fallback
    if not use_tunnel and tunnel_method in ("wireguard", "hybrid"):
        if not meta.get("host"):
            raise HTTPException(500, "Cannot use direct SSH fallback: host metadata missing")
        log.info(f"WireGuard tunnel down for {node_id}, attempting direct SSH fallback to {meta['host']}")

    result = await ssh_manager.exec_command(
        node_id=node_id if use_tunnel else None,  # None = direct SSH, node_id = use tunnel
        host=meta["host"],
        user=meta.get("user", "root"),
        ssh_port=meta.get("ssh_port", 22),
        key_file=meta.get("key_file", "id_rsa"),
        command=req.command,
        timeout=req.timeout,
    )

    # If command failed due to SSH connection issue, mark node offline
    if not result.get("ok"):
        err = (result.get("error", "") + result.get("stderr", "")).lower()
        if any(s in err for s in ("connection refused", "connection reset", "broken pipe", "no route", "timed out")):
            dbc = _get_conn()
            dbc.cursor().execute("UPDATE remote_nodes SET status='offline' WHERE id=%s", (node_id,))
            dbc.commit()
            dbc.close()
            result["tunnel_lost"] = True
            result["error"] = f"SSH connection lost: {result.get('error', '')}. Tunnel marked offline."

    return result


@app.post("/ssh/{node_id}/upload")
async def ssh_upload(node_id: str, remote_path: str, file: bytes = b""):
    """Upload a file to a remote host via SCP (supports WireGuard nodes with SSH fallback).
    Accepts multipart form data with 'file' field or raw bytes."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, status, metadata, tunnel_method FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    ntype, status, meta, tunnel_method = row
    cur.close()
    conn.close()

    # Allow SSH operations on SSH nodes and WireGuard nodes (with SSH fallback)
    if ntype != "ssh" and tunnel_method not in ("wireguard", "hybrid"):
        raise HTTPException(400, "Node does not support SSH operations")

    if not meta or not isinstance(meta, dict):
        raise HTTPException(500, "Node metadata missing")

    # Write uploaded bytes to a temp file
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file)
        local_path = tmp.name

    try:
        result = await ssh_manager.upload_file(
            host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            local_path=local_path,
            remote_path=remote_path,
        )
    finally:
        os.unlink(local_path)

    return result


@app.post("/ssh/{node_id}/download")
async def ssh_download(node_id: str, req: SSHDownloadRequest):
    """Download a file from a remote host via SCP (supports WireGuard nodes with SSH fallback)."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, status, metadata, tunnel_method FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    ntype, status, meta, tunnel_method = row
    cur.close()
    conn.close()

    # Allow SSH operations on SSH nodes and WireGuard nodes (with SSH fallback)
    if ntype != "ssh" and tunnel_method not in ("wireguard", "hybrid"):
        raise HTTPException(400, "Node does not support SSH operations")

    if not meta or not isinstance(meta, dict):
        raise HTTPException(500, "Node metadata missing")

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix="_download") as tmp:
        local_path = tmp.name

    result = await ssh_manager.download_file(
        host=meta["host"],
        user=meta.get("user", "root"),
        ssh_port=meta.get("ssh_port", 22),
        key_file=meta.get("key_file", "id_rsa"),
        remote_path=req.remote_path,
        local_path=local_path,
    )

    if not result.get("ok"):
        os.unlink(local_path)
        raise HTTPException(500, result.get("error", "Download failed"))

    from fastapi.responses import FileResponse
    return FileResponse(
        local_path,
        filename=os.path.basename(req.remote_path),
        media_type="application/octet-stream",
    )


# ---------------------------------------------------------------------------
# Remote Tool Execution — run tools directly on SSH dropbox hosts
# ---------------------------------------------------------------------------
REMOTE_SCAN_TEMPLATES = {
    "masscan": {
        "cmd": ["masscan", "-p", "{ports}", "--rate", "{rate}", "-oJ", "/tmp/scan_out.json"],
        "output": "/tmp/scan_out.json",
        "ingest": "masscan",
    },
    "nmap": {
        "cmd": ["nmap", "-sV", "-oX", "/tmp/scan_out.xml", "-p", "{ports}"],
        "output": "/tmp/scan_out.xml",
        "ingest": "nmap",
    },
    "httpx": {
        "cmd": ["httpx", "-json", "-o", "/tmp/scan_out.json"],
        "output": "/tmp/scan_out.json",
        "ingest": "httpx",
    },
    "nuclei": {
        "cmd": ["nuclei", "-jsonl", "-o", "/tmp/scan_out.json"],
        "output": "/tmp/scan_out.json",
        "ingest": "nuclei",
    },
    # Tools that don't support SOCKS proxy — push to remote node for direct execution
    "hydra": {
        # hydra for credential testing (brutus alternative on remote node)
        # targets appended after cmd; extra_args for -L/-P/-u/-s flags
        "cmd": ["hydra", "-o", "/tmp/scan_out.json", "-b", "json"],
        "output": "/tmp/scan_out.json",
        "ingest": "brutus",
    },
    "playwright": {
        # Run playwright/chromium screenshot+crawl on remote node
        # Expects playwright + chromium installed; targets = URLs
        "cmd": ["python3", "-m", "playwright", "screenshot", "--output", "/tmp/screenshots/"],
        "output": "/tmp/screenshots/",
        "ingest": None,  # screenshots handled separately
    },
    "katana-remote": {
        # Web spider on remote node (no proxy needed, runs locally)
        "cmd": ["katana", "-json", "-o", "/tmp/scan_out.json", "-d", "{depth}"],
        "output": "/tmp/scan_out.json",
        "ingest": "katana",
    },
    "subzy": {
        # Subdomain takeover detection on remote node
        "cmd": ["subzy", "run", "--targets", "/tmp/targets.txt", "--output", "/tmp/scan_out.json"],
        "output": "/tmp/scan_out.json",
        "ingest": "subzy",
    },
    "golinkfinder": {
        # JS endpoint extraction on remote node
        "cmd": ["GoLinkFinder", "-d", "{target}", "-o", "/tmp/scan_out.txt"],
        "output": "/tmp/scan_out.txt",
        "ingest": "golinkfinder",
    },
    "email-enum": {
        # Email infrastructure audit — script auto-installs dnspython if missing
        "cmd": ["python3", "/tmp/service_enum_cli.py", "--domain", "{domain}", "--services", "email", "--output", "/tmp/scan_out.json"],
        "output": "/tmp/scan_out.json",
        "ingest": "service-enum",
        "_upload_script": True,
    },
    "dns-enum": {
        # DNS infrastructure audit — script auto-installs dnspython if missing
        "cmd": ["python3", "/tmp/service_enum_cli.py", "--domain", "{domain}", "--services", "dns", "--output", "/tmp/scan_out.json"],
        "output": "/tmp/scan_out.json",
        "ingest": "service-enum",
        "_upload_script": True,
    },
    "service-enum": {
        # Full service enumeration — script auto-installs dnspython if missing
        "cmd": ["python3", "/tmp/service_enum_cli.py", "--domain", "{domain}", "--services", "all", "--output", "/tmp/scan_out.json"],
        "output": "/tmp/scan_out.json",
        "ingest": "service-enum",
        "_upload_script": True,
    },
    "whois": {
        # WHOIS lookup on remote node — runs whois for each target, saves raw output
        # Parsing happens locally after download (in _whois_ingest handler)
        "cmd": ["whois", "{target}"],
        "output": "/tmp/whois_out.txt",
        "ingest": None,
        "_whois_ingest": True,
        "_per_target": True,  # run once per target, not all at once
    },
}


@app.post("/ssh/{node_id}/remote-scan")
async def remote_scan(node_id: str, req: RemoteScanRequest):
    """Run a scan tool on a remote SSH host, download results, and ingest them."""
    if req.scan_type not in REMOTE_SCAN_TEMPLATES:
        raise HTTPException(400, f"Unsupported scan type: {req.scan_type}. "
                            f"Available: {list(REMOTE_SCAN_TEMPLATES.keys())}")

    # Look up node metadata
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, status, metadata, hostname FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise HTTPException(404, "Node not found")
    ntype, status, meta, hostname = row

    if ntype != "ssh":
        raise HTTPException(400, "Remote scan requires an SSH node")
    if status != "online":
        raise HTTPException(400, f"Node is {status}, not online")
    if not meta or not isinstance(meta, dict):
        raise HTTPException(500, "Node metadata missing")

    # Build tool command from template — substitute placeholders
    tmpl = REMOTE_SCAN_TEMPLATES[req.scan_type]
    # Compute substitution values
    domain_val = req.targets[0] if req.targets else "unknown"
    domain_val = domain_val.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    target_val = req.targets[0] if req.targets else "unknown"
    depth_val = "3"
    if req.extra_args:
        for i, a in enumerate(req.extra_args):
            if a == "--depth" and i + 1 < len(req.extra_args):
                depth_val = req.extra_args[i + 1]
                break

    cmd = []
    for part in tmpl["cmd"]:
        # Replace embedded placeholders in any position within the string
        part = part.replace("{ports}", req.ports or "1-1000")
        part = part.replace("{rate}", str(req.rate or 1000))
        part = part.replace("{domain}", domain_val)
        part = part.replace("{target}", target_val)
        part = part.replace("{targets}", " ".join(req.targets) if req.targets else domain_val)
        part = part.replace("{depth}", depth_val)
        cmd.append(part)

    # Upload service_enum_cli.py if the template requires it
    if tmpl.get("_upload_script"):
        import pathlib
        cli_script = pathlib.Path(__file__).parent / "service_enum_cli.py"
        if cli_script.exists():
            try:
                await ssh_manager.upload_file(
                    node_id=node_id,
                    host=meta["host"],
                    user=meta.get("user", "root"),
                    ssh_port=meta.get("ssh_port", 22),
                    key_file=meta.get("key_file", "id_rsa"),
                    local_path=str(cli_script),
                    remote_path="/tmp/service_enum_cli.py",
                )
                log.info("Uploaded service_enum_cli.py to node %s", node_id)
            except Exception as e:
                log.warning("Failed to upload service_enum_cli.py: %s — will try anyway", e)

    # Resolve hostnames to IPs for masscan (it only accepts IPs/CIDRs)
    targets = list(req.targets)
    if req.scan_type == "masscan":
        resolved = []
        for t in targets:
            # Skip if already an IP or CIDR
            if t.replace(".", "").replace("/", "").replace(":", "").isdigit():
                resolved.append(t)
                continue
            try:
                import socket
                infos = socket.getaddrinfo(t, None, socket.AF_INET)
                ips = list({info[4][0] for info in infos})
                if ips:
                    log.info("Resolved %s → %s for masscan", t, ips)
                    resolved.extend(ips)
                else:
                    log.warning("Could not resolve %s, skipping", t)
            except Exception as e:
                log.warning("DNS resolution failed for %s: %s", t, e)
        targets = resolved
        if not targets:
            raise HTTPException(400, "No valid IP targets after DNS resolution")

    # Append targets
    cmd.extend(targets)

    # Append extra args if provided
    if req.extra_args:
        cmd.extend(req.extra_args)

    job_id = str(uuid.uuid4())
    t0 = time.time()

    write_audit("scan_started", req.scan_type, "node_manager", {
        "job_id": job_id, "execution_mode": "remote", "node_id": node_id,
        "targets": req.targets[:20], "targets_count": len(req.targets),
        "parameters": {"ports": req.ports, "rate": req.rate},
    })

    log.info("Remote scan %s on node %s: %s", req.scan_type, node_id, " ".join(cmd))

    # Per-target mode: run command once per target, collect stdout as results
    if tmpl.get("_per_target") and req.targets:
        all_results = {}
        for tgt in req.targets:
            tgt = tgt.strip()
            if not tgt:
                continue
            per_cmd = [p.replace("{target}", tgt) for p in tmpl["cmd"]]
            try:
                exec_result = await ssh_manager.exec_command(
                    node_id=node_id,
                    host=meta["host"],
                    user=meta.get("user", "root"),
                    ssh_port=meta.get("ssh_port", 22),
                    key_file=meta.get("key_file", "id_rsa"),
                    command=" ".join(per_cmd),
                    timeout=min(req.timeout or 300, 30),
                )
                all_results[tgt] = exec_result.get("stdout", "")
            except Exception as e:
                all_results[tgt] = ""
                log.warning("WHOIS remote exec failed for %s: %s", tgt, e)

        duration_s = round(time.time() - t0, 2)

        # Parse and ingest WHOIS results locally
        ingest_result = {}
        if tmpl.get("_whois_ingest"):
            try:
                from osint_runner.osint_runner import _parse_whois_domain, _parse_whois_ip
            except ImportError:
                _parse_whois_domain = None
            ingested = 0
            conn = _get_conn()
            conn.autocommit = True
            cur = conn.cursor()
            for tgt, raw in all_results.items():
                if not raw.strip():
                    continue
                import re as _re
                is_ip = bool(_re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', tgt))
                # Simple field extraction
                parsed = {"raw_length": len(raw), "target": tgt, "type": "ip" if is_ip else "domain"}
                field_map = {
                    "org": ["OrgName:", "org:", "Registrant Organization:"],
                    "registrar": ["Registrar:", "registrar:"],
                    "creation_date": ["Creation Date:", "created:"],
                    "country": ["Country:", "country:", "Registrant Country:"],
                    "net_range": ["NetRange:", "inetnum:"],
                    "cidr": ["CIDR:", "route:"],
                    "asn": ["OriginAS:", "origin:"],
                    "name_servers": ["Name Server:", "nserver:"],
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
                        parsed[key] = values if key == "name_servers" else values[0]
                finding_type = "whois_ip" if is_ip else "whois_record"
                cur.execute(
                    "INSERT INTO recon_findings (source, finding_type, target, data, severity) "
                    "VALUES ('whois', %s, %s, %s, 'info') ON CONFLICT DO NOTHING",
                    (finding_type, tgt, json.dumps(parsed)),
                )
                ingested += 1
            cur.close(); conn.close()
            ingest_result = {"ok": True, "ingested": ingested, "total": len(all_results)}
            log.info("WHOIS remote: ingested %d/%d", ingested, len(all_results))

        write_audit("scan_completed", req.scan_type, "node_manager", {
            "job_id": job_id, "execution_mode": "remote", "node_id": node_id,
            "duration_s": duration_s, "targets": len(req.targets),
        })
        return {
            "ok": True, "job_id": job_id, "scan_type": req.scan_type,
            "node_id": node_id, "execution_mode": "remote",
            "duration_s": duration_s, "ingest": ingest_result,
            "targets_processed": len(all_results),
        }

    # Standard mode: run full command, download output file, ingest
    result = await ssh_manager.remote_scan(
        node_id=node_id,
        host=meta["host"],
        user=meta.get("user", "root"),
        ssh_port=meta.get("ssh_port", 22),
        key_file=meta.get("key_file", "id_rsa"),
        tool_cmd=cmd,
        output_remote_path=tmpl["output"],
        timeout=req.timeout,
    )

    duration_s = round(time.time() - t0, 2)

    if not result.get("ok"):
        error_detail = result.get("error") or result.get("stderr", "").strip() or "Remote scan failed"
        log.warning("Remote scan failed: %s | stdout=%s | stderr=%s",
                    error_detail, result.get("stdout", "")[:200], result.get("stderr", "")[:200])
        write_audit("scan_failed", req.scan_type, "node_manager", {
            "job_id": job_id, "execution_mode": "remote", "node_id": node_id,
            "error": error_detail[:500], "duration_s": duration_s,
        })
        raise HTTPException(500, {
            "error": error_detail[:500],
            "stdout": result.get("stdout", "")[-500:],
            "stderr": result.get("stderr", "")[-500:],
            "exit_code": result.get("exit_code"),
        })

    # Ingest the downloaded results
    local_path = result["local_path"]
    ingest_result = {}

    # Custom WHOIS ingest — parse JSON and insert directly into recon_findings
    if tmpl.get("_whois_ingest"):
        try:
            import json as _json
            with open(local_path) as f:
                whois_data = _json.load(f)
            conn = _get_conn()
            conn.autocommit = True
            cur = conn.cursor()
            ingested = 0
            for tgt, wdata in whois_data.items():
                if wdata.get("error"):
                    continue
                finding_type = "whois_ip" if wdata.get("type") == "ip" else "whois_record"
                cur.execute(
                    "INSERT INTO recon_findings (source, finding_type, target, data, severity) "
                    "VALUES ('whois', %s, %s, %s, 'info') ON CONFLICT DO NOTHING",
                    (finding_type, tgt, _json.dumps(wdata)),
                )
                ingested += 1
            cur.close(); conn.close()
            ingest_result = {"ok": True, "ingested": ingested, "total": len(whois_data)}
            log.info("WHOIS remote scan: ingested %d/%d results", ingested, len(whois_data))
        except Exception as e:
            log.warning("WHOIS ingest failed: %s", e)
            ingest_result = {"ok": False, "error": str(e)}
    else:
        ingest_type = tmpl.get("ingest")
        if not ingest_type:
            # No ingest endpoint (e.g. screenshots) — just report success
            ingest_result = {"ok": True, "note": "no ingest endpoint, output downloaded only"}
        else:
            try:
                import requests as req_lib
                api_base = os.environ.get("API_BASE", "https://rag-api:8000")
                api_key = os.environ.get("API_KEY", "changeme")

                with open(local_path, "rb") as fh:
                    resp = req_lib.post(
                        f"{api_base}/ingest/{ingest_type}",
                        headers={"x-api-key": api_key},
                        files={"file": (f"remote_{req.scan_type}.json", fh, "application/json")},
                        params={"job_id": job_id},
                        timeout=300,
                    )
                if resp.status_code < 300:
                    ingest_result = resp.json()
                else:
                    ingest_result = {"ok": False, "error": f"HTTP {resp.status_code}"}
            except Exception as e:
                log.warning("Remote scan ingest failed: %s", e)
                ingest_result = {"ok": False, "error": str(e)}
    # Cleanup temp file
    try:
        os.unlink(local_path)
    except OSError:
        pass

    write_audit("scan_completed", req.scan_type, "node_manager", {
        "job_id": job_id, "execution_mode": "remote", "node_id": node_id,
        "duration_s": duration_s,
    })

    return {
        "ok": True,
        "job_id": job_id,
        "scan_type": req.scan_type,
        "node_id": node_id,
        "execution_mode": "remote",
        "duration_s": duration_s,
        "ingest": ingest_result,
        "stdout": result.get("stdout", "")[-500:],
        "stderr": result.get("stderr", "")[-500:],
    }


# ---------------------------------------------------------------------------
# Remote Node Provisioning — install scan tools on SSH nodes
# ---------------------------------------------------------------------------

# Local binary paths (mounted from osint_runner/bin and pd_runner/bin)
# Used to SCP push binaries to remote nodes instead of downloading
_LOCAL_BINARIES = {
    "httpx":       ["/tool-bins/osint/httpx", "/tool-bins/pd/httpx"],
    "subfinder":   ["/tool-bins/osint/subfinder"],
    "nuclei":      ["/tool-bins/osint/nuclei", "/tool-bins/pd/nuclei"],
    "katana":      ["/tool-bins/pd/katana"],
    "naabu":       ["/tool-bins/pd/naabu"],
    "tlsx":        ["/tool-bins/osint/tlsx", "/tool-bins/pd/tlsx"],
    "ffuf":        ["/tool-bins/pd/ffuf"],
    "dnsx":        ["/tool-bins/osint/dnsx"],
    "amass":       ["/tool-bins/osint/amass"],
    "gau":         ["/tool-bins/osint/gau"],
    "waybackurls": ["/tool-bins/osint/waybackurls"],
    "gowitness":   ["/tool-bins/osint/gowitness"],
    "shuffledns":  ["/tool-bins/osint/shuffledns"],
    "uncover":     ["/tool-bins/osint/uncover"],
}


def _find_local_binary(tool: str) -> str:
    """Find a local binary for the tool, or return None."""
    for path in _LOCAL_BINARIES.get(tool, []):
        if os.path.isfile(path):
            return path
    return None


# Prep command: run once before any installs (apt update + prereqs)
_NONINTERACTIVE = (
    "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a && "
    # Suppress Ubuntu 22.04+ needrestart interactive prompts
    "mkdir -p /etc/needrestart/conf.d 2>/dev/null; "
    "echo '\\$nrconf{restart} = \"a\";' > /etc/needrestart/conf.d/no-prompt.conf 2>/dev/null; "
    # Suppress dpkg config file prompts
    "export APT_OPTS='-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold'"
)
_APT_INSTALL = "apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'"

# Enhanced prerequisite setup with automatic permission/lock fixes
_APT_CLEANUP = (
    "# Clean up any stuck apt processes and locks\n"
    "pkill -f 'apt|dpkg' 2>/dev/null || true; "
    "rm -f /var/lib/dpkg/lock* /var/cache/apt/archives/lock /var/lib/apt/lists/lock 2>/dev/null || true; "
    "dpkg --configure -a 2>/dev/null || true"
)

_PROVISION_PREP = {
    "kali":   f"{_APT_CLEANUP}; {_NONINTERACTIVE} && apt-get update && {_APT_INSTALL} curl unzip python3-pip",
    "ubuntu": f"{_APT_CLEANUP}; {_NONINTERACTIVE} && apt-get update && {_APT_INSTALL} curl unzip python3-pip",
    "debian": f"{_APT_CLEANUP}; {_NONINTERACTIVE} && apt-get update && {_APT_INSTALL} curl unzip python3-pip",
}

# Helper: download a PD binary release. Works on amd64/arm64 Linux.
def _pd_binary_cmd(tool: str) -> str:
    """Download latest ProjectDiscovery tool binary from GitHub releases."""
    return _gh_binary_cmd("projectdiscovery", tool, "zip")


def _gh_binary_cmd(org: str, tool: str, ext: str = "zip") -> str:
    """Download latest binary from any GitHub org's releases.
    Supports .zip and .tar.gz archives. Searches for linux_amd64/arm64 in asset names."""
    escaped_ext = ext.replace('.', '\\\\.')
    dl_pattern = f"{tool}[^\\\"]*linux[^\\\"]*\\\\.{escaped_ext}"
    if ext == "tar.gz":
        extract = (
            f'mkdir -p /tmp/{tool}_extract && '
            f'tar xzf /tmp/{tool}.dl -C /tmp/{tool}_extract && '
            f'find /tmp/{tool}_extract -name "{tool}" -type f | head -1 | xargs -I{{}} mv {{}} /usr/local/bin/{tool}'
        )
    else:
        extract = (
            f'unzip -o /tmp/{tool}.dl -d /tmp/{tool}_extract && '
            f'find /tmp/{tool}_extract -name "{tool}" -type f | head -1 | xargs -I{{}} mv {{}} /usr/local/bin/{tool}'
        )
    return (
        f'ARCH=$(uname -m | sed "s/x86_64/amd64/;s/aarch64/arm64/") && '
        f'URL=$(curl -sL "https://api.github.com/repos/{org}/{tool}/releases/latest" '
        f'| grep -oP "https://[^\\\"]*{tool}[^\\\"]*linux[^\\\"]*${{ARCH}}[^\\\"]*.{ext}" | head -1) && '
        f'if [ -z "$URL" ]; then echo "No release found for {org}/{tool} linux/$ARCH"; exit 1; fi && '
        f'echo "Downloading $URL" && '
        f'curl -sL "$URL" -o /tmp/{tool}.dl && '
        f'{extract} && '
        f'chmod +x /usr/local/bin/{tool} && '
        f'rm -rf /tmp/{tool}.dl /tmp/{tool}_extract'
    )

# Tools to install and their check/install commands per OS
# All install commands assume apt-get update + curl + unzip already ran (_PROVISION_PREP)
_PROVISION_TOOLS = {
    "nmap":      {"check": "which nmap",
                  "verify": "nmap --version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' nmap",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' nmap",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' nmap"},
    "masscan":   {"check": "which masscan",
                  "verify": "masscan --version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' masscan",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' masscan",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' masscan"},
    "hydra":     {"check": "which hydra",
                  "verify": "hydra -h 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' hydra || apt-get install -y thc-hydra",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' hydra || apt-get install -y thc-hydra",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' hydra || apt-get install -y thc-hydra"},
    "httpx":     {"check": "which httpx",
                  "verify": "httpx -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("httpx"),
                  "ubuntu": _pd_binary_cmd("httpx"),
                  "debian": _pd_binary_cmd("httpx")},
    "nuclei":    {"check": "which nuclei",
                  "verify": "nuclei -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("nuclei"),
                  "ubuntu": _pd_binary_cmd("nuclei"),
                  "debian": _pd_binary_cmd("nuclei")},
    "subfinder": {"check": "which subfinder",
                  "verify": "subfinder -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("subfinder"),
                  "ubuntu": _pd_binary_cmd("subfinder"),
                  "debian": _pd_binary_cmd("subfinder")},
    "katana":    {"check": "which katana",
                  "verify": "katana -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("katana"),
                  "ubuntu": _pd_binary_cmd("katana"),
                  "debian": _pd_binary_cmd("katana")},
    "chromium":  {"check": "which chromium || which chromium-browser || which google-chrome",
                  "verify": "chromium --version 2>&1 || chromium-browser --version 2>&1 || google-chrome --version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' chromium",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' chromium-browser || apt-get install -y chromium",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' chromium"},
    # --- Additional tools for full remote exec coverage ---
    "naabu":     {"check": "which naabu",
                  "verify": "naabu -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("naabu"),
                  "ubuntu": _pd_binary_cmd("naabu"),
                  "debian": _pd_binary_cmd("naabu")},
    "tlsx":      {"check": "which tlsx",
                  "verify": "tlsx -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("tlsx"),
                  "ubuntu": _pd_binary_cmd("tlsx"),
                  "debian": _pd_binary_cmd("tlsx")},
    "ffuf":      {"check": "which ffuf",
                  "verify": "ffuf -V 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' ffuf || " + _gh_binary_cmd("ffuf", "ffuf", "tar.gz"),
                  "ubuntu": _gh_binary_cmd("ffuf", "ffuf", "tar.gz"),
                  "debian": _gh_binary_cmd("ffuf", "ffuf", "tar.gz")},
    "dnsx":      {"check": "which dnsx",
                  "verify": "dnsx -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("dnsx"),
                  "ubuntu": _pd_binary_cmd("dnsx"),
                  "debian": _pd_binary_cmd("dnsx")},
    "amass":     {"check": "which amass",
                  "verify": "amass -version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' amass",
                  "ubuntu": _gh_binary_cmd("owasp-amass", "amass", "zip"),
                  "debian": _gh_binary_cmd("owasp-amass", "amass", "zip")},
    "gau":       {"check": "which gau",
                  "verify": "gau -version 2>&1 | head -1",
                  # lc/gau releases use: gau_VERSION_linux_amd64.tar.gz
                  "kali": _gh_binary_cmd("lc", "gau", "tar.gz"),
                  "ubuntu": _gh_binary_cmd("lc", "gau", "tar.gz"),
                  "debian": _gh_binary_cmd("lc", "gau", "tar.gz")},
    "waybackurls": {"check": "which waybackurls",
                  "verify": "echo waybackurls installed",
                  # tomnomnom/waybackurls — simple Go binary
                  "kali": _gh_binary_cmd("tomnomnom", "waybackurls", "tar.gz"),
                  "ubuntu": _gh_binary_cmd("tomnomnom", "waybackurls", "tar.gz"),
                  "debian": _gh_binary_cmd("tomnomnom", "waybackurls", "tar.gz")},
    "gowitness": {"check": "which gowitness",
                  "verify": "gowitness version 2>&1 | head -1",
                  "kali": _gh_binary_cmd("sensepost", "gowitness", "zip"),
                  "ubuntu": _gh_binary_cmd("sensepost", "gowitness", "zip"),
                  "debian": _gh_binary_cmd("sensepost", "gowitness", "zip")},
    "nikto":     {"check": "which nikto",
                  "verify": "nikto -Version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' nikto",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' nikto",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' nikto"},
    "whatweb":   {"check": "which whatweb",
                  "verify": "whatweb --version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' whatweb",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' whatweb",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' whatweb"},
    "wafw00f":   {"check": "which wafw00f",
                  "verify": "wafw00f --version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' wafw00f || pip3 install --break-system-packages wafw00f",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' wafw00f || pip3 install --break-system-packages wafw00f",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' wafw00f || pip3 install --break-system-packages wafw00f"},
    "shuffledns": {"check": "which shuffledns",
                  "verify": "shuffledns -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("shuffledns"),
                  "ubuntu": _pd_binary_cmd("shuffledns"),
                  "debian": _pd_binary_cmd("shuffledns")},
    "uncover":   {"check": "which uncover",
                  "verify": "uncover -version 2>&1 | head -1",
                  "kali": _pd_binary_cmd("uncover"),
                  "ubuntu": _pd_binary_cmd("uncover"),
                  "debian": _pd_binary_cmd("uncover")},
    # --- Wordlists ---
    "seclists":  {"check": "test -d /usr/share/seclists || test -d /usr/share/wordlists/seclists && echo ok",
                  "verify": "ls /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 2>/dev/null && echo 'seclists installed' || ls /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 2>/dev/null && echo 'seclists installed' || echo 'not found'",
                  "kali": f"{_APT_CLEANUP}; {_APT_INSTALL} seclists",
                  "ubuntu": f"{_APT_CLEANUP}; {_APT_INSTALL} seclists || (mkdir -p /usr/share/wordlists && git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists)",
                  "debian": "mkdir -p /usr/share/wordlists && git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists"},
    "rockyou":   {"check": "test -f /usr/share/wordlists/rockyou.txt && echo ok",
                  "verify": "wc -l /usr/share/wordlists/rockyou.txt 2>/dev/null | head -1 || echo 'not found'",
                  "kali": "test -f /usr/share/wordlists/rockyou.txt || (test -f /usr/share/wordlists/rockyou.txt.gz && gunzip /usr/share/wordlists/rockyou.txt.gz) || echo 'rockyou.txt not found — install wordlists package'",
                  "ubuntu": "mkdir -p /usr/share/wordlists && test -f /usr/share/wordlists/rockyou.txt || curl -sL https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -o /usr/share/wordlists/rockyou.txt",
                  "debian": "mkdir -p /usr/share/wordlists && test -f /usr/share/wordlists/rockyou.txt || curl -sL https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -o /usr/share/wordlists/rockyou.txt"},
    # --- Content recon tools (PDF, EXIF, wordlist, spider support) ---
    "pdfplumber": {"check": "python3 -c 'import pdfplumber' 2>/dev/null && echo ok",
                  "verify": "python3 -c 'import pdfplumber; print(f\"pdfplumber {pdfplumber.__version__}\")' 2>&1",
                  "kali": "pip3 install --break-system-packages pdfplumber",
                  "ubuntu": "pip3 install --break-system-packages pdfplumber",
                  "debian": "pip3 install --break-system-packages pdfplumber"},
    "pillow":    {"check": "python3 -c 'from PIL import Image' 2>/dev/null && echo ok",
                  "verify": "python3 -c 'from PIL import Image; import PIL; print(f\"Pillow {PIL.__version__}\")' 2>&1",
                  "kali": "pip3 install --break-system-packages Pillow",
                  "ubuntu": "pip3 install --break-system-packages Pillow",
                  "debian": "pip3 install --break-system-packages Pillow"},
    "exiftool":  {"check": "which exiftool",
                  "verify": "exiftool -ver 2>&1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' libimage-exiftool-perl",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' libimage-exiftool-perl",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' libimage-exiftool-perl"},
    "cewl":      {"check": "which cewl",
                  "verify": "cewl --help 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' cewl",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' cewl || gem install cewl",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' cewl || gem install cewl"},
    "gobuster":  {"check": "which gobuster",
                  "verify": "gobuster version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' gobuster || ("
                          'ARCH=$(uname -m) && '
                          'URL=$(curl -sL "https://api.github.com/repos/OJ/gobuster/releases/latest" '
                          '| grep -oP "https://[^\\"]*gobuster_Linux_${ARCH}\\.tar\\.gz" | head -1) && '
                          'curl -sL "$URL" -o /tmp/gobuster.tar.gz && '
                          'tar xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster && '
                          'chmod +x /usr/local/bin/gobuster && rm -f /tmp/gobuster.tar.gz)',
                  "ubuntu": 'ARCH=$(uname -m) && '
                            'URL=$(curl -sL "https://api.github.com/repos/OJ/gobuster/releases/latest" '
                            '| grep -oP "https://[^\\"]*gobuster_Linux_${ARCH}\\.tar\\.gz" | head -1) && '
                            'curl -sL "$URL" -o /tmp/gobuster.tar.gz && '
                            'tar xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster && '
                            'chmod +x /usr/local/bin/gobuster && rm -f /tmp/gobuster.tar.gz',
                  "debian": 'ARCH=$(uname -m) && '
                            'URL=$(curl -sL "https://api.github.com/repos/OJ/gobuster/releases/latest" '
                            '| grep -oP "https://[^\\"]*gobuster_Linux_${ARCH}\\.tar\\.gz" | head -1) && '
                            'curl -sL "$URL" -o /tmp/gobuster.tar.gz && '
                            'tar xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster && '
                            'chmod +x /usr/local/bin/gobuster && rm -f /tmp/gobuster.tar.gz'},
    # --- Python3 + dig (for service enumeration fallback) ---
    "python3":   {"check": "which python3",
                  "verify": "python3 --version 2>&1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' python3 python3-pip",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' python3 python3-pip",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' python3 python3-pip"},
    "dig":       {"check": "which dig",
                  "verify": "dig -v 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' dnsutils",
                  "ubuntu": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' dnsutils",
                  "debian": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' dnsutils"},
    # --- Subdomain takeover + JS endpoint extraction ---
    "subzy":     {"check": "which subzy",
                  "verify": "subzy version 2>&1 | head -1",
                  "kali": _gh_binary_cmd("LukaSikic", "subzy", "tar.gz"),
                  "ubuntu": _gh_binary_cmd("LukaSikic", "subzy", "tar.gz"),
                  "debian": _gh_binary_cmd("LukaSikic", "subzy", "tar.gz")},
    "GoLinkFinder": {"check": "which GoLinkFinder || python3 -c 'import golinkfinder' 2>/dev/null && echo ok",
                  "verify": "GoLinkFinder -h 2>&1 | head -1 || echo 'installed'",
                  "kali": "pip3 install --break-system-packages golinkfinder",
                  "ubuntu": "pip3 install --break-system-packages golinkfinder",
                  "debian": "pip3 install --break-system-packages golinkfinder"},
    # --- Service enumeration (DNS/email) ---
    "mcp-kali-server": {"check": "which kali-server-mcp",
                  "verify": "dpkg -l mcp-kali-server 2>/dev/null | grep ii | head -1 || echo 'not installed'",
                  "kali": f"{_APT_CLEANUP}; DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' mcp-kali-server",
                  "ubuntu": "echo 'mcp-kali-server requires Kali Linux'",
                  "debian": "echo 'mcp-kali-server requires Kali Linux'"},
    "dnspython": {"check": "python3 -c 'import dns' 2>/dev/null && echo ok",
                  "verify": "python3 -c 'import dns; print(f\"dnspython {dns.__version__}\")' 2>&1",
                  "kali": "pip3 install --break-system-packages dnspython",
                  "ubuntu": "pip3 install --break-system-packages dnspython",
                  "debian": "pip3 install --break-system-packages dnspython"},
    # ── KB tools (optional — install on demand) ──────────────────────────
    "ssh-audit":  {"check": "which ssh-audit",
                  "verify": "ssh-audit --help 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} ssh-audit || pip3 install --break-system-packages ssh-audit",
                  "ubuntu": "pip3 install --break-system-packages ssh-audit",
                  "debian": "pip3 install --break-system-packages ssh-audit"},
    "sslscan":   {"check": "which sslscan", "verify": "sslscan --version 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} sslscan", "ubuntu": f"{_APT_INSTALL} sslscan", "debian": f"{_APT_INSTALL} sslscan"},
    "sslyze":    {"check": "which sslyze", "verify": "sslyze --version 2>&1",
                  "kali": "pip3 install --break-system-packages sslyze",
                  "ubuntu": "pip3 install --break-system-packages sslyze", "debian": "pip3 install --break-system-packages sslyze"},
    "testssl":   {"check": "which testssl.sh || which testssl",
                  "verify": "testssl.sh --version 2>&1 | head -3 || which testssl.sh || echo testssl installed",
                  "kali": f"{_APT_INSTALL} testssl.sh", "ubuntu": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh",
                  "debian": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh"},
    "sqlmap":    {"check": "which sqlmap", "verify": "sqlmap --version 2>&1",
                  "kali": f"{_APT_INSTALL} sqlmap", "ubuntu": f"{_APT_INSTALL} sqlmap", "debian": "pip3 install --break-system-packages sqlmap"},
    "enum4linux":{"check": "which enum4linux", "verify": "enum4linux --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} enum4linux", "ubuntu": f"{_APT_INSTALL} enum4linux", "debian": f"{_APT_INSTALL} enum4linux"},
    "enum4linux-ng":{"check": "which enum4linux-ng", "verify": "enum4linux-ng --help 2>&1 | head -1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} enum4linux-ng",
                  "ubuntu": "pipx install enum4linux-ng || pip3 install --break-system-packages enum4linux-ng",
                  "debian": "pipx install enum4linux-ng || pip3 install --break-system-packages enum4linux-ng"},
    "impacket-smbclient":{"check": "which impacket-smbclient", "verify": "impacket-smbclient -h 2>&1 | head -1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} impacket-scripts", "ubuntu": f"{_APT_INSTALL} impacket-scripts", "debian": f"{_APT_INSTALL} impacket-scripts"},
    "lftp":      {"check": "which lftp", "verify": "lftp --version 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} lftp", "ubuntu": f"{_APT_INSTALL} lftp", "debian": f"{_APT_INSTALL} lftp"},
    "smbclient": {"check": "which smbclient", "verify": "smbclient --version 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} smbclient", "ubuntu": f"{_APT_INSTALL} smbclient", "debian": f"{_APT_INSTALL} smbclient"},
    "smbmap":    {"check": "which smbmap", "verify": "smbmap --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} smbmap", "ubuntu": "pip3 install --break-system-packages smbmap",
                  "debian": "pip3 install --break-system-packages smbmap"},
    "medusa":    {"check": "which medusa", "verify": "medusa -V 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} medusa", "ubuntu": f"{_APT_INSTALL} medusa", "debian": f"{_APT_INSTALL} medusa"},
    "ncrack":    {"check": "which ncrack", "verify": "ncrack --version 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} ncrack", "ubuntu": f"{_APT_INSTALL} ncrack", "debian": f"{_APT_INSTALL} ncrack"},
    "snmpwalk":  {"check": "which snmpwalk", "verify": "snmpwalk --version 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} snmp", "ubuntu": f"{_APT_INSTALL} snmp", "debian": f"{_APT_INSTALL} snmp"},
    "onesixtyone":{"check": "which onesixtyone", "verify": "onesixtyone 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} onesixtyone", "ubuntu": f"{_APT_INSTALL} onesixtyone", "debian": f"{_APT_INSTALL} onesixtyone"},
    "redis-cli": {"check": "which redis-cli", "verify": "redis-cli --version 2>&1",
                  "kali": f"{_APT_INSTALL} redis-tools", "ubuntu": f"{_APT_INSTALL} redis-tools", "debian": f"{_APT_INSTALL} redis-tools"},
    "ldapsearch":{"check": "which ldapsearch", "verify": "ldapsearch -VV 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} ldap-utils", "ubuntu": f"{_APT_INSTALL} ldap-utils", "debian": f"{_APT_INSTALL} ldap-utils"},
    "showmount": {"check": "which showmount", "verify": "showmount --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} nfs-common", "ubuntu": f"{_APT_INSTALL} nfs-common", "debian": f"{_APT_INSTALL} nfs-common"},
    "rpcinfo":   {"check": "which rpcinfo", "verify": "rpcinfo --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} rpcbind", "ubuntu": f"{_APT_INSTALL} rpcbind", "debian": f"{_APT_INSTALL} rpcbind"},
    "netcat":    {"check": "which nc || which ncat", "verify": "nc -h 2>&1 | head -1 || ncat --version 2>&1",
                  "kali": f"{_APT_INSTALL} ncat", "ubuntu": f"{_APT_INSTALL} ncat", "debian": f"{_APT_INSTALL} ncat"},
    "curl":      {"check": "which curl", "verify": "curl --version 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} curl", "ubuntu": f"{_APT_INSTALL} curl", "debian": f"{_APT_INSTALL} curl"},
    "dig":       {"check": "which dig", "verify": "dig -v 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} dnsutils", "ubuntu": f"{_APT_INSTALL} dnsutils", "debian": f"{_APT_INSTALL} dnsutils"},
    "dnsrecon":  {"check": "which dnsrecon", "verify": "dnsrecon --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} dnsrecon", "ubuntu": "pip3 install --break-system-packages dnsrecon",
                  "debian": "pip3 install --break-system-packages dnsrecon"},
    "dnsenum":   {"check": "which dnsenum", "verify": "dnsenum --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} dnsenum", "ubuntu": f"{_APT_INSTALL} dnsenum", "debian": f"{_APT_INSTALL} dnsenum"},
    "feroxbuster":{"check": "which feroxbuster", "verify": "feroxbuster --version 2>&1",
                  "kali": f"{_APT_INSTALL} feroxbuster", "ubuntu": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin 2>/dev/null || echo feroxbuster-install-failed",
                  "debian": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin 2>/dev/null || echo feroxbuster-install-failed"},
    "dirsearch": {"check": "which dirsearch", "verify": "dirsearch --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} dirsearch", "ubuntu": "pip3 install --break-system-packages dirsearch",
                  "debian": "pip3 install --break-system-packages dirsearch"},
    "wfuzz":     {"check": "which wfuzz", "verify": "wfuzz --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} wfuzz", "ubuntu": "pip3 install --break-system-packages wfuzz",
                  "debian": "pip3 install --break-system-packages wfuzz"},
    "crackmapexec":{"check": "which crackmapexec || which cme", "verify": "crackmapexec --version 2>&1 || cme --version 2>&1",
                  "kali": f"{_APT_INSTALL} crackmapexec", "ubuntu": "pip3 install --break-system-packages crackmapexec",
                  "debian": "pip3 install --break-system-packages crackmapexec"},
    "evil-winrm":{"check": "which evil-winrm", "verify": "evil-winrm --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} evil-winrm", "ubuntu": "gem install evil-winrm",
                  "debian": "gem install evil-winrm"},
    "xfreerdp":  {"check": "which xfreerdp || which xfreerdp3", "verify": "xfreerdp --version 2>&1 | head -1 || xfreerdp3 --version 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} freerdp3-x11 || {_APT_INSTALL} freerdp2-x11",
                  "ubuntu": f"{_APT_INSTALL} freerdp3-x11 || {_APT_INSTALL} freerdp2-x11",
                  "debian": f"{_APT_INSTALL} freerdp3-x11 || {_APT_INSTALL} freerdp2-x11"},
    "mysql":     {"check": "which mysql", "verify": "mysql --version 2>&1",
                  "kali": f"{_APT_INSTALL} default-mysql-client", "ubuntu": f"{_APT_INSTALL} default-mysql-client",
                  "debian": f"{_APT_INSTALL} default-mysql-client"},
    "psql":      {"check": "which psql", "verify": "psql --version 2>&1",
                  "kali": f"{_APT_INSTALL} postgresql-client", "ubuntu": f"{_APT_INSTALL} postgresql-client",
                  "debian": f"{_APT_INSTALL} postgresql-client"},
    "swaks":     {"check": "which swaks", "verify": "swaks --version 2>&1 | head -1",
                  "kali": f"{_APT_INSTALL} swaks", "ubuntu": f"{_APT_INSTALL} swaks", "debian": f"{_APT_INSTALL} swaks"},
    "smtp-user-enum":{"check": "which smtp-user-enum", "verify": "smtp-user-enum --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} smtp-user-enum", "ubuntu": "pip3 install --break-system-packages smtp-user-enum",
                  "debian": "pip3 install --break-system-packages smtp-user-enum"},
    "crowbar":   {"check": "which crowbar", "verify": "crowbar --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} crowbar", "ubuntu": "pip3 install --break-system-packages crowbar",
                  "debian": "pip3 install --break-system-packages crowbar"},
    "kerbrute":  {"check": "which kerbrute", "verify": "kerbrute version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} kerbrute || " + "curl -sL https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') -o /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute",
                  "ubuntu": "curl -sL https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') -o /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute", "debian": "curl -sL https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') -o /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute"},
    "alterx":    {"check": "which alterx", "verify": "alterx -version 2>&1 || echo 'installed'",
                  "kali": _pd_binary_cmd("alterx"), "ubuntu": _pd_binary_cmd("alterx"), "debian": _pd_binary_cmd("alterx")},
    "vulnx":     {"check": "python3 -c 'import vulnx' 2>/dev/null && echo ok || which vulnx",
                  "verify": "vulnx --version 2>&1 || echo 'installed'",
                  "kali": "pip3 install --break-system-packages vulnx || echo 'vulnx: manual install needed'",
                  "ubuntu": "pip3 install --break-system-packages vulnx || echo 'vulnx: manual install needed'",
                  "debian": "pip3 install --break-system-packages vulnx || echo 'vulnx: manual install needed'"},
    "snmp-check":{"check": "which snmp-check", "verify": "snmp-check --version 2>&1 || echo 'installed'",
                  "kali": f"{_APT_INSTALL} snmp-check || echo 'snmp-check: Kali only'",
                  "ubuntu": "echo 'snmp-check: available on Kali only'", "debian": "echo 'snmp-check: available on Kali only'"},
    "telnet":    {"check": "which telnet", "verify": "echo 'telnet installed'",
                  "kali": f"{_APT_INSTALL} telnet", "ubuntu": f"{_APT_INSTALL} telnet", "debian": f"{_APT_INSTALL} telnet"},
    "ftp":       {"check": "which ftp", "verify": "echo 'ftp installed'",
                  "kali": f"{_APT_INSTALL} ftp", "ubuntu": f"{_APT_INSTALL} ftp", "debian": f"{_APT_INSTALL} ftp"},
    "wireguard": {"check": "which wg", "verify": "wg --version 2>&1 | head -1",
                  "kali": f"{_APT_CLEANUP}; {_APT_INSTALL} wireguard-tools",
                  "ubuntu": f"{_APT_CLEANUP}; {_APT_INSTALL} wireguard-tools",
                  "debian": f"{_APT_CLEANUP}; {_APT_INSTALL} wireguard-tools"},
}


# ── Remote Kali MCP Server Management ─────────────────────────────────

# Track active MCP forwards: node_id -> {"local_port": int, "pid": int}
_mcp_forwards: dict = {}
_MCP_PORT_START = 9040
_MCP_PORT_END = 9059


def _next_mcp_port() -> int:
    """Allocate next available MCP forward port."""
    used = {v["local_port"] for v in _mcp_forwards.values()}
    for port in range(_MCP_PORT_START, _MCP_PORT_END):
        if port not in used:
            return port
    raise HTTPException(503, "No available MCP forward ports (9040-9059)")


@app.post("/ssh/{node_id}/start-mcp")
async def start_remote_mcp(node_id: str):
    """Start mcp-kali-server on a remote node and set up SSH port forwarding."""
    if node_id in _mcp_forwards:
        return {"ok": True, "already_running": True, **_mcp_forwards[node_id]}

    conn_db = _get_conn()
    cur = conn_db.cursor()
    cur.execute("SELECT node_type, status, metadata FROM remote_nodes WHERE id = %s", (node_id,))
    row = cur.fetchone()
    cur.close()
    conn_db.close()

    if not row:
        raise HTTPException(404, "Node not found")
    ntype, status, meta = row
    if ntype != "ssh":
        raise HTTPException(400, "Only SSH nodes support remote MCP")
    if status != "online":
        raise HTTPException(400, f"Node is {status}, must be online")

    host = meta["host"]
    user = meta.get("user", "root")
    ssh_port = meta.get("ssh_port", 22)
    key_file = meta.get("key_file", "id_rsa")
    local_port = _next_mcp_port()

    # Step 1: Start mcp-kali-server on remote node
    # Use SSH -f to background the remote command (avoids shell metachar issues)
    key_path = f"/ssh-keys/{key_file}"
    import asyncio

    # First check if already running
    check_cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
        "-i", key_path, "-p", str(ssh_port),
        f"{user}@{host}", "pgrep -f kali-server-mcp",
    ]
    check_proc = await asyncio.create_subprocess_exec(
        *check_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    check_out, _ = await asyncio.wait_for(check_proc.communicate(), timeout=10)

    if check_proc.returncode != 0:
        # Not running — start it with SSH -f (runs command in background on remote)
        start_cmd = [
            "ssh", "-f", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
            "-i", key_path, "-p", str(ssh_port),
            f"{user}@{host}", "kali-server-mcp --port 5000",
        ]
        try:
            start_proc = await asyncio.create_subprocess_exec(
                *start_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            s_out, s_err = await asyncio.wait_for(start_proc.communicate(), timeout=15)
            log.info(f"Started kali-server-mcp on {node_id}: rc={start_proc.returncode}")
            # Give it a moment to bind the port
            await asyncio.sleep(3)
        except Exception as e:
            log.warning(f"Start MCP command failed (non-fatal): {e}")
    else:
        log.info(f"kali-server-mcp already running on {node_id}: pid={check_out.decode().strip()}")

    # Step 2: Set up SSH local port forward
    key_path = f"/ssh-keys/{key_file}"
    fwd_cmd = [
        "ssh", "-N", "-L", f"0.0.0.0:{local_port}:127.0.0.1:5000",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-i", key_path,
        "-p", str(ssh_port),
        f"{user}@{host}",
    ]
    proc = await asyncio.create_subprocess_exec(
        *fwd_cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )

    # Wait briefly to check if forward established
    await asyncio.sleep(2)
    if proc.returncode is not None:
        stderr = (await proc.stderr.read()).decode()[:200]
        raise HTTPException(500, f"SSH forward failed: {stderr}")

    _mcp_forwards[node_id] = {
        "local_port": local_port,
        "pid": proc.pid,
        "host": host,
        "node_name": meta.get("name", node_id[:8]),
    }

    # Update node metadata with MCP port
    conn_db = _get_conn()
    cur = conn_db.cursor()
    cur.execute(
        "UPDATE remote_nodes SET metadata = metadata || %s WHERE id = %s",
        (json.dumps({"mcp_forward_port": local_port, "mcp_active": True}), node_id),
    )
    conn_db.commit()
    cur.close()
    conn_db.close()

    log.info(f"MCP forward established: local:{local_port} → {host}:5000 (pid {proc.pid})")
    return {"ok": True, "local_port": local_port, "pid": proc.pid, "node_id": node_id}


@app.post("/ssh/{node_id}/stop-mcp")
async def stop_remote_mcp(node_id: str):
    """Stop MCP port forwarding for a node."""
    info = _mcp_forwards.pop(node_id, None)
    if not info:
        return {"ok": True, "message": "MCP not running for this node"}

    # Kill the SSH forward process
    try:
        import signal
        os.kill(info["pid"], signal.SIGTERM)
    except ProcessLookupError:
        pass

    # Update node metadata
    try:
        conn_db = _get_conn()
        cur = conn_db.cursor()
        cur.execute(
            "UPDATE remote_nodes SET metadata = metadata - 'mcp_active' - 'mcp_forward_port' WHERE id = %s",
            (node_id,),
        )
        conn_db.commit()
        cur.close()
        conn_db.close()
    except Exception:
        pass

    return {"ok": True, "stopped_port": info["local_port"]}


@app.get("/ssh/{node_id}/mcp-status")
async def mcp_status(node_id: str):
    """Check if MCP is active for a node."""
    info = _mcp_forwards.get(node_id)
    if not info:
        return {"active": False, "node_id": node_id}

    # Check if the forward process is still alive
    try:
        os.kill(info["pid"], 0)
        alive = True
    except ProcessLookupError:
        _mcp_forwards.pop(node_id, None)
        alive = False

    return {
        "active": alive,
        "node_id": node_id,
        "local_port": info.get("local_port"),
        "host": info.get("host"),
    }


@app.post("/ssh/{node_id}/mcp-proxy")
async def mcp_proxy(node_id: str, request: Request):
    """Proxy MCP JSON-RPC requests to the remote Kali MCP server via SSH forward."""
    info = _mcp_forwards.get(node_id)
    if not info:
        raise HTTPException(400, "MCP not active for this node. Call /ssh/{node_id}/start-mcp first.")

    local_port = info["local_port"]
    body = await request.json()

    try:
        async with httpx.AsyncClient(verify=False, timeout=120) as client:
            # The Kali MCP server has a REST API at port 5000, forwarded to local_port
            # Route based on the MCP method
            method = body.get("method", "")

            if method == "initialize":
                return {"jsonrpc": "2.0", "id": body.get("id"),
                        "result": {"protocolVersion": "2024-11-05",
                                   "capabilities": {"tools": {"listChanged": False}},
                                   "serverInfo": {"name": f"kali-mcp@{info.get('node_name', node_id[:8])}",
                                                  "version": "1.0.0"}}}

            elif method == "tools/list":
                # Query Kali MCP server for available tools
                resp = await client.get(f"http://127.0.0.1:{local_port}/api/tools",
                                        timeout=10)
                if resp.status_code == 200:
                    tools_data = resp.json()
                    # Convert Kali MCP format to standard MCP tools/list format
                    tools = []
                    if isinstance(tools_data, list):
                        for t in tools_data:
                            tools.append({
                                "name": t.get("name", t.get("tool", "")),
                                "description": t.get("description", ""),
                                "inputSchema": t.get("inputSchema", t.get("parameters", {"type": "object", "properties": {}})),
                            })
                    elif isinstance(tools_data, dict):
                        for name, desc in tools_data.items():
                            tools.append({
                                "name": name,
                                "description": desc if isinstance(desc, str) else json.dumps(desc)[:200],
                                "inputSchema": {"type": "object", "properties": {}},
                            })
                    return {"jsonrpc": "2.0", "id": body.get("id"),
                            "result": {"tools": tools}}
                return {"jsonrpc": "2.0", "id": body.get("id"),
                        "result": {"tools": []}}

            elif method == "tools/call":
                params = body.get("params", {})
                tool_name = params.get("name", "")
                arguments = params.get("arguments", {})
                # Call the Kali MCP tool
                resp = await client.post(
                    f"http://127.0.0.1:{local_port}/api/run",
                    json={"tool": tool_name, **arguments},
                    timeout=120,
                )
                result_text = resp.text if resp.status_code == 200 else f"Error: {resp.status_code} {resp.text[:500]}"
                return {"jsonrpc": "2.0", "id": body.get("id"),
                        "result": {"content": [{"type": "text", "text": result_text}]}}

            else:
                return {"jsonrpc": "2.0", "id": body.get("id"),
                        "error": {"code": -1, "message": f"Unknown method: {method}"}}

    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot connect to Kali MCP at 127.0.0.1:{local_port} — is the server running?")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/mcp-nodes")
async def list_mcp_nodes():
    """List all nodes with active MCP forwarding."""
    nodes = []
    for node_id, info in _mcp_forwards.items():
        try:
            os.kill(info["pid"], 0)
            alive = True
        except ProcessLookupError:
            alive = False
        nodes.append({
            "node_id": node_id,
            "local_port": info["local_port"],
            "host": info["host"],
            "node_name": info.get("node_name", ""),
            "active": alive,
        })
    return {"nodes": nodes}


class ProvisionRequest(BaseModel):
    tools: Optional[list[str]] = None  # None = all tools; or list like ["nmap","hydra"]


@app.post("/ssh/{node_id}/provision")
async def provision_node(node_id: str, req: ProvisionRequest):
    """Install scan tools on a remote SSH node. Streams SSE events per tool."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, status, metadata FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise HTTPException(404, "Node not found")
    ntype, status, meta = row
    if ntype != "ssh":
        raise HTTPException(400, "Provisioning requires an SSH node")
    if status != "online":
        raise HTTPException(400, f"Node is {status}, must be online")

    os_type = (meta or {}).get("os_type", "kali")
    if os_type not in ("kali", "ubuntu", "debian"):
        raise HTTPException(400, f"Unsupported OS type: {os_type}")

    requested_tools = req.tools or list(_PROVISION_TOOLS.keys())

    async def _verify_tool(tool_name, spec):
        """Run the tool's version/help command to confirm it actually executes."""
        verify_cmd = spec.get("verify")
        if not verify_cmd:
            return None
        vr = await ssh_manager.provision_exec(
            node_id=node_id, host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            command=verify_cmd, timeout=10,
        )
        if vr.get("ok") and vr.get("exit_code", 1) == 0:
            return vr.get("stdout", "").strip().split("\n")[0][:100]
        return None

    async def _stream():
        results = {}
        yield f"data: {json.dumps({'event': 'start', 'os_type': os_type, 'tools': requested_tools})}\n\n"

        # Step 0: Verify SSH connectivity before doing anything
        yield f"data: {json.dumps({'event': 'checking', 'tool': 'ssh_connectivity'})}\n\n"
        conn_check = await ssh_manager.exec_command(
            node_id=node_id, host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            command="echo ok", timeout=15,
        )
        if not conn_check.get("ok") or conn_check.get("exit_code", 1) != 0:
            error_msg = conn_check.get("error") or conn_check.get("stderr", "SSH connection failed")
            yield f"data: {json.dumps({'event': 'error', 'tool': 'ssh_connectivity', 'status': 'failed', 'error': error_msg})}\n\n"
            yield f"data: {json.dumps({'event': 'done', 'results': {}, 'error': f'SSH connection failed: {error_msg}. Aborting provisioning.'})}\n\n"
            return
        yield f"data: {json.dumps({'event': 'tool', 'tool': 'ssh_connectivity', 'status': 'ok'})}\n\n"

        # Step 1: apt-get update + install prerequisites (curl, unzip)
        prep_cmd = _PROVISION_PREP.get(os_type)
        if prep_cmd:
            yield f"data: {json.dumps({'event': 'installing', 'tool': 'prerequisites', 'cmd': 'apt-get update + curl + unzip'})}\n\n"
            prep_result = await ssh_manager.provision_exec(
                node_id=node_id, host=meta["host"],
                user=meta.get("user", "root"),
                ssh_port=meta.get("ssh_port", 22),
                key_file=meta.get("key_file", "id_rsa"),
                command=prep_cmd, timeout=120,
            )
            if prep_result.get("ok") and prep_result.get("exit_code", 1) == 0:
                yield f"data: {json.dumps({'event': 'tool', 'tool': 'prerequisites', 'status': 'installed'})}\n\n"
            else:
                stderr = prep_result.get("stderr", "")[-300:]
                error = prep_result.get("error", "")
                yield f"data: {json.dumps({'event': 'tool', 'tool': 'prerequisites', 'status': 'failed', 'stderr': stderr})}\n\n"
                # If SSH connection itself failed (not just apt), abort
                if "connection" in (error + stderr).lower() or "timed out" in (error + stderr).lower():
                    yield f"data: {json.dumps({'event': 'done', 'results': {}, 'error': f'SSH connection lost during prerequisites. Aborting.'})}\n\n"
                    return

        for tool_name in requested_tools:
            if tool_name not in _PROVISION_TOOLS:
                r = {"status": "skipped", "reason": "unknown tool"}
                results[tool_name] = r
                yield f"data: {json.dumps({'event': 'tool', 'tool': tool_name, **r})}\n\n"
                continue

            spec = _PROVISION_TOOLS[tool_name]
            yield f"data: {json.dumps({'event': 'checking', 'tool': tool_name})}\n\n"

            check_result = await ssh_manager.provision_exec(
                node_id=node_id, host=meta["host"],
                user=meta.get("user", "root"),
                ssh_port=meta.get("ssh_port", 22),
                key_file=meta.get("key_file", "id_rsa"),
                command=spec["check"], timeout=10,
            )
            if check_result.get("ok") and check_result.get("exit_code", 1) == 0:
                path = check_result.get("stdout", "").strip()
                r = {"status": "already_installed", "path": path}
                results[tool_name] = r

                # Update installation status for WireGuard when detected as already installed
                if tool_name == "wireguard":
                    _safe_db_execute("""
                        UPDATE remote_nodes
                        SET installation_status = 'success', tunnel_method = 'wireguard', updated_at = now()
                        WHERE id = %s
                    """, (node_id,))
                    log.info("Updated WireGuard installation status to 'success' for node %s (already installed)", node_id)

                yield f"data: {json.dumps({'event': 'tool', 'tool': tool_name, **r})}\n\n"
                continue

            # Try SCP push from local binary first (for Go tools)
            local_bin = _find_local_binary(tool_name)
            if local_bin:
                yield f"data: {json.dumps({'event': 'installing', 'tool': tool_name, 'cmd': f'SCP push {local_bin} → /usr/local/bin/{tool_name}'})}\n\n"
                log.info("Pushing %s to node %s via SCP from %s", tool_name, node_id, local_bin)

                scp_result = await ssh_manager.upload_file(
                    host=meta["host"],
                    user=meta.get("user", "root"),
                    ssh_port=meta.get("ssh_port", 22),
                    key_file=meta.get("key_file", "id_rsa"),
                    local_path=local_bin,
                    remote_path=f"/usr/local/bin/{tool_name}",
                    node_id=node_id,
                )
                if scp_result.get("ok"):
                    # Make executable
                    await ssh_manager.provision_exec(
                        node_id=node_id, host=meta["host"],
                        user=meta.get("user", "root"),
                        ssh_port=meta.get("ssh_port", 22),
                        key_file=meta.get("key_file", "id_rsa"),
                        command=f"chmod +x /usr/local/bin/{tool_name}",
                        timeout=10,
                    )
                    # Verify it runs
                    ver = await _verify_tool(tool_name, spec)
                    if ver:
                        r = {"status": "installed", "stdout": f"pushed + verified: {ver}"}
                    else:
                        r = {"status": "installed", "stdout": f"pushed (verify failed — may need libs)"}
                    results[tool_name] = r
                    yield f"data: {json.dumps({'event': 'tool', 'tool': tool_name, **r})}\n\n"
                    continue
                else:
                    # SCP failed — fall through to remote install
                    log.warning("SCP push %s failed: %s — falling back to remote install",
                                tool_name, scp_result.get("stderr", "")[:100])
                    yield f"data: {json.dumps({'event': 'installing', 'tool': tool_name, 'cmd': f'SCP failed, trying remote install...'})}\n\n"

            # Remote install (apt or binary download)
            install_cmd = spec.get(os_type)
            if not install_cmd:
                r = {"status": "skipped", "reason": f"no install command for {os_type}"}
                results[tool_name] = r
                yield f"data: {json.dumps({'event': 'tool', 'tool': tool_name, **r})}\n\n"
                continue

            yield f"data: {json.dumps({'event': 'installing', 'tool': tool_name, 'cmd': install_cmd[:120]})}\n\n"
            log.info("Provisioning %s on node %s (%s)", tool_name, node_id, os_type)

            install_result = await ssh_manager.provision_exec(
                node_id=node_id, host=meta["host"],
                user=meta.get("user", "root"),
                ssh_port=meta.get("ssh_port", 22),
                key_file=meta.get("key_file", "id_rsa"),
                command=install_cmd, timeout=300,
            )

            if install_result.get("ok") and install_result.get("exit_code", 1) == 0:
                ver = await _verify_tool(tool_name, spec)
                if ver:
                    r = {"status": "installed", "stdout": f"verified: {ver}"}
                else:
                    r = {"status": "installed", "stdout": install_result.get("stdout", "")[-200:]}
                results[tool_name] = r
            else:
                r = {"status": "failed", "exit_code": install_result.get("exit_code"),
                     "stderr": install_result.get("stderr", "")[-300:],
                     "stdout": install_result.get("stdout", "")[-200:]}
                results[tool_name] = r
            yield f"data: {json.dumps({'event': 'tool', 'tool': tool_name, **r})}\n\n"

        # Update DB
        installed = [t for t, r in results.items() if r["status"] in ("installed", "already_installed")]
        try:
            conn2 = _get_conn()
            cur2 = conn2.cursor()
            cur2.execute(
                """UPDATE remote_nodes SET metadata = metadata || %s,
                   capabilities = (SELECT array_agg(DISTINCT elem) FROM unnest(capabilities || %s::text[]) elem)
                   WHERE id = %s""",
                (psycopg2.extras.Json({"provisioned_tools": installed}), installed, node_id),
            )
            conn2.commit()
            cur2.close()
            conn2.close()
        except Exception as e:
            log.warning("Failed to update provisioned tools: %s", e)

        yield f"data: {json.dumps({'event': 'done', 'installed': installed, 'results': results})}\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")


# Entries that _PROVISION_TOOLS installs for the runtime/provisioning flow but
# that are NOT dispatchable scan tools — language runtimes, Python libraries,
# wordlist collections, and infrastructure.  They stay in _PROVISION_TOOLS (a
# node still needs them installed) but are excluded from the dispatchable
# registry so they don't pollute the kali-listener allowlist or the recommender
# tool-coverage matrix as if an operator could "run" them against a target.
_NON_DISPATCHABLE_TOOLS = {
    "python3", "dnspython", "pillow", "pdfplumber",  # runtime + python libs
    "seclists", "rockyou",                            # wordlists
    "wireguard", "mcp-kali-server",                   # infrastructure
    "chromium",                                       # headless-browser dep (used by gowitness)
}


@app.get("/tools/registry")
async def tools_registry(include_all: bool = Query(False)):
    """Canonical tool registry — the single source of truth for which tools the
    system knows how to detect/install, and how to check each.

    Derived from _PROVISION_TOOLS so downstream consumers (kali-listener
    allowlist, the recommender tool-coverage audit, pre-dispatch preflight)
    all reconcile against one list and can't drift.  Only the safe-to-share
    `check`/`verify` probes are exposed (install commands stay internal).

    Non-dispatchable provisioning entries (runtimes, libraries, wordlists,
    infra) are filtered out by default so the dispatchable allowlist/coverage
    only contains real, callable tools.  Pass include_all=true to see the full
    provisioning set (e.g. for node provision-status).
    """
    tools = {
        name: {"check": spec.get("check"), "verify": spec.get("verify"),
               "install": spec.get("kali")}
        for name, spec in _PROVISION_TOOLS.items()
        if include_all or name not in _NON_DISPATCHABLE_TOOLS
    }
    return {"ok": True, "count": len(tools), "tools": tools,
            "names": sorted(tools.keys()),
            "excluded": sorted(_NON_DISPATCHABLE_TOOLS) if not include_all else []}


@app.get("/ssh/{node_id}/provision-status")
async def provision_status(node_id: str, live: bool = Query(False)):
    """Check which tools are installed on a remote SSH node.
    With live=true, SSH into the node and probe each tool."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, status, metadata FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise HTTPException(404, "Node not found")
    ntype, status, meta = row
    if ntype != "ssh":
        raise HTTPException(400, "Only SSH nodes support provisioning")

    os_type = (meta or {}).get("os_type", "kali")

    if not live:
        provisioned = (meta or {}).get("provisioned_tools", [])
        return {
            "node_id": node_id,
            "os_type": os_type,
            "provisioned_tools": provisioned,
            "available_tools": list(_PROVISION_TOOLS.keys()),
            "live": False,
        }

    # Live check — SSH in and probe each tool (streamed)
    if status != "online":
        raise HTTPException(400, f"Node is {status}, must be online for live check")

    async def _stream():
        tools_status = {}
        installed = []
        yield f"data: {json.dumps({'event': 'start', 'os_type': os_type, 'tools': list(_PROVISION_TOOLS.keys())})}\n\n"

        for tool_name, spec in _PROVISION_TOOLS.items():
            yield f"data: {json.dumps({'event': 'checking', 'tool': tool_name})}\n\n"
            result = await ssh_manager.provision_exec(
                node_id=node_id, host=meta["host"],
                user=meta.get("user", "root"),
                ssh_port=meta.get("ssh_port", 22),
                key_file=meta.get("key_file", "id_rsa"),
                command=spec["check"], timeout=10,
            )
            found = result.get("ok") and result.get("exit_code", 1) == 0
            path = result.get("stdout", "").strip() if found else None
            version = None
            if found and spec.get("verify"):
                vr = await ssh_manager.provision_exec(
                    node_id=node_id, host=meta["host"],
                    user=meta.get("user", "root"),
                    ssh_port=meta.get("ssh_port", 22),
                    key_file=meta.get("key_file", "id_rsa"),
                    command=spec["verify"], timeout=10,
                )
                if vr.get("ok") and vr.get("exit_code", 1) == 0:
                    version = vr.get("stdout", "").strip().split("\n")[0][:100]
            tools_status[tool_name] = {"installed": found, "path": path, "version": version}
            if found:
                installed.append(tool_name)
            yield f"data: {json.dumps({'event': 'tool', 'tool': tool_name, 'installed': found, 'path': path, 'version': version})}\n\n"

        # Update DB
        try:
            conn2 = _get_conn()
            cur2 = conn2.cursor()
            cur2.execute(
                "UPDATE remote_nodes SET metadata = metadata || %s WHERE id = %s",
                (psycopg2.extras.Json({"provisioned_tools": installed}), node_id),
            )
            conn2.commit()
            cur2.close()
            conn2.close()
        except Exception as e:
            log.warning("Failed to update provisioned tools: %s", e)

        yield f"data: {json.dumps({'event': 'done', 'tools': tools_status, 'provisioned_tools': installed})}\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")


# ── Background Installation API ───────────────────────────────────────────────

class BackgroundInstallRequest(BaseModel):
    tools: Optional[list[str]] = None  # for software installation
    task_type: str = "software"  # "software" or "wireguard"

@app.post("/ssh/{node_id}/provision-background")
async def provision_background(node_id: str, req: BackgroundInstallRequest):
    """Start software/WireGuard installation as background task that persists across GUI sessions."""
    # Verify node exists and is SSH type
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT node_type, status FROM remote_nodes WHERE id = %s", (node_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    ntype, status = row
    if ntype != "ssh":
        cur.close()
        conn.close()
        raise HTTPException(400, "Only SSH nodes support provisioning")

    # Create background task record
    task_id = str(uuid.uuid4())
    tools_list = req.tools if req.task_type == "software" else []

    try:
        cur.execute("""
            INSERT INTO installation_tasks (id, node_id, task_type, tools, status)
            VALUES (%s, %s, %s, %s, 'pending')
        """, (task_id, node_id, req.task_type, tools_list))
        conn.commit()
        log.info("Created background %s task %s for node %s", req.task_type, task_id[:8], node_id[:8])
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(500, f"Failed to create background task: {e}")
    finally:
        cur.close()
        conn.close()

    return {
        "ok": True,
        "task_id": task_id,
        "message": f"Background {req.task_type} installation queued. Task will continue even if you close this window.",
        "status_url": f"/ssh/{node_id}/installation-tasks/{task_id}"
    }

@app.get("/ssh/{node_id}/installation-tasks")
async def list_installation_tasks(node_id: str):
    """List all installation tasks for a node."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id::text, task_type, status, tools, progress_log, error_message,
               started_at, completed_at, created_at, updated_at
        FROM installation_tasks
        WHERE node_id = %s
        ORDER BY created_at DESC
    """, (node_id,))
    tasks = []
    for row in cur.fetchall():
        task_id, task_type, status, tools, progress_log, error_message, started_at, completed_at, created_at, updated_at = row
        tasks.append({
            "id": task_id,
            "task_type": task_type,
            "status": status,
            "tools": tools,
            "progress_log": progress_log,
            "error_message": error_message,
            "started_at": started_at.isoformat() if started_at else None,
            "completed_at": completed_at.isoformat() if completed_at else None,
            "created_at": created_at.isoformat(),
            "updated_at": updated_at.isoformat()
        })
    cur.close()
    conn.close()
    return {"tasks": tasks}

@app.get("/ssh/{node_id}/installation-tasks/{task_id}")
async def get_installation_task(node_id: str, task_id: str):
    """Get detailed status of a specific installation task."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT task_type, status, tools, progress_log, error_message,
               started_at, completed_at, created_at, updated_at
        FROM installation_tasks
        WHERE id = %s AND node_id = %s
    """, (task_id, node_id))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise HTTPException(404, "Installation task not found")

    task_type, status, tools, progress_log, error_message, started_at, completed_at, created_at, updated_at = row

    return {
        "id": task_id,
        "node_id": node_id,
        "task_type": task_type,
        "status": status,
        "tools": tools,
        "progress_log": progress_log,
        "error_message": error_message,
        "started_at": started_at.isoformat() if started_at else None,
        "completed_at": completed_at.isoformat() if completed_at else None,
        "created_at": created_at.isoformat(),
        "updated_at": updated_at.isoformat(),
        "can_close_window": status != "pending"  # User can close window once task starts running
    }

@app.delete("/ssh/{node_id}/installation-tasks/{task_id}")
async def cancel_installation_task(node_id: str, task_id: str):
    """Cancel a pending installation task."""
    conn = _get_conn()
    cur = conn.cursor()

    # Check if task exists and is cancelable
    cur.execute("""
        SELECT status FROM installation_tasks
        WHERE id = %s AND node_id = %s
    """, (task_id, node_id))
    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Installation task not found")

    status = row[0]
    if status not in ("pending", "running"):
        cur.close()
        conn.close()
        raise HTTPException(400, f"Cannot cancel task with status: {status}")

    # Mark as failed/cancelled
    cur.execute("""
        UPDATE installation_tasks
        SET status = 'failed', error_message = 'Cancelled by user', completed_at = now(), updated_at = now()
        WHERE id = %s
    """, (task_id,))
    conn.commit()
    cur.close()
    conn.close()

    # Remove from background tasks tracker
    _background_tasks.pop(task_id, None)

    return {"ok": True, "message": "Installation task cancelled"}


# ── DigitalOcean Cloud Provisioning ──────────────────────────────────────────

DO_SIZES = [
    {"slug": "s-1vcpu-1gb", "label": "1 vCPU / 1GB ($6/mo)", "vcpus": 1, "memory": 1024, "price": 6},
    {"slug": "s-1vcpu-2gb", "label": "1 vCPU / 2GB ($12/mo)", "vcpus": 1, "memory": 2048, "price": 12},
    {"slug": "s-2vcpu-2gb", "label": "2 vCPU / 2GB ($18/mo)", "vcpus": 2, "memory": 2048, "price": 18},
    {"slug": "s-2vcpu-4gb", "label": "2 vCPU / 4GB ($24/mo)", "vcpus": 2, "memory": 4096, "price": 24},
    {"slug": "s-4vcpu-8gb", "label": "4 vCPU / 8GB ($48/mo)", "vcpus": 4, "memory": 8192, "price": 48},
]

DO_REGIONS = [
    {"slug": "nyc1", "label": "New York 1"}, {"slug": "nyc3", "label": "New York 3"},
    {"slug": "sfo3", "label": "San Francisco 3"}, {"slug": "ams3", "label": "Amsterdam 3"},
    {"slug": "lon1", "label": "London 1"}, {"slug": "fra1", "label": "Frankfurt 1"},
    {"slug": "sgp1", "label": "Singapore 1"}, {"slug": "tor1", "label": "Toronto 1"},
]


class DOCreateRequest(BaseModel):
    name: str
    size: str = "s-1vcpu-1gb"
    region: str = "nyc1"
    key_name: str = "id_rsa"        # Public key for DO droplet creation
    ssh_key_name: str = ""           # Private key for SSH tunnel (if different from key_name)
    os_type: str = "ubuntu"
    image: str = "ubuntu-24-04-x64"
    do_token: Optional[str] = None


def _get_do_token(override: Optional[str] = None) -> str:
    if override:
        return override
    token = os.environ.get("DO_API_TOKEN")
    if token:
        return token
    try:
        conn = psycopg2.connect(settings.db_dsn)
        cur = conn.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key = 'do_api_token'")
        row = cur.fetchone()
        cur.close(); conn.close()
        if row and row[0]:
            return row[0]
    except Exception:
        pass
    raise HTTPException(400, "DigitalOcean API token not configured. Set it in Settings > API Keys.")


@app.get("/cloud/do/options")
async def do_options():
    """Return available DO droplet sizes and regions."""
    return {"sizes": DO_SIZES, "regions": DO_REGIONS}


_do_provision_status: dict = {}  # droplet_id -> status dict


@app.get("/cloud/do/status/{droplet_id}")
async def do_provision_status(droplet_id: str):
    """Check provisioning status of a droplet."""
    status = _do_provision_status.get(droplet_id)
    if not status:
        return {"droplet_id": droplet_id, "status": "unknown"}
    return status


@app.post("/cloud/do/create")
async def create_do_droplet(req: DOCreateRequest):
    """Create a DigitalOcean droplet, upload SSH key, return immediately. Background task handles IP wait + SSH tunnel."""
    import httpx as _httpx, subprocess

    token = _get_do_token(req.do_token)
    hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Read/generate SSH public key
    key_path = f"/ssh-keys/{req.key_name}"
    pub_path = f"{key_path}.pub"
    pub_key = None

    # Check if .pub file already exists
    if os.path.isfile(pub_path):
        with open(pub_path) as f:
            pub_key = f.read().strip()

    # Check if the key_name itself is a public key file
    if not pub_key and os.path.isfile(key_path):
        with open(key_path) as f:
            content = f.read().strip()
        if content.startswith("ssh-rsa") or content.startswith("ssh-ed25519") or content.startswith("ecdsa-"):
            pub_key = content
        elif "BEGIN SSH2 PUBLIC KEY" in content:
            # Convert SSH2/PuTTY format to OpenSSH
            r = subprocess.run(["ssh-keygen", "-i", "-f", key_path], capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                pub_key = r.stdout.strip()

    # Try generating from private key
    if not pub_key:
        r = subprocess.run(["ssh-keygen", "-y", "-f", key_path], capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout:
            pub_key = r.stdout.strip()
            with open(pub_path, "w") as f:
                f.write(pub_key)

    if not pub_key:
        raise HTTPException(400, f"Cannot read or generate public key for {req.key_name}")

    async with _httpx.AsyncClient(verify=False, timeout=30) as c:
        # Upload/find SSH key on DO
        fp = None
        resp = await c.get("https://api.digitalocean.com/v2/account/keys?per_page=200", headers=hdrs)
        if resp.status_code == 200:
            for k in resp.json().get("ssh_keys", []):
                if k.get("public_key", "").strip() == pub_key:
                    fp = k["fingerprint"]; break
        if not fp:
            resp = await c.post("https://api.digitalocean.com/v2/account/keys", headers=hdrs,
                                json={"name": f"pentest-{req.key_name}", "public_key": pub_key})
            if resp.status_code in (200, 201):
                fp = resp.json()["ssh_key"]["fingerprint"]
            else:
                raise HTTPException(500, f"Failed to upload SSH key to DO: {resp.text}")

        # Create droplet
        resp = await c.post("https://api.digitalocean.com/v2/droplets", headers=hdrs, json={
            "name": req.name, "region": req.region, "size": req.size,
            "image": req.image, "ssh_keys": [fp], "tags": ["pentest-node"],
        })
        if resp.status_code not in (200, 201, 202):
            raise HTTPException(500, f"Failed to create droplet: {resp.text}")
        droplet_id = resp.json()["droplet"]["id"]

    # Determine SSH private key for tunnel connection
    ssh_key = req.ssh_key_name or req.key_name
    ssh_key_path = f"/ssh-keys/{ssh_key}"

    # Track status
    did = str(droplet_id)
    _do_provision_status[did] = {"droplet_id": did, "status": "created", "name": req.name, "ip": None, "node_id": None}

    # Background: wait for IP, SSH, register, connect tunnel
    import threading
    def _provision_background():
        import httpx as _h2
        st = _do_provision_status[did]
        try:
            st["status"] = "waiting_ip"
            ip = None
            for _ in range(24):  # 2 min
                time.sleep(5)
                try:
                    r = _h2.get(f"https://api.digitalocean.com/v2/droplets/{droplet_id}",
                                headers={"Authorization": f"Bearer {token}"}, timeout=10)
                    if r.status_code == 200:
                        for net in r.json()["droplet"].get("networks", {}).get("v4", []):
                            if net.get("type") == "public":
                                ip = net["ip_address"]; break
                except Exception:
                    pass
                if ip: break
            if not ip:
                st["status"] = "failed"; st["error"] = "IP not assigned after 2 min"; return
            st["ip"] = ip; st["status"] = "waiting_ssh"

            ssh_ok = False
            for _ in range(12):
                time.sleep(5)
                try:
                    r2 = subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                                         "-o", "BatchMode=yes", "-i", ssh_key_path, f"root@{ip}", "echo ok"],
                                        capture_output=True, text=True, timeout=15)
                    if r2.returncode == 0 and "ok" in r2.stdout:
                        ssh_ok = True; break
                except Exception:
                    pass
            if not ssh_ok:
                st["status"] = "ssh_timeout"; st["error"] = "SSH not ready. Try connecting manually."; return
            st["status"] = "registering"

            node_id = str(uuid.uuid4())
            socks_port = allocator.allocate("ssh", node_id)
            conn2 = psycopg2.connect(settings.db_dsn)
            cur2 = conn2.cursor()
            cur2.execute("""
                INSERT INTO remote_nodes (id, name, node_type, status, hostname, network_segment, proxy_port, proxy_type, metadata)
                VALUES (%s, %s, 'ssh', 'connecting', %s, %s, %s, 'socks5', %s)
            """, (node_id, req.name, ip, f"digitalocean_{req.region}", socks_port,
                  json.dumps({"host": ip, "user": "root", "ssh_port": 22, "key_file": ssh_key,
                              "os_type": req.os_type, "droplet_id": droplet_id,
                              "do_region": req.region, "do_size": req.size, "source": "digitalocean"})))
            conn2.commit(); cur2.close(); conn2.close()
            st["node_id"] = node_id; st["socks_port"] = socks_port; st["status"] = "connecting"

            # Record IP assignment in history
            _record_ip_assignment(node_id, ip, "digitalocean", str(droplet_id), req.region, proxy_port=socks_port)

            # Start tunnel in async loop
            import asyncio
            loop = asyncio.new_event_loop()
            tunnel = SSHTunnel(node_id=node_id, host=ip, user="root", ssh_port=22,
                               key_file=ssh_key, socks_port=socks_port)
            result = loop.run_until_complete(ssh_manager.start_tunnel(tunnel))
            loop.close()
            new_status = "online" if result.get("ok") else "error"
            _safe_db_execute("UPDATE remote_nodes SET status = %s WHERE id = %s", (new_status, node_id))
            st["status"] = "online" if result.get("ok") else "tunnel_error"

            _emit_ip_event("node_ip_assigned", node_id, {
                "ip": ip, "provider": "digitalocean", "region": req.region,
                "node_name": req.name, "resource_id": str(droplet_id),
            })
        except Exception as e:
            st["status"] = "failed"; st["error"] = str(e)

    threading.Thread(target=_provision_background, daemon=True).start()

    return {"ok": True, "droplet_id": did, "status": "provisioning",
            "message": "Droplet created. Provisioning in background — poll /cloud/do/status/{droplet_id} for updates.",
            "name": req.name}


@app.get("/cloud/do/droplets")
async def list_do_droplets(do_token: Optional[str] = Query(None)):
    """List all DigitalOcean droplets tagged 'pentest-node'."""
    import httpx as _httpx
    token = _get_do_token(do_token)
    async with _httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get("https://api.digitalocean.com/v2/droplets?tag_name=pentest-node&per_page=100",
                           headers={"Authorization": f"Bearer {token}"})
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, f"DO API error: {resp.text}")
        droplets = []
        for d in resp.json().get("droplets", []):
            ip = ""
            for net in d.get("networks", {}).get("v4", []):
                if net.get("type") == "public":
                    ip = net["ip_address"]; break
            droplets.append({
                "id": d["id"],
                "name": d["name"],
                "ip": ip,
                "status": d["status"],
                "region": d["region"]["slug"] if isinstance(d.get("region"), dict) else "",
                "size": d["size_slug"],
                "created_at": d.get("created_at", ""),
                "image": d.get("image", {}).get("slug", "") if isinstance(d.get("image"), dict) else "",
            })
    return {"droplets": droplets, "total": len(droplets)}


@app.delete("/cloud/do/droplet-by-id/{droplet_id}")
async def destroy_do_droplet_by_id(droplet_id: str, do_token: Optional[str] = Query(None)):
    """Destroy a DO droplet by its DO droplet ID (not node ID). Also removes any matching SSH tunnel."""
    import httpx as _httpx

    token = _get_do_token(do_token)
    destroyed = False
    async with _httpx.AsyncClient(verify=False, timeout=30) as c:
        try:
            resp = await c.delete(f"https://api.digitalocean.com/v2/droplets/{droplet_id}",
                                  headers={"Authorization": f"Bearer {token}"})
            destroyed = resp.status_code in (200, 204)
        except Exception as e:
            log.warning(f"Failed to destroy droplet {droplet_id}: {e}")

    # Find and remove any matching node from DB
    removed_node = None
    try:
        conn = psycopg2.connect(settings.db_dsn)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id FROM remote_nodes WHERE metadata->>'droplet_id' = %s", (str(droplet_id),))
        row = cur.fetchone()
        if row:
            removed_node = str(row["id"])
            try:
                await ssh_manager.stop_tunnel(removed_node)
            except Exception:
                pass
            cur.execute("DELETE FROM remote_nodes WHERE id = %s", (removed_node,))
            conn.commit()
            allocator.release(removed_node)
        cur.close(); conn.close()
    except Exception:
        pass

    return {"ok": True, "droplet_id": droplet_id, "droplet_destroyed": destroyed, "node_removed": removed_node}


@app.delete("/cloud/do/droplet/{node_id}")
async def destroy_do_droplet(node_id: str, do_token: Optional[str] = Query(None)):
    """Destroy a DigitalOcean droplet and decommission the node."""
    import httpx as _httpx

    conn = psycopg2.connect(settings.db_dsn)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT metadata FROM remote_nodes WHERE id = %s", (node_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        raise HTTPException(404, "Node not found")

    meta = row["metadata"] if isinstance(row["metadata"], dict) else {}
    droplet_id = meta.get("droplet_id")
    if not droplet_id:
        raise HTTPException(400, "Not a DigitalOcean droplet")

    # Release IP history before destroying
    _release_current_ip(node_id, "destroy")

    try:
        await ssh_manager.stop_tunnel(node_id)
    except Exception:
        pass

    token = _get_do_token(do_token)
    destroyed = False
    async with _httpx.AsyncClient(verify=False, timeout=30) as c:
        try:
            resp = await c.delete(f"https://api.digitalocean.com/v2/droplets/{droplet_id}",
                                  headers={"Authorization": f"Bearer {token}"})
            destroyed = resp.status_code in (200, 204)
        except Exception as e:
            log.warning(f"Failed to destroy droplet {droplet_id}: {e}")

    conn = psycopg2.connect(settings.db_dsn)
    cur = conn.cursor()
    cur.execute("DELETE FROM remote_nodes WHERE id = %s", (node_id,))
    conn.commit(); cur.close(); conn.close()
    allocator.release(node_id)

    _emit_ip_event("node_ip_released", node_id, {
        "provider": "digitalocean", "resource_id": str(droplet_id), "reason": "destroy",
    })

    return {"ok": True, "node_id": node_id, "droplet_id": droplet_id, "droplet_destroyed": destroyed}


# ── DO IP Rotation ─────────────────────────────────────────────────────────

_do_rotate_status: dict = {}


def _do_rotate_reserved_ip(node_id, old_ip, droplet_id, region, token,
                            ssh_key, ssh_key_path, ssh_user, node_name,
                            socks_port, meta, st):
    """Fast IP rotation via DO Reserved IPs — droplet stays running."""
    import httpx as _h2

    def _reserved_ip_background():
        try:
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

            # 1. Find droplet_id if not stored (needed for reserved IP assignment)
            did = droplet_id
            if not did and old_ip:
                st["status"] = "looking_up_droplet"
                try:
                    lr = _h2.get("https://api.digitalocean.com/v2/droplets?tag_name=pentest-node&per_page=100",
                                 headers=headers, timeout=15)
                    if lr.status_code == 200:
                        for d in lr.json().get("droplets", []):
                            for net in d.get("networks", {}).get("v4", []):
                                if net.get("type") == "public" and net.get("ip_address") == old_ip:
                                    did = d["id"]; break
                            if did:
                                break
                except Exception as e:
                    log.warning("Failed to lookup droplet by IP: %s", e)

            if not did:
                st["status"] = "failed"
                st["error"] = "Could not find droplet ID. Use destroy_recreate strategy instead."
                _safe_db_execute("UPDATE remote_nodes SET status = 'error' WHERE id = %s", (node_id,))
                return

            # 2. Check if droplet already has a reserved IP assigned — unassign + delete it
            st["status"] = "removing_old_reserved_ip"
            try:
                rip_resp = _h2.get("https://api.digitalocean.com/v2/reserved_ips?per_page=100",
                                   headers=headers, timeout=10)
                if rip_resp.status_code == 200:
                    for rip in rip_resp.json().get("reserved_ips", []):
                        rip_droplet = rip.get("droplet")
                        if rip_droplet and rip_droplet.get("id") == did:
                            # Unassign from droplet
                            _h2.post(f"https://api.digitalocean.com/v2/reserved_ips/{rip['ip']}/actions",
                                     headers=headers, json={"type": "unassign"}, timeout=15)
                            time.sleep(2)
                            # Delete the old reserved IP
                            _h2.delete(f"https://api.digitalocean.com/v2/reserved_ips/{rip['ip']}",
                                       headers=headers, timeout=10)
                            log.info("Removed old reserved IP %s from droplet %s", rip["ip"], did)
                            time.sleep(2)
            except Exception as e:
                log.warning("Error cleaning old reserved IPs: %s", e)

            # 3. Stop SSH tunnel (will reconnect with new IP)
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                loop.run_until_complete(ssh_manager.stop_tunnel(node_id))
                loop.close()
            except Exception:
                pass

            # 4. Create a new reserved IP assigned to this droplet
            st["status"] = "creating_reserved_ip"
            cr = _h2.post("https://api.digitalocean.com/v2/reserved_ips",
                          headers=headers,
                          json={"droplet_id": did},
                          timeout=30)
            if cr.status_code not in (200, 201, 202):
                st["status"] = "failed"
                st["error"] = f"Failed to create reserved IP: {cr.text[:200]}"
                _safe_db_execute("UPDATE remote_nodes SET status = 'error' WHERE id = %s", (node_id,))
                return

            new_ip = cr.json().get("reserved_ip", {}).get("ip")
            if not new_ip:
                st["status"] = "failed"; st["error"] = "Reserved IP created but no IP returned"
                _safe_db_execute("UPDATE remote_nodes SET status = 'error' WHERE id = %s", (node_id,))
                return
            st["new_ip"] = new_ip; st["status"] = "waiting_ssh"

            # 5. Wait for SSH to be reachable on the new reserved IP
            ssh_ok = False
            for _ in range(12):
                time.sleep(3)
                try:
                    r2 = subprocess.run(
                        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                         "-o", "BatchMode=yes", "-i", ssh_key_path, f"{ssh_user}@{new_ip}", "echo ok"],
                        capture_output=True, text=True, timeout=15)
                    if r2.returncode == 0 and "ok" in r2.stdout:
                        ssh_ok = True; break
                except Exception:
                    pass
            if not ssh_ok:
                st["status"] = "failed"; st["error"] = "SSH not reachable on new reserved IP"
                _safe_db_execute("UPDATE remote_nodes SET status = 'error' WHERE id = %s", (node_id,))
                return

            # 6. Update node DB + metadata
            st["status"] = "reconnecting"
            new_meta = dict(meta)
            new_meta["droplet_id"] = did
            new_meta["reserved_ip"] = new_ip
            _safe_db_execute(
                "UPDATE remote_nodes SET hostname = %s, external_ip = %s, metadata = %s, status = 'connecting' WHERE id = %s",
                (new_ip, new_ip, json.dumps(new_meta), node_id),
            )

            # Record new IP in history
            _record_ip_assignment(node_id, new_ip, "digitalocean", str(did), region, proxy_port=socks_port)

            # 7. Reconnect SSH tunnel on new IP
            import asyncio
            loop = asyncio.new_event_loop()
            tunnel = SSHTunnel(node_id=node_id, name=node_name, host=new_ip, user=ssh_user,
                               ssh_port=22, key_file=ssh_key, socks_port=socks_port)
            result = loop.run_until_complete(ssh_manager.start_tunnel(tunnel))
            loop.close()

            final_status = "online" if result.get("ok") else "error"
            _safe_db_execute("UPDATE remote_nodes SET status = %s WHERE id = %s", (final_status, node_id))
            st["status"] = final_status

            _log_tunnel_event(node_id, "ip_rotation_completed",
                              f"Reserved IP rotation: {old_ip} → {new_ip}")
            _emit_ip_event("node_ip_rotated", node_id, {
                "old_ip": old_ip, "new_ip": new_ip, "provider": "digitalocean",
                "node_name": node_name, "region": region, "strategy": "reserved_ip",
            })
        except Exception as e:
            st["status"] = "failed"; st["error"] = str(e)
            _safe_db_execute("UPDATE remote_nodes SET status = 'error' WHERE id = %s", (node_id,))
            _emit_ip_event("node_ip_rotation_failed", node_id, {
                "error": str(e), "provider": "digitalocean", "node_name": node_name,
                "strategy": "reserved_ip",
            })

    threading.Thread(target=_reserved_ip_background, daemon=True).start()


@app.post("/cloud/do/rotate-ip/{node_id}")
async def rotate_do_ip(node_id: str, do_token: Optional[str] = Query(None),
                        strategy: str = Query("reserved_ip",
                            description="reserved_ip (fast, keeps droplet) or destroy_recreate (slow, new droplet)")):
    """Rotate IP of a DigitalOcean droplet.

    Strategies:
    - reserved_ip (default): Assign a new Reserved IP to the droplet. Fast (~10s),
      droplet stays running with all tools. Old reserved IP is released.
    - destroy_recreate: Destroy droplet and create a new one. Slow (~2min),
      but guarantees a completely fresh IP from a different pool.
    """
    import httpx as _httpx

    conn = psycopg2.connect(settings.db_dsn)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT name, hostname, metadata, proxy_port FROM remote_nodes WHERE id = %s", (node_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        raise HTTPException(404, "Node not found")
    meta = row["metadata"] if isinstance(row["metadata"], dict) else {}
    is_do = meta.get("source") == "digitalocean" or meta.get("provider") == "digitalocean"
    if not is_do:
        raise HTTPException(400, "Not a DigitalOcean node")

    old_ip = row["hostname"] or ""
    droplet_id = meta.get("droplet_id")
    region = meta.get("do_region", "nyc1")
    size = meta.get("do_size", "s-1vcpu-1gb")
    ssh_key = meta.get("key_file", "id_rsa")
    ssh_key_path = f"/ssh-keys/{ssh_key}"
    node_name = row["name"]
    socks_port = row["proxy_port"]
    ssh_user = meta.get("user", "root")
    token = _get_do_token(do_token)

    _safe_db_execute("UPDATE remote_nodes SET status = 'rotating' WHERE id = %s", (node_id,))
    _release_current_ip(node_id, "rotation")
    _log_tunnel_event(node_id, "ip_rotation_started", f"Rotating IP (old: {old_ip}, strategy: {strategy})")

    if strategy == "reserved_ip":
        # Fast path: swap reserved IP without destroying droplet
        st = {"status": "looking_up_droplet", "old_ip": old_ip, "new_ip": None,
              "error": None, "node_id": node_id, "strategy": "reserved_ip"}
        _do_rotate_status[node_id] = st
        _do_rotate_reserved_ip(node_id, old_ip, droplet_id, region, token,
                               ssh_key, ssh_key_path, ssh_user, node_name, socks_port, meta, st)
        return {"ok": True, "node_id": node_id, "status": "rotating",
                "old_ip": old_ip, "strategy": "reserved_ip"}

    # Slow path: destroy + recreate
    st = {"status": "destroying", "old_ip": old_ip, "new_ip": None,
          "error": None, "node_id": node_id, "strategy": "destroy_recreate"}
    _do_rotate_status[node_id] = st

    def _rotate_background():
        """Destroy+recreate strategy — slow but guarantees fresh IP from different pool."""
        import httpx as _h2
        try:
            # Stop tunnel
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                loop.run_until_complete(ssh_manager.stop_tunnel(node_id))
                loop.close()
            except Exception:
                pass

            # If no droplet_id stored, try to find it by IP from DO API
            nonlocal droplet_id
            if not droplet_id and old_ip:
                try:
                    lr = _h2.get("https://api.digitalocean.com/v2/droplets?tag_name=pentest-node&per_page=100",
                                 headers={"Authorization": f"Bearer {token}"}, timeout=15)
                    if lr.status_code == 200:
                        for d in lr.json().get("droplets", []):
                            for net in d.get("networks", {}).get("v4", []):
                                if net.get("type") == "public" and net.get("ip_address") == old_ip:
                                    droplet_id = d["id"]
                                    log.info("Found droplet %s by IP %s", droplet_id, old_ip)
                                    break
                            if droplet_id:
                                break
                except Exception as e:
                    log.warning("Failed to lookup droplet by IP: %s", e)

            # Destroy old droplet
            if droplet_id:
                try:
                    resp = _h2.delete(f"https://api.digitalocean.com/v2/droplets/{droplet_id}",
                                      headers={"Authorization": f"Bearer {token}"}, timeout=30)
                except Exception as e:
                    log.warning("Failed to destroy old droplet %s: %s", droplet_id, e)
            time.sleep(3)

            # Get SSH key ID for DO
            st["status"] = "creating"
            ssh_pub_path = ssh_key_path + ".pub"
            if not os.path.exists(ssh_pub_path):
                ssh_pub_path = ssh_key_path
            with open(ssh_pub_path) as f:
                local_pub = f.read().strip()

            ssh_key_ids = []
            try:
                kr = _h2.get("https://api.digitalocean.com/v2/account/keys?per_page=200",
                             headers={"Authorization": f"Bearer {token}"}, timeout=10)
                if kr.status_code == 200:
                    for k in kr.json().get("ssh_keys", []):
                        if k.get("public_key", "").strip() == local_pub:
                            ssh_key_ids = [k["id"]]; break
            except Exception:
                pass

            # Create new droplet
            create_body = {
                "name": node_name, "region": region, "size": size,
                "image": "ubuntu-24-04-x64",
                "ssh_keys": ssh_key_ids,
                "tags": ["pentest-node"],
            }
            cr = _h2.post("https://api.digitalocean.com/v2/droplets",
                          headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                          json=create_body, timeout=30)
            if cr.status_code not in (200, 201, 202):
                st["status"] = "failed"; st["error"] = f"DO create failed: {cr.text[:200]}"; return
            new_droplet = cr.json().get("droplet", {})
            new_droplet_id = new_droplet.get("id")

            # Poll for IP
            st["status"] = "waiting_ip"
            new_ip = None
            for _ in range(24):
                time.sleep(5)
                try:
                    r = _h2.get(f"https://api.digitalocean.com/v2/droplets/{new_droplet_id}",
                                headers={"Authorization": f"Bearer {token}"}, timeout=10)
                    if r.status_code == 200:
                        for net in r.json()["droplet"].get("networks", {}).get("v4", []):
                            if net.get("type") == "public":
                                new_ip = net["ip_address"]; break
                except Exception:
                    pass
                if new_ip:
                    break
            if not new_ip:
                st["status"] = "failed"; st["error"] = "New IP not assigned after 2 min"; return
            st["new_ip"] = new_ip; st["status"] = "waiting_ssh"

            # Wait for SSH
            ssh_ok = False
            for _ in range(12):
                time.sleep(5)
                try:
                    r2 = subprocess.run(
                        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                         "-o", "BatchMode=yes", "-i", ssh_key_path, f"root@{new_ip}", "echo ok"],
                        capture_output=True, text=True, timeout=15)
                    if r2.returncode == 0 and "ok" in r2.stdout:
                        ssh_ok = True; break
                except Exception:
                    pass
            if not ssh_ok:
                st["status"] = "failed"; st["error"] = "SSH not ready on new droplet"; return

            # Update node in DB
            st["status"] = "reconnecting"
            new_meta = dict(meta)
            new_meta["droplet_id"] = new_droplet_id
            _safe_db_execute(
                "UPDATE remote_nodes SET hostname = %s, external_ip = %s, metadata = %s, status = 'connecting' WHERE id = %s",
                (new_ip, new_ip, json.dumps(new_meta), node_id),
            )

            # Record new IP
            _record_ip_assignment(node_id, new_ip, "digitalocean", str(new_droplet_id), region, proxy_port=socks_port)

            # Reconnect tunnel
            import asyncio
            loop = asyncio.new_event_loop()
            tunnel = SSHTunnel(node_id=node_id, name=node_name, host=new_ip, user="root",
                               ssh_port=22, key_file=ssh_key, socks_port=socks_port)
            result = loop.run_until_complete(ssh_manager.start_tunnel(tunnel))
            loop.close()

            final_status = "online" if result.get("ok") else "error"
            _safe_db_execute("UPDATE remote_nodes SET status = %s WHERE id = %s", (final_status, node_id))
            st["status"] = final_status

            _log_tunnel_event(node_id, "ip_rotation_completed", f"Rotated {old_ip} → {new_ip}")
            _emit_ip_event("node_ip_rotated", node_id, {
                "old_ip": old_ip, "new_ip": new_ip, "provider": "digitalocean",
                "node_name": node_name, "region": region,
            })
        except Exception as e:
            st["status"] = "failed"; st["error"] = str(e)
            _safe_db_execute("UPDATE remote_nodes SET status = 'error' WHERE id = %s", (node_id,))
            _emit_ip_event("node_ip_rotation_failed", node_id, {
                "error": str(e), "provider": "digitalocean", "node_name": node_name,
            })

    threading.Thread(target=_rotate_background, daemon=True).start()
    return {"ok": True, "node_id": node_id, "status": "rotating", "old_ip": old_ip}


@app.get("/cloud/do/rotate-status/{node_id}")
async def do_rotate_status(node_id: str):
    """Poll rotation progress for a DigitalOcean droplet."""
    st = _do_rotate_status.get(node_id)
    if not st:
        return {"status": "unknown", "error": "No rotation in progress for this node"}
    return st


# ── IP History Query ──────────────────────────────────────────────────────

@app.get("/cloud/ip-history")
async def get_ip_history(node_id: Optional[str] = Query(None), limit: int = Query(100)):
    """List IP assignment history, optionally filtered by node_id."""
    conditions = []
    params: list = []
    if node_id:
        conditions.append("h.node_id = %s")
        params.append(node_id)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)

    rows = _safe_db_execute(f"""
        SELECT h.id::text, h.node_id::text, n.name AS node_name,
               host(h.ip_address)::text AS ip_address, h.cloud_provider,
               h.cloud_resource_id, h.region,
               h.assigned_at, h.released_at, h.release_reason,
               h.scan_count, h.metadata
        FROM node_ip_history h
        LEFT JOIN remote_nodes n ON h.node_id = n.id
        {where}
        ORDER BY h.assigned_at DESC
        LIMIT %s
    """, params, fetch=True) or []

    history = []
    for r in rows:
        meta = r[11] or {}
        history.append({
            "id": r[0], "node_id": r[1], "node_name": r[2] or "deleted",
            "ip_address": r[3], "cloud_provider": r[4],
            "cloud_resource_id": r[5], "region": r[6],
            "assigned_at": r[7].isoformat() if r[7] else None,
            "released_at": r[8].isoformat() if r[8] else None,
            "release_reason": r[9], "scan_count": r[10],
            "proxy_port": meta.get("proxy_port"),
            "metadata": meta,
        })
    return {"history": history, "total": len(history)}


# ══════════════════════════════════════════════════════════════════════════════
# ── AWS EC2 Cloud Provisioning ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

import boto3
from botocore.exceptions import ClientError

AWS_INSTANCE_TYPES = [
    {"type": "t3.micro",   "label": "t3.micro (2 vCPU / 1GB) ~$8/mo",   "vcpus": 2, "memory": 1024, "price": 8},
    {"type": "t3.small",   "label": "t3.small (2 vCPU / 2GB) ~$15/mo",  "vcpus": 2, "memory": 2048, "price": 15},
    {"type": "t3.medium",  "label": "t3.medium (2 vCPU / 4GB) ~$30/mo", "vcpus": 2, "memory": 4096, "price": 30},
    {"type": "t3.large",   "label": "t3.large (2 vCPU / 8GB) ~$60/mo",  "vcpus": 2, "memory": 8192, "price": 60},
    {"type": "m5.large",   "label": "m5.large (2 vCPU / 8GB) ~$70/mo",  "vcpus": 2, "memory": 8192, "price": 70},
    {"type": "c5.large",   "label": "c5.large (2 vCPU / 4GB) ~$62/mo",  "vcpus": 2, "memory": 4096, "price": 62},
    {"type": "t3.xlarge",  "label": "t3.xlarge (4 vCPU / 16GB) ~$120/mo", "vcpus": 4, "memory": 16384, "price": 120},
]

AWS_REGIONS = [
    {"id": "us-east-1",      "label": "US East (N. Virginia)"},
    {"id": "us-east-2",      "label": "US East (Ohio)"},
    {"id": "us-west-1",      "label": "US West (N. California)"},
    {"id": "us-west-2",      "label": "US West (Oregon)"},
    {"id": "eu-west-1",      "label": "EU (Ireland)"},
    {"id": "eu-west-2",      "label": "EU (London)"},
    {"id": "eu-central-1",   "label": "EU (Frankfurt)"},
    {"id": "ap-southeast-1", "label": "Asia Pacific (Singapore)"},
    {"id": "ap-northeast-1", "label": "Asia Pacific (Tokyo)"},
]

# Ubuntu 24.04 LTS AMIs by region (update as needed)
AWS_AMIS = {
    "us-east-1":      "ami-0a0e5d9c7acc336f1",
    "us-east-2":      "ami-0ea3c35c5c3284d82",
    "us-west-1":      "ami-0da424eb883458071",
    "us-west-2":      "ami-05134c8ef96964280",
    "eu-west-1":      "ami-0932dacac40f09fb6",
    "eu-west-2":      "ami-0b45ae66668865cd6",
    "eu-central-1":   "ami-0faab6bdbac9486fb",
    "ap-southeast-1": "ami-060e277c0d4cce553",
    "ap-northeast-1": "ami-0b20f552f63953f0e",
}

_ec2_provision_status: dict = {}  # instance_id -> status dict


def _get_aws_session(region: str = "us-east-1", override_key: str = None, override_secret: str = None):
    """Get boto3 session from override, env, or DB."""
    key_id = override_key or os.environ.get("AWS_ACCESS_KEY_ID")
    secret = override_secret or os.environ.get("AWS_SECRET_ACCESS_KEY")

    if not key_id or not secret:
        try:
            conn2 = psycopg2.connect(settings.db_dsn)
            cur = conn2.cursor()
            cur.execute("SELECT key, value FROM app_settings WHERE key IN ('aws_access_key_id', 'aws_secret_access_key')")
            for row in cur.fetchall():
                if row[0] == "aws_access_key_id": key_id = row[1]
                elif row[0] == "aws_secret_access_key": secret = row[1]
            cur.close(); conn2.close()
        except Exception:
            pass

    if not key_id or not secret:
        raise HTTPException(400, "AWS credentials not configured. Add aws_access_key_id and aws_secret_access_key in Settings → API Keys.")

    return boto3.Session(aws_access_key_id=key_id, aws_secret_access_key=secret, region_name=region)


class AWSCreateRequest(BaseModel):
    name: str
    instance_type: str = "t3.micro"
    region: str = "us-east-1"
    ami: str = ""  # Auto-select from AWS_AMIS if empty
    key_name: str = "id_rsa"       # Public key for EC2
    ssh_key_name: str = ""          # Private key for SSH tunnel
    os_type: str = "ubuntu"
    aws_key: Optional[str] = None
    aws_secret: Optional[str] = None


@app.get("/cloud/aws/options")
async def aws_options():
    return {"instance_types": AWS_INSTANCE_TYPES, "regions": AWS_REGIONS, "amis": AWS_AMIS}


@app.get("/cloud/aws/status/{instance_id}")
async def ec2_provision_status(instance_id: str):
    status = _ec2_provision_status.get(instance_id)
    if not status:
        return {"instance_id": instance_id, "status": "unknown"}
    return status


@app.post("/cloud/aws/create")
async def create_ec2_instance(req: AWSCreateRequest):
    """Create an AWS EC2 instance, wait for IP, SSH, then auto-connect tunnel."""
    session = _get_aws_session(req.region, req.aws_key, req.aws_secret)
    ec2 = session.resource("ec2")
    ec2_client = session.client("ec2")

    # Determine AMI
    ami = req.ami or AWS_AMIS.get(req.region)
    if not ami:
        raise HTTPException(400, f"No default AMI for region {req.region}. Specify ami parameter.")

    # Read SSH public key
    key_path = f"/ssh-keys/{req.key_name}"
    pub_key = None
    for path in [f"{key_path}.pub", f"{key_path}.openssh", key_path]:
        if os.path.isfile(path):
            content = open(path).read().strip()
            if content.startswith("ssh-rsa") or content.startswith("ssh-ed25519") or content.startswith("ecdsa-"):
                pub_key = content; break
            elif "BEGIN SSH2 PUBLIC KEY" in content:
                r = subprocess.run(["ssh-keygen", "-i", "-f", path], capture_output=True, text=True, timeout=10)
                if r.returncode == 0: pub_key = r.stdout.strip(); break
    if not pub_key:
        r = subprocess.run(["ssh-keygen", "-y", "-f", key_path], capture_output=True, text=True, timeout=10)
        if r.returncode == 0: pub_key = r.stdout.strip()
    if not pub_key:
        raise HTTPException(400, f"Cannot read or generate public key from {req.key_name}")

    # Import/find key pair on EC2
    ec2_key_name = f"pentest-{req.key_name.replace('.', '-')}"
    try:
        ec2_client.describe_key_pairs(KeyNames=[ec2_key_name])
    except ClientError:
        ec2_client.import_key_pair(KeyName=ec2_key_name, PublicKeyMaterial=pub_key.encode())

    # Get/create security group
    sg_name = "pentest-node-sg"
    sg_id = None
    try:
        resp = ec2_client.describe_security_groups(GroupNames=[sg_name])
        sg_id = resp["SecurityGroups"][0]["GroupId"]
    except ClientError:
        resp = ec2_client.create_security_group(GroupName=sg_name, Description="Pentest scan node — SSH access")
        sg_id = resp["GroupId"]
        ec2_client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH"}]},
        ])

    # Launch instance
    instances = ec2.create_instances(
        ImageId=ami,
        MinCount=1, MaxCount=1,
        InstanceType=req.instance_type,
        KeyName=ec2_key_name,
        SecurityGroupIds=[sg_id],
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name", "Value": req.name},
                {"Key": "pentest-node", "Value": "true"},
            ],
        }],
    )
    instance_id = instances[0].id

    # Determine SSH private key
    ssh_key = req.ssh_key_name or req.key_name
    ssh_key_path = f"/ssh-keys/{ssh_key}"

    # Track status
    _ec2_provision_status[instance_id] = {
        "instance_id": instance_id, "status": "created", "name": req.name, "ip": None, "node_id": None,
    }

    # Background provision
    import threading
    def _provision():
        st = _ec2_provision_status[instance_id]
        try:
            st["status"] = "waiting_ip"
            inst = ec2.Instance(instance_id)
            inst.wait_until_running()
            inst.reload()
            ip = inst.public_ip_address

            if not ip:
                for _ in range(24):
                    time.sleep(5)
                    inst.reload()
                    ip = inst.public_ip_address
                    if ip: break
            if not ip:
                st["status"] = "failed"; st["error"] = "No public IP after 2 min"; return
            st["ip"] = ip; st["status"] = "waiting_ssh"

            ssh_ok = False
            for _ in range(18):  # 90s
                time.sleep(5)
                try:
                    r2 = subprocess.run(
                        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                         "-o", "BatchMode=yes", "-i", ssh_key_path, f"ubuntu@{ip}", "echo ok"],
                        capture_output=True, text=True, timeout=15)
                    if r2.returncode == 0 and "ok" in r2.stdout:
                        ssh_ok = True; break
                except Exception:
                    pass
            if not ssh_ok:
                st["status"] = "ssh_timeout"; st["error"] = "SSH not ready. Try connecting manually."; return
            st["status"] = "registering"

            node_id = str(uuid.uuid4())
            socks_port = allocator.allocate("ssh", node_id)
            conn2 = psycopg2.connect(settings.db_dsn)
            cur2 = conn2.cursor()
            cur2.execute("""
                INSERT INTO remote_nodes (id, name, node_type, status, hostname, network_segment, proxy_port, proxy_type, metadata)
                VALUES (%s, %s, 'ssh', 'connecting', %s, %s, %s, 'socks5', %s)
            """, (node_id, req.name, ip, f"aws_{req.region}", socks_port,
                  json.dumps({"host": ip, "user": "ubuntu", "ssh_port": 22, "key_file": ssh_key,
                              "os_type": req.os_type, "instance_id": instance_id,
                              "aws_region": req.region, "aws_instance_type": req.instance_type,
                              "source": "aws"})))
            conn2.commit(); cur2.close(); conn2.close()
            st["node_id"] = node_id; st["socks_port"] = socks_port; st["status"] = "connecting"

            # Record IP assignment in history
            _record_ip_assignment(node_id, ip, "aws", instance_id, req.region, proxy_port=socks_port)

            import asyncio
            loop = asyncio.new_event_loop()
            tunnel = SSHTunnel(node_id=node_id, host=ip, user="ubuntu", ssh_port=22,
                               key_file=ssh_key, socks_port=socks_port)
            result = loop.run_until_complete(ssh_manager.start_tunnel(tunnel))
            loop.close()
            new_status = "online" if result.get("ok") else "error"
            _safe_db_execute("UPDATE remote_nodes SET status = %s WHERE id = %s", (new_status, node_id))
            st["status"] = "online" if result.get("ok") else "tunnel_error"

            _emit_ip_event("node_ip_assigned", node_id, {
                "ip": ip, "provider": "aws", "region": req.region,
                "node_name": req.name, "resource_id": instance_id,
            })
        except Exception as e:
            st["status"] = "failed"; st["error"] = str(e)

    threading.Thread(target=_provision, daemon=True).start()
    return {"ok": True, "instance_id": instance_id, "status": "provisioning",
            "message": "EC2 instance launched. Polling for IP and SSH...", "name": req.name}


@app.get("/cloud/aws/instances")
async def list_ec2_instances(aws_key: Optional[str] = Query(None), aws_secret: Optional[str] = Query(None),
                              region: str = Query("us-east-1")):
    """List EC2 instances tagged pentest-node=true."""
    try:
        session = _get_aws_session(region, aws_key, aws_secret)
        ec2_client = session.client("ec2")
        resp = ec2_client.describe_instances(Filters=[
            {"Name": "tag:pentest-node", "Values": ["true"]},
            {"Name": "instance-state-name", "Values": ["running", "pending", "stopped"]},
        ])
        instances = []
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name": name = tag["Value"]
                instances.append({
                    "id": inst["InstanceId"],
                    "name": name,
                    "ip": inst.get("PublicIpAddress", ""),
                    "private_ip": inst.get("PrivateIpAddress", ""),
                    "status": inst["State"]["Name"],
                    "type": inst["InstanceType"],
                    "region": region,
                    "launched_at": inst.get("LaunchTime", "").isoformat() if inst.get("LaunchTime") else "",
                })
        return {"instances": instances, "total": len(instances), "region": region}
    except HTTPException:
        raise
    except Exception as e:
        return {"instances": [], "error": str(e)}


@app.delete("/cloud/aws/instance-by-id/{instance_id}")
async def destroy_ec2_instance_by_id(instance_id: str, region: str = Query("us-east-1"),
                                       aws_key: Optional[str] = Query(None), aws_secret: Optional[str] = Query(None)):
    """Terminate an EC2 instance by its instance ID."""
    session = _get_aws_session(region, aws_key, aws_secret)
    ec2 = session.resource("ec2")
    terminated = False
    try:
        ec2.Instance(instance_id).terminate()
        terminated = True
    except Exception as e:
        log.warning(f"Failed to terminate {instance_id}: {e}")

    # Find and clean up matching node
    removed_node = None
    try:
        conn2 = psycopg2.connect(settings.db_dsn)
        cur = conn2.cursor()
        cur.execute("SELECT id FROM remote_nodes WHERE metadata->>'instance_id' = %s", (instance_id,))
        row = cur.fetchone()
        if row:
            removed_node = str(row[0])
            await ssh_manager.stop_tunnel(removed_node)
            cur.execute("DELETE FROM remote_nodes WHERE id = %s", (removed_node,))
            conn2.commit()
            allocator.release(removed_node)
        cur.close(); conn2.close()
    except Exception:
        pass

    return {"ok": True, "instance_id": instance_id, "terminated": terminated, "node_removed": removed_node}


@app.delete("/cloud/aws/instance/{node_id}")
async def destroy_ec2_instance(node_id: str, aws_key: Optional[str] = Query(None), aws_secret: Optional[str] = Query(None)):
    """Terminate an EC2 instance and decommission the node."""
    conn2 = psycopg2.connect(settings.db_dsn)
    cur = conn2.cursor()
    cur.execute("SELECT metadata FROM remote_nodes WHERE id = %s", (node_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn2.close()
        raise HTTPException(404, "Node not found")
    meta = row[0] if isinstance(row[0], dict) else {}
    instance_id = meta.get("instance_id")
    region = meta.get("aws_region", "us-east-1")
    if not instance_id:
        cur.close(); conn2.close()
        raise HTTPException(400, "Not an AWS EC2 instance")

    # Release IP history before destroying
    _release_current_ip(node_id, "destroy")

    await ssh_manager.stop_tunnel(node_id)
    terminated = False
    try:
        session = _get_aws_session(region, aws_key, aws_secret)
        session.resource("ec2").Instance(instance_id).terminate()
        terminated = True
    except Exception as e:
        log.warning(f"Failed to terminate {instance_id}: {e}")

    cur.execute("DELETE FROM remote_nodes WHERE id = %s", (node_id,))
    conn2.commit(); cur.close(); conn2.close()
    allocator.release(node_id)

    _emit_ip_event("node_ip_released", node_id, {
        "provider": "aws", "resource_id": instance_id, "reason": "destroy",
    })
    return {"ok": True, "node_id": node_id, "instance_id": instance_id, "terminated": terminated}


# ---------------------------------------------------------------------------
# WireGuard Management (Phase 3)
# ---------------------------------------------------------------------------

class WireGuardConfig(BaseModel):
    """WireGuard peer configuration."""
    name: str
    node_id: str
    client_config: str
    qr_code: Optional[str] = None
    installation_status: str = "pending"  # pending, success, failed
    installation_logs: list[str] = []

class CreateWGPeerRequest(BaseModel):
    """Request to create a WireGuard peer."""
    name: str
    node_id: str
    endpoint: Optional[str] = None
    auto_install: bool = True  # Automatically install WireGuard client on the remote node

async def _auto_install_wireguard(node_id: str, client_config: str, assigned_ip: str) -> tuple[list[str], bool]:
    """Automatically install and configure WireGuard client on remote node via SSH.

    Returns: (installation_logs, success_status)
    """
    logs = []

    # Get node metadata for SSH connection
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT metadata, hostname FROM remote_nodes WHERE id = %s", (node_id,))
    result = cur.fetchone()
    cur.close()
    conn.close()

    if not result:
        logs.append("ERROR: Node not found in database")
        return logs, False

    metadata, hostname = result
    # Smart IP selection: prefer reserved_ip over host for DigitalOcean nodes
    if metadata.get("provider") == "digitalocean" and metadata.get("reserved_ip"):
        host = metadata.get("reserved_ip")
    else:
        host = metadata.get("host", hostname)
    user = metadata.get("user", "root")
    ssh_port = metadata.get("ssh_port", 22)
    key_file = metadata.get("key_file", "id_rsa")

    ssh_manager = SSHManager()
    logs.append(f"Starting WireGuard installation on {user}@{host}:{ssh_port}")

    try:
        # Step 1: Install WireGuard and microsocks using script upload approach
        logs.append("Step 1: Installing WireGuard and dependencies...")

        # Create installation script content
        install_script = f"""#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

echo "Cleaning up any stuck apt processes and locks..."
# Clean up any stuck apt processes and locks
pkill -f 'apt|dpkg' 2>/dev/null || true
rm -f /var/lib/dpkg/lock* /var/cache/apt/archives/lock /var/lib/apt/lists/lock 2>/dev/null || true
dpkg --configure -a 2>/dev/null || true

echo "Updating package lists..."
apt-get update -qq

echo "Installing WireGuard tools..."
apt-get install -y wireguard-tools iproute2 curl netcat-openbsd

# Install microsocks if not present
if ! command -v microsocks >/dev/null 2>&1; then
    if [ ! -f /usr/local/bin/microsocks ]; then
        echo "Downloading microsocks..."
        curl -L -o /tmp/microsocks https://github.com/rofl0r/microsocks/releases/download/v1.0.3/microsocks-linux-x86_64
        chmod +x /tmp/microsocks
        mv /tmp/microsocks /usr/local/bin/microsocks
        echo "microsocks installed"
    fi
fi

echo "Installation completed successfully"
"""

        # Write script to temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(install_script)
            local_script_path = f.name

        try:
            # Upload script to remote host
            upload_result = await ssh_manager.upload_file(
                host=host, user=user, ssh_port=ssh_port, key_file=key_file,
                local_path=local_script_path, remote_path="/tmp/install_wg.sh",
                node_id=node_id
            )

            if not upload_result.get("ok"):
                logs.append(f"ERROR: Failed to upload installation script - {upload_result.get('error', 'Unknown error')}")
                return logs, False

            logs.append("✓ Installation script uploaded to remote host")

            # Execute script remotely (simple command that won't be blocked)
            result = await ssh_manager.exec_command(
                node_id=node_id, host=host, user=user, ssh_port=ssh_port,
                key_file=key_file, command="bash /tmp/install_wg.sh", timeout=180
            )

        finally:
            # Clean up local temporary file
            import os
            if os.path.exists(local_script_path):
                os.unlink(local_script_path)

        if not result.get("ok"):
            logs.append(f"ERROR: Package installation failed - {result.get('error', 'Unknown error')}")
            if result.get("stderr"):
                logs.append(f"STDERR: {result['stderr'][:200]}")
            return logs, False

        logs.append("✓ WireGuard and dependencies installed successfully")

        # Step 2: Upload WireGuard config file separately (better architecture!)
        logs.append("Step 2: Uploading WireGuard configuration...")

        # Create config file locally
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(client_config)
            local_config_path = f.name

        # Create generic config installation script (reusable!)
        config_script = """#!/bin/bash
set -e

if [ ! -f "/tmp/wg0.conf" ]; then
    echo "ERROR: WireGuard config file not found at /tmp/wg0.conf"
    exit 1
fi

mkdir -p /etc/wireguard
cp /tmp/wg0.conf /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf
echo "Config installed: /etc/wireguard/wg0.conf"
"""

        # Write config script locally
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(config_script)
            local_script_path = f.name

        try:
            # Upload WireGuard config file
            config_upload = await ssh_manager.upload_file(
                host=host, user=user, ssh_port=ssh_port, key_file=key_file,
                local_path=local_config_path, remote_path="/tmp/wg0.conf",
                node_id=node_id
            )

            if not config_upload.get("ok"):
                logs.append(f"ERROR: Failed to upload WireGuard config - {config_upload.get('error', 'Unknown error')}")
                return logs, False

            logs.append("✓ WireGuard config uploaded to /tmp/wg0.conf")

            # Upload config installation script
            script_upload = await ssh_manager.upload_file(
                host=host, user=user, ssh_port=ssh_port, key_file=key_file,
                local_path=local_script_path, remote_path="/tmp/config_wg.sh",
                node_id=node_id
            )

            if not script_upload.get("ok"):
                logs.append(f"ERROR: Failed to upload config script - {script_upload.get('error', 'Unknown error')}")
                return logs, False

            # Execute config script
            config_cmd = "bash /tmp/config_wg.sh"

        finally:
            # Clean up local temporary files
            for path in [local_config_path, local_script_path]:
                if os.path.exists(path):
                    os.unlink(path)

        result = await ssh_manager.exec_command(
            node_id=node_id, host=host, user=user, ssh_port=ssh_port,
            key_file=key_file, command=config_cmd, timeout=30
        )

        if not result.get("ok"):
            logs.append(f"ERROR: Config write failed - {result.get('error', 'Unknown error')}")
            return logs, False

        logs.append("✓ WireGuard configuration written")

        # Step 3: Start WireGuard interface
        logs.append("Step 3: Starting WireGuard interface...")
        start_wg_cmd = """
        # Stop any existing instance
        echo "Stopping existing WireGuard interface..."
        wg-quick down wg0 2>/dev/null || true

        # Start WireGuard
        echo "Starting WireGuard interface wg0..."
        wg-quick up wg0

        # Verify interface is up and show status
        echo "Interface status:"
        ip addr show wg0
        echo "WireGuard status:"
        wg show
        """

        result = await ssh_manager.exec_command(
            node_id=node_id, host=host, user=user, ssh_port=ssh_port,
            key_file=key_file, command=start_wg_cmd, timeout=30
        )

        if not result.get("ok"):
            logs.append(f"ERROR: WireGuard interface startup failed - {result.get('error', 'Unknown error')}")
            if result.get("stderr"):
                logs.append(f"STDERR: {result['stderr'][:200]}")
            return logs, False

        logs.append("✓ WireGuard interface started")
        if result.get("stdout"):
            logs.append(f"Interface info: {result['stdout'][:100]}...")

        # Step 4: Start microsocks
        logs.append("Step 4: Starting microsocks SOCKS proxy...")
        microsocks_cmd = f"""
        # Kill any existing microsocks
        pkill microsocks 2>/dev/null || true

        # Start microsocks on WireGuard interface
        echo "Starting microsocks on {assigned_ip}:1080..."
        nohup /usr/local/bin/microsocks -i {assigned_ip} -p 1080 >/tmp/microsocks.log 2>&1 &
        sleep 3

        # Verify microsocks is listening
        echo "Checking microsocks status..."
        if netstat -ln 2>/dev/null | grep {assigned_ip}:1080; then
            echo "microsocks is listening on {assigned_ip}:1080"
        elif ss -ln 2>/dev/null | grep {assigned_ip}:1080; then
            echo "microsocks is listening on {assigned_ip}:1080 (ss)"
        else
            echo "ERROR: microsocks not listening on {assigned_ip}:1080"
            cat /tmp/microsocks.log 2>/dev/null || echo "No microsocks log"
            exit 1
        fi
        """

        result = await ssh_manager.exec_command(
            node_id=node_id, host=host, user=user, ssh_port=ssh_port,
            key_file=key_file, command=microsocks_cmd, timeout=30
        )

        if not result.get("ok"):
            logs.append(f"ERROR: microsocks startup failed - {result.get('error', 'Unknown error')}")
            if result.get("stderr"):
                logs.append(f"STDERR: {result['stderr'][:200]}")
            return logs, False

        logs.append("✓ microsocks SOCKS proxy started")

        # Step 5: Test connectivity
        logs.append("Step 5: Testing WireGuard connectivity...")
        test_cmd = f"""
        # Test ping to WireGuard server
        echo "Testing ping to WireGuard server (10.66.0.1)..."
        if ping -c 2 10.66.0.1 >/dev/null 2>&1; then
            echo "✓ Can ping WireGuard server"
        else
            echo "WARNING: Cannot ping WireGuard server"
        fi

        # Test if microsocks responds
        echo "Testing microsocks connectivity..."
        if nc -z {assigned_ip} 1080; then
            echo "✓ microsocks is responding"
        else
            echo "ERROR: microsocks not responding"
            exit 1
        fi

        echo "All tests passed - WireGuard tunnel is ready"
        """

        result = await ssh_manager.exec_command(
            node_id=node_id, host=host, user=user, ssh_port=ssh_port,
            key_file=key_file, command=test_cmd, timeout=30
        )

        if not result.get("ok"):
            logs.append(f"WARNING: Connectivity test failed - {result.get('error', 'Unknown error')}")
            logs.append("WireGuard installed but connectivity test failed")
            return logs, False

        logs.append("✓ WireGuard connectivity test passed")
        logs.append(f"SUCCESS: WireGuard tunnel ready on {assigned_ip}:1080")

        return logs, True

    except Exception as e:
        logs.append(f"EXCEPTION: {str(e)}")
        return logs, False


def _generate_wg_keypair():
    """Generate WireGuard private/public key pair."""
    private_key = subprocess.run(
        ["wg", "genkey"],
        capture_output=True, text=True, check=True
    ).stdout.strip()

    public_key = subprocess.run(
        ["wg", "pubkey"],
        input=private_key, capture_output=True, text=True, check=True
    ).stdout.strip()

    return private_key, public_key

def _get_next_wg_ip():
    """Get next available IP in WireGuard subnet (10.66.0.x)."""
    conn = _get_conn()
    cur = conn.cursor()

    # Get all assigned IPs
    cur.execute("SELECT wg_assigned_ip FROM remote_nodes WHERE wg_assigned_ip IS NOT NULL")
    assigned_ips = [row[0] for row in cur.fetchall()]

    # Find next free IP in 10.66.0.x range (server uses .1, start from .2)
    for i in range(2, 255):
        ip = f"10.66.0.{i}"
        if ip not in assigned_ips:
            cur.close()
            conn.close()
            return ip

    cur.close()
    conn.close()
    raise HTTPException(503, "No available IPs in WireGuard subnet")

def _get_server_public_key():
    """Read WireGuard server public key."""
    try:
        with open("/opt/rag-scan-stack/wireguard/server/server/publickey-server", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise HTTPException(503, "WireGuard server not initialized. Start wg-server container first.")

def _add_peer_to_server(public_key: str, allowed_ip: str, name: str = ""):
    """Add peer to WireGuard server configuration."""
    config_path = "/opt/rag-scan-stack/wireguard/server/wg_confs/wg0.conf"

    peer_block = f"""
[Peer]
# {name} - Added by node-manager API
PublicKey = {public_key}
AllowedIPs = {allowed_ip}/32
PersistentKeepalive = 25
"""

    with open(config_path, "a") as f:
        f.write(peer_block)

    # Note: WireGuard server reload requires docker exec which isn't available in container
    # The server will need to be manually reloaded or the server should watch for config changes

def _remove_peer_from_server(public_key: str):
    """Remove peer from WireGuard server configuration."""
    config_path = "/opt/rag-scan-stack/wireguard/server/wg_confs/wg0.conf"

    try:
        if not os.path.exists(config_path):
            return  # Config file doesn't exist yet

        with open(config_path, "r") as f:
            content = f.read()

        # Split content by [Peer] sections
        sections = content.split("[Peer]")

        # Keep the first section (usually [Interface])
        new_content = sections[0]

        # Process each peer section
        for section in sections[1:]:
            # Check if this section contains our public key
            if f"PublicKey = {public_key}" not in section:
                # Keep this peer section
                new_content += "[Peer]" + section

        with open(config_path, "w") as f:
            f.write(new_content)

        # Note: Server reload requires docker exec which isn't available in container
        log.info(f"Removed peer {public_key} from WireGuard configuration")

    except Exception as e:
        log.warning(f"Failed to remove peer {public_key}: {e}")

def _get_peer_status(public_key: str):
    """Get live status for a WireGuard peer from the WireGuard server."""
    try:
        # Try to get real WireGuard status via docker exec to wg-server container
        try:
            # Execute 'wg show' inside the wg-server container to get real status
            result = subprocess.run(
                ["docker", "exec", "wg-server", "wg", "show", "wg0"],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode != 0:
                # Fall back to connectivity test
                log.debug("Could not exec wg show (container may not be running): %s", result.stderr)
                raise Exception("WireGuard container not accessible")

            wg_output = result.stdout

            # Parse WireGuard output for this peer
            peer_data = {
                "last_handshake": None,
                "rx_bytes": 0,
                "tx_bytes": 0,
            }

            # Look for this peer's data in the output
            lines = wg_output.split('\n')
            in_peer_section = False

            for line in lines:
                line = line.strip()

                # Check if this is our peer
                if line.startswith('peer: ') and public_key in line:
                    in_peer_section = True
                    continue
                elif line.startswith('peer: ') and public_key not in line:
                    in_peer_section = False
                    continue

                if in_peer_section:
                    if 'latest handshake:' in line:
                        # Parse handshake time - format: "latest handshake: 1 minute, 23 seconds ago"
                        handshake_part = line.split('latest handshake:')[1].strip()
                        if handshake_part and handshake_part != '(never)':
                            # Convert relative time to ISO format
                            from datetime import datetime, timezone, timedelta

                            # Simple parsing - if it says "X minutes ago" or similar
                            if 'minute' in handshake_part or 'second' in handshake_part:
                                # Recent handshake - use current time minus estimated offset
                                if 'minute' in handshake_part:
                                    try:
                                        mins = int(handshake_part.split()[0])
                                        handshake_time = datetime.now(timezone.utc) - timedelta(minutes=mins)
                                    except:
                                        handshake_time = datetime.now(timezone.utc) - timedelta(minutes=1)
                                else:
                                    handshake_time = datetime.now(timezone.utc) - timedelta(seconds=30)

                                peer_data["last_handshake"] = handshake_time.isoformat()

                    elif 'transfer:' in line:
                        # Parse transfer data - format: "transfer: 1.23 KiB received, 4.56 KiB sent"
                        transfer_part = line.split('transfer:')[1].strip()
                        parts = transfer_part.split(',')
                        if len(parts) >= 2:
                            try:
                                # Parse received
                                rx_part = parts[0].strip()
                                if 'received' in rx_part:
                                    rx_value = rx_part.split()[0]
                                    rx_unit = rx_part.split()[1]
                                    peer_data["rx_bytes"] = _convert_bytes(rx_value, rx_unit)

                                # Parse sent
                                tx_part = parts[1].strip()
                                if 'sent' in tx_part:
                                    tx_value = tx_part.split()[0]
                                    tx_unit = tx_part.split()[1]
                                    peer_data["tx_bytes"] = _convert_bytes(tx_value, tx_unit)
                            except Exception as e:
                                log.debug("Failed to parse transfer data: %s", e)

            log.debug("Real WireGuard status for %s: %s", public_key[:8], peer_data)
            return peer_data

        except Exception as e:
            log.debug("Could not get real WireGuard status: %s, falling back to basic check", e)

            # Fall back to basic connectivity test
            try:
                result = subprocess.run(
                    ["nc", "-z", "wg-server", "51820"],
                    capture_output=True, text=True, timeout=3
                )
                server_reachable = result.returncode == 0
            except Exception:
                server_reachable = False

            return {
                "last_handshake": None,
                "rx_bytes": 0,
                "tx_bytes": 0,
            }

    except Exception as e:
        log.error("Error getting peer status for %s: %s", public_key[:8], e)
        return {"last_handshake": None, "rx_bytes": 0, "tx_bytes": 0}

def _convert_bytes(value_str: str, unit_str: str) -> int:
    """Convert WireGuard transfer values to bytes."""
    try:
        value = float(value_str)
        unit = unit_str.upper()

        if 'KIB' in unit or 'KB' in unit:
            return int(value * 1024)
        elif 'MIB' in unit or 'MB' in unit:
            return int(value * 1024 * 1024)
        elif 'GIB' in unit or 'GB' in unit:
            return int(value * 1024 * 1024 * 1024)
        elif 'B' in unit:
            return int(value)
        else:
            return int(value)
    except:
        return 0

@app.post("/api/wg/peers")
async def create_wg_peer(request: CreateWGPeerRequest):
    """Generate a new WireGuard peer configuration."""
    try:
        # Verify the node exists
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM remote_nodes WHERE id = %s", (request.node_id,))
        node = cur.fetchone()
        if not node:
            cur.close()
            conn.close()
            raise HTTPException(404, f"Node {request.node_id} not found")

        # Generate keypair
        private_key, public_key = _generate_wg_keypair()

        # Get next available IP
        assigned_ip = _get_next_wg_ip()

        # Get server details
        server_public_key = _get_server_public_key()
        server_url = request.endpoint or os.getenv("WG_SERVERURL", "auto")
        server_port = os.getenv("WG_LISTEN_PORT", "51820")

        # Store WireGuard config but keep tunnel_method as 'ssh' until verified
        cur.execute("""
            UPDATE remote_nodes
            SET wg_public_key = %s,
                wg_assigned_ip = %s,
                updated_at = NOW()
            WHERE id = %s
        """, (public_key, assigned_ip, request.node_id))

        conn.commit()
        cur.close()
        conn.close()

        # Add to server configuration
        _add_peer_to_server(public_key, assigned_ip, request.name)

        # Generate client configuration
        client_config = f"""[Interface]
PrivateKey = {private_key}
Address = {assigned_ip}/24
DNS = 10.66.0.1

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_url}:{server_port}
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
"""

        # Auto-install WireGuard client on the remote node
        installation_status = "pending"
        installation_logs = []

        if request.auto_install:
            try:
                installation_logs, success = await _auto_install_wireguard(request.node_id, client_config, assigned_ip)
                if success:
                    # Only switch to WireGuard after successful verification
                    cur2 = conn.cursor() if conn.closed == 0 else _get_conn().cursor()
                    cur2.execute("""
                        UPDATE remote_nodes
                        SET tunnel_method = 'wireguard'
                        WHERE id = %s
                    """, (request.node_id,))
                    if conn.closed == 0:
                        conn.commit()
                        cur2.close()
                    else:
                        conn2 = _get_conn()
                        conn2.commit()
                        cur2.close()
                        conn2.close()

                    # Emit webhook for successful WireGuard peer creation
                    _emit_wireguard_event("wireguard_peer_created", request.node_id, {
                        "node_name": request.name,
                        "assigned_ip": assigned_ip,
                        "tunnel_method": "wireguard",
                        "operation": "peer_creation",
                        "auto_install": True
                    })

                    installation_status = "success"
                    log.info("Successfully auto-installed WireGuard on node %s", request.node_id)
                else:
                    installation_status = "failed"
                    log.warning("WireGuard installation failed verification on node %s", request.node_id)
            except Exception as e:
                installation_status = "failed"
                installation_logs.append(f"ERROR: {str(e)}")
                log.error("Failed to auto-install WireGuard on node %s: %s", request.node_id, e)

        return WireGuardConfig(
            name=request.name,
            node_id=request.node_id,
            client_config=client_config,
            installation_status=installation_status,
            installation_logs=installation_logs
        )

    except Exception as e:
        raise HTTPException(500, f"Failed to create WireGuard peer: {e}")

def _sync_wg_server_to_database():
    """Synchronize WireGuard server configuration with database.

    This fixes public key mismatches and ensures database reflects actual server state.
    Should be called during startup and periodically.
    """
    try:
        # Get WireGuard server configuration
        result = subprocess.run(
            ["docker", "exec", "wg-server", "wg", "show", "wg0", "dump"],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            log.warning("Could not get WireGuard server configuration: %s", result.stderr)
            return

        # Parse server peers
        server_peers = {}
        lines = result.stdout.strip().split('\n')

        for line in lines[1:]:  # Skip interface line
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                public_key = parts[0]
                allowed_ips = parts[3] if len(parts) > 3 else ""

                # Extract IP from allowed_ips (e.g., "10.66.0.3/32" -> "10.66.0.3")
                if allowed_ips and '/' in allowed_ips:
                    peer_ip = allowed_ips.split('/')[0]
                    server_peers[peer_ip] = public_key

        # Update database with correct public keys
        conn = _get_conn()
        cur = conn.cursor()

        # Get existing peers with IP assignments
        cur.execute("""
            SELECT id, name, wg_assigned_ip, wg_public_key
            FROM remote_nodes
            WHERE tunnel_method = 'wireguard' AND wg_assigned_ip IS NOT NULL
        """)

        db_peers = cur.fetchall()
        updates = 0

        for peer_id, name, assigned_ip, current_key in db_peers:
            if assigned_ip in server_peers:
                correct_key = server_peers[assigned_ip]
                if current_key != correct_key:
                    log.info(f"Updating WireGuard key for {name}: {current_key[:8]}... -> {correct_key[:8]}...")
                    cur.execute("""
                        UPDATE remote_nodes
                        SET wg_public_key = %s, updated_at = now()
                        WHERE id = %s
                    """, (correct_key, peer_id))
                    updates += 1

        if updates > 0:
            conn.commit()
            log.info(f"Updated {updates} WireGuard public keys to match server configuration")
        else:
            log.debug("All WireGuard public keys are synchronized")

        cur.close()
        conn.close()

    except Exception as e:
        log.warning(f"Failed to sync WireGuard server to database: {e}")

@app.post("/api/wg/sync-server")
async def sync_wg_server():
    """Manually sync WireGuard server configuration with database.

    This endpoint can be called to fix public key mismatches and should be
    part of deployment health checks.
    """
    try:
        _sync_wg_server_to_database()
        return {"ok": True, "message": "WireGuard server configuration synced with database"}
    except Exception as e:
        log.error(f"Manual WireGuard sync failed: {e}")
        raise HTTPException(500, f"Failed to sync WireGuard configuration: {e}")

def _get_wg_server_status():
    """Get WireGuard server status with peer handshakes."""
    # For now, return empty dict since docker exec is not available
    # Real handshake data requires accessing WireGuard server directly
    # TODO: Implement via shared volume or API endpoint when available
    log.debug("WireGuard server status query disabled - docker exec not available")
    return {}

@app.get("/api/wg/peers")
async def list_wg_peers():
    """List WireGuard peers from database and server status."""
    try:
        # Get real WireGuard server status
        wg_server_status = _get_wg_server_status()

        # Get database info for peers
        conn = _get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT id, name, wg_public_key, wg_assigned_ip, status, tunnel_method, metadata, created_at, installation_status, installation_logs
            FROM remote_nodes
            WHERE wg_public_key IS NOT NULL
        """)

        peers = []
        for row in cur.fetchall():
            # Using named field access for stability and maintainability
            peer = {
                "id": row["id"],
                "name": row["name"],
                "public_key": row["wg_public_key"],
                "assigned_ip": row["wg_assigned_ip"],
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                # Use actual database status instead of hardcoded values
                "status": row["status"] if row["status"] else "offline",
                # Use consistent status field
                "install_status": row["installation_status"] if row["installation_status"] else "not_attempted",
                "installation_logs": row["installation_logs"] if row["installation_logs"] else [],
            }

            # Use actual database status and metadata for accurate representation
            meta = row["metadata"] if row["metadata"] else {}
            if isinstance(meta, dict) and "install_status" in meta:
                # Use install_status from metadata if available
                peer["install_status"] = meta["install_status"]

            peers.append(peer)

        cur.close()
        conn.close()
        return {"peers": peers}

    except Exception as e:
        raise HTTPException(500, f"Failed to list peers: {e}")

@app.post("/api/wg/peers/{peer_id}/client/status")
async def get_wg_client_status(peer_id: str):
    """Check WireGuard client status on remote node."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT metadata FROM remote_nodes WHERE id = %s", (peer_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    meta = row[0]
    cur.close()
    conn.close()

    # Check WireGuard client status via SSH
    status_cmd = """
    echo "=== WireGuard Interface Status ==="
    wg show 2>/dev/null || echo "WireGuard not active"
    echo
    echo "=== systemd Service Status ==="
    systemctl is-active wg-quick@wg0 2>/dev/null || echo "Service not running"
    echo
    echo "=== Configuration File ==="
    if [ -f /etc/wireguard/wg0.conf ]; then
        echo "✓ Config exists"
        ls -la /etc/wireguard/wg0.conf
    else
        echo "✗ Config missing"
    fi
    echo
    echo "=== Interface Status ==="
    ip addr show wg0 2>/dev/null || echo "Interface down"
    """

    try:
        result = await ssh_manager.exec_command(
            node_id=peer_id,
            host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            command=status_cmd,
            timeout=30
        )

        # Parse WireGuard status and update database
        status_output = result.get("stdout", "")
        is_active = False
        install_status = "not_attempted"

        try:
            if "✓ Config exists" in status_output:
                install_status = "installed"

            # Check if WireGuard interface is active (has IP address)
            if "inet " in status_output and "scope global wg0" in status_output:
                is_active = True
                install_status = "active"

            # Update database with status
            conn = _get_conn()
            cur = conn.cursor()

            # Update tunnel method and status
            cur.execute("""
                UPDATE remote_nodes
                SET tunnel_method = 'wireguard',
                    status = %s,
                    updated_at = now()
                WHERE id = %s
            """, ("online" if is_active else "offline", peer_id))

            # Update install status in metadata if it exists
            cur.execute("""
                UPDATE remote_nodes
                SET metadata = jsonb_set(
                    COALESCE(metadata, '{}'::jsonb),
                    '{install_status}',
                    %s::jsonb
                )
                WHERE id = %s
            """, (f'"{install_status}"', peer_id))

            conn.commit()
            cur.close()
            conn.close()

        except Exception as e:
            log.warning(f"Failed to update WireGuard peer status in database: {e}")

        return {
            "ok": result.get("ok", False),
            "status_output": status_output,
            "error": result.get("stderr", ""),
            "exit_code": result.get("exit_code", 1)
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "status_output": "", "exit_code": 1}

@app.post("/api/wg/peers/{peer_id}/client/start")
async def start_wg_client(peer_id: str):
    """Start WireGuard client on remote node."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT metadata FROM remote_nodes WHERE id = %s", (peer_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    meta = row[0]
    cur.close()
    conn.close()

    # Start WireGuard client
    start_cmd = """
    echo "Starting WireGuard client..."
    if [ ! -f /etc/wireguard/wg0.conf ]; then
        echo "ERROR: Configuration file missing"
        exit 1
    fi

    # Start the interface
    wg-quick up wg0 2>&1 || echo "Interface may already be up"

    # Enable auto-start
    systemctl enable wg-quick@wg0 2>&1 || echo "Failed to enable service"

    echo "Checking status..."
    sleep 2
    wg show 2>&1 || echo "WireGuard not responding"
    """

    try:
        result = await ssh_manager.exec_command(
            node_id=peer_id,
            host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            command=start_cmd,
            timeout=30
        )

        # Update database status if successful
        if result.get("ok", False):
            try:
                conn = _get_conn()
                cur = conn.cursor()
                cur.execute("SELECT name FROM remote_nodes WHERE id = %s", (peer_id,))
                node_name = cur.fetchone()[0] if cur.rowcount > 0 else "unknown"

                cur.execute("""
                    UPDATE remote_nodes
                    SET tunnel_method = 'wireguard',
                        status = 'online',
                        metadata = jsonb_set(
                            COALESCE(metadata, '{}'::jsonb),
                            '{install_status}',
                            '"active"'::jsonb
                        ),
                        updated_at = now()
                    WHERE id = %s
                """, (peer_id,))
                conn.commit()
                cur.close()
                conn.close()

                # Emit webhook for successful WireGuard start
                _emit_wireguard_event("wireguard_client_started", peer_id, {
                    "node_name": node_name,
                    "tunnel_method": "wireguard",
                    "status": "online",
                    "operation": "start"
                })

            except Exception as e:
                log.warning(f"Failed to update start status in database: {e}")
        else:
            # Emit webhook for failed WireGuard start
            _emit_wireguard_event("wireguard_client_start_failed", peer_id, {
                "operation": "start",
                "error": result.get("stderr", str(result.get("error", "unknown")))
            })

        return {
            "ok": result.get("ok", False),
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "exit_code": result.get("exit_code", 1)
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "output": "", "exit_code": 1}

@app.post("/api/wg/peers/{peer_id}/client/stop")
async def stop_wg_client(peer_id: str):
    """Stop WireGuard client on remote node."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT metadata FROM remote_nodes WHERE id = %s", (peer_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    meta = row[0]
    cur.close()
    conn.close()

    # Stop WireGuard client
    stop_cmd = """
    echo "Stopping WireGuard client..."
    wg-quick down wg0 2>&1 || echo "Interface may already be down"
    systemctl disable wg-quick@wg0 2>&1 || echo "Service was not enabled"
    echo "WireGuard client stopped"
    """

    try:
        result = await ssh_manager.exec_command(
            node_id=peer_id,
            host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            command=stop_cmd,
            timeout=30
        )

        # Get node name for webhook
        try:
            conn = _get_conn()
            cur = conn.cursor()
            cur.execute("SELECT name FROM remote_nodes WHERE id = %s", (peer_id,))
            node_name = cur.fetchone()[0] if cur.rowcount > 0 else "unknown"
            cur.close()
            conn.close()
        except Exception:
            node_name = "unknown"

        # Emit webhook event
        if result.get("ok", False):
            _emit_wireguard_event("wireguard_client_stopped", peer_id, {
                "node_name": node_name,
                "operation": "stop",
                "status": "offline"
            })
        else:
            _emit_wireguard_event("wireguard_client_stop_failed", peer_id, {
                "node_name": node_name,
                "operation": "stop",
                "error": result.get("stderr", str(result.get("error", "unknown")))
            })

        return {
            "ok": result.get("ok", False),
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "exit_code": result.get("exit_code", 1)
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "output": "", "exit_code": 1}

@app.post("/api/wg/peers/{peer_id}/client/restart")
async def restart_wg_client(peer_id: str):
    """Restart WireGuard client on remote node."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT metadata FROM remote_nodes WHERE id = %s", (peer_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    meta = row[0]
    cur.close()
    conn.close()

    # Restart WireGuard client
    restart_cmd = """
    echo "Restarting WireGuard client..."
    wg-quick down wg0 2>/dev/null || echo "Interface was down"
    sleep 1
    wg-quick up wg0 2>&1
    systemctl enable wg-quick@wg0 2>&1 || echo "Failed to enable service"
    echo "Checking status..."
    sleep 2
    wg show 2>&1 || echo "WireGuard not responding"
    """

    try:
        result = await ssh_manager.exec_command(
            node_id=peer_id,
            host=meta["host"],
            user=meta.get("user", "root"),
            ssh_port=meta.get("ssh_port", 22),
            key_file=meta.get("key_file", "id_rsa"),
            command=restart_cmd,
            timeout=30
        )

        # Get node name for webhook
        try:
            conn = _get_conn()
            cur = conn.cursor()
            cur.execute("SELECT name FROM remote_nodes WHERE id = %s", (peer_id,))
            node_name = cur.fetchone()[0] if cur.rowcount > 0 else "unknown"
            cur.close()
            conn.close()
        except Exception:
            node_name = "unknown"

        # Emit webhook event
        if result.get("ok", False):
            _emit_wireguard_event("wireguard_client_restarted", peer_id, {
                "node_name": node_name,
                "operation": "restart",
                "status": "restarted"
            })
        else:
            _emit_wireguard_event("wireguard_client_restart_failed", peer_id, {
                "node_name": node_name,
                "operation": "restart",
                "error": result.get("stderr", str(result.get("error", "unknown")))
            })

        return {
            "ok": result.get("ok", False),
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "exit_code": result.get("exit_code", 1)
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "output": "", "exit_code": 1}

@app.delete("/api/wg/peers/{peer_id}")
async def delete_wg_peer(peer_id: str):
    """Remove a WireGuard peer."""
    conn = _get_conn()
    cur = conn.cursor()

    # Get peer details
    cur.execute("SELECT wg_public_key FROM remote_nodes WHERE id = %s", (peer_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Peer not found")

    public_key = row[0]
    if not public_key:
        cur.close()
        conn.close()
        raise HTTPException(400, "Node does not have WireGuard configuration")

    try:
        # Remove from server configuration
        _remove_peer_from_server(public_key)

        # Clear WireGuard fields in database
        cur.execute("""
            UPDATE remote_nodes
            SET tunnel_method = 'ssh',
                wg_public_key = NULL,
                wg_assigned_ip = NULL,
                installation_status = NULL,
                installation_logs = NULL,
                updated_at = NOW()
            WHERE id = %s
        """, (peer_id,))
        conn.commit()

        cur.close()
        conn.close()
        return {"ok": True, "peer_id": peer_id}

    except Exception as e:
        cur.close()
        conn.close()
        raise HTTPException(500, f"Failed to delete peer: {e}")


@app.get("/api/wg/peers/{peer_id}/config")
async def get_wg_peer_config(peer_id: str):
    """Get WireGuard peer configuration."""
    conn = _get_conn()
    cur = conn.cursor()

    # Get peer details
    cur.execute("""
        SELECT name, wg_public_key, wg_assigned_ip
        FROM remote_nodes
        WHERE id = %s
    """, (peer_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Peer not found")

    name, public_key, assigned_ip = row
    if not public_key:
        cur.close()
        conn.close()
        raise HTTPException(400, "Node does not have WireGuard configuration")

    cur.close()
    conn.close()

    try:
        # Regenerate the client configuration
        server_public_key = _get_server_public_key()
        server_url = os.getenv("WG_SERVERURL", "auto")
        server_port = os.getenv("WG_LISTEN_PORT", "51820")

        client_config = f"""[Interface]
# Note: PrivateKey not stored - client must use original
Address = {assigned_ip}/24
DNS = 10.66.0.1

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_url}:{server_port}
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
"""

        return WireGuardConfig(
            name=name,
            node_id=peer_id,
            client_config=client_config
        )

    except Exception as e:
        raise HTTPException(500, f"Failed to get peer config: {e}")


# ---------------------------------------------------------------------------
# WireGuard Tunnel Management
# ---------------------------------------------------------------------------
@app.post("/wg/{node_id}/start")
async def start_wg_tunnel(node_id: str):
    """Start a WireGuard tunnel for a node."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_type, tunnel_method, status, name, wg_assigned_ip, wg_public_key, proxy_port FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    ntype, tunnel_method, status, name, wg_assigned_ip, wg_public_key, proxy_port = row
    cur.close()
    conn.close()

    if tunnel_method != "wireguard":
        raise HTTPException(400, "Node is not configured for WireGuard")

    if not wg_assigned_ip or not wg_public_key:
        raise HTTPException(400, "Node missing WireGuard configuration")

    if status == "online":
        # Already online — check if process is alive
        if _check_wg_tunnel_process(node_id):
            return {"ok": True, "status": "online", "message": "Already connected"}

    # Re-allocate the same port or get a new one
    existing_port = allocator.get_node_port(node_id)
    if existing_port:
        socks_port = existing_port
    else:
        try:
            socks_port = allocator.allocate("ssh", node_id)  # Use SSH port range for now
        except RuntimeError as e:
            raise HTTPException(503, str(e))
        # Update port in DB if it changed
        if socks_port != proxy_port:
            conn = _get_conn()
            cur = conn.cursor()
            cur.execute(
                "UPDATE remote_nodes SET proxy_port = %s WHERE id = %s",
                (socks_port, node_id),
            )
            conn.commit()
            cur.close()
            conn.close()

    # Update status to connecting
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE remote_nodes SET status = 'connecting', last_seen = %s WHERE id = %s",
        (datetime.now(timezone.utc), node_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    # Start the WireGuard tunnel
    try:
        # Create socat process to forward local SOCKS port to remote microsocks
        # socat TCP-LISTEN:10120,fork TCP:10.66.0.3:1080
        socat_cmd = [
            "socat",
            f"TCP-LISTEN:{socks_port},fork",
            f"TCP:{wg_assigned_ip}:1080"
        ]

        log.info("Starting WireGuard tunnel %s: %s", name, " ".join(socat_cmd))

        proc = await asyncio.create_subprocess_exec(
            *socat_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Store process reference for tracking
        wg_processes[node_id] = proc

        # Give it a moment to start
        await asyncio.sleep(1)

        # Check if process is still running
        if proc.returncode is None:
            # Success
            new_status = "online"
            conn = _get_conn()
            cur = conn.cursor()
            cur.execute(
                "UPDATE remote_nodes SET status = %s, last_seen = %s WHERE id = %s",
                (new_status, datetime.now(timezone.utc), node_id),
            )
            conn.commit()
            cur.close()
            conn.close()

            log.info("WireGuard tunnel %s started -> %s:1080 (SOCKS :%d)", name, wg_assigned_ip, socks_port)
            _log_tunnel_event(node_id, "connected", f"WireGuard tunnel started to {wg_assigned_ip}:1080 on port {socks_port}")
            return {"ok": True, "status": "online", "proxy_port": socks_port}
        else:
            # Process failed
            stdout, stderr = await proc.communicate()
            error_msg = f"socat failed: {stderr.decode().strip()}"

            # Update status to error
            conn = _get_conn()
            cur = conn.cursor()
            cur.execute(
                "UPDATE remote_nodes SET status = 'error', last_seen = %s WHERE id = %s",
                (datetime.now(timezone.utc), node_id),
            )
            conn.commit()
            cur.close()
            conn.close()

            allocator.release(socks_port)
            _log_tunnel_event(node_id, "error", error_msg)
            raise HTTPException(500, {"error": error_msg})

    except Exception as e:
        # Update status to error
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE remote_nodes SET status = 'error', last_seen = %s WHERE id = %s",
            (datetime.now(timezone.utc), node_id),
        )
        conn.commit()
        cur.close()
        conn.close()

        allocator.release(socks_port)
        _log_tunnel_event(node_id, "error", f"WireGuard tunnel startup failed: {e}")
        raise HTTPException(500, f"Failed to start WireGuard tunnel: {e}")


@app.post("/wg/{node_id}/stop")
async def stop_wg_tunnel(node_id: str):
    """Stop a WireGuard tunnel for a node."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT tunnel_method, status, name, proxy_port FROM remote_nodes WHERE id = %s",
        (node_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(404, "Node not found")

    tunnel_method, status, name, proxy_port = row
    cur.close()
    conn.close()

    if tunnel_method != "wireguard":
        raise HTTPException(400, "Node is not configured for WireGuard")

    # Stop the socat process
    if node_id in wg_processes:
        proc = wg_processes[node_id]
        try:
            proc.terminate()
            await asyncio.sleep(1)
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            del wg_processes[node_id]
            log.info("Stopped WireGuard tunnel process for node %s", name)
        except Exception as e:
            log.warning("Error stopping WireGuard tunnel for %s: %s", name, e)

    # Release the port
    if proxy_port:
        allocator.release(proxy_port)

    # Update status to offline
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE remote_nodes SET status = 'offline', last_seen = %s WHERE id = %s",
        (datetime.now(timezone.utc), node_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    _log_tunnel_event(node_id, "disconnected", "WireGuard tunnel stopped manually")
    log.info("WireGuard tunnel %s stopped", name)
    return {"ok": True, "status": "offline", "message": "Tunnel stopped"}
