import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
import httpx
from fastapi import APIRouter, Query
from config import get_settings
from utils import safe_json

TCP_SERVICES = {
    "ssh_tunnel": ("ssh_tunnel_host", "ssh_tunnel_port"),
}

# Docker container name checks (healthy if container exists and is running)
CONTAINER_CHECKS = {
    "wireguard": "rag-wireguard",
    "db_proxy": "rag-db-proxy",
    "db_tunnel": "rag-db-tunnel",
}

# Optional services — not required for core functionality.
# Their status is reported but doesn't affect the overall health verdict.
OPTIONAL_SERVICES = {
    "ollama", "scan_recommender", "sliver_server", "chisel_server",
    "ssh_tunnel", "wireguard", "db_proxy", "db_tunnel",
}

log = logging.getLogger("health")
router = APIRouter()

SERVICE_MAP = {
    "rag_api": ("rag_api_url", "/health"),
    "nmap_scanner": ("nmap_scanner_url", "/health"),
    "web_scanner": ("web_scanner_url", "/health"),
    "nuclei": ("nuclei_url", "/health"),
    "pd_runner": ("pd_runner_url", "/health"),
    "osint_runner": ("osint_runner_url", "/health"),
    "exploit_runner": ("exploit_runner_url", "/health"),
    "autogen": ("autogen_url", "/health"),
    "ollama": ("ollama_url", "/api/tags"),
    "scan_recommender": ("scan_recommender_url", "/health"),
    "brutus_runner": ("brutus_runner_url", "/health"),
    "playwright_scanner": ("playwright_scanner_url", "/health"),
    "tunnel_manager": ("tunnel_manager_url", "/health"),
    "chisel_server": ("chisel_server_url", "/"),
    "sliver_server": ("sliver_server_url", "/"),
}


_health_cache: dict = {"data": None, "ts": 0}
_HEALTH_CACHE_TTL = 10  # seconds


@router.get("/api/health")
async def health(bust: bool = False):
    import time as _time
    # Return cached result if fresh (avoids 20+ HTTP calls every request)
    now = _time.time()
    if not bust and _health_cache["data"] and (now - _health_cache["ts"]) < _HEALTH_CACHE_TTL:
        return _health_cache["data"]

    settings = get_settings()
    results = {}

    # Services that are healthy if they respond at all (no proper /health endpoint)
    RESPOND_ONLY = {"chisel_server", "sliver_server"}

    async def check(name: str, attr: str, path: str):
        url = getattr(settings, attr) + path
        try:
            async with httpx.AsyncClient(verify=False, timeout=2) as client:
                resp = await client.get(url, headers={"x-api-key": settings.api_key})
                if name in RESPOND_ONLY:
                    results[name] = {"status": "healthy", "code": resp.status_code}
                else:
                    entry = {
                        "status": "healthy" if resp.status_code == 200 else "degraded",
                        "code": resp.status_code,
                    }
                    # Extract version from health response if available
                    if resp.status_code == 200:
                        try:
                            body = resp.json()
                            v = body.get("version") or body.get("build_version")
                            if v:
                                entry["version"] = v
                        except Exception:
                            pass
                    # For rag_api, include exploitdb status
                    if name == "rag_api" and resp.status_code == 200:
                        try:
                            body = resp.json()
                            edb = body.get("exploitdb")
                            if edb:
                                entry["exploitdb"] = edb
                        except Exception:
                            pass
                    # For tunnel_manager, include tunnel health details
                    if name == "tunnel_manager" and resp.status_code == 200:
                        try:
                            body = resp.json()
                            tunnel_errors = body.get("tunnel_errors", [])
                            tunnels = body.get("tunnels", {})
                            if tunnel_errors:
                                entry["tunnel_errors"] = tunnel_errors
                            if tunnels:
                                entry["tunnels"] = tunnels
                                if tunnels.get("error", 0) > 0:
                                    entry["status"] = "degraded"
                        except Exception:
                            pass
                    results[name] = entry
        except Exception as e:
            results[name] = {"status": "unreachable", "error": str(e)}

    async def check_tcp(name: str, host_attr: str, port_attr: str):
        host = getattr(settings, host_attr)
        port = getattr(settings, port_attr)
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2
            )
            writer.close()
            await writer.wait_closed()
            results[name] = {"status": "healthy", "code": 0}
        except Exception as e:
            results[name] = {"status": "unreachable", "error": str(e)}

    async def check_container(name: str, container_name: str):
        """Check if a Docker container is running via the container-logs service."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=2) as client:
                resp = await client.get(
                    f"{settings.container_logs_url}/services/status"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Search all profiles for the container
                    for profile in data.get("profiles", {}).values():
                        for c in profile.get("containers", []):
                            if c.get("name") == container_name:
                                if c.get("running"):
                                    results[name] = {"status": "healthy", "code": 0}
                                else:
                                    results[name] = {"status": "stopped", "code": 0}
                                return
                    results[name] = {"status": "not_running", "error": "container not found"}
                else:
                    results[name] = {"status": "unreachable", "error": "container-logs unavailable"}
        except Exception as e:
            results[name] = {"status": "unreachable", "error": str(e)}

    async def check_local_postgres():
        """Check local rag-postgres container status via fast single-container endpoint."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=3) as client:
                resp = await client.get(f"{settings.container_logs_url}/container/rag-postgres/status")
                if resp.status_code == 200:
                    c = resp.json()
                    running = c.get("running", False)
                    health = c.get("health", "")
                    if running:
                        results["postgres"] = {
                            "status": "healthy" if health in ("healthy", "") else "degraded",
                            "code": 0, "container": "rag-postgres", "health": health,
                        }
                    else:
                        results["postgres"] = {
                            "status": "stopped", "code": 0, "container": "rag-postgres",
                        }
                else:
                    results["postgres"] = {"status": "unreachable", "container": "rag-postgres", "error": "container-logs unavailable"}
        except Exception as e:
            results["postgres"] = {"status": "unreachable", "container": "rag-postgres", "error": f"{type(e).__name__}: {e}"}

    async def check_remote_postgres():
        """Check remote Postgres via a fast DB health query."""
        try:
            # Fast check: ask rag-api's /health/quick (already connects to DB)
            async with httpx.AsyncClient(verify=False, timeout=3) as client:
                resp = await client.get(
                    f"{settings.rag_api_url}/health/db-pool",
                    headers={"x-api-key": settings.api_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    db_status = data.get("status", "unknown")
                    results["remote_postgres"] = {
                        "status": "healthy" if db_status in ("healthy", "degraded") else "degraded",
                        "code": 200,
                        "connections": data.get("total_connections", 0),
                        "blocked_locks": data.get("blocked_locks", 0),
                    }
                else:
                    results["remote_postgres"] = {"status": "degraded", "code": resp.status_code}
        except Exception as e:
            results["remote_postgres"] = {"status": "unreachable", "error": str(e)}

    await asyncio.gather(
        *[check(name, attr, path) for name, (attr, path) in SERVICE_MAP.items()],
        *[check_tcp(name, h, p) for name, (h, p) in TCP_SERVICES.items()],
        *[check_container(name, cn) for name, cn in CONTAINER_CHECKS.items()],
        check_local_postgres(),
        check_remote_postgres(),
    )

    # Detect DB proxy type (direct SSL vs SSH tunnel) from container-logs config
    db_proxy_type = "ssh_tunnel"  # default
    try:
        async with httpx.AsyncClient(verify=False, timeout=2) as client:
            db_cfg = await client.get(f"{settings.container_logs_url}/db/config")
            if db_cfg.status_code == 200:
                cfg_mode = db_cfg.json().get("mode", "local")
                if cfg_mode == "remote_direct":
                    db_proxy_type = "direct_ssl"
    except Exception:
        pass

    # Tag the db_tunnel entry with proxy type
    if "db_tunnel" in results:
        results["db_tunnel"]["proxy_type"] = db_proxy_type

    # If remote postgres is healthy, the proxy/tunnel must be working — override status
    remote_pg_up = results.get("remote_postgres", {}).get("status") == "healthy"
    if remote_pg_up:
        label = "Direct SSL proxy" if db_proxy_type == "direct_ssl" else "SSH tunnel"
        if results.get("db_tunnel", {}).get("status") != "healthy":
            results["db_tunnel"] = {"status": "healthy", "code": 0, "optional": True,
                                    "proxy_type": db_proxy_type,
                                    "note": f"Remote DB reachable — {label} working"}

    # Dual-postgres warning: both local and remote running simultaneously
    warnings = []
    local_pg_up = results.get("postgres", {}).get("status") in ("healthy",)
    if local_pg_up and remote_pg_up:
        warnings.append({
            "type": "dual_postgres",
            "message": "Both local and remote PostgreSQL are running. Services may connect to the wrong database. Stop one to avoid conflicts.",
            "severity": "warning",
        })
        results["postgres"]["warning"] = "Remote postgres also running"
        results["remote_postgres"]["warning"] = "Local postgres also running"

    # Core services must be healthy; optional services don't affect overall status
    core_results = {k: v for k, v in results.items() if k not in OPTIONAL_SERVICES}
    optional_results = {k: v for k, v in results.items() if k in OPTIONAL_SERVICES}
    core_healthy = all(r["status"] == "healthy" for r in core_results.values())
    optional_unhealthy = [k for k, v in optional_results.items() if v.get("status") != "healthy"]

    # Mark optional services in the response
    for name in optional_results:
        results[name]["optional"] = True

    response = {
        "status": "healthy" if core_healthy else "degraded",
        "services": results,
        "warnings": warnings,
        "core_healthy": len(core_results) - sum(1 for r in core_results.values() if r["status"] != "healthy"),
        "core_total": len(core_results),
        "optional_down": optional_unhealthy,
    }
    _health_cache["data"] = response
    _health_cache["ts"] = now
    return response


# ── DB connection pool status ──

@router.get("/api/db-pool")
async def db_pool_status():
    """Proxy to rag-api /health/db-pool — live Postgres connection pool stats."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.get(
                f"{s.rag_api_url}/health/db-pool",
                headers={"x-api-key": s.api_key},
            )
            return safe_json(resp)
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── Service profile control (proxied to container-logs) ──

@router.get("/api/llm/metrics")
async def llm_metrics(limit: int = 50, caller: str = None, model: str = None):
    s = get_settings()
    params = {"limit": limit}
    if caller: params["caller"] = caller
    if model: params["model"] = model
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/metrics/models/requests",
                           params=params, headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.get("/api/llm/summary")
async def llm_summary(days: int = 7):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.rag_api_url}/metrics/llm/summary",
                           params={"days": days}, headers={"x-api-key": s.api_key})
        return safe_json(resp)


@router.get("/api/services/status")
async def services_status():
    """Get running status of all managed containers grouped by profile."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            resp = await client.get(f"{settings.container_logs_url}/services/status")
            return safe_json(resp)
    except Exception as e:
        return {"profiles": {}, "error": str(e)}


@router.post("/api/services/{action}/{profile}")
async def control_profile(action: str, profile: str):
    """Start or stop all containers in a profile."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            resp = await client.post(f"{settings.container_logs_url}/services/{action}/{profile}")
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/api/services/{action}/container/{container_name}")
async def control_container(action: str, container_name: str):
    """Start or stop a single container."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            resp = await client.post(
                f"{settings.container_logs_url}/services/{action}/container/{container_name}"
            )
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/api/diagnostics/container-logs/{container_name}")
async def container_logs(container_name: str, tail: int = 100, since_minutes: int = 30):
    """Get recent logs for a specific container."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.get(
                f"{settings.container_logs_url}/logs/{container_name}",
                params={"tail": tail, "since": f"{since_minutes}m"},
                timeout=10,
            )
            if resp.status_code == 200:
                return safe_json(resp)
            # Fallback: try docker-style endpoint
            resp2 = await client.get(
                f"{settings.container_logs_url}/containers/{container_name}/logs",
                params={"tail": tail, "since_minutes": since_minutes},
                timeout=10,
            )
            if resp2.status_code == 200:
                return resp2.json()
            return {"logs": [], "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"logs": [], "error": str(e)}


@router.get("/api/diagnostics/ollama")
async def ollama_diagnostics():
    """Get Ollama status, loaded models, GPU info, and version."""
    settings = get_settings()
    result = {"status": "unreachable", "models": [], "running": [], "version": None, "gpu": None}
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # Version
            try:
                resp = await client.get(f"{settings.ollama_url}/api/version")
                if resp.status_code == 200:
                    result["version"] = resp.json().get("version")
                    result["status"] = "connected"
            except Exception:
                pass

            # Models list
            try:
                resp = await client.get(f"{settings.ollama_url}/api/tags")
                if resp.status_code == 200:
                    result["models"] = resp.json().get("models", [])
                    result["status"] = "connected"
            except Exception:
                pass

            # Currently running/loaded models
            try:
                resp = await client.get(f"{settings.ollama_url}/api/ps")
                if resp.status_code == 200:
                    result["running"] = resp.json().get("models", [])
            except Exception:
                pass

            # GPU info (from show endpoint of first model)
            if result["models"]:
                try:
                    model_name = result["models"][0].get("name", "")
                    resp = await client.post(f"{settings.ollama_url}/api/show", json={"name": model_name})
                    if resp.status_code == 200:
                        data = resp.json()
                        details = data.get("details", {})
                        result["gpu"] = {
                            "format": details.get("format"),
                            "family": details.get("family"),
                            "parameter_size": details.get("parameter_size"),
                            "quantization_level": details.get("quantization_level"),
                        }
                except Exception:
                    pass
    except Exception as e:
        result["error"] = str(e)
    return result


@router.get("/api/diagnostics/errors")
async def diagnostics_errors(tail: int = 200, since_minutes: int = 30):
    """Scan all container logs for recent errors."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            resp = await client.get(
                f"{settings.container_logs_url}/diagnostics/errors",
                params={"tail": tail, "since_minutes": since_minutes},
                timeout=55,
            )
            resp.raise_for_status()
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "containers": []}


# ── Diagnostic Log Pull ──────────────────────────────────────────────────

# Map scan types to BFF settings attribute names for scanner log resolution
SCAN_TYPE_TO_SETTING = {
    "nmap": "nmap_scanner_url", "masscan": "nmap_scanner_url",
    "full_scan": "nmap_scanner_url", "udp": "nmap_scanner_url",
    "smb_vuln": "nmap_scanner_url", "credential_check": "nmap_scanner_url",
    "nuclei": "nuclei_url",
    "web_scan": "web_scanner_url", "web-scan": "web_scanner_url",
    "pipeline-scan": "web_scanner_url", "gobuster": "web_scanner_url",
    "nikto": "web_scanner_url",
    "playwright": "playwright_scanner_url",
    "httpx": "pd_runner_url", "naabu": "pd_runner_url",
    "katana": "pd_runner_url", "tlsx": "pd_runner_url",
    "whatweb": "pd_runner_url", "ffuf": "pd_runner_url",
    "subfinder": "osint_runner_url", "dnsx": "osint_runner_url",
    "passive-recon": "osint_runner_url", "recon-pipeline": "osint_runner_url",
    "whois": "osint_runner_url", "amass": "osint_runner_url",
    "brutus": "brutus_runner_url",
}


@router.get("/api/diagnostics/recent-sessions")
async def diagnostics_recent_sessions(hours: int = Query(8, ge=1, le=72)):
    """List agent sessions from the last N hours for the diagnostic selector."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            resp = await client.get(
                f"{settings.autogen_url}/pentest/sessions",
                headers={"x-api-key": settings.api_key},
            )
            if resp.status_code != 200:
                log.warning(f"diagnostics_recent_sessions: autogen returned {resp.status_code}")
                return {"sessions": [], "error": f"autogen returned {resp.status_code}"}
            data = resp.json()
    except Exception as e:
        log.error(f"diagnostics_recent_sessions failed: {e}")
        return {"sessions": [], "error": str(e)}

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    all_sessions = data.get("sessions") if isinstance(data, dict) else data if isinstance(data, list) else []
    log.info(f"diagnostics_recent_sessions: {len(all_sessions)} total sessions, cutoff={cutoff.isoformat()}, hours={hours}")
    sessions = []
    for s in all_sessions:
        created = s.get("created_at") or s.get("started_at") or ""
        try:
            ts = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
        except (ValueError, AttributeError) as e:
            log.warning(f"diagnostics_recent_sessions: date parse error for session {s.get('session_name')}: {e}")
            pass
        sessions.append({
            "session_id": s.get("session_id") or str(s.get("id", "")),
            "session_name": s.get("session_name", ""),
            "target_description": s.get("target_description", ""),
            "status": s.get("status", ""),
            "created_at": created,
            "end_time": s.get("end_time"),
        })
    sessions.sort(key=lambda x: x["created_at"], reverse=True)
    return {"sessions": sessions}


@router.get("/api/diagnostics/session-bundle")
async def diagnostics_session_bundle(session_id: Optional[str] = None, hours: int = 8):
    """
    Pull a comprehensive diagnostic bundle for an agent session.
    Aggregates session info, scans, messages, logs, health, and watchdog data.
    If session_id is omitted, auto-selects the most recent session.
    """
    settings = get_settings()
    req_headers = {"x-api-key": settings.api_key}

    # Auto-select most recent session if none specified
    if not session_id:
        recent = await diagnostics_recent_sessions(hours=hours)
        if recent.get("sessions"):
            session_id = recent["sessions"][0]["session_id"]
        else:
            return {"error": f"No sessions found in the last {hours} hours"}

    async def _safe_get(client, url, timeout=10, params=None):
        """Fetch with error resilience — never raises, logs errors."""
        try:
            resp = await client.get(url, headers=req_headers, params=params, timeout=timeout)
            if resp.status_code == 200:
                return safe_json(resp)
            log.warning(f"diagnostic bundle: {url} returned {resp.status_code}")
            return {"_error": f"HTTP {resp.status_code}", "_url": url}
        except Exception as e:
            log.error(f"diagnostic bundle fetch failed: {url} — {type(e).__name__}: {e}")
            return {"_error": f"{type(e).__name__}: {e}", "_url": url}

    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        (session_info, scans_info, messages_info,
         autogen_logs, watchdog_info, health_info, webhook_events) = await asyncio.gather(
            _safe_get(client, f"{settings.autogen_url}/pentest/{session_id}"),
            _safe_get(client, f"{settings.autogen_url}/pentest/{session_id}/scans"),
            _safe_get(client, f"{settings.autogen_url}/pentest/{session_id}/messages?limit=500"),
            _safe_get(client, f"{settings.autogen_url}/logs", params={"search": session_id, "limit": 500}),
            _safe_get(client, f"{settings.autogen_url}/pentest/watchdog"),
            _safe_get(client, f"{settings.autogen_url}/health"),
            _safe_get(client, f"{settings.rag_api_url}/webhooks/events", params={"limit": 100}),
        )

        # Fetch scanner-specific logs for each scan job
        scans_list = scans_info.get("scans", []) if not scans_info.get("_error") else []
        scanner_log_tasks = []
        for scan in scans_list:
            scan_type = scan.get("type", "")
            job_id = scan.get("job_id", "")
            setting_attr = SCAN_TYPE_TO_SETTING.get(scan_type)
            if setting_attr and job_id:
                base_url = getattr(settings, setting_attr, "")
                if base_url:
                    scanner_log_tasks.append(
                        (scan["job_id"], _safe_get(client, f"{base_url}/logs", timeout=5,
                                                   params={"job_id": job_id, "limit": 50}))
                    )

        scanner_logs_map = {}
        if scanner_log_tasks:
            log_results = await asyncio.gather(*[t[1] for t in scanner_log_tasks])
            for (jid, _), result in zip(scanner_log_tasks, log_results):
                logs = result.get("logs", []) if not result.get("_error") else []
                scanner_logs_map[jid] = logs

        for scan in scans_list:
            scan["scanner_logs"] = scanner_logs_map.get(scan.get("job_id", ""), [])

    # Compute failure trace
    failure_trace = _compute_failure_trace(session_info, scans_list, autogen_logs, health_info, watchdog_info, wh_events)

    # Compute duration
    duration_seconds = None
    if not session_info.get("_error"):
        created = session_info.get("started_at") or session_info.get("created_at")
        ended = session_info.get("ended_at") or session_info.get("end_time")
        if created and ended:
            try:
                t0 = datetime.fromisoformat(created.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(ended.replace("Z", "+00:00"))
                duration_seconds = round((t1 - t0).total_seconds(), 1)
            except (ValueError, TypeError):
                pass

    # Filter webhook events to session timeframe
    wh_events = []
    if not webhook_events.get("_error"):
        raw_events = webhook_events.get("events", [])
        # If we have session timestamps, filter to relevant timeframe
        session_start = session_info.get("started_at") or session_info.get("created_at") if not session_info.get("_error") else None
        if session_start and raw_events:
            try:
                t0 = datetime.fromisoformat(session_start.replace("Z", "+00:00"))
                for ev in raw_events:
                    ev_time = ev.get("created_at", "")
                    if ev_time:
                        try:
                            t_ev = datetime.fromisoformat(str(ev_time).replace("Z", "+00:00"))
                            if t_ev >= t0:
                                wh_events.append(ev)
                        except (ValueError, TypeError):
                            wh_events.append(ev)
            except (ValueError, TypeError):
                wh_events = raw_events[:50]
        else:
            wh_events = raw_events[:50]

    return {
        "session": {
            **(session_info if not session_info.get("_error") else {}),
            "duration_seconds": duration_seconds,
            "_error": session_info.get("_error"),
        },
        "scans": scans_list,
        "messages": messages_info.get("messages", []) if not messages_info.get("_error") else [],
        "messages_error": messages_info.get("_error"),
        "autogen_logs": autogen_logs.get("logs", []) if not autogen_logs.get("_error") else [],
        "autogen_logs_error": autogen_logs.get("_error"),
        "webhook_events": wh_events,
        "webhook_events_error": webhook_events.get("_error"),
        "watchdog": watchdog_info if not watchdog_info.get("_error") else None,
        "watchdog_error": watchdog_info.get("_error"),
        "service_health": health_info if not health_info.get("_error") else None,
        "service_health_error": health_info.get("_error"),
        "failure_trace": failure_trace,
        "pulled_at": datetime.now(timezone.utc).isoformat(),
    }


def _compute_failure_trace(session, scans, autogen_logs, health, watchdog, webhook_events=None):
    """Analyze the diagnostic data and produce a failure summary with root cause hints."""
    trace = {
        "has_failures": False,
        "session_error": None,
        "failed_scans": [],
        "autogen_errors": [],
        "unhealthy_services": [],
        "stalled": False,
        "root_cause_hint": None,
    }

    if not session.get("_error"):
        status = session.get("status", "")
        if status in ("failed", "error", "stalled"):
            trace["has_failures"] = True
            trace["session_error"] = session.get("error") or session.get("summary") or f"Session status: {status}"
            if status == "stalled":
                trace["stalled"] = True

    for scan in (scans or []):
        if scan.get("status") in ("failed", "error"):
            trace["has_failures"] = True
            error_hint = None
            for log_entry in reversed(scan.get("scanner_logs", [])):
                if isinstance(log_entry, dict) and log_entry.get("level", "").upper() == "ERROR":
                    error_hint = log_entry.get("message", "")[:200]
                    break
            trace["failed_scans"].append({
                "type": scan.get("type", "unknown"),
                "job_id": scan.get("job_id", ""),
                "status": scan.get("status", ""),
                "error_hint": error_hint,
            })

    log_list = autogen_logs.get("logs", []) if isinstance(autogen_logs, dict) else []
    for entry in log_list:
        if isinstance(entry, dict) and entry.get("level", "").upper() in ("ERROR", "CRITICAL"):
            trace["has_failures"] = True
            trace["autogen_errors"].append({
                "timestamp": entry.get("timestamp", ""),
                "message": entry.get("message", "")[:300],
            })

    if health and not health.get("_error"):
        for svc, info in (health.get("services") or health.get("dependencies") or {}).items():
            if isinstance(info, dict) and info.get("status") not in ("healthy", None):
                trace["unhealthy_services"].append(svc)
                trace["has_failures"] = True

    if watchdog and not watchdog.get("_error"):
        for tracked in (watchdog.get("tracked_sessions") or []):
            if tracked.get("status") in ("stalled", "recovering"):
                trace["stalled"] = True
                trace["has_failures"] = True

    hints = []
    if trace["failed_scans"] and trace["unhealthy_services"]:
        failed_types = {s["type"] for s in trace["failed_scans"]}
        for svc in trace["unhealthy_services"]:
            for scan_type, setting in SCAN_TYPE_TO_SETTING.items():
                if scan_type in failed_types and svc in setting:
                    hints.append(f"Scanner service '{svc}' was unhealthy when '{scan_type}' scan failed")
    if trace["autogen_errors"]:
        err_msgs = " | ".join(e["message"][:80] for e in trace["autogen_errors"][:3])
        hints.append(f"Autogen errors: {err_msgs}")
    if trace["stalled"]:
        hints.append("Session stalled — watchdog detected no progress")
    # Check webhook delivery failures
    failed_webhooks = []
    if webhook_events:
        for ev in webhook_events:
            status = ev.get("status", "")
            if status in ("failed", "retrying"):
                failed_webhooks.append({
                    "event_type": ev.get("event_type", "?"),
                    "error": ev.get("error_message", "unknown"),
                    "attempt": ev.get("attempt", 0),
                })
    if failed_webhooks:
        trace["has_failures"] = True
        trace["failed_webhooks"] = failed_webhooks
        hints.append(f"{len(failed_webhooks)} webhook delivery failure(s)")

    if trace["session_error"] and not hints:
        hints.append(f"Session failed: {trace['session_error'][:200]}")
    if not hints and trace["has_failures"]:
        hints.append("Failures detected but no clear infrastructure cause — check agent messages for logic errors")

    trace["root_cause_hint"] = " | ".join(hints) if hints else None
    return trace


# ── System Check (DB schema + connectivity + end-to-end) ─────────────────

CRITICAL_TABLES = [
    "assets", "ports", "scans", "findings", "web_findings", "vulns",
    "scan_recommendations", "agent_sessions", "agent_messages",
    "session_scan_metrics", "llm_request_metrics", "pending_exploits",
    "exploit_results", "recon_findings", "credential_findings",
    "playwright_scans", "playwright_findings", "follow_up_items",
    "engagements", "webhooks", "webhook_events",
]

CRITICAL_VIEWS = ["detected_software"]

CRITICAL_COLUMNS = {
    "assets": ["id", "ip", "hostname", "last_seen", "engagement_id"],
    "ports": ["id", "asset_id", "port", "proto", "service", "product", "version", "banner", "is_open"],
    "vulns": ["id", "asset_id", "script", "output", "severity", "cve", "title"],
    "pending_exploits": ["id", "exploit_title", "source", "match_confidence", "status", "edb_id"],
    "agent_sessions": ["id", "session_name", "status", "target_description", "metadata", "parent_session_id"],
}

# Service → (settings_attr, health_path, expected_protocol)
CONNECTIVITY_CHECKS = {
    "rag_api": ("rag_api_url", "/health"),
    "nmap_scanner": ("nmap_scanner_url", "/health"),
    "web_scanner": ("web_scanner_url", "/health"),
    "nuclei": ("nuclei_url", "/health"),
    "pd_runner": ("pd_runner_url", "/health"),
    "osint_runner": ("osint_runner_url", "/health"),
    "brutus_runner": ("brutus_runner_url", "/health"),
    "exploit_runner": ("exploit_runner_url", "/health"),
    "scan_recommender": ("scan_recommender_url", "/health"),
    "autogen_agents": ("autogen_url", "/health"),
    "playwright_scanner": ("playwright_scanner_url", "/health"),
    "container_logs": ("container_logs_url", "/health"),
}


@router.get("/api/system-check")
async def system_check():
    """
    Run comprehensive system checks: DB schema, inter-service connectivity,
    end-to-end call tests, and missing column detection.
    """
    settings = get_settings()
    results = {
        "database": {"status": "unknown", "checks": []},
        "connectivity": {"status": "unknown", "services": {}},
        "end_to_end": {"status": "unknown", "tests": []},
        "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0},
    }

    # ── 1. Database schema checks ──
    db_checks = []
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            # Get table list from rag-api
            resp = await client.get(
                f"{settings.rag_api_url}/health/database",
                headers={"x-api-key": settings.api_key},
            )
            if resp.status_code == 200:
                db_data = resp.json()
                db_checks.append({
                    "check": "database_connection",
                    "status": "pass",
                    "detail": f"Connected, {db_data.get('table_count', '?')} tables found",
                })

                # The /health/database response has missing_tables as a list
                api_missing = set(db_data.get("missing_tables", []))
                # Cross-check: any of OUR critical tables in the missing list?
                our_missing = [t for t in CRITICAL_TABLES if t in api_missing]

                if our_missing:
                    db_checks.append({
                        "check": "critical_tables",
                        "status": "fail",
                        "detail": f"Missing {len(our_missing)} critical tables: {', '.join(our_missing)}",
                        "missing": our_missing,
                    })
                elif api_missing:
                    db_checks.append({
                        "check": "critical_tables",
                        "status": "warning",
                        "detail": f"All {len(CRITICAL_TABLES)} critical tables present, but {len(api_missing)} non-critical missing: {', '.join(api_missing)}",
                    })
                else:
                    db_checks.append({
                        "check": "critical_tables",
                        "status": "pass",
                        "detail": f"All {len(CRITICAL_TABLES)} critical tables present ({db_data.get('table_count', '?')} total)",
                    })
            else:
                db_checks.append({
                    "check": "database_connection",
                    "status": "fail",
                    "detail": f"Health endpoint returned {resp.status_code}",
                })
    except Exception as e:
        log.error(f"system_check: DB check failed: {e}")
        db_checks.append({
            "check": "database_connection",
            "status": "fail",
            "detail": f"Connection failed: {type(e).__name__}: {e}",
        })

    # Check critical views and columns via direct rag-api query
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            resp = await client.post(
                f"{settings.rag_api_url}/health/sql/check-schema",
                headers={"x-api-key": settings.api_key},
                json={
                    "tables": CRITICAL_TABLES,
                    "views": CRITICAL_VIEWS,
                    "columns": CRITICAL_COLUMNS,
                },
            )
            if resp.status_code == 200:
                schema = resp.json()
                # Views
                missing_views = schema.get("missing_views", [])
                if missing_views:
                    db_checks.append({
                        "check": "critical_views",
                        "status": "fail",
                        "detail": f"Missing views: {', '.join(missing_views)}",
                        "missing": missing_views,
                    })
                else:
                    db_checks.append({
                        "check": "critical_views",
                        "status": "pass",
                        "detail": f"All {len(CRITICAL_VIEWS)} critical views present",
                    })
                # Columns
                missing_cols = schema.get("missing_columns", {})
                if missing_cols:
                    col_details = [f"{t}: {', '.join(cols)}" for t, cols in missing_cols.items()]
                    db_checks.append({
                        "check": "critical_columns",
                        "status": "fail",
                        "detail": f"Missing columns in: {'; '.join(col_details)}",
                        "missing": missing_cols,
                    })
                else:
                    db_checks.append({
                        "check": "critical_columns",
                        "status": "pass",
                        "detail": "All critical columns present",
                    })
            elif resp.status_code == 404:
                db_checks.append({
                    "check": "schema_detail",
                    "status": "warning",
                    "detail": "Schema detail endpoint not available (rag-api update needed)",
                })
    except Exception as e:
        log.warning(f"system_check: schema detail check failed: {e}")

    db_status = "pass" if all(c["status"] == "pass" for c in db_checks) else \
                "warning" if any(c["status"] == "warning" for c in db_checks) else "fail"
    results["database"] = {"status": db_status, "checks": db_checks}

    # ── 2. Service connectivity (HTTPS with verify=False) ──
    svc_results = {}

    async def _check_service(name, attr, path):
        url = getattr(settings, attr, "") + path
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                resp = await client.get(url, headers={"x-api-key": settings.api_key})
                svc_results[name] = {
                    "status": "pass" if resp.status_code == 200 else "warning",
                    "code": resp.status_code,
                    "url": url,
                    "protocol": "https" if url.startswith("https") else "http",
                }
        except Exception as e:
            svc_results[name] = {
                "status": "fail",
                "error": f"{type(e).__name__}: {str(e)[:100]}",
                "url": url,
            }

    await asyncio.gather(*[
        _check_service(name, attr, path)
        for name, (attr, path) in CONNECTIVITY_CHECKS.items()
    ])

    conn_status = "pass" if all(s["status"] == "pass" for s in svc_results.values()) else \
                  "warning" if any(s["status"] == "pass" for s in svc_results.values()) else "fail"
    results["connectivity"] = {"status": conn_status, "services": svc_results}

    # ── 3. End-to-end functional tests ──
    e2e_tests = []

    async def _e2e_test(name, test_fn):
        try:
            result = await test_fn()
            e2e_tests.append({"test": name, "status": "pass", **result})
        except Exception as e:
            log.warning(f"system_check e2e {name}: {e}")
            e2e_tests.append({"test": name, "status": "fail", "error": str(e)[:150]})

    async def test_db_query():
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            r = await c.get(f"{settings.rag_api_url}/assets?limit=1",
                            headers={"x-api-key": settings.api_key})
            return {"detail": f"Query returned {r.status_code}"}

    async def test_scan_recommender():
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            r = await c.get(f"{settings.scan_recommender_url}/recommendations?limit=1",
                            headers={"x-api-key": settings.api_key})
            return {"detail": f"Recommendations endpoint: {r.status_code}"}

    async def test_webhook_delivery():
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            r = await c.get(f"{settings.rag_api_url}/webhooks",
                            headers={"x-api-key": settings.api_key})
            count = len(r.json()) if r.status_code == 200 and isinstance(r.json(), list) else 0
            return {"detail": f"{count} webhooks registered"}

    async def test_exploit_search():
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            r = await c.get(f"{settings.scan_recommender_url}/rag/search/enhanced",
                            params={"query": "test", "service": "http"},
                            headers={"x-api-key": settings.api_key})
            return {"detail": f"Exploit search: {r.status_code}"}

    async def test_ollama():
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            r = await c.get(f"{settings.ollama_url}/api/tags")
            models = len(r.json().get("models", [])) if r.status_code == 200 else 0
            return {"detail": f"Ollama: {models} models available"}

    async def _test_mcp_servers(server_list, label):
        """Test a list of (name, port) MCP servers, return result dict."""
        ok = []
        failed = []
        async with httpx.AsyncClient(verify=False, timeout=8) as c:
            for name, port in server_list:
                try:
                    r = await c.post(
                        f"http://mcp-streamable:{port}/mcp",
                        json={"jsonrpc": "2.0", "id": 0, "method": "initialize",
                              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                         "clientInfo": {"name": "health", "version": "1.0"}}},
                        headers={"Accept": "application/json, text/event-stream"},
                        timeout=5,
                    )
                    if r.status_code == 200:
                        ok.append(name)
                    else:
                        failed.append(f"{name} (port {port}: HTTP {r.status_code})")
                except Exception as e:
                    failed.append(f"{name} (port {port}: {type(e).__name__})")

        detail = f"{label}: {len(ok)}/{len(server_list)} servers reachable"
        result = {"detail": detail, "ok_servers": ok}
        if failed:
            result["failed_servers"] = failed
            result["status_override"] = "warning"
            result["detail"] += f" — unreachable: {', '.join(failed)}"
        return result

    BUILTIN_MCP = [
        ("sessions", 9016), ("scanning", 9017), ("recon", 9018),
        ("exploit", 9019), ("credentials", 9020), ("pipelines", 9021),
        ("burp", 9022), ("zap", 9023),
    ]

    async def _test_single_mcp(name, port):
        async with httpx.AsyncClient(verify=False, timeout=8) as c:
            r = await c.post(
                f"http://mcp-streamable:{port}/mcp",
                json={"jsonrpc": "2.0", "id": 0, "method": "initialize",
                      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "health", "version": "1.0"}}},
                headers={"Accept": "application/json, text/event-stream"},
                timeout=5,
            )
            if r.status_code == 200:
                return {"detail": f"MCP {name} (port {port}): OK"}
            return {"detail": f"MCP {name} (port {port}): HTTP {r.status_code}", "status_override": "warning"}

    async def test_mcp_third_party():
        third_party = [
            ("mcp-everything", 9030),
        ]
        result = await _test_mcp_servers(third_party, "Third-party MCP")
        ok = result.get("ok_servers", [])
        failed = result.get("failed_servers", [])

        # Burp MCP proxy runs on a separate host (not mcp-streamable)
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as c:
                r = await c.get("http://burp-mcp-proxy:9876/", timeout=3)
                if r.status_code == 200:
                    ok.append("burpsuite-pro")
                else:
                    failed.append(f"burpsuite-pro (HTTP {r.status_code})")
        except Exception as e:
            failed.append(f"burpsuite-pro ({type(e).__name__})")

        total = len(third_party) + 1  # +1 for burp
        result["detail"] = f"Third-party MCP: {len(ok)}/{total} servers reachable"
        result["ok_servers"] = ok
        if failed:
            result["failed_servers"] = failed
            result["status_override"] = "warning"
            result["detail"] += f" — unreachable: {', '.join(failed)}"
        return result

    await asyncio.gather(
        _e2e_test("db_query", test_db_query),
        _e2e_test("scan_recommender", test_scan_recommender),
        _e2e_test("webhook_system", test_webhook_delivery),
        _e2e_test("exploit_search", test_exploit_search),
        _e2e_test("ollama_models", test_ollama),
        # Each built-in MCP server gets its own check
        *[_e2e_test(f"mcp_{name}", lambda n=name, p=port: _test_single_mcp(n, p))
          for name, port in BUILTIN_MCP],
        _e2e_test("mcp_third_party", test_mcp_third_party),
    )

    # Apply status overrides from e2e tests
    for t in e2e_tests:
        if t.get("status_override"):
            t["status"] = t.pop("status_override")

    e2e_status = "pass" if all(t["status"] == "pass" for t in e2e_tests) else \
                 "warning" if any(t["status"] == "pass" for t in e2e_tests) else "fail"
    results["end_to_end"] = {"status": e2e_status, "tests": e2e_tests}

    # ── 4. Platform & environment advisories ──
    advisories = []
    platform_info = {"os": "unknown", "wsl": False, "docker_desktop": False}

    # Flag failed MCP servers from e2e tests
    all_failed_mcp = []
    for t in e2e_tests:
        if t.get("test", "").startswith("mcp_") and t.get("status") == "fail":
            all_failed_mcp.append(t.get("test", "").replace("mcp_", "") + f": {t.get('error', t.get('detail', ''))[:60]}")
        if t.get("failed_servers"):
            all_failed_mcp.extend(t["failed_servers"])
    if all_failed_mcp:
        advisories.append({
            "level": "warning",
            "title": f"MCP servers unreachable: {len(all_failed_mcp)} failed",
            "detail": "These MCP servers could not be reached. Agent tool calls to these servers will fail.",
            "fix": "Failed servers:\n" +
                   "\n".join(f"  • {s}" for s in all_failed_mcp) +
                   "\n\nTo fix built-in servers:\n"
                   "  1. Check: docker ps | grep mcp-streamable\n"
                   "  2. Logs: docker compose logs mcp-streamable --tail 20\n"
                   "  3. Restart: docker compose restart mcp-streamable\n\n"
                   "To fix third-party servers:\n"
                   "  1. Check registry: cat mcp/third_party/registry.yaml\n"
                   "  2. Verify the server is enabled and the port is correct\n"
                   "  3. For Burp MCP: ensure Burp Suite is running with MCP extension on the host\n"
                   "  4. Restart: docker compose restart mcp-streamable",
        })

    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            # Detect platform from container environment
            resp = await client.get(
                f"{settings.container_logs_url}/health",
            )
            # Check if running in WSL by probing kernel version
            try:
                resp2 = await client.get(f"{settings.rag_api_url}/health/quick",
                                         headers={"x-api-key": settings.api_key})
            except Exception:
                pass

        # Detect Docker Desktop (macOS/Windows) — masscan raw sockets won't work
        # Check if masscan fallback was used in nmap
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                r = await client.get(f"{settings.nmap_scanner_url}/logs",
                                     params={"search": "fallback", "limit": 5},
                                     headers={"x-api-key": settings.api_key})
                if r.status_code == 200:
                    logs = r.json().get("logs", [])
                    if any("fallback" in (l.get("message", "")).lower() for l in logs):
                        platform_info["docker_desktop"] = True
                        advisories.append({
                            "level": "warning",
                            "title": "Docker Desktop detected — masscan uses nmap fallback",
                            "detail": "Raw SYN packets are blocked on Docker Desktop (macOS/Windows). "
                                      "Masscan silently falls back to nmap -sT for port discovery. "
                                      "Scans still work but are slower.",
                            "fix": None,
                        })
        except Exception:
            pass

        # Check Ollama GPU status
        try:
            ollama_data = await ollama_status()
            gpu = ollama_data.get("gpu")
            loaded = ollama_data.get("loaded_models", [])

            if gpu:
                gpu_type = gpu.get("type", "")
                gpu_name = gpu.get("name", "")
                platform_info["gpu"] = gpu_name
                platform_info["gpu_type"] = gpu_type

                # Check if GPU is being used
                if loaded:
                    for m in loaded:
                        if m.get("gpu_percent", 0) == 0:
                            advisories.append({
                                "level": "warning",
                                "title": f"Ollama model '{m['name']}' running on CPU only",
                                "detail": "The model is loaded but using 0% GPU. "
                                          "This causes very slow inference and LLM timeouts.",
                                "fix": "Windows/WSL2: Ensure NVIDIA GPU drivers are installed in Windows "
                                       "(not inside WSL). Run 'nvidia-smi' in PowerShell to verify. "
                                       "Then restart Ollama with: OLLAMA_NUM_GPU=999 ollama serve\n\n"
                                       "macOS: Apple Silicon GPU is used automatically. "
                                       "If on Intel Mac, GPU acceleration is not available.\n\n"
                                       "Linux: Install NVIDIA Container Toolkit: "
                                       "https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html",
                            })
                else:
                    advisories.append({
                        "level": "info",
                        "title": "No Ollama models loaded",
                        "detail": "Load a model to verify GPU acceleration is working.",
                        "fix": "Run: ollama run gemma4:31b 'hello'",
                    })

                # VRAM check
                vram_total = gpu.get("vram_total_mb", 0)
                vram_used = gpu.get("vram_used_mb", 0)
                if vram_total > 0 and vram_used / vram_total > 0.9:
                    advisories.append({
                        "level": "warning",
                        "title": f"GPU memory nearly full ({gpu.get('vram_used_human', '?')}/{gpu.get('vram_total_human', '?')})",
                        "detail": "High VRAM usage may cause OOM errors or slow inference. "
                                  "Consider unloading unused models.",
                        "fix": "Unload unused models from the Ollama panel, or use a smaller quantization.",
                    })
            else:
                advisories.append({
                    "level": "warning",
                    "title": "No GPU detected for Ollama",
                    "detail": "Ollama is running without GPU acceleration. "
                              "LLM inference will be very slow.",
                    "fix": "Windows/WSL2:\n"
                           "  1. Install NVIDIA GPU drivers in Windows (not WSL): https://www.nvidia.com/drivers\n"
                           "  2. Verify: run 'nvidia-smi' in PowerShell\n"
                           "  3. Enable WSL2 GPU: 'wsl --update' in PowerShell\n"
                           "  4. In WSL2: 'nvidia-smi' should show your GPU\n"
                           "  5. Restart Ollama: OLLAMA_NUM_GPU=999 ollama serve\n\n"
                           "macOS: Apple Silicon GPU is automatic. Intel Macs have no GPU support.\n\n"
                           "Linux: Install NVIDIA Container Toolkit and restart Docker.",
                })
        except Exception as e:
            log.warning(f"system_check: Ollama GPU check failed: {e}")

        # WSL2-specific advisories
        try:
            async with httpx.AsyncClient(verify=False, timeout=3) as client:
                # Check kernel version for WSL detection
                r = await client.get(f"{settings.container_logs_url}/health")
                if r.status_code == 200:
                    # Try to detect WSL from uname
                    r2 = await client.get(f"{settings.rag_api_url}/health/quick",
                                          headers={"x-api-key": settings.api_key})
        except Exception:
            pass

        # Always add platform tips
        advisories.append({
            "level": "info",
            "title": "WSL2 Networking Tips",
            "detail": "If running on Windows/WSL2, these settings optimize Docker networking.",
            "fix": "PowerShell (admin):\n"
                   "  # Expose Docker ports to LAN:\n"
                   "  netsh interface portproxy add v4tov4 listenport=3002 listenaddress=0.0.0.0 connectport=3002 connectaddress=$(wsl hostname -I | cut -d' ' -f1)\n\n"
                   "  # Windows Firewall rule:\n"
                   "  New-NetFirewallRule -DisplayName 'RAG Scan Stack' -Direction Inbound -LocalPort 3002,8000,8015 -Protocol TCP -Action Allow\n\n"
                   "WSL2 ~/.wslconfig:\n"
                   "  [wsl2]\n"
                   "  memory=16GB\n"
                   "  swap=8GB\n"
                   "  processors=4\n"
                   "  localhostForwarding=true\n\n"
                   "Docker Desktop Settings:\n"
                   "  - Enable 'Use WSL 2 based engine'\n"
                   "  - Resources → WSL Integration → Enable for your distro\n"
                   "  - Enable 'Expose daemon on tcp://localhost:2375'",
        })

        advisories.append({
            "level": "info",
            "title": "TLS / Self-Signed Cert Notes",
            "detail": "All inter-container traffic uses HTTPS with self-signed certificates.",
            "fix": "If adding new services or MCP servers:\n"
                   "  1. Mount certs volume: ./certs:/certs:ro\n"
                   "  2. Add SSL env vars: SSL_CERTFILE=/certs/server.crt, SSL_KEYFILE=/certs/server.key\n"
                   "  3. Start uvicorn with: --ssl-keyfile=/certs/server.key --ssl-certfile=/certs/server.crt\n"
                   "  4. All httpx/requests calls must use verify=False\n"
                   "  5. Health checks: curl -fk https://127.0.0.1:PORT/health",
        })

    except Exception as e:
        log.warning(f"system_check: platform detection failed: {e}")

    results["advisories"] = advisories
    results["platform"] = platform_info

    # ── Summary ──
    all_checks = db_checks + list(svc_results.values()) + e2e_tests
    results["summary"] = {
        "total": len(all_checks),
        "passed": sum(1 for c in all_checks if c.get("status") == "pass"),
        "failed": sum(1 for c in all_checks if c.get("status") == "fail"),
        "warnings": sum(1 for c in all_checks if c.get("status") == "warning"),
        "advisories": len([a for a in advisories if a["level"] == "warning"]),
        "overall": "pass" if all(c.get("status") == "pass" for c in all_checks) else
                   "degraded" if any(c.get("status") == "pass" for c in all_checks) else "fail",
    }

    return results


@router.post("/api/system-fix")
async def system_fix():
    """
    Attempt to fix detected issues: apply DB schema migrations,
    create missing tables/views/columns, then re-run system check.
    """
    settings = get_settings()
    fixes_applied = []
    errors = []

    # 1. Run ensure_all_tables.sql via rag-api container
    try:
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            # Ask rag-api to apply schema (it has DB access)
            resp = await client.post(
                f"{settings.rag_api_url}/health/sql/apply-schema",
                headers={"x-api-key": settings.api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                fixes_applied.append({
                    "fix": "apply_schema",
                    "detail": data.get("detail", "Schema applied"),
                    "tables_before": data.get("tables_before"),
                    "tables_after": data.get("tables_after"),
                })
            else:
                errors.append(f"Schema apply returned {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log.error(f"system_fix: schema apply failed: {e}")
        errors.append(f"Schema apply failed: {type(e).__name__}: {e}")

    # 2. Re-run system check to verify fixes
    check_result = await system_check()

    return {
        "fixes_applied": fixes_applied,
        "errors": errors,
        "check_after_fix": check_result,
    }


# ── Ollama helpers ────────────────────────────────────────────────────────

def _human_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    if b < 1024 ** 3:
        return f"{b / (1024 ** 2):.1f} MB"
    return f"{b / (1024 ** 3):.1f} GB"


@router.get("/api/ollama/status")
async def ollama_status():
    """Return Ollama GPU/VRAM status, loaded models, and available models."""
    settings = get_settings()
    base = settings.ollama_url
    result: dict = {"gpu": None, "loaded_models": [], "available_models": [], "version": None}

    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        # Version
        try:
            resp = await client.get(f"{base}/api/version")
            if resp.status_code == 200:
                result["version"] = resp.json().get("version")
        except Exception:
            pass

        # Running models (shows VRAM allocation)
        try:
            resp = await client.get(f"{base}/api/ps")
            if resp.status_code == 200:
                for m in resp.json().get("models", []):
                    total = m.get("size", 0)
                    vram = m.get("size_vram", 0)
                    if total > 0:
                        gpu_pct = round(vram / total * 100)
                    else:
                        gpu_pct = 0
                    result["loaded_models"].append({
                        "name": m.get("name"),
                        "parameter_size": m.get("details", {}).get("parameter_size"),
                        "quantization": m.get("details", {}).get("quantization_level"),
                        "family": m.get("details", {}).get("family"),
                        "total_bytes": total,
                        "total_human": _human_bytes(total),
                        "vram_bytes": vram,
                        "vram_human": _human_bytes(vram),
                        "gpu_percent": gpu_pct,
                        "backend": "gpu" if gpu_pct == 100 else "cpu" if gpu_pct == 0 else "gpu+cpu",
                        "context_length": m.get("context_length"),
                        "expires_at": m.get("expires_at"),
                    })
        except Exception:
            pass

        # Available models
        try:
            resp = await client.get(f"{base}/api/tags")
            if resp.status_code == 200:
                for m in resp.json().get("models", []):
                    result["available_models"].append({
                        "name": m.get("name"),
                        "size": m.get("size", 0),
                        "size_human": _human_bytes(m.get("size", 0)),
                        "parameter_size": m.get("details", {}).get("parameter_size"),
                        "quantization": m.get("details", {}).get("quantization_level"),
                        "family": m.get("details", {}).get("family"),
                    })
        except Exception:
            pass

    # GPU info: try NVIDIA first (container-logs/nvidia-smi), fall back to Apple Silicon
    gpu_data = None
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.get("https://container-logs:8018/gpu")
            if resp.status_code == 200:
                gpu_data = resp.json().get("gpu")
    except Exception:
        pass

    if gpu_data:
        result["gpu"] = gpu_data
    elif settings.gpu_name:
        # Apple Silicon / non-NVIDIA: build GPU info from env vars + Ollama model data
        total_mb = settings.gpu_total_memory_gb * 1024
        # Sum memory used by loaded models (Ollama reports size_vram for Apple Silicon unified memory)
        models_used_mb = sum(
            m.get("vram_bytes", m.get("total_bytes", 0)) for m in result["loaded_models"]
        ) / (1024 * 1024)
        used_mb = int(models_used_mb)
        free_mb = max(0, total_mb - used_mb)
        result["gpu"] = {
            "name": settings.gpu_name,
            "type": "apple_silicon",
            "vram_total_mb": total_mb,
            "vram_used_mb": used_mb,
            "vram_free_mb": free_mb,
            "vram_total_human": f"{total_mb / 1024:.0f} GB",
            "vram_used_human": f"{used_mb / 1024:.1f} GB",
            "vram_free_human": f"{free_mb / 1024:.1f} GB",
            "utilization_pct": None,
            "temperature_c": None,
        }

    return result


# ── Model management ──────────────────────────────────────────────────────

from pydantic import BaseModel as PydanticModel


class ModelAction(PydanticModel):
    name: str


@router.post("/api/ollama/model/load")
async def ollama_model_load(body: ModelAction):
    """Preload a model into memory by sending a generate request with keep_alive."""
    settings = get_settings()
    base = settings.ollama_url
    try:
        async with httpx.AsyncClient(verify=False, timeout=120) as client:
            resp = await client.post(
                f"{base}/api/generate",
                json={"model": body.name, "prompt": "", "keep_alive": "10m"},
            )
            if resp.status_code == 200:
                return {"ok": True, "model": body.name, "action": "loaded"}
            return {"ok": False, "model": body.name, "error": resp.text[:500]}
    except Exception as e:
        return {"ok": False, "model": body.name, "error": str(e)}


@router.post("/api/ollama/model/unload")
async def ollama_model_unload(body: ModelAction):
    """Unload a model from memory by setting keep_alive to 0."""
    settings = get_settings()
    base = settings.ollama_url
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            resp = await client.post(
                f"{base}/api/generate",
                json={"model": body.name, "prompt": "", "keep_alive": 0},
            )
            if resp.status_code == 200:
                return {"ok": True, "model": body.name, "action": "unloaded"}
            return {"ok": False, "model": body.name, "error": resp.text[:500]}
    except Exception as e:
        return {"ok": False, "model": body.name, "error": str(e)}


@router.post("/api/ollama/model/pull")
async def ollama_model_pull(body: ModelAction):
    """Pull (download) a model from the Ollama registry."""
    settings = get_settings()
    base = settings.ollama_url
    try:
        async with httpx.AsyncClient(verify=False, timeout=600) as client:
            resp = await client.post(
                f"{base}/api/pull",
                json={"name": body.name, "stream": False},
            )
            if resp.status_code == 200:
                return {"ok": True, "model": body.name, "action": "pulled"}
            return {"ok": False, "model": body.name, "error": resp.text[:500]}
    except Exception as e:
        return {"ok": False, "model": body.name, "error": str(e)}


@router.get("/api/ollama/model/active")
async def get_active_model():
    """Get the active model name from app_settings (used by all services)."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.get(
                f"{settings.rag_api_url}/settings/config/ollama_active_model",
                headers={"x-api-key": settings.api_key},
            )
            if resp.status_code == 200:
                return {"ok": True, "model": resp.json().get("value")}
    except Exception:
        pass
    # Fall back to env var default
    return {"ok": True, "model": settings.ollama_model}


@router.put("/api/ollama/model/active")
async def set_active_model(body: ModelAction):
    """Set the active model globally (persisted to DB, used by all services)."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.put(
                f"{settings.rag_api_url}/settings/config/ollama_active_model",
                headers={"x-api-key": settings.api_key, "Content-Type": "application/json"},
                json={"value": body.name},
            )
            if resp.status_code == 200:
                return {"ok": True, "model": body.name, "action": "active_model_set"}
            return {"ok": False, "error": resp.text[:500]}
    except Exception as e:
        return {"ok": False, "error": str(e)}
