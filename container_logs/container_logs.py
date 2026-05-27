"""
Container Logs Proxy Service
Provides web UI access to Docker container logs for third-party services (ZAP, Metasploit)
"""

import os
import asyncio
import logging
from typing import Optional, List
from datetime import datetime
from collections import deque

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, Response
import docker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Container configuration - which containers to monitor
MONITORED_CONTAINERS = {
    "zap": {"name": "zap", "color": "#2ecc71", "description": "OWASP ZAP Scanner"},
    "metasploit": {"name": "metasploit", "color": "#9b59b6", "description": "Metasploit Framework"}
}

# Docker client
docker_client = docker.from_env()


def get_container_logs(container_name: str, lines: int = 200, since: Optional[str] = None) -> List[dict]:
    """Fetch logs from a Docker container"""
    try:
        container = docker_client.containers.get(container_name)
        logs = container.logs(tail=lines, timestamps=True).decode('utf-8', errors='replace')

        result = []
        for line in logs.splitlines():
            if not line.strip():
                continue
            # Docker logs format: timestamp message
            parts = line.split(' ', 1)
            if len(parts) == 2:
                timestamp, message = parts
                # Parse timestamp
                try:
                    ts = timestamp.replace('Z', '+00:00')
                    result.append({
                        "timestamp": ts[:26],  # Trim to microseconds
                        "message": message,
                        "container": container_name,
                        "level": detect_log_level(message)
                    })
                except:
                    result.append({
                        "timestamp": datetime.now().isoformat(),
                        "message": line,
                        "container": container_name,
                        "level": "INFO"
                    })
            else:
                result.append({
                    "timestamp": datetime.now().isoformat(),
                    "message": line,
                    "container": container_name,
                    "level": "INFO"
                })
        return result
    except docker.errors.NotFound:
        logger.warning(f"Container {container_name} not found")
        return []
    except Exception as e:
        logger.error(f"Error getting logs for {container_name}: {e}")
        return []


def detect_log_level(message: str) -> str:
    """Detect log level from message content"""
    msg_lower = message.lower()
    if 'error' in msg_lower or 'exception' in msg_lower or 'failed' in msg_lower:
        return "ERROR"
    elif 'warn' in msg_lower:
        return "WARNING"
    elif 'debug' in msg_lower:
        return "DEBUG"
    return "INFO"


def get_container_status(container_name: str) -> dict:
    """Get status of a container"""
    try:
        container = docker_client.containers.get(container_name)
        return {
            "name": container_name,
            "status": container.status,
            "running": container.status == "running",
            "id": container.short_id
        }
    except docker.errors.NotFound:
        return {
            "name": container_name,
            "status": "not_found",
            "running": False,
            "id": None
        }
    except Exception as e:
        return {
            "name": container_name,
            "status": f"error: {e}",
            "running": False,
            "id": None
        }


app = FastAPI(title="Container Logs Proxy", description="View Docker container logs for ZAP and Metasploit")


@app.get("/health")
def health():
    """Health check"""
    return {"ok": True, "service": "container-logs-proxy"}


@app.get("/container/{name}/status")
def container_status_endpoint(name: str):
    """Fast single-container status check."""
    try:
        c = docker_client.containers.get(name)
        health = ""
        try:
            health = c.attrs.get("State", {}).get("Health", {}).get("Status", "")
        except Exception:
            pass
        return {"name": name, "status": c.status, "running": c.status == "running",
                "health": health, "id": c.short_id}
    except docker.errors.NotFound:
        return {"name": name, "status": "not_found", "running": False, "health": "", "id": None}
    except Exception as e:
        return {"name": name, "status": "error", "running": False, "health": "", "error": str(e)}


@app.get("/containers")
def list_containers():
    """List monitored containers and their status"""
    result = []
    for key, config in MONITORED_CONTAINERS.items():
        status = get_container_status(config["name"])
        result.append({
            "key": key,
            **config,
            **status
        })
    return {"containers": result}


@app.get("/logs/{container_key}")
def get_logs(
    container_key: str,
    lines: int = Query(200, description="Number of log lines to fetch"),
    search: Optional[str] = Query(None, description="Search filter"),
    level: Optional[str] = Query(None, description="Filter by log level")
):
    """Get logs for a specific container"""
    if container_key not in MONITORED_CONTAINERS:
        return {"error": f"Unknown container: {container_key}", "logs": []}

    container_name = MONITORED_CONTAINERS[container_key]["name"]
    logs = get_container_logs(container_name, lines=lines)

    # Apply filters
    if level:
        logs = [l for l in logs if l["level"] == level.upper()]
    if search:
        logs = [l for l in logs if search.lower() in l["message"].lower()]

    return {"logs": logs, "container": container_key, "total": len(logs)}


@app.get("/logs/ui/{container_key}", response_class=HTMLResponse)
def logs_ui(container_key: str):
    """Container-specific logs UI"""
    if container_key not in MONITORED_CONTAINERS:
        return HTMLResponse(content=f"<h1>Unknown container: {container_key}</h1>", status_code=404)

    config = MONITORED_CONTAINERS[container_key]
    color = config["color"]
    title = config["description"]

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} Logs</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{ background: linear-gradient(135deg, {color} 0%, {color}cc 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        h1 {{ color: white; font-size: 28px; margin-bottom: 10px; }}
        .subtitle {{ color: rgba(255,255,255,0.9); font-size: 14px; }}
        .status {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; margin-left: 10px; }}
        .status.running {{ background: #27ae60; }}
        .status.stopped {{ background: #e74c3c; }}
        .controls {{ background: #2a2a2a; padding: 20px; border-radius: 10px; margin-bottom: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .control-group {{ display: flex; flex-direction: column; }}
        label {{ font-size: 12px; color: #aaa; margin-bottom: 5px; text-transform: uppercase; }}
        input, select {{ background: #1a1a1a; border: 1px solid #444; color: #e0e0e0; padding: 10px; border-radius: 5px; }}
        button {{ background: {color}; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }}
        button:hover {{ opacity: 0.9; }}
        button.secondary {{ background: #6c757d; }}
        .logs-container {{ background: #2a2a2a; border-radius: 10px; padding: 20px; max-height: 600px; overflow-y: auto; }}
        .log-entry {{ background: #1a1a1a; border-radius: 5px; padding: 12px; margin-bottom: 8px; border-left: 4px solid #6c757d; }}
        .log-entry.INFO {{ border-left-color: {color}; }}
        .log-entry.WARNING {{ border-left-color: #ffc107; }}
        .log-entry.ERROR {{ border-left-color: #dc3545; }}
        .log-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }}
        .log-level {{ padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }}
        .log-level.INFO {{ background: {color}; color: white; }}
        .log-level.WARNING {{ background: #ffc107; color: black; }}
        .log-level.ERROR {{ background: #dc3545; color: white; }}
        .log-time {{ color: #888; font-size: 12px; }}
        .log-message {{ font-family: monospace; font-size: 13px; word-break: break-word; white-space: pre-wrap; }}
        .auto-refresh {{ display: flex; align-items: center; gap: 10px; }}
        .auto-refresh input[type="checkbox"] {{ width: 18px; height: 18px; }}
        .stats {{ background: #2a2a2a; padding: 15px 20px; border-radius: 10px; margin-bottom: 20px; display: flex; gap: 30px; flex-wrap: wrap; }}
        .stat-item {{ display: flex; flex-direction: column; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: {color}; }}
        .stat-label {{ font-size: 12px; color: #888; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{title} Logs <span class="status" id="container-status">...</span></h1>
            <p class="subtitle">Docker container logs viewer - Container: {container_key}</p>
        </header>
        <div class="stats">
            <div class="stat-item"><span class="stat-value" id="total-logs">-</span><span class="stat-label">Total Lines</span></div>
            <div class="stat-item"><span class="stat-value" id="error-count">-</span><span class="stat-label">Errors</span></div>
            <div class="stat-item"><span class="stat-value" id="warning-count">-</span><span class="stat-label">Warnings</span></div>
        </div>
        <div class="controls">
            <div class="control-group"><label>Level</label><select id="level"><option value="">All</option><option value="INFO">INFO</option><option value="WARNING">WARNING</option><option value="ERROR">ERROR</option></select></div>
            <div class="control-group"><label>Search</label><input type="text" id="search" placeholder="Search logs..."></div>
            <div class="control-group"><label>Lines</label><select id="lines"><option value="100">100</option><option value="200" selected>200</option><option value="500">500</option><option value="1000">1000</option></select></div>
            <div class="control-group"><label>Actions</label><div style="display:flex;gap:10px"><button onclick="loadLogs()">Refresh</button></div></div>
            <div class="control-group auto-refresh"><label>Auto Refresh</label><input type="checkbox" id="auto-refresh" checked><span style="font-size:12px;color:#888">5s</span></div>
        </div>
        <div class="logs-container" id="logs"><div class="loading">Loading...</div></div>
    </div>
    <script>
        const containerKey = '{container_key}';
        let autoRefreshInterval = null;

        async function loadStatus() {{
            try {{
                const r = await fetch('/containers');
                const d = await r.json();
                const container = d.containers.find(c => c.key === containerKey);
                const statusEl = document.getElementById('container-status');
                if (container) {{
                    statusEl.textContent = container.status;
                    statusEl.className = 'status ' + (container.running ? 'running' : 'stopped');
                }}
            }} catch(e) {{ console.error(e); }}
        }}

        async function loadLogs() {{
            const p = new URLSearchParams();
            const level = document.getElementById('level').value;
            const search = document.getElementById('search').value;
            const lines = document.getElementById('lines').value;
            if (level) p.append('level', level);
            if (search) p.append('search', search);
            p.append('lines', lines);

            try {{
                const r = await fetch(`/logs/${{containerKey}}?${{p}}`);
                const d = await r.json();
                const c = document.getElementById('logs');

                document.getElementById('total-logs').textContent = d.total;
                const errors = d.logs.filter(l => l.level === 'ERROR').length;
                const warnings = d.logs.filter(l => l.level === 'WARNING').length;
                document.getElementById('error-count').textContent = errors;
                document.getElementById('warning-count').textContent = warnings;

                if (!d.logs.length) {{
                    c.innerHTML = '<div style="text-align:center;padding:40px;color:#888">No logs found</div>';
                    return;
                }}

                c.innerHTML = d.logs.map(l => `
                    <div class="log-entry ${{l.level}}">
                        <div class="log-header">
                            <span class="log-level ${{l.level}}">${{l.level}}</span>
                            <span class="log-time">${{new Date(l.timestamp).toLocaleString()}}</span>
                        </div>
                        <div class="log-message">${{l.message.replace(/</g,'&lt;')}}</div>
                    </div>
                `).join('');
                c.scrollTop = c.scrollHeight;
                await loadStatus();
            }} catch(e) {{
                document.getElementById('logs').innerHTML = `<div style="color:#dc3545;text-align:center;padding:40px">Error: ${{e.message}}</div>`;
            }}
        }}

        document.getElementById('auto-refresh').addEventListener('change', e => {{
            if (e.target.checked) autoRefreshInterval = setInterval(loadLogs, 5000);
            else clearInterval(autoRefreshInterval);
        }});

        loadLogs();
        loadStatus();
        if (document.getElementById('auto-refresh').checked) autoRefreshInterval = setInterval(loadLogs, 5000);
    </script>
</body>
</html>'''
    return HTMLResponse(content=html)


@app.get("/", response_class=HTMLResponse)
def index():
    """Main page with links to all container logs"""
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Container Logs Proxy</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: white; font-size: 32px; margin-bottom: 10px; }
        .subtitle { color: #888; font-size: 14px; margin-bottom: 40px; }
        .card { background: #2a2a2a; border-radius: 10px; padding: 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .card-info h2 { font-size: 20px; margin-bottom: 5px; }
        .card-info p { color: #888; font-size: 14px; }
        .status { padding: 4px 12px; border-radius: 20px; font-size: 12px; }
        .status.running { background: #27ae60; color: white; }
        .status.stopped { background: #e74c3c; color: white; }
        .status.unknown { background: #6c757d; color: white; }
        a.btn { display: inline-block; padding: 10px 20px; border-radius: 5px; text-decoration: none; color: white; margin-left: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Container Logs Proxy</h1>
        <p class="subtitle">View logs from third-party Docker containers</p>
        <div id="containers">Loading...</div>
    </div>
    <script>
        async function loadContainers() {
            const r = await fetch('/containers');
            const d = await r.json();
            const el = document.getElementById('containers');
            el.innerHTML = d.containers.map(c => `
                <div class="card">
                    <div class="card-info">
                        <h2>${c.description}</h2>
                        <p>Container: ${c.name}</p>
                    </div>
                    <div>
                        <span class="status ${c.running ? 'running' : 'stopped'}">${c.status}</span>
                        <a class="btn" href="/logs/ui/${c.key}" style="background: ${c.color}">View Logs</a>
                    </div>
                </div>
            `).join('');
        }
        loadContainers();
    </script>
</body>
</html>'''
    return HTMLResponse(content=html)


# ── Profile-based service control ──

PROFILE_CONTAINERS = {
    "core": ["rag-api", "rag-postgres", "pentest-dashboard", "container-logs", "embedder"],
    "scan": ["zap", "web-scanner", "nuclei-runner", "osint-runner", "pd-runner",
             "brutus-runner", "nmap_scanner", "scan-recommender", "playwright-scanner"],
    "offensive": ["exploit-runner", "metasploit", "kali-listener", "sliver-server",
                  "chisel-server", "node-manager"],
    "ai": ["autogen-agents", "mcp-server", "mcp-test", "mcp-streamable", "mcpo",
           "llm_query", "ollama"],
    "optional": ["open-webui", "vllm", "kong", "swagger-ui", "specs", "grpo-trainer"],
    "ssh-tunnel": ["ssh-tunnel"],
}

ALL_MANAGED = [c for group in PROFILE_CONTAINERS.values() for c in group]


@app.get("/services/status")
def services_status():
    """Get running status of all managed containers grouped by profile."""
    result = {}
    for profile, containers in PROFILE_CONTAINERS.items():
        profile_status = []
        for name in containers:
            try:
                c = docker_client.containers.get(name)
                health = ""
                try:
                    health = c.attrs.get("State", {}).get("Health", {}).get("Status", "")
                except Exception:
                    pass
                profile_status.append({
                    "name": name, "status": c.status, "running": c.status == "running",
                    "health": health or ("healthy" if c.status == "running" else ""),
                })
            except docker.errors.NotFound:
                profile_status.append({"name": name, "status": "not_found", "running": False, "health": ""})
            except Exception as e:
                profile_status.append({"name": name, "status": str(e), "running": False, "health": ""})
        running_count = sum(1 for s in profile_status if s["running"])
        result[profile] = {
            "containers": profile_status,
            "running": running_count,
            "total": len(containers),
            "active": running_count > 0,
        }
    return {"profiles": result}


@app.post("/services/{action}/{profile}")
def control_profile(action: str, profile: str):
    """Start or stop all containers in a profile. action: start|stop"""
    if action not in ("start", "stop"):
        return {"ok": False, "error": "action must be 'start' or 'stop'"}
    if profile not in PROFILE_CONTAINERS:
        return {"ok": False, "error": f"Unknown profile: {profile}. Valid: {list(PROFILE_CONTAINERS.keys())}"}

    results = []
    for name in PROFILE_CONTAINERS[profile]:
        try:
            c = docker_client.containers.get(name)
            if action == "start" and c.status != "running":
                c.start()
                results.append({"name": name, "action": "started"})
            elif action == "stop" and c.status == "running":
                c.stop(timeout=10)
                results.append({"name": name, "action": "stopped"})
            else:
                results.append({"name": name, "action": "no_change", "status": c.status})
        except docker.errors.NotFound:
            results.append({"name": name, "action": "not_found"})
        except Exception as e:
            results.append({"name": name, "action": "error", "error": str(e)})

    return {"ok": True, "profile": profile, "action": action, "results": results}


@app.post("/services/{action}/container/{container_name}")
def control_container(action: str, container_name: str):
    """Start or stop a single container. action: start|stop"""
    if action not in ("start", "stop"):
        return {"ok": False, "error": "action must be 'start' or 'stop'"}
    # Only allow controlling managed containers
    if container_name not in ALL_MANAGED:
        return {"ok": False, "error": f"Container '{container_name}' is not managed. Valid: {ALL_MANAGED}"}
    try:
        c = docker_client.containers.get(container_name)
        if action == "start" and c.status != "running":
            c.start()
            return {"ok": True, "name": container_name, "action": "started"}
        elif action == "stop" and c.status == "running":
            c.stop(timeout=10)
            return {"ok": True, "name": container_name, "action": "stopped"}
        else:
            return {"ok": True, "name": container_name, "action": "no_change", "status": c.status}
    except docker.errors.NotFound:
        return {"ok": False, "name": container_name, "action": "not_found"}
    except Exception as e:
        return {"ok": False, "name": container_name, "action": "error", "error": str(e)}


@app.get("/gpu")
def gpu_status():
    """Get GPU info by running nvidia-smi inside the ollama container."""
    try:
        container = docker_client.containers.get("ollama")
        if container.status != "running":
            return {"gpu": None, "error": "ollama container not running"}
        result = container.exec_run(
            "nvidia-smi --query-gpu=name,memory.total,memory.used,memory.free,"
            "utilization.gpu,temperature.gpu,power.draw,power.limit,fan.speed,"
            "driver_version,pci.bus_id "
            "--format=csv,noheader,nounits",
            demux=True,
        )
        stdout = (result.output[0] or b"").decode().strip()
        if result.exit_code != 0 or not stdout:
            return {"gpu": None, "error": "nvidia-smi not available"}
        parts = [p.strip() for p in stdout.split(",")]
        if len(parts) < 6:
            return {"gpu": None, "error": f"unexpected nvidia-smi output: {stdout}"}

        def safe_int(val):
            try: return int(float(val))
            except: return None
        def safe_float(val):
            try: return round(float(val), 1)
            except: return None

        # Get CUDA version from nvidia-smi header
        cuda_ver = None
        try:
            r2 = container.exec_run("nvidia-smi --query-gpu=driver_version --format=csv,noheader", demux=True)
            # Parse CUDA from full nvidia-smi output
            r3 = container.exec_run("nvidia-smi", demux=True)
            smi_out = (r3.output[0] or b"").decode()
            for line in smi_out.split("\n"):
                if "CUDA Version" in line:
                    import re
                    m = re.search(r"CUDA Version:\s*([\d.]+)", line)
                    if m: cuda_ver = m.group(1)
                    break
        except: pass

        gpu_info = {
            "name": parts[0],
            "vram_total_mb": safe_int(parts[1]) or 0,
            "vram_used_mb": safe_int(parts[2]) or 0,
            "vram_free_mb": safe_int(parts[3]) or 0,
            "vram_total_human": f"{(safe_int(parts[1]) or 0) / 1024:.1f} GB",
            "vram_used_human": f"{(safe_int(parts[2]) or 0) / 1024:.1f} GB",
            "vram_free_human": f"{(safe_int(parts[3]) or 0) / 1024:.1f} GB",
            "utilization_pct": safe_int(parts[4]),
            "temperature_c": safe_int(parts[5]),
            "power_w": safe_int(parts[6]) if len(parts) > 6 else None,
            "power_cap_w": safe_int(parts[7]) if len(parts) > 7 else None,
            "fan_pct": safe_int(parts[8]) if len(parts) > 8 else None,
            "driver_version": parts[9].strip() if len(parts) > 9 else None,
            "pci_bus": parts[10].strip() if len(parts) > 10 else None,
            "cuda_version": cuda_ver,
        }
        return {"gpu": gpu_info}
    except docker.errors.NotFound:
        return {"gpu": None, "error": "ollama container not found"}
    except Exception as e:
        return {"gpu": None, "error": str(e)}


# ── Database mode management ──

import subprocess
import json as json_module
from pydantic import BaseModel as PydanticBaseModel

PROJECT_DIR = os.environ.get("PROJECT_DIR", "/project")
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "rag-scan-stack")
ENV_FILE = os.path.join(PROJECT_DIR, ".env")
DB_CONFIG_FILE = os.path.join(PROJECT_DIR, "db-config.json")


class DbConfigBody(PydanticBaseModel):
    remote_db_host: str = ""
    remote_db_ssh_user: str = "azureuser"
    remote_db_ssh_key: str = "remote_db.pem"
    remote_db_port: int = 5432
    remote_db_user: str = "app"
    remote_db_password: str = ""


def _detect_db_mode() -> str:
    """Detect current DB mode.

    1. Check the persisted preference in db-config.json (mode field).
    2. Fall back to checking container status.
    """
    config = _read_db_config()
    persisted = config.get("mode")
    if persisted in ("local", "remote", "remote_direct"):
        return persisted
    # Legacy fallback: no mode field yet — check container status.
    try:
        c = docker_client.containers.get("rag-db-tunnel")
        if c.status == "running":
            return "remote"
    except docker.errors.NotFound:
        pass
    return "local"


_FLAT_DEFAULT = {
    "mode": "local",
    "remote_db_host": "",
    "remote_db_ssh_user": "azureuser",
    "remote_db_ssh_key": "remote_db.pem",
    "remote_db_port": 5432,
    "remote_db_user": "app",
    "remote_db_password": "",
}


def _read_db_config() -> dict:
    """Read remote DB config from db-config.json.

    The on-disk file may be either:
      - flat: {"mode": ..., "remote_db_host": ..., ...}
      - nested: {"enabled": bool, "mode": ..., "config": {flat keys}, "metadata": {...}}

    Always returns a flat dict so callers can do `config.get("remote_db_host")`.
    """
    if not os.path.exists(DB_CONFIG_FILE):
        return dict(_FLAT_DEFAULT)
    try:
        with open(DB_CONFIG_FILE, "r") as f:
            raw = json_module.load(f)
    except Exception:
        return dict(_FLAT_DEFAULT)

    flat = dict(_FLAT_DEFAULT)
    if isinstance(raw, dict) and isinstance(raw.get("config"), dict):
        # Nested shape — merge inner config + top-level mode/enabled.
        flat.update(raw["config"])
        if "mode" in raw:
            flat["mode"] = raw["mode"]
        # enabled=false collapses to local mode regardless of stored mode.
        if raw.get("enabled") is False:
            flat["mode"] = "local"
    elif isinstance(raw, dict):
        flat.update(raw)
    return flat


def _write_db_config(config: dict):
    """Write remote DB config to db-config.json.

    Preserves the on-disk nested shape ({enabled, mode, config, metadata}) if
    the file already uses it; otherwise writes the flat shape it was given.
    """
    existing = None
    if os.path.exists(DB_CONFIG_FILE):
        try:
            with open(DB_CONFIG_FILE, "r") as f:
                existing = json_module.load(f)
        except Exception:
            existing = None

    payload = config
    if isinstance(existing, dict) and isinstance(existing.get("config"), dict):
        inner = dict(existing["config"])
        for k, v in config.items():
            if k == "mode":
                continue
            inner[k] = v
        payload = {
            "enabled": existing.get("enabled", config.get("mode", "local") != "local"),
            "mode": config.get("mode", existing.get("mode", "local")),
            "config": inner,
            "metadata": existing.get("metadata", {}),
        }
        if payload["mode"] != "local":
            payload["enabled"] = True

    with open(DB_CONFIG_FILE, "w") as f:
        json_module.dump(payload, f, indent=2)


def _ensure_remote_tunnel(config: dict = None) -> dict:
    """Create the SSH tunnel container if not already running.

    Returns a status dict with ok/error. Used by both the switch endpoint
    and the startup auto-start hook.
    """
    import time

    config = config or _read_db_config()
    ssh_key_name = config.get("remote_db_ssh_key", "remote_db.pem")
    ssh_key_path = os.path.join(PROJECT_DIR, "ssh-keys", ssh_key_name)
    if not os.path.exists(ssh_key_path):
        return {"ok": False, "error": f"SSH key not found: {ssh_key_path}"}

    remote_host = config.get("remote_db_host") or ""
    remote_user = config.get("remote_db_ssh_user") or "azureuser"
    remote_port = str(config.get("remote_db_port") or 5432)
    if not remote_host:
        return {"ok": False, "error": "remote_db_host not configured"}

    # If tunnel already running and healthy, nothing to do.
    try:
        existing = docker_client.containers.get("rag-db-tunnel")
        if existing.status == "running":
            try:
                h = existing.attrs.get("State", {}).get("Health", {}).get("Status", "")
                if h == "healthy":
                    return {"ok": True, "already_running": True}
            except Exception:
                pass
            return {"ok": True, "already_running": True, "health": "unknown"}
    except docker.errors.NotFound:
        pass

    # Clean up stale containers.
    _remove_container("rag-db-tunnel")
    _remove_container("rag-postgres")  # stop local if present

    host_project = _get_host_project_dir()
    host_ssh_keys = f"{host_project}/ssh-keys"

    try:
        net = docker_client.networks.get("agents_net")
    except docker.errors.NotFound:
        return {"ok": False, "error": "Docker network 'agents_net' not found"}

    ssh_cmd = (
        f"apk add --no-cache openssh-client autossh && "
        f"cp /ssh-keys/{ssh_key_name} /tmp/ssh_key && chmod 600 /tmp/ssh_key && "
        f"exec autossh -M 0 -N "
        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o ServerAliveInterval=15 -o ServerAliveCountMax=3 "
        f"-o TCPKeepAlive=yes -o ExitOnForwardFailure=yes "
        f"-o ConnectionAttempts=3 "
        f"-i /tmp/ssh_key "
        f"-L 0.0.0.0:5432:localhost:{remote_port} "
        f"{remote_user}@{remote_host}"
    )
    try:
        tunnel = docker_client.containers.run(
            "alpine:3.20",
            name="rag-db-tunnel",
            command=["/bin/sh", "-c", ssh_cmd],
            detach=True,
            restart_policy={"Name": "unless-stopped"},
            volumes={host_ssh_keys: {"bind": "/ssh-keys", "mode": "ro"}},
            healthcheck={
                "Test": ["CMD-SHELL", "nc -z 127.0.0.1 5432 || exit 1"],
                "Interval": 10_000_000_000,
                "Timeout": 5_000_000_000,
                "Retries": 6,
                "StartPeriod": 30_000_000_000,
            },
        )
    except Exception as e:
        return {"ok": False, "error": f"Failed to create tunnel: {e}"}

    try:
        net.connect(tunnel, aliases=["rag-postgres"])
    except Exception as e:
        _remove_container("rag-db-tunnel")
        return {"ok": False, "error": f"Failed to connect tunnel to network: {e}"}

    # Wait for healthy (up to 90s).
    for _attempt in range(18):
        try:
            tunnel.reload()
            h = tunnel.attrs.get("State", {}).get("Health", {}).get("Status", "")
            if h == "healthy":
                return {"ok": True}
            if tunnel.status != "running":
                logs = tunnel.logs(tail=20).decode(errors="replace")
                _remove_container("rag-db-tunnel")
                return {"ok": False, "error": f"Tunnel exited: {logs}"}
        except docker.errors.NotFound:
            return {"ok": False, "error": "Tunnel container disappeared"}
        time.sleep(5)

    try:
        logs = tunnel.logs(tail=30).decode(errors="replace")
    except Exception:
        logs = "unable to fetch"
    return {"ok": False, "error": f"Tunnel not healthy after 90s:\n{logs}"}


def _ensure_remote_direct(config: dict = None) -> dict:
    """Create a lightweight socat proxy container for direct SSL Postgres access.

    No SSH tunnel — uses socat to forward TCP from rag-postgres:5432 to the
    remote host directly. Requires the remote Postgres to have SSL enabled and
    port 5432 open in the firewall.
    """
    import time

    config = config or _read_db_config()
    remote_host = config.get("remote_db_host") or ""
    remote_port = str(config.get("remote_db_port") or 5432)
    if not remote_host:
        return {"ok": False, "error": "remote_db_host not configured"}

    # If proxy already running and healthy, nothing to do.
    try:
        existing = docker_client.containers.get("rag-db-tunnel")
        if existing.status == "running":
            # Check if it's already a direct proxy (not SSH tunnel)
            cmd = existing.attrs.get("Config", {}).get("Cmd", [])
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            if "socat" in cmd_str:
                try:
                    h = existing.attrs.get("State", {}).get("Health", {}).get("Status", "")
                    if h == "healthy":
                        return {"ok": True, "already_running": True, "type": "direct"}
                except Exception:
                    pass
                return {"ok": True, "already_running": True, "type": "direct"}
    except docker.errors.NotFound:
        pass

    # Clean up stale containers.
    _remove_container("rag-db-tunnel")
    _remove_container("rag-postgres")

    try:
        net = docker_client.networks.get("agents_net")
    except docker.errors.NotFound:
        return {"ok": False, "error": "Docker network 'agents_net' not found"}

    socat_cmd = (
        f"apk add --no-cache socat && "
        f"exec socat TCP-LISTEN:5432,fork,reuseaddr TCP:{remote_host}:{remote_port}"
    )
    try:
        proxy = docker_client.containers.run(
            "alpine:3.20",
            name="rag-db-tunnel",  # reuse name so health checks still work
            command=["/bin/sh", "-c", socat_cmd],
            detach=True,
            restart_policy={"Name": "unless-stopped"},
            healthcheck={
                "Test": ["CMD-SHELL", "nc -z 127.0.0.1 5432 || exit 1"],
                "Interval": 10_000_000_000,
                "Timeout": 5_000_000_000,
                "Retries": 6,
                "StartPeriod": 15_000_000_000,
            },
        )
    except Exception as e:
        return {"ok": False, "error": f"Failed to create direct proxy: {e}"}

    try:
        net.connect(proxy, aliases=["rag-postgres"])
    except Exception as e:
        _remove_container("rag-db-tunnel")
        return {"ok": False, "error": f"Failed to connect proxy to network: {e}"}

    # Wait for healthy (up to 30s — much faster than SSH tunnel).
    for _attempt in range(6):
        try:
            proxy.reload()
            h = proxy.attrs.get("State", {}).get("Health", {}).get("Status", "")
            if h == "healthy":
                return {"ok": True, "type": "direct"}
            if proxy.status != "running":
                logs = proxy.logs(tail=20).decode(errors="replace")
                _remove_container("rag-db-tunnel")
                return {"ok": False, "error": f"Proxy exited: {logs}"}
        except docker.errors.NotFound:
            return {"ok": False, "error": "Proxy container disappeared"}
        time.sleep(5)

    return {"ok": False, "error": "Direct proxy not healthy after 30s"}


def _auto_start_db():
    """Called once at service startup.

    If db-config.json has mode=remote or remote_direct with a valid host,
    auto-create the appropriate proxy so the stack can reach the remote
    Postgres immediately. ALSO force-remove any local rag-postgres container
    that was left running — restart: unless-stopped on the compose service
    can drag it back across daemon restarts even when the operator selected
    remote mode, which conflicts with the network alias used for the tunnel.

    If mode=local (or no config), do nothing — local postgres is started via
    the 'local-db' compose profile by the user.
    """
    config = _read_db_config()
    mode = config.get("mode", "local")
    if mode not in ("remote", "remote_direct"):
        return
    host = config.get("remote_db_host", "")
    if not host:
        return

    # Defense in depth: kill any leftover local rag-postgres container BEFORE
    # touching the tunnel. _ensure_remote_* already calls this internally,
    # but re-doing it here makes the enforcement obvious and gives us a clean
    # log line for diagnostics.
    try:
        c = docker_client.containers.get("rag-postgres")
        if c.image.tags and any("pgvector" in t or "postgres" in t for t in c.image.tags):
            logger.warning(
                "[auto-start-db] mode=%s but local rag-postgres (%s) is %s — removing.",
                mode, c.image.tags[0], c.status,
            )
            _remove_container("rag-postgres")
    except docker.errors.NotFound:
        pass
    except Exception as e:
        logger.warning("[auto-start-db] cleanup check failed: %s", e)

    if mode == "remote_direct":
        logger.info("[auto-start-db] mode=remote_direct, host=%s — ensuring direct proxy...", host)
        result = _ensure_remote_direct(config)
    else:
        logger.info("[auto-start-db] mode=remote, host=%s — ensuring SSH tunnel...", host)
        result = _ensure_remote_tunnel(config)

    if result.get("ok"):
        if result.get("already_running"):
            logger.info("[auto-start-db] Proxy already running")
        else:
            logger.info("[auto-start-db] Proxy created and healthy")
    else:
        logger.error("[auto-start-db] Failed to start: %s", result.get("error"))


def _enforce_db_mode_loop():
    """Periodically re-assert remote-mode invariants.

    Without this, a `docker compose up -d` from another shell (or the dashboard
    Services panel hitting the wrong button) can re-spawn the local
    rag-postgres pgvector container, which then steals the network alias from
    rag-db-tunnel and breaks every service's DB connection. The loop checks
    every 60s and removes the local container when remote mode is active.
    """
    import time
    while True:
        time.sleep(60)
        try:
            config = _read_db_config()
            mode = config.get("mode", "local")
            if mode not in ("remote", "remote_direct"):
                continue
            try:
                c = docker_client.containers.get("rag-postgres")
            except docker.errors.NotFound:
                continue
            # Only target the real pgvector image — never touch our own
            # rag-db-tunnel sidecar (which uses an alpine/socat image and has
            # the rag-postgres alias, but a different container name).
            tags = c.image.tags or []
            if any("pgvector" in t or "/postgres" in t for t in tags):
                logger.warning(
                    "[db-mode-enforcer] mode=%s but local rag-postgres re-appeared (%s, %s) — removing.",
                    mode, tags[0] if tags else "?", c.status,
                )
                _remove_container("rag-postgres")
                # After removing, re-ensure the tunnel/proxy is healthy.
                if mode == "remote_direct":
                    _ensure_remote_direct(config)
                else:
                    _ensure_remote_tunnel(config)
        except Exception as e:
            logger.warning("[db-mode-enforcer] tick failed: %s", e)


# Run auto-start on import (container-logs startup).
try:
    _auto_start_db()
except Exception as e:
    logger.error("[auto-start-db] Unexpected error: %s", e)

# Spawn the periodic enforcer in a daemon thread (won't block shutdown).
try:
    import threading
    threading.Thread(target=_enforce_db_mode_loop, name="db-mode-enforcer",
                     daemon=True).start()
    logger.info("[db-mode-enforcer] background thread started (60s interval)")
except Exception as e:
    logger.error("[db-mode-enforcer] failed to start: %s", e)


def _update_env_file(config: dict):
    """Update .env file with remote DB variables."""
    if not os.path.exists(ENV_FILE):
        return

    lines = []
    with open(ENV_FILE, "r") as f:
        lines = f.readlines()

    env_map = {
        "REMOTE_DB_HOST": config.get("remote_db_host", ""),
        "REMOTE_DB_SSH_USER": config.get("remote_db_ssh_user", "azureuser"),
        "REMOTE_DB_SSH_KEY": config.get("remote_db_ssh_key", "remote_db.pem"),
        "REMOTE_DB_PORT": str(config.get("remote_db_port", 5432)),
        "REMOTE_DB_USER": config.get("remote_db_user", "app"),
        "REMOTE_DB_PASSWORD": config.get("remote_db_password", ""),
    }

    # Update existing lines or uncomment them
    updated_keys = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        matched = False
        for key, val in env_map.items():
            if stripped.startswith(f"{key}=") or stripped.startswith(f"# {key}="):
                new_lines.append(f"{key}={val}\n")
                updated_keys.add(key)
                matched = True
                break
        if not matched:
            new_lines.append(line)

    # Append any keys not found
    for key, val in env_map.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={val}\n")

    with open(ENV_FILE, "w") as f:
        f.writelines(new_lines)


@app.get("/db/config")
def get_db_config():
    """Get current database configuration and mode."""
    mode = _detect_db_mode()
    config = _read_db_config()
    # Check tunnel and postgres container status
    tunnel_status = "not_found"
    postgres_status = "not_found"
    try:
        c = docker_client.containers.get("rag-db-tunnel")
        tunnel_status = c.status
    except docker.errors.NotFound:
        pass
    except Exception as e:
        tunnel_status = f"error: {e}"
    try:
        c = docker_client.containers.get("rag-postgres")
        postgres_status = c.status
    except docker.errors.NotFound:
        pass
    except Exception as e:
        postgres_status = f"error: {e}"

    return {
        "mode": mode,
        "config": config,
        "containers": {
            "db_tunnel": tunnel_status,
            "postgres": postgres_status,
        },
    }


@app.post("/db/config")
def save_db_config(body: DbConfigBody):
    """Save remote database configuration."""
    config = body.model_dump()
    _write_db_config(config)
    _update_env_file(config)
    return {"ok": True, "config": config}


class RemoteDbToggleBody(PydanticBaseModel):
    enabled: bool
    config: DbConfigBody


@app.post("/db/toggle-remote")
def toggle_remote_db(body: RemoteDbToggleBody):
    """Toggle remote database settings by commenting/uncommenting .env variables."""
    if not os.path.exists(ENV_FILE):
        return {"ok": False, "error": ".env file not found"}

    try:
        lines = []
        with open(ENV_FILE, "r") as f:
            lines = f.readlines()

        remote_db_vars = [
            "REMOTE_DB_HOST", "REMOTE_DB_SSH_USER", "REMOTE_DB_SSH_KEY",
            "REMOTE_DB_PORT", "REMOTE_DB_USER", "REMOTE_DB_PASSWORD"
        ]

        new_lines = []
        updated = False

        for line in lines:
            line_modified = False
            stripped_line = line.strip()

            for var_name in remote_db_vars:
                if body.enabled:
                    # Uncomment: remove leading # and optional space from commented remote DB vars
                    if (stripped_line.startswith(f"# {var_name}=") or
                        stripped_line.startswith(f"#{var_name}=")):
                        # Remove comment markers, preserve original spacing
                        if f"# {var_name}=" in line:
                            uncommented = line.replace(f"# {var_name}=", f"{var_name}=", 1)
                        else:
                            uncommented = line.replace(f"#{var_name}=", f"{var_name}=", 1)
                        new_lines.append(uncommented)
                        line_modified = True
                        updated = True
                        break
                else:
                    # Comment: add # to active remote DB vars (only if not already commented)
                    if (stripped_line.startswith(f"{var_name}=") and
                        not stripped_line.startswith("#")):
                        # Add comment, preserve indentation
                        indent = line[:len(line) - len(line.lstrip())]
                        content = line.lstrip()
                        commented = f"{indent}# {content}"
                        new_lines.append(commented)
                        line_modified = True
                        updated = True
                        break

            if not line_modified:
                new_lines.append(line)

        # If enabling and we have config values, make sure they're set
        if body.enabled and updated:
            config_dict = body.config.model_dump()
            _update_env_file(config_dict)
        elif updated:
            # Write the commented version
            with open(ENV_FILE, "w") as f:
                f.writelines(new_lines)

        return {"ok": True, "enabled": body.enabled, "updated": updated}

    except Exception as e:
        return {"ok": False, "error": str(e)}


def _remove_container(name: str, stop: bool = True):
    """Remove a container by name, optionally stopping it first."""
    try:
        c = docker_client.containers.get(name)
        if stop and c.status == "running":
            c.stop(timeout=10)
        c.remove(force=True)
        return True
    except docker.errors.NotFound:
        return False
    except Exception:
        return False


def _get_host_project_dir() -> str:
    """Get the host-side path for the project directory.

    Inside the container, PROJECT_DIR is /project (bind-mounted).
    We need the actual host path for creating sibling containers.
    """
    try:
        me = docker_client.containers.get(os.environ.get("HOSTNAME", "container-logs"))
        for m in me.attrs.get("Mounts", []):
            if m.get("Destination") == "/project":
                return m["Source"]
    except Exception:
        pass
    # Fallback: check env or use /project
    return os.environ.get("HOST_PROJECT_DIR", PROJECT_DIR)


@app.post("/db/switch/{mode}")
def switch_db_mode(mode: str):
    """Switch between local, remote (SSH tunnel), and remote_direct (SSL) modes."""
    import time

    if mode not in ("local", "remote", "remote_direct"):
        return {"ok": False, "error": "mode must be 'local', 'remote', or 'remote_direct'"}

    if mode == "remote":
        config = _read_db_config()
        result = _ensure_remote_tunnel(config)
        if result.get("ok"):
            config["mode"] = "remote"
            _write_db_config(config)
            return {"ok": True, "mode": "remote",
                    "output": "SSH tunnel healthy" if not result.get("already_running")
                              else "Tunnel already running"}
        return {"ok": False, "mode": mode, "error": result.get("error", "Unknown error")}

    if mode == "remote_direct":
        config = _read_db_config()
        result = _ensure_remote_direct(config)
        if result.get("ok"):
            config["mode"] = "remote_direct"
            _write_db_config(config)
            return {"ok": True, "mode": "remote_direct",
                    "output": "Direct SSL proxy healthy" if not result.get("already_running")
                              else "Direct proxy already running"}
        return {"ok": False, "mode": mode, "error": result.get("error", "Unknown error")}

    else:
        # ── Switch to local ────────────────────────────────────────────
        _remove_container("rag-db-tunnel")
        _remove_container("rag-wait-for-db", stop=False)

        # Persist local mode preference.
        config = _read_db_config()
        config["mode"] = "local"
        _write_db_config(config)

        # Bring local postgres back up
        compose_base = os.path.join(PROJECT_DIR, "docker-compose.yml")
        try:
            result = subprocess.run(
                ["docker", "compose", "-p", COMPOSE_PROJECT,
                 "--profile", "local-db",
                 "-f", compose_base,
                 "up", "-d", "rag-postgres", "wait-for-db"],
                capture_output=True, text=True, timeout=120, cwd=PROJECT_DIR,
            )
            if result.returncode != 0:
                return {"ok": False, "error": result.stderr or result.stdout, "mode": mode}
            return {"ok": True, "mode": "local", "output": "Local postgres restored"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "Timed out starting local postgres", "mode": mode}
        except Exception as e:
            return {"ok": False, "error": str(e), "mode": mode}


@app.post("/db/test-connection")
def test_db_connection():
    """Test the current database connection by checking if rag-postgres:5432 is reachable.

    Returns the underlying host (real IP for remote / direct modes, "rag-postgres
    container" for local) so the operator can confirm at a glance which DB they
    are actually pointed at.
    """
    import socket
    mode = _detect_db_mode()
    config = _read_db_config()

    # Compose the human label and the underlying host that explains where the
    # rag-postgres docker hostname actually resolves to in this mode.
    if mode == "remote":
        remote_host = config.get("remote_db_host", "?")
        remote_port = config.get("remote_db_port", 5432)
        target = f"{remote_host}:{remote_port} (via SSH tunnel — rag-db-tunnel)"
    elif mode == "remote_direct":
        remote_host = config.get("remote_db_host", "?")
        remote_port = config.get("remote_db_port", 5432)
        target = f"{remote_host}:{remote_port} (direct SSL)"
    else:
        target = "rag-postgres container (local Postgres)"

    try:
        # Try connecting to the postgres port via the expected hostname inside
        # the agents_net network. In remote modes that hostname routes through
        # the rag-db-tunnel sidecar; in local mode it hits the rag-postgres
        # container directly.
        sock = socket.create_connection(("rag-postgres", 5432), timeout=5)
        sock.close()
        return {
            "ok": True,
            "mode": mode,
            "target": target,
            "message": f"Connected to {target}",
        }
    except socket.timeout:
        return {"ok": False, "mode": mode, "target": target,
                "error": f"Connection timed out reaching {target}"}
    except socket.error as e:
        return {"ok": False, "mode": mode, "target": target,
                "error": f"{e} (target: {target})"}


@app.post("/db/preflight")
def preflight_remote():
    """Pre-flight check: test SSH + DB connectivity to remote VPS.

    Checks SSH key, SSH connectivity, port 22 reachability, and PostgreSQL access.
    """
    import time

    checks = {
        "ssh_key": {"status": "pending", "detail": ""},
        "ssh_connect": {"status": "pending", "detail": ""},
        "tunnel_container": {"status": "pending", "detail": ""},
        "tcp_5432": {"status": "pending", "detail": ""},
        "postgres_ready": {"status": "pending", "detail": ""},
    }

    compose_base = os.path.join(PROJECT_DIR, "docker-compose.yml")
    compose_remote = os.path.join(PROJECT_DIR, "docker-compose.remote-db.yml")
    config = _read_db_config()
    host = config.get("remote_db_host", "")
    ssh_user = config.get("remote_db_ssh_user", "azureuser")
    ssh_key_name = config.get("remote_db_ssh_key", "remote_db.pem")
    ssh_key_path = os.path.join(PROJECT_DIR, "ssh-keys", ssh_key_name)

    # ── Check 1: SSH key exists ──
    if not host:
        checks["ssh_key"] = {"status": "fail", "detail": "No REMOTE_DB_HOST configured"}
        return {"ok": False, "checks": checks}

    if not os.path.exists(ssh_key_path):
        checks["ssh_key"] = {"status": "fail", "detail": f"SSH key not found: ssh-keys/{ssh_key_name}"}
        return {"ok": False, "checks": checks}
    checks["ssh_key"] = {"status": "pass", "detail": f"SSH key found: ssh-keys/{ssh_key_name}"}

    # ── Check 2: SSH connectivity test ──
    try:
        ssh_cmd = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-i", ssh_key_path,
            f"{ssh_user}@{host}",
            "echo ssh_ok",
        ]
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0 and "ssh_ok" in result.stdout:
            checks["ssh_connect"] = {"status": "pass", "detail": f"SSH to {ssh_user}@{host} succeeded"}
        else:
            err = (result.stderr or result.stdout or "unknown error").strip()[-200:]
            checks["ssh_connect"] = {"status": "fail", "detail": f"SSH failed: {err}"}
            return {"ok": False, "checks": checks}
    except subprocess.TimeoutExpired:
        checks["ssh_connect"] = {"status": "fail", "detail": f"SSH to {host} timed out (10s)"}
        return {"ok": False, "checks": checks}
    except Exception as e:
        checks["ssh_connect"] = {"status": "fail", "detail": str(e)}
        return {"ok": False, "checks": checks}

    # ── Check 3: Start db-tunnel container (only) ──
    was_running = False
    try:
        c = docker_client.containers.get("rag-db-tunnel")
        if c.status == "running":
            was_running = True
            checks["tunnel_container"] = {"status": "pass", "detail": "Already running"}
        else:
            c.start()
            time.sleep(8)
            c.reload()
            if c.status == "running":
                checks["tunnel_container"] = {"status": "pass", "detail": "Started for preflight"}
            else:
                checks["tunnel_container"] = {"status": "fail", "detail": f"Container status: {c.status}"}
                return {"ok": False, "checks": checks}
    except docker.errors.NotFound:
        # Container doesn't exist — create via compose
        try:
            result = subprocess.run(
                [
                    "docker", "compose", "-p", COMPOSE_PROJECT,
                    "-f", compose_base,
                    "-f", compose_remote,
                    "up", "-d", "db-tunnel",
                ],
                capture_output=True, text=True, timeout=60, cwd=PROJECT_DIR,
            )
            if result.returncode != 0:
                checks["tunnel_container"] = {"status": "fail", "detail": result.stderr[:300]}
                return {"ok": False, "checks": checks}
            time.sleep(10)
            checks["tunnel_container"] = {"status": "pass", "detail": "Created and started for preflight"}
        except Exception as e:
            checks["tunnel_container"] = {"status": "fail", "detail": str(e)}
            return {"ok": False, "checks": checks}
    except Exception as e:
        checks["tunnel_container"] = {"status": "fail", "detail": str(e)}
        return {"ok": False, "checks": checks}

    # ── Check 4: TCP port 5432 reachable through tunnel ──
    import socket
    try:
        # db-tunnel has alias rag-postgres, so check that
        sock = socket.create_connection(("rag-db-tunnel", 5432), timeout=8)
        sock.close()
        checks["tcp_5432"] = {"status": "pass", "detail": "TCP localhost:5432 open through SSH tunnel"}
    except Exception:
        # Also try via the alias
        try:
            sock = socket.create_connection(("rag-postgres", 5432), timeout=5)
            sock.close()
            checks["tcp_5432"] = {"status": "pass", "detail": "TCP rag-postgres:5432 open through SSH tunnel"}
        except Exception as e:
            checks["tcp_5432"] = {"status": "fail", "detail": f"Cannot reach port 5432 through tunnel: {e}"}

    # ── Check 5: PostgreSQL responding ──
    if checks["tcp_5432"]["status"] == "pass":
        checks["postgres_ready"] = {"status": "pass", "detail": "PostgreSQL port reachable through SSH tunnel"}
    else:
        checks["postgres_ready"] = {"status": "fail", "detail": "Cannot verify — tunnel port 5432 not reachable"}

    # ── Cleanup: stop tunnel if we started it and we're still in local mode ──
    if not was_running:
        try:
            c = docker_client.containers.get("rag-db-tunnel")
            c.stop(timeout=5)
            logger.info("Preflight: stopped db-tunnel container after checks")
        except Exception:
            pass

    all_pass = all(c["status"] == "pass" for c in checks.values())
    return {"ok": all_pass, "checks": checks}


# ── Health Diagnostics — scan container logs for errors ──────────────

import re

ERROR_PATTERNS = [
    re.compile(r"(?i)\b(error|fatal|exception|traceback|panic|segfault|oom|killed)\b"),
    re.compile(r"(?i)(failed to|cannot connect|connection refused|permission denied)"),
    re.compile(r"(?i)(out of memory|no space left|disk full)"),
    re.compile(r"(?i)(timeout|timed out|deadline exceeded)"),
]

# Patterns to exclude (noisy, expected, or non-errors)
IGNORE_PATTERNS = [
    re.compile(r"(?i)(error_page|error\.html|error_log|on_error|error_handler|errorhandler)"),
    re.compile(r"(?i)(no error|error.{0,3}(=\s*nil|:\s*none|count:\s*0))"),
    re.compile(r"(?i)loglevel|log.level|error.level"),
    re.compile(r"(?i)200 ok"),
    re.compile(r"(?i)health.*200"),
]


@app.get("/diagnostics/errors")
def scan_container_errors(
    tail: int = Query(200, ge=10, le=2000),
    since_minutes: int = Query(30, ge=1, le=1440),
):
    """Scan all running containers for recent error lines in their logs."""
    from datetime import timezone, timedelta

    since_dt = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    results = []

    try:
        containers = docker_client.containers.list()
    except Exception as e:
        return {"ok": False, "error": str(e), "containers": []}

    for container in containers:
        name = container.name
        try:
            log_bytes = container.logs(
                tail=tail,
                since=since_dt,
                timestamps=True,
            )
            log_text = log_bytes.decode(errors="replace")
            lines = log_text.strip().split("\n")

            error_lines = []
            for line in lines:
                if not line.strip():
                    continue
                # Check if line matches any error pattern
                matched = False
                for pat in ERROR_PATTERNS:
                    if pat.search(line):
                        matched = True
                        break
                if not matched:
                    continue
                # Check if it's a false positive
                ignored = False
                for ipat in IGNORE_PATTERNS:
                    if ipat.search(line):
                        ignored = True
                        break
                if ignored:
                    continue
                # Extract timestamp if present (Docker log format: 2026-03-17T...)
                ts = None
                if len(line) > 30 and line[0:4].isdigit():
                    ts = line[:30].strip()
                    msg = line[31:].strip()
                else:
                    msg = line.strip()
                error_lines.append({
                    "timestamp": ts,
                    "message": msg[:500],  # cap length
                })

            if error_lines:
                results.append({
                    "container": name,
                    "status": container.status,
                    "error_count": len(error_lines),
                    "errors": error_lines[-20:],  # last 20 errors per container
                })
        except Exception as e:
            results.append({
                "container": name,
                "status": container.status,
                "error_count": -1,
                "errors": [{"timestamp": None, "message": f"Failed to read logs: {e}"}],
            })

    # Sort by error count descending
    results.sort(key=lambda x: x["error_count"], reverse=True)

    total_errors = sum(r["error_count"] for r in results if r["error_count"] > 0)
    containers_with_errors = len([r for r in results if r["error_count"] > 0])

    return {
        "ok": True,
        "scanned": len(containers),
        "since_minutes": since_minutes,
        "tail_lines": tail,
        "total_errors": total_errors,
        "containers_with_errors": containers_with_errors,
        "containers": results,
    }


# ── Database comparison for pre-switch sync ─────────────────────────

SYNC_TABLES = [
    "assets", "ports", "vulns", "web_findings", "recon_findings",
    "finding_activity", "evidence_store", "credential_vault",
    "campaign_events", "engagements",
]


def _query_db_stats(host: str, port: int, user: str, password: str, dbname: str = "scans") -> dict:
    """Query row counts and latest modified_at per sync table."""
    import psycopg2
    import psycopg2.extras
    stats = {}
    try:
        conn = psycopg2.connect(
            host=host, port=port, user=user, password=password,
            dbname=dbname, connect_timeout=10,
        )
        conn.set_session(readonly=True)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        for table in SYNC_TABLES:
            try:
                cur.execute(f"SELECT count(*) AS cnt FROM {table}")
                cnt = cur.fetchone()["cnt"]
                latest = None
                try:
                    cur.execute(f"SELECT max(modified_at)::text AS latest FROM {table}")
                    row = cur.fetchone()
                    latest = row["latest"] if row else None
                except Exception:
                    conn.rollback()
                stats[table] = {"count": cnt, "latest_modified": latest}
            except Exception:
                conn.rollback()
                stats[table] = {"count": 0, "latest_modified": None, "error": "table not found"}
        # Sync log stats
        try:
            cur.execute("SELECT COALESCE(max(lsn), 0) AS max_lsn, count(*) AS log_entries FROM sync_log")
            row = cur.fetchone()
            sync_info = {"max_lsn": row["max_lsn"], "log_entries": row["log_entries"]}
        except Exception:
            sync_info = {"max_lsn": 0, "log_entries": 0}
        cur.close()
        conn.close()
        return {"ok": True, "tables": stats, "sync": sync_info}
    except Exception as e:
        return {"ok": False, "error": str(e), "tables": {}, "sync": {}}


@app.post("/db/sync-push")
def sync_push_to_remote():
    """Push local DB changes to remote DB via SSH tunnel.

    1. Connects to local postgres
    2. Reads sync_log changes
    3. Connects to remote via ssh-tunnel
    4. Applies changes with ON CONFLICT upsert
    """
    import psycopg2
    import psycopg2.extras

    config = _read_db_config()
    db_user = config.get("remote_db_user") or "app"
    db_password = config.get("remote_db_password") or ""
    remote_host = config.get("remote_db_host") or ""
    if not remote_host:
        return {"ok": False, "error": "No remote_db_host configured"}

    # Determine remote DB connection — use ssh-tunnel or rag-db-tunnel
    remote_dsn_host = None
    for name in ("ssh-tunnel", "rag-db-tunnel"):
        try:
            c = docker_client.containers.get(name)
            if c.status == "running":
                # Get IP on agents_net
                nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                for net_info in nets.values():
                    ip = net_info.get("IPAddress")
                    if ip:
                        remote_dsn_host = ip
                        break
                if remote_dsn_host:
                    break
        except Exception:
            continue

    if not remote_dsn_host:
        return {"ok": False, "error": "No SSH tunnel running. Start the tunnel first."}

    # Connect to local postgres
    local_host = None
    try:
        c = docker_client.containers.get("rag-postgres")
        if c.status == "running":
            nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
            for net_info in nets.values():
                ip = net_info.get("IPAddress")
                if ip:
                    local_host = ip
                    break
    except Exception:
        pass
    if not local_host:
        return {"ok": False, "error": "Local postgres is not running"}

    try:
        local_conn = psycopg2.connect(
            host=local_host, port=5432, user=db_user, password=db_password,
            dbname="scans", connect_timeout=10,
        )
        local_cur = local_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get last push watermark
        local_cur.execute("""
            SELECT last_lsn FROM sync_state
            WHERE node_id = 'local' AND direction = 'push'
        """)
        wm_row = local_cur.fetchone()
        last_push_lsn = wm_row["last_lsn"] if wm_row else 0

        # Get changes from sync_log since last push
        local_cur.execute("""
            SELECT lsn, table_name, operation, row_id, row_data
            FROM sync_log WHERE lsn > %s
            ORDER BY lsn LIMIT 50000
        """, (last_push_lsn,))
        changes = local_cur.fetchall()

        if not changes:
            local_cur.close()
            local_conn.close()
            return {"ok": True, "message": "Nothing to push — all changes already synced", "pushed": 0}

        # Connect to remote via tunnel
        remote_conn = psycopg2.connect(
            host=remote_dsn_host, port=5432, user=db_user, password=db_password,
            dbname="scans", connect_timeout=10,
        )
        remote_cur = remote_conn.cursor()

        applied = 0
        errors = 0
        for change in changes:
            table = change["table_name"]
            op = change["operation"]
            row_data = change.get("row_data") or {}
            row_id = change.get("row_id", "")

            try:
                if op in ("INSERT", "UPDATE") and row_data and isinstance(row_data, dict):
                    cols = list(row_data.keys())
                    # Wrap dict/list values in Json() for JSONB columns
                    vals = []
                    for c in cols:
                        v = row_data[c]
                        if isinstance(v, (dict, list)):
                            vals.append(psycopg2.extras.Json(v))
                        else:
                            vals.append(v)
                    placeholders = ", ".join(["%s"] * len(cols))
                    col_names = ", ".join(f'"{c}"' for c in cols)
                    on_conflict = ", ".join(f'"{c}" = EXCLUDED."{c}"' for c in cols if c != "id")
                    if on_conflict:
                        remote_cur.execute(
                            f'INSERT INTO {table} ({col_names}) VALUES ({placeholders}) '
                            f'ON CONFLICT (id) DO UPDATE SET {on_conflict}',
                            vals,
                        )
                    else:
                        remote_cur.execute(
                            f'INSERT INTO {table} ({col_names}) VALUES ({placeholders}) ON CONFLICT DO NOTHING',
                            vals,
                        )
                    applied += 1
                elif op == "DELETE" and row_id:
                    remote_cur.execute(f"DELETE FROM {table} WHERE id = %s", (row_id,))
                    applied += 1
            except Exception as row_err:
                errors += 1
                remote_conn.rollback()
                if errors <= 3:
                    logging.warning(f"[sync-push] Row error ({table}/{op}): {row_err}")
                continue

        remote_conn.commit()
        remote_cur.close()
        remote_conn.close()

        # Advance the local push watermark so these changes aren't re-pushed
        max_lsn = changes[-1]["lsn"] if changes else last_push_lsn
        try:
            local_conn2 = psycopg2.connect(
                host=local_host, port=5432, user=db_user, password=db_password,
                dbname="scans", connect_timeout=10,
            )
            local_cur2 = local_conn2.cursor()
            local_cur2.execute("""
                INSERT INTO sync_state (node_id, direction, last_lsn, last_sync_at)
                VALUES ('local', 'push', %s, now())
                ON CONFLICT (node_id, direction)
                DO UPDATE SET last_lsn = EXCLUDED.last_lsn, last_sync_at = now()
            """, (max_lsn,))
            local_conn2.commit()
            local_cur2.close()
            local_conn2.close()
            logging.info(f"[sync-push] Watermark advanced to LSN {max_lsn}")
        except Exception as wm_err:
            logging.warning(f"[sync-push] Failed to update watermark: {wm_err}")

        return {
            "ok": True,
            "message": f"Pushed {applied} changes to remote DB ({errors} errors)",
            "pushed": applied,
            "errors": errors,
            "total_changes": len(changes),
            "max_lsn": max_lsn,
        }

    except Exception as e:
        logging.error(f"[sync-push] Failed: {e}")
        return {"ok": False, "error": str(e)}


@app.post("/db/sync-schema")
def sync_schema_to_remote():
    """Apply the local schema (ensure_all_tables.sql) to the remote database.

    Reads the schema SQL from /project/db_init/ensure_all_tables.sql and
    executes it against the remote DB via the SSH tunnel. Safe to run
    multiple times — all statements use IF NOT EXISTS / ADD COLUMN IF NOT EXISTS.
    """
    import psycopg2

    schema_path = os.path.join(PROJECT_DIR, "db_init", "ensure_all_tables.sql")
    if not os.path.exists(schema_path):
        return {"ok": False, "error": f"Schema file not found: {schema_path}"}

    with open(schema_path, "r") as f:
        schema_sql = f.read()

    config = _read_db_config()
    db_user = config.get("remote_db_user") or "app"
    db_password = config.get("remote_db_password") or ""

    # Find remote DB via tunnel
    remote_dsn_host = None
    for name in ("ssh-tunnel", "rag-db-tunnel"):
        try:
            c = docker_client.containers.get(name)
            if c.status == "running":
                nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                for net_info in nets.values():
                    ip = net_info.get("IPAddress")
                    if ip:
                        remote_dsn_host = ip
                        break
                if remote_dsn_host:
                    break
        except Exception:
            continue

    if not remote_dsn_host:
        return {"ok": False, "error": "No SSH tunnel running. Start the tunnel first."}

    try:
        remote_conn = psycopg2.connect(
            host=remote_dsn_host, port=5432, user=db_user, password=db_password,
            dbname="scans", connect_timeout=15,
        )
        remote_conn.autocommit = True
        remote_cur = remote_conn.cursor()

        # Count tables before
        remote_cur.execute(
            "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'"
        )
        tables_before = remote_cur.fetchone()[0]

        # Execute schema
        remote_cur.execute(schema_sql)

        # Count tables after
        remote_cur.execute(
            "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'"
        )
        tables_after = remote_cur.fetchone()[0]

        remote_cur.close()
        remote_conn.close()

        tables_added = tables_after - tables_before
        logging.info(
            f"[sync-schema] Applied schema to remote: {tables_before} → {tables_after} tables (+{tables_added})"
        )

        return {
            "ok": True,
            "message": f"Schema applied to remote DB. Tables: {tables_before} → {tables_after} (+{tables_added} new)",
            "tables_before": tables_before,
            "tables_after": tables_after,
            "tables_added": tables_added,
        }

    except Exception as e:
        logging.error(f"[sync-schema] Failed: {e}")
        return {"ok": False, "error": str(e)}


@app.get("/db/compare")
def compare_databases():
    """Compare local and remote database row counts and timestamps.

    Connects to both databases and returns side-by-side stats for all sync tables.
    If in local mode, starts a temporary tunnel for the remote query.
    """
    import time

    config = _read_db_config()
    db_user = config.get("remote_db_user") or "app"
    db_password = config.get("remote_db_password") or ""
    mode = _detect_db_mode()

    # ── Get local DB stats ─────────────────────────────────────────
    started_local_pg = False
    if mode == "local":
        local_host = "rag-postgres"
    else:
        # In remote mode, local postgres may be stopped. Try to find it or start it temporarily.
        local_host = None
        try:
            c = docker_client.containers.get("rag-postgres")
            if c.status != "running":
                try:
                    c.start()
                    started_local_pg = True
                    for _ in range(10):
                        c.reload()
                        if c.status == "running":
                            break
                        time.sleep(2)
                    time.sleep(3)
                except Exception as start_err:
                    logging.warning(f"[db/compare] Could not start local postgres: {start_err}")
                    # Local postgres can't start (volume mounts missing, etc.)
                    # Skip local stats — this is expected in remote mode
                    local_host = None
            if c.status == "running":
                nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                for net_info in nets.values():
                    ip = net_info.get("IPAddress")
                    if ip:
                        local_host = ip
                        break
                if not local_host:
                    c.reload()
                    nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                    for net_info in nets.values():
                        ip = net_info.get("IPAddress")
                        if ip:
                            local_host = ip
                            break
        except docker.errors.NotFound:
            # Need to create local postgres via compose
            try:
                result = subprocess.run(
                    ["docker", "compose", "-p", COMPOSE_PROJECT,
                     "-f", os.path.join(PROJECT_DIR, "docker-compose.yml"),
                     "up", "-d", "rag-postgres"],
                    capture_output=True, text=True, timeout=60, cwd=PROJECT_DIR,
                )
                started_local_pg = True
                time.sleep(8)
                try:
                    c = docker_client.containers.get("rag-postgres")
                    c.reload()
                    nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                    for net_info in nets.values():
                        ip = net_info.get("IPAddress")
                        if ip:
                            local_host = ip
                            break
                except Exception:
                    pass
            except Exception:
                pass

    local_stats: dict
    if local_host:
        try:
            local_stats = _query_db_stats(local_host, 5432, db_user, db_password)
        except Exception as e:
            local_stats = {"ok": False, "error": f"Local DB query failed: {e}", "tables": {}, "sync": {}}
    else:
        local_stats = {"ok": False, "error": "Local postgres not available (expected in remote mode)", "tables": {}, "sync": {}}

    # ── Get remote DB stats ────────────────────────────────────────
    cleanup_tunnel = False
    if mode == "remote":
        # Tunnel is already running — query through it
        remote_host = "rag-db-tunnel"
        remote_stats = _query_db_stats(remote_host, 5432, db_user, db_password)
    else:
        # Need a temporary tunnel to reach remote DB
        # Check if tunnel already exists (e.g. from preflight)
        tunnel_existed = False
        try:
            c = docker_client.containers.get("rag-db-tunnel")
            if c.status == "running":
                tunnel_existed = True
        except docker.errors.NotFound:
            pass

        if not tunnel_existed:
            # Create temporary tunnel
            ssh_key_name = config.get("remote_db_ssh_key", "remote_db.pem")
            remote_db_host = config.get("remote_db_host", "")
            remote_ssh_user = config.get("remote_db_ssh_user", "azureuser")
            remote_db_port = str(config.get("remote_db_port", "5432"))

            if not remote_db_host:
                return {
                    "ok": False, "error": "No remote DB host configured",
                    "local": local_stats, "remote": None, "mode": mode,
                }

            host_project = _get_host_project_dir()
            host_ssh_keys = f"{host_project}/ssh-keys"

            ssh_cmd = (
                f"apk add --no-cache openssh-client && "
                f"cp /ssh-keys/{ssh_key_name} /tmp/ssh_key && chmod 600 /tmp/ssh_key && "
                f"exec ssh -N -o StrictHostKeyChecking=no "
                f"-o ServerAliveInterval=30 -o ServerAliveCountMax=3 "
                f"-o ExitOnForwardFailure=yes "
                f"-i /tmp/ssh_key "
                f"-L 0.0.0.0:5432:localhost:{remote_db_port} "
                f"{remote_ssh_user}@{remote_db_host}"
            )
            try:
                # Use a different name so it doesn't conflict
                tunnel = docker_client.containers.run(
                    "alpine:3.20",
                    name="rag-db-tunnel-compare",
                    command=["/bin/sh", "-c", ssh_cmd],
                    detach=True,
                    volumes={host_ssh_keys: {"bind": "/ssh-keys", "mode": "ro"}},
                )
                # Connect to agents_net so we can reach it
                try:
                    net = docker_client.networks.get("agents_net")
                    net.connect(tunnel)
                except Exception:
                    pass
                cleanup_tunnel = True
                # Wait for tunnel to establish
                for _ in range(12):
                    tunnel.reload()
                    if tunnel.status != "running":
                        break
                    import socket
                    try:
                        sock = socket.create_connection(("rag-db-tunnel-compare", 5432), timeout=3)
                        sock.close()
                        break
                    except Exception:
                        time.sleep(5)
                remote_host = "rag-db-tunnel-compare"
            except Exception as e:
                # Clean up on failure
                try:
                    c = docker_client.containers.get("rag-db-tunnel-compare")
                    c.remove(force=True)
                except Exception:
                    pass
                return {
                    "ok": False, "error": f"Failed to create temp tunnel: {e}",
                    "local": local_stats, "remote": None, "mode": mode,
                }
        else:
            remote_host = "rag-db-tunnel"

        remote_stats = _query_db_stats(remote_host, 5432, db_user, db_password)

        # Clean up temporary tunnel
        if cleanup_tunnel:
            try:
                c = docker_client.containers.get("rag-db-tunnel-compare")
                c.remove(force=True)
            except Exception:
                pass

    # ── Build comparison ───────────────────────────────────────────
    comparison = []
    all_tables = set(list(local_stats.get("tables", {}).keys()) + list(remote_stats.get("tables", {}).keys()))
    for table in SYNC_TABLES:
        local_t = local_stats.get("tables", {}).get(table, {"count": 0, "latest_modified": None})
        remote_t = remote_stats.get("tables", {}).get(table, {"count": 0, "latest_modified": None})
        diff = (local_t.get("count", 0) or 0) - (remote_t.get("count", 0) or 0)
        comparison.append({
            "table": table,
            "local_count": local_t.get("count", 0),
            "remote_count": remote_t.get("count", 0),
            "diff": diff,
            "local_latest": local_t.get("latest_modified"),
            "remote_latest": remote_t.get("latest_modified"),
        })

    # ── Cleanup: stop local postgres if we started it temporarily ───
    if started_local_pg:
        try:
            c = docker_client.containers.get("rag-postgres")
            c.stop(timeout=10)
        except Exception:
            pass

    return {
        "ok": True,
        "mode": mode,
        "local": local_stats,
        "remote": remote_stats,
        "comparison": comparison,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8018)
