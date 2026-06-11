import httpx
import json
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from config import get_settings
from engagement import engagement_headers
from typing import Optional, Dict
from timeouts import TIMEOUT_NORMAL
import time
from utils import safe_json

router = APIRouter()

# db-config.json is bind-mounted from the host into this container at
# /app/db-config.json. If the host path was missing at the first
# `docker compose up`, Docker silently creates it as a *directory*, which makes
# every read return defaults and every write raise IsADirectoryError — surfacing
# as the misleading "remote_db_host not configured" on a DB mode switch.
DB_CONFIG_PATH = "/app/db-config.json"


def _db_config_path_problem() -> str:
    """Return a human-readable reason db-config.json is unusable, else ""."""
    if os.path.isdir(DB_CONFIG_PATH):
        return ("db-config.json is a DIRECTORY, not a file (Docker auto-created it "
                "because the host path was missing at compose-up). On the host: "
                "rmdir db-config.json && echo '{\"mode\":\"local\"}' > db-config.json, "
                "then recreate container-logs + pentest-dashboard.")
    return ""


async def _trigger_dsn_sync() -> dict:
    """Ask container-logs to rebuild DB_DSN from the just-saved config.

    Services authenticate via ${DB_DSN}; saving the config only rewrites
    db-config.json, so without this the new password/user never reaches the
    running stack. Best-effort — never fails the save.
    """
    try:
        s = get_settings()
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            r = await c.post(f"{s.container_logs_url}/db/sync-dsn")
            return r.json() if r.status_code < 400 else {"ok": False, "status": r.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


class ApiKeyBody(BaseModel):
    value: str = Field(..., min_length=1)


@router.get("/api/settings/keys")
async def list_api_keys():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/settings/keys",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.put("/api/settings/keys/{key_name}")
async def upsert_api_key(key_name: str, body: ApiKeyBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.put(
            f"{s.rag_api_url}/settings/keys/{key_name}",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


class ConfigBody(BaseModel):
    value: str


@router.get("/api/settings/config/{key_name}")
async def get_config_setting(key_name: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/settings/config/{key_name}",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
    if resp.status_code == 404:
        return {"key": key_name, "value": ""}
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.put("/api/settings/config/{key_name}")
async def put_config_setting(key_name: str, body: ConfigBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.put(f"{s.rag_api_url}/settings/config/{key_name}",
                           json={"value": body.value},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


class ProxyTestBody(BaseModel):
    proxy_url: str = Field(..., min_length=1)
    test_url: str = Field(default="https://httpbin.org/get")


class ExploitWatcherSettings(BaseModel):
    poll_interval: int = Field(default=60, ge=30, le=300, description="Poll interval in seconds")
    lookback_minutes: int = Field(default=4320, ge=60, le=10080, description="Lookback window in minutes")
    min_confidence: float = Field(default=0.35, ge=0.1, le=1.0, description="Minimum confidence threshold")
    max_exploits_per_vuln: int = Field(default=2, ge=1, le=10, description="Max exploits to queue per vulnerability")
    enabled: bool = Field(default=True, description="Enable/disable exploit watcher")


@router.get("/api/settings/exploit-watcher")
async def get_exploit_watcher_settings():
    """Get current exploit watcher configuration."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/settings/exploit-watcher",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
    if resp.status_code == 404:
        # Return defaults if not configured
        return ExploitWatcherSettings().model_dump()
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.put("/api/settings/exploit-watcher")
async def update_exploit_watcher_settings(settings: ExploitWatcherSettings):
    """Update exploit watcher configuration."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.put(f"{s.rag_api_url}/settings/exploit-watcher",
                           json=settings.model_dump(),
                           headers={"x-api-key": s.api_key, **engagement_headers()})
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.post("/api/settings/test-proxy")
async def test_proxy(body: ProxyTestBody):
    """Test connectivity through a proxy by making a request to a test URL."""
    start = time.time()
    try:
        async with httpx.AsyncClient(
            proxy=body.proxy_url,
            timeout=10,
            verify=False,
        ) as c:
            resp = await c.get(body.test_url)
            elapsed = round((time.time() - start) * 1000)
            return {
                "ok": True,
                "status_code": resp.status_code,
                "elapsed_ms": elapsed,
                "proxy_url": body.proxy_url,
                "test_url": body.test_url,
            }
    except httpx.ProxyError as e:
        elapsed = round((time.time() - start) * 1000)
        return {
            "ok": False,
            "error": f"Proxy error: {e}",
            "elapsed_ms": elapsed,
            "proxy_url": body.proxy_url,
        }
    except httpx.ConnectError as e:
        elapsed = round((time.time() - start) * 1000)
        return {
            "ok": False,
            "error": f"Connection refused — is the proxy running at {body.proxy_url}?",
            "elapsed_ms": elapsed,
            "proxy_url": body.proxy_url,
        }
    except Exception as e:
        elapsed = round((time.time() - start) * 1000)
        return {
            "ok": False,
            "error": str(e),
            "elapsed_ms": elapsed,
            "proxy_url": body.proxy_url,
        }


@router.delete("/api/settings/keys/{key_name}")
async def delete_api_key(key_name: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/settings/keys/{key_name}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── Database configuration (proxied to container-logs) ──


class DbConfigBody(BaseModel):
    remote_db_host: str = ""
    remote_db_ssh_user: str = "azureuser"
    remote_db_ssh_key: str = "remote_db.pem"
    remote_db_port: int = 5432
    remote_db_user: str = "app"
    remote_db_password: str = ""


@router.get("/api/settings/database")
async def get_db_config():
    """Get current database mode and configuration from mounted db-config.json."""
    try:
        # Read from mounted db-config.json file
        config_file_path = DB_CONFIG_PATH
        problem = _db_config_path_problem()
        if problem:
            return {"mode": "local", "config": {}, "containers": {}, "error": problem}
        if os.path.exists(config_file_path):
            with open(config_file_path, 'r') as f:
                db_config = json.load(f)

            # Tolerate both flat and nested shapes — commit 30a75a6 introduced
            # a nested {enabled, mode, config:{...}, metadata} form that was
            # later flattened in commit 58eb756. Defensive: handle either.
            flat = db_config.get("config") if isinstance(db_config.get("config"), dict) else db_config

            mode = db_config.get("mode", "local")
            if db_config.get("enabled") is False:
                mode = "local"

            return {
                "mode": mode,
                "config": {
                    "remote_db_host": flat.get("remote_db_host", ""),
                    "remote_db_ssh_user": flat.get("remote_db_ssh_user", "azureuser"),
                    "remote_db_ssh_key": flat.get("remote_db_ssh_key", "remote_db.pem"),
                    "remote_db_port": flat.get("remote_db_port", 5432),
                    "remote_db_user": flat.get("remote_db_user", "app"),
                    "remote_db_password": flat.get("remote_db_password", "")
                },
                "remote_enabled": mode != "local",
                "containers": {},  # Not used in new system
                "note": f"Configuration active via db-config.json (last modified: {db_config.get('metadata', {}).get('last_modified', 'unknown')})"
            }
        else:
            # Fallback if config file not found
            return {
                "mode": "local",
                "config": {
                    "remote_db_host": "",
                    "remote_db_ssh_user": "azureuser",
                    "remote_db_ssh_key": "remote_db.pem",
                    "remote_db_port": 5432,
                    "remote_db_user": "app",
                    "remote_db_password": ""
                },
                "remote_enabled": False,
                "containers": {},
                "note": "db-config.json not found, using defaults"
            }
    except json.JSONDecodeError as e:
        return {"mode": "local", "config": {}, "containers": {}, "error": f"Invalid JSON in db-config.json: {e}"}
    except Exception as e:
        return {"mode": "local", "config": {}, "containers": {}, "error": str(e)}


@router.post("/api/settings/database")
async def save_db_config(body: DbConfigBody):
    """Save remote database configuration to mounted db-config.json."""
    try:
        config_file_path = DB_CONFIG_PATH
        problem = _db_config_path_problem()
        if problem:
            return {"ok": False, "error": problem}

        # Read current configuration
        current_config = {}
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as f:
                    current_config = json.load(f)
            except json.JSONDecodeError:
                current_config = {}

        # Update configuration with flattened structure
        updated_config = {
            "enabled": current_config.get("enabled", False),  # Preserve current enabled state
            "mode": current_config.get("mode", "local"),      # Preserve current mode
            "remote_db_host": body.remote_db_host,
            "remote_db_ssh_user": body.remote_db_ssh_user,
            "remote_db_ssh_key": body.remote_db_ssh_key,
            "remote_db_port": body.remote_db_port,
            "remote_db_user": body.remote_db_user,
            "remote_db_password": body.remote_db_password,
            "metadata": {
                "last_modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "last_modified_by": "bff_settings_save",
                "note": "Configuration updated via Settings UI"
            }
        }

        # Write updated configuration
        with open(config_file_path, 'w') as f:
            json.dump(updated_config, f, indent=2)

        # Propagate credential changes into DB_DSN so running services pick them up.
        dsn_sync = await _trigger_dsn_sync()

        return {"ok": True, "message": "Database configuration saved successfully",
                "dsn_sync": dsn_sync}
    except Exception as e:
        return {"ok": False, "error": str(e)}


class RemoteDbToggleBody(BaseModel):
    enabled: bool
    config: DbConfigBody


@router.post("/api/settings/database/toggle-remote")
async def toggle_remote_db(body: RemoteDbToggleBody):
    """Toggle remote database settings using db-config.json with webhook emission."""
    s = get_settings()
    try:
        config_file_path = DB_CONFIG_PATH
        problem = _db_config_path_problem()
        if problem:
            return {"ok": False, "error": problem}

        # Read current configuration
        current_config = {}
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as f:
                    current_config = json.load(f)
            except json.JSONDecodeError:
                current_config = {}

        previous_mode = current_config.get("mode", "local")
        previous_enabled = current_config.get("enabled", False)

        # Update configuration with flattened structure
        updated_config = {
            "enabled": body.enabled,
            "mode": "remote" if body.enabled else "local",
            "remote_db_host": body.config.remote_db_host,
            "remote_db_ssh_user": body.config.remote_db_ssh_user,
            "remote_db_ssh_key": body.config.remote_db_ssh_key,
            "remote_db_port": body.config.remote_db_port,
            "remote_db_user": body.config.remote_db_user,
            "remote_db_password": body.config.remote_db_password,
            "metadata": {
                "last_modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "last_modified_by": "bff_toggle",
                "note": f"Remote database {'enabled' if body.enabled else 'disabled'} via Settings UI"
            }
        }

        # Write updated configuration
        with open(config_file_path, 'w') as f:
            json.dump(updated_config, f, indent=2)

        # Emit webhook for database mode change with audit logging
        webhook_success = False
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as c:
                payload = {
                    "event_type": "database_mode_changed",
                    "source": "settings",
                    "severity": "info",
                    "data": {
                        "enabled": body.enabled,
                        "mode": "remote" if body.enabled else "local",
                        "previous_mode": previous_mode,
                        "previous_enabled": previous_enabled,
                        "host": body.config.remote_db_host if body.enabled else "",
                        "config_provided": bool(body.config.remote_db_host),
                        "timestamp": "{{ now }}",
                        "user_action": f"Database mode changed to {'remote' if body.enabled else 'local'}",
                        "audit_note": "Configuration change completed via Settings UI",
                        "file_path": config_file_path
                    }
                }
                resp = await c.post(
                    f"{s.rag_api_url}/webhooks/emit",
                    json=payload,
                    headers={"x-api-key": s.api_key, **engagement_headers()}
                )
                webhook_success = resp.status_code < 400

                # Also log locally for immediate visibility
                import logging
                logger = logging.getLogger("database_config")
                logger.info(f"Database mode changed: {previous_enabled} -> {body.enabled}, mode: {previous_mode} -> {'remote' if body.enabled else 'local'} (host: {body.config.remote_db_host})")

        except Exception as e:
            # Log webhook failure but don't fail the operation
            import logging
            logger = logging.getLogger("database_config")
            logger.warning(f"Failed to emit database change webhook: {e}")

        # Propagate credential/mode change into DB_DSN for the running services.
        dsn_sync = await _trigger_dsn_sync()

        return {
            "ok": True,
            "enabled": body.enabled,
            "mode": "remote" if body.enabled else "local",
            "previous_mode": previous_mode,
            "webhook_sent": webhook_success,
            "config_updated": True,
            "dsn_sync": dsn_sync,
            "message": f"Remote database {'enabled' if body.enabled else 'disabled'} successfully",
            "audit_trail": f"Database mode change completed: {previous_mode} -> {'remote' if body.enabled else 'local'}"
        }

    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"Invalid JSON in db-config.json: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/api/settings/database/switch/{mode}")
async def switch_db_mode(mode: str):
    """Switch between local and remote database modes."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=180) as c:
            resp = await c.post(
                f"{s.container_logs_url}/db/switch/{mode}",
                timeout=150,
            )
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/api/settings/database/test")
async def test_db_connection():
    """Test the current database connection."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.post(f"{s.container_logs_url}/db/test-connection")
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/api/settings/database/preflight")
async def preflight_remote():
    """Pre-flight: test SSH tunnel + DB connectivity before switching."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=90) as c:
            resp = await c.post(
                f"{s.container_logs_url}/db/preflight",
                timeout=80,
            )
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/api/settings/database/compare")
async def compare_databases():
    """Compare local and remote database row counts and timestamps."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=120) as c:
            resp = await c.get(
                f"{s.container_logs_url}/db/compare",
                timeout=110,
            )
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── MCP Server Registry ──

MCP_REGISTRY_PATH = os.environ.get("MCP_REGISTRY_PATH", "/mcp/third_party/registry.yaml")
MCPO_CONFIG_PATH = os.environ.get("MCPO_CONFIG_PATH", "/mcpo/config.json")

# Built-in servers (always present)
BUILTIN_MCP_SERVERS = [
    {"name": "sessions", "port": 9016, "tools": 17, "builtin": True},
    {"name": "scanning", "port": 9017, "tools": 16, "builtin": True},
    {"name": "recon", "port": 9018, "tools": 9, "builtin": True},
    {"name": "exploit", "port": 9019, "tools": 8, "builtin": True},
    {"name": "credentials", "port": 9020, "tools": 6, "builtin": True},
    {"name": "pipelines", "port": 9021, "tools": 3, "builtin": True},
    {"name": "burp", "port": 9022, "tools": 10, "builtin": True},
    {"name": "zap", "port": 9023, "tools": 10, "builtin": True},
]


def _load_registry():
    """Load third-party registry YAML."""
    try:
        import yaml
    except ImportError:
        return {"servers": []}
    if not os.path.exists(MCP_REGISTRY_PATH):
        return {"servers": []}
    try:
        with open(MCP_REGISTRY_PATH) as f:
            data = yaml.safe_load(f) or {}
        return data
    except Exception:
        return {"servers": []}


def _save_registry(data: dict):
    """Save third-party registry YAML."""
    import yaml
    os.makedirs(os.path.dirname(MCP_REGISTRY_PATH), exist_ok=True)
    with open(MCP_REGISTRY_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


class McpServerBody(BaseModel):
    name: str
    description: str = ""
    source: str = "npm"  # npm | pip | github | local
    package: str = ""
    path: str = ""
    repo: str = ""
    entry: str = "server.py"
    transport: str = "stdio"  # stdio | streamable-http
    port: int = 9030
    env: dict = {}
    args: list = []
    enabled: bool = False


import asyncio


_MCP_HOST = os.environ.get("MCP_STREAMABLE_HOST", "mcp-streamable")
_MCP_SCHEME = os.environ.get("MCP_STREAMABLE_SCHEME", "http")


async def _check_mcp_health(client: httpx.AsyncClient, port: int) -> bool:
    """Quick MCP health check via initialize call."""
    try:
        resp = await client.post(
            f"{_MCP_SCHEME}://{_MCP_HOST}:{port}/mcp",
            json={"jsonrpc": "2.0", "id": 0, "method": "initialize",
                  "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                             "clientInfo": {"name": "health", "version": "1.0"}}},
            headers={"Accept": "application/json, text/event-stream"},
        )
        return resp.status_code == 200
    except Exception:
        return False


@router.get("/api/settings/mcp-servers")
async def list_mcp_servers():
    """List all MCP servers (built-in + third-party) with health status."""
    registry = _load_registry()
    third_party = registry.get("servers") or []

    # Check health concurrently with short timeout
    all_ports = [s["port"] for s in BUILTIN_MCP_SERVERS]
    tp_ports = [s.get("port", 9030) for s in third_party if s.get("enabled", False)]
    check_ports = all_ports + tp_ports

    async with httpx.AsyncClient(verify=False, timeout=2) as c:
        results = await asyncio.gather(
            *[_check_mcp_health(c, p) for p in check_ports],
            return_exceptions=True,
        )
    health_map = {p: (r is True) for p, r in zip(check_ports, results)}

    servers = []
    for srv in BUILTIN_MCP_SERVERS:
        servers.append({**srv, "healthy": health_map.get(srv["port"], False), "enabled": True})

    for srv in third_party:
        port = srv.get("port", 9030)
        servers.append({
            **srv,
            "builtin": False,
            "healthy": health_map.get(port, False),
        })

    return {"servers": servers}


@router.post("/api/settings/mcp-servers")
async def add_mcp_server(body: McpServerBody):
    """Add a new third-party MCP server to the registry."""
    registry = _load_registry()
    servers = registry.get("servers") or []

    # Check for duplicate name
    for s in servers:
        if s.get("name") == body.name:
            raise HTTPException(409, f"Server '{body.name}' already exists")

    # Check for duplicate port
    all_ports = [s.get("port") for s in servers] + [s["port"] for s in BUILTIN_MCP_SERVERS]
    if body.port in all_ports:
        raise HTTPException(409, f"Port {body.port} is already in use")

    servers.append(body.model_dump())
    registry["servers"] = servers
    _save_registry(registry)
    return {"ok": True, "server": body.model_dump()}


@router.put("/api/settings/mcp-servers/{name}")
async def update_mcp_server(name: str, body: McpServerBody):
    """Update an existing third-party MCP server."""
    registry = _load_registry()
    servers = registry.get("servers") or []

    for i, s in enumerate(servers):
        if s.get("name") == name:
            servers[i] = body.model_dump()
            registry["servers"] = servers
            _save_registry(registry)
            return {"ok": True, "server": body.model_dump()}

    raise HTTPException(404, f"Server '{name}' not found")


@router.patch("/api/settings/mcp-servers/{name}/toggle")
async def toggle_mcp_server(name: str):
    """Enable/disable a third-party MCP server."""
    registry = _load_registry()
    servers = registry.get("servers") or []

    for s in servers:
        if s.get("name") == name:
            s["enabled"] = not s.get("enabled", False)
            registry["servers"] = servers
            _save_registry(registry)
            return {"ok": True, "name": name, "enabled": s["enabled"]}

    raise HTTPException(404, f"Server '{name}' not found")


@router.delete("/api/settings/mcp-servers/{name}")
async def delete_mcp_server(name: str):
    """Remove a third-party MCP server from the registry."""
    registry = _load_registry()
    servers = registry.get("servers") or []
    original_len = len(servers)
    servers = [s for s in servers if s.get("name") != name]

    if len(servers) == original_len:
        raise HTTPException(404, f"Server '{name}' not found")

    registry["servers"] = servers
    _save_registry(registry)
    return {"ok": True, "deleted": name}


@router.post("/api/settings/mcp-servers/update-mcpo")
async def update_mcpo_config():
    """Regenerate mcpo/config.json from built-in + enabled third-party servers."""
    registry = _load_registry()
    servers = registry.get("servers") or []

    config = {"mcpServers": {}}

    # Built-in servers
    for srv in BUILTIN_MCP_SERVERS:
        config["mcpServers"][srv["name"]] = {
            "type": "streamable-http",
            "url": f"https://mcp-streamable:{srv['port']}/mcp",
        }

    # Enabled third-party servers
    for srv in servers:
        if srv.get("enabled", False):
            port = srv.get("port", 9030)
            config["mcpServers"][srv["name"]] = {
                "type": "streamable-http",
                "url": f"https://mcp-streamable:{port}/mcp",
            }

    try:
        with open(MCPO_CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
        return {"ok": True, "servers": len(config["mcpServers"])}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Tool Updates ──

UPDATABLE_TOOLS = {
    "nuclei-templates": {
        "label": "Nuclei Templates",
        "description": "ProjectDiscovery vulnerability detection templates",
        "service_attr": "nuclei_url",
        "update_path": "/update-templates",
        "version_path": "/version",
    },
    "nuclei-binary": {
        "label": "Nuclei Binary",
        "description": "Nuclei scanner binary",
        "service_attr": "nuclei_url",
        "update_path": "/update-binary",
        "version_path": "/version",
    },
    "exploitdb": {
        "label": "ExploitDB / Searchsploit",
        "description": "Exploit-DB database for software version CVE matching (git pull)",
        "service_attr": "rag_api_url",
        "update_path": "/exploitdb/update",
        "version_path": "/exploitdb/version",
    },
}


@router.get("/api/settings/updatable-tools")
async def list_updatable_tools():
    """List tools that can be updated without rebuilding containers."""
    s = get_settings()
    tools = []
    for tool_id, info in UPDATABLE_TOOLS.items():
        entry = {"id": tool_id, "label": info["label"], "description": info["description"]}
        # Get version info
        try:
            url = getattr(s, info["service_attr"])
            headers = {"x-api-key": s.api_key, **engagement_headers()} if info["service_attr"] == "rag_api_url" else {}
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                resp = await c.get(f"{url}{info['version_path']}", headers=headers)
                if resp.status_code == 200:
                    entry["version"] = resp.json().get("output", "")[:200]
        except Exception:
            entry["version"] = "unknown"
        tools.append(entry)
    return {"tools": tools}


@router.post("/api/settings/update-tool/{tool_id}")
async def update_tool(tool_id: str):
    """Trigger an update for a specific tool."""
    if tool_id not in UPDATABLE_TOOLS:
        raise HTTPException(404, f"Unknown updatable tool: {tool_id}")
    info = UPDATABLE_TOOLS[tool_id]
    s = get_settings()
    url = getattr(s, info["service_attr"])
    headers = {"x-api-key": s.api_key, **engagement_headers()} if info["service_attr"] == "rag_api_url" else {}
    try:
        async with httpx.AsyncClient(verify=False, timeout=180) as c:
            resp = await c.post(f"{url}{info['update_path']}", headers=headers, timeout=120)
            if resp.status_code == 200:
                return safe_json(resp)
            return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------- LLM Backend Settings ----------

_LLM_KEYS = [
    "llm.backend", "llm.openai_api_key", "llm.openai_model",
    "llm.anthropic_api_key", "llm.anthropic_model",
    "llm.azure_api_key", "llm.azure_endpoint", "llm.azure_model",
]
_MASKED_KEYS = {"llm.openai_api_key", "llm.anthropic_api_key", "llm.azure_api_key"}


@router.get("/api/settings/llm")
async def get_llm_settings():
    """Get LLM backend configuration. API keys are masked."""
    s = get_settings()
    result = {"env_backend": os.environ.get("LLM_BACKEND", "ollama")}
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        for key in _LLM_KEYS:
            try:
                resp = await c.get(f"{s.rag_api_url}/settings/config/{key}",
                                   headers={"x-api-key": s.api_key, **engagement_headers()})
                if resp.status_code == 200:
                    val = resp.json().get("value", "")
                    if key in _MASKED_KEYS and val:
                        val = val[:4] + "..." + val[-4:] if len(val) > 10 else "****"
                    result[key.replace("llm.", "")] = val
                else:
                    result[key.replace("llm.", "")] = ""
            except Exception:
                result[key.replace("llm.", "")] = ""
    return result


class LlmSettingsBody(BaseModel):
    backend: Optional[str] = None
    openai_api_key: Optional[str] = None
    openai_model: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    anthropic_model: Optional[str] = None
    azure_api_key: Optional[str] = None
    azure_endpoint: Optional[str] = None
    azure_model: Optional[str] = None


@router.put("/api/settings/llm")
async def save_llm_settings(body: LlmSettingsBody):
    """Save LLM backend configuration to app_settings DB."""
    s = get_settings()
    updates = {}
    mapping = [
        ("backend", "llm.backend"), ("openai_api_key", "llm.openai_api_key"),
        ("openai_model", "llm.openai_model"), ("anthropic_api_key", "llm.anthropic_api_key"),
        ("anthropic_model", "llm.anthropic_model"), ("azure_api_key", "llm.azure_api_key"),
        ("azure_endpoint", "llm.azure_endpoint"), ("azure_model", "llm.azure_model"),
    ]
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        for field, key in mapping:
            val = getattr(body, field, None)
            if val is not None:
                resp = await c.put(f"{s.rag_api_url}/settings/config/{key}",
                                   headers={"x-api-key": s.api_key, **engagement_headers()}, json={"value": val})
                if resp.status_code < 400:
                    updates[field] = True
    return {"ok": True, "updated": updates}


@router.post("/api/settings/llm/test")
async def test_llm_backend(body: dict):
    """Test connectivity to the selected LLM backend."""
    backend = body.get("backend", "ollama")
    s = get_settings()

    # Read unmasked API keys from DB
    keys: dict = {}
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        for key in _LLM_KEYS:
            try:
                resp = await c.get(f"{s.rag_api_url}/settings/config/{key}",
                                   headers={"x-api-key": s.api_key, **engagement_headers()})
                if resp.status_code == 200:
                    keys[key.replace("llm.", "")] = resp.json().get("value", "")
            except Exception:
                pass

    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            if backend == "openai":
                api_key = keys.get("openai_api_key") or os.environ.get("OPENAI_API_KEY", "")
                model = keys.get("openai_model") or os.environ.get("OPENAI_MODEL", "gpt-4o")
                resp = await c.post(
                    f"{os.environ.get('OPENAI_API_BASE', 'https://api.openai.com')}/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={"model": model, "messages": [{"role": "user", "content": "Reply with OK"}], "max_tokens": 5},
                )
                resp.raise_for_status()
                return {"ok": True, "backend": backend, "model": model,
                        "response": resp.json()["choices"][0]["message"]["content"]}

            elif backend == "anthropic":
                api_key = keys.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
                model = keys.get("anthropic_model") or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
                resp = await c.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
                    json={"model": model, "max_tokens": 5, "messages": [{"role": "user", "content": "Reply with OK"}]},
                )
                resp.raise_for_status()
                data = resp.json()
                text = next((b["text"] for b in data.get("content", []) if b.get("type") == "text"), "")
                return {"ok": True, "backend": backend, "model": model, "response": text}

            elif backend == "azure":
                api_key = keys.get("azure_api_key") or os.environ.get("AZURE_API_KEY", "")
                endpoint = keys.get("azure_endpoint") or os.environ.get("AZURE_ENDPOINT", "")
                model = keys.get("azure_model") or os.environ.get("AZURE_MODEL", "gpt-4o")
                base = endpoint.rstrip("/")
                if ".models.ai.azure.com" in base:
                    url = f"{base}/v1/chat/completions"
                else:
                    url = f"{base}/openai/deployments/{model}/chat/completions?api-version={os.environ.get('AZURE_API_VERSION', '2024-08-01-preview')}"
                resp = await c.post(url, headers={"api-key": api_key},
                                    json={"messages": [{"role": "user", "content": "Reply with OK"}], "max_tokens": 5})
                resp.raise_for_status()
                return {"ok": True, "backend": backend, "model": model,
                        "response": resp.json()["choices"][0]["message"]["content"]}

            else:
                resp = await c.get("https://llm_query:8002/ollama/health")
                data = resp.json()
                return {"ok": data.get("ok", False), "backend": "ollama",
                        "model": os.environ.get("OLLAMA_MODEL", ""), "detail": data}

    except httpx.HTTPStatusError as e:
        return {"ok": False, "backend": backend, "error": f"HTTP {e.response.status_code}: {e.response.text[:300]}"}
    except Exception as e:
        return {"ok": False, "backend": backend, "error": str(e)}


# ── Scan timeouts (long-running port scans) ──
# Stored in app_settings under category 'config' with keys prefixed `scan_timeout_`.
# Frontend reads/writes via /api/settings/scan-timeouts; nmap-api still respects
# these values via the per-job `timeout_seconds` override sent in scan launch payloads.

SCAN_TIMEOUT_KEYS = [
    "scan_timeout_nmap",          # masscan-then-nmap fallback / batch
    "scan_timeout_nmap_proxied",  # nmap via SOCKS proxy
    "scan_timeout_nmap_service",  # ad-hoc service detect
    "scan_timeout_nmap_udp",      # UDP scan
    "scan_timeout_nmap_smb",      # SMB vuln script
    "scan_timeout_nmap_resume",   # nmap --resume
    "scan_timeout_full",          # full-scan composite
    "scan_timeout_masscan",       # masscan-only (informational; masscan has no internal timeout)
]


def _scan_timeout_defaults() -> Dict[str, int]:
    """Match the env defaults compiled into nmap-api.py."""
    return {
        "scan_timeout_nmap": 1800,
        "scan_timeout_nmap_proxied": 3600,
        "scan_timeout_nmap_service": 600,
        "scan_timeout_nmap_udp": 1800,
        "scan_timeout_nmap_smb": 300,
        "scan_timeout_nmap_resume": 7200,
        "scan_timeout_full": 1800,
        "scan_timeout_masscan": 0,  # 0 = no timeout (masscan runs to completion)
    }


@router.get("/api/settings/scan-timeouts")
async def get_scan_timeouts():
    """Return current scan timeouts (seconds). Falls back to defaults when unset."""
    s = get_settings()
    defaults = _scan_timeout_defaults()
    out: Dict[str, int] = {}
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        for key in SCAN_TIMEOUT_KEYS:
            try:
                resp = await c.get(
                    f"{s.rag_api_url}/settings/config/{key}",
                    headers={"x-api-key": s.api_key, **engagement_headers()},
                )
                if resp.status_code == 200:
                    val = resp.json().get("value", "")
                    try:
                        out[key] = int(val)
                        continue
                    except (TypeError, ValueError):
                        pass
            except Exception:
                pass
            out[key] = defaults.get(key, 0)
    return {"timeouts": out, "defaults": defaults}


class ScanTimeoutsBody(BaseModel):
    timeouts: Dict[str, int] = Field(..., description="Map of scan_timeout_* key → seconds (>=0)")


@router.put("/api/settings/scan-timeouts")
async def put_scan_timeouts(body: ScanTimeoutsBody):
    """Bulk-upsert scan timeouts. Unknown keys are rejected; values must be >=0."""
    invalid = [k for k in body.timeouts if k not in SCAN_TIMEOUT_KEYS]
    if invalid:
        raise HTTPException(400, f"Unknown scan timeout keys: {invalid}")
    bad = {k: v for k, v in body.timeouts.items() if not isinstance(v, int) or v < 0}
    if bad:
        raise HTTPException(400, f"Timeout values must be int >=0: {bad}")

    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        for key, seconds in body.timeouts.items():
            resp = await c.put(
                f"{s.rag_api_url}/settings/config/{key}",
                json={"value": str(seconds)},
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code,
                                    f"Failed to write {key}: {resp.text}")
    return {"ok": True, "updated": list(body.timeouts.keys())}


# ── LLM Tuning (reduce hallucination) ──
# Stored in app_settings under keys prefixed `llm.` (category 'config').

LLM_TUNING_KEYS = {
    "llm.temperature":    {"type": float, "default": 0.3,  "min": 0.0, "max": 2.0,
                           "help": "Randomness (0=deterministic, 2=creative). Lower = less hallucination."},
    "llm.top_p":          {"type": float, "default": 0.85, "min": 0.0, "max": 1.0,
                           "help": "Nucleus sampling. Lower = more focused responses."},
    "llm.top_k":          {"type": int,   "default": 40,   "min": 1,   "max": 200,
                           "help": "Top-K sampling. Lower = more conservative token choices."},
    "llm.repeat_penalty": {"type": float, "default": 1.1,  "min": 0.0, "max": 3.0,
                           "help": "Penalize repeated phrases. >1.0 reduces loops/repetition."},
    "llm.num_ctx":        {"type": int,   "default": 8192, "min": 512, "max": 131072,
                           "help": "Context window (tokens). Larger = more conversation history retained."},
    "llm.num_predict":    {"type": int,   "default": 4096, "min": 256, "max": 32768,
                           "help": "Max output tokens per response."},
    "llm.seed":           {"type": int,   "default": 0,    "min": 0,   "max": 999999999,
                           "help": "Random seed. 0=random. Set >0 for reproducible output (debugging)."},
}


@router.get("/api/settings/llm-tuning")
async def get_llm_tuning():
    """Return current LLM tuning params with defaults + metadata."""
    s = get_settings()
    result: Dict[str, dict] = {}
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        for key, meta in LLM_TUNING_KEYS.items():
            entry = {"value": meta["default"], **meta, "source": "default"}
            entry.pop("type", None)
            try:
                resp = await c.get(f"{s.rag_api_url}/settings/config/{key}",
                                   headers={"x-api-key": s.api_key, **engagement_headers()})
                if resp.status_code == 200:
                    raw = resp.json().get("value", "")
                    if raw:
                        entry["value"] = meta["type"](raw)
                        entry["source"] = "custom"
            except Exception:
                pass
            result[key] = entry
    return {"tuning": result}


class LLMTuningBody(BaseModel):
    tuning: Dict[str, float]  # key → value


@router.put("/api/settings/llm-tuning")
async def put_llm_tuning(body: LLMTuningBody):
    """Bulk-upsert LLM tuning params."""
    invalid = [k for k in body.tuning if k not in LLM_TUNING_KEYS]
    if invalid:
        raise HTTPException(400, f"Unknown keys: {invalid}")
    for k, v in body.tuning.items():
        meta = LLM_TUNING_KEYS[k]
        if v < meta["min"] or v > meta["max"]:
            raise HTTPException(400, f"{k}: value {v} out of range [{meta['min']}, {meta['max']}]")

    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        for k, v in body.tuning.items():
            resp = await c.put(f"{s.rag_api_url}/settings/config/{k}",
                               json={"value": str(v)},
                               headers={"x-api-key": s.api_key, **engagement_headers()})
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code, f"Failed to write {k}: {resp.text}")
    return {"ok": True, "updated": list(body.tuning.keys())}


# ── Per-agent model selection ────────────────────────────────────────────


@router.get("/api/settings/agent-models")
async def get_agent_models():
    """Return registered AI agents + currently-resolved models + available
    Ollama models for the dropdown."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/settings/agent-models",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()


class AgentModelBody(BaseModel):
    model: Optional[str] = None  # empty/None = clear override


@router.put("/api/settings/agent-models/{agent_id}")
async def put_agent_model(agent_id: str, body: AgentModelBody):
    """Set or clear the model override for one agent."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.put(f"{s.rag_api_url}/settings/agent-models/{agent_id}",
                           json={"model": body.model},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()


class AgentAutoBody(BaseModel):
    enabled: bool


@router.put("/api/settings/agent-models/{agent_id}/auto")
async def put_agent_auto(agent_id: str, body: AgentAutoBody):
    """Toggle auto-run for an agent. When enabled, the agent fires automatically
    after the relevant ingest/refresh cycle (vault_import_agent runs after a
    MicroBurst ingest; cloud_triage_agent re-ranks recommendations)."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as c:
        resp = await c.put(f"{s.rag_api_url}/settings/agent-models/{agent_id}/auto",
                           json={"enabled": body.enabled},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()
