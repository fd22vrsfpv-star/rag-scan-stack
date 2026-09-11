import httpx
import json
import logging
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from config import get_settings
from engagement import engagement_headers
from typing import Optional, Dict, List
from timeouts import TIMEOUT_NORMAL
import time
from utils import safe_json

log = logging.getLogger("settings")

router = APIRouter()

# llm_query serves PLAIN HTTP: its Dockerfile runs `uvicorn --host 0.0.0.0
# --port 8002` with no ssl_keyfile/ssl_certfile, so an https:// URL fails with
# "[SSL: WRONG_VERSION_NUMBER] wrong version number". Env-overridable, matching
# news_runner's LLM_QUERY_URL convention.
LLM_QUERY_URL = os.environ.get("LLM_QUERY_URL", "http://llm_query:8002").rstrip("/")

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
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(f"{s.container_logs_url}/db/sync-dsn")
            return r.json() if r.status_code < 400 else {"ok": False, "status": r.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


class ApiKeyBody(BaseModel):
    value: str = Field(..., min_length=1)


@router.get("/api/settings/keys")
async def list_api_keys():
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
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
    async with httpx.AsyncClient(timeout=15) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=15) as c:
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
            async with httpx.AsyncClient(timeout=5) as c:
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
        async with httpx.AsyncClient(timeout=180) as c:
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
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(f"{s.container_logs_url}/db/test-connection")
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/api/settings/database/preflight")
async def preflight_remote():
    """Pre-flight: test SSH tunnel + DB connectivity before switching."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=90) as c:
            resp = await c.post(
                f"{s.container_logs_url}/db/preflight",
                timeout=80,
            )
            return safe_json(resp)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/api/settings/database/compare")
async def compare_databases(start_local: bool = False):
    """Compare local and remote database row counts and timestamps.

    `start_local` defaults to FALSE: in a remote mode, starting the local
    Postgres to read its stats hands it the `rag-postgres` network alias, and
    every service then resolves that name to a second, SSL-less database. A bare
    GET reports local stats as unavailable instead of disrupting the stack.
    """
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=120) as c:
            resp = await c.get(
                f"{s.container_logs_url}/db/compare",
                params={"start_local": str(bool(start_local)).lower()},
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

    async with httpx.AsyncClient(timeout=2) as c:
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
            async with httpx.AsyncClient(timeout=10) as c:
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
        async with httpx.AsyncClient(timeout=180) as c:
            resp = await c.post(f"{url}{info['update_path']}", headers=headers, timeout=120)
            if resp.status_code == 200:
                return safe_json(resp)
            return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------- LLM Backend Settings ----------

_LLM_KEYS = [
    "llm.backend", "llm.openai_api_key", "llm.openai_model", "llm.openai_base_url",
    "llm.anthropic_api_key", "llm.anthropic_model",
    "llm.azure_api_key", "llm.azure_endpoint", "llm.azure_model",
]
_MASKED_KEYS = {"llm.openai_api_key", "llm.anthropic_api_key", "llm.azure_api_key"}


@router.get("/api/settings/llm")
async def get_llm_settings():
    """Get LLM backend configuration. API keys are masked."""
    s = get_settings()
    result = {"env_backend": os.environ.get("LLM_BACKEND", "ollama")}
    async with httpx.AsyncClient(timeout=10) as c:
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
    openai_base_url: Optional[str] = None
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
        ("openai_model", "llm.openai_model"), ("openai_base_url", "llm.openai_base_url"),
        ("anthropic_api_key", "llm.anthropic_api_key"),
        ("anthropic_model", "llm.anthropic_model"), ("azure_api_key", "llm.azure_api_key"),
        ("azure_endpoint", "llm.azure_endpoint"), ("azure_model", "llm.azure_model"),
    ]
    async with httpx.AsyncClient(timeout=10) as c:
        for field, key in mapping:
            val = getattr(body, field, None)
            if val is not None:
                # Strip stray whitespace (a leading/trailing space in an endpoint
                # produces "URL missing an 'http://' protocol" at request time).
                if isinstance(val, str):
                    val = val.strip()
                resp = await c.put(f"{s.rag_api_url}/settings/config/{key}",
                                   headers={"x-api-key": s.api_key, **engagement_headers()}, json={"value": val})
                if resp.status_code < 400:
                    updates[field] = True
    return {"ok": True, "updated": updates}


# --- Per-task model routing -----------------------------------------------
# One model for the whole stack is wrong in both directions: the frontier model
# is wasted summarising news, and a cheap model fumbles tool calls in the
# exploit phase. `llm.route.<task>` picks a model (optionally "backend:model")
# per task, and `llm.route.<task>.fallback` says where to go when the primary is
# rate-limited past its retries. Resolution lives in common/llm_settings.py so
# every service agrees; this endpoint only reads and writes the keys.

# Kept in sync with common/llm_settings.LLM_TASKS. Duplicated because the BFF
# does not mount ./common — tests/test_llm_routing.py pins the two together.
LLM_ROUTE_TASKS = [
    ("recon", "Reconnaissance agent — host/service discovery reasoning"),
    ("analyze", "Analyzer agent — findings triage and correlation"),
    ("exploit", "Exploit agent — exploit selection and chain construction"),
    ("scan", "Scanner agent — scan planning and next-step selection"),
    ("postex", "Post-exploitation review"),
    ("news", "Security-news enrichment (high volume, low difficulty)"),
    ("recommend", "Scan recommender — per-service tool suggestions"),
    ("exploit_gen", "Exploit/PoC script generation"),
    ("extract", "Extractor learning — parsing tool output into fields"),
    ("triage", "Cloud/artifact triage"),
    ("chat", "Operator chat in the dashboard"),
]


async def _read_config(c, s, key: str) -> str:
    """One app_settings value, or "" — a missing key is not an error here."""
    try:
        resp = await c.get(f"{s.rag_api_url}/settings/config/{key}",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code == 200:
            return resp.json().get("value", "") or ""
    except Exception as e:
        log.warning("read %s failed: %s", key, str(e) or type(e).__name__)
    return ""


# --- Named provider instances ---------------------------------------------
# The per-type keys (llm.azure_*, ...) allow exactly ONE config per backend
# type, so two Azure resources cannot both be reachable. `llm.providers` holds
# a JSON array of named instances; a route then names the INSTANCE
# ("azure-claude:claude-sonnet-5"). The per-type keys remain honoured as
# implicit providers, so nothing existing breaks.

_PROVIDER_TYPES = ("azure", "openai", "anthropic", "ollama", "vllm")

# Most catalog entries to return per provider. An Azure Foundry resource lists
# 414 models of which one is deployed; the dropdown has to stay usable.
CATALOG_CAP = 60
_KEY_MASK = "********"


def _mask_key(v: str) -> str:
    """Never return a full API key to the browser."""
    if not v:
        return ""
    return v[:4] + "..." + v[-4:] if len(v) > 10 else _KEY_MASK


def _provider_choices(raw: str):
    """[{id, type, default_model}] for the routing dropdowns.

    Includes the implicit per-type providers, because those are what a
    deployment with no llm.providers row has and a route may name them.
    """
    out = []
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for e in parsed or []:
                if isinstance(e, dict) and e.get("id") and e.get("enabled", True) is not False:
                    out.append({"id": e["id"], "type": e.get("type", ""),
                                "default_model": e.get("default_model", "")})
        except Exception:
            pass
    have = {p["id"] for p in out}
    for t in _PROVIDER_TYPES:
        if t not in have:
            out.append({"id": t, "type": t, "default_model": ""})
    return out


@router.get("/api/settings/llm/providers")
async def get_llm_providers():
    """Configured provider instances. API keys are masked."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        raw = await _read_config(c, s, "llm.providers")
    items, error = [], None
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for e in parsed or []:
                if not isinstance(e, dict):
                    continue
                items.append({
                    "id": e.get("id", ""),
                    "type": e.get("type", ""),
                    "endpoint": e.get("endpoint", ""),
                    "api_key_masked": _mask_key(e.get("api_key") or ""),
                    "has_api_key": bool(e.get("api_key")),
                    "api_version": e.get("api_version", ""),
                    "default_model": e.get("default_model", ""),
                    "enabled": e.get("enabled", True) is not False,
                })
        except Exception as e:
            # Surface a malformed blob instead of silently showing none — the
            # resolver falls back to implicit providers, so the stack keeps
            # working and this would otherwise look like "nothing configured".
            error = f"llm.providers is not valid JSON: {str(e) or type(e).__name__}"
    return {"providers": items, "types": list(_PROVIDER_TYPES), "error": error}


class LlmProvider(BaseModel):
    id: str
    type: str
    endpoint: Optional[str] = ""
    # Omit or send the masked value to KEEP the stored key; send a new string
    # to replace it. Without this a round-trip through the UI would overwrite
    # every key with its own mask.
    api_key: Optional[str] = None
    api_version: Optional[str] = ""
    default_model: Optional[str] = ""
    enabled: Optional[bool] = True


class LlmProvidersBody(BaseModel):
    providers: List[LlmProvider]


@router.put("/api/settings/llm/providers")
async def put_llm_providers(body: LlmProvidersBody):
    """Replace the provider list. Validates before writing anything."""
    s = get_settings()

    ids = [p.id.strip() for p in body.providers]
    if any(not i for i in ids):
        raise HTTPException(400, "every provider needs an id")
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise HTTPException(400, f"duplicate provider id(s): {', '.join(dupes)}")
    for p in body.providers:
        if p.type not in _PROVIDER_TYPES:
            raise HTTPException(400, f"provider {p.id!r}: unknown type {p.type!r}")
        # A provider id containing ':' would break route parsing, which splits
        # "<provider>:<model>" on the first colon.
        if ":" in p.id:
            raise HTTPException(400, f"provider id {p.id!r} may not contain ':'")

    async with httpx.AsyncClient(timeout=15) as c:
        existing_raw = await _read_config(c, s, "llm.providers")
        existing = {}
        if existing_raw:
            try:
                for e in json.loads(existing_raw) or []:
                    if isinstance(e, dict) and e.get("id"):
                        existing[e["id"]] = e
            except Exception:
                existing = {}

        out = []
        for p in body.providers:
            prev = existing.get(p.id.strip(), {})
            key = p.api_key
            if key is None or key == _KEY_MASK or (
                    prev.get("api_key") and key == _mask_key(prev["api_key"])):
                key = prev.get("api_key", "")  # unchanged
            out.append({
                "id": p.id.strip(), "type": p.type,
                "endpoint": (p.endpoint or "").strip(),
                "api_key": key or "",
                "api_version": (p.api_version or "").strip(),
                "default_model": (p.default_model or "").strip(),
                "enabled": p.enabled is not False,
            })

        resp = await c.put(
            f"{s.rag_api_url}/settings/config/llm.providers",
            headers={"x-api-key": s.api_key, **engagement_headers()},
            json={"value": json.dumps(out)})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:300])

    return {"ok": True, "count": len(out),
            "ids": [p["id"] for p in out],
            "note": "takes effect within 30s (resolver cache TTL)"}


@router.post("/api/settings/llm/providers/{provider_id}/test")
async def test_llm_provider(provider_id: str):
    """Connectivity check for ONE named provider, step by step.

    Reports each stage separately, because "it does not work" has very
    different causes that look identical from outside — and diagnosing two
    misconfigured providers by hand is what prompted this:

      * endpoint    — is the URL a shape we can build from? (a Foundry
                      PROJECT url or the Responses-API url needs normalising)
      * auth        — does the key work at all?
      * deployments — how many models are actually deployed on the resource?
                      A resource can authenticate fine and serve NOTHING.
      * generate    — a real minimal completion on the default model. This is
                      the only check that proves end-to-end usability;
                      `404 DeploymentNotFound` here with deployments > 0 means
                      the default_model names something not on THIS resource.

    Uses the STORED key, never one from the browser.
    """
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        raw = await _read_config(c, s, "llm.providers")
        legacy_ep = await _read_config(c, s, "llm.azure_endpoint")
        legacy_key = await _read_config(c, s, "llm.azure_api_key")
        legacy_model = await _read_config(c, s, "llm.azure_model")

    prov = None
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for e in parsed or []:
                if isinstance(e, dict) and e.get("id") == provider_id:
                    prov = e
                    break
        except Exception as e:
            raise HTTPException(400, f"llm.providers is not valid JSON: {e}")
    if prov is None and provider_id == "azure":
        prov = {"id": "azure", "type": "azure", "endpoint": legacy_ep,
                "api_key": legacy_key, "default_model": legacy_model}
    if prov is None:
        raise HTTPException(404, f"no provider {provider_id!r}")

    ptype = prov.get("type")
    ep = (prov.get("endpoint") or "").strip()
    key = prov.get("api_key") or ""
    model = (prov.get("default_model") or "").strip()
    checks = []

    def add(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    if not ep.startswith(("http://", "https://")):
        add("endpoint", False, f"{ep!r} is not an http(s) URL")
        return {"provider": provider_id, "type": ptype, "ok": False, "checks": checks}

    root = _azure_root(ep) if ptype in ("azure", "openai") else ep.rstrip("/")
    add("endpoint", True,
        f"root {root}" + ("" if root == ep.rstrip("/") else f"  (normalised from {ep})"))

    async with httpx.AsyncClient(timeout=45, verify=False) as c:
        if ptype in ("azure", "openai"):
            hdr = ({"api-key": key} if ptype == "azure"
                   else {"Authorization": f"Bearer {key}"})
            try:
                r = await c.get(f"{root}/openai/deployments",
                                params={"api-version": "2023-03-15-preview"},
                                headers=hdr)
                if r.status_code == 200:
                    names = [d.get("id") for d in (r.json().get("data") or [])
                             if isinstance(d, dict)
                             and (d.get("status") or "succeeded") == "succeeded"]
                    add("auth", True, "key accepted")
                    add("deployments", bool(names),
                        (", ".join(names) if names else
                         "NONE — this resource authenticates but serves no "
                         "models; the model you want is probably on a "
                         "different resource"))
                elif r.status_code in (401, 403):
                    add("auth", False, f"HTTP {r.status_code} — key rejected")
                else:
                    add("auth", True, "reachable")
                    add("deployments", False,
                        f"listing returned HTTP {r.status_code}: {r.text[:120]}")
            except Exception as e:
                add("auth", False, f"unreachable: {str(e) or type(e).__name__}")
        elif ptype == "ollama":
            try:
                r = await c.get(f"{root}/api/tags")
                names = [m.get("name") for m in (r.json().get("models") or [])] \
                    if r.status_code == 200 else []
                add("reachable", r.status_code == 200, f"HTTP {r.status_code}")
                add("models", bool(names), ", ".join(n for n in names if n) or "none installed")
            except Exception as e:
                add("reachable", False, f"unreachable: {str(e) or type(e).__name__}")

        # The end-to-end check. Nothing else proves usability.
        if not model:
            add("generate", False, "no default model set — nothing to test")
        else:
            try:
                if ptype in ("azure", "openai"):
                    hdr = ({"api-key": key, "Content-Type": "application/json"}
                           if ptype == "azure"
                           else {"Authorization": f"Bearer {key}",
                                 "Content-Type": "application/json"})
                    body = {"model": model,
                            "messages": [{"role": "user", "content": "Reply with only: OK"}],
                            "max_tokens": 16}
                    r = await c.post(f"{root}/openai/v1/chat/completions",
                                     headers=hdr, json=body)
                    # Same swap llm_query performs: the gpt-5 / o-series
                    # families reject max_tokens.
                    if r.status_code == 400 and "max_completion_tokens" in (r.text or ""):
                        body.pop("max_tokens")
                        body["max_completion_tokens"] = 2000
                        r = await c.post(f"{root}/openai/v1/chat/completions",
                                         headers=hdr, json=body)
                    if r.status_code == 200:
                        txt = r.json()["choices"][0]["message"]["content"]
                        add("generate", True, f"{model} answered {txt.strip()[:40]!r}")
                    else:
                        code = ""
                        try:
                            code = r.json().get("error", {}).get("code", "")
                        except Exception:
                            pass
                        add("generate", False,
                            f"HTTP {r.status_code} {code} for model {model!r}"
                            + (" — that model is not deployed on THIS resource"
                               if str(code) == "DeploymentNotFound" else ""))
                else:
                    r = await c.post(f"{root}/api/generate",
                                     json={"model": model, "prompt": "Reply with only: OK",
                                           "stream": False})
                    if r.status_code == 200:
                        add("generate", True,
                            f"{model} answered {str(r.json().get('response',''))[:40]!r}")
                    else:
                        add("generate", False, f"HTTP {r.status_code}: {r.text[:120]}")
            except Exception as e:
                add("generate", False, f"{str(e) or type(e).__name__}")

    return {"provider": provider_id, "type": ptype,
            "ok": all(ch["ok"] for ch in checks), "checks": checks}


@router.get("/api/settings/llm/available-models")
async def list_available_models():
    """Selectable models per provider — ONLY ones that can actually be used.

    The distinction that matters: `/openai/v1/models` on an Azure Foundry
    resource returns the REGIONAL CATALOG (414 entries here) of which only the
    DEPLOYED ones answer; picking any other gives DeploymentNotFound. The
    deployments themselves come from

        GET {endpoint}/openai/deployments?api-version=2023-03-15-preview

    which is the only endpoint on this resource that lists them (the 2024-08-01
    api-version returns 404). Deployment `id` is the name to send as the model.

    Per type:
      * azure (and an openai-typed provider pointing at an Azure host) ->
        deployments, filtered to status == succeeded
      * ollama -> /api/tags, which IS the real installed list
      * openai (genuine) -> /v1/models, which is the usable list there
      * anything unverifiable -> just the provider's configured default_model

    `catalog_total` is returned for information only and is NOT selectable.
    Always returns a list; discovery failing must not break the form.
    """
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        raw = await _read_config(c, s, "llm.providers")
        legacy = {}
        for k in ("llm.azure_endpoint", "llm.azure_api_key", "llm.azure_model",
                  "llm.openai_base_url", "llm.openai_api_key", "llm.openai_model",
                  "llm.ollama_url", "llm.ollama_model", "llm.anthropic_model"):
            legacy[k.replace("llm.", "")] = await _read_config(c, s, k)

    provs = []
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for e in parsed or []:
                if isinstance(e, dict) and e.get("id") and e.get("enabled", True) is not False:
                    provs.append(e)
        except Exception:
            provs = []
    have = {p["id"] for p in provs}
    for t in _PROVIDER_TYPES:
        if t in have:
            continue
        if t == "azure":
            provs.append({"id": t, "type": t, "endpoint": legacy.get("azure_endpoint", ""),
                          "api_key": legacy.get("azure_api_key", ""),
                          "default_model": legacy.get("azure_model", "")})
        elif t == "openai":
            provs.append({"id": t, "type": t, "endpoint": legacy.get("openai_base_url", ""),
                          "api_key": legacy.get("openai_api_key", ""),
                          "default_model": legacy.get("openai_model", "")})
        elif t == "ollama":
            provs.append({"id": t, "type": t, "endpoint": legacy.get("ollama_url", ""),
                          "api_key": "", "default_model": legacy.get("ollama_model", "")})
        elif t == "anthropic":
            provs.append({"id": t, "type": t, "endpoint": "", "api_key": "",
                          "default_model": legacy.get("anthropic_model", "")})
        else:
            provs.append({"id": t, "type": t, "endpoint": "", "api_key": "",
                          "default_model": ""})

    out = []
    async with httpx.AsyncClient(timeout=15, verify=False) as c:
        for p in provs:
            models, verified, err, note = [], False, None, None
            catalog_total = 0
            ptype = p.get("type")
            ep = (p.get("endpoint") or "").rstrip("/")
            key = p.get("api_key") or ""
            dm = (p.get("default_model") or "").strip()

            # An openai-typed provider whose base URL is an Azure host is still
            # Azure underneath — its /v1/models is that same regional catalog.
            azure_host = any(h in ep.lower() for h in
                             ("services.ai.azure.com", "openai.azure.com"))
            treat_as_azure = ptype == "azure" or (ptype == "openai" and azure_host)

            try:
                if treat_as_azure and ep.startswith(("http://", "https://")):
                    root = _azure_root(ep)
                    r = await c.get(
                        f"{root}/openai/deployments",
                        params={"api-version": "2023-03-15-preview"},
                        headers={"api-key": key})
                    if r.status_code == 200:
                        for d in (r.json().get("data") or []):
                            if not isinstance(d, dict):
                                continue
                            if (d.get("status") or "succeeded") != "succeeded":
                                continue
                            name = d.get("id") or d.get("model")
                            if name and name not in models:
                                models.append(name)
                        verified = True
                        note = f"{len(models)} deployment(s) on this resource"
                    else:
                        err = (f"deployments listing returned HTTP "
                               f"{r.status_code}")
                    # Informational only — never offered for selection.
                    try:
                        rc = await c.get(f"{root}/openai/v1/models",
                                         headers={"api-key": key})
                        if rc.status_code == 200:
                            catalog_total = len(rc.json().get("data") or [])
                    except Exception:
                        pass
                elif ptype == "ollama" and ep.startswith(("http://", "https://")):
                    r = await c.get(f"{ep}/api/tags")
                    if r.status_code == 200:
                        for m in r.json().get("models", []):
                            n = m.get("name") or m.get("model")
                            if n and n not in models:
                                models.append(n)
                        verified = True
                        note = f"{len(models)} model(s) installed"
                elif ptype == "openai" and ep.startswith(("http://", "https://")):
                    r = await c.get(f"{ep.rstrip('/')}/v1/models",
                                    headers={"Authorization": f"Bearer {key}"})
                    if r.status_code == 200:
                        for m in (r.json().get("data") or []):
                            n = m.get("id") if isinstance(m, dict) else None
                            if n and n not in models:
                                models.append(n)
                        verified = True
            except Exception as e:
                err = str(e) or type(e).__name__

            # The configured default is always selectable: it is what the
            # provider uses today, so hiding it would make the current setting
            # unpickable. Listed first.
            if dm and dm not in models:
                models.insert(0, dm)

            out.append({
                "provider": p["id"], "type": ptype,
                "models": models,
                "verified": verified,
                "catalog_total": catalog_total,
                "note": note,
                "error": err,
            })
    return {"providers": out}


def _azure_root(ep: str) -> str:
    """Resource root from an Azure endpoint however it was typed.

    Mirrors llm_query._azure_foundry_root, and additionally strips /responses --
    which that function does NOT, so pasting the Responses-API URL there yields
    a doubled path.
    """
    import re
    b = ep.rstrip("/")
    # A Foundry PROJECT endpoint (.../api/projects/<name>) is a shape the portal
    # hands out; the deployments API lives on the RESOURCE, so strip it or the
    # listing 400s.
    b = re.sub(r"/api/projects/[^/]+/?$", "", b, flags=re.I)
    return re.sub(r"(/openai)?(/v1)?(/chat/completions|/embeddings|/responses|/deployments)?/?$",
                  "", b.rstrip("/"), flags=re.I).rstrip("/")


@router.get("/api/settings/llm/routes")
async def get_llm_routes():
    """Per-task model routes, plus the global default and rate-limit fallback."""
    s = get_settings()
    out = []
    async with httpx.AsyncClient(timeout=15) as c:
        global_default = await _read_config(c, s, "llm.route.default")
        global_fallback = await _read_config(c, s, "llm.route.default.fallback")
        global_model = await _read_config(c, s, "llm.azure_model")
        providers_raw = await _read_config(c, s, "llm.providers")
        for task, desc in LLM_ROUTE_TASKS:
            model = await _read_config(c, s, f"llm.route.{task}")
            fb = await _read_config(c, s, f"llm.route.{task}.fallback")
            out.append({
                "task": task,
                "description": desc,
                "model": model,
                "fallback": fb,
                # What actually runs today, so a blank row is not ambiguous.
                "effective": model or global_default or global_model or "",
                "effective_fallback": fb or global_fallback or "",
                "inherited": not model,
            })
    return {"tasks": out, "default": global_default,
            "fallback": global_fallback, "global_model": global_model,
            # So the UI can offer "<provider>:<model>" without the operator
            # having to remember what is configured.
            "providers": _provider_choices(providers_raw)}


class LlmRouteBody(BaseModel):
    """A partial update: only the tasks present are written.

    An empty string CLEARS a route (the task goes back to inheriting), which is
    why this cannot use exclude_none semantics alone — "" is meaningful.
    """
    routes: Optional[Dict[str, str]] = None
    fallbacks: Optional[Dict[str, str]] = None
    default: Optional[str] = None
    default_fallback: Optional[str] = None


@router.put("/api/settings/llm/routes")
async def put_llm_routes(body: LlmRouteBody):
    """Write per-task routes. Unknown task names are REJECTED rather than
    silently stored — a typo'd task would create a key nothing ever reads."""
    s = get_settings()
    known = {t for t, _ in LLM_ROUTE_TASKS}
    bad = sorted((set(body.routes or {}) | set(body.fallbacks or {})) - known)
    if bad:
        raise HTTPException(400, f"unknown task(s): {', '.join(bad)}")

    writes = {}
    for task, val in (body.routes or {}).items():
        writes[f"llm.route.{task}"] = (val or "").strip()
    for task, val in (body.fallbacks or {}).items():
        writes[f"llm.route.{task}.fallback"] = (val or "").strip()
    if body.default is not None:
        writes["llm.route.default"] = body.default.strip()
    if body.default_fallback is not None:
        writes["llm.route.default.fallback"] = body.default_fallback.strip()

    saved, failed = [], {}
    async with httpx.AsyncClient(timeout=15) as c:
        for key, val in writes.items():
            try:
                resp = await c.put(
                    f"{s.rag_api_url}/settings/config/{key}",
                    headers={"x-api-key": s.api_key, **engagement_headers()},
                    json={"value": val})
                if resp.status_code < 400:
                    saved.append(key)
                else:
                    failed[key] = f"HTTP {resp.status_code}"
            except Exception as e:
                failed[key] = str(e) or type(e).__name__
    if failed and not saved:
        raise HTTPException(502, f"no routes saved: {failed}")
    # Resolvers cache for 30s (common/llm_settings.CACHE_TTL), so a save is not
    # instantly visible everywhere. Say so rather than letting it look ignored.
    return {"ok": not failed, "saved": saved, "failed": failed,
            "note": "takes effect within 30s (resolver cache TTL)"}


@router.post("/api/settings/llm/test")
async def test_llm_backend(body: dict):
    """Test connectivity to the selected LLM backend."""
    backend = body.get("backend", "ollama")
    s = get_settings()

    # Read unmasked API keys from DB
    keys: dict = {}
    async with httpx.AsyncClient(timeout=10) as c:
        for key in _LLM_KEYS:
            try:
                resp = await c.get(f"{s.rag_api_url}/settings/config/{key}",
                                   headers={"x-api-key": s.api_key, **engagement_headers()})
                if resp.status_code == 200:
                    keys[key.replace("llm.", "")] = resp.json().get("value", "")
            except Exception:
                pass

    try:
        async with httpx.AsyncClient(timeout=15) as c:
            if backend == "openai":
                api_key = keys.get("openai_api_key") or os.environ.get("OPENAI_API_KEY", "")
                model = keys.get("openai_model") or os.environ.get("OPENAI_MODEL", "gpt-4o")
                base = (keys.get("openai_base_url")
                        or os.environ.get("OPENAI_API_BASE", "https://api.openai.com")).rstrip("/")
                if not base.startswith(("http://", "https://")):
                    return {"ok": False, "backend": backend,
                            "error": f"Base URL must start with http:// or https:// (got: {base!r})"}
                resp = await c.post(
                    f"{base}/v1/chat/completions",
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
                if not base.startswith(("http://", "https://")):
                    return {"ok": False, "backend": backend,
                            "error": "Azure Endpoint is empty or missing http(s)://."}
                low = base.lower()
                payload = {"messages": [{"role": "user", "content": "Reply with OK"}], "max_tokens": 5}
                if ".services.ai.azure.com" in low or "/openai/v1" in low or low.rstrip("/").endswith("/openai"):
                    # Foundry OpenAI-compatible: model in body, no api-version.
                    import re as _re
                    root = _re.sub(r'(/openai)?(/v1)?(/chat/completions)?/?$', '', base, flags=_re.I).rstrip("/")
                    url = f"{root}/openai/v1/chat/completions"
                    payload["model"] = model
                elif ".models.ai.azure.com" in low:
                    url = f"{base}/v1/chat/completions"
                    payload["model"] = model
                else:
                    url = f"{base}/openai/deployments/{model}/chat/completions?api-version={os.environ.get('AZURE_API_VERSION', '2024-08-01-preview')}"
                resp = await c.post(url, headers={"api-key": api_key}, json=payload)
                resp.raise_for_status()
                return {"ok": True, "backend": backend, "model": model,
                        "response": resp.json()["choices"][0]["message"]["content"]}

            else:
                # Was https:// — llm_query serves plain HTTP, so this leg
                # always failed with SSL WRONG_VERSION_NUMBER and the
                # ollama backend test could never pass.
                resp = await c.get(f"{LLM_QUERY_URL}/ollama/health")
                data = resp.json()
                return {"ok": data.get("ok", False), "backend": "ollama",
                        "model": os.environ.get("OLLAMA_MODEL", ""), "detail": data}

    except httpx.HTTPStatusError as e:
        return {"ok": False, "backend": backend, "error": f"HTTP {e.response.status_code}: {e.response.text[:300]}"}
    except Exception as e:
        return {"ok": False, "backend": backend, "error": str(e)}


@router.get("/api/settings/llm/models")
async def list_llm_models(backend: Optional[str] = None):
    """List selectable model IDs for the given/configured backend (best effort).

    Populates the Model autocomplete in the LLM Tuning tab. ALWAYS returns a
    `models` list (possibly empty) — the field stays free-text, so a failure here
    just means no suggestions, never a broken form. For openai it queries the
    endpoint's OpenAI-compatible `/v1/models`; for ollama, `/api/tags`.
    """
    s = get_settings()
    keys: dict = {}
    async with httpx.AsyncClient(timeout=10) as c:
        for key in _LLM_KEYS:
            try:
                resp = await c.get(f"{s.rag_api_url}/settings/config/{key}",
                                   headers={"x-api-key": s.api_key, **engagement_headers()})
                if resp.status_code == 200:
                    keys[key.replace("llm.", "")] = resp.json().get("value", "")
            except Exception:
                pass
    backend = (backend or keys.get("backend") or os.environ.get("LLM_BACKEND", "ollama")).lower()
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            if backend == "openai":
                base = (keys.get("openai_base_url")
                        or os.environ.get("OPENAI_API_BASE", "https://api.openai.com")).rstrip("/")
                api_key = keys.get("openai_api_key") or os.environ.get("OPENAI_API_KEY", "")
                if not base.startswith(("http://", "https://")):
                    return {"ok": False, "backend": backend, "models": [],
                            "error": "Base URL missing http(s)://"}
                resp = await c.get(f"{base}/v1/models", headers={"Authorization": f"Bearer {api_key}"})
                resp.raise_for_status()
                data = resp.json().get("data", [])
                models = sorted({m.get("id") for m in data if isinstance(m, dict) and m.get("id")},
                                key=str.lower)
                return {"ok": True, "backend": backend, "models": models}
            if backend == "azure":
                endpoint = (keys.get("azure_endpoint") or os.environ.get("AZURE_ENDPOINT", "")).rstrip("/")
                api_key = keys.get("azure_api_key") or os.environ.get("AZURE_API_KEY", "")
                low = endpoint.lower()
                if not endpoint.startswith(("http://", "https://")):
                    return {"ok": False, "backend": backend, "models": [],
                            "error": "Azure Endpoint missing http(s)://"}
                if ".services.ai.azure.com" in low or "/openai/v1" in low or low.rstrip("/").endswith("/openai"):
                    import re as _re
                    root = _re.sub(r'(/openai)?(/v1)?/?$', '', endpoint, flags=_re.I).rstrip("/")
                    resp = await c.get(f"{root}/openai/v1/models", headers={"api-key": api_key})
                elif ".models.ai.azure.com" in low:
                    resp = await c.get(f"{endpoint}/v1/models", headers={"api-key": api_key})
                else:
                    resp = await c.get(
                        f"{endpoint}/openai/deployments?api-version={os.environ.get('AZURE_API_VERSION', '2024-08-01-preview')}",
                        headers={"api-key": api_key})
                resp.raise_for_status()
                data = resp.json().get("data", [])
                models = sorted({m.get("id") for m in data if isinstance(m, dict) and m.get("id")},
                                key=str.lower)
                return {"ok": True, "backend": backend, "models": models}
            if backend == "ollama":
                base = os.environ.get("OLLAMA_URL", "http://ollama:11434").rstrip("/")
                resp = await c.get(f"{base}/api/tags")
                resp.raise_for_status()
                models = sorted({m.get("name") for m in resp.json().get("models", []) if m.get("name")},
                                key=str.lower)
                return {"ok": True, "backend": backend, "models": models}
            return {"ok": True, "backend": backend, "models": []}
    except Exception as e:
        return {"ok": False, "backend": backend, "models": [], "error": str(e)}


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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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


# ── 429 backoff, reported by the processes that actually apply it ──────────
#
# There are TWO independent mechanisms because there are two paths to the
# provider, and conflating them in the UI would be a lie:
#   llm_query       — retry-on-429 at the shared HTTP chokepoint (news,
#                     scan-recommender, anything routed through the service)
#   autogen-agents  — an adaptive AIMD governor on the direct langchain path
#
# Values come from each PROCESS, never from .env on disk. They diverge the
# moment someone edits .env without recreating the container, and a panel that
# shows the file would confirm a setting that is not in force.
#
# Each source reports one of three outcomes — ok / error / unreachable — rather
# than collapsing "could not ask" into "nothing configured". That collapse is
# the recurring bug in this repo, and it reads as "no throttling" on a stack
# that is throttling hard.
@router.get("/api/settings/llm-backoff")
async def get_llm_backoff():
    """Effective 429 backoff knobs + live governor state, per service."""
    s = get_settings()
    targets = [("llm_query", f"{LLM_QUERY_URL}/config/backoff"),
               ("autogen-agents", f"{s.autogen_url}/llm/ratelimit")]
    out = []
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL, verify=False) as c:
        for name, url in targets:
            try:
                resp = await c.get(url, headers={"x-api-key": s.api_key})
            except Exception as e:  # noqa: BLE001
                out.append({"service": name, "status": "unreachable",
                            "error": f"{type(e).__name__}: {e}"[:200]})
                continue
            if resp.status_code >= 400:
                out.append({"service": name, "status": "error",
                            "error": f"HTTP {resp.status_code}: {resp.text[:200]}"})
                continue
            try:
                out.append({"service": name, "status": "ok", **resp.json()})
            except Exception as e:  # noqa: BLE001
                out.append({"service": name, "status": "error",
                            "error": f"bad JSON: {e}"})
    return {"sources": out,
            "note": ("These are environment variables read at process start. "
                     "Changing them means editing .env and RECREATING the "
                     "container (restart alone keeps the old values).")}


@router.get("/api/settings/llm-tuning")
async def get_llm_tuning():
    """Return current LLM tuning params with defaults + metadata."""
    s = get_settings()
    result: Dict[str, dict] = {}
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
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
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.put(f"{s.rag_api_url}/settings/agent-models/{agent_id}/auto",
                           json={"enabled": body.enabled},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()
