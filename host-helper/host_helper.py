"""
Host Helper Service - Manages systemd units for SSH tunnels from containers.

This service runs with network_mode: host and systemd access to manage
SSH tunnel units that survive container restarts.
"""

import os
import subprocess
import logging
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-15s %(levelname)-5s %(message)s",
)
log = logging.getLogger("host_helper")

app = FastAPI(title="Host Helper", description="Systemd SSH Tunnel Manager")

SYSTEMD_DIR = Path("/etc/systemd/system")
AUTOSSH_CONFIG_DIR = Path("/opt/rag-scan-stack/systemd")


class TunnelConfig(BaseModel):
    """SSH tunnel configuration."""
    node_id: str
    name: str
    destination: str  # user@host
    port: int
    ssh_port: int = 22
    key_file: str = "/opt/rag-scan-stack/ssh-keys/id_rsa"


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "host-helper"}


@app.post("/tunnels/{port}")
async def create_tunnel(port: int, config: TunnelConfig):
    """Create systemd SSH tunnel unit for the specified port."""
    try:
        # Create environment config file
        env_file = AUTOSSH_CONFIG_DIR / f"autossh@{port}.conf"
        env_content = f"""SSH_DESTINATION={config.destination}
SSH_KEY_FILE={config.key_file}
SSH_PORT={config.ssh_port}
NODE_ID={config.node_id}
NODE_NAME={config.name}
"""

        # Ensure config directory exists
        AUTOSSH_CONFIG_DIR.mkdir(exist_ok=True)
        env_file.write_text(env_content)

        # Enable and start the service
        service_name = f"autossh@{port}.service"

        # Reload systemd daemon
        subprocess.run(["systemctl", "daemon-reload"], check=True)

        # Enable and start service
        subprocess.run(["systemctl", "enable", service_name], check=True)
        subprocess.run(["systemctl", "start", service_name], check=True)

        log.info(f"Created SSH tunnel service {service_name} for {config.name}")
        return {
            "ok": True,
            "service": service_name,
            "port": port,
            "destination": config.destination
        }

    except subprocess.CalledProcessError as e:
        log.error(f"Failed to create tunnel {port}: {e}")
        raise HTTPException(500, f"Systemd command failed: {e}")
    except Exception as e:
        log.error(f"Failed to create tunnel {port}: {e}")
        raise HTTPException(500, f"Failed to create tunnel: {e}")


@app.delete("/tunnels/{port}")
async def remove_tunnel(port: int):
    """Remove systemd SSH tunnel unit."""
    try:
        service_name = f"autossh@{port}.service"
        env_file = AUTOSSH_CONFIG_DIR / f"autossh@{port}.conf"

        # Stop and disable service (ignore errors if not running)
        try:
            subprocess.run(["systemctl", "stop", service_name], check=True)
        except subprocess.CalledProcessError:
            pass  # Service might not be running

        try:
            subprocess.run(["systemctl", "disable", service_name], check=True)
        except subprocess.CalledProcessError:
            pass  # Service might not be enabled

        # Remove config file
        if env_file.exists():
            env_file.unlink()

        log.info(f"Removed SSH tunnel service {service_name}")
        return {"ok": True, "service": service_name}

    except Exception as e:
        log.error(f"Failed to remove tunnel {port}: {e}")
        raise HTTPException(500, f"Failed to remove tunnel: {e}")


@app.get("/tunnels/{port}")
async def get_tunnel_status(port: int):
    """Get status of SSH tunnel systemd unit."""
    try:
        service_name = f"autossh@{port}.service"

        # Check if service is active
        result = subprocess.run([
            "systemctl", "is-active", service_name
        ], capture_output=True, text=True)

        is_active = result.returncode == 0 and result.stdout.strip() == "active"

        # Get service status details
        status_result = subprocess.run([
            "systemctl", "status", service_name
        ], capture_output=True, text=True)

        return {
            "service": service_name,
            "active": is_active,
            "status": status_result.stdout if status_result.returncode == 0 else None,
            "port": port
        }

    except Exception as e:
        raise HTTPException(500, f"Failed to get tunnel status: {e}")


@app.get("/tunnels")
async def list_tunnels():
    """List all autossh tunnel services."""
    try:
        # Find all autossh@*.service units
        result = subprocess.run([
            "systemctl", "list-units", "--all", "--no-legend", "--plain",
            "autossh@*.service"
        ], capture_output=True, text=True)

        tunnels = []
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line and 'autossh@' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        service = parts[0]
                        loaded = parts[1]
                        active = parts[2]
                        running = parts[3]

                        # Extract port from service name
                        if service.startswith('autossh@') and service.endswith('.service'):
                            port_str = service[8:-8]  # Remove autossh@ and .service
                            try:
                                port = int(port_str)
                                tunnels.append({
                                    "service": service,
                                    "port": port,
                                    "loaded": loaded,
                                    "active": active,
                                    "running": running
                                })
                            except ValueError:
                                continue

        return {"tunnels": tunnels}

    except Exception as e:
        raise HTTPException(500, f"Failed to list tunnels: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8029)