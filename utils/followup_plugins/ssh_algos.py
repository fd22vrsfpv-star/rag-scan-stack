"""
SSH banner plugin: read initial SSH banner for quick info.
"""
import socket
from typing import Dict, Any


def _get_banner(host: str, port: int, timeout: float = 5.0) -> str:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        return sock.recv(512).decode(errors="ignore").strip()


async def run(host: str, port: int, proto: str, context: Dict[str, Any]) -> Dict[str, Any]:
    try:
        banner = _get_banner(host, port)
        return {"findings": [{"plugin": "ssh_algos", "title": f"SSH banner {banner[:60]}", "severity": "info", "data": {"banner": banner}}]}
    except Exception as e:
        return {"findings": [{"plugin": "ssh_algos", "title": f"SSH check error on {host}:{port}", "severity": "low", "data": {"error": str(e)}}]}
