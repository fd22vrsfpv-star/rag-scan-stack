"""
TLS cert plugin: connects with TLS (no verification) and extracts cert and negotiated params.
"""
import ssl
import socket
from typing import Dict, Any


def _get_cert(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            pem = ssl.DER_cert_to_PEM_cert(der)
            info = ssock.getpeercert() or {}
            proto = ssock.version()
            cipher = ssock.cipher()
            return {"pem": pem, "info": info, "tls_version": proto, "cipher": cipher}


async def run(host: str, port: int, proto: str, context: Dict[str, Any]) -> Dict[str, Any]:
    try:
        data = _get_cert(host, port)
        finding = {
            "plugin": "tls_cert",
            "title": f"TLS certificate for {host}:{port}",
            "severity": "info",
            "data": {"tls": {"version": data.get("tls_version"), "cipher": data.get("cipher")}},
        }
        return {"findings": [finding], "artifacts": [data]}
    except Exception as e:
        return {"findings": [{"plugin": "tls_cert", "title": f"TLS fetch error on {host}:{port}", "severity": "low", "data": {"error": str(e)}}]}
