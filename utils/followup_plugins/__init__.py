"""
Minimal plugin registry for follow-up scanners.

Plugins must implement:
    async def run(host: str, port: int, proto: str, context: Dict[str, Any]) -> Dict[str, Any]

Return contract:
    {
      "findings": [
        {"plugin": "name", "title": "...", "severity": "info|low|...|critical", "data": {...}}
      ],
      "artifacts": [ ... ]  # optional
    }
"""
from typing import Dict, Any, Callable, Awaitable, Optional

Plugin = Callable[[str, int, str, Dict[str, Any]], Awaitable[Dict[str, Any]]]
_REGISTRY: Dict[str, Plugin] = {}


def register(name: str, plugin: Plugin):
    _REGISTRY[name] = plugin


def get(name: str) -> Optional[Plugin]:
    return _REGISTRY.get(name)


# Load and register built-in PoC plugins
from .http_title import run as http_title_run  # noqa: E402
from .tls_cert import run as tls_cert_run  # noqa: E402
from .ssh_algos import run as ssh_algos_run  # noqa: E402

register("http_title", http_title_run)
register("tls_cert", tls_cert_run)
register("ssh_algos", ssh_algos_run)
