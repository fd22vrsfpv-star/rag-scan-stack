"""Target fragility classification (shared, deterministic).

Some web targets are single-process / no-restart, or run a known-fragile build
that a state-mutating request can crash outright. A crash forecloses the
higher-value outcomes (admin/DB/RCE), so a fingerprinted-fragile target should be
driven with a NON-DESTRUCTIVE profile: skip or approval-gate the config-mutating
endpoints (``set_*``/``update_*``/``save``/``preset``/…) and throttle, rather than
exercising them blindly.

This module is the shared spine used by the recon/surface/crawl paths:

  * :func:`classify` — turn fingerprint signals (Server header, ``/openapi.json``
    title, a version string, the nmap product) into a :class:`Fragility` decision.
  * :func:`is_mutating_path` / :func:`is_mutating_method` — would this request
    change server state?
  * :func:`should_gate` — for a given fragility decision, should this specific
    (method, path) be skipped / approval-gated?

Deterministic and dependency-free so every service can import it and a unit test
can pin it.

OPEN_ITEMS: fragile/known-CVE targets are fingerprinted but not spared
destructive actions (LoLLMs CVE-2024-2624 config-save->reload DoS).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

# --- Non-destructive profile knobs -----------------------------------------
# A fragile target gets a smaller surface budget and slower cadence so we do not
# hammer a process that will not restart.
FRAGILE_MAX_MUTATING_TESTS = 0        # do not fire mutating endpoints unattended
FRAGILE_SURFACE_LIMIT = 8             # cap surface tests on a fragile target
FRAGILE_THROTTLE_SECONDS = 2.0        # inter-request delay hint for crawlers
FRAGILE_THROTTLE_FACTOR = 0.5         # run scans/brute-force at 50% aggressiveness


# Products/builds known to crash the whole process on a config-mutating request
# (or otherwise DoS-prone). Matched case-insensitively as a substring against the
# Server header, openapi title, and nmap product.
_KNOWN_FRAGILE_PRODUCTS = (
    "lollms",            # LoLLMs WebUI — CVE-2024-2624 unsafe-YAML config save->reload
)

# ASGI/dev servers that run single-process by default and do NOT restart on an
# unhandled exception in a request handler — one bad request takes the app down.
_SINGLE_PROCESS_SERVERS = (
    "uvicorn",
    "hypercorn",
    "werkzeug",          # Flask dev server
    "waitress",
)

# Version markers that indicate an unstable / pre-release build.
_PRERELEASE_RE = re.compile(r"\b(alpha|beta|dev|rc\d*|snapshot|nightly|pre-?release)\b", re.I)

# Path fragments that indicate a STATE-MUTATING endpoint. Deliberately broad: on
# a fragile target we would rather over-gate than crash it. Matched against the
# lowercased path.
_MUTATING_PATH_FRAGMENTS = (
    "set_", "/set", "update_", "/update", "save", "preset", "delete", "/del",
    "reset", "restart", "shutdown", "reboot", "config", "settings",
    "apply", "install", "uninstall", "upload", "import", "kill", "stop",
    "create", "add_", "remove", "purge", "drop", "wipe", "clear",
    "reload", "persist", "write",
)

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Fragility:
    """A fragility decision for one target."""
    fragile: bool
    profile: str = "normal"          # "normal" | "non_destructive"
    reasons: List[str] = field(default_factory=list)
    # The fingerprint that drove the decision (for recording / audit).
    server_header: Optional[str] = None
    openapi_title: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "fragile": self.fragile,
            "profile": self.profile,
            "reasons": self.reasons,
            "fingerprint": {
                "server_header": self.server_header,
                "openapi_title": self.openapi_title,
                "version": self.version,
                "product": self.product,
            },
        }


def _hay(*vals: Optional[str]) -> str:
    return " ".join(v for v in vals if v).lower()


def classify(server_header: Optional[str] = None,
             openapi_title: Optional[str] = None,
             version: Optional[str] = None,
             product: Optional[str] = None,
             single_process: Optional[bool] = None) -> Fragility:
    """Classify a target's fragility from its fingerprint.

    ``single_process`` may be passed explicitly (e.g. the crawler observed no
    restart-on-crash); otherwise it is inferred from the Server header.
    """
    reasons: List[str] = []
    hay = _hay(server_header, openapi_title, version, product)

    for prod in _KNOWN_FRAGILE_PRODUCTS:
        if prod in hay:
            reasons.append(f"known-fragile product: {prod}")

    server_low = (server_header or "").lower()
    if single_process is None:
        single_process = any(s in server_low for s in _SINGLE_PROCESS_SERVERS)
    if single_process:
        matched = next((s for s in _SINGLE_PROCESS_SERVERS if s in server_low), "single-process")
        reasons.append(f"single-process/no-restart server: {matched}")

    if version and _PRERELEASE_RE.search(version):
        reasons.append(f"pre-release build: {version}")
    elif openapi_title and _PRERELEASE_RE.search(openapi_title):
        reasons.append(f"pre-release build: {openapi_title}")

    fragile = bool(reasons)
    return Fragility(
        fragile=fragile,
        profile="non_destructive" if fragile else "normal",
        reasons=reasons,
        server_header=server_header,
        openapi_title=openapi_title,
        version=version,
        product=product,
    )


def is_mutating_method(method: Optional[str]) -> bool:
    return (method or "").strip().upper() in _MUTATING_METHODS


def is_mutating_path(path: Optional[str]) -> bool:
    """True when the path looks like a state-mutating endpoint. Note: on the
    LoLLMs DoS the crashing endpoints were config *save/reload* routes reachable
    by GET, so path — not just HTTP method — is what matters."""
    if not path:
        return False
    low = path.lower()
    return any(frag in low for frag in _MUTATING_PATH_FRAGMENTS)


def mutating_reason(method: Optional[str], path: Optional[str]) -> Optional[str]:
    if is_mutating_path(path):
        return f"mutating path: {path}"
    if is_mutating_method(method):
        return f"mutating method: {method}"
    return None


def should_gate(fragility: Optional[Fragility],
                method: Optional[str] = None,
                path: Optional[str] = None) -> bool:
    """Should this (method, path) be SKIPPED / approval-gated for this target?

    Only when the target is fragile AND the request is state-mutating. A fragile
    target's read-only surface is still fair game — we only spare the endpoints
    that could crash it.
    """
    if not fragility or not fragility.fragile:
        return False
    return is_mutating_path(path) or is_mutating_method(method)


def throttle(value, fragile: bool = True, factor: float = FRAGILE_THROTTLE_FACTOR):
    """Scale a scan-aggressiveness knob (THREADS, concurrency, rate) down for a
    fragile target. Returns an int >= 1 (never throttles a scan to zero). When
    not fragile, returns the value unchanged."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return value
    if not fragile:
        return v
    return max(1, int(round(v * factor)))


def probe_and_classify(host: str, ports=None, timeout: float = 6.0):
    """Live-probe a web host (Server header + /openapi.json title + a version
    endpoint) and classify its fragility — a self-contained path for services that
    do not have langgraph's DB-first _target_fragility. Best-effort; on any error
    returns a non-fragile decision. Requires httpx."""
    try:
        import httpx as _httpx
    except Exception:  # noqa: BLE001
        return Fragility(fragile=False)
    cand = list(ports) if ports else [9090, 8080, 80, 8000, 443, 8443]
    server_header = openapi_title = version = None
    for port in cand:
        scheme = "https" if int(port) in (443, 8443) else "http"
        base = f"{scheme}://{host}:{port}"
        try:
            r = _httpx.get(base + "/", timeout=timeout, verify=False,
                           follow_redirects=True)
            server_header = r.headers.get("server") or server_header
        except Exception:  # noqa: BLE001
            continue
        try:
            oj = _httpx.get(base + "/openapi.json", timeout=timeout, verify=False)
            if oj.status_code == 200:
                info = (oj.json() or {}).get("info", {}) or {}
                openapi_title = info.get("title") or openapi_title
                version = version or info.get("version")
        except Exception:  # noqa: BLE001
            pass
        if server_header:
            break
    return classify(server_header=server_header, openapi_title=openapi_title,
                    version=version)
