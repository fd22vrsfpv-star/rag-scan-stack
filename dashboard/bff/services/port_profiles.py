"""Named port scope profiles — the single resolution point for scan port scope.

Profiles ("top-100", "top-1000", "web", "all") are defined in
``knowledge/port_profiles.yaml``, bind-mounted read-only at ``/knowledge``.  This
module loads that file and resolves a profile id into an **explicit port string**
(e.g. ``"1-65535"``) that is safe to hand to either masscan or nmap.

WHY EXPLICIT STRINGS AND NOT ``--top-ports N``:
    masscan has no ``--top-ports`` flag — it only understands ``-p <ranges>``.
    The legacy path smuggled ``--top-ports N`` through ``extra_args``, where
    nmap_scanner spliced it onto the command line AFTER ``-p <discovered ports>``
    (nmap-api.py ``run_nmap_batch``); nmap's last-flag-wins semantics then
    silently discarded everything masscan had just found.  Resolving to a real
    port string at the BFF edge keeps the masscan-discovery -> nmap-enrichment
    handoff intact.

FAILURE POLICY:
    If a requested profile cannot be resolved, ``resolve()`` raises
    ``PortProfileError`` and the caller returns an error.  It deliberately does
    NOT fall back to a narrower profile — an operator who asked for "all 65535
    ports" must never silently receive a top-100 sweep.  Callers that pass no
    profile at all are untouched (passthrough of their literal ``ports`` value),
    so a missing mount degrades to today's behaviour rather than to a wrong one.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from typing import Optional

import yaml

log = logging.getLogger("port_profiles")

PORT_PROFILES_PATH = os.environ.get("PORT_PROFILES_PATH", "/knowledge/port_profiles.yaml")

# Sentinel profile id meaning "use the operator's free-text `ports` verbatim".
CUSTOM = "custom"

# A resolved port string must be masscan-safe: digits, commas and hyphens only.
# This is deliberately checked even for values that came from the YAML, so a
# hand-edited file containing e.g. "--top-ports 100" cannot reach a scanner.
_SAFE_PORTS_RE = re.compile(r"^[0-9,\-]+$")

# Minimal correct fallback used only when the YAML is unreadable (missing mount).
# Values are byte-identical to the corresponding entries in port_profiles.yaml.
# ``top-1000`` is intentionally ABSENT: its list is too large to duplicate here,
# and substituting a smaller profile would silently narrow an operator's scope.
_BUILTIN_FALLBACK = {
    "top-100": {
        "label": "Top 100 ports",
        "description": "nmap's 100 most commonly open TCP ports.",
        "ports": (
            "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,"
            "143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,"
            "631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,"
            "2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,"
            "5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,"
            "7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,"
            "49152-49157"
        ),
    },
    "web": {
        "label": "Web ports",
        "description": "HTTP/HTTPS listeners only.",
        "ports": "80,443,3000,4443,5000,8000,8008,8080,8443,8888,9000,9090,9443",
    },
    "all": {
        "label": "All 65535 ports",
        "description": "Full TCP sweep.",
        "ports": "1-65535",
    },
}

_DEFAULT_PROFILE = "top-1000"

_cache: Optional[dict] = None
_cache_mtime: Optional[float] = None
_lock = threading.Lock()


class PortProfileError(ValueError):
    """Raised when a port profile cannot be resolved to a safe port string."""


def count_ports(ports: str) -> int:
    """Count individual ports in a masscan-style range string."""
    total = 0
    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                total += int(hi) - int(lo) + 1
            except ValueError:
                continue
        else:
            total += 1
    return total


def _load_from_disk() -> dict:
    """Read and validate port_profiles.yaml. Returns the builtin fallback on failure."""
    try:
        with open(PORT_PROFILES_PATH, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        log.error(
            "port_profiles.yaml not found at %s — is ./knowledge:/knowledge:ro "
            "mounted into this container? Falling back to builtin profiles "
            "(%s unavailable).",
            PORT_PROFILES_PATH, _DEFAULT_PROFILE,
        )
        return {"profiles": dict(_BUILTIN_FALLBACK), "default": "top-100", "degraded": True}
    except Exception as e:
        log.error("Failed to parse %s: %s — falling back to builtin profiles", PORT_PROFILES_PATH, e)
        return {"profiles": dict(_BUILTIN_FALLBACK), "default": "top-100", "degraded": True}

    profiles: dict[str, dict] = {}
    for pid, body in (raw.get("profiles") or {}).items():
        if not isinstance(body, dict):
            log.warning("port profile %r is not a mapping — skipping", pid)
            continue
        ports = str(body.get("ports") or "").replace(" ", "")
        if not ports:
            log.warning("port profile %r has no ports — skipping", pid)
            continue
        if not _SAFE_PORTS_RE.match(ports):
            # e.g. someone hand-edited "--top-ports 100" into the file.
            log.error(
                "port profile %r has unsafe ports value %r (must be digits, "
                "commas and hyphens only) — skipping",
                pid, ports[:60],
            )
            continue
        profiles[str(pid)] = {
            "label": str(body.get("label") or pid),
            "description": str(body.get("description") or ""),
            "ports": ports,
        }

    if not profiles:
        log.error("%s contained no usable profiles — falling back to builtins", PORT_PROFILES_PATH)
        return {"profiles": dict(_BUILTIN_FALLBACK), "default": "top-100", "degraded": True}

    default = str(raw.get("default") or _DEFAULT_PROFILE)
    if default not in profiles:
        log.warning("default profile %r not defined — using %r", default, next(iter(profiles)))
        default = next(iter(profiles))

    return {"profiles": profiles, "default": default, "degraded": False}


def load_profiles(force: bool = False) -> dict:
    """Return ``{profiles: {...}, default: str, degraded: bool}``, cached by file mtime.

    The mount is read-only and changes rarely, so we re-read only when the file's
    mtime moves (or ``force=True``), which lets an operator edit the YAML and
    pick it up without a container restart.
    """
    global _cache, _cache_mtime
    try:
        mtime = os.path.getmtime(PORT_PROFILES_PATH)
    except OSError:
        mtime = None

    with _lock:
        if not force and _cache is not None and mtime == _cache_mtime:
            return _cache
        _cache = _load_from_disk()
        _cache_mtime = mtime
        return _cache


def list_profiles() -> dict:
    """Shape for ``GET /api/port-profiles``."""
    data = load_profiles()
    return {
        "profiles": [
            {
                "id": pid,
                "label": body["label"],
                "description": body["description"],
                "ports": body["ports"],
                "port_count": count_ports(body["ports"]),
            }
            for pid, body in data["profiles"].items()
        ],
        "default": data["default"],
        "degraded": data["degraded"],
    }


def resolve(profile: Optional[str], ports: Optional[str] = None) -> Optional[str]:
    """Resolve a profile id into an explicit, scanner-safe port string.

    - ``profile`` empty/None or ``"custom"`` -> passthrough of ``ports`` unchanged
      (preserves every existing caller, including literal ``--top-ports N``
      strings that ``_normalize_ports`` still handles downstream).
    - a known profile id -> its explicit port string.
    - an unknown profile id -> ``PortProfileError`` (never a silent fallback).
    """
    if not profile:
        return ports
    pid = str(profile).strip().lower()
    if pid == CUSTOM:
        return ports

    data = load_profiles()
    body = data["profiles"].get(pid)
    if body is None:
        known = ", ".join(sorted(data["profiles"])) or "(none)"
        hint = ""
        if data["degraded"]:
            hint = (
                " The port profile file could not be read — check that "
                "./knowledge:/knowledge:ro is mounted into this container."
            )
        raise PortProfileError(
            f"Unknown port profile {profile!r}. Known profiles: {known}.{hint}"
        )

    resolved = body["ports"]
    if not _SAFE_PORTS_RE.match(resolved):  # belt and braces; _load_from_disk already filters
        raise PortProfileError(f"Port profile {pid!r} resolved to an unsafe value")
    return resolved
