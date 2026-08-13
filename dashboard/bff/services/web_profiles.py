"""Named web scan scope profiles — the single resolution point for web scan depth.

The web-side counterpart to ``port_profiles.py``. Profiles ("quick", "standard",
"deep", "api", "passive-web") live in ``knowledge/web_profiles.yaml``, bind-mounted
read-only at ``/knowledge``.

WHY A PROFILE RATHER THAN PER-TOOL FIELDS:
    A web scan's intensity is spread across half a dozen tools with different
    parameter names — pipeline ``skip_*`` flags, web-scan ``do_*`` flags, gobuster
    ``wordlist``, katana ``depth``, nuclei ``severity``/``tags``. Picking "how deep
    should this scan go" once and mapping it onto each tool keeps those in step;
    setting them by hand is where they drift (e.g. a big wordlist paired with a
    depth-1 crawl).

FAILURE POLICY:
    Mirrors port_profiles: an unresolvable profile raises ``WebProfileError``
    rather than silently substituting a different depth. Callers that pass no
    profile are untouched, so existing scans behave exactly as before.

RELATIONSHIP TO TRAINING DATA:
    A profile is the BASELINE. Operator-authored per-technology guidance
    (service_prompts with a `tech` selector, surfaced via /kb/web-guidance) is
    layered on top — it can add nuclei tags for whatever tech was detected, but
    never widens the stage list the operator chose.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from typing import Optional

import yaml

log = logging.getLogger("web_profiles")

WEB_PROFILES_PATH = os.environ.get("WEB_PROFILES_PATH", "/knowledge/web_profiles.yaml")

# Sentinel meaning "use the operator's individual form fields verbatim".
CUSTOM = "custom"

# Every stage the pipeline knows about, in execution order. A profile may only
# name stages from this set — a typo would otherwise silently disable a stage.
KNOWN_STAGES = ("wafw00f", "katana", "playwright", "gobuster", "nikto", "nuclei", "zap")

# Wordlist aliases the web_scanner accepts (see SCAN_FIELDS placeholder in
# dashboard/frontend/src/lib/constants.ts).
_SAFE_WORDLIST_RE = re.compile(r"^[A-Za-z0-9_.\-/]+$")
# Severities nuclei accepts.
_KNOWN_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}

_BUILTIN_FALLBACK = {
    "quick": {
        "label": "Quick",
        "description": "Shallow pass — WAF check, light crawl, high/critical templates only.",
        "stages": ["wafw00f", "katana", "nuclei"],
        "wordlist": "common", "max_paths": 25, "crawl_depth": 1,
        "nuclei_severity": "high,critical", "nuclei_tags": "",
    },
    "standard": {
        "label": "Standard",
        "description": "Balanced default — crawl, render, medium discovery, medium+ templates.",
        "stages": ["wafw00f", "katana", "playwright", "gobuster", "nuclei"],
        "wordlist": "medium", "max_paths": 100, "crawl_depth": 3,
        "nuclei_severity": "medium,high,critical", "nuclei_tags": "",
    },
    "deep": {
        "label": "Deep",
        "description": "Everything on, big wordlist, all severities, plus ZAP active scan.",
        "stages": list(KNOWN_STAGES),
        "wordlist": "big", "max_paths": 500, "crawl_depth": 5,
        "nuclei_severity": "info,low,medium,high,critical", "nuclei_tags": "",
    },
}

_DEFAULT_PROFILE = "standard"

_cache: Optional[dict] = None
_cache_mtime: Optional[float] = None
_lock = threading.Lock()


class WebProfileError(ValueError):
    """Raised when a web profile cannot be resolved."""


def _clean_profile(pid: str, body: dict) -> Optional[dict]:
    """Validate + normalize one profile entry. Returns None if unusable."""
    if not isinstance(body, dict):
        log.warning("web profile %r is not a mapping — skipping", pid)
        return None

    raw_stages = body.get("stages") or []
    if isinstance(raw_stages, str):
        raw_stages = [s.strip() for s in raw_stages.split(",")]
    stages, unknown = [], []
    for s in raw_stages:
        s = str(s).strip().lower()
        if not s:
            continue
        (stages if s in KNOWN_STAGES else unknown).append(s)
    if unknown:
        # Loud: a typo'd stage silently means "don't run that tool".
        log.error("web profile %r names unknown stage(s) %s — ignoring them (known: %s)",
                  pid, unknown, ", ".join(KNOWN_STAGES))
    if not stages:
        log.warning("web profile %r has no valid stages — skipping", pid)
        return None

    wordlist = str(body.get("wordlist") or "").strip()
    if wordlist and not _SAFE_WORDLIST_RE.match(wordlist):
        log.error("web profile %r has unsafe wordlist %r — dropping it", pid, wordlist[:40])
        wordlist = ""

    sev_in = str(body.get("nuclei_severity") or "").strip().lower()
    sevs = [s.strip() for s in sev_in.split(",") if s.strip()]
    bad = [s for s in sevs if s not in _KNOWN_SEVERITIES]
    if bad:
        log.error("web profile %r has unknown severity %s — dropping them", pid, bad)
        sevs = [s for s in sevs if s in _KNOWN_SEVERITIES]

    def _pos_int(key: str, default: int) -> int:
        try:
            n = int(body.get(key, default))
            return n if n > 0 else default
        except (TypeError, ValueError):
            log.warning("web profile %r has non-numeric %s — using %d", pid, key, default)
            return default

    return {
        "label": str(body.get("label") or pid),
        "description": str(body.get("description") or ""),
        "stages": stages,
        "wordlist": wordlist,
        "max_paths": _pos_int("max_paths", 100),
        "crawl_depth": _pos_int("crawl_depth", 3),
        "nuclei_severity": ",".join(sevs),
        "nuclei_tags": str(body.get("nuclei_tags") or "").strip(),
    }


def _load_from_disk() -> dict:
    try:
        with open(WEB_PROFILES_PATH, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        log.error(
            "web_profiles.yaml not found at %s — is ./knowledge:/knowledge:ro mounted "
            "into this container? Falling back to builtin profiles.",
            WEB_PROFILES_PATH,
        )
        return {"profiles": dict(_BUILTIN_FALLBACK), "default": _DEFAULT_PROFILE, "degraded": True}
    except Exception as e:
        log.error("Failed to parse %s: %s — falling back to builtin profiles", WEB_PROFILES_PATH, e)
        return {"profiles": dict(_BUILTIN_FALLBACK), "default": _DEFAULT_PROFILE, "degraded": True}

    profiles: dict[str, dict] = {}
    for pid, body in (raw.get("profiles") or {}).items():
        cleaned = _clean_profile(str(pid), body)
        if cleaned:
            profiles[str(pid)] = cleaned

    if not profiles:
        log.error("%s contained no usable profiles — falling back to builtins", WEB_PROFILES_PATH)
        return {"profiles": dict(_BUILTIN_FALLBACK), "default": _DEFAULT_PROFILE, "degraded": True}

    default = str(raw.get("default") or _DEFAULT_PROFILE)
    if default not in profiles:
        log.warning("default web profile %r not defined — using %r", default, next(iter(profiles)))
        default = next(iter(profiles))

    return {"profiles": profiles, "default": default, "degraded": False}


def load_profiles(force: bool = False) -> dict:
    """Return ``{profiles, default, degraded}``, cached by file mtime."""
    global _cache, _cache_mtime
    try:
        mtime = os.path.getmtime(WEB_PROFILES_PATH)
    except OSError:
        mtime = None
    with _lock:
        if not force and _cache is not None and mtime == _cache_mtime:
            return _cache
        _cache = _load_from_disk()
        _cache_mtime = mtime
        return _cache


def list_profiles() -> dict:
    """Shape for ``GET /api/web-profiles``."""
    data = load_profiles()
    return {
        "profiles": [
            {"id": pid, **body, "stage_count": len(body["stages"])}
            for pid, body in data["profiles"].items()
        ],
        "default": data["default"],
        "degraded": data["degraded"],
        "known_stages": list(KNOWN_STAGES),
    }


def resolve(profile: Optional[str]) -> Optional[dict]:
    """Resolve a profile id into its settings dict, or None for passthrough.

    - empty/None or ``"custom"`` -> None (caller's own fields are used verbatim)
    - a known id -> its settings
    - an unknown id -> ``WebProfileError`` (never a silent substitution)
    """
    if not profile:
        return None
    pid = str(profile).strip().lower()
    if pid == CUSTOM:
        return None

    data = load_profiles()
    body = data["profiles"].get(pid)
    if body is None:
        known = ", ".join(sorted(data["profiles"])) or "(none)"
        hint = ""
        if data["degraded"]:
            hint = (" The web profile file could not be read — check that "
                    "./knowledge:/knowledge:ro is mounted into this container.")
        raise WebProfileError(f"Unknown web profile {profile!r}. Known profiles: {known}.{hint}")
    return dict(body)
