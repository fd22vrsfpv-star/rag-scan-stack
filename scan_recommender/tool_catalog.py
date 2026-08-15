"""Validate that a recommended scan can actually be run.

Recommendations come from two places — deterministic tool_kb rules and an LLM
carrying operator guidance — and the LLM half is not constrained to real tool
names. Observed live: `smb Vuln-MS17-010` (capital V, space for a hyphen), which
is not an nmap script and would have been dispatched and failed at the scanner.

The catalogs are snapshotted from the running containers by
scripts/refresh-tool-catalogs.sh into knowledge/tool_catalogs.json, which is
already bind-mounted read-only here.

FAILURE BIAS — the important design decision
--------------------------------------------
This gate can block work, so it is built to *fail open*: a recommendation is
rejected only when a token is confidently identified AND confidently absent from
a populated catalog. Everything else passes:

  * catalog empty or missing        -> pass (cannot verify != invalid)
  * scanner with no catalog         -> pass (snmpwalk, hydra, gobuster, …)
  * value is a shell command        -> validate only the --script= names in it
  * glob patterns (`snmp-*`)        -> pass if ANY real script matches

Blocking a legitimate scan is worse than letting one bad invocation through: a
bad one fails loudly at the scanner, while a wrongly-blocked one silently
removes coverage the operator asked for.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CATALOG_PATH = os.environ.get("TOOL_CATALOG_PATH", "/knowledge/tool_catalogs.json")

# Validation is only meaningful for scanners whose vocabulary is a closed set.
_VALIDATED_SCANNERS = {"nmap", "metasploit", "msf", "nuclei"}

_cache: Optional[Dict] = None
_cache_mtime: Optional[float] = None

# A token that could plausibly be a script/module identifier rather than prose.
_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/*-]*$")


def load_catalogs(path: str = None) -> Dict[str, List[str]]:
    """Load the catalog file, re-reading only when it changes on disk."""
    global _cache, _cache_mtime
    p = path or CATALOG_PATH
    try:
        mtime = os.path.getmtime(p)
    except OSError:
        if _cache is None:
            logger.info("Tool catalog %s not found — validation disabled "
                        "(run scripts/refresh-tool-catalogs.sh)", p)
            _cache, _cache_mtime = {}, None
        return _cache or {}
    if _cache is None or mtime != _cache_mtime:
        try:
            with open(p) as fh:
                data = json.load(fh)
            _cache = {k: set(v) for k, v in data.items() if isinstance(v, list)}
            _cache_mtime = mtime
            logger.info("Loaded tool catalogs: %s",
                        ", ".join(f"{k}={len(v)}" for k, v in sorted(_cache.items())))
        except Exception as e:
            logger.warning("Tool catalog %s unreadable (%s) — validation disabled", p, e)
            _cache, _cache_mtime = {}, mtime
    return _cache or {}


def _script_tokens(value: str) -> List[str]:
    """The script/module identifiers in a value, or [] if it carries none.

    Handles the two shapes that reach us: a bare identifier
    (`smb-enum-shares`, `auxiliary/admin/smb/samba_symlink_traversal`) and a full
    command from a tool_kb rule (`nmap -sV --script=mysql-* {target}`).
    """
    v = (value or "").strip()
    if not v:
        return []
    # A command line: only the --script= payload is a script name. Anything else
    # in it is flags and targets, which we must not try to validate.
    if "--script" in v:
        out: List[str] = []
        for m in re.finditer(r"--script[= ]([^\s]+)", v):
            out.extend(t for t in m.group(1).strip("\"'").split(",") if t)
        return out
    # Looks like a command (has flags or a placeholder) but names no script.
    if re.search(r"(^|\s)-{1,2}[A-Za-z]", v) or "{" in v:
        return []
    # Otherwise treat comma-separated tokens as identifiers. A space inside a
    # token is exactly the `smb Vuln-MS17-010` defect, so keep it as one token
    # and let the catalog check reject it.
    return [t.strip() for t in v.split(",") if t.strip()]


def _known(token: str, catalog: set) -> bool:
    """Is this token in the catalog, allowing glob patterns?"""
    t = token.strip().lower()
    if not t:
        return True
    if t in catalog:
        return True
    if "*" in t or "?" in t:
        # `snmp-*` is a legitimate nmap invocation; real if anything matches.
        return any(fnmatch.fnmatchcase(c, t) for c in catalog)
    return False


def validate_recommendation(rec: Dict) -> Tuple[bool, Optional[str]]:
    """(ok, reason). `ok` is False only on a confident catalog miss."""
    cats = load_catalogs()
    if not cats:
        return True, None

    scanner = (rec.get("scanner") or "").strip().lower()
    if scanner not in _VALIDATED_SCANNERS:
        return True, None

    if scanner == "nmap":
        catalog, label = cats.get("nmap_scripts") or set(), "nmap script"
        values = [rec.get("script")]
    elif scanner in ("metasploit", "msf"):
        catalog, label = cats.get("msf_modules") or set(), "metasploit module"
        # Modules arrive in either field depending on the generator.
        values = [rec.get("script"), rec.get("action")]
    else:  # nuclei — a template id OR a tag expression
        catalog = (cats.get("nuclei_templates") or set()) | (cats.get("nuclei_tags") or set())
        label, values = "nuclei template/tag", [rec.get("template")]

    if not catalog:
        return True, None          # catalog unavailable: cannot verify

    for value in values:
        for token in _script_tokens(value or ""):
            if not _IDENT_RE.match(token):
                # Contains whitespace or punctuation no identifier has. This is
                # the `smb Vuln-MS17-010` case.
                return False, f"{label} {token!r} is not a valid identifier"
            if not _known(token, catalog):
                return False, f"{label} {token!r} does not exist"
    return True, None


def filter_recommendations(recs: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Split into (runnable, rejected). Rejected carry a `_rejection` reason."""
    ok, bad = [], []
    for rec in recs:
        valid, reason = validate_recommendation(rec)
        if valid:
            ok.append(rec)
        else:
            bad.append({**rec, "_rejection": reason})
    return ok, bad
