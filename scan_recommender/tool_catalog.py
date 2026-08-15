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
            # tool_flags is a dict of tool -> [flags]; keep it as-is so
            # flags_for() can distinguish "unprobed" from "no flags".
            if isinstance(data.get('tool_flags'), dict):
                _cache['tool_flags'] = data['tool_flags']
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
    # A value STARTING with a flag names no tool. Observed from qwen3.8: `-sV`
    # and `-sV -p 6667` returned as nmap *scripts* — scanner flags, not scripts,
    # unrunnable as `--script=-sV`. A genuine command names its binary first
    # (`nmap -sV -p {port} {target}`), so the first token is the discriminator;
    # checking "every token is a flag" missed `-sV -p 6667` because 6667 is not.
    words = [w for w in v.split() if w]
    if words and words[0].startswith("-"):
        return [v]                       # hand it back so it fails the ident check

    # Prose, not an invocation. Measured from qwen3.8, which returned
    # "Send IRC command prefixed with 'AB' to test for UnrealIRCd system-command
    # backdoor; verify server response..." in the script field. It described the
    # right technique but is not something a scanner can run, and it slipped
    # through as a "command" because it contains ordinary words.
    #
    # A real command names its binary or a script in the first few tokens, so
    # anything long-winded with no flag, no path and no placeholder is prose.
    if (len(words) > 6 and "--script" not in v and "{" not in v
            and not any(w.startswith("-") for w in words)
            and "/" not in v):
        return [v]                       # fails the identifier check below

    # Looks like a command (has flags or a placeholder) but names no script.
    if re.search(r"(^|\s)-{1,2}[A-Za-z]", v) or "{" in v:
        return []
    # Otherwise treat comma-separated tokens as identifiers. A space inside a
    # token is exactly the `smb Vuln-MS17-010` defect, so keep it as one token
    # and let the catalog check reject it.
    return [t.strip() for t in v.split(",") if t.strip()]


# Metasploit's module DIRECTORIES are plural (`exploits/`, `payloads/`) while its
# invocation syntax — and everything humans and models write — is singular
# (`exploit/unix/misc/distcc_exec`). The catalog is built by walking the source
# tree, so without folding these the validator rejects every real exploit module
# it is shown. `auxiliary` and `post` are spelled the same either way, which is
# why tests using auxiliary/ paths passed and hid this.
_MSF_DIR_TO_SYNTAX = {"exploits/": "exploit/", "payloads/": "payload/",
                      "posts/": "post/", "encoders/": "encoder/",
                      "nops/": "nop/", "evasions/": "evasion/"}


def _msf_canonical(path: str) -> str:
    """Fold a module path to msfconsole syntax."""
    p = path.strip().lower().lstrip("/")
    for dir_form, syntax in _MSF_DIR_TO_SYNTAX.items():
        if p.startswith(dir_form):
            return syntax + p[len(dir_form):]
    return p


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
        # `action` too: models put the script name in either field, and checking
        # only `script` let `-sV` and a sentence of prose through in measurement.
        values = [rec.get("script"), rec.get("action")]
    elif scanner in ("metasploit", "msf"):
        # Fold both sides to msfconsole syntax — see _MSF_DIR_TO_SYNTAX.
        catalog = {_msf_canonical(m) for m in (cats.get("msf_modules") or set())}
        label = "metasploit module"
        # Modules arrive in either field depending on the generator.
        values = [_msf_canonical(v) if v else v
                  for v in (rec.get("script"), rec.get("action"))]
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


# Scanner labels that are not the name of an executable.
_SCANNER_BINARY = {
    "metasploit": "msfconsole", "msf": "msfconsole",
    "nmap-smb-vuln": "nmap", "impacket-smbclient": "impacket-smbclient",
    "vulnx": None,          # runs via the assets software flow, not a binary here
}


def binary_available(rec: Dict) -> Tuple[Optional[bool], str]:
    """(available, binary_name). `available` is None when it cannot be judged.

    ADVISORY ONLY — deliberately not wired into the blocking path. Scanner labels
    are not reliably binary names (`metasploit` is msfconsole; tool_kb uses
    labels like `nmap-smb-vuln`), so blocking on absence would reproduce the
    false-positive failure that the msf `exploits/` vs `exploit/` bug caused.

    Useful as a signal: measured across the scanner containers, the models and
    tool_kb between them recommended ncrack, crackmapexec and snmp-check, none of
    which are installed anywhere in the stack.
    """
    cats = load_catalogs()
    binaries = cats.get("binaries") or set()
    scanner = (rec.get("scanner") or "").strip().lower()
    if not binaries or not scanner:
        return None, scanner
    mapped = _SCANNER_BINARY.get(scanner, scanner)
    if mapped is None:
        return None, scanner
    return (mapped in binaries), mapped


def flags_for(tool: str) -> Optional[List[str]]:
    """Known flags for a tool, or None when it was never probed successfully.

    None means "unknown", not "no flags" — a caller must not treat an unprobed
    tool as having an empty flag set and reject everything it is given.
    """
    cats = load_catalogs()
    raw = cats.get("tool_flags")
    if not isinstance(raw, dict):
        return None
    vals = raw.get((tool or "").strip().lower())
    return list(vals) if vals else None


def catalog_info(path: str = None) -> Dict:
    """Everything the UI needs to judge whether validation can be trusted.

    The catalog is a SNAPSHOT, deliberately: validation must not require live
    containers. The cost is that it goes stale silently — install a tool on a
    node and the validator will not know until someone re-runs the refresh. The
    file has always carried `generated_at` and nothing read it, so staleness was
    invisible. This surfaces it.
    """
    import datetime as _dt

    p = path or CATALOG_PATH
    info: Dict = {
        "path": p,
        "exists": os.path.exists(p),
        "counts": {},
        "generated_at": None,
        "age_seconds": None,
        "validated_scanners": sorted(_VALIDATED_SCANNERS),
        "supplement": {"path": None, "exists": False, "counts": {}},
    }
    if not info["exists"]:
        return info
    try:
        with open(p) as fh:
            data = json.load(fh)
    except Exception as e:
        info["error"] = f"unreadable: {e}"
        return info

    info["counts"] = {k: len(v) for k, v in data.items() if isinstance(v, list)}
    if isinstance(data.get("tool_flags"), dict):
        info["counts"]["tool_flags"] = len(data["tool_flags"])
    info["generated_at"] = data.get("generated_at")
    if info["generated_at"]:
        try:
            gen = _dt.datetime.fromisoformat(info["generated_at"])
            if gen.tzinfo is None:
                gen = gen.replace(tzinfo=_dt.timezone.utc)
            info["age_seconds"] = int(
                (_dt.datetime.now(_dt.timezone.utc) - gen).total_seconds())
        except Exception:
            pass

    supp = os.path.join(os.path.dirname(p) or ".", "tool_catalogs.local.json")
    info["supplement"]["path"] = supp
    if os.path.exists(supp):
        info["supplement"]["exists"] = True
        try:
            with open(supp) as fh:
                sdata = json.load(fh)
            info["supplement"]["counts"] = {
                k: len(v) for k, v in sdata.items() if isinstance(v, list)}
            note = sdata.get("_comment")
            if isinstance(note, list):
                info["supplement"]["notes"] = [
                    n for n in note if n.startswith("Inventoried from node")]
        except Exception as e:
            info["supplement"]["error"] = str(e)
    return info


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
