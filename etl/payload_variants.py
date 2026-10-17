"""Which payload to send at THIS target, and what proves it there.

The class says WHAT the vulnerability is; this says what to actually send.
Different questions, different files: a path traversal is a path traversal
everywhere, but `/etc/passwd` is useless against IIS and `win.ini` is useless
against nginx.

Why it exists: `assets.os` has been in the schema for a long time and is
populated on 0 of 2,295 rows. Nothing in the build-PoC pipeline referenced an
OS at all, so the craft guidance compensated by HEDGING — the lfi and
path-traversal entries listed `/etc/passwd` and `win.ini` side by side and let
the model pick. A wrong pick costs a refine iteration that the loop then reads
as "the endpoint is wrong" rather than "the OS is wrong".

TWO AXES, not one. OS decides path separators and system files; RUNTIME decides
wrappers and app files and is independent of it — `php://filter` works on PHP
on Windows, `web.xml` is Java anywhere.

THREE OUTCOMES. An undetermined OS does NOT mean linux. `detect()` returns
None for what it could not establish, and `variants_for()` then returns EVERY
variant with `ambiguous=True`, so the build tries both and records which one
worked — paying the ambiguity once per build instead of once per iteration.

Pure: no database, no network. The caller supplies the headers, body and paths
it already has.

    pytest tests/test_payload_variants.py
"""
from __future__ import annotations

import os as _os
import re
import threading
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_HERE = _os.path.dirname(_os.path.abspath(__file__))
_DEFAULT_PATHS = (
    _os.path.join(_os.environ.get("KNOWLEDGE_DIR", "/knowledge"), "payload_variants.yaml"),
    _os.path.join(_HERE, "..", "knowledge", "payload_variants.yaml"),
)

_lock = threading.Lock()
_cache: Dict[str, Any] = {}


def load(path: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
    """The parsed table, cached. Empty (and `loaded` False) when unreadable."""
    global _cache
    with _lock:
        if _cache and not force and not path:
            return _cache
        data: Dict[str, Any] = {}
        src = None
        if yaml is not None:
            for p in ([path] if path else list(_DEFAULT_PATHS)):
                if not p or not _os.path.isfile(p):
                    continue
                try:
                    with open(p, encoding="utf-8") as fh:
                        data = yaml.safe_load(fh) or {}
                    src = p
                    break
                except Exception:  # noqa: BLE001
                    continue
        rules = []
        for r in (data.get("detection") or []):
            if not isinstance(r, dict) or not r.get("pattern"):
                continue
            try:
                rules.append({**r, "_re": re.compile(r["pattern"])})
            except re.error:
                continue        # a bad pattern is skipped, never fatal
        built = {"raw": data, "source": src, "rules": rules,
                 "variants": data.get("variants") or {},
                 "loaded": bool(data.get("variants"))}
        if not path:
            _cache = built
        return built


def loaded() -> bool:
    """Did the table load? `False` is not the same as "no variants"."""
    return bool(load().get("loaded"))


# ── detection ────────────────────────────────────────────────────────────────


def detect(headers=None, body=None, paths=None) -> dict:
    """Determine the target's OS and runtime from what recon already has.

    Returns {os, runtime, evidence, os_provenance, runtime_provenance}. A value
    is None when nothing established it — NOT a default. Reporting `linux`
    because nothing said otherwise is how a Windows target gets attacked with
    `/etc/passwd` for every iteration of a build.
    """
    t = load()
    hdrs = {str(k).lower(): str(v or "") for k, v in (headers or {}).items()}
    text = str(body or "")
    plist = [str(p) for p in (paths or [])]
    out = {"os": None, "runtime": None, "evidence": [],
           "os_provenance": None, "runtime_provenance": None,
           # THREE OUTCOMES for the detection itself. "nothing matched" and
           # "there was nothing to look at" both yield os=None, and they send
           # an operator to different fixes: the first means the target is
           # quiet, the second means recon handed us nothing to read.
           "basis": "no_material",
           "examined": {"headers": len(hdrs), "body_chars": len(text),
                        "paths": len(plist)}}
    if hdrs or text or plist:
        out["basis"] = "no_match"
    for r in t["rules"]:
        where = str(r.get("where") or "")
        hay = []
        if where == "header":
            hay = [hdrs.get(str(r.get("header") or "").lower(), "")]
        elif where == "body":
            hay = [text]
        elif where == "path":
            hay = plist
        if not any(h and r["_re"].search(h) for h in hay):
            continue
        hit = {"rule": r.get("id"), "where": where}
        used = False
        if r.get("os") and not out["os"]:
            out["os"] = str(r["os"])
            out["os_provenance"] = r.get("provenance") or "scan_observed"
            used = True
        if r.get("runtime") and not out["runtime"]:
            out["runtime"] = str(r["runtime"])
            out["runtime_provenance"] = r.get("provenance") or "scan_observed"
            used = True
        if used:
            out["evidence"].append(hit)
            out["basis"] = "matched"
        if out["os"] and out["runtime"]:
            break
    return out


# ── selection ────────────────────────────────────────────────────────────────


def variants_for(vuln_class, os=None, runtime=None) -> dict:
    """Variant entries that apply to this target.

    An entry declaring neither `os` nor `runtime` always applies. An entry
    declaring one applies when that axis matches OR when the axis is UNKNOWN —
    unknown means "try them all", with `ambiguous` set so the caller can say
    so rather than quietly picking one.
    """
    t = load()
    entries = t["variants"].get(str(vuln_class or "").strip().lower()) or []
    want_os = str(os).lower() if os else None
    want_rt = str(runtime).lower() if runtime else None
    keep, ambiguous_axes = [], set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        e_os = str(e["os"]).lower() if e.get("os") else None
        e_rt = str(e["runtime"]).lower() if e.get("runtime") else None
        if e_os:
            if want_os is None:
                ambiguous_axes.add("os")
            elif e_os != want_os:
                continue
        if e_rt:
            if want_rt is None:
                ambiguous_axes.add("runtime")
            elif e_rt != want_rt:
                continue
        keep.append(e)
    return {"entries": keep, "ambiguous": bool(ambiguous_axes),
            "ambiguous_axes": sorted(ambiguous_axes),
            "os": want_os, "runtime": want_rt,
            "reason": ("every variant applies because %s unknown"
                       % " and ".join(sorted(ambiguous_axes))
                       if ambiguous_axes else
                       "selected for os=%s runtime=%s" % (want_os, want_rt))}


def payloads_for(vuln_class, os=None, runtime=None) -> List[str]:
    """Flat, de-duplicated, order preserved — the first entry is the best bet."""
    out: List[str] = []
    for e in variants_for(vuln_class, os=os, runtime=runtime)["entries"]:
        for p in (e.get("payloads") or []):
            if p not in out:
                out.append(str(p))
    return out


def proof_for(vuln_class, os=None, runtime=None) -> Dict[str, str]:
    """{what was requested: regex only the real content matches}.

    This is the assertion's `expect_regex`, chosen for the target rather than
    guessed — which is why the OS work is not only about the payload: a right
    payload judged by a wrong regex still fails.
    """
    out: Dict[str, str] = {}
    for e in variants_for(vuln_class, os=os, runtime=runtime)["entries"]:
        for k, v in (e.get("proof") or {}).items():
            out.setdefault(str(k), str(v))
    return out


WORLD, PRIVILEGED, PROCESS = "world", "privileged", "process"


def proof_access_for(vuln_class, os=None, runtime=None) -> Dict[str, dict]:
    """{proof target: {readable, note}} — ACCESS PERMISSIONS, declared.

    Readability is not existence, and the loop cannot tell them apart: an
    empty read means either the primitive failed or the file was not readable.
    Under the repeated-outcome rule two empty results set a REQUIRED AXIS and
    walk the build away from a primitive that WAS working — a refutation
    manufactured out of a file permission.
    """
    out: Dict[str, dict] = {}
    for e in variants_for(vuln_class, os=os, runtime=runtime)["entries"]:
        for k, v in (e.get("proof_access") or {}).items():
            if not isinstance(v, dict):
                continue
            out.setdefault(str(k), {"readable": str(v.get("readable") or PROCESS),
                                    "note": " ".join(str(v.get("note") or "").split())})
    return out


def preferred_proof(vuln_class, os=None, runtime=None) -> List[str]:
    """Proof targets that are ALWAYS readable, best first.

    `/etc/passwd` is mode 0644 on every linux host; `/etc/shadow` is 0640
    root:shadow and the web-server user cannot read it. A target with no
    declared access is treated as world — most app files are owned by the app.
    """
    acc = proof_access_for(vuln_class, os=os, runtime=runtime)
    out = []
    for k in proof_for(vuln_class, os=os, runtime=runtime):
        if acc.get(k, {}).get("readable", WORLD) == WORLD:
            out.append(k)
    return out


def proof_caveats_for(vuln_class, os=None, runtime=None) -> Dict[str, str]:
    """Targets whose EMPTY result proves nothing, with the reason.

    Derived from `proof_access` rather than written twice: anything not
    world-readable is a permission outcome, not a refutation.
    """
    return {k: v["note"] for k, v in
            proof_access_for(vuln_class, os=os, runtime=runtime).items()
            if v.get("readable") != WORLD and v.get("note")}


def file_read_signatures() -> Dict[str, str]:
    """Every file-read proof signature, OS-blind.

    The projection that replaces api.py's `_FILE_READ_SIGNATURES` — the same
    table it always was, with the OS now recoverable instead of flattened away.
    """
    out: Dict[str, str] = {}
    for cls in ("path-traversal", "lfi", "ssi-injection"):
        for e in (load()["variants"].get(cls) or []):
            for k, v in (e.get("proof") or {}).items():
                out.setdefault(str(k), str(v))
    return out


def note(sel: dict) -> str:
    """One line for the trace: which variants, and whether we had to guess."""
    n = len(sel.get("entries") or [])
    if not n:
        return "[variants] none for this class"
    if sel.get("ambiguous"):
        return ("[variants] %d applied, %s — trying every form and recording "
                "which answers" % (n, sel.get("reason")))
    return "[variants] %d applied, %s" % (n, sel.get("reason"))
