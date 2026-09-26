"""Vulnerability-class methodology ("skill") loader — the ONE by-name resolver.

Reads knowledge/vuln_class_methodology.yaml (bind-mounted at /knowledge in every
service) and resolves a finding's vuln class to a curated methodology pack. Lives
in common/ so BOTH LLM consumers import the same implementation without an HTTP
hop: exploit_runner (web payload gen/refine) and autogen (test synthesizer +
the get_vuln_methodology agent tool). This is the deterministic, by-name
counterpart to similarity search — the pack is chosen by class identity, never by
a cosine score, so a new class takes effect the moment its YAML entry lands.

Mirrors app/rag-api/wstg.py: module-level path (env-overridable), a lock, an mtime
cache that reloads on change, and "any signal hits" matching semantics. Every
public function degrades to None/"" on any error so a caller never breaks a PoC or
a synthesis because the file was missing or malformed.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

_MAP_PATH = os.environ.get(
    "VULN_METHODOLOGY_PATH", "/knowledge/vuln_class_methodology.yaml")

_lock = threading.Lock()
_cache: Optional[Dict[str, Any]] = None
_cache_mtime: float = 0.0

_log = logging.getLogger("vuln_skills")


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def enabled(env_name: str, default: bool = True) -> bool:
    """Feature-flag check for the methodology feed. ON BY DEFAULT: an absent env
    var uses `default` (True), and only an explicit 0/false/no/off disables. Both
    injection sites (web gen/refine, synth) route their flag through here so the
    default posture lives in one place."""
    v = os.environ.get(env_name)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off", "")


def load_pack() -> Dict[str, Any]:
    """Load + cache the methodology file, reloading if it changed on disk.

    Returns the parsed mapping ``{"version": int, "classes": {id: entry}}`` or an
    empty-classes stub if the file is absent/unreadable/malformed.
    """
    global _cache, _cache_mtime
    with _lock:
        try:
            mtime = os.path.getmtime(_MAP_PATH)
        except OSError:
            return {"version": 0, "classes": {}}
        if _cache is None or mtime != _cache_mtime:
            try:
                import yaml
                with open(_MAP_PATH, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
            except Exception:
                return {"version": 0, "classes": {}}
            if not isinstance(data.get("classes"), dict):
                data["classes"] = {}
            _cache, _cache_mtime = data, mtime
        return _cache


def _classes() -> Dict[str, Any]:
    return load_pack().get("classes", {}) or {}


def resolve(
    issue_type: Optional[str] = None,
    cwe: Optional[Any] = None,
    name: Optional[str] = None,
    nuclei_tags: Optional[List[str]] = None,
) -> Optional[str]:
    """Return the canonical class id for these finding signals, or None.

    "Any signal hits" wins, mirroring wstg.match_finding: an exact match of the
    canonical id or any alias against issue_type / name / a CWE id / a nuclei tag,
    or a human-readable alias phrase appearing as a substring of issue_type/name.
    Short code-like aliases (cwe-*, nuclei:*) are matched only EXACTLY, never as
    substrings, so they cannot false-positive inside free text.
    """
    it = _norm(issue_type)
    nm = _norm(name)
    # cwe may be a str or a list
    if isinstance(cwe, (list, tuple, set)):
        cwes = {_norm(c) for c in cwe if c}
    else:
        cwes = {_norm(cwe)} if cwe else set()
    tags = {_norm(t) for t in (nuclei_tags or []) if t}
    tag_variants = tags | {f"nuclei:{t}" for t in tags}

    for cid, entry in _classes().items():
        cidn = _norm(cid)
        aliases = {_norm(a) for a in (entry.get("aliases") or [])}
        keys = {cidn} | aliases

        # exact whole-value match on issue_type / name
        if (it and it in keys) or (nm and nm in keys):
            return cid
        # exact CWE / nuclei-tag match
        if cwes & keys or tag_variants & keys:
            return cid
        # substring match — only for readable phrases, never for code-like aliases
        for a in keys:
            if a.startswith("cwe-") or a.startswith("nuclei:"):
                continue
            if (" " in a or len(a) >= 6) and ((it and a in it) or (nm and a in nm)):
                return cid
    return None


def get(canonical_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return the class entry (web_hint / synth_methodology / aliases) or None."""
    if not canonical_id:
        return None
    return _classes().get(canonical_id)


def match(
    issue_type: Optional[str] = None,
    cwe: Optional[Any] = None,
    name: Optional[str] = None,
    nuclei_tags: Optional[List[str]] = None,
) -> Optional[Dict[str, str]]:
    """Resolve + fetch in one call.

    Returns ``{"canonical", "web_hint", "synth_methodology"}`` or None if no class
    matched. The two text fields are always present (possibly empty strings).
    """
    cid = resolve(issue_type=issue_type, cwe=cwe, name=name, nuclei_tags=nuclei_tags)
    if not cid:
        return None
    entry = get(cid) or {}
    return {
        "canonical": cid,
        "web_hint": str(entry.get("web_hint") or "").strip(),
        "synth_methodology": str(entry.get("synth_methodology") or "").strip(),
    }


def web_block(issue_type: Optional[str] = None,
              flag: str = "WEB_METHODOLOGY") -> str:
    """Formatted web methodology block for the exploit_gen prompt, or "".

    ON by default (flag set to 0/false/no/off disables). Best-effort: any failure
    returns "". Capped at 700 chars so it cannot crowd out target context in a
    small model. This is where the web injection logic LIVES (import-light, so it
    is unit-testable without the exploit_runner module); the consumer helper just
    delegates here.
    """
    try:
        if not enabled(flag):
            return ""
        m = match(issue_type=issue_type)
        if not m or not m.get("web_hint"):
            return ""
        return f"\nMethodology ({m['canonical']}):\n{m['web_hint'][:700]}\n"
    except Exception:
        return ""


def synth_block(guidance: str, finding: Dict[str, Any],
                flag: str = "SYNTH_METHODOLOGY") -> str:
    """Prepend per-class methodology to the synth guidance, or return it unchanged.

    ON by default (flag set to 0/false/no/off disables). PREPENDED so it survives
    the caller's guidance cap. Best-effort: any failure returns guidance unchanged.
    The synth injection logic LIVES here (import-light, unit-testable without the
    autogen test_synth module); the consumer helper just delegates.
    """
    try:
        if not enabled(flag):
            return guidance
        finding = finding if isinstance(finding, dict) else {}
        m = match(issue_type=(finding.get("issue_type") or finding.get("finding_type")),
                  cwe=finding.get("cwe"), name=finding.get("name"))
        if not m or not m.get("synth_methodology"):
            return guidance
        block = (f"=== Methodology ({m['canonical']}) ===\n"
                 f"{m['synth_methodology'][:1500]}\n\n")
        return block + (guidance or "")
    except Exception:
        return guidance


def list_classes() -> List[Dict[str, str]]:
    """Every class id + a one-line summary (first sentence of web_hint), for a
    catalog the planner/UI can browse."""
    out: List[Dict[str, str]] = []
    for cid, entry in _classes().items():
        hint = str(entry.get("web_hint") or "").strip()
        summary = hint.split(". ", 1)[0][:160] if hint else ""
        out.append({"canonical": cid, "summary": summary})
    return out


# ── selection observability ──────────────────────────────────────────────────
# Every place that PICKS a knowledge source/skill for a finding routes through
# here so "which source built this?" is logged and (best-effort) emitted as a
# webhook, consistently across services (exploit_runner, autogen, scan-recommender,
# post-enumeration). Never raises into a build.
def selection_payload(canonical, *, source, phase, finding_id=None, target=None,
                      engagement_id=None, knowledge_source=None,
                      comparison_group=None):
    """Standard webhook body for a skill/source selection, or None when nothing
    was selected. `source` is the emitting subsystem (stored type becomes
    {source}_methodology_source_selected); `knowledge_source` is skill|rag|yaml."""
    if not canonical and not knowledge_source:
        return None
    return {"event_type": "methodology_source_selected", "source": source,
            "data": {"skill": canonical, "knowledge_source": knowledge_source,
                     "phase": phase, "finding_id": finding_id, "target": target,
                     "engagement_id": engagement_id,
                     "comparison_group": comparison_group}}


def emit_selected(canonical, *, source, phase, finding_id=None, target=None,
                  engagement_id=None, knowledge_source=None,
                  comparison_group=None):
    """Log the selection and emit a best-effort methodology_source_selected
    webhook. Never raises. Works in any service: API_BASE (or RAG_API_URL) +
    API_KEY from env, httpx or requests, whichever imports."""
    payload = selection_payload(
        canonical, source=source, phase=phase, finding_id=finding_id,
        target=target, engagement_id=engagement_id,
        knowledge_source=knowledge_source, comparison_group=comparison_group)
    if not payload:
        return
    _log.info("methodology selection: skill=%s knowledge_source=%s phase=%s "
              "source=%s finding=%s target=%s", canonical, knowledge_source,
              phase, source, finding_id, target)
    base = os.environ.get("API_BASE") or os.environ.get("RAG_API_URL")
    if not base:
        return
    url = f"{base.rstrip('/')}/webhooks/emit"
    headers = {"x-api-key": os.environ.get("API_KEY", ""),
               "Content-Type": "application/json"}
    try:
        try:
            import httpx
            httpx.post(url, headers=headers, json=payload, timeout=5, verify=False)
            return
        except ImportError:
            pass
        import requests
        requests.post(url, headers=headers, json=payload, timeout=5, verify=False)
    except Exception as e:  # noqa: BLE001
        _log.debug("selection webhook emit skipped: %s", e)
