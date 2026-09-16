"""Operator allowlist for DoS exploits.

A denial-of-service exploit is never recommended/queued/approved/executed by
default (no access, only disruption). This module reads the operator override list
from knowledge/dos_exploit_overrides.yaml (RAG-first knowledge, also embedded for
discovery) so specific exploits can be EXEMPTED and allowed to fire. Shared by the
recommender (exploit_watcher), the approval sweep (rag-api) and the execution gate
(exploit-runner) so the allowlist means the same thing everywhere.
"""
import os
import time
import logging

log = logging.getLogger("dos_overrides")

_KNOWLEDGE_DIR = os.environ.get("KNOWLEDGE_DIR", "/knowledge")
_TTL = 60.0
_cache = {"t": 0.0, "entries": None}


def _load_entries():
    now = time.time()
    if _cache["entries"] is not None and (now - _cache["t"]) < _TTL:
        return _cache["entries"]
    path = os.path.join(_KNOWLEDGE_DIR, "dos_exploit_overrides.yaml")
    if not os.path.exists(path):
        alt = os.path.join(os.path.dirname(__file__), "..", "knowledge",
                           "dos_exploit_overrides.yaml")
        if os.path.exists(alt):
            path = alt
    entries = []
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for o in (data.get("overrides") or []):
            m = o.get("match") if isinstance(o, dict) else o
            if m:
                entries.append(str(m).strip().lower())
    except FileNotFoundError:
        entries = []
    except Exception as e:  # noqa: BLE001
        log.debug("dos_overrides load failed: %s", e)
        entries = []
    _cache["t"] = now
    _cache["entries"] = entries
    return entries


def is_dos_override(edb_id=None, module=None, title=None) -> bool:
    """True if this exploit is on the operator allowlist and may fire despite being
    tagged DoS. `match` equals an edb_id/module exactly, or is a substring of any
    of the identifiers (so a title token like 'slowloris' matches)."""
    entries = _load_entries()
    if not entries:
        return False
    edb = str(edb_id or "").lower().strip()
    mod = str(module or "").lower().strip()
    hay = " ".join(x for x in (edb, mod, str(title or "").lower()) if x)
    for m in entries:
        if m and (m == edb or m == mod or m in hay):
            return True
    return False
