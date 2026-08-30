"""WSTG finding->test matcher + guidance loader.

Single source of truth for turning a web finding into a WSTG-guided test spec.
The map (knowledge/wstg_map.yaml, bind-mounted at /knowledge) keys a finding
(issue_type / CWE / nuclei tag / name) to a WSTG test id + a concrete
tier/category/tool/command/assertion. The prose "how to test" comes from the
ingested WSTG corpus in exploit_chunks (doc_kind='wstg'), matched by wstg_id.

This lives ONLY here; the agent tool and the surface-test phase both reach it
through the /rag/wstg endpoints, so the finding->test logic is never duplicated
across containers.
"""
from __future__ import annotations

import os
import threading
from typing import Any, Dict, List, Optional

_MAP_PATH = os.environ.get("WSTG_MAP_PATH", "/knowledge/wstg_map.yaml")
_lock = threading.Lock()
_cache: Optional[Dict[str, Any]] = None
_cache_mtime: float = 0.0


def load_map() -> Dict[str, Any]:
    """Load + cache the map, reloading if the file changed on disk."""
    global _cache, _cache_mtime
    with _lock:
        try:
            mtime = os.path.getmtime(_MAP_PATH)
        except OSError:
            return {"version": 0, "entries": []}
        if _cache is None or mtime != _cache_mtime:
            import yaml
            with open(_MAP_PATH, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            data.setdefault("entries", [])
            _cache, _cache_mtime = data, mtime
        return _cache


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def match_finding(
    *,
    issue_type: Optional[str] = None,
    cwe: Optional[List[str]] = None,
    name: Optional[str] = None,
    nuclei_tags: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Return the first map entry whose `match` block hits, or None.

    Any signal hitting is a match: a CWE id (exact, case-insensitive), a nuclei
    tag (exact), or a substring of issue_type / name against the entry's
    issue_type / name_contains lists.
    """
    it = _norm(issue_type)
    nm = _norm(name)
    cwes = {_norm(c) for c in (cwe or []) if c}
    tags = {_norm(t) for t in (nuclei_tags or []) if t}

    for entry in load_map().get("entries", []):
        m = entry.get("match", {}) or {}
        # CWE — exact id match
        if cwes & {_norm(c) for c in m.get("cwe", [])}:
            return entry
        # nuclei tag — exact
        if tags & {_norm(t) for t in m.get("nuclei_tags", [])}:
            return entry
        # issue_type / name — substring either direction on the free text
        for needle in m.get("issue_type", []):
            n = _norm(needle)
            if n and (n in it or n in nm):
                return entry
        for needle in m.get("name_contains", []):
            n = _norm(needle)
            if n and (n in it or n in nm):
                return entry
    return None


def render_command(entry: Dict[str, Any], *, target: str, url: Optional[str] = None) -> str:
    """Fill {target}/{url} in the entry's command. {url} falls back to target."""
    cmd = str(entry.get("command", ""))
    return (cmd.replace("{url}", url or target)
               .replace("{target}", target))
