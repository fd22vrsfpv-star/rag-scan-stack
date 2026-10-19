"""CAPEC attack patterns, read from knowledge/mitre/capec.yaml.

The layer between a weakness (CWE) and a technique (ATT&CK). The same file is
embedded into rag_documents by etl/load_knowledge_documents.py (`_render_capec`)
for retrieval; this module answers the exact lookups the PoC pipeline needs:
"which attack patterns exploit this class's CWEs, and how".

Fail-soft and loud, like etl/craft_guidance.py: an unreadable file logs at
ERROR and yields no patterns; `loaded()` says which.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Dict, List, Optional

log = logging.getLogger(__name__)
_HERE = os.path.dirname(os.path.abspath(__file__))
_PATHS = (
    os.path.join(os.environ.get("KNOWLEDGE_DIR", "/knowledge"), "mitre", "capec.yaml"),
    os.path.join(_HERE, "..", "knowledge", "mitre", "capec.yaml"),
)
_lock = threading.Lock()
_state: Dict[str, object] = {}

# Standard/Detailed patterns name a concrete attack; Meta ones are umbrellas
# ("Inject Unexpected Items"). Prefer the concrete ones when ranking.
_ABSTRACTION_RANK = {"Detailed": 0, "Standard": 1, "Meta": 2}


def load(force: bool = False) -> List[dict]:
    with _lock:
        if "patterns" in _state and not force:
            return _state["patterns"]  # type: ignore[return-value]
        pats: List[dict] = []
        for p in _PATHS:
            if not os.path.exists(p):
                continue
            try:
                import yaml
                with open(p, encoding="utf-8") as f:
                    pats = list((yaml.safe_load(f) or {}).get("patterns") or [])
                break
            except Exception as e:  # noqa: BLE001
                log.error("capec unreadable at %s: %s", p, e)
        if not pats:
            log.error("CAPEC NOT LOADED from any of %s", list(_PATHS))
        _state["patterns"] = pats
        _state["loaded"] = bool(pats)
        return pats


def loaded() -> bool:
    load()
    return bool(_state.get("loaded"))


def get(capec_id: str) -> Optional[dict]:
    key = str(capec_id or "").upper()
    return next((p for p in load() if p.get("id") == key), None)


def for_cwes(cwes, limit: int = 5) -> List[dict]:
    """Patterns exploiting any of these CWEs, concrete ones with an execution
    flow first."""
    want = {str(c).upper() for c in (cwes or [])}
    hits = [p for p in load() if want & set(p.get("cwes") or [])]
    hits.sort(key=lambda p: (_ABSTRACTION_RANK.get(p.get("abstraction"), 3),
                             0 if p.get("execution_flow") else 1,
                             int(str(p.get("id", "CAPEC-0")).split("-")[1])))
    return hits[:limit]


def for_class(vuln_class: str, limit: int = 5) -> List[dict]:
    """Patterns for a vuln class, via the class table's CWEs."""
    try:
        from etl import vuln_classes as _vc
        cwes = _vc.cwe_ids_for(vuln_class)
    except Exception:  # noqa: BLE001
        cwes = []
    return for_cwes(cwes, limit)


def brief(p: dict, steps: int = 4) -> str:
    """One compact paragraph for a prompt: name, prerequisites, flow steps."""
    out = f"{p.get('id')} {p.get('name')}"
    if p.get("prerequisites"):
        out += ". Needs: " + "; ".join(p["prerequisites"][:3])
    flow = p.get("execution_flow") or []
    if flow:
        out += ". Steps: " + " -> ".join(f"[{s.get('phase')}] {s.get('step')}" for s in flow[:steps])
    return out
