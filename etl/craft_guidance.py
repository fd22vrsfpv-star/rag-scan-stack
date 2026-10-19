"""Per-class craft-and-prove guidance, read from knowledge/craft_guidance.yaml.

This was `_CRAFT_CLASS_GUIDANCE`, a 29-class dict literal in app/rag-api/api.py
— the largest class-keyed table still living in Python, so changing how a class
is crafted or proven cost an image rebuild. knowledge/ is bind-mounted, so the
YAML takes effect on the next process start with no rebuild.

Same path conventions as etl/vuln_classes.py: $KNOWLEDGE_DIR first, then the
repo-relative copy, so tests and containers resolve the same file.

FAILURE IS LOUD, NOT SILENT. An unreadable table returns a one-entry fallback
holding only `unknown` — enough that no caller KeyErrors — and logs at ERROR,
and `loaded()` reports False so a health check can tell "no guidance" from
"guidance loaded". Returning `{}` quietly would hand the crafter no class
guidance at all while every build still appeared to run normally.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Dict, Optional

log = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_PATHS = (
    os.path.join(os.environ.get("KNOWLEDGE_DIR", "/knowledge"), "craft_guidance.yaml"),
    os.path.join(_HERE, "..", "knowledge", "craft_guidance.yaml"),
)

# Used ONLY when the YAML cannot be read: one class, so the guard against
# hard-coded class vocabularies (tests/test_vuln_classes.py) does not see a
# second copy of the table, and no `["unknown"]` lookup can raise.
_FALLBACK = {
    "unknown": ("The CVE's vuln class is unclassified. Use the advisory_poc from "
                "the spec as a starting shape; adapt the canary placement to "
                "land in the response."),
}

_lock = threading.Lock()
_state: Dict[str, object] = {}


def load(path: Optional[str] = None, force: bool = False) -> Dict[str, str]:
    """Return {canonical_class: guidance_text}. Cached; `force` reloads."""
    with _lock:
        if _state.get("table") is not None and not force and path is None:
            return _state["table"]  # type: ignore[return-value]
        table: Optional[Dict[str, str]] = None
        src = None
        for p in ([path] if path else list(_DEFAULT_PATHS)):
            if not p or not os.path.exists(p):
                continue
            try:
                import yaml
                with open(p, encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                g = data.get("guidance") or {}
                if not isinstance(g, dict) or not g:
                    raise ValueError("no `guidance` mapping")
                table = {str(k): str(v) for k, v in g.items()}
                src = p
                break
            except Exception as e:  # noqa: BLE001
                log.error("craft guidance unreadable at %s: %s", p, e)
        if table is None:
            log.error("craft guidance NOT LOADED from any of %s — the crafter "
                      "gets only the `unknown` fallback for every class",
                      list(_DEFAULT_PATHS))
            table = dict(_FALLBACK)
            _state["loaded"] = False
        else:
            table.setdefault("unknown", _FALLBACK["unknown"])
            _state["loaded"] = True
        _state["table"] = table
        _state["source"] = src
        return table


def loaded() -> bool:
    """True only when the YAML was actually read (not the fallback)."""
    if "loaded" not in _state:
        load()
    return bool(_state.get("loaded"))


def source() -> Optional[str]:
    if "source" not in _state:
        load()
    return _state.get("source")  # type: ignore[return-value]
