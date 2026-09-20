"""Decide whether a target is JS-heavy enough to warrant the ZAP ajax (browser)
spider, from enumeration signals — data-driven by knowledge/ajax_spider_signals.yaml
(RAG-first; edit the YAML, not this code, to tune thresholds/frameworks).

Signals (any one at/above threshold -> JS-heavy -> run the ajax spider):
  - XHR/fetch/API endpoints katana observed (content_extractions.api_endpoints)
  - an SPA framework in the page's JS (dom_analysis.javascript_libs/external_scripts)
  - any websocket usage (dom_analysis.websockets)

Used by:
  - etl/post_enumeration.facts_from_web_tech  -> emits a `web_tech` fact
  - etl/default_cred_check._zap_crawl_settings -> enables ajax when zap.ajax_spider='auto'
"""
import os
from typing import Any, Dict, List, Optional

try:
    import yaml
except Exception:  # noqa: BLE001  # pragma: no cover
    yaml = None

_KN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "knowledge")


def load_ajax_signals() -> Dict[str, Any]:
    """Load the ajax_spider_signals rule block (thresholds + framework list)."""
    path = os.path.join(_KN, "ajax_spider_signals.yaml")
    if not yaml or not os.path.exists(path):
        return {}
    try:
        data = yaml.safe_load(open(path, encoding="utf-8")) or {}
        d = data.get("ajax_spider_signals")
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _names_from(jsonb_val) -> List[str]:
    """Lowercased names out of a jsonb array that may hold strings or objects."""
    out = []
    for it in (jsonb_val or []):
        if isinstance(it, str):
            out.append(it.lower())
        elif isinstance(it, dict):
            for k in ("name", "library", "lib", "src", "url"):
                v = it.get(k)
                if isinstance(v, str):
                    out.append(v.lower())
                    break
    return out


def evaluate_ajax_signals(cur, host: str,
                          engagement_id: Optional[str] = None) -> Dict[str, Any]:
    """Evaluate the JS-heavy signals for `host`. Returns
    {js_heavy, xhr_count, js_frameworks, websockets, reasons}. Never raises;
    rolls back on a query error and reports js_heavy=False (fail-safe: the ajax
    spider stays off unless a signal positively fires)."""
    cfg = load_ajax_signals()
    sig = cfg.get("signals") or {}
    xhr_min = int((sig.get("xhr_endpoints") or {}).get("min_count", 3) or 3)
    fw_min = int((sig.get("js_frameworks") or {}).get("min_count", 1) or 1)
    fw_names = [str(n).lower() for n in ((sig.get("js_frameworks") or {}).get("names") or [])]
    ws_min = int((sig.get("websockets") or {}).get("min_count", 1) or 1)

    out: Dict[str, Any] = {"js_heavy": False, "xhr_count": 0,
                           "js_frameworks": [], "websockets": False, "reasons": []}
    if not host:
        return out
    try:
        cur.execute("SELECT id FROM assets WHERE hostname=%s OR host(ip)=%s", (host, host))
        asset_ids = [r[0] for r in cur.fetchall()]
        if not asset_ids:
            return out

        # XHR / API endpoints katana recorded for the asset(s).
        cur.execute(
            """SELECT COALESCE(SUM(jsonb_array_length(
                        CASE WHEN jsonb_typeof(api_endpoints)='array'
                             THEN api_endpoints ELSE '[]'::jsonb END)), 0)
                 FROM content_extractions
                WHERE asset_id = ANY(%s)""", (asset_ids,))
        out["xhr_count"] = int((cur.fetchone() or [0])[0] or 0)

        # SPA frameworks + websockets from the DOM analysis.
        cur.execute(
            """SELECT javascript_libs, external_scripts, websockets
                 FROM dom_analysis WHERE asset_id = ANY(%s)""", (asset_ids,))
        found_fw, ws_count = set(), 0
        for js_libs, ext_scripts, wsock in cur.fetchall():
            names = _names_from(js_libs) + _names_from(ext_scripts)
            for fw in fw_names:
                if any(fw in n for n in names):
                    found_fw.add(fw)
            if wsock:
                try:
                    ws_count += len(wsock)
                except Exception:  # noqa: BLE001
                    ws_count += 1
        out["js_frameworks"] = sorted(found_fw)
        out["websockets"] = ws_count >= ws_min
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
        return out

    if out["xhr_count"] >= xhr_min:
        out["reasons"].append(f"{out['xhr_count']} XHR/API endpoints (>= {xhr_min})")
    if len(out["js_frameworks"]) >= fw_min:
        out["reasons"].append("SPA framework(s): " + ", ".join(out["js_frameworks"]))
    if out["websockets"]:
        out["reasons"].append("websocket usage")
    out["js_heavy"] = bool(out["reasons"])
    return out
