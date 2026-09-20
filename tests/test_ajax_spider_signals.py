"""Guard: RAG-driven ajax-spider gating (knowledge/ajax_spider_signals.yaml +
etl/ajax_spider_signals.evaluate_ajax_signals + the web_tech fact).

The ajax (browser) spider is expensive and only worth running on JS-heavy / SPA
targets. This proves the decision is data-driven by the YAML and fires on the
right signals (XHR endpoint count, SPA framework, websockets) — and NOT on a
plain server-rendered app. Sabotage-proven: drop a signal branch or the YAML
threshold and a case flips.

Self-contained: evaluate_ajax_signals is exercised with a scripted fake cursor,
so it needs no DB.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "etl"))

yaml = pytest.importorskip("yaml")


class FakeCursor:
    """Answers the three queries evaluate_ajax_signals runs, by inspecting SQL."""
    def __init__(self, asset_ids, xhr_sum, dom_rows):
        self._asset_ids, self._xhr, self._dom = asset_ids, xhr_sum, dom_rows
        self._last = None
        self.connection = type("C", (), {"rollback": lambda self: None})()

    def execute(self, sql, params=None):
        self._last = sql

    def fetchall(self):
        s = self._last or ""
        if "FROM assets" in s:
            return [(a,) for a in self._asset_ids]
        if "FROM dom_analysis" in s:
            return self._dom
        return []

    def fetchone(self):
        return (self._xhr,)


def test_yaml_has_thresholds_and_frameworks():
    d = yaml.safe_load((ROOT / "knowledge/ajax_spider_signals.yaml").read_text())["ajax_spider_signals"]
    sig = d["signals"]
    assert sig["xhr_endpoints"]["min_count"] >= 1
    names = [n.lower() for n in sig["js_frameworks"]["names"]]
    assert "react" in names and "angular" in names and "vue" in names
    assert d["setting_key"] == "zap.ajax_spider"


def test_framework_triggers_js_heavy():
    from ajax_spider_signals import evaluate_ajax_signals
    cur = FakeCursor(asset_ids=["a1"], xhr_sum=0,
                     dom_rows=[(["React 18.2"], [], [])])
    r = evaluate_ajax_signals(cur, "spa.example.com")
    assert r["js_heavy"] is True
    assert "react" in r["js_frameworks"]


def test_xhr_count_triggers_js_heavy():
    from ajax_spider_signals import evaluate_ajax_signals
    cur = FakeCursor(asset_ids=["a1"], xhr_sum=5, dom_rows=[([], [], [])])
    r = evaluate_ajax_signals(cur, "api.example.com")
    assert r["js_heavy"] is True
    assert r["xhr_count"] == 5


def test_websocket_triggers_js_heavy():
    from ajax_spider_signals import evaluate_ajax_signals
    cur = FakeCursor(asset_ids=["a1"], xhr_sum=0,
                     dom_rows=[([], [], [{"url": "ws://x"}])])
    assert evaluate_ajax_signals(cur, "rt.example.com")["js_heavy"] is True


def test_server_rendered_app_not_js_heavy():
    """testfire-shape: a couple of jQuery scripts, no framework, few endpoints."""
    from ajax_spider_signals import evaluate_ajax_signals
    cur = FakeCursor(asset_ids=["a1"], xhr_sum=1,
                     dom_rows=[(["jquery-1.11.min.js"], ["/style.css"], [])])
    r = evaluate_ajax_signals(cur, "demo.testfire.net")
    assert r["js_heavy"] is False
    assert r["reasons"] == []


def test_no_asset_is_not_heavy():
    from ajax_spider_signals import evaluate_ajax_signals
    cur = FakeCursor(asset_ids=[], xhr_sum=0, dom_rows=[])
    assert evaluate_ajax_signals(cur, "unknown.example.com")["js_heavy"] is False


def test_default_cred_check_ajax_is_tristate_auto():
    src = (ROOT / "etl/default_cred_check.py").read_text()
    assert 'zap.ajax_spider", "auto"' in src or "zap.ajax_spider','auto'" in src
    assert "evaluate_ajax_signals" in src


def test_web_tech_fact_wired_into_enumeration():
    src = (ROOT / "etl/post_enumeration.py").read_text()
    assert "def facts_from_web_tech(" in src
    assert "facts += facts_from_web_tech(" in src
    assert '"fact": "web_tech"' in src


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
