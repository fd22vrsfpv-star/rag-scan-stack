"""Unit tests for scan-recommender feedback enrichments (G1 + G2).

Covers:
  - tool_kb tech-signature matching (G1)
  - _append_tech_targeted_recs (G1) with detected tech mocked
  - _append_high_value_port_recs (G2)
  - persist_recommendations writes `priority` + merges context into `extra`
  - _emit_webhook HTTP emit + WEBHOOK_ENABLED gate

Imports the scan_recommender module by file path (its sibling `from
tool_kb import ...` needs the scan_recommender/ dir on sys.path, and the
file name collides with the package dir, so we load it explicitly).
"""
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

SR_DIR = Path(__file__).parent.parent / "scan_recommender"
sys.path.insert(0, str(SR_DIR))  # let the module's bare imports resolve

from tool_kb import ToolKnowledgeBase, get_high_value_port_info  # noqa: E402

_spec = importlib.util.spec_from_file_location("sr_module", SR_DIR / "scan_recommender.py")
sr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sr)


def _kb_with(sigs):
    """Build a ToolKnowledgeBase with injected tech_signatures (no file/YAML)."""
    kb = ToolKnowledgeBase.__new__(ToolKnowledgeBase)
    kb._data = {"tech_signatures": sigs}
    return kb


@pytest.mark.unit
@pytest.mark.scan_recommender
class TestTechMatching:
    SIGS = {
        "wordpress": {"match": ["wordpress", "wp-content"], "nuclei_tags": ["wordpress", "wp-plugin"]},
        "apache": {"match": ["apache httpd", "apache/"], "nuclei_tags": ["apache"]},
        "nginx": {"match": ["nginx"], "nuclei_tags": ["nginx"]},
    }

    def test_matches_multiple_case_insensitive(self):
        kb = _kb_with(self.SIGS)
        names = {m["name"] for m in kb.match_tech_to_tags(["WordPress 5.9", "Apache/2.4.41"])}
        assert names == {"wordpress", "apache"}

    def test_no_match(self):
        kb = _kb_with(self.SIGS)
        assert kb.match_tech_to_tags(["CoolCMS X"]) == []

    def test_empty(self):
        kb = _kb_with(self.SIGS)
        assert kb.match_tech_to_tags([]) == []

    def test_dedup_same_signature(self):
        kb = _kb_with(self.SIGS)
        # two tokens both hit wordpress -> single match
        out = kb.match_tech_to_tags(["wordpress", "wp-content theme"])
        assert [m["name"] for m in out] == ["wordpress"]


@pytest.mark.unit
@pytest.mark.scan_recommender
class TestTechTargetedRecs:
    def test_appends_distinct_nuclei_rec(self, monkeypatch):
        monkeypatch.setattr(sr, "_get_detected_tech", lambda ip, port=None: (["WordPress 5.9"], "httpx"))
        monkeypatch.setattr(sr, "get_tool_kb",
                             lambda: _kb_with({"wordpress": {"match": ["wordpress"], "nuclei_tags": ["wordpress", "wp-plugin"]}}))
        recs = []
        matches = sr._append_tech_targeted_recs(recs, "1.2.3.4", 80)
        assert [m["name"] for m in matches] == ["wordpress"]
        assert len(recs) == 1
        r = recs[0]
        assert r["scanner"] == "nuclei"
        assert "wordpress" in r["template"]
        assert r["priority"] == 15
        # distinct action so the fingerprint differs from the generic nuclei rec
        assert r["action"] == "tech-targeted scan (wordpress)"
        assert r["tech_context"]["matched"] == "wordpress"

    def test_no_tech_no_recs(self, monkeypatch):
        monkeypatch.setattr(sr, "_get_detected_tech", lambda ip, port=None: ([], ""))
        recs = []
        assert sr._append_tech_targeted_recs(recs, "1.2.3.4", 80) == []
        assert recs == []


@pytest.mark.unit
@pytest.mark.scan_recommender
class TestHighValuePortRecs:
    def test_msf_port_bumps_priority_and_enqueues_module(self):
        recs = [{"scanner": "nuclei", "action": "template scan", "template": "ajp"}]
        info = sr._append_high_value_port_recs(recs, 8009)  # Ghostcat, has msf
        assert info is not None
        # existing rec priority bumped to 5
        assert recs[0]["priority"] == 5
        assert recs[0]["high_value"]["vulns"] == ["CVE-2020-1938"]
        # metasploit rec appended
        msf = [r for r in recs if r["scanner"] == "metasploit"]
        assert len(msf) == 1
        assert msf[0]["script"] == "auxiliary/admin/http/tomcat_ghostcat"
        assert msf[0]["priority"] == 5

    def test_no_msf_port_priority_10_no_module(self):
        recs = [{"scanner": "nmap", "action": "banner"}]
        sr._append_high_value_port_recs(recs, 1524)  # bindshell, msf=None
        assert recs[0]["priority"] == 10
        assert all(r["scanner"] != "metasploit" for r in recs)

    def test_non_high_value_port_noop(self):
        recs = [{"scanner": "nmap", "action": "banner"}]
        assert sr._append_high_value_port_recs(recs, 80) is None
        assert "priority" not in recs[0]

    def test_does_not_raise_priority(self):
        # an already-higher-priority rec (lower int) is not demoted
        recs = [{"scanner": "metasploit", "priority": 3}]
        sr._append_high_value_port_recs(recs, 8009)
        assert recs[0]["priority"] == 3


class _FakeCtx:
    def __init__(self, val):
        self.val = val
    def __enter__(self):
        return self.val
    def __exit__(self, *a):
        return False


@pytest.mark.unit
@pytest.mark.scan_recommender
class TestPersistPriority:
    def _fake_db(self):
        cur = MagicMock()
        cur.fetchone.return_value = None  # no asset found
        cur.rowcount = 1
        conn = MagicMock()
        conn.cursor.return_value = _FakeCtx(cur)
        return conn, cur

    def test_priority_and_context_persisted(self, monkeypatch):
        conn, cur = self._fake_db()
        monkeypatch.setattr(sr, "get_db", lambda: _FakeCtx(conn))
        # passthrough Json so we can inspect the dict that would be stored
        monkeypatch.setattr(sr, "Json", lambda x: ("JSON", x))

        rec = {"scanner": "metasploit", "action": "high-value port 8009: Ghostcat",
               "script": "auxiliary/admin/http/tomcat_ghostcat", "template": None,
               "priority": 5, "high_value": {"vulns": ["CVE-2020-1938"], "port": 8009}}
        inserted = sr.persist_recommendations("1.2.3.4", [rec], source="rules")
        assert inserted == 1

        # find the INSERT call
        insert_calls = [c for c in cur.execute.call_args_list
                        if "INSERT INTO public.scan_recommendations" in c.args[0]]
        assert len(insert_calls) == 1
        sql, params = insert_calls[0].args[0], insert_calls[0].args[1]
        assert "priority" in sql
        # priority is the last bound param
        assert params[-1] == 5
        # extra (2nd to last) carries the high_value context
        extra_arg = params[-2]
        assert extra_arg[0] == "JSON"
        assert extra_arg[1]["high_value"]["port"] == 8009

    def test_priority_defaults_to_null_for_unset(self, monkeypatch):
        conn, cur = self._fake_db()
        monkeypatch.setattr(sr, "get_db", lambda: _FakeCtx(conn))
        monkeypatch.setattr(sr, "Json", lambda x: ("JSON", x))
        rec = {"scanner": "nmap", "action": "banner", "script": "banner", "template": None}
        sr.persist_recommendations("1.2.3.4", [rec], source="rules")
        insert_calls = [c for c in cur.execute.call_args_list
                        if "INSERT INTO public.scan_recommendations" in c.args[0]]
        params = insert_calls[0].args[1]
        assert params[-1] is None  # COALESCE(NULL, 50) applies the DB default


@pytest.mark.unit
@pytest.mark.scan_recommender
class TestWebhookEmit:
    def test_emits_post(self, monkeypatch):
        monkeypatch.setattr(sr, "WEBHOOK_ENABLED", True)
        calls = {}
        def fake_post(url, **kw):
            calls["url"] = url
            calls["json"] = kw.get("json")
            calls["headers"] = kw.get("headers")
            return MagicMock(status_code=200)
        monkeypatch.setattr(sr.requests, "post", fake_post)
        sr._emit_webhook("scan_recommender_high_value_port_detected", {"ip": "1.2.3.4"}, severity="high")
        assert calls["url"].endswith("/webhooks/emit")
        assert calls["json"]["event_type"] == "scan_recommender_high_value_port_detected"
        assert calls["json"]["source"] == "scan_recommender"
        assert calls["json"]["severity"] == "high"
        assert "x-api-key" in calls["headers"]

    def test_disabled_no_post(self, monkeypatch):
        monkeypatch.setattr(sr, "WEBHOOK_ENABLED", False)
        called = {"n": 0}
        monkeypatch.setattr(sr.requests, "post", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
        sr._emit_webhook("x", {})
        assert called["n"] == 0
