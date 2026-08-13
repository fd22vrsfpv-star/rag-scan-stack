"""Web scan scope profile tests.

Covers the loader (dashboard/bff/services/web_profiles.py) and the BFF
request-level applier (_apply_web_profile in routers/scans.py).

Properties locked down here:
  1. A profile NEVER overwrites a field the operator set explicitly.
  2. Stage lists map correctly onto BOTH spellings — pipeline `skip_*` (opt-out)
     and web-scan `do_*` (opt-in). An inverted flag silently runs, or silently
     skips, a whole tool.
  3. Malformed YAML entries are dropped loudly, never half-applied.
  4. No profile means no change.
"""
import os
import sys
import textwrap
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dashboard", "bff"))

from services import web_profiles as wp  # noqa: E402

# routers.scans imports polling, which mkdirs /scan_results at import time.
if "polling" not in sys.modules:
    _stub = types.ModuleType("polling")
    _stub.register_job = lambda *a, **k: None
    _stub.active_jobs = {}
    _stub._persist = lambda *a, **k: None
    _stub.pending_queue = []
    sys.modules["polling"] = _stub

from routers.scans import _apply_web_profile  # noqa: E402

REAL_YAML = os.path.join(os.path.dirname(__file__), "..", "knowledge", "web_profiles.yaml")


@pytest.fixture(autouse=True)
def _use_real_yaml(monkeypatch):
    monkeypatch.setattr(wp, "WEB_PROFILES_PATH", REAL_YAML)
    wp.load_profiles(force=True)
    yield
    wp.load_profiles(force=True)


def _apply(scan_type, payload):
    _apply_web_profile(scan_type, payload)
    return payload


# ── Loader ──────────────────────────────────────────────────────────────────
class TestLoader:
    def test_expected_profiles_present(self):
        ids = {p["id"] for p in wp.list_profiles()["profiles"]}
        assert {"quick", "standard", "deep", "api", "passive-web"} <= ids

    def test_default_is_standard(self):
        assert wp.list_profiles()["default"] == "standard"

    def test_not_degraded_with_real_yaml(self):
        assert wp.list_profiles()["degraded"] is False

    def test_every_stage_is_known(self):
        """A typo'd stage silently disables a tool — it must never survive load."""
        for p in wp.list_profiles()["profiles"]:
            assert set(p["stages"]) <= set(wp.KNOWN_STAGES), p["id"]

    def test_deep_is_a_superset_of_quick(self):
        prof = {p["id"]: p for p in wp.list_profiles()["profiles"]}
        assert set(prof["quick"]["stages"]) <= set(prof["deep"]["stages"])
        assert prof["deep"]["max_paths"] > prof["quick"]["max_paths"]
        assert prof["deep"]["crawl_depth"] > prof["quick"]["crawl_depth"]

    def test_passthrough_and_unknown(self):
        assert wp.resolve(None) is None
        assert wp.resolve("custom") is None
        with pytest.raises(wp.WebProfileError):
            wp.resolve("nope")


class TestLoaderValidation:
    def _load(self, monkeypatch, tmp_path, body):
        f = tmp_path / "web_profiles.yaml"
        f.write_text(textwrap.dedent(body))
        monkeypatch.setattr(wp, "WEB_PROFILES_PATH", str(f))
        return wp.load_profiles(force=True)

    def test_unknown_stage_is_dropped(self, monkeypatch, tmp_path):
        d = self._load(monkeypatch, tmp_path, """
            default: p
            profiles:
              p: {label: P, stages: [katana, bogus, nuclei]}
        """)
        assert d["profiles"]["p"]["stages"] == ["katana", "nuclei"]

    def test_profile_with_no_valid_stages_is_skipped(self, monkeypatch, tmp_path):
        d = self._load(monkeypatch, tmp_path, """
            default: good
            profiles:
              good: {label: G, stages: [nuclei]}
              bad:  {label: B, stages: [nonsense]}
        """)
        assert "bad" not in d["profiles"]

    def test_unsafe_wordlist_is_dropped(self, monkeypatch, tmp_path):
        d = self._load(monkeypatch, tmp_path, """
            default: p
            profiles:
              p: {label: P, stages: [gobuster], wordlist: 'list; whoami'}
        """)
        assert d["profiles"]["p"]["wordlist"] == ""

    def test_unknown_severity_is_dropped(self, monkeypatch, tmp_path):
        d = self._load(monkeypatch, tmp_path, """
            default: p
            profiles:
              p: {label: P, stages: [nuclei], nuclei_severity: 'hgih,high'}
        """)
        assert d["profiles"]["p"]["nuclei_severity"] == "high"

    def test_missing_file_is_degraded_but_usable(self, monkeypatch):
        monkeypatch.setattr(wp, "WEB_PROFILES_PATH", "/nonexistent/web_profiles.yaml")
        d = wp.load_profiles(force=True)
        assert d["degraded"] is True
        assert "standard" in d["profiles"]


# ── Applier ─────────────────────────────────────────────────────────────────
class TestApplyWebProfile:
    def test_no_profile_leaves_payload_untouched(self):
        assert _apply("web", {"target_url": "http://x"}) == {"target_url": "http://x"}

    def test_custom_leaves_payload_untouched(self):
        p = _apply("web", {"target_url": "http://x", "web_profile": "custom"})
        assert p == {"target_url": "http://x"}

    def test_profile_key_is_consumed(self):
        assert "web_profile" not in _apply("nuclei", {"web_profile": "quick"})

    def test_non_web_scan_type_is_untouched(self):
        """A web profile on an nmap scan must not inject web fields."""
        p = _apply("nmap", {"target": "1.2.3.4", "web_profile": "deep"})
        assert "wordlist" not in p and "severity" not in p

    def test_fills_tool_settings(self):
        p = _apply("gobuster", {"target_url": "http://x", "web_profile": "deep"})
        assert p["wordlist"] == "big"
        assert p["depth"] == 5
        assert p["max_paths"] == 500

    def test_explicit_field_wins_over_profile(self):
        """The operator typed a wordlist — the profile must not clobber it."""
        p = _apply("gobuster", {"wordlist": "raft-small", "web_profile": "deep"})
        assert p["wordlist"] == "raft-small"

    def test_explicit_severity_wins(self):
        p = _apply("nuclei", {"severity": "critical", "web_profile": "quick"})
        assert p["severity"] == "critical"

    # ── stage flag mapping ──
    def test_pipeline_uses_skip_flags_inverted(self):
        """`quick` runs wafw00f/katana/nuclei only — everything else skipped."""
        p = _apply("pipeline", {"target_url": "http://x", "web_profile": "quick"})
        assert p["skip_wafw00f"] is False
        assert p["skip_katana"] is False
        assert p["skip_nuclei"] is False
        assert p["skip_gobuster"] is True
        assert p["skip_zap"] is True
        assert p["skip_playwright"] is True

    def test_pipeline_deep_runs_everything(self):
        p = _apply("pipeline", {"web_profile": "deep"})
        assert not any(v for k, v in p.items() if k.startswith("skip_"))

    def test_web_uses_do_flags_not_inverted(self):
        """Same stage list, opposite spelling — this is the easy bug."""
        p = _apply("web", {"target_url": "http://x", "web_profile": "quick"})
        assert p["do_katana"] is True
        assert p["do_gobuster"] is False
        assert p["do_zap"] is False

    def test_web_deep_enables_all_do_flags(self):
        p = _apply("web", {"web_profile": "deep"})
        assert p["do_gobuster"] and p["do_playwright"] and p["do_katana"] and p["do_zap"]

    def test_explicit_stage_flag_wins(self):
        p = _apply("pipeline", {"skip_zap": False, "web_profile": "quick"})
        assert p["skip_zap"] is False   # operator forced ZAP on despite quick

    def test_api_profile_skips_browser_and_bruteforce(self):
        p = _apply("pipeline", {"web_profile": "api"})
        assert p["skip_playwright"] is True
        assert p["skip_gobuster"] is True
        assert p["skip_katana"] is False
        assert p["tags"] == "api,exposure,misconfig"

    def test_unknown_profile_becomes_http_400(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _apply("web", {"web_profile": "ultra-deep"})
        assert exc.value.status_code == 400


class TestProfileReachesTheWirePayload:
    """Applier + the real SCAN_ROUTES transform, asserting the final payload.

    The applier alone only proves the intermediate dict. These run the actual
    route lambda on top, so a profile field that the route happens to drop
    (rather than forward) is caught here.
    """

    @staticmethod
    def _payload(scan_type, raw):
        from routers.scans import SCAN_ROUTES
        _apply_web_profile(scan_type, raw)
        _attr, _path, transform = SCAN_ROUTES[scan_type]
        return {k: v for k, v in transform(raw).items() if v is not None}

    def test_nuclei_forwards_profile_severity_and_tags(self):
        p = self._payload("nuclei", {"target": "1.2.3.4", "web_profile": "api"})
        assert p["severity"] == "medium,high,critical"
        assert p["tags"] == "api,exposure,misconfig"

    def test_nuclei_quick_narrows_severity(self):
        p = self._payload("nuclei", {"target": "1.2.3.4", "web_profile": "quick"})
        assert p["severity"] == "high,critical"

    def test_gobuster_forwards_profile_wordlist(self):
        p = self._payload("gobuster", {"target_url": "http://x", "web_profile": "deep"})
        assert p["wordlist"] == "big"

    def test_katana_forwards_profile_depth(self):
        p = self._payload("katana", {"targets": "x.com", "web_profile": "deep"})
        assert p["depth"] == 5

    def test_pipeline_forwards_max_paths(self):
        p = self._payload("pipeline", {"target_url": "http://x", "web_profile": "deep"})
        assert p["max_paths_to_visit"] == 500

    def test_web_route_forwards_do_flags(self):
        p = self._payload("web", {"target_url": "http://x", "web_profile": "quick"})
        assert p["do_katana"] is True
        assert p["do_gobuster"] is False
        assert p["do_zap"] is False

    def test_no_profile_payload_is_unchanged(self):
        """Regression guard: existing callers must be byte-identical."""
        base = self._payload("nuclei", {"target": "1.2.3.4"})
        assert base["severity"] == "medium,high,critical"   # route default, not a profile
        assert "tags" not in base
