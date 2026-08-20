"""Port scope profile tests.

Covers the resolver (dashboard/bff/services/port_profiles.py) and the BFF
request-level application logic (_apply_port_profile in routers/scans.py).

The behaviour these lock down, in priority order:
  1. A profile NEVER silently resolves to a narrower port set. An operator who
     asks for "all" must get all 65535 ports or an error — never top-100.
  2. Resolved strings are always masscan-safe (digits/commas/hyphens), because
     masscan has no --top-ports flag and a bad string reaches the binary.
  3. Callers that pass no profile are byte-for-byte unaffected.
"""
import pytest

# Skip rather than fail: BFF dependency; present in the pentest-dashboard image.
pytest.importorskip("pydantic_settings", reason="pydantic_settings unavailable — BFF dependency; present in the pentest-dashboard image")

import pytest

# Skip rather than fail when unavailable: HTTP client used by the BFF; present in the pentest-dashboard image.
pytest.importorskip("httpx",
                    reason="httpx not available here — HTTP client used by the BFF; present in the pentest-dashboard image")

import os
import sys
import textwrap
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dashboard", "bff"))

from services import port_profiles as pp  # noqa: E402

# routers.scans imports polling, which mkdirs the container path /scan_results
# at import time. Stub it so these tests run on a plain checkout instead of
# requiring that directory to exist and be writable. _apply_port_profile does
# not touch polling.
if "polling" not in sys.modules:
    _stub = types.ModuleType("polling")
    _stub.register_job = lambda *a, **k: None
    _stub.active_jobs = {}
    _stub._persist = lambda *a, **k: None
    _stub.pending_queue = []
    sys.modules["polling"] = _stub

from routers.scans import _apply_port_profile  # noqa: E402

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
REAL_YAML = os.path.join(REPO_ROOT, "knowledge", "port_profiles.yaml")


@pytest.fixture(autouse=True)
def _use_real_yaml(monkeypatch):
    """Point the loader at the repo's real port_profiles.yaml and reset the cache."""
    monkeypatch.setattr(pp, "PORT_PROFILES_PATH", REAL_YAML)
    pp.load_profiles(force=True)
    yield
    pp.load_profiles(force=True)


def _reload_from(monkeypatch, path):
    monkeypatch.setattr(pp, "PORT_PROFILES_PATH", path)
    return pp.load_profiles(force=True)


# ── Resolver ────────────────────────────────────────────────────────────────
class TestResolve:
    def test_all_is_the_full_tcp_range(self):
        assert pp.resolve("all") == "1-65535"

    def test_known_profiles_present(self):
        ids = {p["id"] for p in pp.list_profiles()["profiles"]}
        assert {"top-100", "top-1000", "web", "all"} <= ids

    @pytest.mark.parametrize("pid,expected", [
        ("top-100", 100), ("top-1000", 1000), ("all", 65535), ("web", 13),
    ])
    def test_port_counts_are_exact(self, pid, expected):
        """The collapsed ranges must expand back to exactly N ports."""
        got = {p["id"]: p["port_count"] for p in pp.list_profiles()["profiles"]}
        assert got[pid] == expected

    @pytest.mark.parametrize("pid", ["top-100", "top-1000", "web", "all"])
    def test_every_profile_is_masscan_safe(self, pid):
        """No profile may contain --top-ports or any non [0-9,-] character."""
        resolved = pp.resolve(pid)
        assert pp._SAFE_PORTS_RE.match(resolved), f"{pid} resolved to unsafe {resolved!r}"
        assert "--top-ports" not in resolved

    def test_profile_id_is_case_insensitive(self):
        assert pp.resolve("ALL") == pp.resolve("all")

    def test_unknown_profile_raises_rather_than_falling_back(self):
        with pytest.raises(pp.PortProfileError) as exc:
            pp.resolve("top-9999")
        assert "top-9999" in str(exc.value)

    # ── passthrough: pre-existing callers must be untouched ──
    def test_no_profile_passes_ports_through(self):
        assert pp.resolve(None, "22,80,443") == "22,80,443"

    def test_no_profile_and_no_ports_is_none(self):
        assert pp.resolve(None, None) is None

    def test_custom_passes_ports_through_verbatim(self):
        """--top-ports still flows to _normalize_ports for the nmap routes."""
        assert pp.resolve("custom", "--top-ports 50") == "--top-ports 50"


# ── Degraded mode (missing / broken YAML) ───────────────────────────────────
class TestDegradedMode:
    def test_missing_file_flags_degraded_but_still_serves_builtins(self, monkeypatch):
        data = _reload_from(monkeypatch, "/nonexistent/port_profiles.yaml")
        assert data["degraded"] is True
        assert pp.resolve("all") == "1-65535"

    def test_missing_file_refuses_top_1000_instead_of_substituting(self, monkeypatch):
        """The critical safety property: no silent narrowing of scope."""
        _reload_from(monkeypatch, "/nonexistent/port_profiles.yaml")
        with pytest.raises(pp.PortProfileError) as exc:
            pp.resolve("top-1000")
        assert "knowledge" in str(exc.value)  # points at the missing mount

    def test_unsafe_yaml_entry_is_dropped_not_passed_through(self, monkeypatch, tmp_path):
        """A hand-edited '--top-ports' in the YAML must never reach a scanner."""
        bad = tmp_path / "port_profiles.yaml"
        bad.write_text(textwrap.dedent("""
            default: good
            profiles:
              good:  {label: Good, ports: "1-1000"}
              nasty: {label: Nasty, ports: "--top-ports 100"}
        """))
        data = _reload_from(monkeypatch, str(bad))
        assert "nasty" not in data["profiles"]
        assert pp.resolve("good") == "1-1000"
        with pytest.raises(pp.PortProfileError):
            pp.resolve("nasty")

    def test_default_falls_back_when_it_names_a_missing_profile(self, monkeypatch, tmp_path):
        f = tmp_path / "port_profiles.yaml"
        f.write_text('default: ghost\nprofiles:\n  real: {label: R, ports: "1-10"}\n')
        assert _reload_from(monkeypatch, str(f))["default"] == "real"


# ── BFF request-level application ───────────────────────────────────────────
class TestApplyPortProfile:
    @staticmethod
    def _apply(scan_type, payload):
        _apply_port_profile(scan_type, payload)
        return payload

    def test_profile_overwrites_ports(self):
        p = self._apply("nmap", {"ports": "22", "port_profile": "all"})
        assert p["ports"] == "1-65535"
        assert "port_profile" not in p  # consumed, never forwarded downstream

    def test_full_scan_also_gets_quick_ports(self):
        """The full-scan route drives masscan from quick_ports, not ports."""
        p = self._apply("full", {"port_profile": "all"})
        assert p["quick_ports"] == "1-65535"

    def test_full_scan_without_profile_omits_quick_ports(self):
        """Scanner-side DEFAULT_QUICK_PORTS must still apply when unset."""
        assert "quick_ports" not in self._apply("full", {})

    def test_no_profile_leaves_ports_untouched(self):
        assert self._apply("nmap", {"ports": "--top-ports 100"})["ports"] == "--top-ports 100"

    def test_custom_leaves_ports_untouched(self):
        p = self._apply("nmap", {"ports": "8080", "port_profile": "custom"})
        assert p["ports"] == "8080"

    @pytest.mark.parametrize("scan_type", ["masscan", "full"])
    def test_top_ports_rejected_on_masscan_backed_routes(self, scan_type):
        """masscan has no --top-ports flag — this must 400, not reach the binary."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            self._apply(scan_type, {"ports": "--top-ports 100"})
        assert exc.value.status_code == 400
        assert "masscan" in exc.value.detail

    def test_top_ports_still_allowed_on_nmap_route(self):
        """_nmap_payload relocates it into extra_args, so nmap remains legal."""
        assert self._apply("nmap", {"ports": "--top-ports 100"})["ports"] == "--top-ports 100"

    def test_unknown_profile_becomes_http_400(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            self._apply("nmap", {"port_profile": "bogus"})
        assert exc.value.status_code == 400
