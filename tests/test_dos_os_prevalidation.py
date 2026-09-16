"""Pre-validation: DoS exploits are never recommended/run, and OS-type mismatches
are blocked only when confident (else downranked + flagged).

- A denial-of-service exploit gains no access, only disrupts — it must never be
  recommended, queued, approved, or executed.
- A CONFIDENT wrong-OS exploit (a Windows .exe against a Linux target) is dropped;
  an UNCERTAIN one or a service-level exploit is kept but downranked and flagged
  (don't guess a target away). OS matching is family-only and applies only when the
  target OS is actually known.

Pure classification tests — no infra.

    pytest tests/test_dos_os_prevalidation.py
"""
import sys
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "autogen_agents"))
sys.path.insert(0, str(ROOT / "exploit_runner"))

ew = pytest.importorskip("exploit_watcher")
er = pytest.importorskip("exploit_runner")
W = ew.ExploitWatcher


# ---- DoS: never ----
@pytest.mark.parametrize("exploit", [
    {"type": "dos", "title": "whatever"},
    {"type": "remote", "title": "ProFTPd 1.2 - SIZE Remote Denial of Service"},
    {"title": "Something (DoS)"},
])
def test_dos_detected_by_recommender(exploit):
    assert W._is_dos(exploit) is True


def test_non_dos_not_flagged():
    assert W._is_dos({"type": "remote", "title": "vsftpd 2.3.4 - Backdoor Command Execution"}) is False


def test_dos_blocked_at_runner():
    assert er._is_dos_exploit({"exploit_type": "other",
                               "exploit_title": "X - Remote Denial of Service"}) is True
    assert er._is_dos_exploit({"exploit_type": "dos", "exploit_title": "x"}) is True
    assert er._is_dos_exploit({"exploit_type": "rce",
                               "exploit_title": "distcc daemon command execution"}) is False


# ---- OS type: confident block vs uncertain downrank ----
def test_confident_windows_is_strong():
    fam, strong = W._exploit_os({"title": "RealVNC 4.1.2 - vncviewer.exe RFB Protocol Remote"})
    assert fam == "windows" and strong is True          # -> blocked on a nix target


def test_explicit_platform_is_strong():
    assert W._exploit_os({"platform": "windows", "title": "x"}) == ("windows", True)
    assert W._exploit_os({"platform": "linux", "title": "x"}) == ("nix", True)


def test_service_level_has_no_os():
    # A bare service exploit is not tied to an OS -> never blocked on OS grounds.
    assert W._exploit_os({"title": "VNC RFB Protocol Remote"})[0] is None


def test_incidental_os_mention_is_weak():
    fam, strong = W._exploit_os({"title": "Foo also affects Windows in some setups"})
    assert fam == "windows" and strong is False         # -> downranked + flagged, not blocked


def test_target_os_from_banners():
    assert W._os_from_text("OpenSSH 4.7p1 Debian-8ubuntu1") == "nix"
    assert W._os_from_text("Microsoft-IIS/6.0") == "windows"
    assert W._os_from_text("nginx 1.4.0") is None       # unknown -> caller won't OS-filter


# ---- Operator DoS override allowlist ----
def test_dos_override_allowlist():
    do = pytest.importorskip("etl.dos_overrides")
    # Empty list (default) exempts nothing.
    do._cache["entries"] = []
    do._cache["t"] = 9e18
    assert do.is_dos_override(edb_id="49999", title="X - Denial of Service") is False
    # An allowlisted exploit is exempt (match by edb_id, module, or title token).
    do._cache["entries"] = ["49999", "slowloris", "exploit/windows/http/foo"]
    do._cache["t"] = 9e18
    assert do.is_dos_override(edb_id="49999", title="whatever") is True
    assert do.is_dos_override(edb_id="1", title="Apache Slowloris DoS") is True
    assert do.is_dos_override(module="exploit/windows/http/foo") is True
    assert do.is_dos_override(edb_id="2", title="vsftpd backdoor") is False
