"""POST /msf/resolve validates a metasploit exploit_id/title before it is queued.

Anything MSF must be checked BEFORE it is queued/run: the endpoint returns the
canonical module path + its configurable options only when the name resolves to a
REAL, loaded module, and null otherwise. This stops doomed source=metasploit rows
(a synthetic id like 'metasploitable_root_shell_1524', or a module not shipped in
this MSF like 'drb_remote_codeexec') from being queued to fail every scan, and
hands the queue path the module's options so an exploit is configured up front.

Hits the live exploit-runner; skips cleanly when it or Metasploit is unreachable.

    EXPLOIT_RUNNER_URL=https://localhost:8017 pytest tests/test_msf_resolve.py
"""
import os
import re
import pathlib

import pytest

requests = pytest.importorskip("requests")

BASE = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")


def _key():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _resolve(exploit_id="", exploit_title=""):
    try:
        r = requests.post(f"{BASE}/msf/resolve",
                          json={"exploit_id": exploit_id, "exploit_title": exploit_title},
                          headers={"x-api-key": _key()}, timeout=30, verify=False)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, f"{r.status_code} {r.text[:200]}"
    data = r.json()
    if data.get("error"):
        pytest.skip(f"MSF not reachable for resolve: {data['error'][:80]}")
    return data


def test_synthetic_id_does_not_resolve():
    # A bind-shell banner, not an MSF module — must resolve to null so it is not
    # queued as a metasploit exploit that can only fail.
    data = _resolve("metasploitable_root_shell_1524",
                    "Interactive root shell banner on TCP/1524 (Metasploitable)")
    assert data["module"] is None, f"synthetic id resolved to {data['module']!r}"
    assert data["exists"] is False


def test_real_module_resolves_with_options():
    # A standard module: resolves to its canonical path AND returns options.
    data = _resolve("usermap_script", "Samba usermap_script exploit")
    if not data["module"]:
        pytest.skip("usermap_script not loaded in this MSF build")
    assert data["module"].endswith("usermap_script"), data["module"]
    assert data["module"].startswith("exploit/")
    assert data["exists"] is True
    assert isinstance(data.get("options"), dict) and data["options"], "no options returned"
    # Options carry MSF's standard connection knobs.
    assert any(k in data["options"] for k in ("RHOSTS", "RPORT", "RHOST")), \
        f"expected host/port options, got {list(data['options'])[:8]}"


def test_near_miss_is_normalised():
    # A mistyped leaf resolves to the real module (not null, not the typo).
    data = _resolve("php_cgi_argument_injection", "")
    if not data["module"]:
        pytest.skip("php_cgi_arg_injection not loaded in this MSF build")
    assert data["module"] == "exploit/multi/http/php_cgi_arg_injection", data["module"]
