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


# ── the vector-sweep writer must gate too ───────────────────────────────────

def test_the_vector_sweep_resolves_before_queueing():
    """`process_service_vectors` auto-approves and auto-fires what it queues.

    Its module comes straight from knowledge/service_access_methods.yaml, which
    is hand-written and can name a module this Metasploit does not ship — it
    declares `exploit/linux/misc/drb_remote_codeexec`, and `/msf/resolve` reports
    exists=False for it on this install. Without the gate that becomes an
    auto-fired row that can only fail, and it is the likely origin of the
    "synthetic module ids queued as source=metasploit" rows.

    queue_exploit_for_approval already gates this way; this pins that the vector
    path does too, and that it FAILS OPEN (an unreachable resolver must not stop
    all queueing — `checked` is False in that case).
    """
    import ast as _ast
    repo = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
    src = open(os.path.join(repo, "autogen_agents", "exploit_watcher.py"),
               encoding="utf-8").read()
    fn = next((n for n in _ast.walk(_ast.parse(src))
               if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))
               and n.name == "process_service_vectors"), None)
    assert fn, "process_service_vectors not found"
    body = _ast.get_source_segment(src, fn)

    calls = {getattr(c.func, "id", None) or getattr(c.func, "attr", None)
             for c in _ast.walk(fn) if isinstance(c, _ast.Call)}
    assert "_resolve_msf_module" in calls, (
        "the vector sweep queues a metasploit exploit without checking the module "
        "is loaded — and this path is auto-approved and auto-fired")

    # fail-open: the skip must require `checked`, not merely "did not resolve"
    assert "checked and not resolved" in body, (
        "the vector sweep skips on an unresolved module without requiring that "
        "the check actually RAN — an unreachable resolver would then silently "
        "stop all vector queueing")


def test_the_bff_writer_resolves_before_queueing():
    """`dispatch_rec` inserts source=metasploit from the recommender.

    Lower risk than the vector sweep — an operator initiated it, so a bad row is
    seen — but the same class: a module this Metasploit does not load can only
    queue a row that fails. It resolves in the ASYNC caller because the insert
    helper (`_queue_pending`) is sync, mirroring how the watcher does it.

    Fail-open is the property that matters: an unreachable exploit-runner must
    not stop an operator queueing work, so only a check that actually RAN and
    came back negative may skip.
    """
    import ast as _ast
    repo = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
    path = os.path.join(repo, "dashboard", "bff", "routers", "assets.py")
    if not os.path.exists(path):
        pytest.skip("assets.py not present")
    src = open(path, encoding="utf-8").read()
    fn = next((n for n in _ast.walk(_ast.parse(src))
               if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))
               and n.name == "dispatch_rec"), None)
    assert fn, "dispatch_rec not found"
    body = _ast.get_source_segment(src, fn)

    assert "/msf/resolve" in body, (
        "the BFF queues a metasploit exploit without checking the module is "
        "loaded in this install")
    assert "not a loaded Metasploit module" in body, (
        "there is no skip path for an unresolvable module")
    # fail-open: a None/failed response must NOT skip
    assert "_rdata is not None" in body, (
        "the BFF skips on an unresolved module without requiring that the check "
        "actually ran — an unreachable exploit-runner would then block all "
        "operator queueing")
