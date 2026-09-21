"""Reverse callbacks via a relay on a remote node → central MSF.

Run on demand:

    pytest tests/test_callback_relay.py -v

WHY THIS EXISTS
---------------
The central metasploit container is on the docker bridge (a 172.x address), so a
reverse shell from a LAN/external target can never call back to it. A callback
relay fixes that WITHOUT a bind port on the target (safer): the assigned node
listens on a port and hands every connection back through the SSH mgmt channel to
our central MSF handler. `ssh -R 0.0.0.0:<lport>:metasploit:<lport>` — works for
SSH and WireGuard nodes alike, because mgmt/exec is SSH regardless of which
transport carries the SOCKS proxy. When a dispatch goes through a relay node,
exploit-runner builds a reverse payload with LHOST = the node's target-reachable
IP; MSF binds the handler centrally.

SABOTAGE PROOF
--------------
Drop `-R`/`0.0.0.0` from start_callback_relay and test_relay_uses_reverse_ssh_forward
fails. Make _node_callback_config return a bind config and
test_relay_node_yields_reverse_to_node fails.
"""
import ast
import os
import sys

import pytest

import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ast_assert import calls  # noqa: E402

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SSH_MGR = os.path.join(REPO, "node_manager", "ssh_manager.py")
NODE_MGR = os.path.join(REPO, "node_manager", "node_manager.py")
ERUNNER = os.path.join(REPO, "exploit_runner", "exploit_runner.py")


def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    return open(path, encoding="utf-8").read()


def _func(path, name):
    for node in ast.walk(ast.parse(_src(path))):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    pytest.fail(f"{name} not found in {os.path.basename(path)}")


# ── Source guards ────────────────────────────────────────────────────────────

def test_relay_uses_reverse_ssh_forward():
    fn = _func(SSH_MGR, "start_callback_relay")
    assert "-R" in fn, "the relay is not a reverse SSH forward"
    assert "0.0.0.0" in fn, "the node must bind 0.0.0.0 so the target can reach it"
    assert "ExitOnForwardFailure" in fn, (
        "without ExitOnForwardFailure a refused 0.0.0.0 bind silently falls back "
        "to localhost — a relay that drops every callback")
    assert "GatewayPorts" in fn, "the sshd GatewayPorts requirement is not surfaced"


def test_relay_verifies_the_actual_bind_is_not_localhost():
    """GatewayPorts=off makes the node SILENTLY bind 127.0.0.1 (ExitOnForwardFailure
    does not catch it), so the relay must verify the real listener is 0.0.0.0 and
    refuse a localhost-only bind — else it reports a working relay that drops every
    callback. Confirmed live against a real node."""
    fn = _func(SSH_MGR, "start_callback_relay")
    assert ("ss -tln" in fn or "netstat -tln" in fn), (
        "the relay no longer checks the node's actual listener")
    assert "0.0.0.0:" in fn, "the relay no longer verifies a wildcard (0.0.0.0) bind"
    assert "localhost-only" in fn.lower() or "localhost only" in fn.lower()


def test_node_manager_exposes_relay_endpoints():
    src = _src(NODE_MGR)
    assert '"/nodes/{node_id}/callback-relay"' in src or "'/nodes/{node_id}/callback-relay'" in src
    start = _func(NODE_MGR, "start_callback_relay")
    assert "start_callback_relay" in start and "callback_host" in start
    # Relay state is persisted so a dispatch can find the node's LHOST.
    assert "_store_relay_meta" in start
    stored = _func(NODE_MGR, "_store_relay_meta")
    assert "callback_relay" in stored


def _passes_name(src, callee, keyword, value):
    """True if some call to `callee` passes `keyword=<value>` as a bare name."""
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = getattr(fn, "id", None) or getattr(fn, "attr", None)
        if name != callee:
            continue
        for kw in node.keywords:
            if kw.arg == keyword and isinstance(kw.value, ast.Name) and kw.value.id == value:
                return True
    return False


def _first_arg_is(src, callee, value):
    """True if some call to `callee` takes `value` as its first positional arg."""
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = getattr(fn, "id", None) or getattr(fn, "attr", None)
        if name == callee and node.args and isinstance(node.args[0], ast.Name):
            if node.args[0].id == value:
                return True
    return False


def test_exploit_runner_prefers_node_relay():
    """Both MSF dispatch paths consult the node relay config.

    by-id reaches it by DELEGATION now: it enforces the proxy itself, then hands
    that effective proxy to execute_msf_module, which resolves the relay. What
    matters is that by-id's *enforced* proxy is the one the relay is computed
    from — passing the raw query parameter instead would resolve the relay
    against a proxy the fail-closed gate had already overridden.
    """
    byid = _func(ERUNNER, "execute_by_id")
    assert calls(byid, "execute_msf_module"), (
        "by-id no longer routes MSF through the shared executor")
    assert calls(byid, "_enforce_proxy"), "by-id no longer enforces the proxy policy"
    assert _passes_name(byid, "MsfExecuteRequest", "proxy_url", "eff_proxy"), (
        "by-id passes something other than its ENFORCED proxy to the executor, so "
        "the node relay would be resolved against the wrong proxy")
    msf = _func(ERUNNER, "execute_msf_module")
    assert calls(msf, "_node_callback_config"), "/execute/msf ignores the node relay"
    # it resolves the relay from the ENFORCED proxy, not the raw request field --
    # the guard used to pin `_node_callback_config(request.proxy_url)`, which was
    # the weaker of the two behaviours.
    assert _first_arg_is(msf, "_node_callback_config", "eff_proxy"), (
        "/execute/msf resolves the node relay from the unenforced request proxy")


# ── Unit test the resolver (skips cleanly without the runner's deps) ─────────

sys.path.insert(0, os.path.join(REPO, "exploit_runner"))
er = pytest.importorskip("exploit_runner", reason="exploit_runner deps not installed")


class _FakeCur:
    def __init__(self, row): self._row = row
    def execute(self, *a, **k): pass
    def fetchone(self): return self._row
    def __enter__(self): return self
    def __exit__(self, *a): return False


class _FakeConn:
    def __init__(self, row): self._row = row
    def cursor(self): return _FakeCur(self._row)
    def close(self): pass


def _patch_db(monkeypatch, row):
    monkeypatch.setattr(er.psycopg2, "connect", lambda *a, **k: _FakeConn(row))


def test_no_proxy_means_no_relay():
    assert er._node_callback_config(None) is None
    assert er._node_callback_config("") is None


def test_relay_node_yields_reverse_to_node(monkeypatch):
    meta = {"callback_relay": {"active": True, "callback_host": "192.168.1.50", "lport": 4444}}
    _patch_db(monkeypatch, (meta,))
    cfg = er._node_callback_config("socks5://127.0.0.1:10120")
    assert cfg and cfg["connect_style"] == "reverse"
    assert cfg["callback_host"] == "192.168.1.50"
    assert cfg["listener_bind_address"] == "0.0.0.0"   # MSF binds centrally
    assert cfg["callback_port"] == 4444


def test_inactive_relay_is_ignored(monkeypatch):
    _patch_db(monkeypatch, ({"callback_relay": {"active": False, "callback_host": "x"}},))
    assert er._node_callback_config("socks5://127.0.0.1:10120") is None
    # no relay metadata at all
    _patch_db(monkeypatch, ({},))
    assert er._node_callback_config("socks5://127.0.0.1:10120") is None


def test_relay_config_merges_into_payload_config(monkeypatch):
    """The node config flows through MsfPayloadConfig.merged as a reverse override."""
    meta = {"callback_relay": {"active": True, "callback_host": "10.10.0.9", "lport": 5555}}
    _patch_db(monkeypatch, (meta,))
    override = er._node_callback_config("socks5://n:10121")
    cfg = er.MsfPayloadConfig.merged(override)
    assert cfg.connect_style == "reverse" and cfg.callback_host == "10.10.0.9"
    assert cfg.listener_bind_address == "0.0.0.0" and cfg.callback_port == 5555
