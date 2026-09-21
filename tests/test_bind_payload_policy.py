"""A bind payload is third-party risk: prefer a callback, never auto-approve.

WHY THIS EXISTS
---------------
A reverse payload dials out to an address we control — only we receive it. A BIND
payload opens a LISTENING PORT ON THE TARGET and waits, so for as long as it
lives it is an unauthenticated command shell on someone else's host that anyone
who can reach the port may use: another tenant, another tester, the target's own
users, whoever scans that range next. We do not choose who connects and cannot
tell afterwards who did.

That exposure is taken on the client's behalf, so a human decides it every time.

Before this, `auto` PREFERRED bind (it holds through NAT, and a callback to an
unroutable container LHOST never arrives), and an approval rule could approve and
auto-fire such an exploit with no operator ever seeing it.

Sabotage checks, each proven:
  * make _pick_payload try bind before reverse           -> ordering test fails
  * put "netcat" back in _pref                           -> last-resort test fails
  * drop the runner's bind gate                          -> execution test fails
  * drop the sweep's held_bind branch                    -> sweep test fails
  * make approval_is_manual() accept "rule:..."          -> approval test fails
"""
import ast
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ast_assert import calls, defines, function_source  # noqa: E402

RUNNER = os.path.join(REPO, "exploit_runner", "exploit_runner.py")
API = os.path.join(REPO, "app", "rag-api", "api.py")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _load_pick_payload():
    """_pick_payload alone, without importing the runner (needs msgpack, a DB)."""
    src = _read(RUNNER)
    fn = next((n for n in ast.parse(src).body
               if isinstance(n, ast.FunctionDef) and n.name == "_pick_payload"), None)
    assert fn, "_pick_payload not found"
    ns = {"logger": type("L", (), {"warning": staticmethod(lambda *a, **k: None)})()}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<pick>", "exec"), ns)
    return ns["_pick_payload"]


# ── the policy module ────────────────────────────────────────────────────────

def test_is_bind_payload_reads_style_or_name():
    from etl import bind_payload_policy as bp
    assert bp.is_bind_payload(style="bind")
    assert bp.is_bind_payload(payload="cmd/unix/bind_perl")
    assert bp.is_bind_payload(payload="java/meterpreter/bind_tcp")
    assert not bp.is_bind_payload(payload="cmd/unix/reverse_perl", style="reverse")
    assert not bp.is_bind_payload()


def test_a_rule_is_not_a_human():
    """The whole control rests on this distinction."""
    from etl import bind_payload_policy as bp
    assert not bp.approval_is_manual("rule:8f14e45f-ceea-467a-9f6b-4d3c2a1b0000")
    assert not bp.approval_is_manual("RULE:abc")          # case
    assert not bp.approval_is_manual(None)                # fail closed
    assert not bp.approval_is_manual("")
    assert bp.approval_is_manual("operator:doug")
    assert bp.approval_is_manual("doug")


def test_bind_is_likely_mirrors_the_runner():
    from etl import bind_payload_policy as bp
    assert bp.bind_is_likely({"connect_style": "bind"})
    assert bp.bind_is_likely({"connect_style": "auto", "callback_host": ""})
    assert bp.bind_is_likely({"connect_style": "auto"})
    assert bp.bind_is_likely({"payload": "cmd/unix/bind_perl"})
    assert not bp.bind_is_likely({"connect_style": "auto", "callback_host": "10.9.0.5"})
    assert not bp.bind_is_likely({"connect_style": "reverse"})
    assert bp.bind_is_likely(None)                        # unknown shape -> hold


# ── payload selection ────────────────────────────────────────────────────────

def test_auto_prefers_the_callback():
    """The change of default: auto used to take bind first."""
    pick = _load_pick_payload()
    payload, style = pick(["cmd/unix/bind_perl", "cmd/unix/reverse_perl"], "auto", "")
    assert style == "reverse", (payload, style)


def test_bind_is_still_reachable_when_no_callback_exists():
    """Preferring a callback must not make bind unreachable — _build_exploit_options
    downgrades reverse->bind when no callback host is configured, and an operator
    may ask for bind explicitly."""
    pick = _load_pick_payload()
    assert pick(["cmd/unix/bind_perl"], "auto", "")[1] == "bind"
    assert pick(["cmd/unix/bind_perl", "cmd/unix/reverse_perl"], "bind", "")[1] == "bind"


def test_netcat_is_the_last_resort():
    """`nc -e` is absent from most modern builds, and a plain netcat bind is the
    most exposed shell of the set. It must lose to anything else, including a
    payload matching no interpreter at all."""
    pick = _load_pick_payload()
    assert "perl" in pick(["cmd/unix/bind_netcat", "cmd/unix/bind_perl"], "bind", "")[0]
    assert "meterpreter" in pick(
        ["cmd/unix/bind_netcat", "java/meterpreter/bind_tcp"], "bind", "")[0]
    assert "awk" in pick(["cmd/unix/bind_netcat", "cmd/unix/bind_awk"], "bind", "")[0]
    # but still used when it is all there is
    assert "netcat" in pick(["cmd/unix/bind_netcat"], "bind", "")[0]


def test_the_live_verified_interpreter_ordering_survives():
    """bind_awk failed on metasploitable while bind_perl opened a shell (verified
    on usermap + distcc). Demoting netcat must not disturb that."""
    pick = _load_pick_payload()
    assert "perl" in pick(["cmd/unix/bind_awk", "cmd/unix/bind_perl"], "bind", "")[0]


# ── the two enforcement points ───────────────────────────────────────────────

def test_the_runner_refuses_an_unapproved_bind():
    src = _read(RUNNER)
    assert defines(src, "_bind_payload_is_approved"), "the runner has no bind gate"
    fn = function_source(src, "execute_msf_module")
    assert fn, "execute_msf_module not found"
    assert calls(fn, "is_bind_payload"), (
        "the runner no longer asks whether the resolved payload is a bind")
    assert calls(fn, "_bind_payload_is_approved"), (
        "the runner no longer requires a human approval for a bind payload")

    gate = function_source(src, "_bind_payload_is_approved")
    assert "reviewed_by" in gate, "the gate must read who approved it"
    assert calls(gate, "approval_is_manual"), (
        "the gate must use the shared rule-vs-human test, not its own")
    assert "return False" in gate, "the gate must fail closed"


def test_the_sweep_holds_a_bind_instead_of_auto_approving():
    src = _read(API)
    assert defines(src, "_bind_payload_likely"), "the sweep cannot tell bind from reverse"
    fn = function_source(src, "_sweep_exploit_approval_rules")
    assert fn, "_sweep_exploit_approval_rules not found"
    assert calls(fn, "_bind_payload_likely"), "the sweep no longer checks for bind"
    assert "held_bind" in fn, (
        "a bind exploit must be HELD and reported, not silently dropped or approved")

    pred = function_source(src, "_bind_payload_likely")
    assert calls(pred, "bind_is_likely"), (
        "the sweep must use the shared prediction, or it will drift from the runner")
    assert "return True" in pred, "the prediction must fail closed"


def test_the_recommendation_names_a_node_not_a_settings_field():
    """A refusal must tell the operator what to DO.

    The recommended callback is a node/proxy relay: the node listens on an
    address the target can reach and relays the shell to MSF, so nothing opens a
    port on the target and our own address is not the callback. Generic advice
    ("configure a callback host") pointed at a settings field instead of the node
    that already exists.
    """
    from etl.bind_payload_policy import recommend_callback, RECOMMENDATION
    assert "relay" in RECOMMENDATION.lower()

    none_live = recommend_callback([{"name": "rt3_scan1", "relay_active": False}])
    assert "rt3_scan1" in none_live, "the candidate node is not named"

    live = recommend_callback([{"name": "rt3_scan1", "relay_active": True}])
    assert "rt3_scan1" in live and "already up" in live, (
        "when a relay IS running the operator must be told the dispatch missed it, "
        "not told to start one")

    assert recommend_callback([]) == RECOMMENDATION       # no nodes: generic
    assert recommend_callback(None) == RECOMMENDATION


def test_both_refusals_carry_the_recommendation():
    runner = _read(RUNNER)
    fn = function_source(runner, "execute_msf_module")
    assert calls(fn, "recommend_callback"), (
        "the runner refuses a bind payload without saying how to get a callback")
    assert defines(runner, "_relay_candidates"), "the runner cannot name a node"

    api = _read(API)
    sweep = function_source(api, "_sweep_exploit_approval_rules")
    assert calls(sweep, "recommend_callback"), (
        "the sweep holds a bind exploit without saying how to get a callback")
    assert defines(api, "_relay_candidates"), "the sweep cannot name a node"


def test_the_policy_is_shared_not_reimplemented():
    """Two enforcement points, one module — the dos_overrides pattern. A second
    copy of "what counts as bind" is how the two ends stop agreeing."""
    for path in (RUNNER, API):
        src = _read(path)
        assert "bind_payload_policy" in src, (
            f"{os.path.basename(path)} does not use the shared policy module")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
