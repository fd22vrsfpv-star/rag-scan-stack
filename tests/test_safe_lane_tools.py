"""The no-approval safe lane is bounded to READ-ONLY tools, and both processes agree.

Run on demand:

    pytest tests/test_safe_lane_tools.py -v
    BFF_BASE=... KALI_URL=... pytest tests/test_safe_lane_tools.py   # live checks

WHY THIS EXISTS
---------------
`/tools/execute` runs a tool WITHOUT the exploit approval gate. It used to admit
the whole install manifest minus Metasploit — which includes sqlmap (--os-shell →
RCE), ssh/sshpass (remote exec), hydra/medusa/ncrack (credential attacks),
netexec (-x), nc, the DB clients and smbclient (upload). The dangerous-char
filter only stops shell *chaining*, not a tool being offensive with its OWN
flags, so the no-approval lane could run RCE.

Now the lane is bounded to an explicit read-only set. That set lives in TWO
processes — the listener (`_SAFE_READONLY_TOOLS`) enforces it and the agent
(`_SAFE_TOOL_HINTS`) tiers tests by it — so they MUST agree or a test the agent
calls "safe" is refused by the listener (or worse, a tool the agent tiers safe
is one the listener would run). This pins them to one table.

SABOTAGE PROOF
--------------
Put "sqlmap" back into either set and test_no_offensive_tool_is_on_the_safe_lane
fails. Let the two sets drift and test_both_processes_agree fails. Drop the
get_safe_execution_tools call from the endpoint and test_execute_gate_uses_safe_set
fails.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")

#: Tools that must NEVER be on the no-approval lane — offensive with their own
#: flags (RCE, credential attacks, uploads, arbitrary TCP, DB writes).
OFFENSIVE = {
    "sqlmap", "ssh", "sshpass", "hydra", "medusa", "ncrack", "nc", "netcat",
    "netexec", "crackmapexec", "psql", "mysql", "redis-cli", "smbclient",
    "tftp", "ftp", "lftp", "vncviewer", "swaks", "telnet",
    "metasploit", "msfconsole", "msfvenom", "msf",
}
#: Borderline tools the operator chose to keep on the safe lane (with arg guards).
BORDERLINE_KEPT = {"curl", "wget", "nmap", "nuclei", "ffuf", "gobuster", "feroxbuster"}


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _set_literal(path, name):
    """The value of a module-level `name = {...}` set literal, via ast (no import
    — these modules pull in fastapi/langgraph that a bare checkout lacks)."""
    tree = ast.parse(_read(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return {el.value for el in node.value.elts
                            if isinstance(el, ast.Constant)}
    pytest.fail(f"{name} not found as a set literal in {os.path.basename(path)}")


def _func_src(path, name):
    tree = ast.parse(_read(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    pytest.fail(f"{name} not found in {os.path.basename(path)}")


def test_both_processes_agree():
    """The listener's enforcement set and the agent's tiering set are identical —
    otherwise a test tiered 'safe' is refused, or a tool tiered safe would run."""
    listener = _set_literal(LISTENER, "_SAFE_READONLY_TOOLS")
    agent = _set_literal(ENGINE, "_SAFE_TOOL_HINTS")
    assert listener == agent, (
        "safe-lane sets drifted:\n"
        f"  only in listener: {sorted(listener - agent)}\n"
        f"  only in agent:    {sorted(agent - listener)}")


def test_no_offensive_tool_is_on_the_safe_lane():
    safe = _set_literal(LISTENER, "_SAFE_READONLY_TOOLS")
    leaked = OFFENSIVE & safe
    assert not leaked, f"offensive tools on the no-approval lane: {sorted(leaked)}"


def test_borderline_tools_are_kept_per_operator_choice():
    """The operator kept these read-only tools on the safe lane (with arg guards),
    so a regression that drops them would silently push enumeration behind the
    approval gate."""
    safe = _set_literal(LISTENER, "_SAFE_READONLY_TOOLS")
    missing = BORDERLINE_KEPT - safe
    assert not missing, f"borderline read-only tools dropped from the safe lane: {sorted(missing)}"


def test_execute_gate_uses_safe_set_and_arg_filter():
    """/tools/execute must gate on the safe set (not the install manifest) and
    run the per-tool argument filter."""
    fn = _func_src(LISTENER, "execute_tool_endpoint")
    assert "get_safe_execution_tools()" in fn, (
        "/tools/execute no longer gates on the read-only safe set")
    assert "_readonly_arg_violation" in fn, (
        "/tools/execute no longer applies the per-tool argument filter")


def test_recommender_autoexec_uses_safe_set():
    """The recommender auto-exec path also runs without approval, so it must use
    the safe set too."""
    fn = _func_src(LISTENER, "execute_recommended_tools")
    assert "get_safe_execution_tools()" in fn, (
        "recommender auto-exec no longer bounded to the read-only safe set")


# ── Live (skips cleanly without the stack) ───────────────────────────────────

def _kali_url():
    return os.environ.get("KALI_URL")  # e.g. https://localhost:8019


def test_offensive_tool_refused_live():
    url = _kali_url()
    if not url:
        pytest.skip("KALI_URL not set")
    requests = pytest.importorskip("requests")
    try:
        r = requests.post(f"{url.rstrip('/')}/tools/execute",
                          json={"tool": "sqlmap", "command": "sqlmap -u http://x",
                                "target": "127.0.0.1", "port": 80},
                          timeout=15, verify=False)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"kali listener unreachable: {type(e).__name__}")
    assert r.status_code == 400, (r.status_code, r.text[:200])
    assert "safe lane" in r.text.lower() or "exploit manager" in r.text.lower(), r.text[:200]
