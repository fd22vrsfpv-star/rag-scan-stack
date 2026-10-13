"""masscan on a remote node must run under `sudo -n`.

masscan builds its own packets, so it needs CAP_NET_RAW. Cloud images log in as
`ubuntu`/`admin`, never root, so without elevation every remote masscan exited:

    [-] FAIL: permission denied
        [hint] need to sudo or run as root or something
    [-] if:ens5:init: failed

and the operator saw a scan that found nothing — the repo's recurring
"unreachable reported as absent". There were zero occurrences of `sudo` anywhere
in node_manager/ before this.

Three things have to hold together, so all three are pinned:

  1. `SSHManager.remote_scan(elevate=True)` prefixes `sudo -n` — and only for a
     non-root SSH user, so a node that logs in as root is unaffected.
  2. The masscan template declares `needs_root`.
  3. The call site passes that declaration through, rather than a constant.

nmap is deliberately NOT elevated: without root it falls back to a TCP connect
scan and still works, so requiring sudo there would break nodes that scan fine
today. The test asserts that too, so "mark everything needs_root" fails here.

No DB, no SSH, no fastapi import — `exec_command`/`download_file` are stubbed and
node_manager.py is read with `ast`.

Sabotage check: drop the `sudo -n` prefix in `ssh_manager.remote_scan` and
`test_masscan_is_elevated` fails; remove `needs_root` from the template and
`test_masscan_template_declares_needs_root` fails; hardcode `elevate=False` at
the call site and `test_call_site_forwards_the_declaration` fails.

    pytest tests/test_remote_scan_privilege.py -q
"""

import ast
import asyncio
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NODE_MANAGER = REPO / "node_manager" / "node_manager.py"

sys.path.insert(0, str(REPO / "node_manager"))
ssh_manager_mod = pytest.importorskip(
    "ssh_manager", reason="node_manager/ssh_manager.py not importable here"
)


# ── 1. behaviour: what actually gets sent over SSH ────────────────────────────

def _run_scan(user: str, elevate: bool) -> str:
    """Call the real remote_scan with the SSH legs stubbed; return the command."""
    mgr = ssh_manager_mod.SSHManager()
    seen = {}

    async def fake_exec(**kw):
        seen["command"] = kw["command"]
        return {"ok": True, "stdout": "", "stderr": "", "duration_ms": 1}

    async def fake_download(**kw):
        return {"ok": True}

    mgr.exec_command = fake_exec
    mgr.download_file = fake_download

    result = asyncio.run(mgr.remote_scan(
        node_id="n1", host="203.0.113.10", user=user, ssh_port=22,
        key_file="k.pem",
        tool_cmd=["masscan", "-p", "80,443", "--rate", "1000",
                  "-oJ", "/tmp/scan_out.json", "198.51.100.1"],
        output_remote_path="/tmp/scan_out.json",
        elevate=elevate,
    ))
    assert result.get("ok"), result
    return seen["command"]


def test_masscan_is_elevated():
    """A non-root SSH user gets `sudo -n`, non-interactively."""
    cmd = _run_scan(user="ubuntu", elevate=True)
    head = cmd.split()
    assert head[0] == "sudo", f"not elevated: {cmd!r}"
    assert "-n" in head[1:2], f"sudo would prompt and hang: {cmd!r}"
    assert head[2] == "masscan", f"tool displaced by the prefix: {cmd!r}"


def test_root_user_is_not_elevated():
    """sudo may not even be installed on a root-login node; don't add it."""
    cmd = _run_scan(user="root", elevate=True)
    assert cmd.split()[0] == "masscan", f"root should run bare: {cmd!r}"


def test_elevation_is_opt_in():
    """Tools that work unprivileged keep running unprivileged."""
    cmd = _run_scan(user="ubuntu", elevate=False)
    assert cmd.split()[0] == "masscan", f"elevated without asking: {cmd!r}"


# ── 2 + 3. the declaration and its wiring, read from source ───────────────────

def _node_manager_tree() -> ast.Module:
    if not NODE_MANAGER.exists():
        pytest.skip(f"{NODE_MANAGER} not found")
    return ast.parse(NODE_MANAGER.read_text(encoding="utf-8"))


def _scan_templates() -> dict:
    """Return {scan_type: {key: literal}} for REMOTE_SCAN_TEMPLATES."""
    for node in ast.walk(_node_manager_tree()):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "REMOTE_SCAN_TEMPLATES"
                   for t in node.targets):
            continue
        out = {}
        for k, v in zip(node.value.keys, node.value.values):
            if not isinstance(k, ast.Constant) or not isinstance(v, ast.Dict):
                continue
            entry = {}
            for ik, iv in zip(v.keys, v.values):
                if isinstance(ik, ast.Constant):
                    try:
                        entry[ik.value] = ast.literal_eval(iv)
                    except ValueError:
                        entry[ik.value] = None
            out[k.value] = entry
        return out
    pytest.fail("REMOTE_SCAN_TEMPLATES not found in node_manager.py")


def test_masscan_template_declares_needs_root():
    templates = _scan_templates()
    assert "masscan" in templates, sorted(templates)
    assert templates["masscan"].get("needs_root") is True, (
        "masscan has no needs_root flag — it will fail 'permission denied' "
        "on every non-root node")


def test_connect_scan_tools_stay_unprivileged():
    """nmap degrades gracefully without root; elevating it is a regression."""
    templates = _scan_templates()
    if "nmap" in templates:
        assert not templates["nmap"].get("needs_root"), (
            "nmap marked needs_root — it works unprivileged (TCP connect scan), "
            "and requiring sudo breaks nodes without passwordless sudo")


def test_call_site_forwards_the_declaration():
    """`elevate=` must come from the template, not be pinned to a constant."""
    calls = [
        n for n in ast.walk(_node_manager_tree())
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "remote_scan"
    ]
    assert calls, "no ssh_manager.remote_scan(...) call found in node_manager.py"
    for call in calls:
        kw = {k.arg: k.value for k in call.keywords if k.arg}
        assert "elevate" in kw, "remote_scan called without elevate="
        value = kw["elevate"]
        assert not isinstance(value, ast.Constant), (
            "elevate is hardcoded — the per-tool needs_root declaration is "
            "no longer reaching the SSH layer")
        # It must read the template entry, directly or through a wrapper.
        names = {n.value for n in ast.walk(value) if isinstance(n, ast.Constant)}
        assert "needs_root" in names, (
            "elevate= does not read needs_root from the scan template")
