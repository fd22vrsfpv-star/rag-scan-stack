"""Post-access wrapped remote-exec steps route via the NODE lane, never the
kali read-only lane — and ssh/sshpass are NEVER on the read-only allow-list.

Run on demand:

    pytest tests/test_post_access_lane.py -v

WHY THIS EXISTS
---------------
`_wrap_remote()` (autogen_agents/langgraph_engine.py) queues a playbook
post-access step as a command whose FIRST token — stored as the recommendation's
`scanner` — is a general-purpose remote-execution tool: `sshpass`/`ssh`,
`netexec`, `mysql -e`, `psql -c`. The command RUNS ON the target through that
tool, i.e. it is arbitrary remote code execution.

The kali dispatch route posts to `/tools/execute`, which name-gates on
`get_safe_execution_tools()` / `_SAFE_READONLY_TOOLS`. That allow-list holds only
read-only tools and contains NEITHER `ssh` NOR `sshpass` (nor netexec/mysql/psql)
— so these steps 400 on the kali route. They can only run via the tool-name-
AGNOSTIC node SSH path (`_dispatch_via_node`).

DECISION guarded here: keep the read-only lane read-only (do NOT add these tools
to `_SAFE_READONLY_TOOLS` — that would silently turn the no-approval lane into an
arbitrary-exec lane), and route the wrapped remote-exec steps via the node path,
never letting a set `use_kali` send them to the kali gate where they only 400.

SABOTAGE PROOF
--------------
* Add "ssh" or "sshpass" to `_SAFE_READONLY_TOOLS` in listener_service.py →
  test_readonly_lane_excludes_ssh_sshpass fails.
* Route the POST_ACCESS_REMOTE_EXEC scanners through `_dispatch_via_kali`, or
  delete the guard so they fall through to the `use_kali` kali branch →
  test_post_access_routes_via_node_not_kali fails.
"""
import ast
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _ast_assert import const_elements  # noqa: E402

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")
ASSETS = os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")

#: The wrapped remote-exec scanners `_wrap_remote()` can queue. Each is
#: general-purpose remote code execution, not a safe read-only scanner.
REMOTE_EXEC = {"ssh", "sshpass", "netexec", "mysql", "psql"}


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _local_set(src, name):
    """Elements of a set/list/tuple literal assigned to `name` ANYWHERE in the
    module (const_elements only sees module level; POST_ACCESS_REMOTE_EXEC is
    function-local)."""
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if not isinstance(n, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            continue
        v = n.value
        if isinstance(v, (ast.Set, ast.List, ast.Tuple)):
            return {e.value for e in v.elts if isinstance(e, ast.Constant)}
    return None


def _func(src, name):
    """The AsyncFunctionDef/FunctionDef node named `name`, or fail."""
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} not found in source")


def _callees(node):
    """Bare/attribute callee names of every Call under `node`."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.append(f.id)
            elif isinstance(f, ast.Attribute):
                out.append(f.attr)
    return out


# ── (a) the read-only lane stays read-only ───────────────────────────────────

def test_readonly_lane_excludes_ssh_sshpass():
    """`_SAFE_READONLY_TOOLS` must NOT list ssh or sshpass — they are
    general-purpose remote exec, not safe read-only tools."""
    safe = const_elements(Path(LISTENER), "_SAFE_READONLY_TOOLS")
    assert safe is not None, "_SAFE_READONLY_TOOLS not found in listener_service.py"
    leaked = {"ssh", "sshpass"} & safe
    assert not leaked, (
        f"remote-exec tools on the read-only allow-list: {sorted(leaked)} — "
        f"adding them turns the no-approval /tools/execute lane into an "
        f"arbitrary-exec lane")


def test_readonly_lane_excludes_all_wrapped_remote_exec():
    """None of the wrapped remote-exec scanners belong on the read-only lane."""
    safe = const_elements(Path(LISTENER), "_SAFE_READONLY_TOOLS")
    assert safe is not None
    leaked = REMOTE_EXEC & safe
    assert not leaked, f"remote-exec tools on the read-only allow-list: {sorted(leaked)}"


# ── (b) post-access steps route via the node lane, not the kali gate ──────────

def test_post_access_set_covers_wrapped_remote_exec():
    """The BFF's interception set must name the wrapped remote-exec scanners so
    they are diverted from the kali route."""
    src = _read(ASSETS)
    got = _local_set(src, "POST_ACCESS_REMOTE_EXEC")
    assert got is not None, "POST_ACCESS_REMOTE_EXEC not defined in assets.py"
    missing = REMOTE_EXEC - got
    assert not missing, f"wrapped remote-exec scanners not intercepted: {sorted(missing)}"


def test_post_access_routes_via_node_not_kali():
    """Inside dispatch, the `if scanner in POST_ACCESS_REMOTE_EXEC` guard must:
      * dispatch via `_dispatch_via_node` (tool-name-agnostic), never
        `_dispatch_via_kali` (which name-gates and would 400), and
      * come BEFORE any `_dispatch_via_kali` call, so a set `use_kali` cannot
        send these scanners to the kali gate first.
    """
    src = _read(ASSETS)
    disp = _func(src, "dispatch_rec")

    guard = None
    for n in ast.walk(disp):
        if not isinstance(n, ast.If):
            continue
        t = n.test
        if (isinstance(t, ast.Compare)
                and isinstance(t.left, ast.Name) and t.left.id == "scanner"
                and len(t.ops) == 1 and isinstance(t.ops[0], ast.In)
                and isinstance(t.comparators[0], ast.Name)
                and t.comparators[0].id == "POST_ACCESS_REMOTE_EXEC"):
            guard = n
            break
    assert guard is not None, (
        "no `if scanner in POST_ACCESS_REMOTE_EXEC:` guard in dispatch_rec — "
        "wrapped remote-exec steps would fall through to the kali route and 400")

    body_calls = _callees(guard)
    assert "_dispatch_via_node" in body_calls, (
        "post-access guard does not dispatch via the node path")
    assert "_dispatch_via_kali" not in body_calls, (
        "post-access guard dispatches via the kali route — that route name-gates "
        "on the read-only allow-list and would refuse these tools")

    kali_calls = [n for n in ast.walk(disp)
                  if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Name)
                  and n.func.id == "_dispatch_via_kali"]
    if kali_calls:
        assert guard.lineno < min(c.lineno for c in kali_calls), (
            "the POST_ACCESS_REMOTE_EXEC guard runs AFTER a _dispatch_via_kali "
            "branch — a set use_kali would send these scanners to the kali gate "
            "before the guard could divert them")
