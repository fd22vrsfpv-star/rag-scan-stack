"""The dispatch gate must not open a database connection per target.

`scope_guard.aliases_for()` opens its own connection, and the node-dispatch gate
called it once per target through `refusal_for`. The database is remote and the
DSN requires SSL, so a 760-target masscan of the examplecorp scope meant **760 TLS
handshakes inside the gate** before a single packet left the stack.

Observed 2026-10-14: the request sat in the gate for over twelve minutes,
node-manager logged nothing at all, and the BFF eventually raised
`httpx.ReadTimeout`. From outside that is indistinguishable from a hung scanner
— and the scan it was blocking is the one that decides whether 510 hosts get
filed as having no attack surface.

The verdicts are unchanged: same deny-list check, same scope check, same order.
Only the connection count changes.

This is the AUTHORIZATION path, so the guard also pins that it still fails
closed when the gate cannot be imported.

Static (`ast`). No DB.

Sabotage check: restore the per-target `refusal_for` call and
`test_gate_resolves_aliases_once_for_the_batch` fails.

    pytest tests/test_dispatch_gate_batching.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NODES = REPO / "dashboard" / "bff" / "routers" / "nodes.py"
GUARD = REPO / "dashboard" / "bff" / "scope_guard.py"


def _fn(path: Path, name: str):
    if not path.exists():
        pytest.skip(f"{path} not found")
    fn = next((n for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)
    assert fn, f"{name} not found in {path.name}"
    return fn


def test_gate_resolves_aliases_once_for_the_batch():
    fn = _fn(NODES, "scan_through_node")
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name)]
    names = [c.func.id for c in calls]
    assert "aliases_for_many" in names, (
        "the dispatch gate does not batch its alias lookups — with one DB "
        "connection per target a large dispatch stalls in the gate and looks "
        "like a dead scanner")
    # And the per-target form must be gone from the loop.
    for node in ast.walk(fn):
        if not isinstance(node, ast.For):
            continue
        inner = {c.func.id for c in ast.walk(node)
                 if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
        assert "refusal_for" not in inner, (
            "refusal_for is still called inside the per-target loop; it opens "
            "its own connection every time")
        assert "aliases_for" not in inner, (
            "aliases_for is called per target inside the loop")


def test_batch_helper_uses_one_connection():
    fn = _fn(GUARD, "aliases_for_many")
    withs = [n for n in ast.walk(fn) if isinstance(n, ast.With)]
    assert withs, "aliases_for_many opens no connection at all"
    # The connection must be opened OUTSIDE the per-host loop.
    for w in withs:
        loops_inside = [n for n in ast.walk(w) if isinstance(n, ast.For)]
        if loops_inside:
            return
    pytest.fail("the per-host loop is not inside a single connection context — "
                "the batch helper reopens per host, which is the bug it fixes")


def test_gate_still_fails_closed_when_unavailable():
    """Authorization, not a view filter."""
    fn = _fn(NODES, "scan_through_node")
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "SCOPE_GATE_AVAILABLE" in names, (
        "the gate no longer checks whether the scope gate imported — an "
        "unavailable gate would read as 'nothing to refuse'")
    raises = [n for n in ast.walk(fn) if isinstance(n, ast.Raise)]
    codes = {c.value for r in raises for c in ast.walk(r)
             if isinstance(c, ast.Constant) and isinstance(c.value, int)}
    assert 403 in codes, "the gate no longer refuses with 403"


def test_batch_failure_narrows_never_widens():
    """A lookup that could not run must not grant extra identities."""
    fn = _fn(GUARD, "aliases_for_many")
    handlers = [h for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler)]
    assert handlers, "aliases_for_many has no failure path"
    for h in handlers:
        sets = [n for n in ast.walk(h) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == "set"]
        dicts = [n for n in ast.walk(h) if isinstance(n, ast.DictComp)]
        assert sets or dicts, (
            "a failed alias lookup does not fall back to an empty alias set; "
            "it must narrow the host to itself, never widen it")
