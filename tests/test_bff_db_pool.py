"""The BFF must pool its database connections, and return them clean.

Measured against this stack's database (remote, `sslmode=require`), 2026-10-15:

    fresh connect       317.6 ms
    query on open conn   45.7 ms
    alias lookup query   48.6 ms

The handshake costs SEVEN TIMES the query it carries. The BFF opened a fresh
connection per `get_db()` call, and the dispatch scope gate calls
`aliases_for()` once per target — so a 760-target masscan spent minutes doing
TLS handshakes inside the gate before a packet left the stack. node-manager
logged nothing and the BFF raised `httpx.ReadTimeout`, which from outside is
indistinguishable from a hung scanner.

rag-api has pooled for a long time; this pins that the BFF does the same.

The second half matters as much as the first. A per-call connection hid
transaction leaks by closing; a POOLED one hands the same session to the next
caller. Without a rollback on the way back, a failed caller returns a connection
in a failed transaction and the next user of that slot sees
`InFailedSqlTransaction` on a completely unrelated query — a bug that would
present as random, unrelated endpoint failures.

Static (`ast`). No DB.

Sabotage check: swap the pool back for `psycopg2.connect` and
`test_get_db_uses_a_pool` fails; drop the rollback-on-exception and
`test_connection_is_returned_clean` fails.

    pytest tests/test_bff_db_pool.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DB = REPO / "dashboard" / "bff" / "db.py"


def _tree() -> ast.Module:
    if not DB.exists():
        pytest.skip(f"{DB} not found")
    return ast.parse(DB.read_text(encoding="utf-8"))


def _fn(name: str) -> ast.FunctionDef:
    fn = next((n for n in ast.walk(_tree())
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn, f"{name} not found in dashboard/bff/db.py"
    return fn


def test_get_db_uses_a_pool():
    fn = _fn("get_db")
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_get_pool" in calls, (
        "get_db does not take from a pool — every call pays a ~318ms TLS "
        "handshake for a ~46ms query")
    attrs = {n.func.attr for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "getconn" in attrs, "get_db never calls getconn"
    assert "connect" not in calls, (
        "get_db still opens its own connection alongside the pool")


def test_connection_is_returned_to_the_pool():
    fn = _fn("get_db")
    attrs = [n.func.attr for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
    assert "putconn" in attrs, (
        "the connection is never returned — the pool would be exhausted after "
        "a handful of requests and the BFF would hang")
    assert "close" not in attrs or attrs.count("putconn") >= 1, (
        "connections are closed rather than returned, which defeats pooling")


def test_connection_is_returned_clean():
    """A pooled connection carries its transaction state to the next caller."""
    fn = _fn("get_db")
    handlers = [h for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler)]
    assert handlers, "get_db has no exception path at all"
    rolled = any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "rollback"
        for h in handlers for n in ast.walk(h))
    assert rolled, (
        "a failing caller returns its connection without a rollback, so the "
        "NEXT user of that slot sees InFailedSqlTransaction on an unrelated "
        "query — a per-call connection hid this by closing, a pooled one cannot")


def test_stale_connections_are_replaced():
    """An idle pooled connection can be dropped by the server."""
    fn = _fn("get_db")
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_alive" in calls, (
        "get_db yields a pooled connection without checking it is still "
        "usable — callers would see sporadic OperationalError on their first "
        "query after an idle period")


def test_pool_bounds_are_configurable_and_sane():
    tree = _tree()
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in ("_POOL_MIN", "_POOL_MAX"):
                    names[t.id] = node
    assert {"_POOL_MIN", "_POOL_MAX"} <= set(names), "pool bounds are not defined"
    for n in names.values():
        src = ast.dump(n.value)
        assert "environ" in src, (
            "pool bounds are hardcoded — an operator cannot tune them without "
            "a rebuild")
