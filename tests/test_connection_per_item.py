"""A database connection must not be opened once per item in a loop.

Measured on this stack (remote database, `sslmode=require`), 2026-10-15:

    fresh connect       317.6 ms
    query on open conn   45.7 ms

The handshake costs seven times the query it carries, so a loop that connects
per item pays that tax N times inside one request. The BFF's dispatch scope gate
did exactly this — `aliases_for()` per target — and a 760-target masscan sat in
the gate for over twelve minutes while node-manager logged nothing and the BFF
raised `httpx.ReadTimeout`. From outside, indistinguishable from a hung scanner.

**Pooling every service is NOT the answer, and this guard is not an argument for
it.** Measured connection churn across the whole stack at idle was **0.7 new
connections per minute** — about 0.2 s of handshake per minute. rag-api and the
BFF pool because they burst; the rest connect from slept watchdogs (every
5–60 s) or from small bounded loops, where a pool would save nothing worth the
moving part.

What matters is the BURST shape, so that is what this ratchets: a connection
opened inside a loop. The known sites are listed with why each is acceptable. A
NEW one fails by name, and the author decides — hoist the connection, use a
pooled helper, or add a line here saying why it is bounded.

Static (`ast`). No DB.

Sabotage check: add a `psycopg2.connect` inside any loop in a non-listed
function and this fails naming the file and function.

    pytest tests/test_connection_per_item.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# Helpers that hand back a POOLED connection — cheap, not a handshake.
POOLED_HELPERS = {"get_db"}          # rag-api and the BFF both pool theirs
RAW_CONNECTORS = {"connect", "_get_conn", "get_conn", "_db_conn"}

SKIP_DIRS = {"tests", "scripts", "grpo_trainer", "node_modules", ".git",
             "venv", ".venv", "__pycache__"}

# Known per-item connect sites, each with the reason it is tolerable.
# RATCHETS: shrink it, do not grow it without a stated reason.
CONNECT_IN_LOOP_DEBT = {
    ("node_manager/node_manager.py", "_tunnel_health_watchdog"):
        "background watchdog, sleeps 60s between iterations",
    ("node_manager/node_manager.py", "_installation_task_processor"):
        "background poller, sleeps 5-10s between iterations",
    ("node_manager/node_manager.py", "lifespan"):
        "startup only, runs once per process",
    ("node_manager/ssh_manager.py", "reload_tunnels"):
        "one iteration per configured node (3 here); startup path",
    ("web_scanner/scan_pipeline.py", "_run_wafw00f"):
        "sleeps 5s between iterations",
    ("autogen_agents/langgraph_engine.py", "surface_exec"):
        "one iteration per operator-approved exploit, and each iteration runs "
        "the exploit itself — the connect is noise beside it",
}


def _offenders():
    found = {}
    for p in sorted(REPO.rglob("*.py")):
        rel = str(p.relative_to(REPO))
        if set(p.parts) & SKIP_DIRS or rel.startswith("tests/"):
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for fn in [n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for loop in [n for n in ast.walk(fn)
                         if isinstance(n, (ast.For, ast.AsyncFor, ast.While))]:
                for call in ast.walk(loop):
                    if not isinstance(call, ast.Call):
                        continue
                    if isinstance(call.func, ast.Name):
                        name = call.func.id
                    elif isinstance(call.func, ast.Attribute):
                        name = call.func.attr
                    else:
                        continue
                    if name in POOLED_HELPERS:
                        continue          # a pool checkout, not a handshake
                    if name not in RAW_CONNECTORS:
                        continue
                    if name == "connect" and isinstance(call.func, ast.Attribute):
                        if getattr(call.func.value, "id", "") != "psycopg2":
                            continue
                    found[(rel, fn.name)] = call.lineno
                    break
    return found


def test_no_new_connection_per_item_loops():
    offenders = _offenders()
    new = {k: v for k, v in offenders.items() if k not in CONNECT_IN_LOOP_DEBT}
    assert not new, (
        "a database connection is opened inside a loop in:\n  "
        + "\n  ".join(f"{f}:{ln} {fn}()" for (f, fn), ln in sorted(new.items()))
        + "\n\nEach iteration pays a ~318ms TLS handshake for ~46ms of work. "
          "Hoist the connection out of the loop, use a pooled helper, or add "
          "an entry to CONNECT_IN_LOOP_DEBT saying why the loop is bounded.")


def test_debt_list_does_not_rot():
    """A fixed entry must be deleted, or the list stops meaning anything."""
    offenders = _offenders()
    stale = [k for k in CONNECT_IN_LOOP_DEBT if k not in offenders]
    assert not stale, (
        "these CONNECT_IN_LOOP_DEBT entries no longer connect in a loop — "
        "delete them: " + ", ".join(f"{f}::{fn}" for f, fn in sorted(stale)))


def test_the_two_bursting_services_pool():
    """rag-api and the BFF are the ones that burst; both must pool."""
    for rel, helper in (("app/rag-api/api.py", "_get_pool"),
                        ("dashboard/bff/db.py", "_get_pool")):
        src = (REPO / rel).read_text(encoding="utf-8")
        assert f"def {helper}" in src, (
            f"{rel} no longer defines {helper} — the service that bursts "
            "connections is back to a handshake per call")
