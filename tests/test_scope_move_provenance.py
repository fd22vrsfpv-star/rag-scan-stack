"""A scope move is destructive, so it must leave a record of what moved.

`/scope/move` has always called `_capture_scope_decisions`. The per-engagement
route `/engagements/{eid}/scopes/{scope_name}/move` — the one the Scope tab
uses — did not: it wrote `source='moved'` and nothing else. No
`scope_decisions` row, no audit entry, no webhook. The same destructive
operation was accountable through one route and anonymous through the other.

That asymmetry is invisible until the record is needed. Seven `*.agents_net`
hostnames, including this stack's own `zap` and `playwright-scanner`
containers, were moved into `excluded` in one batch on 2026-10-14 20:35:37.
Their previous scope is unrecoverable: 0 decision rows, 0 audit entries for any
of them. The outcome was correct and the provenance was simply gone.
`/scope/move`'s own docstring records a worse case — a widened move took
`examplecorp.com` and `legacycorp.net`, the two apexes defining the engagement, out
of scope from a dialog that said "77 item(s) selected".

Two further defects covered here:

  * `target_type` was hardcoded to 'domain', so an IP moved through this route
    was recorded as a domain.
  * `except Exception: conn.rollback()` rolled the WHOLE transaction back
    mid-loop and kept going, so one bad target silently discarded every move
    already made while `moved` still counted them — a success count describing
    work that no longer existed.

Sabotage check: delete the `_capture_scope_decisions` call and
`test_the_per_engagement_move_records_provenance` fails; hardcode
`'domain'` again and `test_target_type_is_derived` fails; restore
`conn.rollback()` inside the loop and `test_one_bad_target_does_not_discard_the_batch`
fails.

    pytest tests/test_scope_move_provenance.py -q
"""

import ast
import os
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
ROUTE = "/engagements/{eid}/scopes/{scope_name}/move"


def _moves():
    """Both move endpoints, keyed by route."""
    src = API.read_text(encoding="utf-8") if API.exists() else pytest.skip("api.py missing")
    out = {}
    for n in ast.walk(ast.parse(src)):
        if not isinstance(n, ast.FunctionDef) or n.name != "move_scope_targets":
            continue
        for dec in n.decorator_list:
            if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant):
                out[dec.args[0].value] = ast.get_source_segment(src, n) or ""
    return out


def _calls(route: str) -> set:
    """Function names CALLED by the handler, from the AST.

    Not a substring search. The handler's own docstring names
    `_capture_scope_decisions` while explaining why it must be there, so
    `"_capture_scope_decisions" in body` passed with the call deleted — the
    same trap that has hidden a removed import, a removed call and a
    one-of-two-branches deletion elsewhere in this suite.
    """
    src = API.read_text(encoding="utf-8")
    for n in ast.walk(ast.parse(src)):
        if not isinstance(n, ast.FunctionDef) or n.name != "move_scope_targets":
            continue
        for dec in n.decorator_list:
            if isinstance(dec, ast.Call) and dec.args \
               and isinstance(dec.args[0], ast.Constant) and dec.args[0].value == route:
                return {c.func.id for c in ast.walk(n)
                        if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
    pytest.fail(f"no move handler for {route}")


def test_both_move_routes_still_exist():
    routes = _moves()
    assert len(routes) == 2, f"expected two move endpoints, found {sorted(routes)}"
    assert ROUTE in routes


def test_the_per_engagement_move_records_provenance():
    """THE gap. A destructive move with no record of what it destroyed."""
    assert "_capture_scope_decisions" in _calls(ROUTE), (
        "the per-engagement move does not CALL _capture_scope_decisions, so "
        "what moved and from where is unrecoverable the moment it runs — the "
        "row in the source scope is DELETEd")


def test_both_routes_record_provenance_the_same_way():
    """One accountable route and one anonymous one is the actual defect."""
    routes = _moves()
    missing = [r for r in routes if "_capture_scope_decisions" not in _calls(r)]
    assert not missing, (
        f"these move routes record no provenance: {missing}. Two endpoints "
        "performing the same destructive operation must be equally "
        "accountable, or the unaudited one becomes the one that gets used")


def test_provenance_is_captured_before_the_commit():
    """A recorded decision must never describe a move that did not land."""
    body = _moves()[ROUTE]
    i_cap = body.find("_capture_scope_decisions")
    i_commit = body.find("conn.commit()")
    assert 0 < i_cap < i_commit, (
        "provenance is captured after the commit (or not at all), so a crash "
        "between them leaves a decision row for a move that was rolled back")


def test_target_type_is_derived():
    body = _moves()[ROUTE]
    assert "'domain', 'moved'" not in body and '"domain", "moved"' not in body, (
        "target_type is still hardcoded to 'domain', so every IP moved "
        "through this route is recorded as a domain")
    assert "ttype" in body or "target_type" in body, "no target_type derivation"


def test_one_bad_target_does_not_discard_the_batch():
    """`conn.rollback()` inside the loop undoes work already done."""
    body = _moves()[ROUTE]
    i_loop = body.find("for target in body.targets")
    assert i_loop > 0, "the loop is gone"
    # Structural: no conn.rollback() CALL anywhere inside the per-target loop.
    # The substring form also matched the explanation in the docstring above.
    import ast as _ast
    fn = next(n for n in _ast.walk(_ast.parse(API.read_text(encoding="utf-8")))
              if isinstance(n, _ast.FunctionDef) and n.name == "move_scope_targets"
              and any(isinstance(d, _ast.Call) and d.args
                      and getattr(d.args[0], "value", None) == ROUTE
                      for d in n.decorator_list))
    loops = [n for n in _ast.walk(fn) if isinstance(n, _ast.For)]
    assert loops, "the per-target loop is gone"
    rollbacks = [n for loop in loops for n in _ast.walk(loop)
                 if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
                 and n.func.attr == "rollback"]
    assert not rollbacks, (
        f"conn.rollback() is called inside the per-target loop (line "
        f"{rollbacks[0].lineno}): one bad target rolls back the WHOLE "
        "transaction while the loop keeps going, so earlier successful moves "
        "are silently discarded and `moved` still counts them")
    # ... and the failure is REPORTED rather than swallowed: appended to a
    # per-target list inside the loop's handler, and returned to the caller.
    appends = [n for loop in loops for n in _ast.walk(loop)
               if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
               and n.func.attr == "append"
               and isinstance(n.func.value, _ast.Name)
               and n.func.value.id == "failed"]
    assert appends, (
        "nothing is appended to `failed` inside the per-target loop, so a "
        "target that raised is swallowed and a partial move looks total")
    returned = {k.value for r in _ast.walk(fn) if isinstance(r, _ast.Return)
                and isinstance(r.value, _ast.Dict)
                for k in r.value.keys
                if isinstance(k, _ast.Constant)}
    assert "failed" in returned, (
        f"the handler does not return a `failed` key (returns {sorted(returned)}), "
        "so the caller sees `moved` and cannot tell the batch was partial")


def test_the_route_executes():
    """Mutating endpoint: it must be exercised, not just parsed.

    Uses tests/_container.container_exec rather than a private `docker exec`.
    The hand-rolled version here branched on a raised FileNotFoundError, which
    is how the absent-container skip was missed in five modules at once: a
    container that is DOWN makes `docker exec` exit non-zero rather than raise,
    so the skip never fired and the failure read as the endpoint being broken.
    The helper distinguishes "cannot run here" from "ran and broke".
    """
    import json
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent))
    try:
        from _container import container_exec
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"container helper unavailable: {e}")

    out = container_exec(SCRIPT, timeout=120)
    if out is None:
        pytest.skip("rag-api container not reachable from here")
    if out.startswith("__ERR__"):
        pytest.fail(f"probe failed inside rag-api: {out[:300]}")
    line = [l for l in out.strip().splitlines() if l.startswith("{")]
    if not line:
        pytest.skip(f"probe produced no result: {out[-200:]}")
    got = json.loads(line[-1])
    if "skip" in got:
        pytest.skip(got["skip"])
    assert "error" not in got, got["error"]
    assert got["moved"] == 1, got
    assert got["landed"] and got["landed"][0] == "pytest_dst", got
    assert got["decision"] == ["pytest_src", "pytest_dst"], (
        f"the move left no decision row recording where it came from: {got}")


SCRIPT = r'''
import sys, json, uuid; sys.path.insert(0, "/app")
from api import get_db
EID = None
tgt = "pytest-move-%s.example" % uuid.uuid4().hex[:8]
out = {}
try:
    with get_db() as c, c.cursor() as cur:
        cur.execute("SELECT id::text FROM engagements LIMIT 1")
        row = cur.fetchone()
        if not row:
            print(json.dumps({"skip": "no engagement"})); raise SystemExit
        EID = row[0]
        cur.execute("""INSERT INTO scope_targets (engagement_id, name, target, target_type, source)
                       VALUES (%s::uuid, 'pytest_src', %s, 'domain', 'pytest')
                       ON CONFLICT DO NOTHING""", (EID, tgt))
        c.commit()
    import api
    class B:
        targets = [tgt]; to_engagement_id = EID; to_scope_name = "pytest_dst"
    res = api.move_scope_targets(EID, "pytest_src", B(), True)
    with get_db() as c, c.cursor() as cur:
        cur.execute("SELECT name, target_type FROM scope_targets WHERE target=%s", (tgt,))
        landed = cur.fetchone()
        cur.execute("SELECT from_scope, to_scope FROM scope_decisions WHERE target=%s", (tgt,))
        dec = cur.fetchone()
        cur.execute("DELETE FROM scope_targets WHERE target=%s", (tgt,))
        cur.execute("DELETE FROM scope_decisions WHERE target=%s", (tgt,))
        c.commit()
    out = {"moved": res.get("moved"), "landed": list(landed) if landed else None,
           "decision": list(dec) if dec else None}
except Exception as e:
    out = {"error": "%s: %s" % (type(e).__name__, e)}
print(json.dumps(out))
'''
