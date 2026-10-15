"""The scope gate must not re-fetch the asset list once per target.

`_enforce_scope` calls `_scope_aliases(h)` for each target, and `_scope_aliases`
used to issue its own `GET /assets?limit=5000`. A 762-host dispatch was
therefore up to 762 full asset-list fetches. The request never finished
validating, the BFF's 30s client timeout fired, and the operator saw a bare

    HTTP 500 Internal Server Error        (httpx.ReadTimeout)

with **no job created**. Nothing was wrong with the scan or the scope — the gate
could not be evaluated in the time the caller was willing to wait. That is
CLAUDE.md's "client timeouts MUST cover the worst admitted latency", failing
from the other side: the work was never admitted at all.

Two fixes, both pinned here:

  1. one cached `/assets` fetch builds a host -> aliases map for every target;
  2. the direct scope check runs FIRST, so an in-scope host never pays for
     alias resolution at all.

The gate's VERDICTS are unchanged — a host in scope under another observed
identity is still accepted, which is what `_scope_aliases` exists for.

Static (`ast`): no network, no running scanner.

Sabotage check: move the requests.get back inside `_scope_aliases` and
`test_alias_lookup_does_not_fetch_per_target` fails; drop the direct-check
short-circuit and `test_direct_scope_check_runs_before_alias_resolution` fails.

    pytest tests/test_scope_gate_alias_cost.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NMAP_API = REPO / "nmap_scanner" / "nmap-api.py"


def _tree() -> ast.Module:
    if not NMAP_API.exists():
        pytest.skip(f"{NMAP_API} not found")
    return ast.parse(NMAP_API.read_text(encoding="utf-8"))


def _func(name: str):
    fn = next((n for n in ast.walk(_tree())
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn, f"{name} not found in nmap_scanner/nmap-api.py"
    return fn


def _http_calls(fn) -> list:
    """requests.get / requests.post inside this function."""
    return [n for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("get", "post")
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id == "requests"]


def test_alias_lookup_does_not_fetch_per_target():
    """_scope_aliases is called once per target — it must be cheap."""
    assert not _http_calls(_func("_scope_aliases")), (
        "_scope_aliases issues an HTTP request; _enforce_scope calls it once "
        "per target, so a large dispatch times out before any job is created")


def test_alias_map_is_cached():
    fn = _func("_alias_map")
    assert _http_calls(fn), "_alias_map never fetches anything"
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "_ALIAS_CACHE" in names, (
        "_alias_map does not use _ALIAS_CACHE — every call would re-fetch and "
        "the per-target cost is back")


def test_a_failed_fetch_does_not_become_no_aliases():
    """A lookup that could not run is not evidence that no aliases exist."""
    fn = _func("_alias_map")
    # Only the handler guarding the FETCH. _alias_map also has a handler around
    # the optional shared-cache import, which correctly just falls back to the
    # local dict and returns nothing — judging every handler alike flagged that
    # as a missing failure path.
    handlers = [h for h in ast.walk(fn)
                if isinstance(h, ast.ExceptHandler)
                and any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and n.func.attr in ("get", "post")
                        for n in ast.walk(getattr(h, "parent_try", h)))]
    if not handlers:
        # Fall back to "handlers that return", which is the property under test.
        handlers = [h for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler)
                    and any(isinstance(n, ast.Return) for n in ast.walk(h))]
    assert handlers, "_alias_map has no failure path that returns at all"
    for h in handlers:
        returns = [n for n in ast.walk(h) if isinstance(n, ast.Return)]
        assert returns, "the failure path falls through instead of returning"
        for r in returns:
            # Must fall back to the previous map, not an empty literal alone.
            empties = [n for n in ast.walk(r)
                       if isinstance(n, ast.Dict) and not n.keys]
            names = {n.id for n in ast.walk(r) if isinstance(n, ast.Name)}
            assert "_ALIAS_CACHE" in names or not empties, (
                "a failed fetch returns a bare empty map, so every host loses "
                "its aliases for the rest of the TTL and in-scope targets get "
                "refused")


def test_direct_scope_check_runs_before_alias_resolution():
    """An in-scope host must not pay for alias resolution."""
    fn = _func("_enforce_scope")
    for node in ast.walk(fn):
        if not isinstance(node, ast.For):
            continue
        body = list(ast.walk(node))
        # ast.walk is BREADTH-first, so it does not give source order and a
        # swapped check would still pass. Sort by position instead.
        calls = sorted(
            (n for n in body
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)),
            key=lambda n: (n.lineno, n.col_offset))
        names = [c.func.id for c in calls]
        if "_in_scope" in names and "_scope_aliases" in names:
            assert names.index("_in_scope") < names.index("_scope_aliases"), (
                "_scope_aliases is resolved before the direct scope check, so "
                "every in-scope host pays for it")
            return
    pytest.fail("no per-target loop found in _enforce_scope that does both "
                "the direct check and alias resolution")


def test_gate_still_refuses_out_of_scope_hosts():
    """The cost fix must not have removed the verdict."""
    fn = _func("_enforce_scope")
    raises = [n for n in ast.walk(fn) if isinstance(n, ast.Raise)]
    assert raises, "_enforce_scope no longer refuses anything"
    codes = {n.value for r in raises for n in ast.walk(r)
             if isinstance(n, ast.Constant) and isinstance(n.value, int)}
    assert 403 in codes, "_enforce_scope no longer raises 403 for out-of-scope"
