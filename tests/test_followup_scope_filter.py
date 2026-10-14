"""Selecting a scope must filter the counts and the grouped view, not just the list.

The follow-ups page filtered its TABLE by the selected scope client-side, in
`matchesAnyScope`. The stats header and the grouped view are server queries, and
they only ever received `exclude_scope` — a scope to omit. The scope the
operator actually selected never reached them.

Reported 2026-10-14: with the `examplecorp` scope selected, the panel showed IP
addresses that are not in it. That scope holds 760 targets, every one a
hostname, zero IPs — and the grouped rows render `host_samples` straight from
the unfiltered query.

A client-side filter cannot fix either surface: it cannot change a count
computed in SQL, and it cannot un-hide an in-scope row that pagination dropped
before it ever reached the browser.

`_scope_inclusion_clause` is the inverse of `_scope_exclusion_clause` and uses a
dot-boundary suffix match, unlike it. The reasoning inverts with the direction:
an over-generous EXCLUDE hides the operator's work, and so does an over-strict
INCLUDE — a scope naming `examplecorp.com` is understood to cover
`www.examplecorp.com`. This is a VIEW filter; `etl/scope_gate.py` is the
authorization boundary and that one fails closed.

Static (`ast`) — no DB, no running stack.

Sabotage check: drop `scope_name` from any of the three handlers, or stop
applying the clause in one of them, and that case fails by name.

    pytest tests/test_followup_scope_filter.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
API_TS = REPO / "dashboard" / "frontend" / "src" / "api" / "followups.ts"
PAGE = REPO / "dashboard" / "frontend" / "src" / "pages" / "FollowUps.tsx"

# All three read follow-ups and all three are rendered under the scope header.
HANDLERS = ("list_follow_ups", "follow_up_stats", "follow_ups_grouped")


def _read(p: Path) -> str:
    if not p.exists():
        pytest.skip(f"{p} not found")
    return p.read_text(encoding="utf-8")


def _fn(name: str) -> ast.FunctionDef:
    fn = next((n for n in ast.walk(ast.parse(_read(API)))
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn, f"{name} not found in api.py — renamed, and this guard went blind"
    return fn


@pytest.mark.parametrize("name", HANDLERS)
def test_handler_accepts_the_selected_scope(name):
    args = {a.arg for a in _fn(name).args.args} | {a.arg for a in _fn(name).args.kwonlyargs}
    assert "scope_name" in args, (
        f"{name} cannot be told which scope is selected, so it answers for the "
        "whole engagement under that scope's header")


@pytest.mark.parametrize("name", HANDLERS)
def test_handler_applies_the_inclusion_clause(name):
    calls = {n.func.id for n in ast.walk(_fn(name))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_scope_inclusion_clause" in calls, (
        f"{name} takes scope_name and never uses it — the parameter is accepted "
        "and discarded, which looks like a working filter")


def test_inclusion_matches_subdomains():
    """An exact-only include would hide most of a scope's real hosts."""
    fn = _fn("_scope_inclusion_clause")
    sql = " ".join(n.value for n in ast.walk(fn)
                   if isinstance(n, ast.Constant) and isinstance(n.value, str))
    assert "LIKE" in sql.upper(), (
        "the include clause is exact-match only, so a scope naming "
        "examplecorp.com would hide www.examplecorp.com")
    assert "scope_targets" in sql


def test_inclusion_is_a_noop_when_nothing_is_selected():
    """Otherwise every unfiltered view empties itself."""
    fn = _fn("_scope_inclusion_clause")
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    empties = [r for r in returns
               if isinstance(r.value, ast.Tuple)
               and isinstance(r.value.elts[0], ast.Constant)
               and r.value.elts[0].value == ""]
    assert empties, (
        "no empty-clause return — with no scope selected the caller would "
        "append a filter that matches nothing")


@pytest.mark.parametrize("hook", ["useFollowUpStats", "useFollowUpGrouped"])
def test_frontend_hook_forwards_the_scope(hook):
    src = _read(API_TS)
    import re
    m = re.search(rf"export function {hook}\b[^{{]*{{", src)
    assert m, f"{hook} not found"
    body = src[m.start(): m.start() + 900]
    assert "scope_name" in body, (
        f"{hook} does not forward the selected scope, so the server still "
        "answers for the whole engagement")


def test_page_passes_the_selected_scope_to_both():
    page = _read(PAGE)
    import re
    for call in ("useFollowUpStats", "useFollowUpGrouped"):
        m = re.search(rf"{call}\(([^)]*)\)", page)
        assert m, f"{call} not called in FollowUps.tsx"
        assert "scopeFilter" in m.group(1), (
            f"{call} is called without scopeFilter — the dropdown changes the "
            "table but not this view")
