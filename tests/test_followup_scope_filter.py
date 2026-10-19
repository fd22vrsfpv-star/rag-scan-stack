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


BFF = REPO / "dashboard" / "bff" / "routers" / "followups.py"
BFF_PROXIES = ("follow_up_stats", "follow_ups_grouped")


@pytest.mark.parametrize("name", BFF_PROXIES)
def test_bff_proxy_forwards_the_scope(name):
    """The layer in the middle.

    rag-api gained `scope_name` and the frontend started sending it, and the
    BFF proxy between them did not — so the filter was accepted at both ends
    and silently dropped. The panel kept showing 172.18.0.33, a cvebench
    target, under the examplecorp scope, and the endpoint answered identically
    with and without the parameter.

    A proxy that accepts a parameter and does not forward it is the same as not
    having it, and looks exactly like a working filter.
    """
    src = BFF.read_text(encoding="utf-8") if BFF.exists() else pytest.skip("bff router missing")
    fn = next((n for n in ast.walk(ast.parse(src))
               if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef)) and n.name == name), None)
    assert fn, f"{name} not found in the BFF followups router"
    args = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    assert "scope_name" in args, f"{name} does not accept scope_name"
    # It must reach the outgoing params dict, not just the signature.
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Subscript)]
    keys = {n.slice.value for n in assigns
            if isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str)}
    assert "scope_name" in keys, (
        f"{name} accepts scope_name and never puts it in the upstream params — "
        "the filter is dropped in the middle and both ends look correct")


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


def test_group_samples_are_filtered_client_side_too():
    """Belt and braces on the row that leaked.

    `host_samples` render straight from the grouped query. When the scope param
    does not reach the server — an older bundle, a stale query, a caller that
    forgot it — the group header shows hosts the operator's filter excludes.
    That is how `172.18.0.33:9090` appeared under a examplecorp scope while the
    table rows beneath it were correctly filtered.

    Samples can carry a `:port`, so the host must be split out before matching.
    """
    page = _read(PAGE)
    import re
    m = re.search(r"host_samples.*?summary\s*=", page, re.S)
    assert m, "the grouped summary no longer reads host_samples"
    block = m.group(0)
    assert "matchesAnyScope" in block, (
        "group host_samples are rendered unfiltered — the header can show "
        "hosts the table beneath it hides")
    assert "split(':')" in block, (
        "samples carry a :port; without stripping it the match fails and every "
        "sample is hidden instead")


def test_target_board_sends_the_scope_server_side():
    """It had a scope filter and applied it only in the browser."""
    tb = REPO / "dashboard" / "frontend" / "src" / "pages" / "TargetBoard.tsx"
    src = _read(tb)
    import re
    m = re.search(r"useFollowUps\(\{(.*?)\}\)", src, re.S)
    assert m, "useFollowUps not called in TargetBoard"
    assert "scope_name" in m.group(1), (
        "TargetBoard filters client-side only, so pagination drops in-scope "
        "rows before the browser can keep them")


def test_page_passes_the_selected_scope_to_both():
    page = _read(PAGE)
    import re
    for call in ("useFollowUpStats", "useFollowUpGrouped"):
        m = re.search(rf"{call}\(([^)]*)\)", page)
        assert m, f"{call} not called in FollowUps.tsx"
        assert "scopeFilter" in m.group(1), (
            f"{call} is called without scopeFilter — the dropdown changes the "
            "table but not this view")


# ── A scope NAME is not unique, and the panel defaulted to every engagement ──
#
# Reported 2026-10-19: "the follow-up panel engagement scope doesn't seem to
# filter correctly." Two independent causes, both measured on the live DB:
#
#  1. `_scope_inclusion_clause` matched `scope_targets` on NAME ALONE.
#     `unknown_scope` exists under FIVE engagements (`not_in_scope` under two,
#     `default` under two). Filtering follow-ups by `unknown_scope` returned 11
#     rows, of which **10 matched only because another engagement owns a list
#     of that name** — 7 play_demo, 3 cvebench, 1 redteam3.
#  2. The panel's engagement toggle defaulted to OFF, so the unfiltered list was
#     all 5080 rows across 7 engagements (2267 redteam3 / 1933 play_demo /
#     852 cvebench / …) shown under one engagement's header.
#
# NULL-engagement scope rows stay matched on purpose: `not_in_scope` is the
# global deny-list by design and legacy rows predate attribution — the same
# `= %s OR IS NULL` the listing endpoints use.

def test_scope_clauses_take_an_engagement():
    """Both clause builders must accept an engagement to narrow the list."""
    import ast as _ast
    tree = _ast.parse(_read(API))
    fns = {n.name: n for n in tree.body if isinstance(n, _ast.FunctionDef)}
    for name in ("_scope_inclusion_clause", "_scope_exclusion_clause"):
        assert name in fns, f"{name} gone from api.py"
        args = [a.arg for a in fns[name].args.args]
        assert "engagement_id" in args, (
            f"{name} matches scope_targets on NAME ALONE; unknown_scope exists "
            "under five engagements, so every one of them answers at once")


def test_engagement_predicate_keeps_global_rows():
    """The narrowing must keep NULL-engagement rows: `not_in_scope` is the
    cross-engagement deny-list by design, and dropping it would un-hide hosts
    the operator deny-listed."""
    import ast as _ast
    tree = _ast.parse(_read(API))
    fn = [n for n in tree.body
          if isinstance(n, _ast.FunctionDef) and n.name == "_scope_engagement_predicate"]
    assert fn, "_scope_engagement_predicate gone — the two clauses would drift"
    src = _ast.get_source_segment(_read(API), fn[0]) or ""
    assert "st.engagement_id = %s" in src and "st.engagement_id IS NULL" in src, (
        "the predicate must be `= %s OR IS NULL`; equality alone drops the "
        "global deny-list and the legacy pre-attribution rows")
    # No engagement -> no predicate, so an explicit all-engagements view still works.
    assert 'return "", []' in src, "None must append nothing, not match nothing"


def test_all_followup_callsites_pass_the_engagement():
    """Three handlers (list / stats / grouped), each applying both clauses.
    A handler that forgets is a view filtered by somebody else's scope list."""
    import re as _re
    src = _read(API)
    for fname in ("_scope_inclusion_clause", "_scope_exclusion_clause"):
        calls = _re.findall(rf"{fname}\(HOST_EXPR_FOLLOWUP,[^)]*\)", src)
        assert len(calls) == 3, f"expected 3 follow-up call sites of {fname}, found {len(calls)}"
        for c in calls:
            assert "engagement_id" in c, (
                f"{c} does not pass the engagement — this surface matches every "
                "engagement's list of that name")


def test_panel_defaults_to_engagement_only():
    """The read-path rule: a listing under an engagement header is that
    engagement's data unless the operator opts out explicitly."""
    page = _read(PAGE)
    import re as _re
    m = _re.search(r"filterByEngagement, setFilterByEngagement\] = useState\((.*?)\n", page, _re.S)
    assert m, "filterByEngagement state gone from FollowUps.tsx"
    init = m.group(1)
    assert "false)" not in init, (
        "the panel defaults to All Engagements — selecting an engagement then "
        "changes the header and nothing else (5080 rows across 7 engagements)")
    assert "localStorage" in page and "followups.filterByEngagement" in page, (
        "the choice must persist, or a refresh silently widens the view back out")
