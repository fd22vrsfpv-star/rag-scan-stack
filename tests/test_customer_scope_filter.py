"""Filtering customer-hosted sites out of Follow-Ups and Software.

Run on demand:

    pytest tests/test_customer_scope_filter.py -v

WHY THIS EXISTS
---------------
`customer_scope` holds hosts the mark-customer-sites flow moved OUT of the
scanned scope: they belong to the engagement's data, but they are the customer's
estate, not ours to test or report on. Nothing could filter on them, and on the
live database they dominate both lists:

    follow_up_items      1310 of 1516  (86%)
    detected_software    3165 of 5572  (57%)

So the operator's two main triage views were mostly other people's hosts.

THE BUG THIS TEST EXISTS TO CATCH
---------------------------------
The exclusion is a `NOT EXISTS` subquery over `scope_targets` — and
`scope_targets` ALSO has a column called `target`. A bare `target` inside that
subquery therefore binds to `scope_targets.target`, NOT to the follow-up's. The
first version compared each scope row against itself, which was true for nearly
every row, and excluded the ENTIRE list: **1516 rows in, 0 out**. It looked like
a working filter until the numbers were checked.

Hence `HOST_EXPR_FOLLOWUP` is qualified as
`followup_target_host(follow_up_items.target)`, and this test pins that.

EXACT MATCH, NOT SUFFIX
-----------------------
customer_scope holds specific hostnames. A dot-boundary suffix match would let
one broad entry (`blackbaud.com`) hide the whole engagement — the same
too-generous-matcher failure as treating a blank scope target as a wildcard.

NOT SILENTLY DROPPED
--------------------
Both toggles default to hiding, and both show the hidden COUNT, because a list
that quietly shrinks by 86% reads as data loss. Stats take the same filter as
the list, or the header contradicts the table beneath it.

SABOTAGE PROOF
--------------
Unqualify `HOST_EXPR_FOLLOWUP` back to `followup_target_host(target)` and
`test_host_expression_is_qualified` fails. Drop `exclude_scope` from
`follow_up_stats` and `test_stats_takes_the_same_filter_as_the_list` fails.
"""
import ast
import os
import re

import pytest

from _container import container_exec

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")
BFF_FU = os.path.join(REPO, "dashboard", "bff", "routers", "followups.py")
BFF_AS = os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")
UI_FU = os.path.join(REPO, "dashboard", "frontend", "src", "pages", "FollowUps.tsx")
UI_AB = os.path.join(REPO, "dashboard", "frontend", "src", "pages", "AssetBrowser.tsx")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func_source(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


# ── The trap ───────────────────────────────────────────────────────────────

def test_host_expression_is_qualified():
    """THE bug. scope_targets.target would shadow the outer column."""
    src = _read(API)
    m = re.search(r'HOST_EXPR_FOLLOWUP\s*=\s*"([^"]+)"', src)
    assert m, "HOST_EXPR_FOLLOWUP is gone"
    assert m.group(1) == "followup_target_host(follow_up_items.target)", (
        f"the host expression is {m.group(1)!r}. Unqualified, the bare `target` "
        "inside the NOT EXISTS binds to scope_targets.target and the filter "
        "excludes EVERY row (1516 in, 0 out)")


def test_exclusion_is_exact_not_suffix():
    """A suffix match would let one broad entry hide the whole engagement."""
    fn = _func_source(_read(API), "_scope_exclusion_clause")
    assert fn, "_scope_exclusion_clause() is gone"
    assert "lower(st.target) = " in fn, "the match is no longer exact equality"
    assert "LIKE" not in fn.upper(), (
        "the exclusion grew a LIKE — a suffix match on customer_scope can hide "
        "an entire engagement from one broad entry")


def test_blank_scope_targets_are_ignored():
    fn = _func_source(_read(API), "_scope_exclusion_clause")
    assert "st.target <> ''" in fn, (
        "blank scope targets are no longer skipped; they would match nothing "
        "useful and only add rows to the subquery")


def test_no_exclusion_means_no_clause():
    """Callers append unconditionally, so an empty filter must be a no-op."""
    fn = _func_source(_read(API), "_scope_exclusion_clause")
    assert 'return "", []' in fn, (
        "the empty case must return an empty fragment, or every unfiltered "
        "query gets a stray WHERE")


# ── Every layer carries the parameter ──────────────────────────────────────

@pytest.mark.parametrize("fn_name", [
    "list_follow_ups", "follow_up_stats", "follow_ups_grouped", "get_detected_software"])
def test_rag_api_endpoints_accept_it(fn_name):
    fn = _func_source(_read(API), fn_name)
    assert fn, f"{fn_name}() is gone"
    assert "exclude_scope" in fn, f"{fn_name} no longer accepts exclude_scope"


def test_stats_takes_the_same_filter_as_the_list():
    """A header counting rows the table refuses to show contradicts it."""
    fn = _func_source(_read(API), "follow_up_stats")
    assert "_scope_exclusion_clause" in fn, (
        "stats no longer applies the exclusion, so the counts will disagree "
        "with the list under them")


@pytest.mark.parametrize("path,fn_name", [
    (BFF_FU, "list_follow_ups"), (BFF_FU, "follow_up_stats"),
    (BFF_FU, "follow_ups_grouped"), (BFF_AS, "detected_software")])
def test_bff_forwards_it(path, fn_name):
    fn = _func_source(_read(path), fn_name)
    assert fn, f"{fn_name}() is gone from the BFF"
    assert "exclude_scope" in fn, f"the BFF drops exclude_scope in {fn_name}"


# ── The UI labels what it hides ────────────────────────────────────────────

@pytest.mark.parametrize("path,flag", [
    (UI_FU, "hideCustomerHosted"), (UI_AB, "hideCustomerHostedSw")])
def test_ui_has_the_toggle(path, flag):
    src = _read(path)
    assert flag in src, f"{flag} toggle is gone"
    assert "customer_scope" in src, "the UI no longer names the scope list it excludes"


@pytest.mark.parametrize("path", [UI_FU, UI_AB])
def test_ui_reports_the_hidden_count(path):
    """Hiding 86% of a list without saying so reads as data loss."""
    src = _read(path)
    assert "Customer-hosted hidden" in src, (
        "the toggle no longer reports what it is hiding")
    assert "hidden > 0" in src, (
        "the hidden COUNT is gone; the operator cannot tell how much is filtered")


# ── Live ───────────────────────────────────────────────────────────────────

_LIVE = r"""
import json, os, urllib3, requests
urllib3.disable_warnings()
H = {"x-api-key": os.environ.get("API_KEY", "changeme")}
B = "https://localhost:8000"
out = {}
r = requests.get(f"{B}/follow-ups", params={"limit": 10000}, headers=H, verify=False, timeout=60)
out["fu_all"] = len(r.json().get("follow_ups", [])) if r.ok else None
r = requests.get(f"{B}/follow-ups", params={"limit": 10000, "exclude_scope": "customer_scope"},
                 headers=H, verify=False, timeout=60)
out["fu_filtered"] = len(r.json().get("follow_ups", [])) if r.ok else None
r = requests.get(f"{B}/follow-ups/stats", params={"exclude_scope": "customer_scope"},
                 headers=H, verify=False, timeout=60)
# The endpoint returns {"stats": {...}}, not a bare total.
out["stats_filtered_total"] = (r.json().get("stats") or {}).get("total") if r.ok else None
r = requests.get(f"{B}/software", params={"limit": 10000}, headers=H, verify=False, timeout=60)
out["sw_all"] = len(r.json().get("items", [])) if r.ok else None
r = requests.get(f"{B}/software", params={"limit": 10000, "exclude_scope": "customer_scope"},
                 headers=H, verify=False, timeout=60)
out["sw_filtered"] = len(r.json().get("items", [])) if r.ok else None
# A scope list that does not exist must exclude NOTHING, not everything.
r = requests.get(f"{B}/follow-ups", params={"limit": 10000, "exclude_scope": "no_such_scope_xyz"},
                 headers=H, verify=False, timeout=60)
out["fu_bogus_scope"] = len(r.json().get("follow_ups", [])) if r.ok else None
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def live():
    out = container_exec(_LIVE, timeout=240)
    if out is None:
        pytest.skip("rag-api container unreachable")
    if out.startswith("__ERR__"):
        pytest.fail(f"scope-filter round-trip failed: {out}")
    import json
    return json.loads(out.strip().splitlines()[-1])


def test_filter_removes_some_but_not_all(live):
    """The original bug returned 0. Zero is the failure mode, not success."""
    assert live["fu_all"] > 0, "no follow-ups at all — cannot judge the filter"
    assert live["fu_filtered"] > 0, (
        "the filter excluded EVERY follow-up. That is the unqualified-column "
        "bug: `target` inside the NOT EXISTS bound to scope_targets.target")
    assert live["fu_filtered"] < live["fu_all"], (
        "the filter excluded nothing — it is not being applied")


def test_stats_agree_with_the_filtered_list(live):
    assert live["stats_filtered_total"] == live["fu_filtered"], (
        f"stats say {live['stats_filtered_total']} but the list returns "
        f"{live['fu_filtered']} — the header contradicts the table")


def test_software_filter_applies(live):
    assert live["sw_all"] > 0
    assert 0 < live["sw_filtered"] < live["sw_all"], (
        "the software exclusion either did nothing or removed everything")


def test_unknown_scope_name_excludes_nothing(live):
    """Fail OPEN here: an unrecognised list name must not hide the operator's
    work. Excluding on a typo would silently empty the view."""
    assert live["fu_bogus_scope"] == live["fu_all"], (
        "an unknown scope name changed the result set; a typo would silently "
        "hide findings")
