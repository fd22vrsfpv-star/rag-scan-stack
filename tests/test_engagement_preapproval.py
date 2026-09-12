"""Pre-approving exploit execution for one engagement.

Run on demand:

    pytest tests/test_engagement_preapproval.py -v

WHY THIS EXISTS
---------------
The exploit gate parks the graph until a human answers, and its docstring said
override flags never apply because the gate IS the operator's authorization. A
run therefore sat `awaiting_approval` indefinitely — and a human may not look
until the next day, by which time the session has been open for hours with its
report unwritten.

The operator's position, which the code now reflects: **selecting pre-approval
for a specific engagement IS that authorization**, given in advance rather than
at the interrupt. That is not an override — it is the same decision, earlier,
and scoped to one named engagement. It is the same reasoning as the standing
rules in `exploit_approval_rules`.

WHAT KEEPS IT HONEST
--------------------
  * **Per engagement, never global.** Enabling it on one leaves the others
    parking exactly as before.
  * **Off unless set.** No default, no inherited value.
  * **Scope is untouched.** `execute_approved_exploit` still fails closed on
    scope, so pre-approval can never make an out-of-scope target runnable. The
    node does not read, relax or mention the scope gate.
  * **Recorded, never silent.** `reviewed_by` names the engagement
    (`engagement_preapproval:<uuid>`), a session message says it happened, and a
    webhook event carries it.
  * **Fails closed.** An unreadable setting parks as usual rather than assuming
    approval.
  * The pending exploit it approves is scoped to the SESSION that queued it, so
    it can never approve another run's exploit.

The toggle is its own endpoint rather than `PUT /engagements/{eid}`, because
that one REPLACES `metadata` wholesale — setting one key through it would
silently drop every other key the engagement holds.

SABOTAGE PROOF
--------------
Make `_engagement_preapproval` return True on exception and
`test_preapproval_fails_closed` fails. Drop `session_id` from the pending-exploit
query and `test_preapproval_only_approves_this_sessions_exploit` fails.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")
API = os.path.join(REPO, "app", "rag-api", "api.py")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


# ── Scoped to one engagement, and off by default ───────────────────────────

def test_preapproval_is_per_engagement():
    fn = _func(_read(ENGINE), "_engagement_preapproval")
    assert fn, "_engagement_preapproval() is gone"
    assert "FROM engagements WHERE id = %s::uuid" in fn, (
        "the lookup is no longer scoped to one engagement — a global switch "
        "would authorise work on engagements nobody approved")
    assert "engagement_id" in fn


def test_preapproval_defaults_off():
    fn = _func(_read(ENGINE), "_engagement_preapproval")
    assert "COALESCE((metadata->>'exploit_preapproved')::boolean, false)" in fn, (
        "the default is no longer false; an engagement with no setting would "
        "inherit approval it never gave")


def test_preapproval_fails_closed():
    """An unreadable setting is not approval."""
    fn = _func(_read(ENGINE), "_engagement_preapproval")
    tail = fn[fn.index("except Exception"):]
    assert "return False, None" in tail, (
        "the error path no longer fails closed — a database hiccup would read "
        "as pre-approval")


# ── It approves the right thing, and says so ───────────────────────────────

def test_preapproval_only_approves_this_sessions_exploit():
    fn = _func(_read(ENGINE), "_pending_exploit_for_session")
    assert fn, "_pending_exploit_for_session() is gone"
    assert "session_id = %s::uuid" in fn, (
        "the pending-exploit lookup is no longer scoped to the session, so a "
        "pre-approved run could approve an exploit some OTHER session queued")
    assert "status = 'pending'" in fn, "it could re-approve an already-decided exploit"


def test_preapproval_is_audited():
    fn = _func(_read(ENGINE), "exploit_approval")
    assert "engagement_preapproval:" in fn, (
        "reviewed_by no longer names the engagement, so an auto-approved "
        "exploit is indistinguishable from a human-approved one")
    assert "langgraph_exploit_preapproved" in fn, "the webhook event is gone"
    assert "_msg(" in fn, "nothing is written to the session transcript"


def _code_only(src: str) -> str:
    """`src` with docstrings removed.

    Searching the raw source matched PROSE, not code: the node's own message
    says "Scope is still enforced", and `enforced` contains `force`; its
    docstring says "`interrupt()` parks the graph", which comes before every
    real statement. Both made this file fail against correct code — the same
    too-literal matching that has bitten twice already in this repo.
    """
    tree = ast.parse(src)
    out = src
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                out = out.replace(doc, "")
    return out


def test_preapproval_does_not_touch_scope():
    """Authorization and scope are different things. This changes only one."""
    fn = _code_only(_func(_read(ENGINE), "exploit_approval"))
    for forbidden in ("scope_gate", "check_dispatch", "is_in_scope"):
        assert not re.search(rf"\b{re.escape(forbidden)}\b", fn), (
            f"exploit_approval references {forbidden!r} — pre-approval must not "
            "read, relax or override the scope gate")


def test_human_gate_still_exists():
    """Without pre-approval the interrupt must still park the graph."""
    fn = _code_only(_func(_read(ENGINE), "exploit_approval"))
    assert "interrupt(" in fn, (
        "the human-in-the-loop interrupt is gone entirely — pre-approval was "
        "meant to be an opt-in for one engagement, not a removal of the gate")
    assert fn.index("_engagement_preapproval") < fn.index("interrupt("), (
        "the pre-approval check must come before the park, or it never skips it")


# ── The toggle ─────────────────────────────────────────────────────────────

def test_toggle_endpoint_merges_metadata():
    """PUT /engagements/{eid} replaces metadata wholesale; this must not."""
    fn = _func(_read(API), "set_exploit_preapproval")
    assert fn, "the pre-approval endpoint is gone"
    assert "||" in fn and "jsonb_build_object" in fn, (
        "the setting no longer MERGES into metadata — it would silently drop "
        "every other key the engagement holds")
    assert "metadata = %s" not in fn


def test_toggle_is_audited_and_reads_back():
    src = _read(API)
    assert _func(src, "get_exploit_preapproval"), "there is no way to read the setting back"
    fn = _func(src, "set_exploit_preapproval")
    assert "emit_webhook" in fn, (
        "changing who can execute exploits without a human emits no event")
    assert "X-Operator" in fn, "the actor who enabled it is not recorded"


def test_toggle_routes_do_not_shadow_the_engagement_route():
    """FastAPI matches in declaration order."""
    src = _read(API)
    order = [m.group(0) for m in re.finditer(
        r'@app\.\w+\("/engagements/\{eid\}[^"]*"', src)]
    pre = [i for i, p in enumerate(order) if "exploit-preapproval" in p]
    assert pre, "the pre-approval routes are gone"
    # They are two-segment paths, so the one-segment /engagements/{eid} cannot
    # swallow them — but a future /engagements/{eid}/{anything} could.
    generic = [i for i, p in enumerate(order)
               if p.endswith('/engagements/{eid}/{') ]
    assert not generic or min(pre) < min(generic), (
        "a catch-all /engagements/{eid}/{...} route is declared before the "
        "pre-approval routes and will shadow them")
