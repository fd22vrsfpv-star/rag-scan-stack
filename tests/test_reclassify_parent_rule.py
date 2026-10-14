"""Parent protection must block a LIVE subtree's apex, not every parent.

The rule exists for one incident: relocating `examplecorp.com` and `legacycorp.net`
split their scopes and took live hosts with them. The guard written for it
skipped any candidate that another scope entry sat under — which, on redteam3,
blocked **all 49 candidates**:

    candidates: 49 | would_move: 0 | skipped as parents: 49

Every one. And they were not apexes in any meaningful sense:

    keys3.examplecorp.com      parent of  www.keys3.examplecorp.com        (also dead)
    education.examplecorp.com  parent of  www.education.examplecorp.com    (also dead)
    hi.examplecorp.com         parent of  cpanel/cpcalendars/cpcontacts/
                                        mail/webdisk/webmail           (all dead)

Filing a dead host whose whole subtree is dead splits nothing. So the skip now
applies only when a child is NOT itself being filed — still listening, or never
evaluated. Both are reasons to leave the parent alone; neither describes a
subtree that is uniformly dead.

Static (`ast`) — the judgement has to be visible in the code, because the
alternative is a guard that silently files nothing.

Sabotage check: restore the unconditional `endswith` skip and
`test_a_uniformly_dead_subtree_does_not_block_its_parent` fails.

    pytest tests/test_reclassify_parent_rule.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"


def _handler() -> ast.FunctionDef:
    if not API.exists():
        pytest.skip(f"{API} not found")
    fn = next((n for n in ast.walk(ast.parse(API.read_text(encoding="utf-8")))
               if isinstance(n, ast.FunctionDef)
               and n.name == "reclassify_engagement_scope"), None)
    assert fn, "reclassify_engagement_scope not found"
    return fn


def _child_test() -> ast.expr:
    """The comprehension that decides whether a child blocks its parent."""
    for node in ast.walk(_handler()):
        if not isinstance(node, ast.ListComp):
            continue
        src = ast.dump(node)
        if "endswith" in src:
            return node
    pytest.fail("no child-of-this-host comprehension found — the parent rule "
                "has moved and this guard is blind")


def test_a_uniformly_dead_subtree_does_not_block_its_parent():
    """The child must be checked against the set being filed."""
    comp = _child_test()
    names = {n.id for n in ast.walk(comp) if isinstance(n, ast.Name)}
    assert "verdicts" in names, (
        "the parent rule does not consult the set of hosts being filed, so a "
        "parent whose children are ALL dead is still skipped — which blocked "
        "every candidate on redteam3")
    # and it must be an exclusion: child NOT in verdicts
    assert any(isinstance(n, ast.NotIn) for n in ast.walk(comp)), (
        "the child test is not an exclusion — it should block only on children "
        "that are NOT themselves being filed")


def test_it_still_blocks_a_live_child():
    """Narrowing must not delete the protection."""
    comp = _child_test()
    src = ast.dump(comp)
    assert "endswith" in src, (
        "the subtree check is gone entirely — a live subtree's apex could be "
        "relocated again, which is the incident this rule exists for")


def test_verdicts_are_decided_before_the_parent_check():
    """One pass cannot know whether a child is dead; two can."""
    fn = _handler()
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "verdicts" for t in n.targets)]
    assert assigns, "no `verdicts` map is built — the parent rule cannot be correct"
    first_assign = min(a.lineno for a in assigns)
    assert first_assign < _child_test().lineno, (
        "the parent check runs before every host has been judged, so it cannot "
        "tell a dead child from an unevaluated one")
