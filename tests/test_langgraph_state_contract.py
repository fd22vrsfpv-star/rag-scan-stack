"""Every key a node returns must be declared on BuildPocState.

LangGraph propagates state ONLY through the dict a node returns, and it DROPS
a returned key that the state schema does not declare — silently. No error, no
warning. Verified against the installed langgraph on 2026-10-15:

    node returns {"declared": ..., "undeclared": ...}
    final keys : ['declared']
    undeclared survived to the END?: False

Two ways to lose data, both of which look like working code:

  1. RETURNING AN UNDECLARED KEY. `node_post_run_review` returned
     {"review": review} with no `review` field on BuildPocState. It was
     dropped on every run. Nothing read it, so nothing broke — but the next
     reader would get None with no indication why.

  2. MUTATING `state[...]`. A node's assignment to the state it was handed
     does not propagate; only the return does. The known_good wiring was
     written this way first and would have made synthesis never see the
     result, while the code read as though it did.

This guard is the automated version of an analysis that had to be run three
times by hand before it was right: the first pass missed `upd = {...}; return
upd` and reported 12 phantom violations, the second missed
`upd: Dict[str, Any] = {...}` (an AnnAssign, not an Assign) and reported 21
phantom dead fields. Both write patterns are covered below. If a node ever
writes state through a helper or `dict(**x)`, this will not see it — the
guard is only as good as the patterns it knows, and that is worth remembering
before trusting a clean run.

Sabotage check: return an undeclared key from any node and
`test_every_returned_key_is_declared` fails by node and key; assign to
`state["x"]` in a node and `test_no_node_mutates_state` fails.

    pytest tests/test_langgraph_state_contract.py -q
"""

import ast
import collections
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"
STATE_CLASS = "BuildPocState"


def _tree() -> ast.Module:
    if not GRAPH.exists():
        pytest.skip("build_poc_graph.py not found")
    return ast.parse(GRAPH.read_text(encoding="utf-8"))


def _declared() -> set:
    for cls in ast.walk(_tree()):
        if isinstance(cls, ast.ClassDef) and cls.name == STATE_CLASS:
            return {n.target.id for n in cls.body
                    if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)}
    pytest.fail(f"{STATE_CLASS} is not defined")


def _nodes() -> list:
    return [n for n in _tree().body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("node_")]


def _dict_keys(d: ast.Dict) -> set:
    return {k.value for k in d.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)}


def _returned_keys(fn) -> set:
    """Keys a node actually propagates, across every write pattern used here.

    Both `x = {...}` and `x: Dict[str, Any] = {...}` must be handled; missing
    the annotated form is what made an earlier hand analysis report 21 dead
    fields that were all written.
    """
    out = set()
    ret_names = {n.value.id for n in ast.walk(fn)
                 if isinstance(n, ast.Return) and isinstance(n.value, ast.Name)}
    for n in ast.walk(fn):
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict):
            out |= _dict_keys(n.value)
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            if isinstance(n.value, ast.Dict):
                for t in targets:
                    if isinstance(t, ast.Name) and t.id in ret_names:
                        out |= _dict_keys(n.value)
            for t in targets:
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) \
                   and isinstance(t.slice, ast.Constant) \
                   and isinstance(t.slice.value, str) \
                   and t.value.id in ret_names:
                    out.add(t.slice.value)
    return out


def test_the_state_class_exists_and_is_populated():
    d = _declared()
    assert len(d) > 20, f"{STATE_CLASS} declares only {len(d)} fields"


def test_there_are_nodes_to_check():
    """A guard that finds nothing to inspect is not a guard."""
    assert len(_nodes()) > 10, (
        f"only {len(_nodes())} graph nodes found — the naming convention "
        "changed and this guard is now inspecting almost nothing")


def test_every_returned_key_is_declared():
    """THE check. An undeclared key is dropped silently."""
    declared = _declared()
    offenders = collections.defaultdict(list)
    for fn in _nodes():
        for key in _returned_keys(fn) - declared:
            offenders[key].append(fn.name)
    assert not offenders, (
        "these keys are returned by a node but NOT declared on "
        f"{STATE_CLASS}, so LangGraph drops them silently — no error, no "
        "warning, the value simply never reaches the next node:\n  "
        + "\n  ".join(f"{k!r} returned by {sorted(v)}" for k, v in sorted(offenders.items()))
        + f"\nAdd the field to {STATE_CLASS}.")


def test_no_node_mutates_state():
    """`state[...] = x` inside a node does not propagate."""
    offenders = []
    for fn in _nodes():
        for n in ast.walk(fn):
            if not isinstance(n, (ast.Assign, ast.AnnAssign)):
                continue
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) \
                   and t.value.id == "state":
                    key = (t.slice.value if isinstance(t.slice, ast.Constant) else "?")
                    offenders.append(f"{fn.name} sets state[{key!r}] at line {n.lineno}")
    assert not offenders, (
        "a LangGraph node propagates its changes ONLY through the dict it "
        "returns; assigning into the state it was handed is silently "
        "discarded, and the code reads as though it worked:\n  "
        + "\n  ".join(offenders))


def test_declared_fields_are_either_an_input_or_written():
    """A field nothing ever sets is dead weight that reads as plumbing."""
    tree = _tree()
    init = next((n for n in tree.body
                 if isinstance(n, ast.FunctionDef) and n.name == "initial_state"), None)
    if init is None:
        pytest.skip("initial_state() not found")
    inputs = set()
    for n in ast.walk(init):
        if isinstance(n, ast.Dict):
            inputs |= _dict_keys(n)
    written = set()
    for fn in _nodes():
        written |= _returned_keys(fn)
    dead = sorted(_declared() - inputs - written)
    assert not dead, (
        f"these {STATE_CLASS} fields are neither set by initial_state() nor "
        f"returned by any node, so they are always absent: {dead}")
