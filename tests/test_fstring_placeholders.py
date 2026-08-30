"""Guard against f-string placeholders that are not real variables.

Run on demand:

    pytest tests/test_fstring_placeholders.py -v

WHY THIS EXISTS
---------------
A SQL query in scan_recommender.py is built with an f-string. A comment added
inside it mentioned the template placeholders it was describing:

    -- r.script is the recommender's TEMPLATE and still holds
    -- {target}/{port}, so showing it ...

Python evaluated `{target}` as an expression. Every call to the listing query
then raised `name 'target' is not defined`, the endpoint swallowed it, and the
Recommendations page silently returned ZERO rows — a total outage of that view
from a change to a comment.

Nothing caught it:
  * `ast.parse` passes — the file is syntactically valid.
  * Import succeeds — f-strings are only evaluated when the function RUNS.
  * The unit tests for that module cover pure helpers and never execute the
    query, so the suite stayed green.

This test walks every f-string and asserts each `{name}` refers to something
actually bound in scope, which is precisely the check that was missing.
"""
import ast
import builtins
import os

import pytest

REPO = os.path.join(os.path.dirname(__file__), "..")

# Modules that build SQL or shell strings with f-strings. These are the files
# where a stray brace takes out a live endpoint rather than merely printing oddly.
TARGETS = [
    "scan_recommender/scan_recommender.py",
    "app/rag-api/api.py",
    "app/rag-api/artifact_actions.py",
    "dashboard/bff/routers/assets.py",
    "dashboard/bff/routers/artifacts.py",
    "dashboard/bff/routers/scans.py",
    "kali_listener/listener_service.py",
    "etl/parse_tool_output.py",
    "web_scanner/web_scan.py",
]

_BUILTINS = set(dir(builtins))


def _bound_names(node) -> set:
    """Every name bound anywhere inside a function body.

    Deliberately over-inclusive (it does not model execution order or nested
    scopes precisely): the goal is to flag names that exist NOWHERE, which is
    what a mistyped or accidental placeholder looks like. Being generous here
    keeps the test free of false positives on real code.
    """
    names = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        a = node.args
        for arg in list(a.args) + list(a.posonlyargs) + list(a.kwonlyargs):
            names.add(arg.arg)
        if a.vararg:
            names.add(a.vararg.arg)
        if a.kwarg:
            names.add(a.kwarg.arg)
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            names.add(child.id)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(child, (ast.Global, ast.Nonlocal)):
            names.update(child.names)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(child.name)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            names.add(child.name)
    return names


def _module_names(tree) -> set:
    """Names bound at TRUE module level.

    This used to ast.walk() the whole tree and collect every Store name it
    found, including ones local to unrelated functions. In a 20,000-line module
    like app/rag-api/api.py that whitelists nearly every short identifier for
    every f-string in the file, which made the guard close to vacuous there.

    It missed a real one: a SQL comment inside an f-string mentioning
    /scope/{name}/analysis raised NameError on every call, and the test stayed
    green because some unrelated function had a `for name in ...` loop.

    So: do not descend into function or class bodies. Those bindings are not
    module-level names, and _bound_names() already supplies them per-function.
    """
    names = set()

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(child.name)
                continue  # its body is a separate scope
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                names.add(child.id)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    names.add((alias.asname or alias.name).split(".")[0])
            elif isinstance(child, ast.Global):
                names.update(child.names)
            visit(child)

    visit(tree)
    return names


def _undefined_placeholders(path: str):
    """Return [(line, name)] for f-string placeholders bound nowhere."""
    with open(path) as fh:
        src = fh.read()
    tree = ast.parse(src)
    module_names = _module_names(tree) | _BUILTINS

    # Map each f-string to the innermost function that contains it, so the
    # check uses that function's own bindings.
    scopes = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append((node.lineno, getattr(node, "end_lineno", node.lineno),
                           _bound_names(node)))

    problems = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for part in node.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            if not isinstance(part.value, ast.Name):
                continue  # attribute/call expressions are out of scope here
            name = part.value.id
            line = getattr(part.value, "lineno", node.lineno)
            visible = set(module_names)
            for start, end, bound in scopes:
                if start <= line <= end:
                    visible |= bound
            if name not in visible:
                problems.append((line, name))
    return problems


@pytest.mark.parametrize("rel", TARGETS)
def test_no_undefined_fstring_placeholders(rel):
    """Every {name} in an f-string must be a real variable.

    A placeholder that is not bound anywhere raises NameError the moment the
    line executes — which, for a query built once per request, means the
    endpoint fails for every caller while the module still imports cleanly.
    """
    path = os.path.join(REPO, rel)
    if not os.path.exists(path):                 # pragma: no cover
        pytest.skip(f"{rel} not present")
    problems = _undefined_placeholders(path)
    assert not problems, (
        f"{rel} has f-string placeholders bound nowhere: "
        + ", ".join(f"line {ln}: {{{n}}}" for ln, n in problems)
        + ". If this is documentation text, escape the braces ({{...}}) or "
          "reword it — Python evaluates them at runtime."
    )


def test_the_guard_actually_catches_the_real_regression(tmp_path):
    """Sabotage check: reproduce the exact bug and confirm this test fails.

    A guard that cannot fail is worse than none, so this reconstructs the
    original defect — a brace placeholder inside a SQL comment in an f-string.
    """
    bad = tmp_path / "bad.py"
    bad.write_text(
        "def list_recommendations(where):\n"
        "    return f'''\n"
        "        SELECT id\n"
        "          -- script still holds {target}/{port}\n"
        "          FROM scan_recommendations {where}\n"
        "    '''\n"
    )
    problems = _undefined_placeholders(str(bad))
    found = {n for _, n in problems}
    assert "target" in found and "port" in found, f"guard missed the bug: {problems}"
    # ...and must not flag the legitimate interpolation next to it.
    assert "where" not in found, "guard flagged a real variable"
