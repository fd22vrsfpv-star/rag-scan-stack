"""A name used but never bound is a runtime-only defect.

THE DEFECT (2026-10-23)
-----------------------
`_known_identities` called `re.findall(...)`. In `app/rag-api/api.py` the bare
name `re` is NEVER BOUND: both module-level imports are aliased —
`import re as _re_module` and `import re as _re_cls` — and the file's prevailing
idiom is a function-local `import re` (116 occurrences). So the call raised
NameError at runtime, inside a broad `except Exception` that logged at debug.

The symptom was three consecutive builds reporting `gather_incomplete:identity`
while the identity tools demonstrably ran and returned `"slug":"admin"`. Every
static check passed: `ast.parse` passed, the module imported, the container was
healthy, and the function's source read correctly. It took running the function
inside the container to see `module 'api' has no attribute 're'`.

This is precisely the class CLAUDE.md already calls out —
"a brace placeholder inside an f-string SQL comment made every recommendations
query raise NameError. ast.parse passed, the module imported, the container was
healthy" — in a different disguise.

    pytest tests/test_unbound_names.py
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = [
    ROOT / "app" / "rag-api" / "api.py",
    ROOT / "app" / "rag-api" / "build_poc_graph.py",
]

# Names commonly used without importing, because another module of the same
# codebase does bind them. Extend deliberately.
WATCHED = ("re", "json", "os", "time", "logging", "base64", "hashlib")


def _module_bound(tree):
    """Names bound at module scope — honouring `as` aliases, which is the trap:
    `import re as _re_module` binds `_re_module`, NOT `re`."""
    bound = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                bound.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                bound.add(a.asname or a.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    bound.add(t.id)
    return bound


def _locally_bound(fn):
    bound = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    for node in ast.walk(fn):
        if isinstance(node, ast.Import):
            for a in node.names:
                bound.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                bound.add(a.asname or a.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    bound.add(t.id)
    return bound


@pytest.mark.parametrize("path", TARGETS, ids=lambda p: p.name)
def test_no_watched_name_is_used_unbound(path):
    if not path.exists():
        pytest.skip(f"{path.name} not present")
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    mod = _module_bound(tree)
    offenders = []
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        local = _locally_bound(fn)
        for node in ast.walk(fn):
            # `re.findall(...)` -> Attribute(value=Name(id='re'))
            if not (isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)):
                continue
            name = node.value.id
            if name in WATCHED and name not in mod and name not in local:
                offenders.append(f"{path.name}:{node.lineno} {fn.name}() uses "
                                 f"`{name}.{node.attr}` but `{name}` is not bound")
    assert not offenders, (
        "name(s) used without being bound — this raises NameError at runtime "
        "and passes every static check:\n  " + "\n  ".join(sorted(set(offenders))))


def test_the_alias_trap_is_what_this_catches():
    """SABOTAGE GUARD for the guard: if `_module_bound` ever credited the
    module name instead of the alias, this check would pass on the very code
    that broke."""
    tree = ast.parse("import re as _re_module\nimport os\n")
    bound = _module_bound(tree)
    assert "os" in bound
    assert "re" not in bound, "an aliased import must NOT bind the bare name"
    assert "_re_module" in bound
