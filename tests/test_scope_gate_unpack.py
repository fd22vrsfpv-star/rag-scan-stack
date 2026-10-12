"""`load_dispatch_scope` returns (rows, source) — every caller must unpack it.

Assigning the whole 2-tuple breaks two things at once, and neither is obvious:

  * `is_in_scope(host, scope_rows)` then iterates over `[rows_list, source_str]`
    and raises `ValueError: too many values to unpack (expected 2)`. That is
    what killed a masscan->nmap run before it scanned anything —
    `app/run_masscan_nmap.py` was the one site of 29 that got it wrong.
  * The `if not scope_rows: refuse` guard below such a call is DEAD, because a
    2-tuple is always truthy. The fail-closed check silently stops checking.

A static guard is the right shape here: the failure is a plain unpacking
mistake that `ast.parse` accepts, the module imports fine, and it only raises
when that scan path actually executes.

*Enforced by:* this file.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))

#: Call sites that legitimately keep the pair intact — they pass it straight
#: through to their own caller, who unpacks. Each must stay a bare `return`.
PASSTHROUGH = {
    os.path.join("dashboard", "bff", "scope_guard.py"),
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv"}


def _py_files():
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs
                   if d not in SKIP_DIRS and not d.startswith("run_archive")]
        for fn in files:
            if fn.endswith(".py"):
                yield os.path.join(root, fn)


def _calls(tree):
    """Every Call node whose func is named load_dispatch_scope."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = (f.id if isinstance(f, ast.Name)
                    else f.attr if isinstance(f, ast.Attribute) else None)
            if name == "load_dispatch_scope":
                yield node


def test_every_caller_unpacks_the_pair():
    """A single-name assignment binds (rows, source), not the rows."""
    bad = []
    for path in _py_files():
        rel = os.path.relpath(path, REPO)
        try:
            tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
        except SyntaxError:
            continue
        call_lines = {c.lineno for c in _calls(tree)}
        if not call_lines:
            continue
        for node in ast.walk(tree):
            # Assignment: must be a tuple target (rows, source = ...)
            if isinstance(node, ast.Assign) and node.value.lineno in call_lines:
                if not any(isinstance(c, ast.Call) for c in ast.walk(node.value)):
                    continue
                tgt = node.targets[0]
                if not isinstance(tgt, (ast.Tuple, ast.List)):
                    bad.append(f"{rel}:{node.lineno} assigns the (rows, source) "
                               f"pair to a single name")
            # Return: only the declared pass-through may hand the pair onward.
            if isinstance(node, ast.Return) and node.value is not None \
                    and node.value.lineno in call_lines \
                    and isinstance(node.value, ast.Call) \
                    and rel not in PASSTHROUGH:
                bad.append(f"{rel}:{node.lineno} returns the (rows, source) pair "
                           f"without unpacking; add it to PASSTHROUGH if the "
                           f"caller unpacks")
    assert not bad, (
        "load_dispatch_scope returns (rows, source). These sites treat it as "
        "the rows list — is_in_scope will raise 'too many values to unpack' and "
        "any `if not scope_rows` guard beside them is dead (a tuple is always "
        "truthy):\n  " + "\n  ".join(sorted(bad))
    )


def test_passthrough_entries_still_exist():
    """A stale exemption must not rot."""
    missing = [p for p in PASSTHROUGH if not os.path.exists(os.path.join(REPO, p))]
    assert not missing, f"PASSTHROUGH names files that no longer exist: {missing}"


def test_harness_actually_finds_call_sites():
    """The guard must be looking at real code, not quietly matching nothing."""
    found = 0
    for path in _py_files():
        try:
            tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
        except SyntaxError:
            continue
        found += sum(1 for _ in _calls(tree))
    assert found >= 10, (
        f"only {found} load_dispatch_scope call sites found; the scan is not "
        "reaching the codebase")


def test_is_in_scope_still_expects_pairs():
    """The guard's premise: is_in_scope unpacks each row into two names."""
    gate = os.path.join(REPO, "etl", "scope_gate.py")
    if not os.path.exists(gate):
        pytest.skip("scope_gate.py not present")
    src = open(gate, encoding="utf-8").read()
    assert "for target, ttype in scope_rows" in src, (
        "is_in_scope no longer unpacks rows as (target, ttype); re-check what "
        "callers must pass before trusting this guard")
