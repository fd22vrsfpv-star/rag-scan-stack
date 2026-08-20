"""Copies of shared modules must not drift from the canonical version.

Run on demand:

    pytest tests/test_shared_code.py -v

WHY THIS EXISTS
---------------
`common/validation.py` holds the input sanitizers — command arguments, output
paths, ports, CIDRs. Seven services carry their own copy of that file because
each has its own Docker build context, and one of them had drifted:
nmap_scanner's `sanitize_command_arg` gained a `max_len` parameter because the
hardcoded 1000-character cap rejected nmap's top-1000 port specification (3,808
characters), which broke scans using that profile.

The fix was correct and stayed in one service for as long as the duplication
lasted. The other six kept the bug. Nobody was wrong at any point — there was
simply no way to notice.

This asserts every copy still matches `common/`. It does NOT argue against the
duplication; it makes the duplication survivable until the copies are replaced
by imports from a mounted `common/` (the pattern `etl/scope_gate.py` now uses).
"""
import ast
import hashlib
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CANONICAL = os.path.join(REPO, "common", "validation.py")

# Every public helper the canonical module exposes.
GUARDED = (
    "sanitize_scan_id", "sanitize_filename", "validate_output_path",
    "sanitize_port", "validate_cidr", "sanitize_url_path", "sanitize_command_arg",
)


def _bodies(path):
    """name -> hash of the function BODY, ignoring comments and docstrings."""
    out = {}
    try:
        tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
    except (OSError, SyntaxError):               # pragma: no cover
        return out
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in GUARDED:
            body = [n for n in node.body
                    if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                            and isinstance(n.value.value, str))]
            dumped = ast.dump(ast.Module(body=body, type_ignores=[]))
            sig = ast.dump(node.args)
            out[node.name] = hashlib.md5((sig + dumped).encode()).hexdigest()[:12]
    return out


def _copies():
    found = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs
                   if d not in ("__pycache__", "node_modules", ".git", "tests")]
        if os.path.realpath(root) == os.path.dirname(CANONICAL):
            continue
        for fn in files:
            if fn == "validation.py":
                found.append(os.path.join(root, fn))
    return found


@pytest.fixture(scope="module")
def canonical():
    if not os.path.exists(CANONICAL):            # pragma: no cover
        pytest.skip("common/validation.py not present")
    b = _bodies(CANONICAL)
    assert b, "canonical module defines none of the guarded functions"
    return b


def test_the_canonical_module_defines_every_guarded_helper(canonical):
    missing = [f for f in GUARDED if f not in canonical]
    assert not missing, f"common/validation.py is missing: {missing}"


def test_copies_were_actually_found():
    """Without this the drift test below passes by finding nothing to compare."""
    copies = _copies()
    assert len(copies) >= 5, (
        f"expected the per-service validation.py copies, found {len(copies)}. "
        "If they were replaced by imports from common/, delete this test — "
        "the duplication it guards is gone.")


@pytest.mark.parametrize("copy_path", _copies(), ids=lambda p: os.path.relpath(p, REPO))
def test_copy_matches_canonical(canonical, copy_path):
    """A copy that lags the canonical version is a bug fix that did not travel.

    Compares signature + body, ignoring docstrings and comments: a reworded
    docstring is not drift, a changed default or an extra parameter is.
    """
    theirs = _bodies(copy_path)
    drifted = [name for name, h in theirs.items()
               if name in canonical and canonical[name] != h]
    missing = [name for name in canonical if name not in theirs]
    rel = os.path.relpath(copy_path, REPO)
    assert not drifted, (
        f"{rel} has diverged from common/validation.py in: {drifted}. "
        f"Port the change into common/validation.py and re-sync every copy — "
        f"these are input sanitizers, so a weaker one here is a real hole.")
    assert not missing, (
        f"{rel} is missing {missing} — it will fall back to whatever the "
        f"importing service defines, or fail at runtime.")
