"""A missing dependency must SKIP the module, never abort the run.

Run on demand:

    pytest tests/test_collection_never_errors.py -v

WHY THIS EXISTS
---------------
Seven test modules imported a third-party package at module level with no guard.
On a runner without that package pytest raises during COLLECTION, and a
collection error does not fail one module — it **interrupts the entire run**:

    15 skipped, 5 errors in 0.63s
    !!!!!! Interrupted: 5 errors during collection !!!!!!

Two thousand tests produced no signal because four of them could not be
imported. Worse, the failure looked like breakage rather than like a runner that
was simply missing `yaml`, so the honest reading — "cannot run here" — was
unavailable. CLAUDE.md: a skip says "cannot run here"; an error says "broken",
and mixing them hides real breakage.

One of the seven had the comment ``# (optional; guarded below)`` on an import
that was not guarded at all, and lost nine passing tests that needed nothing
from the package in question.

THE CONTRACT
------------
`tests/requirements.txt` is the boundary. A package listed there may be imported
bare — CI installs it, and its absence is a broken environment worth failing on.
Anything else MUST be guarded:

  * `pytest.importorskip("pkg")` before the import, or
  * the import inside a `try:` that skips on ModuleNotFoundError.

Repo-local modules are exempt: their absence is a real defect and must fail
loudly, which is why the guarded modules check that the file EXISTS before
treating an import error as a missing dependency.

SABOTAGE PROOF
--------------
Add a bare `import msgpack` at the top of any test module and this fails by
name. Remove the `importorskip` from `tests/test_msf_token_refresh.py` and it
fails the same way.
"""
import ast
import os
import re
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
TESTS = os.path.join(REPO, "tests")
REQUIREMENTS = os.path.join(TESTS, "requirements.txt")

# Distribution name on PyPI -> the name you actually import.
_ALIAS = {"psycopg2-binary": "psycopg2", "pyyaml": "yaml",
          "beautifulsoup4": "bs4", "pytest-asyncio": "pytest_asyncio"}


def _declared():
    """Packages tests/requirements.txt promises will be installed."""
    if not os.path.exists(REQUIREMENTS):
        pytest.skip("tests/requirements.txt not present")
    out = set()
    with open(REQUIREMENTS, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#")[0].strip()
            if line:
                dist = re.split(r"[<>=\[]", line)[0].strip().lower()
                out.add(_ALIAS.get(dist, dist).replace("-", "_"))
    return out


def _repo_modules():
    """Every name importable from the checkout — a file or a directory.

    Deliberately broad. A false "this is local" only weakens the guard for that
    one name, while a false "this is third-party" would fail the suite over a
    module that is right there in the tree, and a guard that cries wolf gets
    deleted.
    """
    names = set()
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs
                   if not d.startswith(".") and d not in ("__pycache__", "node_modules")]
        names.update(f[:-3] for f in files if f.endswith(".py"))
        names.update(d.replace("-", "_") for d in dirs)
    return names


def _guarded_names(tree):
    """Packages named by a module-level `pytest.importorskip("pkg")`.

    Read from the AST, never from the source text. A regex over raw source
    counts a COMMENTED-OUT importorskip as a guard — which it is not, and which
    is exactly how the first version of this test passed its own sabotage. Three
    guards in this repo have now been fooled by matching prose instead of code.
    """
    names = set()
    for node in tree.body:
        call = None
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
        if call is None:
            continue
        fn = call.func
        named = (getattr(fn, "attr", None) == "importorskip"
                 or getattr(fn, "id", None) == "importorskip")
        if named and call.args and isinstance(call.args[0], ast.Constant) \
                and isinstance(call.args[0].value, str):
            names.add(call.args[0].value.split(".")[0])
    return names


def _unguarded(path, allowed):
    """Third-party names imported at module level with nothing to catch them."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    try:
        tree = ast.parse(src)
    except SyntaxError as e:  # a broken test file is a different failure
        pytest.fail(f"{os.path.basename(path)} does not parse: {e}")
    guarded = _guarded_names(tree)
    bad = set()
    # Only `tree.body` — a module-level statement. An import nested in a `try`,
    # a function or a fixture is already guarded by construction.
    for node in tree.body:
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module.split(".")[0]]
        else:
            continue
        bad.update(n for n in names if n not in allowed and n not in guarded)
    return bad


def test_no_test_module_can_abort_collection():
    allowed = set(sys.stdlib_module_names) | _declared() | _repo_modules()
    offenders = {}
    for fn in sorted(os.listdir(TESTS)):
        if fn.endswith(".py"):
            bad = _unguarded(os.path.join(TESTS, fn), allowed)
            if bad:
                offenders[fn] = sorted(bad)
    assert not offenders, (
        "these modules import an undeclared third-party package at module "
        f"level: {offenders}\n"
        "On a runner without it pytest raises during COLLECTION, which does not "
        "fail one module — it interrupts the WHOLE run, and ~2000 tests report "
        "nothing. Either add the package to tests/requirements.txt, or guard "
        "the import with pytest.importorskip(...) so the module skips instead.")


def test_the_requirements_file_is_the_contract():
    """The guard is only meaningful while requirements.txt still declares the
    packages CI installs. An empty or unreadable file would make every bare
    import look like a violation, or none of them."""
    declared = _declared()
    for essential in ("pytest", "psycopg2", "yaml", "requests"):
        assert essential in declared, (
            f"{essential} is no longer declared in tests/requirements.txt, so "
            "this guard's notion of 'may be imported bare' has drifted from "
            "what CI actually installs")


def test_the_guard_would_notice_a_bare_import(tmp_path):
    """Sabotage proof, in-process: the analyser must flag exactly the shape it
    exists to catch, and must not flag the guarded form of the same import."""
    allowed = set(sys.stdlib_module_names) | _declared() | _repo_modules()

    bare = tmp_path / "test_bare.py"
    bare.write_text("import msgpack\n\n\ndef test_x():\n    assert msgpack\n")
    assert _unguarded(str(bare), allowed) == {"msgpack"}

    guarded = tmp_path / "test_guarded.py"
    guarded.write_text('import pytest\n'
                       'pytest.importorskip("msgpack")\n'
                       'import msgpack\n\n\ndef test_x():\n    assert msgpack\n')
    assert _unguarded(str(guarded), allowed) == set()

    # The shape that fooled the first version of this analyser: the guard is
    # still there in the TEXT, commented out, and does nothing.
    commented = tmp_path / "test_commented.py"
    commented.write_text('import pytest\n'
                         '# pytest.importorskip("msgpack")\n'
                         'import msgpack\n\n\ndef test_x():\n    assert msgpack\n')
    assert _unguarded(str(commented), allowed) == {"msgpack"}, (
        "a commented-out importorskip is being counted as a guard")
