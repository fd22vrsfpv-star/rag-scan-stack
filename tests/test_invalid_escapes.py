"""No module may carry an invalid escape sequence.

`"\\d"` inside a non-raw Python string is not an error today — Python leaves an
unrecognised escape as a literal backslash plus the character, so the SQL regex
`'://[^/:]+:(\\d+)'` reaches Postgres intact and the query works. That is exactly
what makes it dangerous: it is a SyntaxWarning that every static check passes,
the container reports healthy, and the suite is green.

It is scheduled to become a SyntaxError. When it does, the module stops
importing — not the line, the whole module — and in this repo that is `api.py`,
the service. The failure arrives on a Python upgrade, far from the commit that
wrote the escape, and the traceback points at a SQL string nobody has touched
in months.

This is the same shape as the f-string placeholder bug `test_fstring_placeholders.py`
exists for (CLAUDE.md, "Tests"): a runtime-only defect that `ast.parse` accepts.
`compile()` is what surfaces it, because warnings are raised during code
generation rather than parsing.

Two were found when this guard was written, both SQL regexes:
  app/rag-api/api.py:7294                      '://[^/:]+:(\\d+)'   -> '\\\\d'
  scripts/optional/create_software_view.py:8   the whole VIEW_SQL   -> r\"\"\"

The fix is `\\\\d` for a single escape, or a raw string when the literal is full
of them. Both are no-ops at runtime, which is why this costs nothing to keep at
zero.

    pytest tests/test_invalid_escapes.py
"""
from __future__ import annotations

import pathlib
import warnings

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

# Directories that are not ours to fix: vendored code, virtualenvs, caches, and
# the Strix clone kept at /opt/strix for comparison (see Docs/Memories.md).
SKIP_PARTS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "site-packages", "strix", ".mypy_cache", ".pytest_cache", "build", "dist",
}

# Files that legitimately carry one, each with a reason. Keep this EMPTY.
# An entry here is debt: it ratchets, so a new offender fails by name.
ESCAPE_DEBT: dict[str, str] = {}


def _python_files():
    for p in sorted(REPO.rglob("*.py")):
        if any(part in SKIP_PARTS for part in p.parts):
            continue
        yield p


def _offenders():
    """(relative path, lineno, message) for every invalid escape sequence.

    Compiles rather than parses: `ast.parse` does not run code generation, and
    the warning is emitted there. A file that will not compile at all is NOT
    this guard's business — a real SyntaxError belongs to whatever test imports
    that module, and swallowing it here would hide it.
    """
    out = []
    for p in _python_files():
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                compile(src, str(p), "exec")
            except SyntaxError:
                continue
            except ValueError:
                # e.g. source containing a null byte
                continue
        for w in caught:
            if "invalid escape sequence" in str(w.message):
                out.append((p.relative_to(REPO).as_posix(), w.lineno, str(w.message)))
    return out


def test_no_invalid_escape_sequences():
    found = _offenders()
    undeclared = [f for f in found if f[0] not in ESCAPE_DEBT]
    assert not undeclared, (
        "invalid escape sequence(s) — these are SyntaxWarnings today and "
        "SyntaxErrors in a future Python, at which point the whole module "
        "stops importing:\n"
        + "\n".join(f"  {path}:{line}: {msg}" for path, line, msg in undeclared)
        + "\n\nFix with a doubled backslash (\\\\d) for a one-off, or make the "
          "literal raw (r\"\"\"...\"\"\") when it is a regex-heavy SQL block. "
          "Both are no-ops at runtime."
    )


def test_escape_debt_has_no_stale_entries():
    """A declared offender that no longer offends must be deleted, or the list
    rots into a permanent allow-list that nobody rechecks."""
    if not ESCAPE_DEBT:
        pytest.skip("no declared escape debt — the list is empty, which is the goal")
    offending = {f[0] for f in _offenders()}
    stale = sorted(set(ESCAPE_DEBT) - offending)
    assert not stale, (
        f"ESCAPE_DEBT entries no longer have an invalid escape: {stale}. "
        "Delete them — a resolved entry must not stay on the list."
    )


def test_guard_actually_reaches_the_source():
    """Sabotage-protection: if the walk silently matched nothing, the guard
    above would pass on an empty set and look like coverage."""
    files = list(_python_files())
    assert len(files) > 200, (
        f"only {len(files)} python files found under {REPO} — the walk is not "
        "reaching the source tree, so the guard proves nothing"
    )
    assert any(p.name == "api.py" for p in files), "app/rag-api/api.py not scanned"


def test_detector_fires_on_a_known_bad_literal():
    """The detector itself must be able to fail. Compiles a string carrying the
    exact defect that was found in api.py, and asserts it is reported."""
    bad = "SQL = \"substring(url from '://[^/:]+:(\\d+)')\"\n"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        compile(bad, "<sabotage>", "exec")
    msgs = [str(w.message) for w in caught]
    assert any("invalid escape sequence" in m for m in msgs), (
        "the detector did not fire on a literal known to carry the defect — "
        f"caught: {msgs}"
    )
