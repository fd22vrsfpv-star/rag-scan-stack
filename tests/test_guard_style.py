"""Ratchet: guard tests must not pin source SUBSTRINGS.

Many tests here assert against the SOURCE of the code under test, because that
code needs a running service or a database to execute. That is fine. Asserting a
*code fragment* of it is not:

    assert 'json={"tool": _tool,' in src            # dies on a reformat
    assert "sign ?in|log ?in|not authori" in src    # FAILED when the check improved
    assert "_bl_discovered_paths(cur, host, root)" in src   # exact arg spelling

The second is why this ratchet exists. A guard pinned the IDOR probe's login
regex; replacing that regex with a better check (the old one matched the word
"Login" in static page furniture and suppressed every real finding) made the
TEST fail rather than the code. A guard that fails when the implementation
improves is worse than no guard: it argues for keeping the bug.

`tests/_ast_assert.py` provides the structural alternative — defines(), calls(),
call_kwarg(), call_order(within=...), const_elements(), string_constants().

The count RATCHETS: convert some and lower BASELINE. Adding new ones fails.

    pytest tests/test_guard_style.py
"""
import collections
import glob
import os
import re

import pytest

TESTS = os.path.dirname(os.path.abspath(__file__))

# `assert "<literal>" in <name>` / `assert "<literal>" not in <name>`
_ASSERT = re.compile(
    r'assert\s+(?:not\s+)?([\'"])(.+?)\1\s+(?:not\s+)?in\s+([A-Za-z_][A-Za-z0-9_\.]*)')
# only files that actually read source code are in scope
_READS_SOURCE = re.compile(r'read_text\(|_src\(|open\([^)]*\.py')

# Known brittle assertions still to convert. LOWER this as they are converted;
# it may not rise. 255 at the time the ratchet was introduced; 234 after that
# conversion pass, 233 after the stale-guard fixes, 230 after the skip audit,
# 218 after converting the post-enumeration graph and dispatch guards.
BASELINE = 218


def _is_code_fragment(literal: str) -> bool:
    """A literal that pins an EXPRESSION rather than naming a flag or a key.

    Punctuation that only occurs in source (=, (, [, {) plus enough length that
    it is not simply a value like "uid=33" or a flag like "-c ".
    """
    return len(literal) > 12 and bool(re.search(r'[=(\[{]', literal))


def _brittle_by_file():
    found = collections.Counter()
    for path in sorted(glob.glob(os.path.join(TESTS, "*.py"))):
        if os.path.basename(path) == os.path.basename(__file__):
            continue
        text = open(path, encoding="utf-8", errors="ignore").read()
        if not _READS_SOURCE.search(text):
            continue
        for m in _ASSERT.finditer(text):
            if _is_code_fragment(m.group(2)):
                found[os.path.basename(path)] += 1
    return found


def test_source_substring_assertions_do_not_grow():
    found = _brittle_by_file()
    total = sum(found.values())
    worst = ", ".join(f"{f} ({c})" for f, c in found.most_common(5))
    assert total <= BASELINE, (
        f"source-substring assertions rose to {total} (baseline {BASELINE}).\n"
        f"Worst files: {worst}\n\n"
        "Assert STRUCTURE instead — tests/_ast_assert.py:\n"
        "  defines(src, 'fn')                    not  'def fn(' in src\n"
        "  calls(src, 'fn')                      not  'fn(a, b)' in src\n"
        "  call_kwarg(src, 'fn', 'kw')           not  'fn(x, kw=' in src\n"
        "  call_order(src, 'a', 'b', within='f') not  src.index(a) < src.index(b)\n"
        "  const_elements(src, 'ALLOWLIST')      not  '\"tool\"' in src\n")


def test_baseline_is_not_stale():
    """If conversions have dropped the real count well below BASELINE, tighten it
    — a ratchet that has gone slack stops catching anything."""
    total = sum(_brittle_by_file().values())
    assert total > BASELINE - 25, (
        f"only {total} brittle assertions remain but BASELINE is {BASELINE}; "
        "lower BASELINE to lock the improvement in")


def test_ast_helper_offers_the_alternatives():
    """The ratchet is only fair if the replacement exists and works."""
    import sys
    sys.path.insert(0, TESTS)
    import _ast_assert as a
    for fn in ("defines", "calls", "call_kwarg", "call_order",
               "const_elements", "string_constants"):
        assert hasattr(a, fn), f"_ast_assert.{fn} missing"
    src = "def foo():\n    bar(x=1)\n    baz()\n"
    assert a.defines(src, "foo") and a.calls(src, "bar")
    assert a.call_kwarg(src, "bar", "x")
    assert a.call_order(src, "bar", "baz", within="foo")
    assert not a.call_order(src, "baz", "bar", within="foo")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
