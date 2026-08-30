"""Copies of shared modules must not drift from the canonical version.

Run on demand:

    pytest tests/test_shared_code.py -v
    python3 scripts/check_shared_code.py --list     # same check, no pytest

WHY THIS EXISTS
---------------
`common/validation.py` holds the input sanitizers — command arguments, output
paths, ports, CIDRs. Seven services carry their own copy because each has its
own Docker build context, and one had drifted: nmap_scanner's
`sanitize_command_arg` gained a `max_len` parameter because the hardcoded
1000-character cap rejected nmap's top-1000 port specification (3,808 characters
expanded), which broke scans on that profile. The fix was correct and stayed in
one service; the other six kept the bug. Nobody was wrong — there was no way to
notice.

The comparison itself lives in scripts/check_shared_code.py, NOT here. Writing
it twice would make this file the eighth copy of something that must not be
duplicated, which would be a poor advertisement for the rule it enforces. The
same script runs from post-install-check.sh and from CI, so the check holds at
deploy time and on every push, not only when someone runs pytest.
"""
import importlib.util
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
_CHECKER = os.path.join(REPO, "scripts", "check_shared_code.py")


@pytest.fixture(scope="module")
def checker():
    if not os.path.exists(_CHECKER):             # pragma: no cover
        pytest.skip("scripts/check_shared_code.py not present")
    spec = importlib.util.spec_from_file_location("check_shared_code", _CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_shared_module_drift(checker):
    """Every per-service copy matches its canonical version."""
    problems, _compared = checker.check()
    assert not problems, (
        "shared module drift:\n  " + "\n  ".join(problems)
        + "\n\nPort the change into the canonical file, re-sync every copy, and "
          "rebuild those images.")


def test_the_check_actually_compared_something(checker):
    """A drift check that finds nothing to compare passes and proves nothing.

    That failure mode has already occurred twice in this repo's guards, so it is
    asserted rather than assumed. If the per-service copies are ever replaced by
    imports from a mounted common/, this test should be deleted along with them.
    """
    _problems, compared = checker.check()
    # Was >= 5 when seven services each carried a copy. Six were deleted once
    # the rag-common base image began supplying validation.py, so the threshold
    # follows the duplication down rather than failing on success. Only
    # playwright_scanner still has one — its image is built FROM the Playwright
    # base, so it cannot inherit rag-common.
    #
    # When that last copy goes, `compared` reaches 0 and this whole module
    # should be deleted along with it: there is nothing left to drift.
    assert compared >= 1, (
        f"{compared} copies compared. If the per-service copies are genuinely "
        "gone, delete this test module — the duplication it guards no longer "
        "exists. If they are not, the checker has stopped finding them.")


def test_canonical_modules_exist_and_define_their_functions(checker):
    for canonical_rel, (_basename, names) in checker.SHARED_MODULES.items():
        path = os.path.join(REPO, canonical_rel)
        assert os.path.exists(path), f"canonical module missing: {canonical_rel}"
        found = checker.function_hashes(path, names)
        missing = [n for n in names if n not in found]
        assert not missing, f"{canonical_rel} does not define: {missing}"
