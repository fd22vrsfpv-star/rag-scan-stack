"""A scan whose nmap batches partly failed must not report `completed`.

WHY THIS EXISTS
---------------
`mass2nmap` splits a host list into nmap batches. `run_nmap_batch` raises on a
non-zero exit, and the caller counts those into `stats["errors"]` with samples in
`stats["error_examples"]` — so the failure IS recorded. But the job was then
marked `completed` unconditionally, and the poller's partial-detection looked for
`result["errors"]` while nmap writes them one level deeper at
`result["stats"]["errors"]`.

Both halves had to be wrong for the bug to show, and both were: a host whose
ports were never enumerated read as fully scanned. The port list silently shrank
and nothing said so — which is how "only one HTTP port was discovered on a host
serving several" happened.

`partial` is an already-recognised terminal status in the poller, so this needed
no new vocabulary.

Sabotage: make the status unconditional again, or drop the nested `stats` read
in polling.py -> the matching test fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
NMAP_API = os.path.join(REPO, "nmap_scanner", "nmap-api.py")
POLLING = os.path.join(REPO, "dashboard", "bff", "polling.py")


def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _func(src, name):
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.get_source_segment(src, n)
    return None


def test_the_runner_reports_partial_when_batches_failed():
    """The status must depend on stats['errors'], not be a constant."""
    fn = _func(_src(NMAP_API), "_run_masscan_then_nmap_async")
    assert fn, "_run_masscan_then_nmap_async not found"

    tree = ast.parse(fn.lstrip())
    statuses = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        name = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
        if name != "update_job_status":
            continue
        if len(n.args) >= 2 and isinstance(n.args[1], ast.Constant):
            statuses.add(n.args[1].value)
    assert "partial" in statuses, (
        "the masscan->nmap runner never reports 'partial', so a run with failed "
        "nmap batches still reads as fully scanned")
    assert "completed" in statuses, "the success path is gone"

    # and the choice must actually be driven by the error count
    reads_errors = any(
        isinstance(n, ast.Constant) and n.value == "errors"
        for n in ast.walk(tree))
    assert reads_errors, "the runner does not read stats['errors'] at all"


def test_the_poller_reads_the_nested_error_count():
    """nmap's errors are at result['stats']['errors'], one level deeper than the
    poller's original check looked."""
    src = _src(POLLING)
    assert '"stats"' in src or "'stats'" in src, (
        "polling.py never reads the nested stats block, so an nmap run with "
        "failed batches is not detected as partial")

    # the nested read must sit in the partial-detection branch, not somewhere else
    idx = src.find("failed_targets")
    assert idx != -1, "the partial-detection branch is gone"
    window = src[max(0, idx - 500):idx + 200]
    assert "stats" in window, (
        "the partial-detection branch does not consult result['stats']['errors']")


def test_partial_is_a_recognised_status_downstream():
    """Guard the premise: 'partial' must already mean something to the poller, or
    this change invents a status nothing handles."""
    src = _src(POLLING)
    assert '"partial"' in src, "'partial' is not a status the poller knows"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
