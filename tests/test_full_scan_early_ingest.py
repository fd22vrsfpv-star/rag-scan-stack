"""The full_scan must ingest the quick-scan ports BEFORE the full sweep finishes.

Run on demand:

    pytest tests/test_full_scan_early_ingest.py -v

WHY THIS EXISTS
---------------
_run_full_scan_async ran nmap on the quick (top-1000) ports in parallel with the
slow 1-65535 masscan sweep, but ingested EVERYTHING only at the very end — after
the ~hour-long sweep. So the pipeline's first analyze/exploit pass ran on an empty
inventory, and the quick ports (found in seconds) were not actionable until the
whole job finished. The early ingest lands the quick masscan + quick-port nmap the
moment nmap-on-quick-ports returns, while the full sweep keeps running.

SABOTAGE PROOF
--------------
Move the _ingest_masscan_file(job_id, quick_path) call to AFTER
masscan_future.result() and test_quick_ingest_precedes_full_sweep fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
NMAP_API = os.path.join(REPO, "nmap_scanner", "nmap-api.py")


def _src():
    if not os.path.exists(NMAP_API):
        pytest.skip("nmap-api.py not present")
    return open(NMAP_API, encoding="utf-8").read()


def test_ingest_helpers_exist():
    src = _src()
    assert "def _ingest_masscan_file(" in src, (
        "shared masscan ingest helper must exist for early + final ingest")
    assert "def _ingest_nmap_results(" in src, (
        "shared nmap ingest helper must exist for early + final ingest")


def test_quick_ingest_precedes_full_sweep():
    """In Phase 2, the quick-port ingest must run BEFORE the code blocks on the
    full masscan sweep (masscan_future.result()) — otherwise it is not early."""
    src = _src()
    i_ingest = src.find("_ingest_masscan_file(job_id, quick_path)")
    assert i_ingest != -1, "the early quick-port masscan ingest call is missing"
    # the blocking wait on the full sweep, assigned to phase2_masscan_path
    i_block = src.find("phase2_masscan_path = masscan_future.result()")
    assert i_block != -1, "the full-sweep blocking wait is missing"
    assert i_ingest < i_block, (
        "the quick-port ingest must precede the full-sweep wait, or the pipeline "
        "still can't act on the quick ports until the whole scan finishes")
    # and the early nmap ingest is there too
    assert "_ingest_nmap_results(job_id, phase2_nmap_results)" in src, (
        "the quick-port nmap service detection must be ingested early as well")
