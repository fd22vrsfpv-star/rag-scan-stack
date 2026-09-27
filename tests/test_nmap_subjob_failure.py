"""A failed nmap sub-job (batch) must be VISIBLE in the scan result, not silently
reduce the port list.

Regression (Docs/OPEN_ITEMS.md): the full-scan batch loops wrapped the whole
per-target loop in one try, so a single failed batch aborted the rest and dropped
their ports, while the phase and the job still reported "completed". The fix
records each failed batch (with its ports) and marks the phase/job "partial".

These exercise nmap-api._collect_failed_batches, the pure aggregation the
finalizer uses to decide completed-vs-partial. Loaded by file path (the module
name has a hyphen); skips cleanly where the service deps are absent.
"""
import importlib.util
import os
from pathlib import Path

import pytest

# Repo layout by default; overridable so the test can run inside the nmap_scanner
# container (where the module lives at /app/nmap-api.py), mirroring conftest's
# env-override convention.
NMAP_API = Path(os.environ.get(
    "NMAP_API_PATH",
    str(Path(__file__).parent.parent / "nmap_scanner" / "nmap-api.py")))


def _load():
    spec = importlib.util.spec_from_file_location("nmap_api_under_test", NMAP_API)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:  # fastapi / service deps not present here
        pytest.skip(f"nmap-api not importable in this environment: {e}")
    return mod


def test_all_batches_ok_yields_no_failures():
    mod = _load()
    phases = {
        "phase2": {"status": "completed", "nmap_results": [
            {"target": "10.0.0.1", "ports": [80, 443], "xml_path": "/x/a.xml"},
        ]},
        "phase3": {"status": "completed", "nmap_results": [
            {"target": "10.0.0.1", "ports": [8080], "xml_path": "/x/b.xml"},
        ]},
    }
    assert mod._collect_failed_batches(phases) == []


def test_failed_batch_is_collected_with_its_ports():
    mod = _load()
    phases = {
        "phase2": {"nmap_results": [
            {"target": "10.0.0.1", "ports": [80], "xml_path": "/x/a.xml"},
            {"target": "10.0.0.1", "ports": [3306, 5432], "error": "nmap exit 1: boom"},
        ]},
        "phase3": {"nmap_results": [
            {"target": "10.0.0.1", "ports": [9000], "error": "timeout"},
        ]},
    }
    failed = mod._collect_failed_batches(phases)
    assert len(failed) == 2
    # The dropped ports are preserved so the operator sees what went un-scanned.
    dropped = sorted(p for f in failed for p in (f["ports"] or []))
    assert dropped == [3306, 5432, 9000]
    assert {f["phase"] for f in failed} == {"phase2", "phase3"}


def test_missing_phases_are_safe():
    mod = _load()
    assert mod._collect_failed_batches({}) == []
    assert mod._collect_failed_batches({"phase2": {}}) == []
    assert mod._collect_failed_batches({"phase3": {"nmap_results": None}}) == []
