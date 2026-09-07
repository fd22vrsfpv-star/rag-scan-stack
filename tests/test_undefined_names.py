"""No module-level undefined name in a service entrypoint.

WHY THIS EXISTS
---------------
`ast.parse` passes on `@contextlib.contextmanager` with no `import contextlib` —
it is valid syntax and an invalid program. The container then crash-loops on
NameError at import, which looks like an infrastructure problem rather than a
one-word omission. That happened here: a decorator was added, the import guard
silently did not match (this file's imports are on ONE line, so an
`"import logging\n"` anchor never fired), and web-scanner restarted in a loop.

CI does not catch it either: the sanity job runs
`flake8 etl app scanner nuclei || true` — note the `|| true`, which discards the
result entirely, and note that `web_scanner/` is not in the list.

This runs pyflakes and fails on **undefined names only** (F821 and friends). Not
style, not unused imports — just "this name does not exist", which is always a
bug and never a preference.

Skips cleanly when pyflakes is unavailable.
"""
import os
import subprocess
import sys

import pytest

pytest.importorskip("pyflakes")

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))

#: Service entrypoints whose import failure takes a container down.
MODULES = [
    "web_scanner/web_scan.py",
    "web_scanner/scan_pipeline.py",
    "app/rag-api/api.py",
    "app/rag-api/health_router.py",
    "app/rag-api/wstg_coverage.py",
    "scan_recommender/scan_recommender.py",
    "kali_listener/listener_service.py",
    "playwright_scanner/playwright_scanner.py",
    "nmap_scanner/nmap-api.py",
    "etl/scope_gate.py",
]


def _undefined_names(path):
    """pyflakes messages that mean 'this name does not exist'."""
    proc = subprocess.run([sys.executable, "-m", "pyflakes", path],
                          capture_output=True, text=True)
    bad = []
    for line in (proc.stdout or "").splitlines():
        low = line.lower()
        if "undefined name" in low or "undefined local" in low:
            bad.append(line.strip())
    return bad


@pytest.mark.parametrize("rel", MODULES)
def test_no_undefined_names(rel):
    path = os.path.join(REPO, rel)
    if not os.path.exists(path):
        pytest.skip(f"{rel} not present")
    bad = _undefined_names(path)
    assert not bad, (
        f"{rel} references names that do not exist — the container will "
        f"crash-loop on import, not fail a test: {bad}"
    )
