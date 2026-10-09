"""The service containers run Python 3.10; the test tier runs 3.12.

2026-10-09: a backslash inside an f-string expression (legal since 3.12,
PEP 701) passed `ast.parse` on the host and every test, then failed to IMPORT
inside rag-api — which would have taken the API down on the next restart.
This compiles the hot-copied modules with a 3.10 interpreter. Skips when
docker is unavailable.

    pytest tests/test_py310_syntax.py -v
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FILES = [
    "app/rag-api/api.py",
    "app/rag-api/build_poc_graph.py",
    "app/rag-api/webhooks.py",
    "dashboard/bff/routers/exploits.py",
]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
def test_service_modules_compile_on_python_310():
    existing = [f for f in FILES if (REPO / f).exists()]
    # compile() instead of py_compile: the repo is mounted read-only and
    # py_compile wants to write __pycache__.
    snippet = ("import sys\n"
               "for f in sys.argv[1:]:\n"
               "    compile(open(f, encoding='utf-8').read(), f, 'exec')\n"
               "print('ok', len(sys.argv) - 1)\n")
    cmd = ["docker", "run", "--rm", "-v", f"{REPO}:/work:ro", "-w", "/work", "python:3.10-slim",
           "python", "-c", snippet, *existing]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        pytest.skip(f"cannot run the 3.10 container here: {e}")
    if out.returncode != 0 and ("Cannot connect to the Docker daemon" in out.stderr or "permission denied" in out.stderr.lower()):
        pytest.skip("docker daemon unreachable")
    assert out.returncode == 0, f"3.12-only syntax in a 3.10 service module:\n{out.stderr[-2000:]}"
