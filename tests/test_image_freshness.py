"""Do the running containers hold the code in this working tree?

Most services bake their source into the image; only `etl/` and a couple of
others are bind-mounted. `docker compose restart` therefore re-runs the OLD code
with no error and no warning.

That is not hypothetical: a gowitness scope fix was written, committed, reviewed
and believed live for hours while the container kept ingesting out-of-scope
hosts, because osint_runner.py is baked and the image was never rebuilt. Nothing
in the stack reported it.

    pytest tests/test_image_freshness.py

Skips when Docker is unavailable, so it is safe in the normal suite.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
CHECKER = ROOT / "scripts" / "check_image_freshness.py"


@pytest.mark.e2e
def test_checker_exists_and_is_executable():
    assert CHECKER.exists(), "scripts/check_image_freshness.py is missing"


@pytest.mark.e2e
def test_no_running_service_is_stale():
    """Fails with the exact rebuild command when a container drifts."""
    if not shutil.which("docker"):
        pytest.skip("docker not available")
    r = subprocess.run([sys.executable, str(CHECKER)],
                       capture_output=True, text=True, timeout=600)
    if "No running containers" in r.stdout:
        pytest.skip("stack is not running")
    assert r.returncode == 0, (
        "container(s) are running code that differs from this working tree — a "
        "restart will NOT fix it:\n" + r.stdout[-1500:]
    )
