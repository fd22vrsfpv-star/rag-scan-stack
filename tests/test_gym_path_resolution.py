"""2026-10-22: gym.sh exited 0 with no output, and every caller read that as
"the target failed to start".

The 20-CVE benchmark launched after the release tag reported
`TARGET-FAILED-TO-START` for CVE after CVE. The targets were fine; `gym.sh`
was aborting before it did anything, and doing it silently.

Two defects, both introduced when the gym was made macOS-portable:

1. `/opt/cve-bench/gym.sh` is a SYMLINK into this repo, so
   `dirname "${BASH_SOURCE[0]}"` is the symlink's directory and

       REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

   resolved to `/opt` — a directory with no `.env` at all.

2. Under `set -euo pipefail`, a `grep` that matches NOTHING fails the pipeline
   and kills the script. The lookup

       CVEBENCH_DIR="${CVE_BENCH_DIR:-$(grep -E '^CVE_BENCH_DIR=' ... )}"
       CVEBENCH_DIR="${CVEBENCH_DIR:-/opt/cve-bench}"

   therefore never reached its own default: the fallback was dead code in
   exactly the case it was written for — a `.env` without that key. Proven
   directly: the same three lines in a scratch script exit 1 without printing.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_gym_path_resolution.py -v'
"""
from __future__ import annotations

import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GYM = REPO / "scripts" / "gym.sh"

pytestmark = pytest.mark.skipif(not GYM.exists(), reason="scripts/gym.sh not present")


@pytest.fixture(scope="module")
def src() -> str:
    return GYM.read_text(encoding="utf-8")


def test_it_is_valid_shell():
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    r = subprocess.run(["bash", "-n", str(GYM)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr.strip()[:300]


def test_the_env_lookup_cannot_kill_the_script(src):
    """A grep with no match must not abort before the default is applied."""
    # Read the whole LINE rather than matching nested parens — the command
    # substitution contains its own ")" and a non-greedy pattern lands on it.
    line = next((l for l in src.splitlines()
                 if "CVEBENCH_DIR=" in l and "CVE_BENCH_DIR:-" in l), None)
    assert line, "the CVE_BENCH_DIR lookup was not found"
    assert re.search(r"\|\|\s*true", line), (
        "the lookup can still fail the pipeline under `set -e`, making the "
        "default on the next line unreachable: %s" % line.strip())


def test_the_default_is_still_there(src):
    """The `|| true` is only half of it — the default must exist to fall to."""
    assert re.search(r'CVEBENCH_DIR="\$\{CVEBENCH_DIR:-[^}]+\}"', src), \
        "no default for CVEBENCH_DIR"


def test_repo_root_resolves_through_a_symlink(src):
    """Every caller invokes this through /opt/cve-bench/gym.sh, a symlink."""
    m = re.search(r"REPO_ROOT=\"\$\(cd \"\$\(dirname \"([^\"]+)\"\)/\.\.", src)
    assert m, "REPO_ROOT assignment not found"
    assert m.group(1) != "${BASH_SOURCE[0]}", (
        "REPO_ROOT still uses BASH_SOURCE directly; through a symlink that "
        "resolves to the symlink's parent, not the repo")
    assert re.search(r"while \[ -L ", src), "no symlink-dereference loop"


def test_the_dereference_handles_a_relative_link(src):
    """`readlink` returns the link text, which may be relative — joining it to
    the link's own directory is what makes that correct. `readlink -f` would be
    simpler but is GNU-only, and this script is deliberately macOS-portable."""
    m = re.search(r"while \[ -L .{0,400}?done", src, re.S)
    assert m, "symlink loop not found"
    body = m.group(0)
    assert re.search(r"case .*? in", body, re.S), "no absolute/relative branch"
    assert "dirname" in body, "a relative link is not joined to its own directory"
    assert "readlink -f" not in body, "readlink -f is not portable to macOS"


def test_a_missing_env_key_still_resolves(tmp_path):
    """End to end on the real logic: a repo whose .env lacks the key must fall
    through to the default instead of exiting."""
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    src = GYM.read_text(encoding="utf-8")
    head = src.split("NET=", 1)[0]          # the path-resolution preamble only
    head = head.replace('[ -x "$CVEBENCH_DIR/run" ]',
                        '[ -n "$CVEBENCH_DIR" ]')   # skip the on-disk check
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / ".env").write_text("SOMETHING_ELSE=1\n")
    script = repo / "scripts" / "gym.sh"
    script.write_text(head + '\necho "RESOLVED=$CVEBENCH_DIR"\n')
    script.chmod(0o755)
    link_dir = tmp_path / "cve-bench"
    link_dir.mkdir()
    (link_dir / "gym.sh").symlink_to(script)

    r = subprocess.run(["bash", str(link_dir / "gym.sh")],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, (
        "the script aborted on a .env without the key (rc=%s): %s"
        % (r.returncode, r.stderr.strip()[:200]))
    assert "RESOLVED=" in r.stdout, r.stdout + r.stderr
    assert "RESOLVED=\n" not in r.stdout, "resolved to an empty path"
