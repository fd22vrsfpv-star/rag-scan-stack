"""A clean checkout must contain everything `docker compose build` COPYs.

Run on demand:

    pytest tests/test_clean_checkout.py -v

WHY THIS EXISTS
---------------
Found by the first fresh-install rehearsal on this repo. `docker compose build`
died on a clean clone with:

    ERROR: failed to calculate checksum of ref ...: "/pd_runner/bin": not found
    target pd-runner: failed to solve: ... "/pd_runner/bin": not found

`pd_runner/bin/` and `osint_runner/bin/` hold Go binaries built by
scripts/build-go-tools.sh. They are correctly gitignored as build output — but
the DIRECTORY has to exist, because `COPY <svc>/bin/ /tmp/...` fails outright
when its source is absent. An EMPTY directory is fine: every tool underneath is
guarded by `if [ -f ... ]`, which is exactly what the Dockerfile comment "the
build succeeds even if some binaries are missing" always claimed.

So the failure mode is: skip Phase 2 (or clone and build directly) and the build
dies with a checksum error naming a path that is *supposed* to be absent. The
error says nothing about Go tools.

The fix is a tracked .gitkeep plus a gitignore that excludes the CONTENTS
(`bin/*`) rather than the directory (`bin/`) — git cannot re-include a file
underneath an excluded directory, so the negation silently does nothing if the
directory itself is ignored. That subtlety is why this is a test and not a note.

Static — no docker needed, runs in CI.

Sabotage check: delete pd_runner/bin/.gitkeep -> RED.
"""
import os
import re
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))


def _copied_dirs():
    """Directories that a Dockerfile COPYs and that git would not otherwise keep."""
    found = {}
    for root, _dirs, files in os.walk(REPO):
        if "/.git" in root or "/node_modules" in root:
            continue
        for name in files:
            if name != "Dockerfile" and not name.startswith("Dockerfile."):
                continue
            path = os.path.join(root, name)
            try:
                body = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in re.finditer(r"^\s*COPY\s+(?:--[\w=.-]+\s+)*([^\s]+)\s", body, re.M):
                src = m.group(1)
                if src.endswith("/bin/"):
                    found.setdefault(src.rstrip("/"), path)
    return found


def test_build_copies_at_least_one_bin_dir():
    """Otherwise the assertions below pass for the wrong reason."""
    assert _copied_dirs(), (
        "no Dockerfile COPYs a */bin/ directory — either the layout changed or "
        "the scan is broken, and this guard is now vacuous"
    )


@pytest.mark.parametrize("rel", sorted(_copied_dirs()))
def test_copied_bin_dir_survives_a_clean_checkout(rel):
    """`git ls-files` is the question that matters: what a fresh clone gets."""
    out = subprocess.run(["git", "ls-files", rel], cwd=REPO,
                         capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    assert out.stdout.strip(), (
        f"{rel}/ is COPYed by a Dockerfile but git tracks nothing inside it, so "
        f"a clean clone has no such directory and the build fails with "
        f'"failed to calculate checksum ... /{rel}: not found". Add a tracked '
        f"{rel}/.gitkeep and ignore {rel}/* rather than {rel}/."
    )


@pytest.mark.parametrize("rel", sorted(_copied_dirs()))
def test_the_binaries_themselves_stay_ignored(rel):
    """The marker must not become a licence to commit build output."""
    probe = os.path.join(rel, "__probe_binary__")
    out = subprocess.run(["git", "check-ignore", probe], cwd=REPO,
                         capture_output=True, text=True)
    if out.returncode == 128:
        pytest.skip("not a git checkout")
    assert out.returncode == 0, (
        f"{probe} is NOT ignored — the gitignore was loosened too far and Go "
        f"build output can now be committed"
    )
