"""Every Go build container must be allowed to fetch the toolchain a tool needs.

Run on demand:

    pytest tests/test_go_tool_build.py -v

WHY THIS EXISTS
---------------
Found by the first fresh-install rehearsal. `pd-runner` finished a clean install
with 3 of 5 tools:

    [WARN] pd-runner (post-build): 3/5 present, missing: httpx katana

Cause, from the build log:

    httpx@v1.12.0 requires go >= 1.26.0 (running go 1.25.9; GOTOOLCHAIN=local)
    [httpx] FAILED — skipping

The official `golang:` images pin `GOTOOLCHAIN=local`, so a tool whose go.mod
requires a newer Go than the image simply cannot build. The osint-runner block
had always exported `GOTOOLCHAIN=auto`; the pd-runner block had not. One missing
word, and every fresh install produced a pd-runner that cannot probe HTTP
(`httpx`) or crawl (`katana`).

Two things made it invisible:

* the tools are installed with `@latest`, so the requirement moved under us —
  nothing changed in this repo on the day it broke;
* a failed tool is a WARNING, not an error, so the install still reports success.

Static — no docker or Go needed, runs in CI.

Sabotage check: drop GOTOOLCHAIN=auto from either block -> RED.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(REPO, "scripts", "build-go-tools.sh")


def _src():
    if not os.path.exists(SCRIPT):
        pytest.skip("scripts/build-go-tools.sh not present")
    return open(SCRIPT, encoding="utf-8").read()


def _go_build_blocks():
    """Each `docker run ... golang:<v> bash -c '...'` body in the script."""
    src = _src()
    blocks = []
    for m in re.finditer(r"golang:[\d.]+\s+bash\s+-c\s+'", src):
        start = m.end()
        depth = src.find("\n'", start)          # closing quote on its own
        blocks.append(src[start:depth if depth > 0 else len(src)])
    return blocks


def test_the_script_has_go_build_blocks():
    """Otherwise every assertion below passes for the wrong reason."""
    blocks = _go_build_blocks()
    assert len(blocks) >= 2, (
        f"found {len(blocks)} golang build block(s); the script builds both "
        "osint-runner and pd-runner tools, so the scan is broken"
    )


def test_every_go_build_block_allows_a_toolchain_upgrade():
    offenders = []
    for i, body in enumerate(_go_build_blocks()):
        if "go install" not in body:
            continue
        # Anchor on a real assignment on a NON-COMMENT line. The block carries a
        # comment explaining GOTOOLCHAIN at length, so a bare substring test
        # stays true after the export is deleted — the first version of this
        # guard passed its own sabotage for exactly that reason.
        effective = [l for l in body.splitlines() if not l.lstrip().startswith("#")]
        if not any(re.search(r"(^|\s)(export\s+[^#\n]*)?GOTOOLCHAIN=auto(\s|$)", l)
                   for l in effective):
            first = next((l.strip() for l in body.splitlines()
                          if "go install" in l or "TOOLS=" in l), "?")
            offenders.append(f"block {i} (near {first[:60]!r})")
    assert not offenders, (
        "these Go build blocks run `go install` without GOTOOLCHAIN=auto, so the "
        "golang image's GOTOOLCHAIN=local applies and any tool needing a newer "
        "Go fails — as a WARNING, leaving the binary silently absent:\n  "
        + "\n  ".join(offenders)
    )


def test_a_failed_tool_is_at_least_reported():
    """It is a warning by design, so the wording must survive refactors —
    a silent skip would make the next occurrence invisible again."""
    src = _src()
    assert "FAILED — skipping" in src or "FAILED" in src, (
        "a tool that fails to build is not reported at all"
    )
