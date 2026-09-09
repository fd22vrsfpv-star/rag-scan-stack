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


# The image is named once as $GO_IMAGE (2026-09-09) so the cross-arch
# capability probe execs the same image the build does. Match either form:
# this finder returning 0 blocks makes every GOTOOLCHAIN assertion below pass
# vacuously, which is how it noticed the refactor in the first place.
_BUILD_BLOCK_START = re.compile(r"""(?:golang:[\d.]+|"\$GO_IMAGE")\s+bash\s+-c\s+'""")


def _go_build_blocks():
    """Each `docker run ... <go image> bash -c '...'` body in the script."""
    src = _src()
    blocks = []
    for m in _BUILD_BLOCK_START.finditer(src):
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


# ── The cross-architecture pass, found by the SECOND rehearsal ──────────────
#
# The first rehearsal reported "osint-runner: all 18 Go binaries present". The
# second, run after a WSL restart, reported 0/18 and 0/5:
#
#     Host: x86_64 | Building for: arm64 amd64
#     [arm64] Building osint-runner tools (18 Go tools + massdns + trufflehog)...
#     exec /usr/bin/bash: exec format error
#     [ERR] Go tool build failed — continuing without missing binaries
#
# `--platform linux/arm64` on an amd64 host needs qemu registered with the
# kernel's binfmt_misc, and WSL2 drops those registrations on restart. Two
# defects compounded: `both` built the CROSS arch first, and `set -euo pipefail`
# turned its failure into an exit before the LOCAL arch — the only binaries
# `docker compose build` copies — was ever built. Nothing in the repo changed
# between the two runs; the kernel's binfmt table did.


def test_both_builds_the_host_arch_first():
    """Whichever arch fails, the local one must already be built.

    A literal ("arm64" "amd64") ordering means an amd64 host builds the cross
    arch first, and one `exec format error` there costs it every local binary.
    """
    src = _src()
    m = re.search(r"^\s*both\)(.*?);;", src, re.M | re.S)
    assert m, "the `both` case is gone — this guard would pass vacuously"
    block = m.group(1)
    assert "HOST_ARCH" in block, (
        "the `both` case does not order the arch list by $HOST_ARCH, so on one "
        "of the two host architectures the cross build runs first and its "
        "failure costs the local binaries"
    )
    assert not re.search(r'ARCHES=\(\s*"arm64"\s+"amd64"\s*\)', block), (
        "the `both` case still uses a fixed arm64-then-amd64 order"
    )


def test_a_host_that_cannot_cross_build_skips_rather_than_fails():
    """"Cannot run here" is a skip. The cross binaries exist only for deploying
    to remote nodes of the other arch — nothing on this host needs them."""
    src = _src()
    assert re.search(r"^can_build_arch\(\)", src, re.M), (
        "no can_build_arch() probe — a host without qemu/binfmt registered "
        "cannot execute foreign-arch containers, and the build must say so "
        "instead of dying with `exec format error`"
    )
    loop = re.search(r'for arch in "\$\{ARCHES\[@\]\}"; do(.*?)^done', src, re.M | re.S)
    assert loop, "the per-arch build loop is gone"
    assert "can_build_arch" in loop.group(1), (
        "the build loop does not consult can_build_arch, so the probe exists "
        "but nothing acts on it"
    )


def test_the_probe_uses_the_same_image_as_the_build():
    """A probe against a different image proves nothing about whether the build
    can run — it must exec the image the build actually uses."""
    src = _src()
    assert re.search(r'^GO_IMAGE=', src, re.M), "GO_IMAGE is not defined"
    probe = re.search(r"^can_build_arch\(\)\s*\{(.*?)^\}", src, re.M | re.S)
    assert probe, "can_build_arch() not found"
    assert "$GO_IMAGE" in probe.group(1), (
        "the capability probe does not run $GO_IMAGE, so it may succeed on an "
        "image the build never uses"
    )
    assert not re.search(r"^\s*docker run.*golang:\d", src, re.M), (
        "a build still names a golang: image literally instead of $GO_IMAGE — "
        "the probe and the build can now drift apart"
    )


def test_only_the_host_arch_decides_the_exit_status():
    """setup.sh reads a non-zero exit as "Go tool build failed" and carries on
    with whatever is on disk. A cross build that cannot run here must not spend
    that signal — and a failed HOST build must."""
    src = _src()
    assert "HOST_RC" in src, (
        "no separate status for the host-arch build: either a cross failure "
        "fails the whole script (the original defect) or a host failure is "
        "silently ignored (worse)"
    )
    assert re.search(r'exit "\$HOST_RC"', src), (
        "the script never exits with the host-arch build's status"
    )
