"""The dashboard build version must be identical everywhere it is declared.

WHY THIS EXISTS
---------------
CLAUDE.md requires the version string to be bumped in lockstep, but nothing
FAILED when it drifted — and by that project's own standard, "a rule with no
enforcing test is a suggestion". The lockfile made the cost concrete: it carries
a copy of package.json's `version`, and `npm ci` (the CI frontend job's install
step) refuses to run against a lockfile out of sync with package.json. A silent
drift there breaks the build, not just a label in the UI.

Pure-file checks: no DB, no containers, no node. Runs anywhere.

Sabotage check: edit BUILD_VERSION in constants.ts only -> RED.

NOT CHECKED HERE: `.env`. It is gitignored and machine-local, so CI never sees
it and it legitimately holds a different value after a branch switch. Asserting
on it would make the suite red for a file the repo does not control — exactly
the failure mode this module exists to prevent. Operators still must bump it
(docker-compose injects it into every service container); the deploy scripts,
not pytest, are where that belongs.
"""
import json
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
PKG = os.path.join(REPO, "dashboard", "frontend", "package.json")
LOCK = os.path.join(REPO, "dashboard", "frontend", "package-lock.json")
CONST = os.path.join(REPO, "dashboard", "frontend", "src", "lib", "constants.ts")

VERSION_RE = re.compile(r"^\d{4}\.\d{2}\.\d{2}-\d+$")


def _json(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _constants_version():
    if not os.path.exists(CONST):
        pytest.skip("constants.ts not present")
    with open(CONST, encoding="utf-8") as fh:
        m = re.search(r"export const BUILD_VERSION\s*=\s*['\"]([^'\"]+)['\"]", fh.read())
    assert m, "BUILD_VERSION not found in constants.ts — this guard would pass vacuously"
    return m.group(1)


def test_all_declared_versions_agree():
    pkg = _json(PKG).get("version")
    lock = _json(LOCK)
    const = _constants_version()
    seen = {
        "package.json": pkg,
        "package-lock.json (top level)": lock.get("version"),
        'package-lock.json (packages[""])': (lock.get("packages") or {}).get("", {}).get("version"),
        "src/lib/constants.ts": const,
    }
    assert all(seen.values()), f"a version is missing entirely: {seen}"
    assert len(set(seen.values())) == 1, (
        "BUILD_VERSION has drifted between declaration sites — `npm ci` fails when "
        f"package.json and package-lock.json disagree: {seen}"
    )


def test_version_has_the_documented_shape():
    """YYYY.MM.DD-N, matching the frontend's own constants.test.ts assertion."""
    v = _constants_version()
    assert VERSION_RE.match(v), f"{v!r} is not the documented YYYY.MM.DD-N shape"


def test_the_lockfile_is_committed():
    """`npm ci` REQUIRES a lockfile; setup-node's cache keys off its path. It was
    gitignored, so the CI frontend job could never install and never ran a single
    frontend test."""
    assert os.path.exists(LOCK), (
        "dashboard/frontend/package-lock.json is missing — `npm ci` cannot run"
    )
