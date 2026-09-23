"""Declared wordlists must exist in the image that runs them.

WHY THIS EXISTS
---------------
`knowledge/content_discovery.yaml` publishes custom-attack recipes whose command
templates carry `{param_wordlist}`, `{payload_wordlist}`, `{vhost_wordlist}` and
friends. They are RAG recipes, not rendered templates: the loader embeds each one
with "Fill the {placeholders} at run time". Nothing mapped those placeholders to
a real path, so whoever filled one had to guess.

A guessed path matters more than it looks. `ffuf -w /nope.txt` exits immediately,
so the attack is recorded as having run and found nothing — a negative result for
something that never executed. That is this repo's recurring failure mode, and a
wordlist is an unusually quiet place for it to happen.

`wordlist_sources` now declares concrete paths, and this asserts every one of
them exists in the kali-listener image. Skips cleanly where docker or the image
is unavailable, because "cannot check" is not "the path is missing".

SABOTAGE PROOF
--------------
* Add a path that does not exist to wordlist_sources -> test_every_declared_wordlist_exists
  fails naming it.
* Delete the loader block -> test_wordlist_sources_are_embedded fails.
"""
import os

import pytest

from _container import container_available, container_exec

yaml = pytest.importorskip("yaml")

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
KB = os.path.join(REPO, "knowledge", "content_discovery.yaml")
LOADER = os.path.join(REPO, "etl", "load_knowledge_documents.py")
IMAGE_CONTAINER = "kali-listener"


def _sources():
    if not os.path.exists(KB):
        pytest.skip("content_discovery.yaml not present")
    data = yaml.safe_load(open(KB, encoding="utf-8")) or {}
    ws = data.get("wordlist_sources")
    if not isinstance(ws, dict) or not ws:
        pytest.fail("wordlist_sources is missing — the placeholders are unsourced again")
    paths = []
    for placeholder, val in ws.items():
        if isinstance(val, dict):
            for kind, ps in val.items():
                paths += [(f"{placeholder}/{kind}", p) for p in (ps or [])]
        elif isinstance(val, list):
            paths += [(placeholder, p) for p in val]
    return paths


def _docker_ok():
    """Via tests/_container.py, not a private `docker exec`.

    A local copy of the subprocess pattern is what test_ci_baseline's
    DIRECT_EXEC_DEBT ratchet exists to prevent — this test grew one and the
    ratchet caught it. The shared helper also gets the skip-vs-fail distinction
    right: "no such container" is unreachable (skip), a non-zero exit from the
    command itself is a real failure.
    """
    return container_available(IMAGE_CONTAINER)


def test_every_declared_path_is_absolute():
    """A relative wordlist path resolves against whatever cwd the tool inherits."""
    bad = [(k, p) for k, p in _sources() if not p.startswith("/")]
    assert not bad, f"these wordlist paths are not absolute: {bad}"


def test_every_declared_wordlist_exists():
    """The whole point: a declared path that is not on disk fails silently."""
    if not _docker_ok():
        pytest.skip(f"{IMAGE_CONTAINER} not available — cannot check paths from here")
    missing = []
    for key, path in _sources():
        # `test -e` exits 0 (stdout "") when the path exists, 1 when it does not.
        # container_exec turns the latter into an "__ERR__ ..." string and a
        # genuinely unreachable container into None.
        out = container_exec(path, container=IMAGE_CONTAINER, runner=("test", "-e"),
                             timeout=60)
        if out is None:
            pytest.skip(f"{IMAGE_CONTAINER} became unreachable mid-check")
        if str(out).startswith("__ERR__"):
            missing.append(f"{key} -> {path}")
    assert not missing, (
        "these wordlists are declared but do not exist in the image, so a recipe "
        "filled with one exits immediately and records as 'found nothing':\n  "
        + "\n  ".join(missing))


def test_wordlist_sources_are_embedded():
    """CLAUDE.md: knowledge that is read but never embedded is retrievable by
    nobody. The recipes are embedded; their sources must be too."""
    if not os.path.exists(LOADER):
        pytest.skip("loader not present")
    src = open(LOADER, encoding="utf-8").read()
    assert "wordlist_sources" in src, (
        "etl/load_knowledge_documents.py does not embed wordlist_sources, so the "
        "planner retrieving a recipe still cannot find out which list to use")


def test_the_placeholders_used_by_recipes_are_sourced():
    """Every {*_wordlist} a recipe names should have a declared source, or be
    deliberately absent with a reason."""
    import re
    data = yaml.safe_load(open(KB, encoding="utf-8")) or {}
    declared = set((data.get("wordlist_sources") or {}).keys())
    used = set()
    for r in (data.get("custom_attacks") or []):
        for m in re.finditer(r"\{([a-z_]*wordlist)\}", r.get("template", "") or ""):
            used.add(m.group(1))
    undeclared = sorted(used - declared)
    # bypass_wordlist is knowingly unsourced: seclists ships only a markdown
    # write-up for 403 bypasses in this image, not a list.
    undeclared = [u for u in undeclared if u != "bypass_wordlist"]
    assert not undeclared, (
        f"these placeholders are used by a recipe but have no declared source: "
        f"{undeclared}")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
