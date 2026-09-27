"""BUILD_VERSION staleness is visible in the health output.

Run on demand:

    pytest tests/test_build_version_staleness.py -v

WHY THIS EXISTS
---------------
`BUILD_VERSION` is injected into a container's environment at CREATE time
(docker-compose `environment:` block). A service that was NOT recreated after a
version bump keeps reporting the OLD value while running current code, and the UI
reads that as the stack's version (Docs/OPEN_ITEMS.md, resolved by this change).

The fix bakes `IMAGE_BUILD_VERSION` into the image at BUILD time (Dockerfile
ARG/ENV, wired via compose `build.args`) and has `app/rag-api/health_router.py`
::build_version_info() report BOTH the env label (`build_version`) and the baked
stamp (`image_build_version`) plus `version_stale` = they differ. `/health/quick`
returns those fields, so a stale container is visibly stale instead of silently
mislabelled.

This test exercises the REAL function body (extracted from the source file, not a
re-typed copy) so sabotaging the comparison — e.g. hard-coding
`version_stale=False`, or dropping the `bool(image_build_version)` guard so an
older image without the baked stamp is falsely flagged — makes it fail.

It needs no database, no fastapi and no psycopg2: it isolates and execs only the
pure helper, so it runs anywhere and skips cleanly if the helper is missing.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
HEALTH_ROUTER = os.path.join(REPO, "app", "rag-api", "health_router.py")
FUNC = "build_version_info"


def _load_pure_helper():
    """Return the real build_version_info, exec'd in isolation.

    Importing health_router pulls in psycopg2/fastapi, which need not be present
    on the host. Instead, parse the source, lift the single FunctionDef, and exec
    just that — it is a pure function over `os.environ` and its arguments, so the
    only names it needs are os + a couple of typing aliases.
    """
    if not os.path.exists(HEALTH_ROUTER):
        pytest.skip(f"{HEALTH_ROUTER} not present")
    src = open(HEALTH_ROUTER, encoding="utf-8").read()
    tree = ast.parse(src)
    node = next(
        (n for n in tree.body
         if isinstance(n, ast.FunctionDef) and n.name == FUNC),
        None,
    )
    if node is None:
        pytest.skip(f"{FUNC} not defined in health_router.py")
    from typing import Optional, Dict, Any  # noqa: F401 (names the func annotates with)
    ns = {"os": os, "Optional": Optional, "Dict": Dict, "Any": Any}
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, HEALTH_ROUTER, "exec"), ns)
    return ns[FUNC]


def test_source_parses():
    """The whole module still parses (ast, no imports needed)."""
    assert ast.parse(open(HEALTH_ROUTER, encoding="utf-8").read())


def test_stale_when_baked_stamp_differs_from_env():
    info = _load_pure_helper()(build_version="2026.09.27-2",
                               image_build_version="2026.09.27-1")
    assert info["version_stale"] is True
    assert info["build_version"] == "2026.09.27-2"
    assert info["image_build_version"] == "2026.09.27-1"
    # `version` stays the CREATE-time env label (what compose labels the container).
    assert info["version"] == "2026.09.27-2"


def test_not_stale_when_they_match():
    info = _load_pure_helper()(build_version="2026.09.27-1",
                               image_build_version="2026.09.27-1")
    assert info["version_stale"] is False


def test_backward_compatible_when_no_baked_stamp():
    """Older image with no IMAGE_BUILD_VERSION must NOT be flagged stale."""
    info = _load_pure_helper()(build_version="2026.09.27-1",
                               image_build_version=None)
    assert info["version_stale"] is False
    assert info["image_build_version"] is None


def test_reads_environment_by_default(monkeypatch):
    monkeypatch.setenv("BUILD_VERSION", "envlabel-9")
    monkeypatch.setenv("IMAGE_BUILD_VERSION", "baked-8")
    info = _load_pure_helper()()
    assert info["build_version"] == "envlabel-9"
    assert info["image_build_version"] == "baked-8"
    assert info["version_stale"] is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
