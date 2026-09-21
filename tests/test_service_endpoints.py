"""Service URLs in tests come from conftest, not from a literal per file.

WHY THIS EXISTS
---------------
Nearly every live-stack test talks to rag-api (:8000) or the dashboard BFF
(:3002). They used to be reached through THIRTEEN different environment
variables — RAG_API_URL, RAG_API, WSTG_URL, ST_URL, SCANS_URL, LAT_URL,
CTRL_URL, CRED_URL, COV_URL, AGENT_API, BFF_BASE, BFF_URL, SMOKE_BASE,
RECS_URL — while sixteen further files hardcoded the URL with no override at
all. "Run the suite against another stack" therefore meant knowing every one of
those names, and even then a third of the files ignored all of them.

The literal was never the real problem. The sprawl of names was.

Now: TEST_RAG_API and TEST_BFF, resolved once in conftest. A file may still
honour its own legacy name first (`os.environ.get("ST_URL") or RAG_API`) so no
existing invocation breaks, but the DEFAULT lives in one place.

CONTAINER-INTERNAL URLs ARE DIFFERENT AND STAY LITERAL
------------------------------------------------------
Several tests build a shell or Python script and run it with `docker exec
rag-api ...`. Inside that container, `localhost:8000` / `127.0.0.1:8000` is the
service itself. Those are not host-side URLs and must NOT be rewritten: a
TEST_RAG_API pointing at a remote stack still cannot change where `docker exec`
runs. One of them was a plain (non-f) string, so interpolating a constant there
produced a literal `f'{RAG_API}/...'` in the generated code and a NameError in
the container.

They are declared below with a reason — exempt by design, not debt.

Sabotage check: add `BASE = "https://localhost:8000"` to any test file ->
test_no_new_hardcoded_service_urls fails by name.
"""
import ast
import os
import re
import sys

import pytest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS)

# localhost/loopback on a port this stack's services listen on
_SERVICE_URL = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1):(?:8000|3002|8014|8015|8017|8019)")

# Files that legitimately hardcode a service URL because the string is a script
# or command executed INSIDE a container, where loopback means that container.
# Exempt by design (permanent), not debt — but each entry must stay true, and
# test_exemptions_are_not_stale deletes the excuse when the usage goes away.
CONTAINER_INTERNAL = {
    "test_credential_bridge.py": "urllib script run via `docker exec rag-api python`",
    "test_export_completeness.py": "urllib script run via `docker exec rag-api python`",
    "test_findings_rollup.py": "SARIF/HAR fetched via `docker exec rag-api python`",
    "test_follow_up_export.py": "requests script run via `docker exec rag-api python3`",
    "test_identity_credential_state.py": "curl run via `docker exec rag-api sh -c`",
    "test_infrastructure_rollup_export.py": "urllib script run via `docker exec rag-api`",
    "test_post_review.py": "curl run via `docker exec rag-api sh -c`",
    "test_scan_parameters.py": "curl run via `docker exec rag-api sh -c`",
    "test_target_wordlists.py": "curl run via `docker exec rag-api sh -c`",
    "test_tool_command_check.py": "curl run via `docker exec kali-listener`",
}


def _docstring_nodes(tree):
    """ids of the Constant nodes that are docstrings.

    A module docstring showing `TEST_RAG_API=https://localhost:8000 pytest ...`
    is documentation, not a hardcoded endpoint — the usage line is exactly where
    the URL SHOULD appear.
    """
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = n.body[0] if n.body else None
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                out.add(id(first.value))
    return out


def _hardcoded_by_file():
    found = {}
    for name in sorted(os.listdir(TESTS)):
        if not name.startswith("test_") or not name.endswith(".py"):
            continue
        if name == os.path.basename(__file__):
            continue
        src = open(os.path.join(TESTS, name), encoding="utf-8", errors="ignore").read()
        try:
            tree = ast.parse(src)
        except SyntaxError:  # a broken file is another test's problem
            continue
        skip = _docstring_nodes(tree)
        hits = [n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and id(n) not in skip and _SERVICE_URL.search(n.value)]
        if hits:
            found[name] = hits
    return found


def test_conftest_resolves_both_services():
    """One variable per service, and it actually takes effect."""
    import conftest
    for attr in ("RAG_API", "BFF", "BFF_API"):
        assert hasattr(conftest, attr), f"conftest.{attr} missing"
    assert conftest.BFF_API == conftest.BFF + "/api"
    assert not conftest.RAG_API.endswith("/"), "a trailing slash doubles up on f-string joins"

    # the override is read at import time, so re-import under a patched environ
    import importlib
    old = dict(os.environ)
    try:
        os.environ["TEST_RAG_API"] = "https://example.invalid:8000/"
        os.environ["TEST_BFF"] = "https://example.invalid:3002"
        reloaded = importlib.reload(conftest)
        assert reloaded.RAG_API == "https://example.invalid:8000", \
            "TEST_RAG_API is not honoured — the suite cannot be pointed at another stack"
        assert reloaded.BFF_API == "https://example.invalid:3002/api", \
            "TEST_BFF is not honoured"
    finally:
        os.environ.clear()
        os.environ.update(old)
        importlib.reload(conftest)


def test_no_new_hardcoded_service_urls():
    """A new literal endpoint fails by name."""
    offenders = {f: h for f, h in _hardcoded_by_file().items()
                 if f not in CONTAINER_INTERNAL}
    assert not offenders, (
        "these test files hardcode a service URL instead of importing it:\n  "
        + "\n  ".join(f"{f}: {h[0][:70]!r}" for f, h in sorted(offenders.items()))
        + "\n\nUse the shared endpoints:\n"
          "  from conftest import RAG_API, BFF, BFF_API\n"
          "  BASE = os.environ.get('MY_LEGACY_VAR') or RAG_API\n"
          "If the URL is executed INSIDE a container (`docker exec ...`), it is "
          "correctly literal — declare the file in CONTAINER_INTERNAL with the reason.")


def test_exemptions_are_not_stale():
    """An exemption whose usage is gone is an excuse nobody needs."""
    found = _hardcoded_by_file()
    stale = sorted(f for f in CONTAINER_INTERNAL
                   if not os.path.exists(os.path.join(TESTS, f)) or f not in found)
    assert not stale, (
        "these files are declared CONTAINER_INTERNAL but no longer hardcode a "
        f"service URL — delete the entry: {stale}")


def test_every_exemption_is_really_container_internal():
    """The reason must be checkable, not just stated."""
    for name in CONTAINER_INTERNAL:
        path = os.path.join(TESTS, name)
        if not os.path.exists(path):
            continue
        src = open(path, encoding="utf-8").read()
        assert "docker" in src and "exec" in src, (
            f"{name} is declared container-internal but never runs `docker exec` — "
            "the URL is host-side and belongs in conftest")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
