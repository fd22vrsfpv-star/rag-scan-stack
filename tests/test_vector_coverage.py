"""The vector-coverage endpoint executes and reports applicability.

Run on demand:

    pytest tests/test_vector_coverage.py -v
    BFF_BASE=https://localhost:3002/api pytest tests/test_vector_coverage.py

WHY THIS EXISTS
---------------
"Close the loop" means a per-host answer: for each known vector applicable to the
target, did we attempt it and what happened (shell/no_shell/blocked/not_attempted).
GET /coverage/vectors is that surface — a new endpoint, so it must actually
execute (CLAUDE.md: ast.parse passing is not verification). Skips cleanly without
the stack.
"""
import os

import pytest

requests = pytest.importorskip("requests")

BASE = os.environ.get("BFF_BASE", "https://localhost:3002/api")
URL = f"{BASE}/vector-coverage"


def _get(params=None):
    try:
        r = requests.get(URL, params=params or {}, timeout=20, verify=False)
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"coverage endpoint unreachable at {URL}: {type(e).__name__}")
    if r.status_code == 404:                     # pragma: no cover
        pytest.skip("route not present (stack not rebuilt?)")
    if r.status_code >= 500:                     # pragma: no cover
        pytest.fail(f"{URL} returned HTTP {r.status_code}: {r.text[:300]}")
    if r.status_code >= 400:                     # pragma: no cover
        pytest.skip(f"endpoint HTTP {r.status_code} (auth/config)")
    return r.json()


def test_coverage_executes_and_has_shape():
    body = _get()
    assert isinstance(body, dict), body
    assert set(body) >= {"count", "shells", "by_result", "coverage"}, body
    assert isinstance(body["coverage"], list)
    for row in body["coverage"]:
        assert set(row) >= {"target", "vector_id", "result"}, row
        assert row["result"] in (
            "shell", "no_shell", "blocked", "not_attempted", "planned"), row


def test_coverage_filters_by_target():
    body = _get({"target": "203.0.113.199"})   # a target with no coverage rows
    assert body["count"] == 0 and body["coverage"] == [], body
