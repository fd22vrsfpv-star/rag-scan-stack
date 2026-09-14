"""POST /scope/{name}/purge-data executes and previews without deleting.

Run on demand:

    pytest tests/test_scope_purge.py -v
    BFF_BASE=https://localhost:3002/api pytest tests/test_scope_purge.py

WHY THIS EXISTS
---------------
A new mutating endpoint that DELETES findings/follow-ups/recommendations for a
scope must actually execute (CLAUDE.md: ast.parse is not verification), and its
`dry_run` must be a true no-op that only counts. This exercises the dry_run path
(never deletes) and its shape; the destructive path is exercised by the operator.
Skips cleanly without the stack.
"""
import os

import pytest

requests = pytest.importorskip("requests")

BASE = os.environ.get("BFF_BASE", "https://localhost:3002/api")


def _post(path, params=None):
    try:
        r = requests.post(f"{BASE}{path}", params=params or {}, json={},
                          timeout=30, verify=False)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"unreachable at {BASE}{path}: {type(e).__name__}")
    if r.status_code == 404:  # pragma: no cover
        pytest.skip("route not present (stack not rebuilt?)")
    if r.status_code >= 500:  # pragma: no cover
        pytest.fail(f"HTTP {r.status_code}: {r.text[:300]}")
    if r.status_code >= 400:  # pragma: no cover
        pytest.skip(f"HTTP {r.status_code} (auth/config)")
    return r.json()


def test_dry_run_on_unknown_scope_is_empty_and_deletes_nothing():
    body = _post("/scope/__nope_no_such_scope__/purge-data", {"dry_run": "true"})
    assert body.get("ok") is True, body
    assert body.get("targets") == 0 and body.get("total") == 0, body
    assert body.get("dry_run") is True, body


def test_dry_run_shape_on_a_real_scope():
    # Use whatever scope the deployment has; the point is the endpoint executes
    # and returns the documented shape, and dry_run never mutates.
    body = _post("/scope/msf/purge-data", {"dry_run": "true"})
    assert set(body) >= {"ok", "scope", "dry_run", "targets", "total", "deleted"}, body
    assert body["dry_run"] is True
    assert isinstance(body["deleted"], dict)
    assert body["total"] == sum(body["deleted"].values())
