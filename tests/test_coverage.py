"""Service-level coverage ledger + engagement stop condition (Phase 1).

The coverage endpoints join ports/assets (enumerated) with tool_executions/
security_tests (tested) and successful exploit_results / passing runs (proven).
That join is exactly the kind that passes ast/import checks and 500s only when a
column is wrong, so this EXECUTES it against the live stack and pins the response
shape. Skips cleanly without a stack.

    COV_URL=https://localhost:8000 pytest tests/test_coverage.py
"""
import os
import re
import pathlib

import pytest

requests = pytest.importorskip("requests")
BASE = os.environ.get("COV_URL", "https://localhost:8000")
REPO = pathlib.Path(__file__).resolve().parents[1]


def _key():
    env = REPO / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _get(path):
    try:
        return requests.get(f"{BASE}{path}", headers={"x-api-key": _key()},
                            timeout=25, verify=False)
    except Exception as e:
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def _an_engagement():
    r = _get("/engagements")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    if r.status_code != 200:
        pytest.skip(f"cannot list engagements (HTTP {r.status_code})")
    data = r.json()
    engs = data.get("engagements") or data.get("items") or data
    if not engs:
        pytest.skip("no engagements to check coverage for")
    return (engs[0].get("id") or engs[0].get("engagement_id"))


def test_coverage_executes_and_has_the_rollup():
    eid = _an_engagement()
    r = _get(f"/coverage/{eid}")
    assert r.status_code == 200, f"coverage 500/err: {r.text[:300]}"
    body = r.json()
    s = body["summary"]
    for k in ("services", "tested", "proven", "untested", "pct_tested", "pct_proven"):
        assert k in s, f"summary missing {k}"
    assert s["tested"] + s["untested"] == s["services"]
    assert isinstance(body.get("services"), list)


def test_complete_is_a_clean_stop_condition():
    eid = _an_engagement()
    r = _get(f"/coverage/{eid}/complete")
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert isinstance(body["complete"], bool)
    assert isinstance(body["remaining"], list)
    # complete iff nothing remains untested
    assert body["complete"] == (len(body["remaining"]) == 0 or body["services"] == 0)
