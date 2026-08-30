"""GET /scans/{job_id} must execute against a real table.

Run on demand:

    SCANS_URL=https://localhost:8000 pytest tests/test_scan_results_endpoint.py

WHY THIS EXISTS
---------------
The handler queried `SELECT * FROM scan_results` — a table that has NEVER been
declared in db_init. So every call raised `relation "scan_results" does not
exist` and returned HTTP 500. It passed `ast.parse`, imported cleanly, the
container was healthy, and the OpenAPI schema listed it — nothing had ever
executed the query. The SQL-column guard skips it precisely because the table is
undeclared, so only running the endpoint catches this class.

The fix repoints it at `scan_runs` (the real per-job record, keyed by job_id).
This test locks that in: a well-formed job_id returns 200 with a `results` list,
NEVER a 500 about a missing relation.

Skips cleanly when the stack is not running.
"""
import os
import re
import pathlib

import pytest

requests = pytest.importorskip("requests")

BASE = os.environ.get("SCANS_URL", "https://localhost:8000")
# A well-formed id that will not match anything -> empty results, not an error.
UNKNOWN_JOB = "smoke-nonexistent-job-0000"


def _key():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _get(job_id):
    try:
        return requests.get(f"{BASE}/scans/{job_id}",
                            headers={"x-api-key": _key()}, timeout=20, verify=False)
    except Exception as e:
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def test_scan_results_does_not_500_on_missing_relation():
    r = _get(UNKNOWN_JOB)
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    # The whole point: no 500, and specifically not the missing-relation error.
    assert r.status_code != 500, f"500 from /scans/{{job_id}}: {r.text[:300]}"
    assert "does not exist" not in r.text, \
        f"endpoint still queries a nonexistent relation: {r.text[:300]}"
    assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text[:200]}"


def test_scan_results_shape():
    r = _get(UNKNOWN_JOB)
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    if r.status_code != 200:
        pytest.skip(f"endpoint returned HTTP {r.status_code}")
    body = r.json()
    assert body.get("job_id") == UNKNOWN_JOB
    assert isinstance(body.get("results"), list), "results must be a list"
