"""Executes the long-transaction read path and the sweep trigger inside the
rag-api container (fresh process, so the FILE in the container is what runs —
`docker cp` is enough, no restart needed). Skips when the stack is not up.

    PYTHONPATH=. python -m pytest tests/test_db_long_transactions_endpoint.py -v
"""
from __future__ import annotations

import json

import pytest

from tests._container import container_exec, ERR

SCRIPT = r'''
import json, os
import api
from fastapi.testclient import TestClient
out = {}
rows = api._db_long_transactions(min_age_min=0, limit=5)
out["rows_executed"] = True
out["n"] = len(rows)
out["keys"] = sorted(rows[0].keys()) if rows else []
c = TestClient(api.app)                      # no `with`: startup daemons are NOT armed
h = {"x-api-key": os.environ.get("API_KEY", "")}
r = c.get("/db/long-transactions", params={"min_age_min": 0, "limit": 3}, headers=h)
out["endpoint_status"] = r.status_code
d = r.json() if r.status_code == 200 else {}
out["watchdog"] = d.get("watchdog")
out["count_le_limit"] = d.get("count", 99) <= 3
# the trigger honours the query form (what the recon agent sends) without queueing a real sweep
api.BackgroundTasks.add_task = lambda self, *a, **k: None
r2 = c.post("/agent/scan", params={"since_minutes": 5}, headers=h)
out["scan_status"] = r2.status_code
out["scan_body"] = r2.json() if r2.status_code == 200 else r2.text[:200]
r3 = c.post("/agent/scan", json={"since_minutes": 0}, headers=h)
out["scan_default"] = r3.json().get("since_minutes") if r3.status_code == 200 else r3.text[:200]
r4 = c.post("/agent/scan", params={"full": "true"}, headers=h)
out["scan_full"] = r4.json().get("since_minutes") if r4.status_code == 200 else r4.text[:200]
print(json.dumps(out))
'''


@pytest.fixture(scope="module")
def result():
    out = container_exec(SCRIPT, timeout=240, timeout_is_error=True)
    if out is None:
        pytest.skip("rag-api container not reachable")
    assert not out.startswith(ERR), out
    return json.loads(out.strip().splitlines()[-1])


def test_long_transactions_query_executes(result):
    assert result["rows_executed"] is True
    if result["n"]:
        for k in ("pid", "client_addr", "xact_age_sec", "state", "query"):
            assert k in result["keys"], k


def test_endpoint_returns_rows_and_watchdog_thresholds(result):
    assert result["endpoint_status"] == 200, result
    assert result["count_le_limit"]
    wd = result["watchdog"]
    assert set(wd) == {"alert_after_min", "terminate_after_min", "interval_sec"}
    assert wd["alert_after_min"] > 0


def test_agent_scan_honours_query_body_and_full(result):
    assert result["scan_status"] == 200, result
    assert result["scan_body"]["since_minutes"] == 5 and result["scan_body"]["full"] is False
    assert result["scan_default"] == 1440        # the periodic trigger's old "0" is now a day, not a year
    assert result["scan_full"] == 525600
