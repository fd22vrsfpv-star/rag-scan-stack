"""Agent-to-agent feedback channel: flag -> approve -> scope-gated run.

Run on demand:

    pytest tests/test_agent_flags.py -v

WHY THIS EXISTS
---------------
An agent flags something worth another run; approving the flag must enqueue a
scan_recommendation ONLY for an in-scope, resolvable target. Pins the
authorization invariant: an out-of-scope / unresolvable flag is REFUSED
('acknowledged'), never queued. Runs in the rag-api container and rolls back.
"""
import json
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MOD = os.path.join(REPO, "app", "rag-api", "agent_flags.py")


def _run(script):
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return f"__ERR__ {out.stderr.strip()[-1200:]}"
    return out.stdout


@pytest.mark.unit
def test_module_and_endpoints_exist():
    assert os.path.exists(MOD)
    api = open(os.path.join(REPO, "app", "rag-api", "api.py")).read()
    assert '@app.post("/agent-flags"' in api
    assert '/agent-flags/{flag_id}/approve' in api


_ROUNDTRIP = r"""
import os, json, psycopg2
from psycopg2.extras import RealDictCursor
import agent_flags as af
c = psycopg2.connect(os.environ["DB_DSN"]); cur = c.cursor(cursor_factory=RealDictCursor)
out = {}
try:
    # in-scope host with a known IP (from a real engagement asset)
    cur.execute("SELECT hostname, host(ip) ip, engagement_id FROM assets "
                "WHERE hostname IS NOT NULL AND ip IS NOT NULL AND engagement_id IS NOT NULL LIMIT 1")
    a = cur.fetchone()
    if a:
        flag = {"id": "00000000-0000-0000-0000-000000000001", "engagement_id": a["engagement_id"],
                "data": {"target": a["hostname"], "scanner": "nuclei", "template": "cves"}}
        r_ok = af.enqueue_from_flag(cur, flag)
        out["in_scope_status"] = r_ok["status"]
    # unresolvable / out-of-scope target -> refused
    flag2 = {"id": "00000000-0000-0000-0000-000000000002", "engagement_id": a["engagement_id"] if a else None,
             "data": {"target": "definitely-not-ours.example", "scanner": "nuclei"}}
    r_bad = af.enqueue_from_flag(cur, flag2)
    out["oos_status"] = r_bad["status"]
    out["oos_reason"] = r_bad.get("reason")
    # missing scanner -> refused
    r_ns = af.enqueue_from_flag(cur, {"id": "x", "engagement_id": None, "data": {"target": "h"}})
    out["no_scanner_status"] = r_ns["status"]
    print(json.dumps(out))
finally:
    c.rollback(); c.close()
"""


def test_enqueue_scope_gate():
    if _run("print('ok')") is None:
        pytest.skip("rag-api container not reachable")
    body = _run(_ROUNDTRIP)
    if body and body.startswith("__ERR__") and ("connect" in body or "DB_DSN" in body):
        pytest.skip("db not reachable")
    assert body and not body.startswith("__ERR__"), body
    data = json.loads(body.strip().splitlines()[-1])
    # in-scope resolvable target -> queued
    if "in_scope_status" in data:
        assert data["in_scope_status"] == "acted"
    # out-of-scope / unresolvable -> refused, never queued
    assert data["oos_status"] == "acknowledged"
    assert data["no_scanner_status"] == "acknowledged"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
