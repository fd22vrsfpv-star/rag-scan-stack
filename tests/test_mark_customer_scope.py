"""POST /engagements/{eid}/scope/mark-customer-sites.

Run on demand:

    pytest tests/test_mark_customer_scope.py -v

WHY THIS EXISTS
---------------
Marking a customer site out of scope must (a) actually stop it being scanned —
i.e. REMOVE it from the scanned engagement scope, not just add a global flag —
and (b) NOT distil a `*.domain` rule, because the shared domain (convio.net) is
ours and a domain-wide rule would wrongly drop our own infra. This pins:

  * the host leaves `blackbaud` and lands in `customer_scope` (engagement-scoped);
  * it is also recorded in the global `not_in_scope` list;
  * a scope_decision is captured (learning);
  * the customer-site follow-up is resolved;
  * NO `*.{domain}` classification rule is created.

Creates a throwaway engagement, exercises the live endpoint, asserts, and cleans
up. Skips if the rag-api container / DB is unreachable.
"""
import json
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")

_SCRIPT = r"""
import os, json, urllib3, requests, psycopg2
urllib3.disable_warnings()
c = psycopg2.connect(os.environ["DB_DSN"]); c.autocommit = True
cur = c.cursor()
KEY = os.environ.get("API_KEY", "changeme")
HOST = "pytest-cust.example-test.invalid"
eid = None
try:
    cur.execute("INSERT INTO engagements (name, status) VALUES ('pytest-cust-scope','planning') RETURNING id")
    eid = cur.fetchone()[0]
    cur.execute("INSERT INTO scope_targets (engagement_id,name,target,target_type,source) "
                "VALUES (%s,'blackbaud',%s,'domain','manual')", (eid, HOST))
    cur.execute("INSERT INTO follow_up_items (id,finding_source,title,target,severity,rule_id,status,engagement_id) "
                "VALUES (gen_random_uuid(),'recon',%s,%s,'info','customer_hosted_site','open',%s)",
                ("Customer-hosted site — " + HOST, HOST, eid))

    r = requests.post(f"https://localhost:8000/engagements/{eid}/scope/mark-customer-sites",
                      headers={"x-api-key": KEY}, json={"targets": [HOST]},
                      verify=False, timeout=60)
    status = r.status_code

    cur.execute("SELECT name FROM scope_targets WHERE engagement_id=%s AND target=%s", (eid, HOST))
    names = sorted(x[0] for x in cur.fetchall())
    cur.execute("SELECT 1 FROM scope_targets WHERE engagement_id IS NULL AND name='not_in_scope' AND target=%s", (HOST,))
    global_oos = cur.fetchone() is not None
    cur.execute("SELECT status FROM follow_up_items WHERE target=%s AND rule_id='customer_hosted_site'", (HOST,))
    fu = (cur.fetchone() or [None])[0]
    cur.execute("SELECT 1 FROM scope_decisions WHERE target=%s AND to_scope='customer_scope'", (HOST,))
    decision = cur.fetchone() is not None
    cur.execute("SELECT count(*) FROM scope_classification_rules "
                "WHERE name LIKE '%example-test%' OR conditions->>'pattern' LIKE '%example-test%'")
    rules_created = cur.fetchone()[0]

    print(json.dumps({"status": status, "names": names, "global_oos": global_oos,
                      "fu": fu, "decision": decision, "rules_created": rules_created}))
finally:
    cur.execute("DELETE FROM scope_decisions WHERE target=%s", (HOST,))
    cur.execute("DELETE FROM follow_up_items WHERE target=%s", (HOST,))
    cur.execute("DELETE FROM scope_targets WHERE target=%s", (HOST,))
    if eid:
        cur.execute("DELETE FROM scope_classification_rules WHERE engagement_id=%s", (eid,))
        cur.execute("DELETE FROM engagements WHERE id=%s", (eid,))
"""


def _run(script):
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return f"__ERR__ {out.stderr.strip()[-1200:]}"
    return out.stdout


@pytest.mark.unit
def test_endpoint_declared():
    src = open(API).read()
    assert '@app.post("/engagements/{engagement_id}/scope/mark-customer-sites"' in src \
        or '/scope/mark-customer-sites' in src


def test_mark_customer_sites_roundtrip():
    out = _run("print('ok')")
    if out is None:
        pytest.skip("rag-api container not reachable")
    out = _run(_SCRIPT)
    if out and out.startswith("__ERR__"):
        if "could not connect" in out or "DB_DSN" in out:
            pytest.skip("database not reachable: " + out)
        pytest.fail(out)
    data = json.loads(out.strip().splitlines()[-1])
    assert data["status"] == 200, data
    # host left blackbaud and now lives ONLY in customer_scope
    assert data["names"] == ["customer_scope"], data
    assert data["global_oos"] is True          # global not_in_scope safety
    assert data["fu"] == "resolved"            # follow-up resolved
    assert data["decision"] is True            # learning decision captured
    assert data["rules_created"] == 0          # NO *.domain rule distilled


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
