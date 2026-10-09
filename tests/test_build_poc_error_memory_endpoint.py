"""2026-10-09: the cross-run error memory EXECUTES end-to-end inside rag-api.

Flushes three iterations of a synthetic build (two failures, then a pass)
through `_record_error_memory`, looks the first failure up from a DIFFERENT
run id with a cosmetically different signature (pg_trgm similarity), reads it
back through `GET /build-poc/error-memory` (similar-lookup and listing modes)
via FastAPI's TestClient, checks redaction, and deletes the rows. Skips (does
not fail) when the container is unreachable or still runs an api.py that
predates the feature (hot-copy pending).

    pytest tests/test_build_poc_error_memory_endpoint.py -v
"""
from __future__ import annotations

import json

import pytest

from _container import container_exec

SCRIPT = r'''
import sys, os, json
sys.path.insert(0, "/app")
import api
if not hasattr(api, "_record_error_memory") or not hasattr(api, "list_build_poc_error_memory"):
    print("__SKIP__ container api.py predates build_poc_error_memory (hot-copy pending)")
    raise SystemExit(0)
from fastapi.testclient import TestClient
out = {}
RUN_A, RUN_B = "TEST-errmem-a-7c1", "TEST-errmem-b-7c1"
api._ensure_build_poc_error_memory_table()        # fresh install: the table is created on first use
with api.get_db() as conn, conn.cursor() as cur:
    cur.execute("DELETE FROM build_poc_error_memory WHERE run_id LIKE 'TEST-errmem-%%'"); conn.commit()
sig_fail, tier = api._error_signature('\n0.007414\n{"message":"Attack unsuccessful.","status":false}\n', method="latency_too_fast")
rows = [
  {"iteration": 1, "signature": sig_fail, "tier": tier, "status": tier,
   "command": "curl -s -b 'zbx_session=SECRETCOOKIE' -d 'action=script.execute&scriptid=1' 'http://10.255.255.9:8080/zabbix.php'"},
  {"iteration": 2, "signature": sig_fail, "tier": tier, "status": tier,
   "command": "curl -s -H 'Cookie: zbx_session=SECRETCOOKIE' 'http://10.255.255.9:8080/zabbix.php?action=clientip&clientip=1'"},
  {"iteration": 3, "signature": "", "tier": "passed", "status": "PASSED",
   "command": "curl -s -H 'Cookie: zbx_session=SECRETCOOKIE' 'http://10.255.255.9:8080/zabbix.php?action=clientip&clientip=1%27%20AND%20SLEEP(5)--' -w '%{time_total}'"},
]
out["written"] = api._record_error_memory(rows, "cve-0000-0002", "10.255.255.9", 8080, None, RUN_A, True)
# lookup from another run: same error, cosmetically different output (digits differ) -> same signature
sig_other, _ = api._error_signature('\n0.009911\n{"message":"Attack unsuccessful.","status":false}\n', method="latency_too_fast")
out["same_signature"] = (sig_other == sig_fail)
hits = api._similar_prior_errors(sig_other, cve="CVE-0000-0002", exclude_run_id=RUN_B, limit=5)
mine = [h for h in hits if h.get("run_id") == RUN_A]
out["hits_mine"] = len(mine)
first = mine[0] if mine else {}
out["first_resolved"] = first.get("resolved"); out["first_verified"] = first.get("verified")
out["first_iteration"] = first.get("iteration")                       # ranking: resolved rows first; both resolved -> recency/sim tie
out["change_summaries"] = sorted(str(h.get("change_summary")) for h in mine)
out["redacted"] = all("SECRETCOOKIE" not in json.dumps(h, default=str) for h in mine)
out["self_excluded"] = not any(h.get("run_id") == RUN_A for h in api._similar_prior_errors(sig_fail, exclude_run_id=RUN_A, limit=5))
# fuzzy: a trailing variation still matches via trigram similarity
fuzzy = api._similar_prior_errors(sig_fail[:-3] + 'x."', exclude_run_id=RUN_B, limit=5)
out["fuzzy_hit"] = any(h.get("run_id") == RUN_A for h in fuzzy)
note = api._render_similar_errors_note(mine)
out["note_ok"] = ("SIMILAR ERRORS SEEN IN OTHER BUILDS" in note) and ("RESOLVED→verified" in note)
c = TestClient(api.app)
h = {"x-api-key": os.environ.get("API_KEY", "")}
r = c.get("/build-poc/error-memory", params={"signature": sig_other, "cve": "CVE-0000-0002"}, headers=h)
out["lookup_status"] = r.status_code
out["lookup_scope"] = r.json().get("scope") if r.status_code == 200 else None
out["lookup_has_row"] = any(x.get("run_id") == RUN_A for x in (r.json().get("rows") or [])) if r.status_code == 200 else None
r2 = c.get("/build-poc/error-memory", params={"cve": "CVE-0000-0002", "all_engagements": "true"}, headers=h)
out["list_status"] = r2.status_code
out["list_scope"] = r2.json().get("scope") if r2.status_code == 200 else None
out["list_count_mine"] = sum(1 for x in (r2.json().get("rows") or []) if x.get("run_id") == RUN_A) if r2.status_code == 200 else None
with api.get_db() as conn, conn.cursor() as cur:
    cur.execute("DELETE FROM build_poc_error_memory WHERE run_id LIKE 'TEST-errmem-%%'"); conn.commit()
print(json.dumps(out, default=str))
'''


@pytest.fixture(scope="module")
def result():
    out = container_exec(SCRIPT, timeout=180, timeout_is_error=True)
    if out is None:
        pytest.skip("rag-api container unreachable")
    if "__SKIP__" in out:
        pytest.skip(out.strip().splitlines()[-1])
    if out.startswith("__ERR__"):
        pytest.fail(out[:1500])
    line = [ln for ln in out.strip().splitlines() if ln.startswith("{")][-1]
    return json.loads(line)


def test_writer_stores_only_failing_iterations_with_resolution(result):
    assert result["written"] == 2, result                      # iteration 3 passed -> not a memory row
    assert result["same_signature"] is True
    assert result["hits_mine"] == 2
    assert result["first_resolved"] is True and result["first_verified"] is True
    assert result["redacted"] is True
    assert result["self_excluded"] is True


def test_change_summary_names_what_the_next_command_did(result):
    joined = " || ".join(result["change_summaries"])
    assert "method POST → GET" in joined                        # iter 1 -> 2
    assert "url-encoded payload" in joined                      # iter 2 -> 3


def test_fuzzy_match_and_prompt_note(result):
    assert result["fuzzy_hit"] is True
    assert result["note_ok"] is True


def test_endpoint_lookup_and_listing_modes(result):
    assert result["lookup_status"] == 200 and result["lookup_scope"] == "similar_lookup"
    assert result["lookup_has_row"] is True
    assert result["list_status"] == 200 and result["list_scope"] == "all_engagements"
    assert result["list_count_mine"] == 2
