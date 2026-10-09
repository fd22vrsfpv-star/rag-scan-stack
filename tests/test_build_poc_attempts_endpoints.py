"""2026-10-09: the build-poc attempts endpoints EXECUTE (not just import).

Writes a synthetic attempt row inside the rag-api container, reads it back
through the three endpoints via FastAPI's TestClient, asserts the review.md
carries the failure-analysis section, and deletes the row. Skips (does not
fail) when the container is unreachable or still runs an api.py that predates
the feature (hot-copy pending).

    pytest tests/test_build_poc_attempts_endpoints.py -v
"""
from __future__ import annotations

import json

import pytest

from _container import container_exec

SCRIPT = r'''
import sys, os, json
sys.path.insert(0, "/app")
import api
if not hasattr(api, "_record_build_poc_attempt") or not hasattr(api, "export_build_poc_attempt_review_md"):
    print("__SKIP__ container api.py predates build_poc_attempts (hot-copy pending)")
    raise SystemExit(0)
from fastapi.testclient import TestClient
run_id = "TEST-attempts-endpoint-9f1"
fa = {"schema": 1, "run_id": run_id, "stage_reached": "gather", "stop_reason": "gather_incomplete:input_field",
      "verified": False, "iterations": 0, "missing": ["input_field"], "endpoint": "/admin/dict.php",
      "method": "GET,POST", "input_field": None, "vuln_class": "sqli",
      "blockers": [{"item": "input_field", "why": "no field", "what_live_recon_found": "arjun honored 2 params on /admin/dict.php",
                    "candidate_values": ["sortfield", "sortorder"], "suggested_manual_step": "inject via sortfield"}],
      "tried": [], "recon_inventory": {"urls": ["/support/index.php"], "params_by_path": {"/admin/dict.php": ["sortfield", "sortorder"]},
                                        "forms": [], "session": {"attempted": True, "method": "supplied", "ok": True, "creds_supplied": True}},
      "llm": {"models_used_by_phase": {}, "fallback_errors": [], "judge": {}},
      "next_steps_deterministic": ["Inject via `sortfield` on `/admin/dict.php`"],
      "narrative": "TEST narrative", "ranked_next_steps": [{"step": "Inject via sortfield", "why": "arjun honored it", "how": "GET /admin/dict.php?sortfield=1'"}],
      "confidence": 0.7, "llm_model": "test-model"}
rid = api._record_build_poc_attempt(run_id=run_id, cve="CVE-0000-0001", ip="10.255.255.1", port=9090, eid=None,
                                    verified=False, stage_reached="gather", stop_reason="gather_incomplete:input_field",
                                    missing=["input_field"], gather_manifest={"missing": ["input_field"], "facts": {"endpoint": "/admin/dict.php"}},
                                    live_recon={"crawl_urls": ["/support/index.php"], "arjun_params": {"/admin/dict.php": ["sortfield", "sortorder"]}},
                                    summary={"framework": "Dolibarr"}, failure_analysis=fa, poc_log_path="/nonexistent.jsonl", llm_model="test-model")
assert rid, "upsert returned no id"
c = TestClient(api.app)
h = {"x-api-key": os.environ.get("API_KEY", "")}
out = {}
r = c.get("/build-poc/attempts", params={"cve": "CVE-0000-0001", "all_engagements": "true"}, headers=h)
out["list_status"] = r.status_code
out["list_has_row"] = any(a.get("run_id") == run_id for a in (r.json().get("attempts") or [])) if r.status_code == 200 else None
r2 = c.get(f"/build-poc/attempts/{run_id}", headers=h)
out["detail_status"] = r2.status_code
out["detail_stage"] = (r2.json().get("attempt") or {}).get("stage_reached") if r2.status_code == 200 else None
out["detail_fa_conf"] = ((r2.json().get("attempt") or {}).get("failure_analysis") or {}).get("confidence") if r2.status_code == 200 else None
r3 = c.get(f"/build-poc/attempts/{run_id}/export/review.md", headers=h)
out["md_status"] = r3.status_code
body = r3.text if r3.status_code == 200 else ""
out["md_has_section"] = "## Failure analysis" in body
out["md_has_blocker"] = "arjun honored 2 params" in body
out["md_has_step"] = "Inject via sortfield" in body
out["md_has_live_recon"] = "Live recon (this run)" in body and "/support/index.php" in body
out["md_disposition"] = r3.headers.get("content-disposition", "")
# redaction: a cookie must never land in the row
rid2 = api._record_build_poc_attempt(run_id=run_id + "-redact", cve="CVE-0000-0001", ip="10.255.255.1", port=9090,
                                     summary={"session": {"cookie_header": "SECRET=1", "method": "supplied"}})
r4 = c.get(f"/build-poc/attempts/{run_id}-redact", headers=h)
out["redacted"] = (r4.json()["attempt"]["summary"]["session"]["cookie_header"] == "[redacted]") if r4.status_code == 200 else None
with api.get_db() as conn, conn.cursor() as cur:
    cur.execute("DELETE FROM build_poc_attempts WHERE run_id IN (%s, %s)", (run_id, run_id + "-redact"))
    conn.commit()
print(json.dumps(out))
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


def test_list_endpoint_executes_and_returns_the_row(result):
    assert result["list_status"] == 200 and result["list_has_row"] is True, result


def test_detail_endpoint_returns_the_analysis(result):
    assert result["detail_status"] == 200 and result["detail_stage"] == "gather", result
    assert result["detail_fa_conf"] == 0.7, result


def test_attempt_review_md_has_failure_analysis_and_live_recon(result):
    assert result["md_status"] == 200, result
    assert result["md_has_section"] and result["md_has_blocker"] and result["md_has_step"], result
    assert result["md_has_live_recon"], result
    assert "attempt-review.md" in result["md_disposition"], result


def test_session_cookies_are_redacted_in_the_row(result):
    assert result["redacted"] is True, result
