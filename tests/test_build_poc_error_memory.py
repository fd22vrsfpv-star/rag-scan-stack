"""2026-10-09: cross-run error memory for the build-PoC refine loop.

Operator: "web applications act in a similar manner with the same payloads, so
we look for similar errors across previous results if it gets stuck."

Pure helpers are AST-loaded from api.py and driven with REAL outputs from the
CVE-2024-22120 trace (tests/fixtures/poc_trace_CVE-2024-22120_refine.jsonl,
cookies scrubbed): 12 of its 15 iterations returned a bare timing number, so
the error lives in the verdict method, not the body. Structural checks pin the
loop wiring (collect → stuck lookup → prompt → flush), the trace phases, the
DDL + health-check lists, the BFF proxy and the UI field — each sabotage-
provable by deleting the named leg.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_build_poc_error_memory.py -v'
"""
from __future__ import annotations

import ast as _ast
import json
import logging
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
FIXTURE = REPO / "tests" / "fixtures" / "poc_trace_CVE-2024-22120_refine.jsonl"


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def _load(names):
    ns: dict = {"logging": logging, "json": json, "_ERR_SIG_MAX": 160,
                "_WAF_FINGERPRINTS": (("网站防火墙", "safedog", "safedog"), ("Request Rejected", "f5", "f5"))}
    for n in names:
        src = _func_src(n)
        assert src, f"{n} missing from api.py"
        exec(src, ns)
    return ns


@pytest.fixture(scope="module")
def fx():
    return _load(["_error_signature", "_command_change_summary", "_render_similar_errors_note",
                  "_redact_command_for_memory"])


@pytest.fixture(scope="module")
def trace():
    return [json.loads(l) for l in FIXTURE.read_text().splitlines() if l.strip()]


# ── real outputs from the 22120 trace ────────────────────────────────────────
OUT_JSON_1 = '\n0.007414\n{"message":"Attack unsuccessful.","status":false}\n'   # iter 1
OUT_JSON_2 = '\n0.007516\n{"message":"Attack unsuccessful.","status":false}\n'   # iter 2
OUT_REFUSE = ("REFUSE: I cannot provide (pre-dispatch detected LLM refusal prose instead of a "
              "shell command): llm refusal detected (not a shell command)")           # iter 3
OUT_TIMING_A = "\n0.010300"                                                        # iter 4
OUT_TIMING_B = "0.007692"                                                          # iter 8
CMD_IT1 = ("COOKIE='zbx_session=REDACTED'; CSRF=$(curl -s -b \"$COOKIE\" 'http://172.18.0.35:8080/zabbix.php?action=script.list' "
           "| grep -oP 'csrf-token[^=]+=\\K[a-f0-9]+' | head -1); curl -s -b \"$COOKIE\" "
           "-H \"X-Forwarded-For: 127.0.0.1' OR SLEEP(5) AND '1'='1\" -H \"Content-Type: application/x-www-form-urlencoded\" "
           "-d \"action=script.execute&scriptid=1&hostid=10084&_csrf_token=$CSRF\" 'http://172.18.0.35:8080/zabbix.php'")
CMD_IT3 = ("curl -sS 'http://172.18.0.35:8080/zabbix.php?action=clientip&clientip=1%27%20AND%20(SELECT%205184%20FROM%20"
           "(SELECT(SLEEP(5)))POCz0d38270d93)%20AND%20%27zq%27=%27zq' -H 'Cookie: zbx_session=REDACTED' "
           "-w '\\n%{time_total}' -o /dev/null")


def test_signature_collapses_per_run_values(fx):
    sig1, tier1 = fx["_error_signature"](OUT_JSON_1, method="latency_too_fast")
    sig2, tier2 = fx["_error_signature"](OUT_JSON_2, method="latency_too_fast")
    assert sig1 == sig2, (sig1, sig2)                      # timing differs, error identical
    assert '"message":"attack unsuccessful."' in sig1
    assert tier1 == tier2 == "latency_too_fast"            # body has no HTTP error → verdict method is the tier
    assert sig1.startswith("-|latency_too_fast|")


def test_bare_timing_outputs_share_a_signature_keyed_on_the_verdict(fx):
    a, ta = fx["_error_signature"](OUT_TIMING_A, method="latency_too_fast")
    b, tb = fx["_error_signature"](OUT_TIMING_B, method="latency_too_fast")
    assert a == b == "-|latency_too_fast|{n}.{n}"
    # without the method the tier is 'other' and the signature is still stable
    c, tc = fx["_error_signature"](OUT_TIMING_A)
    assert tc == "other" and c == "-|other|{n}.{n}"
    assert fx["_error_signature"]("", method="canary_missing") == ("-|canary_missing|", "canary_missing")
    assert fx["_error_signature"]("") == ("", "empty")


def test_tiers_from_real_shapes(fx):
    assert fx["_error_signature"](OUT_REFUSE)[1] == "refusal"
    assert fx["_error_signature"]("/bin/sh: 1: Syntax error: Unterminated quoted string")[1] == "syntax"
    assert fx["_error_signature"]("PRERUN_PROBE_FAIL method=HEAD status=000")[1] == "probe"
    s404, t404 = fx["_error_signature"]("HTTP/1.1 404 Not Found\ncontent-type: text/html\n\n<title>404 Not Found</title>")
    assert t404 == "404" and s404.startswith("404|404|")
    assert fx["_error_signature"]("HTTP/1.1 403 Forbidden\n<h1>Request Rejected</h1>")[1] == "waf"
    assert fx["_error_signature"]("HTTP/1.1 500 Internal Server Error\nFatal error: Uncaught PDOException in /var/www/x.php:12")[1] == "500"
    # canaries / hex / IPs / URLs collapse
    s, _ = fx["_error_signature"]('{"error":"token POCz0d38270d93 not found for http://172.18.0.35:8080/x?id=7a9f3c2b1d4e5f60a1b2c3d4"}')
    assert "{canary}" in s and "{url}" in s and "172.18" not in s and "7a9f3c2b" not in s


def test_change_summary_on_consecutive_real_commands(fx):
    summ = fx["_command_change_summary"](CMD_IT1, CMD_IT3)
    assert "method POST → GET" in summ
    assert "added header cookie" in summ
    assert "clientip" in summ                                # new query param
    assert fx["_command_change_summary"](CMD_IT1, CMD_IT1) == "identical command"
    assert fx["_command_change_summary"](CMD_IT1, "") == "no next command"
    # a path move is named
    assert "path /a.php → /b.php" in fx["_command_change_summary"]("curl http://h/a.php?x=1", "curl http://h/b.php?x=1")
    # a token fetch added is named
    assert "inline token/cookie fetch" in fx["_command_change_summary"]("curl http://h/a.php", "T=$(curl -s http://h/); curl http://h/a.php?t=$T")


def test_redaction_before_storage(fx):
    red = fx["_redact_command_for_memory"]("curl -H 'Cookie: zbx_session=abc123' -d 'password=hunter2&user=x' http://h/")
    assert "abc123" not in red and "hunter2" not in red
    assert "Cookie: REDACTED" in red and "password=REDACTED" in red and "user=x" in red


def test_prompt_note_is_bounded_and_actionable(fx):
    rows = [{"cve": "CVE-2024-22120", "ip": "172.18.0.35", "port": 8080, "iteration": 2, "resolved": True, "verified": True,
             "signature": '-|latency_too_fast|"message":"attack unsuccessful."', "change_summary": "method POST → GET; added param clientip",
             "next_status": "PASSED", "next_command": CMD_IT3},
            {"cve": "CVE-2024-0001", "ip": "10.0.0.2", "port": 80, "iteration": 5, "resolved": False, "verified": False,
             "signature": "-|other|x", "change_summary": "payload value changed", "next_status": "other", "next_command": "curl x"}]
    note = fx["_render_similar_errors_note"](rows)
    assert note.startswith("\nSIMILAR ERRORS SEEN IN OTHER BUILDS")
    assert "RESOLVED→verified" in note and "method POST → GET" in note and "next status: PASSED" in note
    assert "next command (adapt host/path/param to THIS target)" in note     # only the resolved row carries its command
    assert note.count("next command (adapt") == 1
    assert "not resolved" in note
    assert fx["_render_similar_errors_note"]([]) == ""
    assert fx["_render_similar_errors_note"](None) == ""


def test_fixture_is_the_real_scrubbed_trace(trace):
    runs = [e for e in trace if e.get("phase") == "run"]
    assert len(runs) == 15 and not any(e.get("assertion_passed") for e in runs)
    assert not any("eyJzZXNz" in json.dumps(e) for e in trace)      # zbx_session cookies scrubbed
    assert all(e.get("method") == "latency_too_fast" for e in runs)


# ── structural: the wiring, sabotage-provable by deleting a leg ──────────────

def test_refine_loop_collects_looks_up_and_flushes():
    loop = _func_src("_run_refine_poc")
    assert loop
    assert "_err_rows = []" in loop and "_err_rows.append({" in loop
    assert "_error_signature(output, method=verification_method)" in loop
    assert '"error_signature": _sig_now' in loop and '"command": (command or "")[:600]' in loop   # run record carries both now
    assert "_similar_prior_errors(_cur_sig, cve=cve, ip=ip, exclude_run_id=run_id, limit=3)" in loop
    assert "_similar_lookups < 3" in loop and "_cur_sig not in _similar_seen_sigs" in loop       # bounded
    assert "{waf_hit_note}{similar_note}{escalation_guidance}" in loop                              # reaches the prompt
    assert '_poc_trace(run_id, "refine_similar_errors"' in loop
    assert "_record_error_memory(_err_rows, cve, ip, port, eid, run_id, verified)" in loop          # flushed at the end
    # stuck = dup streak, tier streak, or same signature twice
    assert "_refine_dup_streak >= 1" in loop and "any(v >= 2 for v in _status_tier_streak.values())" in loop
    assert '_err_rows[-2]["signature"] == _cur_sig' in loop


def test_memory_writer_and_lookup_contract():
    w = _func_src("_record_error_memory")
    assert w and "ON CONFLICT (run_id, iteration) DO UPDATE" in w
    assert "_redact_command_for_memory(r.get(\"command\"))" in w
    assert 'r.get("status") == "PASSED" or not r.get("signature")' in w          # only failing iterations stored
    assert 'any(x.get("status") == "PASSED" for x in rows[i + 1:])' in w           # resolved = a later pass
    assert 'emit_webhook("build_poc_error_memory_recorded"' in w
    lk = _func_src("_similar_prior_errors")
    assert lk and "similarity(signature, %s)" in lk and "run_id <> %s" in lk
    assert "ORDER BY resolved DESC, verified DESC, (cve = %s) DESC" in lk
    assert "conn.rollback()" in lk                                                  # exact-match fallback without pg_trgm


def test_failure_analysis_and_review_carry_similar_errors():
    fa = _func_src("_build_failure_analysis")
    assert fa and '"similar_prior_errors": similar' in fa and 'get("error_signature")' in fa
    assert "steps.insert(0," in fa
    api = API.read_text()
    assert "### Similar errors in other builds (cross-run error memory)" in api
    assert "| build | iter | tier | what changed next | next status | resolved | sim |" in api


def test_phases_ddl_healthchecks_bff_and_ui_are_wired():
    api = API.read_text()
    k = api[api.index("_KEY_TRACE_PHASES = {"):api.index("_KEY_TRACE_PREFIXES")]
    assert '"refine_similar_errors"' in k and '"error_memory_recorded"' in k
    sql = (REPO / "db_init" / "ensure_all_tables.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS public.build_poc_error_memory" in sql
    assert "UNIQUE (run_id, iteration)" in sql and "gin (signature gin_trgm_ops)" in sql
    assert sql.index("CREATE EXTENSION IF NOT EXISTS pg_trgm") < sql.index("gin_trgm_ops")
    assert '"build_poc_error_memory"' in (REPO / "scripts" / "ensure_db_schema.sh").read_text()
    assert "build_poc_error_memory" in (REPO / "scripts" / "post-install-check.sh").read_text()
    assert "/build-poc/error-memory" in (REPO / "dashboard" / "bff" / "routers" / "exploits.py").read_text()
    assert '@app.get("/build-poc/error-memory"' in api
    ui = (REPO / "dashboard" / "frontend" / "src" / "pages" / "ExploitManager.tsx").read_text()
    assert "similar_prior_errors?: Array<{" in ui and "Similar errors in other builds" in ui
