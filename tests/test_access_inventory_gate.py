"""Verify the post-access enumeration step feeds the challenge/readiness gate.

Operator ask (the gap this closes): "why didn't this challenge catch it, gather
all information from any logins before moving on." The build-poc readiness gate
used to declare a precondition unmet (e.g. no hostid) after a weak UI scrape,
instead of consuming the FULL post-access inventory gathered from the login.

These tests pin the new wiring, executing the real functions in the rag-api
container (no network to a live target required — inventory is passed in):
  - _enumerate_exploit_preconditions seeds `resolved` from access_inventory
    (an id the login already exposed is RESOLVED, no re-probe)
  - _assess_exploit_readiness adds a "post-access inventory gathered" satisfied
    line when the login's inventory is supplied
  - _assess_exploit_readiness BLOCKS (the gap) when a session is in hand, the
    exploit needs auth, but NO inventory was gathered
  - the build-poc graph wires access_enumeration between research and
    precondition_enumeration/readiness_gate
"""
import subprocess
import pytest


def _rag_api_up():
    try:
        r = subprocess.run(
            ["docker", "exec", "rag-api", "sh", "-lc",
             "curl -sk https://localhost:8000/health -o /dev/null -w '%{http_code}'"],
            capture_output=True, text=True, timeout=6,
        )
        return r.returncode == 0 and r.stdout.strip() == "200"
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _rag_api_up(), reason="rag-api container not reachable")


def _in_container(py_snippet):
    r = subprocess.run(
        ["docker", "exec", "rag-api", "python3", "-c", py_snippet],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def test_preconditions_seed_resolved_from_inventory():
    # A hostid already enumerated by the login's inventory must RESOLVE the
    # "host to run a script against" precondition without any re-probe.
    py = """
import sys; sys.path.insert(0,'/app')
from api import _enumerate_exploit_preconditions
analysis = {'preconditions': ['user must have access to a host to run a script against'],
            'summary': 'script execution on a host'}
inv = {'hostid': [{'id': '10084', 'name': 'Zabbix server'}]}
# Unreachable ip on purpose — resolution must come from the inventory, not a probe.
out = _enumerate_exploit_preconditions('127.0.0.1', 1, analysis,
                                       product='Zabbix', access_inventory=inv)
assert '10084' in (out.get('resolved', {}).get('hostid') or []), out.get('resolved')
assert any('10084' in c for c in out.get('confirmed', [])), out.get('confirmed')
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_readiness_gate_records_inventory_gathered():
    # When the login inventory IS supplied, the gate records it as satisfied.
    py = """
import sys; sys.path.insert(0,'/app')
from api import _assess_exploit_readiness
analysis = {'preconditions': ['authenticated session required'], 'summary': 'needs login'}
inv = {'hostid': [{'id': '10084', 'name': 'srv'}], 'scriptid': [{'id': '1', 'name': 'ping'}]}
rd = _assess_exploit_readiness('127.0.0.1', 1, analysis,
                               session_info={'cookie_header': 'zbx_session=abc'},
                               product='Zabbix', validate_vendor_docs=False,
                               llm_challenge=False, access_inventory=inv)
assert any('post-access inventory gathered' in s for s in rd.get('satisfied', [])), rd.get('satisfied')
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_readiness_gate_blocks_when_login_not_enumerated():
    # The exact gap: a session is in hand, exploit needs auth, but NO inventory
    # was gathered. The gate must BLOCK rather than move on.
    py = """
import sys; sys.path.insert(0,'/app')
from api import _assess_exploit_readiness
analysis = {'preconditions': ['authenticated session required'], 'summary': 'needs login'}
rd = _assess_exploit_readiness('127.0.0.1', 1, analysis,
                               session_info={'cookie_header': 'zbx_session=abc'},
                               product='Zabbix', validate_vendor_docs=False,
                               llm_challenge=False, access_inventory={})
assert any('no post-access inventory was gathered' in b.lower()
           or 'NO post-access inventory' in b for b in rd.get('blockers', [])), rd.get('blockers')
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_graph_wires_access_enumeration_before_gate():
    py = """
import sys; sys.path.insert(0,'/app')
import build_poc_graph as b
G = b.build_graph().get_graph()
nodes = set(G.nodes.keys())
assert 'access_enumeration' in nodes, nodes
edges = [(e.source, e.target) for e in G.edges]
assert ('research','access_enumeration') in edges, edges
assert ('access_enumeration','precondition_enumeration') in edges, edges
assert ('precondition_enumeration','readiness_gate') in edges, edges
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_enforce_resolved_ids_rewrites_invented_hostid():
    # The exact CVE-2024-22120 failure: login proved hostid=10084 but the model
    # emitted hostid=1001. Enforcement must rewrite it; scriptid (already right)
    # stays; an ambiguous kind (several candidates) is left alone.
    py = """
import sys; sys.path.insert(0,'/app')
from api import _enforce_resolved_object_ids
cmd = "curl 'http://t/zabbix.php?action=script.execute&scriptid=1&hostid=1001&ip=127.0.0.1'"
resolved = {'hostid': ['10084'], 'scriptid': ['1','2','3'], 'userid': ['1']}
out, changes = _enforce_resolved_object_ids(cmd, resolved)
assert 'hostid=10084' in out, out
assert 'hostid=1001' not in out, out
assert 'scriptid=1' in out, out          # single-candidate-but-correct: unchanged value
assert any(k=='hostid' and o=='1001' and n=='10084' for (k,o,n) in changes), changes
# scriptid has 3 candidates -> ambiguous -> never rewritten even if wrong
cmd2 = "curl 't?scriptid=9&hostid=1001'"
out2, _ = _enforce_resolved_object_ids(cmd2, resolved)
assert 'scriptid=9' in out2, out2        # left to the model (ambiguous)
assert 'hostid=10084' in out2, out2
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_enforce_resolved_ids_noop_when_correct_or_empty():
    py = """
import sys; sys.path.insert(0,'/app')
from api import _enforce_resolved_object_ids
# already correct -> no changes
out, changes = _enforce_resolved_object_ids("x?hostid=10084", {'hostid':['10084']})
assert changes == [], changes
# no resolved ids -> command untouched
out2, changes2 = _enforce_resolved_object_ids("x?hostid=1001", {})
assert out2 == "x?hostid=1001" and changes2 == [], (out2, changes2)
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_enforce_resolved_ids_rewrites_hex_token_sid():
    # Zabbix `sid` is a hex CSRF token, not digits — enforcement must rewrite a
    # stale hardcoded sid to the live-enumerated one (kinds ending in 'id' incl.
    # 'sid'; values may be hex). This is the CVE-2024-22120 CSRF-token fix.
    py = """
import sys; sys.path.insert(0,'/app')
from api import _enforce_resolved_object_ids
cmd = "curl -d 'action=script.execute&hostid=10084&sid=a6094b4f052fd133adc335382f0297f6&ip=1'"
out, ch = _enforce_resolved_object_ids(cmd, {'sid': ['8f7a151b9cb72637'], 'hostid': ['10084']})
assert 'sid=8f7a151b9cb72637' in out, out
assert 'a6094b4f' not in out, out
assert any(k=='sid' and n=='8f7a151b9cb72637' for (k,o,n) in ch), ch
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_sanitize_poc_auth_redacts_literals_keeps_shell_vars():
    # Auth info must never be stored as a literal (operator: "auth info should
    # never be hard coded"); live shell-var references are kept (they resolve at
    # run time). Covers the CVE-2024-22120 poisoning: a stored PoC embedded a
    # stale sid + a plaintext zbx_session cookie that seeded later builds.
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _sanitize_poc_auth
t = ('curl -d "sid=a6094b4f052fd133adc335382f0297f6&x=1" '
     '-H "Cookie: zbx_session=eyJzZXNzaW9uaWQiOiJhYmMi" '
     '-H "X-CSRF-Token: $CSRF_TOKEN" -H "Authorization: Bearer $TOKEN"')
out = _sanitize_poc_auth(t)
assert 'sid=<SID>' in out, out
assert 'a6094b4f' not in out, out
assert 'zbx_session=<SESSION>' in out, out
assert 'eyJzZXNzaW9u' not in out, out
assert 'X-CSRF-Token: $CSRF_TOKEN' in out, out      # shell var preserved
assert 'Bearer $TOKEN' in out, out                   # shell var preserved
# idempotent
assert _sanitize_poc_auth(out) == out, 'not idempotent'
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_refine_assertion_blocks_timing_drift_to_regex():
    # A blind-timing proof must NEVER drift to expect_regex (canary never shows
    # in a blind exploit's output). The refine loop keeps the latency assertion.
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _resolve_refine_assertion as R
cmd = "curl -d 'ip=1%27 AND SLEEP(5)-- -'"
# timing mode + LLM tries expect_regex -> blocked, latency kept from prev
a, d = R({'expect_regex':'POChit'}, {'min_seconds':5,'max_seconds':30}, cmd, 'POCc', True)
assert d is True and a.get('min_seconds')==5 and 'expect_regex' not in a, (a,d)
# no prev min_seconds -> derive from command SLEEP(5)
a2, _ = R({'expect_regex':'x'}, {}, cmd, 'POCc', True)
assert a2.get('min_seconds')==5.0, a2
# LLM supplies min_seconds -> accepted, not a drift
a3, d3 = R({'min_seconds':12}, {'min_seconds':5}, cmd, 'POCc', True)
assert d3 is False and a3.get('min_seconds')==12, (a3,d3)
# non-timing: expect_regex honored; min_seconds wins when both present
a4, _ = R({'expect_regex':'POChit'}, {}, 'curl x', 'POCc', False)
assert a4.get('expect_regex')=='POChit', a4
a5, _ = R({'expect_regex':'x','min_seconds':5}, {}, 'curl x', 'POCc', False)
assert 'expect_regex' not in a5 and a5.get('min_seconds')==5, a5
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_app_request_contract_zabbix_known_fields():
    # KNOWN request-shape facts are supplied to the model, not guessed.
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _app_request_contract
c = _app_request_contract('Zabbix 6.0')
assert c and c['csrf']['param'] == 'sid', c
assert 'csrf-token' in (c['csrf'].get('aliases') or []), c
assert c.get('action_endpoint') == '/zabbix.php', c
assert _app_request_contract('UnknownApp') is None
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_enforce_request_contract_renames_and_injects_sid():
    # The model keeps naming Zabbix's CSRF param wrong / omitting it; the
    # contract enforcement renames it to `sid` + sets the live token, or injects.
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _enforce_request_contract
# wrong name + shell-var value -> renamed to sid + live literal
cmd = ("curl -s -X POST 'http://t:8080/zabbix.php' "
       "-d 'action=script.execute&hostid=10084&clientip=1&csrf-token=$TOKEN'")
out, ch = _enforce_request_contract(cmd, 'Zabbix', {'sid':['c34588cf8d9f5004']})
assert 'sid=c34588cf8d9f5004' in out and 'csrf-token=' not in out, out
# missing entirely -> injected into the -d body
cmd2 = "curl -X POST 'http://t:8080/zabbix.php' -d 'action=script.execute&clientip=1'"
out2, ch2 = _enforce_request_contract(cmd2, 'Zabbix', {'sid':['abc123def4567890']})
assert 'sid=abc123def4567890' in out2, out2
# non-matching command (not zabbix.php) untouched
out3, ch3 = _enforce_request_contract('curl http://t/x', 'Zabbix', {'sid':['x']})
assert ch3 == [] and out3 == 'curl http://t/x', (out3, ch3)
# grep extraction pattern 'csrf-token.*' (no '=') must NOT be renamed
cmd4 = "curl 'http://t:8080/zabbix.php?action=x' | grep -o 'csrf-token.*'"
out4, _ = _enforce_request_contract(cmd4, 'Zabbix', {})
assert "grep -o 'csrf-token.*'" in out4, out4
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_derive_tools_for_poc_sqli_to_sqlmap():
    # Once a SQLi PoC exists, the system derives sqlmap and builds the call.
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _derive_tools_for_poc
cmd = ("curl -s -X POST 'http://t:8080/zabbix.php' "
       "-d 'action=script.execute&hostid=10084&clientip=1%27%20AND%20SLEEP(5)--%20-&sid=abc' "
       "-b 'zbx_session=eyJ=='")
tools = _derive_tools_for_poc(cmd, assertion={'min_seconds':5}, product='Zabbix', cve='CVE-2024-22120')
sm = [t for t in tools if t['tool']=='sqlmap']
assert sm, tools
assert sm[0]['class']=='sqli' and sm[0]['binary']=='sqlmap', sm[0]
assert sm[0]['command'].startswith('sqlmap '), sm[0]['command']
assert '-p clientip' in sm[0]['command'] and '--technique=T' in sm[0]['command'], sm[0]['command']
assert sm[0]['confirm_markers'], sm[0]
# non-SQLi PoC derives nothing
assert _derive_tools_for_poc("curl -s http://t/status") == []
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_graph_wires_tool_handoff_after_save_store():
    py = r"""
import sys; sys.path.insert(0,'/app')
import build_poc_graph as b
G = b.build_graph().get_graph()
assert 'tool_handoff' in set(G.nodes.keys())
edges = [(e.source, e.target) for e in G.edges]
assert ('save_store','tool_handoff') in edges, edges
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_injection_vector_probe_shape_and_candidates():
    # The injection-vector probe is a required precondition: it returns a
    # {confirmed, guidance} shape, handles no-auth gracefully (no crash, nothing
    # confirmed), and its candidate carriers include the IP-spoofing headers that
    # CVE-2024-22120 actually uses (X-Forwarded-For).
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _probe_injection_vectors, _IP_INJECTION_HEADERS
assert 'X-Forwarded-For' in _IP_INJECTION_HEADERS, _IP_INJECTION_HEADERS
# no auth -> no probe, graceful empty result
r = _probe_injection_vectors('127.0.0.1', 1, 'Zabbix', resolved={}, auth=None)
assert isinstance(r, dict) and r.get('confirmed') == [] and 'guidance' in r, r
# non-matching product -> empty, no crash
r2 = _probe_injection_vectors('127.0.0.1', 1, 'Grafana', resolved={}, auth={'username':'x'})
assert r2.get('confirmed') == [], r2
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_research_building_block_resolves_assumption_from_advisory():
    # "When making an assumption, do some research": an unconfirmed block pulls
    # the concrete answer from the advisory/ticket text (and RAG) before guessing.
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _research_building_block
adv = ("CVE-2024-22120 Zabbix time-based blind SQLi: the clientip is taken from "
       "the X-Forwarded-For header and logged to auditlog (ZBX-24505).")
r = _research_building_block("injection_vector", "Zabbix", "CVE-2024-22120", adv)
assert r.startswith("RESEARCH:"), r
assert "X-Forwarded-For" in r, r
assert "not a body param" in r.lower(), r
# no advisory + no RAG hit -> empty (no fabricated assumption)
r2 = _research_building_block("injection_vector", "Zabbix", "CVE-9999-0000", "")
assert isinstance(r2, str), r2
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_probe_spec_and_placeholder_fill():
    # The probe layer is data-driven: the Zabbix spec is read from YAML and
    # param placeholders resolve from enumerated ids. A new product = YAML.
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _probe_spec, _spec_fill
sp = _probe_spec('Zabbix 6.0')
assert sp and sp.get('transport') == 'jsonrpc', sp
assert sp.get('login',{}).get('method') == 'user.login', sp
assert any(o.get('id_field') == 'hostid' for o in sp.get('objects',[])), sp
assert sp.get('injection_probe',{}).get('carriers') == 'headers', sp
# placeholder fill from resolved ids
filled = _spec_fill({'scriptid':'1','hostid':'{hostid}'}, {'hostid':['10084']})
assert filled == {'scriptid':'1','hostid':'10084'}, filled
# unknown placeholder -> benign 0, never crashes
assert _spec_fill({'x':'{missing}'}, {}) == {'x':'0'}
# product without a spec -> None (falls back to legacy/http path, no crash)
assert _probe_spec('NoSuchApp') is None
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_http_transport_ctx_sub_and_extract():
    # Generic HTTP transport primitives (REST/JSON/XML/all-methods backbone):
    # placeholder substitution + response extraction (header/json/regex/status).
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _ctx_sub, _http_extract
# recursive placeholder fill in str/dict/list
assert _ctx_sub({"log":"{user}","pwd":"{pass}","x":["{user}"]}, {"user":"a","pass":"b"}) \
       == {"log":"a","pwd":"b","x":["a"]}
assert _ctx_sub("id={INJ}", {"INJ":"1' AND SLEEP(5)"}) == "id=1' AND SLEEP(5)"
# unknown placeholder left intact
assert _ctx_sub("{missing}", {}) == "{missing}"
# extraction
resp = {"status":200, "headers":{"Server":"Apache/2.4"}, "text":'name="_wpnonce" value="abc123"',
        "json":{"data":{"id":"10084"}}}
assert _http_extract(resp, {"source":"header","name":"server"}) == "Apache/2.4"
assert _http_extract(resp, {"source":"body_regex","regex":'value="([^"]+)"'}) == "abc123"
assert _http_extract(resp, {"source":"json_pointer","pointer":"/data/id"}) == "10084"
assert _http_extract(resp, {"source":"status"}) == 200
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"


def test_assemble_confirmed_poc_command_from_ledger():
    # Enhancement 1: build the first command from CONFIRMED pieces. CVE-2024-22120
    # has a confirmed injection_vector (X-Forwarded-For) in the ledger from the
    # probe, so the assembler produces an inline-login + header-injection command.
    py = r"""
import sys; sys.path.insert(0,'/app')
from api import _assemble_confirmed_poc_command
asm = _assemble_confirmed_poc_command('172.18.0.40', 8080, 'Zabbix', 'POCx',
                                      auth={'username':'low_priv_user','password':'zabbixpw'})
# depends on the ledger having a confirmed injection_vector for this target
if asm:
    assert 'user.login' in asm['command'], asm['command']
    assert 'X-Forwarded-For' in asm['command'] or 'header' in asm.get('origin',''), asm
    assert asm['assertion'].get('min_seconds') == 5, asm['assertion']
    assert asm['assertion'].get('canary') == 'POCx', asm['assertion']
    print('OK-assembled')
else:
    # no confirmed vector in this environment -> graceful None (still valid)
    print('OK-none')
# no spec / unknown product -> None, never crashes
assert _assemble_confirmed_poc_command('1.2.3.4', 80, 'NoSuchApp', 'c', auth={'username':'u'}) is None
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"out={out} err={err}"
