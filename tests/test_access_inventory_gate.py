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
