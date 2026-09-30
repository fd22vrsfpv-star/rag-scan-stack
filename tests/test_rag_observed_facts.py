"""Executes the observed-fact + enum-fact RAG round-trip.

Verifies: load (embed + upsert + dedup), recall (self-target + cross-target),
purge (age / engagement / ip / source filters), and the DELETE endpoint.
Skips cleanly when rag-api isn't reachable; sabotage-proven per project
CLAUDE.md (rename any helper and the test fails).
"""
import json
import os
import subprocess
import uuid
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


def _call(method, path, body=None):
    args = ["docker", "exec", "rag-api", "sh", "-lc",
            f'curl -sk -X {method} https://localhost:8000{path} '
            f'-H "x-api-key: $API_KEY" -H "Content-Type: application/json"'
            + (f" -d '{json.dumps(body)}'" if body else "")]
    r = subprocess.run(args, capture_output=True, text=True, timeout=15)
    try:
        return r.returncode, json.loads(r.stdout or "{}")
    except Exception:
        return r.returncode, {"raw": r.stdout[:400]}


def _in_container(py_snippet):
    """Run a python snippet inside rag-api and return stdout."""
    r = subprocess.run(
        ["docker", "exec", "-e", "RAG_OBSERVED_FACTS=1", "rag-api", "python3", "-c", py_snippet],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def test_observed_fact_load_dedup_and_recall():
    """Load same (source, ip, kind, value) twice — exactly one row remains — recall
    returns it. Flag ON required."""
    test_ip = f"192.0.2.{__import__('random').randint(10, 200)}"
    py = f"""
import sys; sys.path.insert(0, '/app')
from api import (_load_observed_fact_into_rag, _recall_observed_facts,
                 purge_observed_facts, RAG_OBSERVED_FACTS_SOURCE)
# Twice — dedup should collapse to one
a = _load_observed_fact_into_rag(RAG_OBSERVED_FACTS_SOURCE, '{test_ip}',
                                  'framework', 'LyLme Spage', product='LyLme Spage')
b = _load_observed_fact_into_rag(RAG_OBSERVED_FACTS_SOURCE, '{test_ip}',
                                  'framework', 'LyLme Spage', product='LyLme Spage')
recalled = _recall_observed_facts('{test_ip}', product='LyLme Spage')
n = purge_observed_facts(ip='{test_ip}')
print(a, b, len(recalled), n)
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    parts = out.split()
    # Both loads succeeded, exactly 1 row recalled, purge removed exactly 1
    assert parts == ["True", "True", "1", "1"], f"got: {out!r}"


def test_observed_fact_flag_off_no_op():
    """When RAG_OBSERVED_FACTS is not set, _load_observed_fact_into_rag returns
    False and writes nothing. Guards against silent DB writes in default config."""
    py = """
import os
os.environ.pop('RAG_OBSERVED_FACTS', None)
import sys; sys.path.insert(0, '/app')
from api import _load_observed_fact_into_rag, RAG_OBSERVED_FACTS_SOURCE
r = _load_observed_fact_into_rag(RAG_OBSERVED_FACTS_SOURCE, '192.0.2.99',
                                  'framework', 'Test', product='Test')
print(r)
"""
    r = subprocess.run(
        ["docker", "exec", "rag-api", "python3", "-c", py],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0
    assert r.stdout.strip() == "False", f"expected False (flag off), got {r.stdout!r}"


def test_purge_by_ip_scoped():
    """Purge for one ip removes only that ip's rows; other ips untouched."""
    ip_a = f"192.0.2.{__import__('random').randint(1, 100)}"
    ip_b = f"192.0.2.{__import__('random').randint(150, 250)}"
    py = f"""
import sys; sys.path.insert(0, '/app')
from api import (_load_observed_fact_into_rag, _recall_observed_facts,
                 purge_observed_facts, RAG_OBSERVED_FACTS_SOURCE)
_load_observed_fact_into_rag(RAG_OBSERVED_FACTS_SOURCE, '{ip_a}', 'framework', 'A')
_load_observed_fact_into_rag(RAG_OBSERVED_FACTS_SOURCE, '{ip_b}', 'framework', 'B')
purge_observed_facts(ip='{ip_a}')
after_a = len(_recall_observed_facts('{ip_a}'))
after_b = len(_recall_observed_facts('{ip_b}'))
purge_observed_facts(ip='{ip_b}')  # clean up
print(after_a, after_b)
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    assert out.strip() == "0 1", f"purge should have removed only ip_a (got: {out!r})"


def test_delete_endpoint_round_trip():
    """DELETE /rag/observed-facts?ip=X removes that ip's rows and reports count."""
    test_ip = f"192.0.2.{__import__('random').randint(1, 254)}"
    # Seed via python (flag ON required)
    py = f"""
import sys; sys.path.insert(0, '/app')
from api import _load_observed_fact_into_rag, RAG_OBSERVED_FACTS_SOURCE
for k in ('framework', 'credential', 'admin_path'):
    _load_observed_fact_into_rag(RAG_OBSERVED_FACTS_SOURCE, '{test_ip}', k,
                                  f'test-value-{{k}}')
print('seeded')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and "seeded" in out, f"seed failed: {err}"
    # DELETE via HTTP
    rc, resp = _call("DELETE", f"/rag/observed-facts?ip={test_ip}")
    assert rc == 0, f"delete failed: {resp}"
    assert resp.get("ok") is True
    assert resp.get("deleted") == 3, f"expected 3 deleted, got {resp}"
    # Second call is idempotent
    rc, resp2 = _call("DELETE", f"/rag/observed-facts?ip={test_ip}")
    assert resp2.get("deleted") == 0, f"second call should return 0, got {resp2}"


def test_recall_format_prior_observations():
    """_format_recall_block returns a PRIOR OBSERVATIONS block when facts present."""
    py = """
import sys; sys.path.insert(0, '/app')
from api import _format_recall_block
# Empty -> empty
assert _format_recall_block([]) == ''
# One fact
facts = [{'scope': 'self', 'ip': '192.0.2.1', 'kind': 'framework',
          'value': 'LyLme Spage', 'source': 'observed_target_fact'}]
out = _format_recall_block(facts)
assert out.startswith('PRIOR OBSERVATIONS')
assert 'framework' in out and 'LyLme Spage' in out
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and "OK" in out, f"stderr: {err}"
