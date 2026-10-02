"""Verify the build-poc operator-handoff surfaces:
  - /software/cves-without-poc lists asset-software CVEs lacking a stored PoC
  - BuildPocBody accepts target_url and resolves it into ip/port/hint
  - _resolve_target_url: explicit ip/port win over URL-parsed values
  - BuildPocBody.cve is OPTIONAL — endpoint synthesizes NOCVE-<ts> when absent
  - /software/cves-without-poc scope filter honors CIDR / domain / URL via
    etl.scope_gate.is_in_scope (NOT an SQL LIKE) — matches the dispatch gate
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
        capture_output=True, text=True, timeout=15,
    )
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def test_resolve_target_url_parses_full_url():
    py = """
import sys; sys.path.insert(0,'/app')
from api import _resolve_target_url
ip, port, hint = _resolve_target_url('http://172.18.0.35:9090/wp-json/wp/v2/users/1',
                                      None, None, None, None)
assert ip == '172.18.0.35'
assert port == 9090
assert '/wp-json/wp/v2/users/1' in hint
assert 'OPERATOR-SUPPLIED TARGET ENDPOINT' in hint
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_resolve_target_url_explicit_wins():
    py = """
import sys; sys.path.insert(0,'/app')
from api import _resolve_target_url
# Explicit ip + port must override the URL
ip, port, _ = _resolve_target_url('http://url-host/path', '10.0.0.1', 8443, None, None)
assert ip == '10.0.0.1', ip
assert port == 8443, port
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_resolve_target_url_https_default_port():
    py = """
import sys; sys.path.insert(0,'/app')
from api import _resolve_target_url
_, port, _ = _resolve_target_url('https://host/x', None, None, None, None)
assert port == 443
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_cves_without_poc_endpoint_shape():
    """Live endpoint smoke: returns the shape the UI needs. Allowed to be
    empty (zero rows is a real state); only the SHAPE is pinned."""
    r = subprocess.run(
        ["docker", "exec", "rag-api", "sh", "-lc",
         'curl -sk -H "x-api-key: $API_KEY" '
         '"https://localhost:8000/software/cves-without-poc?limit=3"'],
        capture_output=True, text=True, timeout=12,
    )
    assert r.returncode == 0, r.stderr
    import json
    d = json.loads(r.stdout)
    assert "count" in d and "total_candidates" in d and "items" in d
    for item in d["items"]:
        # Each item carries the fields the frontend needs to call /software/build-poc
        for k in ("cve", "ip", "severity", "build_poc_payload"):
            assert k in item, f"missing key {k}: {item}"
        assert item["cve"].startswith("CVE-")
        assert item["build_poc_payload"]["cve"] == item["cve"]


# ─── CVE-optional path ────────────────────────────────────────────────────
# BuildPocBody.cve is Optional[str]; the endpoint synthesizes NOCVE-<ts>
# when absent so run_id/hints stay unique. Validation still rejects a
# non-CVE string and requires some signal (product/url/hint) alongside.

def test_build_poc_cve_optional_in_pydantic_model():
    """BuildPocBody.cve is Optional[str]; empty is OK — endpoint synthesizes
    NOCVE-<ts>. Verifies the Pydantic field is actually optional (not a
    required field we claim is optional in the docstring)."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import BuildPocBody
# Should not raise — cve omitted
b = BuildPocBody(target_url='http://host/x', product='apache')
assert b.cve is None
# Should not raise — cve explicit None
b2 = BuildPocBody(cve=None, product='apache', ip='10.0.0.1')
assert b2.cve is None
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_build_poc_rejects_non_cve_string():
    """A malformed CVE string must 400, not quietly fall through to NOCVE
    synthesis. Guards against operator typos (e.g. 'CVE2024-X') landing
    as a NOCVE-prefixed build."""
    r = subprocess.run(
        ["docker", "exec", "rag-api", "sh", "-lc",
         'curl -sk -o /dev/null -w "%{http_code}" -X POST '
         '-H "x-api-key: $API_KEY" -H "Content-Type: application/json" '
         '-d \'{"cve":"BAD","target_url":"http://172.18.0.32/"}\' '
         '"https://localhost:8000/software/build-poc"'],
        capture_output=True, text=True, timeout=12,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "400", f"expected 400 on bad cve, got {r.stdout}"


def test_build_poc_rejects_missing_target():
    """No ip + no target_url → 400 — fail-fast rather than running a build
    without a target to aim at."""
    r = subprocess.run(
        ["docker", "exec", "rag-api", "sh", "-lc",
         'curl -sk -o /dev/null -w "%{http_code}" -X POST '
         '-H "x-api-key: $API_KEY" -H "Content-Type: application/json" '
         '-d \'{}\' '
         '"https://localhost:8000/software/build-poc"'],
        capture_output=True, text=True, timeout=12,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "400", f"expected 400 on missing target, got {r.stdout}"


# ─── Scope filter uses is_in_scope (not SQL LIKE) ────────────────────────
# The listing endpoint MUST route scope decisions through
# etl.scope_gate.is_in_scope so CIDR / domain-wildcard / URL rules behave
# the same way the dispatch gate does. A `LIKE st.target || '%'` SQL
# filter silently misses CIDR entries (192.168.1.0/24 cannot LIKE-match
# 192.168.1.150) — this test fails if the filter regresses to SQL LIKE.

def test_cves_without_poc_uses_is_in_scope_not_sql_like():
    """Grep the handler body for the call pattern — the Python-side filter
    is the whole reason this endpoint handles CIDR correctly. If a future
    refactor replaces it with an SQL `LIKE st.target || '%'` the CIDR path
    silently stops working; this test is the sabotage-proof backstop."""
    py = r"""
import sys, ast, textwrap; sys.path.insert(0,'/app')
import inspect, api
src = textwrap.dedent(inspect.getsource(api.software_cves_without_poc))

# Walk the AST and collect executable identifiers + call targets ONLY.
# Comments and docstrings don't appear in the AST, so a comment saying
# "we deliberately avoided LIKE st.target" or a docstring explaining the
# scope filter cannot false-trip the guard.
tree = ast.parse(src)
names, calls, strings = set(), set(), set()
for node in ast.walk(tree):
    if isinstance(node, ast.Name):
        names.add(node.id)
    elif isinstance(node, ast.Attribute):
        names.add(node.attr)
    elif isinstance(node, ast.alias):  # import aliases
        names.add(node.asname or node.name.split('.')[-1])
    elif isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
        calls.add(getattr(node.func, 'id', None) or getattr(node.func, 'attr', None))
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        # String literals (SQL fragments, etc.) — docstrings excluded because
        # they attach to a FunctionDef.body[0] as ast.Expr(ast.Constant) and
        # we skip the module/function docstring explicitly below.
        strings.add(node.value)
# Drop function docstring (always body[0] if a Constant string).
fn = tree.body[0]
if (isinstance(fn, ast.FunctionDef) and fn.body
        and isinstance(fn.body[0], ast.Expr)
        and isinstance(fn.body[0].value, ast.Constant)
        and isinstance(fn.body[0].value.value, str)):
    strings.discard(fn.body[0].value.value)

# is_in_scope + load_engagement_scope must be in the CALL set (not just the
# docstring). Allowed names: 'is_in_scope', or the aliased '_is_in_scope'.
assert ('is_in_scope' in calls or '_is_in_scope' in calls), 'is_in_scope not called in code'
assert ('load_engagement_scope' in calls or '_load_eng_scope' in calls), 'load_engagement_scope not called'
# And no SQL fragment contains `LIKE st.target` — would miss CIDR.
for s in strings:
    assert 'LIKE st.target' not in s, f'SQL LIKE on scope_targets regressed: {s!r}'
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_is_in_scope_matches_cidr():
    """Direct contract check on the gate itself: a /24 CIDR entry matches
    hosts inside the network. If this ever stops holding, the scope
    filter above regresses silently with no 500 to notice."""
    py = """
import sys; sys.path.insert(0,'/app')
from etl.scope_gate import is_in_scope
# A /24 contains .150; /25 does not reach .150; wrong network misses.
assert is_in_scope('192.168.1.150', [('192.168.1.0/24', 'cidr')]) is True
assert is_in_scope('192.168.1.150', [('192.168.1.0/25', 'cidr')]) is False
assert is_in_scope('192.168.1.150', [('10.0.0.0/8',     'cidr')]) is False
# Exact IP still works; domain wildcard still works.
assert is_in_scope('192.168.1.150', [('192.168.1.150',  'ip')])   is True
assert is_in_scope('web.example.com', [('example.com',  'domain')]) is True
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_cves_without_poc_accepts_scope_params():
    """`?scope_only=` and `?all_engagements=` are accepted + change behavior
    (default = scope_only on). Pins the plumbing between the frontend
    chips and the backend filter."""
    base = (
        'curl -sk -H "x-api-key: $API_KEY" '
        '-o /dev/null -w "%{http_code}" '
        '"https://localhost:8000/software/cves-without-poc'
    )
    for q in ("?limit=1", "?limit=1&scope_only=false",
              "?limit=1&scope_only=true&all_engagements=true"):
        r = subprocess.run(
            ["docker", "exec", "rag-api", "sh", "-lc", f'{base}{q}"'],
            capture_output=True, text=True, timeout=12,
        )
        assert r.returncode == 0 and r.stdout.strip() == "200", \
            f"query {q!r} → {r.stdout} / {r.stderr}"


# ─── Response time captured on bulk/version runs ──────────────────────────
# For bulk PoC testing (Run-all / Run-selected on the Versions chart),
# per-row response time distinguishes "slow target" from "slow setup".
# Backend adds response_time_ms (listener RTT) + target_response_ms
# (parsed from curl -w %{time_total} when present).

def test_parse_curl_time_total_ms_from_output():
    """`_parse_curl_time_total_ms` parses `curl -w %{time_total}` output
    into milliseconds. Handles bare-float lines (curl default) and the
    __CURL_TIME:<float>s marker we may inject later."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _parse_curl_time_total_ms
# Bare float on its own line (curl -w '%{time_total}\\n' default).
assert _parse_curl_time_total_ms('HTTP/1.1 200 OK\\nhi\\n0.173') == 173
# Marker form (future-proofing for an injected format).
assert _parse_curl_time_total_ms('output\\n__CURL_TIME:1.250s\\n') == 1250
# Nothing timing-shaped → None (empty, big-number guard, non-string).
assert _parse_curl_time_total_ms('just output, no timing') is None
assert _parse_curl_time_total_ms('99999') is None   # above the 300s guard
assert _parse_curl_time_total_ms(None) is None
assert _parse_curl_time_total_ms('') is None
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_run_endpoints_declare_response_time_fields():
    """Grep both run_exploit and run_exploit_version to make sure
    response_time_ms + target_response_ms are present in the return dict —
    the UI depends on them being there in every run row for bulk scans."""
    py = r"""
import sys; sys.path.insert(0,'/app')
import inspect, api
for fn_name in ('run_exploit', 'run_exploit_version'):
    src = inspect.getsource(getattr(api, fn_name))
    assert 'response_time_ms' in src, f'{fn_name} missing response_time_ms'
    assert 'target_response_ms' in src, f'{fn_name} missing target_response_ms'
    assert 'lr.elapsed' in src, f'{fn_name} missing listener-RTT capture'
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"
