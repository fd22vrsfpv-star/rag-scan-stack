"""A POST-body finding must get a POST/impactful deepen probe (approval lane),
never a dead read-only GET.

Run on demand:

    pytest tests/test_deepen_post_body.py -v

WHY THIS EXISTS
---------------
The deepen path authored a `curl -G` (read-only GET) confirmation probe for a
POST-body SQL injection (e.g. /doLogin uid on testfire). A GET query cannot
reach the vulnerable servlet path, so baseline and injection returned the
identical redirect — the probe could never confirm the finding. deepen_finding
is now METHOD-AWARE: a state-changing (POST/PUT/PATCH/DELETE) finding gets an
IMPACTFUL confirmation (curl -X POST/--data or sqlmap --data), tier='impactful',
which post_enumeration routes to the APPROVAL lane (pending_exploits), never the
safe lane. A read-only GET returned for a state-changing finding is rejected
(fail-closed).

SABOTAGE PROOF
--------------
- Drop the `state_changing and not impactful -> return None` guard in
  deepen_finding and test_get_probe_for_post_finding_is_rejected fails.
- Route an impactful deepen back to scan_recommendations and
  test_impactful_deepen_routes_to_pending_exploits fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROUTER = os.path.join(REPO, "etl", "enumeration_llm_router.py")
POSTENUM = os.path.join(REPO, "etl", "post_enumeration.py")


# ── source guards (always run) ──────────────────────────────────────────────

def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} missing")
    return open(path, encoding="utf-8").read()


def test_deepen_finding_is_method_aware_and_fail_closed():
    src = _src(ROUTER)
    fn = next((n for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.FunctionDef) and n.name == "deepen_finding"), None)
    assert fn, "deepen_finding not found"
    body = ast.get_source_segment(src, fn)
    assert "state_changing" in body, "deepen_finding must branch on the HTTP method"
    assert 'method in ("POST", "PUT", "PATCH", "DELETE")' in body, \
        "deepen_finding must treat POST/PUT/PATCH/DELETE as state-changing"
    # the dead-probe fail-closed reject
    assert "state_changing and not impactful" in body, \
        "a read-only probe for a state-changing finding must be rejected (fail-closed)"
    assert '"tier"' in body, "deepen_finding must return a tier"
    assert "_DEEPEN_IMPACTFUL_TOOLS" in src, "impactful tool allowlist must exist"


def test_impactful_deepen_routes_to_pending_exploits():
    src = _src(POSTENUM)
    assert "def _queue_impactful_deepen" in src, "impactful deepen queue helper missing"
    # helper targets the approval lane, pending status
    helper = next((n for n in ast.walk(ast.parse(src))
                   if isinstance(n, ast.FunctionDef) and n.name == "_queue_impactful_deepen"), None)
    assert helper, "_queue_impactful_deepen not found"
    hbody = ast.get_source_segment(src, helper)
    assert "INSERT INTO pending_exploits" in hbody, "impactful deepen must queue a pending_exploit"
    assert "'pending'" in hbody, "queued pending_exploit must be status pending (needs approval)"
    # both deepen paths branch on the impactful tier
    for fname in ("deepen_web_finding", "_deepen_info_findings"):
        fn = next((n for n in ast.walk(ast.parse(src))
                   if isinstance(n, ast.FunctionDef) and n.name == fname), None)
        assert fn, f"{fname} not found"
        fb = ast.get_source_segment(src, fn)
        assert 'proposal.get("tier") == "impactful"' in fb, \
            f"{fname} must route impactful proposals to the approval lane"
        assert "_queue_impactful_deepen" in fb, f"{fname} must call the impactful queue helper"


# ── behavioural test (skips if the module cannot import here) ────────────────

def _router():
    try:
        import sys
        sys.path.insert(0, os.path.join(REPO, "etl"))
        import enumeration_llm_router as m
    except Exception as e:  # pragma: no cover - infra dependent
        pytest.skip(f"router import unavailable: {e}")
    r = m.EnumerationLLMRouter()
    # stub the LLM plumbing so no backend is needed
    r.route = lambda task: {"enabled": True, "model": "x", "provider": "x"}
    r._within_budget = lambda *a, **k: True
    m._GLOBAL_ENABLED = True
    return r, m


def test_probe_is_impactful_classifier():
    _, m = _router()
    f = m.EnumerationLLMRouter._probe_is_impactful
    assert f("sqlmap -u 'http://x/doLogin' --data 'uid=a' -p uid") is True
    assert f("curl -s -i -X POST --data 'uid=a' http://x/doLogin") is True
    assert f("curl -s -i http://x/page") is False
    # -G makes --data a GET query -> read-only again
    assert f("curl -s -G --data-urlencode 'q=1' http://x/s") is False


def test_get_probe_for_post_finding_is_rejected():
    r, _ = _router()
    # LLM (mis)returns a read-only GET for a POST-body finding -> must be rejected
    r._call_llm = lambda s, u, p: '{"worth": true, "command": "curl -s -i http://x/doLogin", "why": "x"}'
    finding = {"url": "http://x/doLogin", "name": "SQL Injection", "method": "POST",
               "issue_type": "sqli", "param": "uid"}
    assert r.deepen_finding(finding, force=True) is None


def test_post_finding_gets_impactful_probe():
    import json
    r, _ = _router()
    reply = json.dumps({"worth": True,
                        "command": "sqlmap -u 'http://x/doLogin' --data 'uid=a&passw=b' -p uid --batch",
                        "why": "confirm sqli"})
    r._call_llm = lambda s, u, p: reply
    finding = {"url": "http://x/doLogin", "name": "SQL Injection", "method": "POST",
               "issue_type": "sqli", "param": "uid"}
    out = r.deepen_finding(finding, force=True)
    assert out and out["tier"] == "impactful", out
    assert out["command"].startswith("sqlmap")


def test_get_finding_keeps_readonly_safe_probe():
    r, _ = _router()
    r._call_llm = lambda s, u, p: '{"worth": true, "command": "curl -s -i http://x/robots.txt", "why": "x"}'
    finding = {"url": "http://x/robots.txt", "name": "Info disclosure", "method": "GET",
               "issue_type": "information-disclosure"}
    out = r.deepen_finding(finding, force=True)
    assert out and out["tier"] == "safe", out
