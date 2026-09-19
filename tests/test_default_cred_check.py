"""Default-credential check on login forms, gated by the max_auto_attempts SETTING.

Run on demand:

    pytest tests/test_default_cred_check.py -v

WHY THIS EXISTS
---------------
A discovered login form must get a bounded default-credential check: try
documented defaults, report any that work, and on success record the credential +
auto-populate an Auth Profile. The check is gated by an operator SETTING
(max_auto_attempts): at/below it the check auto-fires on the safe lane; ABOVE it
the check is queued for approval instead (a large spray never fires unattended).
Candidates are documented defaults, hard-capped by max_total_attempts — never a
brute force.

SABOTAGE PROOF
--------------
- Remove the `len(pairs) > threshold` approval gate and
  test_over_threshold_requires_approval fails.
- Break _is_success and test_success_detection fails.
- Drop the app_login/common merge and test_candidate_pairs_bounded fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MOD = os.path.join(REPO, "etl", "default_cred_check.py")
POSTENUM = os.path.join(REPO, "etl", "post_enumeration.py")
YAML = os.path.join(REPO, "knowledge", "default_cred_check.yaml")
API = os.path.join(REPO, "app", "rag-api", "api.py")


def _src(p):
    if not os.path.exists(p):
        pytest.skip(f"{p} missing")
    return open(p, encoding="utf-8").read()


def _mod():
    import sys
    sys.path.insert(0, os.path.join(REPO, "etl"))
    try:
        import default_cred_check as m
    except Exception as e:  # pragma: no cover
        pytest.skip(f"import unavailable: {e}")
    return m


def test_yaml_has_the_setting():
    import yaml
    d = yaml.safe_load(_src(YAML))["default_cred_check"]
    assert isinstance(d.get("max_auto_attempts"), int), "the threshold SETTING must exist"
    assert isinstance(d.get("max_total_attempts"), int) and d["max_total_attempts"] >= d["max_auto_attempts"]
    assert d.get("app_login"), "app_login default pairs expected"
    assert d.get("followup_tag") == "default_cred_check"


def test_env_overrides_setting(monkeypatch):
    m = _mod()
    monkeypatch.setenv("DEFAULT_CRED_MAX_AUTO_ATTEMPTS", "7")
    assert m.load_cfg()["max_auto_attempts"] == 7


def test_candidate_pairs_bounded():
    m = _mod()
    cfg = m.load_cfg()
    pairs = m.candidate_pairs(8080, cfg)   # 8080 -> tomcat service defaults included
    assert pairs and all(isinstance(t, tuple) and len(t) == 2 for t in pairs)
    assert ("admin", "admin") in pairs, "app_login admin:admin must be a candidate"
    assert len(pairs) <= cfg["max_total_attempts"], "hard cap must bound the set"
    assert len(pairs) == len(set(pairs)), "pairs must be deduped"


def test_success_detection():
    m = _mod()
    markers = ["login", "error"]
    baseline = {"status": 302, "location": "login.jsp?err=1", "cookies": {"jsessionid"}}
    # success: redirect to a non-login page
    ok = {"status": 302, "location": "/bank/main.jsp", "cookies": {"jsessionid"}}
    assert m._is_success(ok, baseline, markers) is True
    # failure: same login redirect as baseline
    bad = {"status": 302, "location": "login.jsp?err=1", "cookies": {"jsessionid"}}
    assert m._is_success(bad, baseline, markers) is False
    # success via a new auth cookie
    cookie = {"status": 200, "location": "", "cookies": {"jsessionid", "altoroaccounts"}}
    assert m._is_success(cookie, baseline, markers) is True


def test_response_parser():
    m = _mod()
    dump = "HTTP/1.1 302 Found\r\nServer: x\r\nSet-Cookie: JSESSIONID=abc; Path=/\r\nLocation: /bank/main.jsp\r\n\r\n"
    r = m._parse_response(dump)
    assert r["status"] == 302 and r["location"] == "/bank/main.jsp" and "jsessionid" in r["cookies"]


def test_over_threshold_requires_approval_gate_present():
    src = _src(MOD)
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_default_cred_check")
    body = ast.get_source_segment(src, fn)
    # auto-submit at most `threshold`; force runs the full set
    assert "run_set = pairs if force else pairs[:threshold]" in body, \
        "the setting must cap how many creds are submitted unattended"
    # a larger set queues the fuller spray for approval
    assert "not force and len(pairs) > threshold" in body, \
        "must queue the fuller spray for approval when candidates exceed the setting"
    assert '"requires_approval": True' in body
    assert "/web-auth" in src, "success must upsert an Auth Profile via /web-auth (keyed by hostname)"
    assert "authenticated_scan" in src, "success must trigger an authenticated scan (Gap 2)"
    assert "credential_findings" in body, "a working default cred must be recorded"


def test_pipeline_resolves_stored_auth_profile():
    """Gap #1: the web_scanner pipeline resolves a stored Auth Profile when the
    caller passed no explicit auth, so the ZAP stage runs authenticated."""
    ws = os.path.join(REPO, "web_scanner", "web_scan.py")
    if not os.path.exists(ws):
        pytest.skip("web_scan.py missing")
    src = open(ws, encoding="utf-8").read()
    assert "def _resolve_scan_auth" in src, "pipeline auth resolver missing"
    assert "if auth is None:" in src and "_resolve_scan_auth(target_url" in src, \
        "pipeline job must resolve a stored profile when no explicit auth is given"
    assert "engagement_id: Optional[str] = None" in src, "pipeline must accept engagement_id"
    assert "credential_findings" in src, "resolver must resolve the secret from credential_findings"


def test_wired_into_post_enum_and_api():
    pe = _src(POSTENUM)
    assert "_default_cred_check_followups(" in pe and "def _default_cred_check_followups" in pe
    api = _src(API)
    assert "/followups/default-cred-check/{rec_id}/approve" in api, "approval endpoint missing"
    assert "force=True" in api, "approval endpoint must run the check forced"
