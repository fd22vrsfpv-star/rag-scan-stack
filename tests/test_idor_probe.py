"""Single-credential IDOR / object-reference mutation probe.

Run on demand:  pytest tests/test_idor_probe.py -v

WHY: when we lack a 2nd credential (the two-user path uses ZAP's accessControl
add-on), the authenticated crawl also mutates object-reference ids as the one
logged-in user and flags a potential IDOR when a mutated id returns a distinct,
substantive authenticated response. Numeric GET refs only (safe, low false-positive).

SABOTAGE: remove the mutation loop / the login gate and these fail.
"""
import os
import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PW = os.path.join(REPO, "playwright_scanner", "playwright_scanner.py")


def _src():
    if not os.path.exists(PW):
        pytest.skip("playwright_scanner missing")
    return open(PW, encoding="utf-8").read()


def test_idor_probe_defined_and_wired():
    s = _src()
    assert "async def _idor_mutate_probe" in s, "IDOR probe missing"
    # runs only when authenticated, reusing the crawl's context
    assert 'if job.get("authenticated"):' in s and "_idor_mutate_probe(ctx" in s, \
        "IDOR probe must run in the authenticated crawl context"


def test_idor_probe_mutates_and_records():
    s = _src()
    fn = s[s.index("async def _idor_mutate_probe"):s.index("async def _browser_login")]
    assert "discovered_params" in fn, "candidates come from discovered object-ref params"
    assert "(n + 1, n - 1, n + 2)" in fn, "must mutate the numeric id to neighbours"
    assert "isdigit()" in fn, "only numeric object refs are mutated (safe)"
    assert "sign ?in|log ?in|not authori" in fn, "must exclude login/error pages (false-positive guard)"
    assert "issue_type, name, severity" in fn and "'idor'" in fn, "must record an IDOR web_finding"
