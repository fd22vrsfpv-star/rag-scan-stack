"""Operator "Deepen this finding": rag-api endpoint + helper + bff proxy exist."""
import os, re
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
def _r(rel):
    p=os.path.join(REPO,rel)
    if not os.path.exists(p): pytest.skip(f"{rel} missing")
    return open(p,encoding="utf-8").read()

def test_rag_api_endpoint():
    s=_r("app/rag-api/api.py")
    assert '@app.post("/findings/{source}/{fid}/deepen"' in s
    assert "deepen_web_finding(fid" in s

def test_post_enumeration_helper():
    s=_r("etl/post_enumeration.py")
    m=re.search(r"def deepen_web_finding\([\s\S]*?(?=\ndef _observe)", s)
    assert m, "deepen_web_finding not found"
    b=m.group(0)
    assert "deepen_finding(fact, force=True)" in b
    assert "check_dispatch" in b and "scan_recommendations" in b  # scope-gated + queued

def test_bff_proxy():
    s=_r("dashboard/bff/routers/findings.py")
    assert '@router.post("/api/findings/{source}/{fid}/deepen")' in s
    assert "/findings/{source}/{fid}/deepen" in s
