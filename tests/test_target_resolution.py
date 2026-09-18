"""Target/URL resolution: a hostname/URL target resolves to its asset IP so the
IP-keyed port/asset/web-finding queries match (they returned zero for
'demo.testfire.net' because ports/findings are keyed by the resolved IP)."""
import os, re, textwrap
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
def _r(rel):
    p=os.path.join(REPO,rel)
    if not os.path.exists(p): pytest.skip(f"{rel} missing")
    return open(p,encoding="utf-8").read()

def test_target_host_normalizer():
    src=_r("app/rag-api/api.py")
    m=re.search(r"^def _target_host\(.*?(?=^\ndef |^@app)", src, re.S|re.M)
    assert m, "_target_host not found"
    ns={}; exec(textwrap.dedent(m.group(0)), ns); f=ns["_target_host"]
    assert f("http://demo.testfire.net:80/login") == "demo.testfire.net"
    assert f("https://demo.testfire.net/") == "demo.testfire.net"
    assert f("demo.testfire.net") == "demo.testfire.net"
    assert f("192.168.1.150") == "192.168.1.150"

def test_resolve_endpoint_and_ports_hostname_match():
    src=_r("app/rag-api/api.py")
    assert '@app.get("/assets/resolve"' in src
    assert "host(ip) = %s OR lower(hostname) = %s" in src
    # /ports/open matches ip OR hostname
    assert "(host(a.ip)=%s OR lower(a.hostname)=%s)" in src

def test_tools_resolve_target():
    src=_r("autogen_agents/scan_tools.py")
    assert "def _resolve_target_ip" in src and "/assets/resolve" in src
    # all three query tools resolve first
    assert src.count("_resolve_target_ip(target)") >= 3
    assert "get_web_findings(limit, ip=_rip)" in src
