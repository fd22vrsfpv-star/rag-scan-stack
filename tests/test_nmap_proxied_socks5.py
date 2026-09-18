"""Proxied nmap routes through the selected node via proxychains4 (socks5 + DNS)
and -Pn — not nmap's socks4-only --proxies. The socks4 downgrade against the
socks5 nodes failed every connect, so an internet target scanned 'through the
selected node' came back entirely closed."""
import os, re
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def _fn():
    src = open(os.path.join(REPO, "nmap_scanner", "nmap-api.py"), encoding="utf-8").read()
    m = re.search(r"def _run_nmap_proxied_async\([\s\S]*?(?=\ndef )", src)
    assert m, "_run_nmap_proxied_async not found"
    return m.group(0)

def test_uses_proxychains_socks5_and_pn():
    b = _fn()
    assert "proxychains4" in b and 'proxy_dns' in b
    # socks5 preserved (not force-downgraded to socks4 as the primary path)
    assert '"socks5"' in b
    assert '"-Pn"' in b, "must add -Pn (SOCKS can't carry host-discovery pings)"
    # proxychains command drops nmap's own --proxies
    assert re.search(r'"proxychains4"[\s\S]{0,200}"nmap", "-sT", "-Pn"', b)

def test_socks4_only_as_fallback():
    b = _fn()
    # the socks4 downgrade survives ONLY as a fallback when proxychains4 is absent
    assert "use_proxychains" in b
    assert b.index("use_proxychains") < b.index('replace("socks5://", "socks4://")')
