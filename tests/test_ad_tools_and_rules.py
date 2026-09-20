"""Guard: AD tools in the kali install list ('install ad tools') + AD enum rules."""
import re
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
yaml = pytest.importorskip("yaml")


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# a representative set that MUST be installable + grouped
AD_TOOLS = ["responder", "mitm6", "impacket", "netexec", "bloodhound-python",
            "certipy", "ldeep", "kerbrute", "lsassy", "hashcat", "coercer"]


def test_ad_tools_in_install_map():
    s = _src("dashboard/bff/routers/assets.py")
    for t in AD_TOOLS:
        assert f'"{t}":' in s, f"{t} missing from TOOL_INSTALL_MAP"
    # an 'ad' install group + endpoint
    assert "TOOL_GROUPS" in s and '"ad":' in s
    assert '"label": "AD tools"' in s
    assert "/api/tools/groups" in s


def test_ad_tools_in_kali_manifest():
    s = _src("kali_listener/listener_service.py")
    for t in ("responder", "mitm6", "certipy", "ldeep", "kerbrute", "secretsdump", "ticketer"):
        assert f'"{t}"' in s, f"{t} missing from kali manifest"


def test_safe_ad_enum_tools_on_readonly_lane():
    s = _src("kali_listener/listener_service.py")
    # read-only AD enum allowed on the no-approval lane
    for t in ("ldeep", "kerbrute", "bloodhound-python", "GetUserSPNs", "GetNPUsers"):
        assert f'"{t}"' in s
    # offensive AD tools must NOT be on the safe lane (checked by absence in the
    # _SAFE_READONLY_TOOLS block specifically)
    safe_block = s[s.index("_SAFE_READONLY_TOOLS = {"):s.index("def get_safe_execution_tools")]
    for t in ("secretsdump", "ticketer", "responder", "ntlmrelayx", "mitm6"):
        assert f'"{t}"' not in safe_block, f"{t} must NOT be on the safe lane"


def test_ad_enum_rules_present_and_safe():
    rules = yaml.safe_load(_src("knowledge/enumeration_rules.yaml"))["rules"]
    ad = [r for r in rules if str(r.get("id", "")).startswith("ad-")]
    assert len(ad) >= 3
    ids = {r["id"] for r in ad}
    assert "ad-dc-kerberos-detected" in ids and "ad-ldap-anonymous-enum" in ids
    for r in ad:
        assert r["when"]["fact"] == "open_port"
        # fires on DC/LDAP ports, only needs {target}, uses a safe-lane tool
        assert r["when"]["where"]["port"] in (88, 389, 636)
        assert r["propose"]["tool"] in ("enum4linux-ng", "ldapsearch")
        assert "{target}" in r["propose"]["command"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
