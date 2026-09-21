"""Guard: AD tools in the kali install list ('install ad tools') + AD enum rules."""
import re
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _ast_assert import const_elements  # noqa: E402

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
    """The manifest is a SET constant — read it, don't grep the file. A quoted
    tool name also appears in comments and in the safe-lane set, so a substring
    search proves nothing about which set the tool is actually in."""
    manifest = const_elements(ROOT / "kali_listener/listener_service.py",
                              "_FALLBACK_ALLOWED_TOOLS")
    assert manifest, "_FALLBACK_ALLOWED_TOOLS not found"
    for t in ("responder", "mitm6", "certipy", "ldeep", "kerbrute", "secretsdump", "ticketer"):
        assert t in manifest, f"{t} missing from the kali install manifest"


def test_safe_ad_enum_tools_on_readonly_lane():
    """Read-only AD enum may run without approval; offensive AD tooling may not.

    This used to slice the file between two marker strings and grep the slice —
    which silently passes if either marker is edited. The set is right there.
    """
    safe = const_elements(ROOT / "kali_listener/listener_service.py",
                          "_SAFE_READONLY_TOOLS")
    assert safe, "_SAFE_READONLY_TOOLS not found"
    for t in ("ldeep", "kerbrute", "bloodhound-python", "GetUserSPNs", "GetNPUsers"):
        assert t in safe, f"{t} should be runnable on the no-approval lane"
    for t in ("secretsdump", "ticketer", "responder", "ntlmrelayx", "mitm6"):
        assert t not in safe, f"{t} must NOT be on the safe lane"


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
