"""Guard: AD credential tagging + credentialed AD enumeration followup."""
import sys
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "etl")); sys.path.insert(0, str(ROOT))
yaml = pytest.importorskip("yaml")


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_extract_domain():
    from ad_credentials import extract_domain
    assert extract_domain("user@corp.local") == "corp.local"
    assert extract_domain("CORP\\user") == "CORP"
    assert extract_domain("administrator") is None
    assert extract_domain("") is None


def test_tagging_sets_metadata_flag():
    s = _src("etl/ad_credentials.py")
    assert '"ad_credential"] = True' in s
    assert '"domain"] = domain' in s
    # AD if domain-qualified OR host runs DC services (88/389/636)
    assert "IN (88, 389, 636)" in s


def test_credentialed_enum_yaml():
    d = yaml.safe_load((ROOT / "knowledge/ad_attacks.yaml").read_text())["ad_attacks"]
    ce = d["credentialed_enum"]
    names = {t["name"] for t in ce}
    assert "bloodhound-collection" in names and "kerberoast" in names and "ldap-enum" in names
    for t in ce:
        assert t["tier"] == "safe"  # only safe enum auto-runs
        cmd = t["command"]
        # fills cleanly with the followup's placeholders
        cmd.format(domain="corp.local", user="u", password="p", dc_ip="10.0.0.1")


def test_followup_wired_and_safe():
    s = _src("etl/ad_enum_followup.py")
    assert "credentialed_enum" in s
    assert 'tier", "safe")) != "safe"' in s  # skips non-safe
    assert "scan_recommendations" in s and "'ad_enum_followup'" in s
    assert "check_dispatch" in s  # scope-gated
    pe = _src("etl/post_enumeration.py")
    assert "queue_ad_enum_followups(cur, context, out" in pe


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
