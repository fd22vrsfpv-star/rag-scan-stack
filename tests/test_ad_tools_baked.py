"""Guard: AD tools are baked into the local kali image (local enumeration)."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_bakes_ad_toolkit():
    df = (ROOT / "kali_listener/Dockerfile").read_text()
    # core AD toolkit present in the image build (apt or pip/binary)
    for t in ("responder", "mitm6", "evil-winrm", "ldeep", "bloodhound.py",
              "bloodyad", "certipy-ad", "kerbrute", "lsassy", "pcredz"):
        assert t in df, f"{t} not baked into kali Dockerfile"
    # git baked so git+ AD installs resolve; certipy symlinked to the yaml name
    assert "git " in df and "pipx" in df
    assert "certipy" in df
    # already-present AD tools (earlier blocks)
    for t in ("netexec", "impacket-scripts", "enum4linux-ng", "smbmap",
              "ldap-utils", "hashcat", "crackmapexec"):
        assert t in df


if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-v"]))
