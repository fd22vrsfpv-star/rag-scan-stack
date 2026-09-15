"""Generic service-credential access: any protocol is capturable, crypt hashes
are NOT logins, and a service-auth marker scores like access.

Run: pytest tests/test_credential_access.py -v
"""
import os, sys
import pytest
REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
ax = pytest.importorskip("etl.access", reason="etl.access not importable")


def test_crypt_hashes_are_not_logins():
    assert ax._is_crypt_hash("$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZj")   # md5crypt
    assert ax._is_crypt_hash("$6$abc$def")                        # sha512
    assert ax._is_crypt_hash("$2y$10$abcdef")                     # bcrypt
    assert not ax._is_crypt_hash("msfadmin")                      # plaintext
    assert not ax._is_crypt_hash("")
    assert not ax._is_crypt_hash(None)


def test_generic_credential_transport_registered():
    assert "credential" in ax.TRANSPORTS


def test_auth_marker_scores_as_access():
    # A service prober returning AUTH_OK is authenticated access, not a shell.
    m = ax._AUTH_RE.search("AUTH_OK user=postgres svc=postgres priv=1")
    assert m and m.group("user") == "postgres" and ax._PRIV_RE.search("AUTH_OK user=postgres svc=postgres priv=1")
    assert ax._REACH_RE.search("REACHABLE svc=vnc (RFB 003.008)")


def test_default_ports_cover_common_services():
    for svc in ("mysql", "postgres", "vnc", "redis", "ftp", "smb", "mssql"):
        assert ax._DEFAULT_PORTS.get(svc)
