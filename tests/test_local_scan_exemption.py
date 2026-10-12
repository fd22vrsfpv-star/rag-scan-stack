"""Stack-local targets may be scanned without a proxy; nothing else may.

`BLOCK_LOCAL_SCANS` refuses an active scan that is not routed through a
proxy/tunnel, so an operator's real source IP cannot be disclosed to a target.
A host on one of the stack's OWN Docker bridges observes a bridge address and
nothing else — no public IP to leak, no third party in the path — so the block
there prevented lab work while protecting no one.

The exemption is deliberately narrow. These must keep REQUIRING a proxy:
  * 10.0.0.0/8 and 192.168.0.0/16 — private, but a client network reached over
    a VPN is exactly where a proxy still matters;
  * any public address;
  * a hostname. Resolving it to decide would be a DNS lookup that itself
    discloses the target, which is what the block protects.

A widened exemption is a silent safety regression — it does not fail loudly,
it just scans unproxied — so this file exists to make it fail by name.

Guards `_is_stack_local_target` + `LOCAL_SCAN_EXEMPT_CIDRS` in
`dashboard/bff/routers/scans.py`.
"""
import ipaddress  # noqa: F401  (used by the extracted source)
import logging
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCANS = os.path.join(REPO, "dashboard", "bff", "routers", "scans.py")


def _load():
    """Exec just the predicate out of scans.py — importing the module pulls in
    the whole BFF."""
    if not os.path.exists(SCANS):
        pytest.skip("scans.py not present")
    src = open(SCANS, encoding="utf-8").read()
    try:
        start = src.index("LOCAL_SCAN_EXEMPT_CIDRS = [")
        end = src.index("def _check_proxy_required")
    except ValueError:
        pytest.skip("local-scan exemption not found in scans.py")
    ns = {"os": os, "log": logging.getLogger("test")}
    exec(compile(src[start:end], SCANS, "exec"), ns)  # noqa: S102
    return ns["_is_stack_local_target"], ns["LOCAL_SCAN_EXEMPT_CIDRS"]


@pytest.mark.parametrize("target", [
    "172.19.21.5",                              # test_net, bare
    "172.19.21.5:9090",                         # host:port
    "http://172.19.21.5:9090/wp-login.php",     # full URL
    "https://172.19.88.23:8443/",               # https + port
    "172.18.0.32",                              # agents_net
    "127.0.0.1",                                # loopback
])
def test_stack_local_targets_are_exempt(target):
    is_local, _ = _load()
    assert is_local(target) is True, f"{target} should not require a proxy"


@pytest.mark.parametrize("target", [
    "10.1.2.3",            # client internal over VPN — a proxy still matters
    "192.168.1.50",        # home/office LAN
    "172.32.0.1",          # outside the exempt /16s though numerically close
    "8.8.8.8",             # public
    "1.1.1.1",             # public
])
def test_other_networks_still_require_a_proxy(target):
    """Private is not the test — being on OUR bridge is."""
    is_local, _ = _load()
    assert is_local(target) is False, (
        f"{target} was exempted from the proxy requirement; the exemption must "
        "cover only the stack's own Docker bridges")


@pytest.mark.parametrize("target", [
    "example.com", "https://example.com/", "target.internal:8080", "", None,
])
def test_hostnames_and_empty_are_not_exempt(target):
    """A hostname must NOT be resolved here — the lookup would itself disclose
    the target to a DNS server, which is what the block guards against."""
    is_local, _ = _load()
    assert is_local(target) is False


def test_exemption_does_not_cover_all_rfc1918():
    """The classic over-broadening. 10/8 and 192.168/16 must not appear."""
    _, cidrs = _load()
    joined = ",".join(cidrs)
    assert "10.0.0.0/8" not in joined, "10/8 exempted — far too broad"
    assert "192.168." not in joined, "192.168/16 exempted — too broad"
    assert "0.0.0.0/0" not in joined, "everything exempted"
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        assert net.prefixlen >= 8, f"{c} is implausibly broad"


def test_call_site_requires_every_target_to_be_local():
    """A list of targets must not ride through unproxied because the FIRST one
    is a lab address."""
    src = open(SCANS, encoding="utf-8").read()
    assert "_all_local" in src, (
        "the scan call site no longer checks that ALL targets are stack-local; "
        "one external host in a list would be scanned unproxied")
    assert "all(_is_stack_local_target(t) for t in _targets)" in src, (
        "the all-targets check was weakened")
