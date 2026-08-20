"""Dispatch must refuse targets outside the engagement scope.

Run on demand:

    pytest tests/test_dispatch_scope.py -v

WHY THIS EXISTS
---------------
Dispatch had no scope check at all. Recommendations are generated from whatever
hosts turn up in scan output, so a redirect or a certificate SAN can put a third
party's address into the queue — and 14 recommendations targeting Cloudflare
addresses (104.20.44.163, 172.66.0.227) were sitting in the database, several
already marked completed. Scanning a host nobody authorised is the one failure
this tool must not have.

The BFF cannot import etl/scope_gate.py (it is not mounted into that container),
so the matching rules exist in two places. The final test here pins them
together on a shared table of cases so they cannot drift apart silently.
"""
import importlib.util
import os

import pytest

REPO = os.path.join(os.path.dirname(__file__), "..")
_BFF = os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")
_GATE = os.path.join(REPO, "etl", "scope_gate.py")


def _load_bff_scope():
    """Extract the BFF's scope matcher without importing the whole router.

    assets.py pulls in fastapi, httpx and the BFF's config module; lifting just
    the matcher keeps this runnable from a bare checkout.
    """
    if not os.path.exists(_BFF):                 # pragma: no cover
        pytest.skip("assets.py not present")
    src = open(_BFF).read()
    try:
        seg = src[src.index("def _host_in_scope("):src.index("class RunRecommendationsRequest")]
    except ValueError:                           # pragma: no cover
        pytest.skip("_host_in_scope not found in assets.py")
    ns = {}
    exec(seg, ns)
    return ns["_host_in_scope"]


@pytest.fixture(scope="module")
def in_scope():
    return _load_bff_scope()


@pytest.fixture(scope="module")
def gate():
    if not os.path.exists(_GATE):                # pragma: no cover
        pytest.skip("scope_gate.py not present")
    spec = importlib.util.spec_from_file_location("scope_gate", _GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SCOPE = [("192.168.1.150", "ip"), ("10.10.0.0/16", "cidr"), ("example.com", "domain")]


def test_exact_ip_is_in_scope(in_scope):
    assert in_scope("192.168.1.150", SCOPE) is True


@pytest.mark.parametrize("host", ["104.20.44.163", "172.66.0.227"])
def test_the_real_out_of_scope_hosts_are_refused(in_scope, host):
    """The exact Cloudflare addresses that were queued against this engagement."""
    assert in_scope(host, SCOPE) is False


def test_cidr_membership(in_scope):
    assert in_scope("10.10.5.9", SCOPE) is True
    assert in_scope("10.11.5.9", SCOPE) is False


def test_domain_and_subdomain(in_scope):
    assert in_scope("example.com", SCOPE) is True
    assert in_scope("api.example.com", SCOPE) is True
    assert in_scope("notexample.com", SCOPE) is False


def test_empty_scope_refuses_everything(in_scope):
    """Fail closed. An unconfigured scope must not mean 'scan anything' — that
    turns a setup mistake into unauthorised traffic."""
    assert in_scope("192.168.1.150", []) is False
    assert in_scope("192.168.1.150", None) is False


def test_blank_host_is_refused(in_scope):
    for host in ("", "   ", None):
        assert in_scope(host, SCOPE) is False


def test_near_miss_addresses_are_refused(in_scope):
    """Substring-ish neighbours must not slip through a sloppy comparison."""
    for host in ("192.168.1.15", "192.168.1.1500", "1192.168.1.150"):
        assert in_scope(host, SCOPE) is False


def test_malformed_scope_rows_do_not_crash(in_scope):
    """A bad row must not take out the gate — and must not authorise anything."""
    bad = [("", "ip"), (None, "cidr"), ("not-a-cidr", "cidr"), ("x", None)]
    assert in_scope("192.168.1.150", bad) is False


def test_trailing_dot_and_case_are_normalised(in_scope):
    assert in_scope("EXAMPLE.COM.", SCOPE) is True


# ── Drift guard ───────────────────────────────────────────────────────────

CASES = [
    ("192.168.1.150", True), ("104.20.44.163", False), ("172.66.0.227", False),
    ("10.10.5.9", True), ("10.11.5.9", False),
    ("example.com", True), ("api.example.com", True), ("notexample.com", False),
    ("", False), ("192.168.1.15", False),
]


@pytest.mark.parametrize("host,expected", CASES)
def test_bff_and_scope_gate_agree(in_scope, gate, host, expected):
    """The two implementations must reach the same verdict.

    They exist separately only because the BFF container has no access to
    etl/scope_gate.py. A divergence here means one path authorises traffic the
    other would refuse, which is precisely the bug that matters.
    """
    bff_verdict = in_scope(host, SCOPE)
    gate_verdict = gate.is_in_scope(host, SCOPE)
    assert bff_verdict == gate_verdict == expected, (
        f"host={host!r}: bff={bff_verdict} scope_gate={gate_verdict} expected={expected}")
