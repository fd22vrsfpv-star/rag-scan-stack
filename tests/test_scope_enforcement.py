"""Scope must be default-DENY, and must key on the URL host only.

The osint_agent scope check was default-ALLOW behind a 20-entry hardcoded
denylist and ended with `return False`, so every unrecognised external host was
treated as in-scope. Links on a target's own pages therefore became follow-up
items on an engagement that never authorized them:
www.owasp.org, irongeek.com, www.jcp.org, java.sun.com, www.jguru.com,
en.wikipedia.org, samurai.inguardians.com, www.hackersforcharity.org.

Two properties are load-bearing and tested here:
  1. Default-deny — an unrecognised host is OUT, not in.
  2. Host-only matching — an in-scope URL carrying an external host in a QUERY
     PARAMETER (an open-redirect finding) stays IN. Substring matching would
     drop a real finding, and would also call devblog.attacker.com in-scope
     because it contains "dev".
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "app" / "rag-api"))

from etl.scope_gate import is_in_scope  # noqa: E402

SCANNED_HOSTS = [("192.168.1.150", "ip"), ("127.0.0.1", "ip")]

# Every external host observed in the operator's follow-up queue.
LEAKED_HOSTS = [
    "www.owasp.org",
    "irongeek.com",
    "www.irongeek.com",
    "www.jcp.org",
    "samurai.inguardians.com",
    "www.hackersforcharity.org",
    "www.jguru.com",
    "en.wikipedia.org",
    "java.sun.com",
]


def _host_of(target):
    """Mirror of osint_agent._target_hostname, kept trivial on purpose."""
    from urllib.parse import urlparse
    t = str(target).strip()
    netloc = urlparse(t if "://" in t else "//" + t).netloc
    return (netloc.split("@")[-1].split(":")[0] or "").strip().lower().rstrip(".")


@pytest.mark.unit
@pytest.mark.parametrize("host", LEAKED_HOSTS)
def test_leaked_hosts_are_out_of_scope(host):
    """Every host that leaked into the queue must now be denied."""
    assert is_in_scope(host, SCANNED_HOSTS) is False


@pytest.mark.unit
def test_unknown_host_denied_by_default():
    """The core inversion: unrecognised != allowed."""
    assert is_in_scope("something-nobody-listed.example", SCANNED_HOSTS) is False


@pytest.mark.unit
def test_scanned_host_is_in_scope():
    assert is_in_scope("192.168.1.150", SCANNED_HOSTS) is True


@pytest.mark.unit
def test_open_redirect_on_an_in_scope_host_stays_in_scope():
    """The finding that a naive substring filter would wrongly drop.

    The host is the target; www.owasp.org appears only in a query parameter, and
    that parameter IS the vulnerability.
    """
    target = ("http://192.168.1.150/mutillidae/index.php"
              "?forwardurl=https%3A%2F%2F8875853757105814929.owasp.org"
              "&page=redirectandlog.php")
    assert _host_of(target) == "192.168.1.150"
    assert is_in_scope(_host_of(target), SCANNED_HOSTS) is True


@pytest.mark.unit
def test_external_page_on_the_same_topic_is_still_out():
    """Contrast with the case above — here the HOST is external."""
    target = "http://www.owasp.org/index.php/Top_10_2010-A1"
    assert _host_of(target) == "www.owasp.org"
    assert is_in_scope(_host_of(target), SCANNED_HOSTS) is False


@pytest.mark.unit
@pytest.mark.parametrize("host", [
    "devblog.attacker.com",      # contains "dev"
    "latest-news.attacker.com",  # contains "test"
    "localhost.attacker.com",    # contains "localhost"
    "internal.attacker.com",     # contains "internal"
])
def test_internal_looking_substrings_do_not_grant_scope(host):
    """The old check did `any(x in domain for x in ["dev","test","local",...])`."""
    assert is_in_scope(host, SCANNED_HOSTS) is False


@pytest.mark.unit
def test_empty_scope_authorizes_nothing():
    """Fail closed: no scope means nothing is in scope, never everything."""
    assert is_in_scope("192.168.1.150", []) is False
    assert is_in_scope("www.owasp.org", []) is False


@pytest.mark.unit
def test_cidr_and_domain_scope_still_match():
    """Real engagement scope, once populated, behaves as expected."""
    scope = [("10.0.0.0/24", "cidr"), ("example.com", "domain")]
    assert is_in_scope("10.0.0.7", scope) is True
    assert is_in_scope("10.0.1.7", scope) is False
    assert is_in_scope("app.example.com", scope) is True
    assert is_in_scope("example.com.attacker.net", scope) is False


# ---------------------------------------------------------------- aliasing
# A host can be in scope under a different identity: scope lists 127.0.0.1 but
# the finding says "localhost", or scope lists a hostname the scan already
# resolved to an IP. Matching the literal string alone rejects a host the tool
# demonstrably just scanned.

ALIAS_PAIRS = {                      # what `assets` observed
    "localhost": {"127.0.0.1"},
    "127.0.0.1": {"localhost"},
    "target.local": {"192.168.1.150"},
    "192.168.1.150": {"target.local"},
}


def _in_scope_with_aliases(host, scope):
    aliases = {host} | ALIAS_PAIRS.get(host, set())
    return any(is_in_scope(a, scope) for a in aliases)


@pytest.mark.unit
def test_ip_in_scope_authorizes_its_hostname():
    """Scope lists 127.0.0.1; a finding recorded as 'localhost' must be allowed."""
    scope = [("127.0.0.1", "ip")]
    assert is_in_scope("localhost", scope) is False        # literal match fails
    assert _in_scope_with_aliases("localhost", scope) is True


@pytest.mark.unit
def test_hostname_in_scope_authorizes_its_resolved_ip():
    """Scope lists a hostname; the scan resolved it to an IP, findings use the IP."""
    scope = [("target.local", "domain")]
    assert is_in_scope("192.168.1.150", scope) is False     # literal match fails
    assert _in_scope_with_aliases("192.168.1.150", scope) is True


@pytest.mark.unit
def test_aliasing_does_not_grant_scope_to_unrelated_hosts():
    """Aliases widen scope only along OBSERVED pairings — never arbitrarily."""
    scope = [("127.0.0.1", "ip")]
    assert _in_scope_with_aliases("www.owasp.org", scope) is False
    assert _in_scope_with_aliases("192.168.1.150", scope) is False


# ------------------------------------------------------- placeholder rows
# scope_targets can hold a sentinel row (target='', source='__placeholder__') so
# a NAMED scope can exist before it has targets. It is not a target. The
# engagement-scoped endpoints always filtered it; the global /scope ones did not,
# so a scope holding only a placeholder reported target_count=1 and read as
# populated. For a gate that REFUSES scans that is the worst possible shape:
# "scope exists" plus "nothing matches" means 403 on everything.

def _strip_placeholders(rows):
    """Mirror of the BFF loader's filter."""
    return [
        (r.get("target"), r.get("target_type"))
        for r in rows
        if (r.get("target") or "").strip() and r.get("source") != "__placeholder__"
    ]


@pytest.mark.unit
def test_placeholder_row_is_not_a_scope_target():
    rows = [
        {"target": "", "target_type": "domain", "source": "__placeholder__"},
        {"target": "192.168.1.150", "target_type": "ip", "source": "manual"},
    ]
    assert _strip_placeholders(rows) == [("192.168.1.150", "ip")]


@pytest.mark.unit
def test_placeholder_only_scope_reads_as_no_scope():
    """The dangerous shape: must be indistinguishable from an empty scope.

    If it read as "scope exists", the gate would enforce against a scope that
    matches nothing and refuse every scan, including in-scope ones.
    """
    rows = [{"target": "", "target_type": "domain", "source": "__placeholder__"}]
    assert _strip_placeholders(rows) == []


@pytest.mark.unit
def test_placeholder_never_grants_scope():
    """An empty target must not match anything, even if it slips through."""
    scope = [("", "domain")]
    assert is_in_scope("www.owasp.org", scope) is False
    assert is_in_scope("192.168.1.150", scope) is False
