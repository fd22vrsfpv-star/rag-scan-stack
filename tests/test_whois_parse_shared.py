"""One WHOIS field map, not two that agree today.

node_manager's remote-WHOIS branch opened with

    try:
        from osint_runner.osint_runner import _parse_whois_domain, _parse_whois_ip
    except ImportError:
        _parse_whois_domain = None

and `docker exec node-manager python -c "import osint_runner"` answers
`ModuleNotFoundError` — the module is not in that image and never was. The
import failed on every call. It also did not matter, because the names were
never read: below it sat a re-typed, SHORTER copy of the same field maps, 8
fields against 11 for a domain, with the domain and IP maps merged into one.

So a remote WHOIS stored `org`, `registrar`, `creation_date`, `country`,
`net_range`, `cidr`, `asn`, `name_servers` — and silently dropped
`expiry_date`, `updated_date`, `registrant_name`, `registrant_email`,
`registrant_country`, `dnssec` and `status`, every one of which a LOCAL whois
of the same domain recorded. Nothing failed; the rows were just thinner, which
is invisible unless you compare two findings side by side.

Shipping osint_runner.py into node-manager's image to fix that would have been
the wrong trade: 5,267 lines that build a FastAPI app at import time and pull
in tool_job, log_manager, validation and service_enum, for two pure string
functions. They live in `common/whois_parse.py` instead, which both services
already bind-mount.

The field-map cases below are the contract. They are not invented shapes: the
domain sample is the published `example.com` WHOIS record and the IP samples
are real ARIN and RIPE responses, which differ in label spelling (`NetRange:`
vs `inetnum:`) — the thing the map exists to absorb.

Sabotage check: drop `dnssec` from `_DOMAIN_FIELDS` and
`test_domain_fields_are_extracted` fails by field name; restore the inline
field_map in node_manager and `test_node_manager_has_no_private_copy` fails.

    pytest tests/test_whois_parse_shared.py -q
"""

import ast
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

try:
    from common.whois_parse import (_DOMAIN_FIELDS, _IP_FIELDS,
                                    parse_whois, parse_whois_domain,
                                    parse_whois_ip)
except ImportError as e:  # pragma: no cover
    pytest.skip(f"common/whois_parse.py not importable: {e}", allow_module_level=True)


ARIN = """NetRange:       93.184.216.0 - 93.184.216.255
CIDR:           93.184.216.0/24
NetName:        EDGECAST-NETBLK-03
NetHandle:      NET-93-184-216-0-1
Parent:         NET93 (NET-93-0-0-0-0)
OrgName:        MCI Communications Services, Inc. d/b/a Verizon Business
OrgId:          MCICS
Country:        US
OriginAS:       AS15133
OrgAbuseEmail:  abuse@verizon.com
OrgTechEmail:   tech@verizon.com
Ref:            https://rdap.arin.net/registry/ip/93.184.216.0"""

RIPE = """inetnum:        66.45.103.0 - 66.45.103.255
netname:        EXAMPLE-NET
descr:          Example Hosting BV
country:        NL
origin:         AS12345
abuse-mailbox:  abuse@example.nl
source:         RIPE
route:          66.45.103.0/24"""

DOMAIN = """Domain Name: EXAMPLE.COM
Registrar: MarkMonitor Inc.
Registrant Organization: Internet Assigned Numbers Authority
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z
Updated Date: 2025-08-14T07:01:44Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Registrant Name: Redacted for Privacy
Registrant Email: https://domains.markmonitor.com/whois/contact
Registrant Country: US
DNSSEC: signedDelegation
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited"""


@pytest.mark.parametrize("field,expected", [
    ("registrar", "MarkMonitor Inc."),
    ("org", "Internet Assigned Numbers Authority"),
    ("creation_date", "1995-08-14T04:00:00Z"),
    ("expiry_date", "2026-08-13T04:00:00Z"),
    ("updated_date", "2025-08-14T07:01:44Z"),
    ("registrant_name", "Redacted for Privacy"),
    ("registrant_country", "US"),
    ("dnssec", "signedDelegation"),
])
def test_domain_fields_are_extracted(field, expected):
    """Seven of these eight were dropped by the copy node_manager carried."""
    assert parse_whois_domain(DOMAIN, "example.com").get(field) == expected


def test_multi_valued_fields_keep_every_value():
    d = parse_whois_domain(DOMAIN, "example.com")
    assert d["name_servers"] == ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
    assert d["status"] == ["clientTransferProhibited", "clientUpdateProhibited"]


def test_single_valued_fields_keep_the_first_value():
    """`registrar` is one value even when a record repeats it."""
    raw = "Registrar: First Inc.\nRegistrar: Second Inc."
    assert parse_whois_domain(raw, "x.com")["registrar"] == "First Inc."


def test_arin_and_ripe_spellings_both_resolve():
    """The label spelling is the whole reason the map is a list per field."""
    a, r = parse_whois_ip(ARIN, "93.184.216.34"), parse_whois_ip(RIPE, "66.45.103.92")
    assert a["net_range"] == "93.184.216.0 - 93.184.216.255"
    assert r["net_range"] == "66.45.103.0 - 66.45.103.255"
    assert a["asn"] == "AS15133" and r["asn"] == "AS12345"
    assert a["cidr"] == "93.184.216.0/24" and r["cidr"] == "66.45.103.0/24"
    assert a["abuse_email"] == "abuse@verizon.com"
    assert r["abuse_email"] == "abuse@example.nl"


def test_a_value_containing_colons_survives():
    """Split on the FIRST colon only — values carry URLs and timestamps."""
    d = parse_whois_domain(DOMAIN, "example.com")
    assert d["registrant_email"].startswith("https://")
    assert d["creation_date"].count(":") == 2
    assert parse_whois_ip(ARIN, "1.2.3.4")["ref"].startswith("https://rdap.arin.net")


@pytest.mark.parametrize("raw", ["", "   ", "no labels here at all", ": : :"])
def test_empty_and_junk_input_yield_the_identity_fields_only(raw):
    """A parse that finds nothing must still return a well-formed record."""
    d = parse_whois_domain(raw, "x.com")
    assert d["domain"] == "x.com" and d["type"] == "domain"
    assert set(d) <= {"raw_length", "domain", "type"} | set(_DOMAIN_FIELDS)
    i = parse_whois_ip(raw, "1.2.3.4")
    assert i["ip"] == "1.2.3.4" and i["type"] == "ip"


def test_none_input_does_not_raise():
    """node_manager guards with `if not raw.strip()`, osint_runner does not."""
    assert parse_whois_domain(None, "x.com")["raw_length"] == 0


def test_dispatch_helper_picks_the_right_map():
    assert parse_whois(ARIN, "1.2.3.4", True)["type"] == "ip"
    assert parse_whois(DOMAIN, "x.com", False)["type"] == "domain"


def test_node_manager_has_no_private_copy():
    """The defect: a second field map in the consumer."""
    src = (REPO / "node_manager" / "node_manager.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "field_map" for t in node.targets):
            pytest.fail(
                f"node_manager.py:{node.lineno} builds its own WHOIS field_map "
                "again. Two maps drift, and the drift shows up only as findings "
                "with fewer fields than a local scan produced. Use "
                "common.whois_parse.")
    assert "from common.whois_parse import" in src, (
        "node_manager does not import the shared parser")
    assert "from osint_runner.osint_runner import" not in src, (
        "node_manager still imports osint_runner, which is not in its image "
        "(ModuleNotFoundError on every call)")


def test_osint_runner_delegates_rather_than_duplicating():
    src = (REPO / "osint_runner" / "osint_runner.py").read_text(encoding="utf-8")
    assert "from common.whois_parse import" in src, (
        "osint_runner still owns a private implementation")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name in ("_parse_whois_domain", "_parse_whois_ip"):
            maps = [n for n in ast.walk(node)
                    if isinstance(n, ast.Assign) and any(
                        isinstance(t, ast.Name) and t.id == "field_map"
                        for t in n.targets)]
            assert not maps, (
                f"osint_runner.{node.name} still builds its own field_map at "
                f"line {maps[0].lineno}")


def test_the_two_maps_do_not_overlap_identity_keys():
    """`org` is in both, deliberately. `domain`/`ip` must not be."""
    assert "domain" not in _IP_FIELDS and "ip" not in _DOMAIN_FIELDS
