"""Tests for the cert-pivot helpers in osint_runner.osint_runner.

Covers the pure-logic helpers:
  * _cert_pivot_candidates  — serial/SPKI/SAN pivot aggregation
  * _asn_high_precision_filter  — ASN membership + cert-subject/domain match

Network calls (`_query_crtsh_serial`, `_query_crtsh_by_spki`,
`_fetch_tls_cert_direct`) are mocked. The E2E path (`/jobs/scope-pivot`)
is covered by its own live-exec test in test_scope_pivot_endpoint.py.

The osint_runner module has heavy top-level imports (flask, requests,
psycopg2, …) that aren't available in the pure-unit test environment,
so this test extracts the target helpers from the source AST and
executes them in a sandbox with just the stdlib + requests. That keeps
the test fast and dependency-light while still exercising the real code.

Sabotage-proven:
  * Removing SAN-overlap handling fails test_san_pivot_catches_cross_domain.
  * Removing the "parent_domains" filter in _cert_pivot_candidates fails
    test_cert_rows_outside_parent_filtered_out.
  * Removing the and-either-signal check in _asn_high_precision_filter
    fails test_asn_no_signal_rejected.
"""
import ast
import logging
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_MOD_PATH = Path(__file__).parent.parent / "osint_runner" / "osint_runner.py"

# Target helpers extracted from the source. Executed in a sandbox so we
# don't need to import the full osint_runner module.
_WANTED = {
    "_query_crtsh_serial",       # mocked below
    "_query_crtsh_by_spki",      # mocked below
    "_cert_pivot_candidates",    # under test
    "_asn_high_precision_filter", # under test
}


def _load_helpers():
    """Parse osint_runner.py, pull the target FunctionDefs, exec them in
    an isolated namespace with the stdlib pieces they reference.

    Returns the namespace (dict) so tests can reach into it to patch
    `_query_crtsh_serial` / `_query_crtsh_by_spki` for mocking."""
    try:
        import requests as _requests
    except ImportError:
        _requests = MagicMock()
    src = _MOD_PATH.read_text()
    tree = ast.parse(src)
    pulled = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _WANTED:
            pulled.append(node)
    assert pulled, "no wanted helpers found in osint_runner.py"
    glob = {
        "__builtins__": __builtins__,
        "logging": logging,
        "requests": _requests,
        "json": __import__("json"),
    }
    module_ast = ast.Module(body=pulled, type_ignores=[])
    code = compile(module_ast, str(_MOD_PATH), "exec")
    exec(code, glob)
    return glob


_ns = _load_helpers()
_cert_pivot_candidates = _ns["_cert_pivot_candidates"]
_asn_high_precision_filter = _ns["_asn_high_precision_filter"]


@pytest.mark.unit
class TestCertPivotCandidates:
    def test_serial_pivot_collects_related_domains(self):
        """A crt.sh serial query returning multiple hostnames in the
        same parent domain should produce candidates for each."""
        _ns["_query_crtsh_serial"] = MagicMock(return_value=[
            {"common_name": "api.blackbaud.com",
             "name_value": "api.blackbaud.com\nwww.blackbaud.com"},
        ])
        result = _cert_pivot_candidates(
            seed_host="blackbaud.com",
            parent_domains={"blackbaud.com"},
            serial="DEADBEEF",
            rate_limit_sec=0.0,
        )
        assert "api.blackbaud.com" in result["from_serial"]
        assert "www.blackbaud.com" in result["from_serial"]

    def test_cert_rows_outside_parent_filtered_out(self):
        """Sabotage canary: without the parent_domains filter in
        _cert_pivot_candidates the result would include noise domains."""
        _ns["_query_crtsh_serial"] = MagicMock(return_value=[
            {"common_name": "shared.cdn.example.net",
             "name_value": "shared.cdn.example.net"},
        ])
        result = _cert_pivot_candidates(
            seed_host="blackbaud.com",
            parent_domains={"blackbaud.com"},
            serial="DEADBEEF",
            rate_limit_sec=0.0,
        )
        assert "shared.cdn.example.net" not in result["from_serial"]

    def test_spki_pivot_runs_and_returns_matches(self):
        _ns["_query_crtsh_by_spki"] = MagicMock(return_value=[
            {"common_name": "legacy.blackbaud.com",
             "name_value": "legacy.blackbaud.com"},
        ])
        result = _cert_pivot_candidates(
            seed_host="blackbaud.com",
            parent_domains={"blackbaud.com"},
            spki_sha256="abc123" * 8,
            rate_limit_sec=0.0,
        )
        assert "legacy.blackbaud.com" in result["from_spki"]

    def test_san_pivot_catches_cross_domain(self):
        """Sabotage canary: removing SAN-overlap handling drops cross-
        parent domains from the output. The whole point of SAN overlap is
        catching sister domains the org also owns."""
        result = _cert_pivot_candidates(
            seed_host="blackbaud.com",
            parent_domains={"blackbaud.com"},
            san_list=[
                "*.blackbaud.com",
                "www.blackbaud.com",
                "sister-brand.com",     # <- the catch
                "another-cousin.org",   # <- also a catch
            ],
            rate_limit_sec=0.0,
        )
        # Within-parent SANs are expected and filtered out.
        assert "www.blackbaud.com" not in result["from_san"]
        # Cross-parent SANs are the pivots.
        assert "sister-brand.com" in result["from_san"]
        assert "another-cousin.org" in result["from_san"]

    def test_san_pivot_strips_wildcard_prefix(self):
        result = _cert_pivot_candidates(
            seed_host="blackbaud.com",
            parent_domains={"blackbaud.com"},
            san_list=["*.external-brand.com"],
            rate_limit_sec=0.0,
        )
        # The leading "*." gets stripped
        assert "external-brand.com" in result["from_san"]

    def test_all_three_signals_can_coexist(self):
        _ns["_query_crtsh_serial"] = MagicMock(return_value=[
            {"name_value": "a.blackbaud.com"}])
        _ns["_query_crtsh_by_spki"] = MagicMock(return_value=[
            {"name_value": "b.blackbaud.com"}])
        result = _cert_pivot_candidates(
            seed_host="blackbaud.com",
            parent_domains={"blackbaud.com"},
            serial="DEAD",
            spki_sha256="BEEF" * 16,
            san_list=["sister.net"],
            rate_limit_sec=0.0,
        )
        assert "a.blackbaud.com" in result["from_serial"]
        assert "b.blackbaud.com" in result["from_spki"]
        assert "sister.net" in result["from_san"]

    def test_empty_inputs_return_empty_sets(self):
        result = _cert_pivot_candidates(
            seed_host="blackbaud.com",
            parent_domains={"blackbaud.com"},
            rate_limit_sec=0.0,
        )
        assert result == {"from_serial": set(), "from_spki": set(),
                           "from_san": set()}


@pytest.mark.unit
class TestAsnHighPrecisionFilter:
    IN_SCOPE_ORGS = {"Blackbaud", "Blackbaud Inc"}
    IN_SCOPE_DOMAINS = {"blackbaud.com", "blackbaud.co.uk"}

    def test_cert_subject_match_passes(self):
        hosts = [
            {"host": "1.2.3.4", "cert_subject": "CN=api, O=Blackbaud Inc",
             "rdns": "", "asn": 12345},
        ]
        result = _asn_high_precision_filter(hosts, self.IN_SCOPE_ORGS,
                                             self.IN_SCOPE_DOMAINS)
        assert len(result) == 1
        assert result[0]["match_signal"] == "cert_subject"

    def test_rdns_domain_match_passes(self):
        hosts = [
            {"host": "1.2.3.5", "cert_subject": "",
             "rdns": "edge.blackbaud.com", "asn": 12345},
        ]
        result = _asn_high_precision_filter(hosts, self.IN_SCOPE_ORGS,
                                             self.IN_SCOPE_DOMAINS)
        assert len(result) == 1
        assert result[0]["match_signal"] == "rdns"

    def test_both_signals_annotated_as_both(self):
        hosts = [
            {"host": "edge.blackbaud.com",
             "cert_subject": "CN=api, O=Blackbaud Inc",
             "rdns": "edge.blackbaud.com", "asn": 12345},
        ]
        result = _asn_high_precision_filter(hosts, self.IN_SCOPE_ORGS,
                                             self.IN_SCOPE_DOMAINS)
        assert len(result) == 1
        assert result[0]["match_signal"] == "both"

    def test_asn_no_signal_rejected(self):
        """Sabotage canary: a host in the in-scope ASN but with NEITHER
        a cert-subject match NOR a domain-string match must be filtered
        out. This is the whole point of 'high precision' mode."""
        hosts = [
            {"host": "9.9.9.9",
             "cert_subject": "CN=unrelated, O=SomeCDN",
             "rdns": "unrelated.cdn.net", "asn": 12345},
        ]
        result = _asn_high_precision_filter(hosts, self.IN_SCOPE_ORGS,
                                             self.IN_SCOPE_DOMAINS)
        assert result == []

    def test_mixed_input_only_matches_kept(self):
        hosts = [
            {"host": "1.2.3.4", "cert_subject": "O=Blackbaud",
             "rdns": "", "asn": 12345},
            {"host": "1.2.3.5", "cert_subject": "O=Unrelated",
             "rdns": "", "asn": 12345},
            {"host": "1.2.3.6", "cert_subject": "",
             "rdns": "api.blackbaud.com", "asn": 12345},
        ]
        result = _asn_high_precision_filter(hosts, self.IN_SCOPE_ORGS,
                                             self.IN_SCOPE_DOMAINS)
        assert len(result) == 2
        kept = {r["host"] for r in result}
        assert kept == {"1.2.3.4", "1.2.3.6"}

    def test_case_insensitive_org_match(self):
        hosts = [
            {"host": "1.1.1.1", "cert_subject": "o=BLACKBAUD",
             "rdns": "", "asn": 12345},
        ]
        result = _asn_high_precision_filter(hosts, self.IN_SCOPE_ORGS,
                                             self.IN_SCOPE_DOMAINS)
        assert len(result) == 1

    def test_empty_inputs(self):
        assert _asn_high_precision_filter([], self.IN_SCOPE_ORGS,
                                           self.IN_SCOPE_DOMAINS) == []
        assert _asn_high_precision_filter(
            [{"host": "x", "cert_subject": "O=Blackbaud"}],
            set(), set(),
        ) == []
