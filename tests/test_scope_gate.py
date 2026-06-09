"""Unit tests for the discovery scope gate (G3).

Pure-stdlib logic: confirms an out-of-scope host is never treated as
in-scope (the hard authorization boundary) and that ip/cidr/domain/url
targets match as expected.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from etl.scope_gate import is_in_scope, load_engagement_scope


SCOPE = [
    ("example.com", "domain"),
    ("10.0.0.0/24", "cidr"),
    ("1.2.3.4", "ip"),
    ("https://app.test.com/login", "url"),
    ("AS12345", "asn"),
]


@pytest.mark.unit
class TestIsInScope:
    def test_domain_exact_and_subdomain(self):
        assert is_in_scope("example.com", SCOPE) is True
        assert is_in_scope("www.example.com", SCOPE) is True
        assert is_in_scope("a.b.example.com", SCOPE) is True

    def test_domain_negative(self):
        assert is_in_scope("evil.com", SCOPE) is False
        assert is_in_scope("notexample.com", SCOPE) is False  # not a subdomain

    def test_cidr(self):
        assert is_in_scope("10.0.0.5", SCOPE) is True
        assert is_in_scope("10.0.0.255", SCOPE) is True
        assert is_in_scope("10.0.1.5", SCOPE) is False

    def test_exact_ip(self):
        assert is_in_scope("1.2.3.4", SCOPE) is True
        assert is_in_scope("1.2.3.5", SCOPE) is False

    def test_url_target_matches_host(self):
        assert is_in_scope("app.test.com", SCOPE) is True
        assert is_in_scope("api.app.test.com", SCOPE) is True
        assert is_in_scope("other.com", SCOPE) is False

    def test_asn_target_never_matches_a_host(self):
        # ASN can't be matched from a bare host string — must not match.
        assert is_in_scope("12345", SCOPE) is False

    def test_fail_closed(self):
        assert is_in_scope("", SCOPE) is False
        assert is_in_scope(None, SCOPE) is False
        assert is_in_scope("example.com", []) is False  # empty scope = nothing in scope

    def test_trailing_dot_and_case(self):
        assert is_in_scope("WWW.Example.com.", SCOPE) is True


@pytest.mark.unit
class TestLoadEngagementScope:
    def test_no_engagement_returns_empty(self):
        cur = MagicMock()
        assert load_engagement_scope(cur, None) == []
        cur.execute.assert_not_called()

    def test_tuple_rows(self):
        cur = MagicMock()
        cur.fetchall.return_value = [("example.com", "domain"), ("10.0.0.0/24", "cidr")]
        rows = load_engagement_scope(cur, "eng-1")
        assert rows == [("example.com", "domain"), ("10.0.0.0/24", "cidr")]

    def test_dict_rows(self):
        cur = MagicMock()
        cur.fetchall.return_value = [
            {"target": "example.com", "target_type": "domain"},
        ]
        rows = load_engagement_scope(cur, "eng-1")
        assert rows == [("example.com", "domain")]

    def test_query_error_fails_closed(self):
        cur = MagicMock()
        cur.execute.side_effect = Exception("boom")
        assert load_engagement_scope(cur, "eng-1") == []
