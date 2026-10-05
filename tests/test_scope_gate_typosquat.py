"""Unit tests for the not_in_scope deny-list short-circuit in is_in_scope().

The typosquat detector writes high-confidence lookalike domains to the
GLOBAL `not_in_scope` deny-list (name='not_in_scope', engagement_id IS NULL)
so the scope gate refuses dispatch for every engagement. These tests pin
that behavior:

  (1) a host matching the deny-list is REFUSED even when it also matches
      an in-scope row (belt-and-braces),
  (2) check_dispatch returns a specific "in the not_in_scope deny-list"
      message so operators can distinguish it from a plain miss,
  (3) load_not_in_scope_denylist filters by name + engagement_id correctly.

Sabotage-proven: revert the short-circuit in etl/scope_gate.py (remove the
`if denylist and is_in_denylist(h, denylist)` block in is_in_scope) and
test_scope_wins_without_short_circuit fails loudly — the test is only
green when the short-circuit is in place.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from etl.scope_gate import (
    is_in_scope,
    is_in_denylist,
    is_in_scope_with_aliases,
    check_dispatch,
    load_not_in_scope_denylist,
)


# In-scope rows an engagement actually configures.
SCOPE = [
    ("blackbaud.com", "domain"),
    ("10.0.0.0/24", "cidr"),
    ("1.2.3.4", "ip"),
]

# Deny-list rows the typosquat detector would auto-populate.
DENYLIST = [
    ("blackbacd.com", "domain"),       # edit-1 lookalike of blackbaud.com
    ("b1ackbaud.com", "domain"),       # homoglyph l->1
    ("xn--blckbaud-9za.com", "domain"), # IDN form
    ("10.0.0.99", "ip"),               # inside the in-scope CIDR but denied
]


@pytest.mark.unit
class TestIsInDenylist:
    def test_exact_domain_hit(self):
        assert is_in_denylist("blackbacd.com", DENYLIST) is True

    def test_subdomain_hit(self):
        # Deny-list treats a domain like scope rows: *.domain also refused.
        assert is_in_denylist("www.blackbacd.com", DENYLIST) is True
        assert is_in_denylist("api.b1ackbaud.com", DENYLIST) is True

    def test_ip_hit(self):
        assert is_in_denylist("10.0.0.99", DENYLIST) is True

    def test_miss(self):
        assert is_in_denylist("blackbaud.com", DENYLIST) is False
        assert is_in_denylist("www.blackbaud.com", DENYLIST) is False

    def test_empty_denylist(self):
        assert is_in_denylist("blackbacd.com", []) is False
        assert is_in_denylist("blackbacd.com", None) is False

    def test_empty_host(self):
        assert is_in_denylist("", DENYLIST) is False
        assert is_in_denylist(None, DENYLIST) is False


@pytest.mark.unit
class TestIsInScopeShortCircuit:
    def test_denylist_wins_over_in_scope_match(self):
        """The whole point: a typosquat auto-added to the deny-list is
        REFUSED even when it would otherwise match a scope row. If the
        deny-list IP sat inside the in-scope CIDR, the short-circuit must
        still refuse it."""
        # 10.0.0.99 IS inside the in-scope 10.0.0.0/24 — would normally
        # be allowed. With the deny-list it must be refused.
        assert is_in_scope("10.0.0.99", SCOPE, denylist=DENYLIST) is False
        # Confirm it WAS allowed without the deny-list (sanity check).
        assert is_in_scope("10.0.0.99", SCOPE) is True

    def test_scope_wins_without_short_circuit(self):
        """Sabotage canary: this test must FAIL if someone removes the
        deny-list short-circuit from is_in_scope. A deny-listed typosquat
        that doesn't match a scope row returns False either way, so we
        need the overlap case (deny-list IP inside in-scope CIDR) to catch
        a sabotage."""
        # If the short-circuit is removed, this reverts to True (scope
        # match wins) and the test fails loudly.
        assert is_in_scope("10.0.0.99", SCOPE, denylist=DENYLIST) is False

    def test_denylist_host_not_in_scope_also_refused(self):
        # Standard case: typosquat domain not in any in-scope row.
        assert is_in_scope("blackbacd.com", SCOPE, denylist=DENYLIST) is False

    def test_in_scope_host_still_allowed(self):
        # Positive scope match that isn't deny-listed MUST still pass.
        assert is_in_scope("blackbaud.com", SCOPE, denylist=DENYLIST) is True
        assert is_in_scope("www.blackbaud.com", SCOPE, denylist=DENYLIST) is True

    def test_omitted_denylist_is_backward_compatible(self):
        # Callers that don't pass denylist keep the old behavior exactly.
        assert is_in_scope("10.0.0.99", SCOPE) is True
        assert is_in_scope("blackbaud.com", SCOPE) is True
        assert is_in_scope("blackbacd.com", SCOPE) is False


@pytest.mark.unit
class TestIsInScopeWithAliases:
    def test_denylist_propagates_through_aliases(self):
        # Alias refers to a deny-listed host — must still be refused.
        aliases = {"blackbacd.com"}
        assert is_in_scope_with_aliases(
            "someother.example", SCOPE, aliases=aliases, denylist=DENYLIST
        ) is False

    def test_url_form_also_refused(self):
        # URL form of the deny-listed host must be refused via
        # _host_from_url normalization + deny-list check.
        assert is_in_scope_with_aliases(
            "http://blackbacd.com/login", SCOPE, denylist=DENYLIST
        ) is False


@pytest.mark.unit
class TestCheckDispatchDenylist:
    def test_denylist_refusal_message_is_specific(self):
        """The refusal must name 'not_in_scope deny-list' so operators
        can tell it apart from a plain 'not in scope' miss."""
        msg = check_dispatch("blackbacd.com", SCOPE, command="", denylist=DENYLIST)
        assert msg is not None
        assert "not_in_scope" in msg.lower() or "deny-list" in msg.lower()

    def test_denylist_refusal_mentions_target(self):
        msg = check_dispatch("blackbacd.com", SCOPE, command="", denylist=DENYLIST)
        assert "blackbacd.com" in msg

    def test_in_scope_target_passes(self):
        msg = check_dispatch("blackbaud.com", SCOPE, denylist=DENYLIST)
        assert msg is None

    def test_denylist_command_ip_refused(self):
        """IPv4 literal in the command that matches the deny-list must
        be refused with a deny-list-specific message."""
        msg = check_dispatch(
            "blackbaud.com", SCOPE,
            command="curl http://10.0.0.99/",
            denylist=DENYLIST,
        )
        assert msg is not None
        assert "10.0.0.99" in msg
        assert "deny-list" in msg.lower()


@pytest.mark.unit
class TestLoadNotInScopeDenylist:
    def test_filters_name_and_engagement_id(self):
        """Loader must only return rows with name='not_in_scope' AND
        engagement_id IS NULL. Any per-engagement row with the same
        name must NOT appear in the global deny-list."""
        cur = MagicMock()
        cur.fetchall.return_value = [
            ("blackbacd.com", "domain"),
            ("b1ackbaud.com", "domain"),
        ]
        result = load_not_in_scope_denylist(cur)
        assert result == [
            ("blackbacd.com", "domain"),
            ("b1ackbaud.com", "domain"),
        ]
        # Query must constrain by name AND engagement_id — sabotage-check
        # by inspecting the SQL.
        sql = cur.execute.call_args[0][0].lower()
        assert "not_in_scope" in sql
        assert "engagement_id is null" in sql

    def test_loader_reads_new_for_review_scope(self):
        """cert-pivot / asn-pivot accepts land in a per-engagement
        `new_for_review` STAGING scope; the deny-list loader MUST read it
        so the gate refuses dispatch until the operator promotes the
        target. Sabotage: drop 'new_for_review' from the loader's WHERE
        and this fails."""
        cur = MagicMock()
        cur.fetchall.return_value = []
        load_not_in_scope_denylist(cur)
        sql = cur.execute.call_args[0][0].lower()
        assert "new_for_review" in sql
        assert "typosquats" in sql

    def test_new_for_review_cidr_refused_even_when_in_scope(self):
        """A host inside a new_for_review CIDR is refused even if it also
        matches an in-scope row — the staging scope is gate-blocked."""
        denylist = [("203.0.113.0/24", "cidr"), ("altoromutual.example.org", "domain")]
        # The host is in-scope AND in the new_for_review deny-list.
        scope = [("203.0.113.0/24", "cidr")]
        assert is_in_scope("203.0.113.10", scope, denylist=denylist) is False
        assert is_in_scope("altoromutual.example.org",
                           [("altoromutual.example.org", "domain")],
                           denylist=denylist) is False

    def test_query_error_returns_empty(self):
        cur = MagicMock()
        cur.execute.side_effect = RuntimeError("db down")
        result = load_not_in_scope_denylist(cur)
        assert result == []

    def test_realdict_rows_unpacked(self):
        cur = MagicMock()
        cur.fetchall.return_value = [
            {"target": "blackbacd.com", "target_type": "domain"},
        ]
        result = load_not_in_scope_denylist(cur)
        assert result == [("blackbacd.com", "domain")]
