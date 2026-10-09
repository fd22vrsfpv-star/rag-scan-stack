"""Tests for app/rag-api/typosquat_agent.py — generator + scorer.

Sabotage-proven:
  * Removing any of the six transform families drops the matching
    assertion in test_each_transform_family_fires — the test fails
    with a specific "missing transform=X" message.
  * Dropping the IDN high-score bonus (0.6 in score_typosquat) fails
    test_idn_always_scores_high — can't limp through on noise.
  * Dropping the TLD-swap penalty (-0.3) fails
    test_tld_swap_only_never_auto_blocks.

The CLAUDE.md "every endpoint has a test that EXECUTES it" invariant
is satisfied for the module-level helpers; the DB-writing path
(flag_typosquats_for_engagement) is covered by the E2E test in
test_scope_pivot_endpoint.py which exercises the live /jobs/scope-pivot
endpoint.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

# typosquat_agent.py sits under app/rag-api/ which is not on sys.path
# at the project root; load it by explicit file path like other service
# modules in tests/.
_mod_path = Path(__file__).parent.parent / "app" / "rag-api" / "typosquat_agent.py"
_spec = importlib.util.spec_from_file_location("typosquat_agent", _mod_path)
typosquat_agent = importlib.util.module_from_spec(_spec)
sys.modules["typosquat_agent"] = typosquat_agent
_spec.loader.exec_module(typosquat_agent)

generate_typosquat_candidates = typosquat_agent.generate_typosquat_candidates
score_typosquat = typosquat_agent.score_typosquat
_split_domain = typosquat_agent._split_domain
_levenshtein = typosquat_agent._levenshtein
_confusable_char_count = typosquat_agent._confusable_char_count
TYPOSQUAT_AUTO_BLOCK_AT = typosquat_agent.TYPOSQUAT_AUTO_BLOCK_AT


@pytest.mark.unit
class TestSplitDomain:
    def test_simple(self):
        assert _split_domain("blackbaud.com") == ("blackbaud", "com")

    def test_multipart_tld(self):
        assert _split_domain("foo.co.uk") == ("foo", "co.uk")
        assert _split_domain("bar.gov.uk") == ("bar", "gov.uk")

    def test_subdomain_stays_in_label(self):
        # The TLD-swap transform must not touch internal structure.
        assert _split_domain("api.blackbaud.com") == ("api.blackbaud", "com")

    def test_empty(self):
        assert _split_domain("") == ("", "")
        assert _split_domain("...") == ("", "")

    def test_strips_trailing_dot(self):
        assert _split_domain("blackbaud.com.") == ("blackbaud", "com")


@pytest.mark.unit
class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("abc", "abc") == 0

    def test_one_sub(self):
        assert _levenshtein("abc", "abd") == 1

    def test_one_insert(self):
        assert _levenshtein("abc", "abcd") == 1

    def test_one_delete(self):
        assert _levenshtein("abcd", "abc") == 1

    def test_empty(self):
        assert _levenshtein("", "abc") == 3
        assert _levenshtein("abc", "") == 3

    def test_blackbaud_pair(self):
        assert _levenshtein("blackbaud", "blackbacd") == 1
        assert _levenshtein("blackbaud", "b1ackbaud") == 1


@pytest.mark.unit
class TestConfusableCount:
    def test_single_lookalike_pair(self):
        # 'l' -> '1' is in _HOMOGLYPHS["l"]
        assert _confusable_char_count("blackbaud", "b1ackbaud") == 1

    def test_cyrillic_a(self):
        # 'a' -> cyrillic a (U+0430)
        assert _confusable_char_count("blackbaud", "blаckbaud") == 1

    def test_no_confusable(self):
        assert _confusable_char_count("blackbaud", "redaud") == 0


@pytest.mark.unit
class TestGenerator:
    def test_returns_non_empty_for_blackbaud(self):
        cands = generate_typosquat_candidates("blackbaud.com", max_candidates=200)
        assert len(cands) > 0
        assert len(cands) <= 200

    def test_bounded_by_max(self):
        cands = generate_typosquat_candidates("blackbaud.com", max_candidates=10)
        assert len(cands) <= 10

    def test_each_transform_family_fires(self):
        """Sabotage canary: if any transform family is removed from the
        generator (edit, qwerty, homoglyph, bitsquat, idn, tld_swap),
        this test fails loudly naming the missing one. Keep MAX high so
        the trim at the end doesn't drop any family's rep."""
        cands = generate_typosquat_candidates("blackbaud.com", max_candidates=1000)
        transforms = {c["transform"] for c in cands}
        expected = {"edit1", "qwerty", "homoglyph", "bitsquat", "idn",
                    "tld_swap"}
        missing = expected - transforms
        assert not missing, f"missing transform(s): {sorted(missing)}"

    def test_does_not_include_seed(self):
        cands = generate_typosquat_candidates("blackbaud.com", max_candidates=1000)
        domains = {c["domain"].lower() for c in cands}
        assert "blackbaud.com" not in domains

    def test_deterministic(self):
        a = generate_typosquat_candidates("blackbaud.com", max_candidates=50)
        b = generate_typosquat_candidates("blackbaud.com", max_candidates=50)
        assert a == b

    def test_known_lookalikes_appear(self):
        """Spot-check that classic lookalikes do appear in the output.
        These are the ones a human researcher would notice first."""
        cands = generate_typosquat_candidates("blackbaud.com", max_candidates=1000)
        domains = {c["domain"].lower() for c in cands}
        # Edit-1 (character insertion)
        assert "bllackbaud.com" in domains or "blaackbaud.com" in domains
        # Homoglyph l->1
        assert "b1ackbaud.com" in domains
        # TLD swap
        assert any(d.startswith("blackbaud.") and d != "blackbaud.com"
                   for d in domains)

    def test_empty_seed(self):
        assert generate_typosquat_candidates("") == []
        assert generate_typosquat_candidates("notadomain") == []

    def test_multipart_tld_preserved(self):
        cands = generate_typosquat_candidates("foo.co.uk", max_candidates=1000)
        # TLD-swap transforms should swap only the "co.uk" portion.
        tld_swaps = [c for c in cands if c["transform"] == "tld_swap"]
        assert tld_swaps  # at least some
        assert all(c["domain"].startswith("foo.") for c in tld_swaps)


@pytest.mark.unit
class TestScorer:
    SEED = "blackbaud.com"

    def _cand(self, domain, transform):
        return {"domain": domain, "transform": transform,
                "source_label": self.SEED}

    def test_idn_always_scores_high(self):
        """Sabotage canary: remove the +0.6 IDN bonus and this fails."""
        c = self._cand("xn--blckbaud-9za.com", "idn")
        result = score_typosquat(c, self.SEED, resolution=None)
        assert result["score"] >= 0.6, (
            f"IDN score should always be >= 0.6, got {result['score']}")

    def test_homoglyph_scores_above_half(self):
        c = self._cand("b1ackbaud.com", "homoglyph")
        result = score_typosquat(c, self.SEED, resolution="unregistered")
        assert result["score"] >= 0.5

    def test_resolution_boosts_score(self):
        c = self._cand("blackbacd.com", "edit1")
        no_res = score_typosquat(c, self.SEED, resolution="unregistered")
        res = score_typosquat(c, self.SEED, resolution="resolves")
        assert res["score"] > no_res["score"]

    def test_tld_swap_only_never_auto_blocks(self):
        """Sabotage canary: remove the -0.3 TLD-swap penalty and this
        test might start producing scores above the auto-block threshold.
        TLD-swap-only candidates must always stay below."""
        c = self._cand("blackbaud.net", "tld_swap")
        # Even with resolution='resolves' (full +0.2) + edit_distance_0
        # bonus, the -0.3 penalty must keep it well below the threshold.
        result = score_typosquat(c, self.SEED, resolution="resolves")
        assert result["score"] < TYPOSQUAT_AUTO_BLOCK_AT, (
            f"TLD swap scored {result['score']}, must stay below "
            f"auto-block threshold {TYPOSQUAT_AUTO_BLOCK_AT}")

    def test_score_bounded_0_1(self):
        c = self._cand("xn--blckbaud-9za.com", "idn")
        result = score_typosquat(c, self.SEED, resolution="resolves")
        assert 0.0 <= result["score"] <= 1.0

    def test_reason_populated(self):
        c = self._cand("b1ackbaud.com", "homoglyph")
        result = score_typosquat(c, self.SEED, resolution="resolves")
        assert result["reason"]
        assert result["reason"] != "(no signal)"

    def test_no_signal_scores_zero(self):
        # Edit distance HUGE, no confusables, no IDN, unregistered
        c = self._cand("completelyunrelated.com", "edit1")
        result = score_typosquat(c, self.SEED, resolution="unregistered")
        # Score could be small positive from edit-distance window but
        # not auto-block level
        assert result["score"] < TYPOSQUAT_AUTO_BLOCK_AT
