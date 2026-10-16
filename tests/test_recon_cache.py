"""Reuse a previous recon result — and never confuse 'could not ask' with 'no'.

Every recon node ran its tool unconditionally, so rebuilding the same CVE
against the same host paid for a full ZAP spider, Playwright crawl and arjun
fan-out again for answers already in the database.

The two ways a cache goes wrong are both covered here:

  * It serves a stale answer as a current one. Bounded by a per-tool TTL, and
    a reused result carries its AGE into the manifest where the `fact_is_stale`
    rule downgrades it.
  * It serves the WRONG answer — an unauthenticated crawl answering a request
    for an authenticated one. Bounded by `variant` being part of the key.

And the repo's recurring failure: a cache that could not be READ must not look
like a cache MISS. Both run the tool; only one means the cache is broken.

Run standalone:

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_recon_cache.py -v'
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from etl import recon_cache as rc  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("RECON_CACHE_TTL_"):
            monkeypatch.delenv(k, raising=False)


# ── modes + TTLs ───────────────────────────────────────────────────────────

@pytest.mark.unit
class TestPolicy:
    def test_an_unrecognised_mode_falls_back_to_auto(self):
        """Not to `always` — a typo must never widen reuse — and not to
        `never`, which would silently disable the feature."""
        for bad in ("", None, "yes", "ALWAYS?", "aut0"):
            assert rc.valid_mode(bad) == rc.AUTO, bad

    def test_known_modes_survive_casing_and_spaces(self):
        assert rc.valid_mode("  Always ") == rc.ALWAYS
        assert rc.valid_mode("NEVER") == rc.NEVER

    def test_ttl_is_per_tool_with_a_short_fallback(self):
        assert rc.ttl_for("zap") == rc.DEFAULT_TTL_SECONDS["zap"]
        assert rc.ttl_for("a-tool-nobody-reasoned-about") == rc.FALLBACK_TTL_SECONDS
        assert rc.FALLBACK_TTL_SECONDS <= min(rc.DEFAULT_TTL_SECONDS.values()), (
            "an unknown tool must not get MORE benefit of the doubt than a "
            "tool somebody thought about")

    def test_an_env_override_wins(self, monkeypatch):
        monkeypatch.setenv("RECON_CACHE_TTL_ZAP", "60")
        assert rc.ttl_for("zap") == 60

    def test_a_non_numeric_override_is_ignored_not_fatal(self, monkeypatch):
        monkeypatch.setenv("RECON_CACHE_TTL_ZAP", "an hour")
        assert rc.ttl_for("zap") == rc.DEFAULT_TTL_SECONDS["zap"]

    def test_a_zero_ttl_disables_caching_for_that_tool(self, monkeypatch):
        monkeypatch.setenv("RECON_CACHE_TTL_ARJUN", "0")
        assert rc.ttl_for("arjun") == 0
        action, reason = rc.decide(rc.AUTO, 1, rc.ttl_for("arjun"))
        assert action == rc.REFRESH
        assert "disabled" in reason

    def test_an_active_scan_is_cached_more_briefly_than_a_passive_one(self):
        assert rc.ttl_for("zap_active") < rc.ttl_for("zap")


# ── the decision ───────────────────────────────────────────────────────────

@pytest.mark.unit
class TestDecide:
    def test_fresh_is_reused_and_names_the_age(self):
        action, reason = rc.decide(rc.AUTO, 300, 3600)
        assert action == rc.REUSE
        assert "300" in reason and "3600" in reason

    def test_stale_is_re_run(self):
        action, reason = rc.decide(rc.AUTO, 7200, 3600)
        assert action == rc.REFRESH
        assert "past" in reason

    def test_never_refuses_even_a_fresh_hit(self):
        assert rc.decide(rc.NEVER, 1, 3600)[0] == rc.REFRESH

    def test_always_accepts_a_stale_hit_but_still_reports_the_age(self):
        action, reason = rc.decide(rc.ALWAYS, 999999, 3600)
        assert action == rc.REUSE
        assert "999999" in reason, (
            "reusing at any age is the operator's call; hiding the age is not")

    def test_an_unreadable_age_re_runs(self):
        """An unmeasurable age is not evidence of freshness."""
        for bad in (None, "recently", object()):
            assert rc.decide(rc.AUTO, bad, 3600)[0] == rc.REFRESH

    def test_a_future_dated_row_re_runs(self):
        action, reason = rc.decide(rc.AUTO, -500, 3600)
        assert action == rc.REFRESH
        assert "skew" in reason

    def test_exactly_at_the_ttl_is_still_fresh(self):
        assert rc.decide(rc.AUTO, 3600, 3600)[0] == rc.REUSE
        assert rc.decide(rc.AUTO, 3601, 3600)[0] == rc.REFRESH


# ── the key ────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestCacheKey:
    def test_the_same_request_gets_the_same_key(self):
        a = rc.cache_key("zap", "10.0.0.1", 443, {"active": False})
        b = rc.cache_key("zap", "10.0.0.1", 443, {"active": False})
        assert a == b

    def test_the_variant_separates_authenticated_from_anonymous(self):
        """The wrong-answer failure: serving an unauthenticated crawl in
        answer to a request for an authenticated one."""
        anon = rc.cache_key("playwright", "10.0.0.1", 443, {"auth": None})
        authed = rc.cache_key("playwright", "10.0.0.1", 443, {"auth": "user1"})
        assert anon != authed

    def test_tool_target_and_port_all_separate(self):
        base = rc.cache_key("zap", "10.0.0.1", 443)
        assert base != rc.cache_key("arjun", "10.0.0.1", 443)
        assert base != rc.cache_key("zap", "10.0.0.2", 443)
        assert base != rc.cache_key("zap", "10.0.0.1", 8443)

    def test_variant_ordering_does_not_change_the_key(self):
        a = rc.cache_key("arjun", "1.1.1.1", 80, {"paths": ["/a"], "depth": 2})
        b = rc.cache_key("arjun", "1.1.1.1", 80, {"depth": 2, "paths": ["/a"]})
        assert a == b, "a dict's insertion order must not fork the cache"

    def test_the_key_is_a_stable_hex_digest(self):
        k = rc.cache_key("zap", "10.0.0.1", 443)
        assert len(k) == 64 and all(c in "0123456789abcdef" for c in k)


# ── database side, with a stub cursor ──────────────────────────────────────

class _Cur:
    def __init__(self, row=None, raise_on=None):
        self._row, self._raise, self.executed = row, raise_on, []

    def execute(self, sql, params=None):
        self.executed.append((" ".join(sql.split()), params))
        if self._raise:
            raise self._raise

    def fetchone(self):
        return self._row


@pytest.mark.unit
class TestLookup:
    def test_a_fresh_row_is_reused_and_returns_the_payload(self):
        cur = _Cur(row=({"segments": ["zap output"]}, 120))
        action, reason, payload, age = rc.lookup(cur, "k", "zap", rc.AUTO)
        assert action == rc.REUSE
        assert payload == {"segments": ["zap output"]}
        assert age == 120

    def test_a_stale_row_returns_no_payload(self):
        """Handing back a payload the caller must remember not to use is how
        a stale result gets used anyway."""
        cur = _Cur(row=({"segments": ["old"]}, 10 ** 7))
        action, reason, payload, age = rc.lookup(cur, "k", "zap", rc.AUTO)
        assert action == rc.REFRESH
        assert payload is None
        assert age == 10 ** 7, "the age is still reported so the trace can say why"

    def test_nothing_stored_is_a_miss(self):
        action, reason, payload, age = rc.lookup(_Cur(row=None), "k", "zap")
        assert action == rc.MISS and payload is None

    def test_an_unreadable_cache_is_not_a_miss(self):
        """The repo's most expensive recurring bug, in cache form. Both run
        the tool; only one says the cache is broken."""
        cur = _Cur(raise_on=RuntimeError("relation does not exist"))
        action, reason, payload, age = rc.lookup(cur, "k", "zap")
        assert action == rc.UNAVAILABLE
        assert action != rc.MISS
        assert "unreadable" in reason

    def test_never_does_not_even_query(self):
        cur = _Cur(row=({"x": 1}, 1))
        action, _, payload, _ = rc.lookup(cur, "k", "zap", rc.NEVER)
        assert action == rc.REFRESH and payload is None
        assert cur.executed == [], "never must not pay for a query either"

    def test_a_dict_row_is_handled_as_well_as_a_tuple(self):
        """RealDictCursor is used across this codebase; reading only tuples
        would make the cache silently dead in production."""
        cur = _Cur(row={"payload": {"segments": ["x"]}, "age": 5})
        action, _, payload, age = rc.lookup(cur, "k", "zap", rc.AUTO)
        assert action == rc.REUSE and payload == {"segments": ["x"]} and age == 5


@pytest.mark.unit
class TestStore:
    def test_a_result_is_upserted_with_its_engagement(self):
        cur = _Cur()
        ok = rc.store(cur, "k", "zap", "10.0.0.1", 443, {"segments": ["x"]},
                      engagement_id="e-1", variant={"active": False}, run_id="r-1")
        assert ok is True
        sql, params = cur.executed[0]
        assert "INSERT INTO public.recon_cache" in sql
        # Token-wise rather than one quoted SQL fragment: the guard ratchet
        # in tests/test_guard_style.py exists because pinning an expression
        # makes a test fail when the code is reformatted or improved.
        assert "ON CONFLICT" in sql and "DO UPDATE" in sql and "cache_key" in sql
        assert "e-1" in params, (
            "collected target data must be engagement-attributable or a purge "
            "cannot claim it")

    def test_a_failed_store_is_not_fatal(self):
        cur = _Cur(raise_on=RuntimeError("disk full"))
        assert rc.store(cur, "k", "zap", "1.1.1.1", 80, {"a": 1}) is False

    def test_a_disabled_tool_is_not_stored(self, monkeypatch):
        monkeypatch.setenv("RECON_CACHE_TTL_ZAP", "0")
        cur = _Cur()
        assert rc.store(cur, "k", "zap", "1.1.1.1", 80, {"a": 1}) is False
        assert cur.executed == []

    def test_an_upsert_does_not_null_out_an_existing_engagement(self):
        cur = _Cur()
        rc.store(cur, "k", "zap", "1.1.1.1", 80, {"a": 1}, engagement_id=None)
        sql, _ = cur.executed[0]
        assert "COALESCE" in sql and "EXCLUDED.engagement_id" in sql, (
            "a later writer with no engagement must not erase the attribution "
            "an earlier one resolved")


# ── visibility ─────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestNote:
    def test_reused_and_ran_fresh_read_differently(self):
        """An operator reading a suspiciously fast build must be able to tell
        whether the tool ran."""
        reused = rc.note(rc.REUSE, "zap", "age 120s")
        fresh = rc.note(rc.MISS, "zap", "nothing cached")
        assert "REUSED" in reused
        assert "REUSED" not in fresh and "ran fresh" in fresh

    def test_an_unavailable_cache_still_says_the_tool_ran(self):
        assert "ran fresh" in rc.note(rc.UNAVAILABLE, "zap", "cache unreadable")

    def test_the_note_carries_the_reason_verbatim(self):
        assert "age 120s within the 3600s window" in rc.note(
            rc.REUSE, "zap", "age 120s within the 3600s window")


# ── schema ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_the_table_is_declared_in_the_installer():
    """CLAUDE.md: any new database element goes in the install scripts, or
    every query against it is skipped by the SQL guard rather than checked."""
    ddl = (REPO / "db_init" / "ensure_all_tables.sql").read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS public.recon_cache" in ddl
    for col in ("cache_key", "tool", "ip", "port", "engagement_id", "variant",
                "payload", "run_id", "created_at"):
        assert col in ddl.split("public.recon_cache")[1][:900], col
    assert "UNIQUE" in ddl.split("public.recon_cache")[1][:900], (
        "the ON CONFLICT (cache_key) upsert needs a unique constraint on that "
        "column or every insert raises")
