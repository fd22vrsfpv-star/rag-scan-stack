"""`support` counts observations, not pairings.

Run on demand:

    pytest tests/test_tool_learning_support.py -v

WHY THIS EXISTS
---------------
`learn_from_tool_executions()` reconstructs "tool A failed like this and tool B
ran next" from the `tool_executions` history. It paired every failure against
EVERY later run inside the correlation window, so the count it stored was a
cross product, not a count of occasions: 77 executions produced 284 rule
upserts, and one pair's `support` read 68 for something observed a handful of
times. Both the DDL comment on the column ("support = times this (failure ->
preferred_tool) pair was observed") and the sentence an operator reads out of
`preferred_order` ("learned from N observations of: <phrase>") promise a count
of occasions, and `PROMOTE_AFTER_SUPPORT` gates candidate RE-ORDERING on it —
so an inflated number promotes a rule seen once.

An observation is now: one failed run of A, and the NEXT run of B after it.
Re-running B does not make the failure more observed, and once A fails that way
again, everything after that belongs to the second failure.

THE FIXTURE
-----------
Synthetic, and a realistic reproduction rather than a capture: the shape is the
sequence this module was written for (hydra failing on an OpenSSH 4.7p1 that
offers only ssh-rsa/ssh-dss host keys, nmap's ssh-brute running after it), and
the hydra error line is that tool's real wording. It is deliberately tiny so the
correct support is countable by eye.

SABOTAGE PROOF
--------------
Delete either half of the de-duplication in
`learn_from_tool_executions` — the `if later["tool"] in paired: continue`, or
the `break` when the same failure recurs — and the corresponding test below
fails with the old inflated number (3 and 2 respectively, against 1).
"""
import datetime as dt
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

tl = pytest.importorskip("etl.tool_learning", reason="etl/tool_learning.py not importable")

T0 = dt.datetime(2026, 9, 20, 11, 0, 0)

# Hydra's own wording for the failure this module exists to learn from.
HYDRA_KEX = (
    "[ERROR] could not connect to ssh://192.168.1.150:22 - kex error : "
    "no match for method server host key algo: server [ssh-rsa,ssh-dss], "
    "client [rsa-sha2-512,rsa-sha2-256,ssh-ed25519]"
)


def _fail(tool, minute, error=HYDRA_KEX):
    """A tool_executions row for a run that errored."""
    return (tool, "ssh", "192.168.1.150", 22, "failed", 255, "", error, None,
            T0 + dt.timedelta(minutes=minute))


def _ok(tool, minute):
    """A tool_executions row for a run that parsed to something."""
    return (tool, "ssh", "192.168.1.150", 22, "completed", 0, "ok", "",
            {"credentials": [{"username": "msfadmin"}]},
            T0 + dt.timedelta(minutes=minute))


class _Cur:
    """Enough cursor to drive the backfill, and it accumulates like the upsert.

    The RETURNING values are computed the way the real `ON CONFLICT DO UPDATE`
    computes them (support/attempts +1, successes += the excluded value), so the
    number this test asserts on is the number a reader of the table would see.
    """

    def __init__(self, rows):
        self._rows = rows
        self._fetchone = None
        self.rules = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        if "FROM public.tool_executions" in sql:
            self._pending = list(self._rows)
            return
        if "INSERT INTO public.tool_selection_learned" in sql:
            phase, service, failed_tool, sig, preferred, _phrase, succ = params[:7]
            key = (phase, service, failed_tool, sig, preferred)
            r = self.rules.setdefault(
                key, {"support": 0, "attempts": 0, "successes": 0})
            r["support"] += 1
            r["attempts"] += 1
            r["successes"] += succ
            self._fetchone = ("00000000-0000-0000-0000-000000000000",
                              r["support"], r["attempts"], r["successes"],
                              r["successes"] / r["attempts"], "active", False)
            return
        raise AssertionError(f"unexpected SQL: {sql[:80]}")

    def fetchall(self):
        return self._pending

    def fetchone(self):
        return self._fetchone


class _Conn:
    def __init__(self, cur):
        self._cur = cur

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return self._cur

    def commit(self):
        pass


def _backfill(monkeypatch, rows):
    """Run the backfill over `rows`; return (result, {rule key: counters})."""
    cur = _Cur(rows)
    monkeypatch.setattr(tl, "_connect", lambda: _Conn(cur))
    out = tl.learn_from_tool_executions()
    assert out["available"] is True, out
    return out, cur.rules


def _support(rules, failed_tool, preferred_tool):
    hits = [v for k, v in rules.items()
            if k[2] == failed_tool and k[4] == preferred_tool]
    assert len(hits) == 1, f"expected one {failed_tool}->{preferred_tool} rule, got {rules}"
    return hits[0]["support"]


def test_one_failure_followed_by_repeated_runs_is_one_observation(monkeypatch):
    """hydra failed once; nmap then ran three times. That is ONE observation.

    The old logic paired the single failure against each nmap run and stored
    support 3 — a rule that clears PROMOTE_AFTER_SUPPORT (2) on the strength of
    one failure nobody saw twice.
    """
    rows = [_fail("hydra", 0), _ok("nmap", 1), _ok("nmap", 2), _ok("nmap", 3)]
    out, rules = _backfill(monkeypatch, rows)
    assert out["examined"] == 4
    assert out["failures"] == 1
    assert _support(rules, "hydra", "nmap") == 1
    assert out["rules"] == 1


def test_repeated_failures_before_one_run_are_one_observation(monkeypatch):
    """hydra failed twice, then nmap ran once. Still ONE 'nmap followed hydra'.

    The old logic paired both failures against the same nmap run: support 2.
    """
    rows = [_fail("hydra", 0), _fail("hydra", 1), _ok("nmap", 2)]
    _out, rules = _backfill(monkeypatch, rows)
    assert _support(rules, "hydra", "nmap") == 1


def test_genuinely_separate_occasions_still_count_separately(monkeypatch):
    """Two failures each followed by their own nmap run ARE two observations.

    The de-duplication must not flatten a pair to 1 forever — corroboration is
    the whole point of the support threshold. The old logic scored this 3 (the
    first failure also pairing with the second nmap run); the truth is 2.
    """
    rows = [_fail("hydra", 0), _ok("nmap", 1), _fail("hydra", 2), _ok("nmap", 3)]
    _out, rules = _backfill(monkeypatch, rows)
    assert _support(rules, "hydra", "nmap") == 2


def test_each_distinct_next_tool_is_its_own_observation(monkeypatch):
    """One failure followed by two DIFFERENT tools teaches one pair each."""
    rows = [_fail("hydra", 0), _ok("nmap", 1), _ok("netexec", 2), _ok("nmap", 3)]
    _out, rules = _backfill(monkeypatch, rows)
    assert _support(rules, "hydra", "nmap") == 1
    assert _support(rules, "hydra", "netexec") == 1


def test_a_run_outside_the_window_is_still_not_paired(monkeypatch):
    """The correlation window is unchanged by the de-duplication."""
    beyond = tl.CORRELATION_WINDOW_MINUTES + 10
    rows = [_fail("hydra", 0), _ok("nmap", beyond)]
    _out, rules = _backfill(monkeypatch, rows)
    assert rules == {}
