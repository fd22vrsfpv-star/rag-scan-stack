"""The shared query cache: TTL, refresh on demand, and the failure rule.

The database is remote (`sslmode=require`): ~46 ms for a pooled query over the
WAN, 80 s for `/assets?limit=5000`. Four services had each written the same
cache to cope —

    nmap_scanner, dashboard/bff/routers/scans.py, etl/scope_gate.py,
    kali_listener

— and **none of them could be refreshed**. An operator who changed the scope
waited out the TTL with no way to say "re-read it now".

The behaviour that matters most here is the failure rule. A refresh that raises
is NOT evidence the data is gone, so the previous value keeps being served and
the error is recorded. Caching the failure instead — or dropping the value —
would turn one transient DB blip into a TTL-long outage, which is this repo's
recurring "unreachable reported as absent" in another costume.

Runs anywhere: pure Python, no DB.

    pytest tests/test_query_cache.py -q
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
qc = pytest.importorskip("query_cache", reason="common/query_cache.py missing")


def _counter():
    """A loader that returns 1, 2, 3 … so a re-read is visible."""
    box = {"n": 0}

    def load():
        box["n"] += 1
        return box["n"]
    return load, box


def test_second_read_is_served_from_cache():
    c = qc.QueryCache("t_hit", ttl=60)
    load, _ = _counter()
    assert c.get(load) == 1
    assert c.get(load) == 1, "the loader ran twice inside the TTL"
    assert c.hits == 1 and c.misses == 1


def test_expiry_reloads():
    c = qc.QueryCache("t_ttl", ttl=0.05)
    load, _ = _counter()
    assert c.get(load) == 1
    time.sleep(0.08)
    assert c.get(load) == 2, "the value did not reload after the TTL"


def test_refresh_on_demand_without_waiting_for_the_ttl():
    """The whole point: the operator can say 're-read it now'."""
    c = qc.QueryCache("t_inval", ttl=3600)
    load, _ = _counter()
    assert c.get(load) == 1
    c.invalidate()
    assert c.get(load) == 2, (
        "invalidate() did not force a re-read — this is the capability the four "
        "hand-rolled caches lacked")


def test_force_bypasses_a_fresh_value():
    c = qc.QueryCache("t_force", ttl=3600)
    load, _ = _counter()
    c.get(load)
    assert c.get(load, force=True) == 2


# -- the failure rule ----------------------------------------------------

def test_a_failed_refresh_keeps_serving_the_last_good_value():
    c = qc.QueryCache("t_stale", ttl=0.01)
    assert c.get(lambda: "good") == "good"
    time.sleep(0.03)

    def boom():
        raise RuntimeError("db unreachable")

    assert c.get(boom) == "good", (
        "a failed refresh dropped the value — a transient DB blip would become "
        "a TTL-long outage, and 'could not re-read' would read as 'no data'")
    assert c.stale_serves == 1
    assert "db unreachable" in (c.last_error or "")


def test_a_failure_is_never_cached():
    """Otherwise one blip poisons the whole TTL."""
    c = qc.QueryCache("t_nocache_err", ttl=3600)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("blip")
        return "recovered"

    with pytest.raises(RuntimeError):
        c.get(flaky)          # nothing cached yet -> the caller must see it
    assert c.get(flaky) == "recovered", (
        "the error was cached; the next call should retry, not serve the "
        "failure for a whole TTL")


def test_first_load_failure_propagates():
    """With nothing held, there is no stale value to fall back to."""
    c = qc.QueryCache("t_first_fail", ttl=60)
    with pytest.raises(ValueError):
        c.get(lambda: (_ for _ in ()).throw(ValueError("cold")))
    assert c.peek("sentinel") == "sentinel"


def test_stale_on_error_can_be_turned_off():
    c = qc.QueryCache("t_nostale", ttl=0.01, stale_on_error=False)
    c.get(lambda: "v")
    time.sleep(0.03)
    with pytest.raises(RuntimeError):
        c.get(lambda: (_ for _ in ()).throw(RuntimeError("x")))


# -- visibility ----------------------------------------------------------

def test_age_survives_invalidation():
    """Invalidating must not destroy the one number the operator needs.

    `invalidate()` originally zeroed the load timestamp, so `age()` returned
    seconds-since-epoch and a failed refresh logged "serving the previous
    value, 1792019805s old" — meaningless, and it reads like corruption at the
    moment the operator most needs to know how stale the data is.
    """
    c = qc.QueryCache("t_age_inval", ttl=3600)
    c.get(lambda: "v")
    c.invalidate()
    a = c.age()
    assert a is not None and a < 5, (
        f"age() reported {a}s after invalidate() — the load timestamp was "
        "destroyed instead of a staleness flag being set")
    assert not c.is_fresh(), "invalidate() did not actually mark it stale"


def test_age_is_reportable_so_staleness_can_be_shown():
    c = qc.QueryCache("t_age", ttl=60)
    assert c.age() is None, "an unloaded cache must not claim an age"
    c.get(lambda: 1)
    a = c.age()
    assert a is not None and a < 1.0


def test_registry_lists_and_busts_by_name():
    a = qc.QueryCache("t_reg_a", ttl=3600)
    b = qc.QueryCache("t_reg_b", ttl=3600)
    la, _ = _counter(); lb, _ = _counter()
    a.get(la); b.get(lb)
    names = {s["name"] for s in qc.all_stats()}
    assert {"t_reg_a", "t_reg_b"} <= names

    assert qc.invalidate("t_reg_a") == ["t_reg_a"]
    assert a.get(la) == 2
    assert b.get(lb) == 1, "busting one cache invalidated another"

    busted = qc.invalidate()
    assert "t_reg_b" in busted, "invalidate(None) must mark every cache stale"


def test_invalidate_reports_what_it_actually_did():
    """Claiming success for a name that does not exist is a lie."""
    assert qc.invalidate("no_such_cache_xyz") == []
