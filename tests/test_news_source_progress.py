"""A news source has THREE outcomes, and the run record must carry all three.

Two defects, one shape — "fetched and fine", "fetched with errors" and "could
not fetch / still fetching" were stored as two states, and the state that
disappeared was the one needing attention:

 1. `_fetch_feed` returns `(articles, fetch_error)` and a soft error is
    RECORDED, not raised ("one dead feed must not abort the other sixteen").
    Control then fell straight into an UPDATE with a hardcoded
    `last_status = 'ok', last_error = NULL`, so a feed that soft-failed every
    run was stored clean. The Sources panel renders `last_error`, so it showed
    the feed healthy while the per_source row for the SAME run said it failed.

 2. `src_stats` was appended to `stats["per_source"]` only AFTER the per-source
    try/except, and `_update_run` persists the list only then. A source hanging
    mid-fetch contributed no row at all — visible only as the arithmetic gap
    between `sources_fetched` and the source count, which no view computes.

These tests EXECUTE `fetch_all_sources` against a fake connection that records
every statement, so they check what is written rather than how it is spelled.
No network and no database.

Sabotage check (each reintroduces the exact defect):
  * hardcode `last_status = 'ok', last_error = NULL` in the success UPDATE ->
    test_a_soft_failure_is_stored_as_a_failure and
    test_sources_panel_agrees_with_the_run_record fail;
  * move `stats["per_source"].append(src_stats)` back below the try/except ->
    test_a_pending_row_is_persisted_before_the_fetch_starts and
    test_a_hung_source_stays_visible_in_flight fail.

    pytest tests/test_news_source_progress.py -q
"""

import copy
import importlib.util
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
AGENT = REPO / "news_runner" / "news_agent.py"


@pytest.fixture(scope="module")
def agent():
    if not AGENT.exists():
        pytest.skip("news_agent.py not present in this checkout")
    pytest.importorskip("psycopg2", reason="psycopg2 required to import news_agent")
    pytest.importorskip("requests")
    spec = importlib.util.spec_from_file_location("news_agent_under_test", AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
# A fake psycopg2 connection: records (sql, params) and nothing else.
# --------------------------------------------------------------------------

class _Cursor:
    def __init__(self, conn, rows):
        self._conn = conn
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        # A real driver serialises the parameters AT EXECUTE TIME. The record
        # here is mutated in place afterwards (that is the feature under test),
        # so a reference would make every snapshot show the final state.
        snap = params
        if params is not None:
            snap = tuple(copy.deepcopy(_jsonb_payload(x)) for x in params)
        self._conn.statements.append((" ".join(sql.split()), snap))

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _Conn:
    def __init__(self, sources):
        self.sources = sources
        self.statements = []
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self, cursor_factory=None):
        # The only SELECT in this path is the source list.
        return _Cursor(self, self.sources if cursor_factory is not None else [])

    def commit(self):
        self.commits += 1


SOURCES = [
    {"id": "11111111-1111-1111-1111-111111111111", "name": "Good Feed",
     "url": "https://example-corp.com/good.xml", "parser": "rss"},
    {"id": "22222222-2222-2222-2222-222222222222", "name": "Soft Fail Feed",
     "url": "https://legacy-corp.net/dead.xml", "parser": "rss"},
]

SOFT_ERROR = ("direct=failed: HTTP 406; feedparser=failed: no entries; "
              "discover=failed: no feed link")


def _jsonb_payload(obj):
    """psycopg2 wraps the list in Json(...); unwrap to the adapted value."""
    return getattr(obj, "adapted", obj)


EMITTED: list = []


def _run(agent, monkeypatch, feed, sources=SOURCES, run_id="run-1"):
    """Drive fetch_all_sources with a stubbed fetcher. Returns (stats, conn)."""
    conn = _Conn(sources)
    EMITTED.clear()
    monkeypatch.setattr(agent, "_connect", lambda: conn)
    monkeypatch.setattr(agent, "_fetch_feed", feed)
    monkeypatch.setattr(agent, "_dedupe_and_upsert",
                        lambda c, art, name: (art["link"], True))
    monkeypatch.setattr(agent, "_apply_kev_flags", lambda c: 0)
    monkeypatch.setattr(agent, "_emit_webhook",
                        lambda ev, src, data: EMITTED.append((ev, data)))
    stats = agent.fetch_all_sources(run_id=run_id)
    return stats, conn


def _source_updates(conn):
    """Every UPDATE news_sources, as {source_id: (status, error)}."""
    out = {}
    for sql, params in conn.statements:
        if not sql.startswith("UPDATE news_sources"):
            continue
        if "last_status = 'error'" in sql:          # the raised-exception branch
            out[params[-1]] = ("error", params[0])
        elif "last_status = 'ok'" in sql:           # the old hardcoded branch
            out[params[-1]] = ("ok", None)
        else:                                       # parameterised: (status, error, id)
            out[params[-1]] = (params[0], params[1])
    return out


def _run_rows(conn):
    """Every per_source list persisted to news_runs, in write order."""
    return [params[-2] for sql, params in conn.statements
            if sql.startswith("UPDATE news_runs")]


def _entry(per_source, name):
    for e in per_source:
        if e["name"] == name:
            return e
    raise AssertionError(f"{name!r} has no per_source entry: {per_source}")


# --------------------------------------------------------------------------
# Item 1 — a soft feed error must be stored as a failure
# --------------------------------------------------------------------------

def _mixed_feed(url, parser):
    if "dead" in url:
        return [], SOFT_ERROR
    return [{"title": "t", "link": "https://example-corp.com/a",
             "published": None, "raw_excerpt": ""}], None


def test_a_soft_failure_is_stored_as_a_failure(agent, monkeypatch):
    stats, conn = _run(agent, monkeypatch, _mixed_feed)
    updates = _source_updates(conn)

    status, error = updates[SOURCES[1]["id"]]
    assert status == "error", (
        "a source whose fetch returned an error was stored with "
        f"last_status={status!r} — the soft-fail path still writes a "
        "hardcoded 'ok', so a feed that fails every run reads as healthy")
    assert error == SOFT_ERROR, (
        f"last_error is {error!r}, not the reason the fetcher gave; the "
        "operator sees a dead feed with no diagnosis")

    assert updates[SOURCES[0]["id"]] == ("ok", None), (
        "a source that fetched cleanly must still be stored ok with no error")


def test_sources_panel_agrees_with_the_run_record(agent, monkeypatch):
    """Both surfaces describe the same run, so they must not contradict.

    The Sources panel renders news_sources.last_status/last_error; the progress
    panel renders news_runs.per_source. One said healthy while the other said
    failed, for the same source in the same run.
    """
    stats, conn = _run(agent, monkeypatch, _mixed_feed)
    updates = _source_updates(conn)

    for src in SOURCES:
        entry = _entry(stats["per_source"], src["name"])
        status, error = updates[src["id"]]
        assert status == entry["status"], (
            f"{src['name']}: Sources panel shows last_status={status!r} while "
            f"the run record shows status={entry['status']!r} for the same run")
        assert (error or None) == (entry["error"] or None), (
            f"{src['name']}: Sources panel shows last_error={error!r} while "
            f"the run record shows error={entry['error']!r}")


def test_one_soft_failure_does_not_abort_the_other_sources(agent, monkeypatch):
    stats, _ = _run(agent, monkeypatch, _mixed_feed)
    assert len(stats["per_source"]) == len(SOURCES)
    assert _entry(stats["per_source"], "Good Feed")["new"] == 1


# --------------------------------------------------------------------------
# Item 2 — a source in flight must contribute a row
# --------------------------------------------------------------------------

def test_a_pending_row_is_persisted_before_the_fetch_starts(agent, monkeypatch):
    """At the moment a fetch begins, that source is already on the record."""
    seen = {}

    def feed(url, parser):
        # Snapshot what the DATABASE holds right now, not the in-memory list.
        rows = _run_rows(conn_box["conn"])
        seen[url] = rows[-1] if rows else []
        return [], None

    conn_box = {}
    conn = _Conn(SOURCES)
    conn_box["conn"] = conn
    monkeypatch.setattr(agent, "_connect", lambda: conn)
    monkeypatch.setattr(agent, "_fetch_feed", feed)
    monkeypatch.setattr(agent, "_dedupe_and_upsert", lambda c, a, n: ("i", True))
    monkeypatch.setattr(agent, "_apply_kev_flags", lambda c: 0)
    monkeypatch.setattr(agent, "_emit_webhook", lambda *a, **k: None)
    agent.fetch_all_sources(run_id="run-1")

    for src in SOURCES:
        persisted = seen[src["url"]]
        entry = _entry(persisted, src["name"])
        assert entry["status"] == "fetching", (
            f"{src['name']} is persisted as {entry['status']!r} while its fetch "
            "is still running")
        assert entry["articles"] == 0 and entry["error"] is None, (
            "a pending row must claim no results yet")


def test_a_hung_source_stays_visible_in_flight(agent, monkeypatch):
    """A source that never returns must not vanish from the record.

    Simulated with a BaseException, which `except Exception` does not catch —
    the same observable end state as a worker killed mid-fetch: the loop never
    reaches the completion write, so whatever was persisted before the fetch is
    what the operator is left looking at.
    """
    class _Killed(BaseException):
        pass

    def feed(url, parser):
        if "dead" in url:
            raise _Killed("worker went away mid-fetch")
        return [], None

    conn = _Conn(SOURCES)
    monkeypatch.setattr(agent, "_connect", lambda: conn)
    monkeypatch.setattr(agent, "_fetch_feed", feed)
    monkeypatch.setattr(agent, "_dedupe_and_upsert", lambda c, a, n: ("i", True))
    monkeypatch.setattr(agent, "_apply_kev_flags", lambda c: 0)
    monkeypatch.setattr(agent, "_emit_webhook", lambda *a, **k: None)
    with pytest.raises(_Killed):
        agent.fetch_all_sources(run_id="run-1")

    last = _run_rows(conn)[-1]
    stalled = _entry(last, "Soft Fail Feed")
    assert stalled["status"] == "fetching", (
        "the stalled source is recorded as "
        f"{stalled['status']!r}; it is still in flight")
    assert _entry(last, "Good Feed")["status"] == "ok", (
        "the source that finished before the stall must still read as finished")


def test_each_source_contributes_exactly_one_row(agent, monkeypatch):
    """The pending row is updated IN PLACE, not appended a second time."""
    stats, conn = _run(agent, monkeypatch, _mixed_feed)
    names = [e["name"] for e in stats["per_source"]]
    assert names == [s["name"] for s in SOURCES], (
        f"per_source holds {names} — a completed source was appended again "
        "instead of updating the pending row it already had")
    for rows in _run_rows(conn):
        seen = [e["name"] for e in rows]
        assert len(seen) == len(set(seen)), f"duplicate rows persisted: {seen}"


def test_progress_writes_stay_bounded_and_commit(agent, monkeypatch):
    """Two writes per source, each committed — no transaction spans a fetch.

    More frequent progress means more writes; the bound is what keeps that
    honest, and committing each one is what makes the pending row visible to
    the reader while the fetch is still running.
    """
    stats, conn = _run(agent, monkeypatch, _mixed_feed)
    run_writes = len(_run_rows(conn))
    assert run_writes == 2 * len(SOURCES), (
        f"{run_writes} news_runs writes for {len(SOURCES)} sources; expected "
        "exactly one pending + one completion write per source")
    assert conn.commits >= run_writes, (
        "a progress write that is not committed is invisible to the reader "
        "polling the run, and holds a transaction open across the next fetch")


def test_a_failed_cycle_keeps_the_partial_record(agent, monkeypatch):
    """finish_run with no stats must not erase what the loop already wrote.

    `run_full_cycle` calls `finish_run(run_id, {}, error=...)` when the cycle
    raises — the run that most needs explaining. Zeroing per_source there would
    delete the in-flight row this change exists to keep.
    """
    conn = _Conn([])
    monkeypatch.setattr(agent, "_connect", lambda: conn)
    agent.finish_run("run-1", {}, error="boom")

    sql, params = conn.statements[-1]
    assert re.search(r"per_source\s*=\s*COALESCE\(", sql), (
        "finish_run overwrites per_source unconditionally, so a failed cycle "
        "erases the per-source detail that explains the failure")
    assert params[-3] is None, (
        "finish_run passes a value for per_source even when the caller has "
        "none, so COALESCE can never keep the stored rows")


def test_the_completion_webhook_counts_the_failures(agent, monkeypatch):
    """A run where a feed failed must not emit as an unqualified success."""
    _run(agent, monkeypatch, _mixed_feed)
    events = dict(EMITTED)
    assert "news_ingest_completed" in events, "the completion event is not emitted"
    data = events["news_ingest_completed"]
    assert data.get("sources_failed") == 1, (
        f"sources_failed={data.get('sources_failed')!r}; a subscriber sees "
        "only how many sources were processed, not that one of them failed")
