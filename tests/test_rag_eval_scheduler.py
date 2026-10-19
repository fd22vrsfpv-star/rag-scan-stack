"""Something re-runs the retrieval eval, and every cycle leaves a record.

`_run_rag_eval` has scored retrieval against operator feedback since the rating
UI landed on 2026-06-01. Repo-wide its only caller outside the router was a
button in the dashboard — no cron, no scheduler, no sweep — so
Docs/OPEN_ITEMS.md's "nothing measures whether retrieval improved" was true of
a measurement that already existed.

`scan_recommender/rag_eval_scheduler.py` takes it on a cadence. What this guard
pins is the part that is easy to get wrong:

  * THREE outcomes, never two. "scored", "nothing to score" and "it blew up"
    are different facts. An empty eval set is NOT a failure, and a failure is
    not a score of zero.
  * A non-scored cycle leaves metric columns NULL, never 0.0 — a 0.0 is a
    score, and would read in the history chart as retrieval that found nothing
    useful.
  * The operator toggle is re-read from `app_settings` every cycle, and a
    database blip falls back to the env default rather than silently
    disabling a scheduler the operator turned on.
  * One bad cycle does not kill the loop.
  * The literal `/rag/eval/scheduler` routes are declared ABOVE
    `/rag/eval/{run_id}`, or FastAPI matches "scheduler" as a run id.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q -r tests/requirements.txt; PYTHONPATH=.:tests \
      python -m pytest tests/test_rag_eval_scheduler.py -q'
"""
from __future__ import annotations

import asyncio
import importlib
import os
import re
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVICE_DIR = os.path.join(REPO, "scan_recommender")

pytest.importorskip("psycopg2", reason="psycopg2 required to import the scheduler")


def _load(modname):
    """Import a scan_recommender module the way the SERVICE does — flat.

    The service runs with `scan_recommender/` as its working directory and its
    modules import each other by bare name. The suite deliberately keeps
    service directories off sys.path (they hold colliding module names such as
    `scan_recommender.py` shadowing the package), so the path goes on only for
    the duration of the import and comes straight back off.
    """
    sys.path.insert(0, SERVICE_DIR)
    try:
        return importlib.import_module(modname)
    finally:
        try:
            sys.path.remove(SERVICE_DIR)
        except ValueError:  # pragma: no cover
            pass


S = _load("rag_eval_scheduler")


# ───────────────────────────── a fake database ──────────────────────────────

class FakeCursor:
    def __init__(self, owner):
        self.owner = owner

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.owner.executed.append((sql, params))
        if self.owner.raise_on_execute:
            raise RuntimeError("database is down")

    def fetchall(self):
        return list(self.owner.settings_rows)

    def fetchone(self):
        return ("00000000-0000-0000-0000-000000000001",)


class FakeConn:
    def __init__(self, settings_rows=(), raise_on_execute=False):
        self.settings_rows = settings_rows
        self.raise_on_execute = raise_on_execute
        self.executed = []
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self, **kw):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1


def _sched(monkeypatch, settings_rows=(), raise_on_execute=False):
    sched = S.RagEvalScheduler()
    conn = FakeConn(settings_rows, raise_on_execute)
    monkeypatch.setattr(sched, "_conn", lambda: conn)
    monkeypatch.setattr(S, "_emit_webhook", lambda data: None)
    return sched, conn


def _outcome_of(sql_params):
    """The `outcome=<token>` written into rag_eval_runs.notes, or None."""
    for sql, params in sql_params:
        if "rag_eval_runs" not in sql:
            continue
        for p in (params or ()):
            m = re.search(r"outcome=(\w+)", str(p))
            if m:
                return m.group(1)
    return None


# ──────────────────────── three outcomes, never two ─────────────────────────

class TestThreeOutcomes:
    def test_an_empty_eval_set_is_skipped_not_failed(self, monkeypatch):
        sched, conn = _sched(monkeypatch)
        monkeypatch.setattr(S, "_load_evaluator", lambda: (
            lambda **kw: {"ok": True, "ran": False, "eval_set_size": 0,
                          "reason": "no feedback-rated queries in the window"}))
        out = sched.run_once()
        assert out["outcome"] == S.OUTCOME_SKIPPED_EMPTY
        assert out["outcome"] != S.OUTCOME_FAILED
        assert _outcome_of(conn.executed) == S.OUTCOME_SKIPPED_EMPTY

    def test_an_exploding_evaluator_is_failed_not_skipped(self, monkeypatch):
        sched, conn = _sched(monkeypatch)

        def _boom(**kw):
            raise RuntimeError("embedder unreachable")

        monkeypatch.setattr(S, "_load_evaluator", lambda: _boom)
        out = sched.run_once()
        assert out["outcome"] == S.OUTCOME_FAILED
        assert "embedder unreachable" in out["error"]
        assert _outcome_of(conn.executed) == S.OUTCOME_FAILED

    def test_a_scored_run_is_not_written_twice(self, monkeypatch):
        """`_run_rag_eval` already wrote the row with the metrics in it."""
        sched, conn = _sched(monkeypatch)
        monkeypatch.setattr(S, "_load_evaluator", lambda: (
            lambda **kw: {"ok": True, "ran": True, "id": "abc",
                          "eval_set_size": 7, "ndcg_at_10": 0.61, "mrr": 0.5}))
        out = sched.run_once()
        assert out["outcome"] == S.OUTCOME_SCORED
        assert out["eval_set_size"] == 7
        inserts = [s for s, _ in conn.executed if "rag_eval_runs" in s]
        assert inserts == [], "the scheduler double-recorded a scored run"

    def test_the_three_tokens_are_distinct(self):
        assert len(set(S.OUTCOMES)) == 3

    def test_a_cycle_never_raises(self, monkeypatch):
        """The loop body must come back with an outcome, not an exception."""
        sched, _ = _sched(monkeypatch, raise_on_execute=True)

        def _boom(**kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(S, "_load_evaluator", lambda: _boom)
        assert sched.run_once()["outcome"] in S.OUTCOMES


class TestANonScoredRunIsNotAScoreOfZero:
    def test_no_metric_column_is_written(self, monkeypatch):
        sched, conn = _sched(monkeypatch)
        monkeypatch.setattr(S, "_load_evaluator", lambda: (
            lambda **kw: {"ok": True, "ran": False, "eval_set_size": 0}))
        sched.run_once()
        inserts = [s for s, _ in conn.executed if "rag_eval_runs" in s]
        assert len(inserts) == 1
        metric = re.compile(r"\b(ndcg_at_\d+|mrr|recall_at_\d+|precision_at_\d+)\b")
        assert not metric.search(inserts[0]), (
            "a skipped cycle wrote a metric column; NULL means 'not measured',"
            " 0.0 means 'measured and bad' and the two must not be confused")

    def test_the_row_is_sized_zero(self, monkeypatch):
        sched, conn = _sched(monkeypatch)
        monkeypatch.setattr(S, "_load_evaluator", lambda: (
            lambda **kw: {"ok": True, "ran": False}))
        sched.run_once()
        params = [p for s, p in conn.executed if "rag_eval_runs" in s][0]
        assert 0 in params


# ─────────────────────────── the operator toggle ────────────────────────────

class TestTheToggle:
    def test_unset_falls_back_to_the_env_default(self, monkeypatch):
        sched, _ = _sched(monkeypatch, settings_rows=[])
        monkeypatch.setattr(S, "ENABLED_DEFAULT", True)
        assert sched.is_enabled() is True
        monkeypatch.setattr(S, "ENABLED_DEFAULT", False)
        assert sched.is_enabled() is False

    def test_the_persisted_value_wins(self, monkeypatch):
        monkeypatch.setattr(S, "ENABLED_DEFAULT", True)
        sched, _ = _sched(monkeypatch, settings_rows=[(S.KEY_ENABLED, "false")])
        assert sched.is_enabled() is False

    def test_a_database_error_does_not_disable_a_watcher_left_on(self, monkeypatch):
        """A blip must not read as "the operator turned it off"."""
        monkeypatch.setattr(S, "ENABLED_DEFAULT", True)
        sched, _ = _sched(monkeypatch, raise_on_execute=True)
        assert sched.is_enabled() is True

    def test_the_toggle_is_read_every_cycle(self, monkeypatch):
        """Not cached at construction — the UI must not need a restart."""
        sched, _ = _sched(monkeypatch, settings_rows=[(S.KEY_ENABLED, "true")])
        assert sched.is_enabled() is True
        sched._conn().settings_rows = [(S.KEY_ENABLED, "off")]
        assert sched.is_enabled() is False

    def test_the_cadence_is_clamped(self, monkeypatch):
        sched, _ = _sched(monkeypatch, settings_rows=[(S.KEY_POLL, "5")])
        assert sched.effective_config()["poll_interval"] == S.MIN_POLL_INTERVAL

    def test_only_the_named_keys_are_writable(self, monkeypatch):
        sched, conn = _sched(monkeypatch)
        updated = sched.write_settings(
            {"enabled": False, "window_days": 30, "value": "'; DROP TABLE"})
        assert sorted(updated) == ["enabled", "window_days"]
        written = {p[1] for s, p in conn.executed if "app_settings" in s}
        assert written == {S.KEY_ENABLED, S.KEY_WINDOW}
        assert all(re.search(r"ON CONFLICT", s) for s, _ in conn.executed
                   if "app_settings" in s and "INSERT" in s)


# ─────────────────────────────── the loop ───────────────────────────────────

class TestTheLoop:
    def test_one_bad_cycle_does_not_kill_it(self, monkeypatch):
        monkeypatch.setattr(S, "STARTUP_DELAY", 0)
        monkeypatch.setattr(S, "POLL_INTERVAL", 0)
        sched, _ = _sched(monkeypatch, settings_rows=[(S.KEY_ENABLED, "true")])
        monkeypatch.setattr(sched, "effective_config",
                            lambda: {"poll_interval": 0, "window_days": 1,
                                     "model_label": "t", "top_k": 10})
        calls = {"n": 0}

        def _boom():
            calls["n"] += 1
            if calls["n"] >= 4:
                sched.running = False
            raise RuntimeError("cycle blew up")

        monkeypatch.setattr(sched, "run_once", _boom)

        async def _drive():
            await asyncio.wait_for(sched.watch_loop(), timeout=10)

        asyncio.run(_drive())
        assert calls["n"] >= 4, "the loop stopped at the first failing cycle"

    def test_disabled_idles_without_evaluating(self, monkeypatch):
        monkeypatch.setattr(S, "STARTUP_DELAY", 0)
        monkeypatch.setattr(S, "MIN_POLL_INTERVAL", 0)
        monkeypatch.setattr(S, "POLL_INTERVAL", 0)
        sched, _ = _sched(monkeypatch, settings_rows=[(S.KEY_ENABLED, "false")])
        ran = {"n": 0}
        monkeypatch.setattr(sched, "run_once", lambda: ran.__setitem__("n", ran["n"] + 1))

        async def _drive():
            task = asyncio.ensure_future(sched.watch_loop())
            await asyncio.sleep(0.05)
            sched.stop()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_drive())
        assert ran["n"] == 0
        assert sched._active is False

    def test_start_is_idempotent(self, monkeypatch):
        """`rag_router` is mounted onto the app TWICE, so startup fires twice."""
        monkeypatch.setattr(S, "_scheduler", None)
        monkeypatch.setattr(S, "_task", None)

        async def _drive():
            started = [S.ensure_started(), S.ensure_started()]
            task = S._task
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return started

        assert asyncio.run(_drive()) == [True, False]


# ────────────────────────── the endpoints execute ───────────────────────────

@pytest.fixture(scope="module")
def client():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    try:
        er = _load("exploits_rag")
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"exploits_rag not importable here: {e}")
    app = FastAPI()
    app.include_router(er.rag_router)
    # Not a context manager on purpose: entering it runs the router's startup
    # handler, which would launch the real cadence inside the test.
    return TestClient(app), er


class TestTheEndpoints:
    def test_status_reports_an_outcome_vocabulary(self, client, monkeypatch):
        c, er = client
        sched = S.RagEvalScheduler()
        monkeypatch.setattr(sched, "_conn", lambda: FakeConn([]))
        monkeypatch.setattr(er, "_eval_scheduler", lambda: sched)
        r = c.get("/rag/eval/scheduler")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["last_outcome"] is None
        assert set(body["counts"]) == set(S.OUTCOMES)
        assert body["config"]["poll_interval"] >= S.MIN_POLL_INTERVAL

    def test_the_literal_route_is_not_eaten_by_the_id_route(self, client, monkeypatch):
        """Declared after /eval/{run_id}, "scheduler" arrives as a run id."""
        c, er = client
        sched = S.RagEvalScheduler()
        monkeypatch.setattr(sched, "_conn", lambda: FakeConn([]))
        monkeypatch.setattr(er, "_eval_scheduler", lambda: sched)
        body = c.get("/rag/eval/scheduler").json()
        assert "last_outcome" in body, \
            "/rag/eval/scheduler reached the run-detail handler instead"

    def test_put_persists_and_reports_what_it_wrote(self, client, monkeypatch):
        c, er = client
        sched = S.RagEvalScheduler()
        conn = FakeConn([])
        monkeypatch.setattr(sched, "_conn", lambda: conn)
        monkeypatch.setattr(er, "_eval_scheduler", lambda: sched)
        r = c.put("/rag/eval/scheduler", json={"enabled": False, "window_days": 14})
        assert r.status_code == 200, r.text
        assert sorted(r.json()["updated"]) == ["enabled", "window_days"]
        assert conn.commits >= 1

    def test_run_now_executes_a_cycle(self, client, monkeypatch):
        c, er = client
        sched = S.RagEvalScheduler()
        monkeypatch.setattr(sched, "_conn", lambda: FakeConn([]))
        monkeypatch.setattr(S, "_emit_webhook", lambda data: None)
        monkeypatch.setattr(S, "_load_evaluator", lambda: (
            lambda **kw: {"ok": True, "ran": False, "reason": "nothing rated"}))
        monkeypatch.setattr(er, "_eval_scheduler", lambda: sched)
        r = c.post("/rag/eval/scheduler/run-now")
        assert r.status_code == 200, r.text
        assert r.json()["outcome"] == S.OUTCOME_SKIPPED_EMPTY


def test_the_image_ships_the_scheduler():
    """The service Dockerfile COPYs each module by name.

    Miss one and the startup handler's import fails inside a try/except that
    exists so a broken scheduler never blocks the service — which is exactly
    the shape of a feature that silently never runs.
    """
    text = open(os.path.join(SERVICE_DIR, "Dockerfile"), encoding="utf-8").read()
    assert re.search(r"^COPY\s+rag_eval_scheduler\.py", text, re.M), \
        "scan_recommender/Dockerfile does not ship rag_eval_scheduler.py"


def test_the_router_starts_the_scheduler_on_startup():
    """A loop nothing starts is the bug this change exists to fix."""
    import ast
    src = open(os.path.join(SERVICE_DIR, "exploits_rag.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    handlers = [n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(getattr(d.func, "attr", None) == "on_event"
                        for d in n.decorator_list if isinstance(d, ast.Call))]
    assert handlers, "no startup handler on rag_router — nothing starts the loop"
    names = {getattr(n, "id", None) or getattr(n, "attr", None)
             for h in handlers for n in ast.walk(h) if isinstance(n, ast.Name)
             or isinstance(n, ast.Attribute)}
    assert "ensure_started" in names
