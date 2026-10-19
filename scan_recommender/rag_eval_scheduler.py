"""Re-run the retrieval evaluation on a cadence, and record that it ran.

WHY THIS EXISTS
---------------
`exploits_rag._run_rag_eval` replays every feedback-rated query through the
current retrieval pipeline and scores it against the operator's helpful /
unhelpful labels — NDCG@K, MRR, recall@K. The rating UI has existed since
2026-06-01. The evaluator has existed just as long. Repo-wide, its only caller
outside the router was a button in the dashboard (`dashboard/frontend/src/api/
rag.ts::useRagEvalRun`): no cron, no scheduler, no sweep. So "nothing measures
whether retrieval improved" was literally true — the measurement existed and
was never taken, and a re-rank change could land with no before/after number
anywhere.

This is the thing that takes it. Same shape as the other watchers in this repo
(`autogen_agents/reconnect_watcher.py` is the reference): a poll interval from
env, an operator toggle persisted in `app_settings` and re-read EVERY cycle so
the UI can disable it without a restart, and a loop body wrapped so one bad
cycle never kills the loop.

THREE OUTCOMES, NEVER TWO
-------------------------
"The eval ran and scored badly" and "there was nothing to score" are different
facts, and both differ from "the eval blew up". Each cycle therefore lands a
row in `rag_eval_runs`:

  * ``scored``        — `_run_rag_eval` wrote the row itself, metrics filled.
  * ``skipped_empty`` — nobody has rated a query in the window. NOT a failure.
                        Written here with `eval_set_size = 0` and metrics left
                        NULL (never 0.0 — a zero is a score, a NULL is "not
                        measured"; the dashboard already renders NULL as "—").
  * ``failed``        — the evaluator raised. Also `eval_set_size = 0` and NULL
                        metrics, so it never reads as a score of zero.

`notes` carries a machine-readable ``outcome=<token>`` so the three are
distinguishable without parsing prose, and silence in `rag_eval_runs` now means
the SCHEDULER is not running — which is a fact worth being able to see.

NOT A SCAN INITIATOR, AND NOT A DISPATCHER. It re-embeds stored query text and
reads the database; it sends nothing to a target, starts no tool and holds no
scan slot, so the scope gate and MAX_CONCURRENT_SCANS do not apply.

Run standalone:  python -m rag_eval_scheduler   (from scan_recommender/)
Tests:           pytest tests/test_rag_eval_scheduler.py
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2

logger = logging.getLogger("rag_eval_scheduler")

# ── Configuration ────────────────────────────────────────────────────────────
PG_DSN = os.getenv(
    "PG_DSN", "dbname=postgres user=app password=app host=rag-postgres port=5432")

# Seconds between evaluation passes. Daily by default: the eval re-embeds every
# rated query, so the cadence is set by how fast the gold set changes (an
# operator rating a handful of queries a week), not by how fast it could run.
POLL_INTERVAL = int(os.environ.get("RAG_EVAL_INTERVAL", "86400"))
# Feedback window the eval set is drawn from, and how the run is labelled.
WINDOW_DAYS = int(os.environ.get("RAG_EVAL_WINDOW_DAYS", "365"))
MODEL_LABEL = os.environ.get("RAG_EVAL_MODEL_LABEL", "scheduled")
TOP_K = int(os.environ.get("RAG_EVAL_TOP_K", "10"))
# Env value is only the DEFAULT for the persisted toggle below. The operator's
# on/off choice lives in app_settings and is honoured live, every cycle.
ENABLED_DEFAULT = os.environ.get(
    "RAG_EVAL_SCHEDULER_ENABLED", "true").lower() == "true"
# How long to wait before the FIRST pass. A service restart should not cost an
# eval run, and several restarts in a row should not cost several.
STARTUP_DELAY = int(os.environ.get("RAG_EVAL_STARTUP_DELAY", "300"))

# app_settings storage. `key` is a GLOBAL primary key there, so every key is
# namespaced with the category — a bare "enabled" would collide with the
# reconnect watcher's.
SETTINGS_CATEGORY = "rag_eval_scheduler"
KEY_ENABLED = "rag_eval_scheduler.enabled"
KEY_POLL = "rag_eval_scheduler.poll_interval"
KEY_WINDOW = "rag_eval_scheduler.window_days"
KEY_LABEL = "rag_eval_scheduler.model_label"

# The outcome vocabulary. Written into rag_eval_runs.notes as `outcome=<token>`
# and emitted on the webhook, so a reader never has to infer one from silence.
OUTCOME_SCORED = "scored"
OUTCOME_SKIPPED_EMPTY = "skipped_empty"
OUTCOME_FAILED = "failed"
OUTCOMES = (OUTCOME_SCORED, OUTCOME_SKIPPED_EMPTY, OUTCOME_FAILED)

WEBHOOK_EVENT = "rag_eval_scheduled_run"

# Minimum enforced cadence. An operator who sets 5 seconds in the UI would have
# the service re-embedding the whole gold set continuously.
MIN_POLL_INTERVAL = 300


def _note(outcome: str, **fields: Any) -> str:
    """`outcome=skipped_empty window_days=365 ...` — parseable, and readable in
    the dashboard's notes column without a decoder."""
    parts = [f"{SETTINGS_CATEGORY} outcome={outcome}"]
    for k, v in fields.items():
        if v not in (None, ""):
            parts.append(f"{k}={str(v).replace(chr(10), ' ')[:300]}")
    return " ".join(parts)


def _emit_webhook(data: Dict[str, Any]) -> None:
    """Fire-and-forget. Per CLAUDE.md every action-performing feature emits;
    `source` is required (422 without it) and telemetry must never break the
    loop it reports on."""
    try:
        import requests
        if os.environ.get("WEBHOOK_ENABLED", "1").lower() not in ("1", "true", "yes"):
            return
        requests.post(
            f"{os.environ.get('API_BASE', 'https://rag-api:8000')}/webhooks/emit",
            json={"event_type": WEBHOOK_EVENT, "source": "rag-eval-scheduler",
                  "data": data},
            headers={"x-api-key": os.environ.get("API_KEY", "changeme")},
            timeout=5, verify=False,
        )
    except Exception:  # noqa: BLE001
        logger.debug("webhook emit failed for %s", WEBHOOK_EVENT, exc_info=True)


class RagEvalScheduler:
    """Runs the retrieval eval on a cadence and records every cycle."""

    def __init__(self) -> None:
        self.running = False
        self._active = False
        self._last_run: Optional[datetime] = None
        self._last_outcome: Optional[str] = None
        self._last_detail: Optional[str] = None
        self._counts = {o: 0 for o in OUTCOMES}

    # ── DB ────────────────────────────────────────────────────────────────
    def _conn(self):
        return psycopg2.connect(PG_DSN, connect_timeout=5)

    # ── Persisted settings (operator toggle, honoured live) ────────────────
    def _read_settings(self) -> Dict[str, str]:
        """Raw app_settings values for this scheduler. On any DB error return
        {} so the caller falls back to the env defaults rather than crashing
        the loop — and so a database blip never silently disables a scheduler
        the operator turned on."""
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT key, value FROM public.app_settings WHERE category = %s",
                    (SETTINGS_CATEGORY,))
                return {k: v for k, v in cur.fetchall()}
        except Exception:  # noqa: BLE001
            logger.debug("could not read app_settings; using env defaults",
                         exc_info=True)
            return {}

    def is_enabled(self) -> bool:
        """Operator on/off. The persisted value wins; env is only the default
        when it is unset."""
        val = self._read_settings().get(KEY_ENABLED)
        if val is None:
            return ENABLED_DEFAULT
        return str(val).lower() in ("true", "1", "yes", "on")

    def effective_config(self) -> Dict[str, Any]:
        s = self._read_settings()

        def _int(key, default):
            try:
                return int(s[key])
            except (KeyError, TypeError, ValueError):
                return default

        return {
            "poll_interval": max(MIN_POLL_INTERVAL, _int(KEY_POLL, POLL_INTERVAL)),
            "window_days": max(1, _int(KEY_WINDOW, WINDOW_DAYS)),
            "model_label": s.get(KEY_LABEL) or MODEL_LABEL,
            "top_k": TOP_K,
        }

    def write_settings(self, values: Dict[str, Any]) -> list:
        """Persist the operator's choices. Returns the keys actually written.

        Only the four keys above are writable — an endpoint that forwards an
        arbitrary dict into a settings table is a write primitive, not a
        setting.
        """
        allowed = {"enabled": KEY_ENABLED, "poll_interval": KEY_POLL,
                   "window_days": KEY_WINDOW, "model_label": KEY_LABEL}
        updated = []
        with self._conn() as conn, conn.cursor() as cur:
            for name, key in allowed.items():
                if name not in values or values[name] is None:
                    continue
                v = values[name]
                v = ("true" if v else "false") if isinstance(v, bool) else str(v)
                cur.execute(
                    "INSERT INTO public.app_settings (category, key, value)"
                    " VALUES (%s, %s, %s)"
                    " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value,"
                    " category = EXCLUDED.category",
                    (SETTINGS_CATEGORY, key, v))
                updated.append(name)
            conn.commit()
        return updated

    # ── The record ────────────────────────────────────────────────────────
    def _record_non_scored(self, outcome: str, model_label: str,
                           **fields: Any) -> Optional[str]:
        """Land a row for an outcome that produced no metrics.

        `eval_set_size` is 0 and every metric column is left NULL. A 0.0 would
        be a SCORE of zero — indistinguishable in a chart from retrieval that
        returned nothing useful — whereas NULL is "not measured", which is what
        actually happened.
        """
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO public.rag_eval_runs"
                    " (model_label, eval_set_size, notes)"
                    " VALUES (%s, %s, %s) RETURNING id",
                    (model_label, 0, _note(outcome, **fields)))
                new_id = cur.fetchone()[0]
                conn.commit()
                return str(new_id)
        except Exception as e:  # noqa: BLE001
            logger.warning("could not record %s outcome: %s", outcome, e)
            return None

    # ── One cycle ─────────────────────────────────────────────────────────
    def run_once(self) -> Dict[str, Any]:
        """Run the eval once and record the outcome. Never raises.

        Returns {"outcome": one of OUTCOMES, ...}. Blocking (psycopg2 + the
        embedder are both sync), so the loop hands it to a worker thread.
        """
        cfg = self.effective_config()
        label = cfg["model_label"]
        result: Dict[str, Any] = {}
        try:
            # Imported HERE, not at module scope: exploits_rag is a 3,800-line
            # module that pulls in the whole service (tool_kb, the LLM config,
            # …), and it is what starts THIS scheduler — importing it at the
            # top would be circular and would make the scheduler untestable on
            # its own.
            _run_rag_eval = _load_evaluator()
            result = _run_rag_eval(
                model_label=label, top_k=cfg["top_k"], days=cfg["window_days"],
                notes=_note(OUTCOME_SCORED, window_days=cfg["window_days"],
                            cadence_s=cfg["poll_interval"]),
            ) or {}
        except Exception as e:  # noqa: BLE001
            out = {"outcome": OUTCOME_FAILED, "error": f"{type(e).__name__}: {e}",
                   "model_label": label, "window_days": cfg["window_days"]}
            logger.warning("eval run failed: %s", e)
            out["eval_run_id"] = self._record_non_scored(
                OUTCOME_FAILED, label, window_days=cfg["window_days"],
                error=out["error"])
            return self._finish(out)

        if result.get("ran"):
            out = {"outcome": OUTCOME_SCORED, "model_label": label,
                   "window_days": cfg["window_days"],
                   "eval_run_id": result.get("id"),
                   "eval_set_size": result.get("eval_set_size"),
                   "ndcg_at_10": result.get("ndcg_at_10"),
                   "mrr": result.get("mrr")}
            return self._finish(out)

        # "Queried and empty" — a real, reportable state, not a failure. The
        # evaluator writes NO row in this case, so the scheduler writes one;
        # otherwise an eval set that nobody has rated yet looks exactly like a
        # scheduler that is not running.
        out = {"outcome": OUTCOME_SKIPPED_EMPTY, "model_label": label,
               "window_days": cfg["window_days"], "eval_set_size": 0,
               "reason": result.get("reason") or "no feedback-rated queries"}
        out["eval_run_id"] = self._record_non_scored(
            OUTCOME_SKIPPED_EMPTY, label, window_days=cfg["window_days"],
            reason=out["reason"])
        return self._finish(out)

    def _finish(self, out: Dict[str, Any]) -> Dict[str, Any]:
        self._last_run = datetime.now(timezone.utc)
        self._last_outcome = out["outcome"]
        self._last_detail = out.get("error") or out.get("reason")
        self._counts[out["outcome"]] = self._counts.get(out["outcome"], 0) + 1
        out["at"] = self._last_run.isoformat()
        logger.info("rag eval cycle: %s", out)
        _emit_webhook(out)
        return out

    # ── The loop ──────────────────────────────────────────────────────────
    async def watch_loop(self) -> None:
        logger.info("RAG eval scheduler starting (interval=%ss, enabled_default=%s)",
                    POLL_INTERVAL, ENABLED_DEFAULT)
        self.running = True
        was_active: Optional[bool] = None
        if STARTUP_DELAY > 0:
            await asyncio.sleep(STARTUP_DELAY)
        while self.running:
            sleep_for = POLL_INTERVAL
            try:
                # Operator toggle, re-read every cycle so enabling/disabling in
                # the UI takes effect within one interval — no restart.
                if not self.is_enabled():
                    self._active = False
                    if was_active is not False:
                        logger.info("RAG eval scheduler is DISABLED (operator toggle) — idling")
                        was_active = False
                    await asyncio.sleep(min(sleep_for, MIN_POLL_INTERVAL))
                    continue
                self._active = True
                if was_active is not True:
                    logger.info("RAG eval scheduler is ENABLED — evaluating")
                    was_active = True
                sleep_for = self.effective_config()["poll_interval"]
                await asyncio.to_thread(self.run_once)
            except Exception as e:  # noqa: BLE001 — one bad cycle, not the loop
                logger.error("Error in RAG eval loop: %s", e)
            await asyncio.sleep(sleep_for)

    def stop(self) -> None:
        self.running = False

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": self.running,            # the background task exists
            "enabled": self.is_enabled(),       # operator toggle (persisted)
            "active": self._active,             # evaluating, not idling
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "last_outcome": self._last_outcome,
            "last_detail": self._last_detail,
            "counts": dict(self._counts),
            "config": {**self.effective_config(),
                       "enabled_default": ENABLED_DEFAULT,
                       "startup_delay": STARTUP_DELAY},
        }


def _load_evaluator():
    """`_run_rag_eval`, however this process happens to see the module.

    The service runs with `scan_recommender/` as the working directory and
    imports its siblings flat (`from tool_kb import ...`); a test or a REPL at
    the repo root sees it as `scan_recommender.exploits_rag`. Both are real,
    so both are tried.
    """
    try:
        from exploits_rag import _run_rag_eval  # type: ignore
    except ImportError:
        from scan_recommender.exploits_rag import _run_rag_eval  # type: ignore
    return _run_rag_eval


# ── Singleton + entrypoints (mirrors reconnect_watcher) ──────────────────────
_scheduler: Optional[RagEvalScheduler] = None
_task: Optional[Any] = None


def get_rag_eval_scheduler() -> RagEvalScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = RagEvalScheduler()
    return _scheduler


def ensure_started() -> bool:
    """Start the loop once per process. Returns True if THIS call started it.

    `rag_router` is included into the app TWICE (scan_recommender.py mounts it,
    then multi_app.py mounts it again onto the same app object), so a
    router-level startup handler fires twice. Without this guard that is two
    loops evaluating on the same cadence.
    """
    global _task
    if _task is not None and not _task.done():
        return False
    sched = get_rag_eval_scheduler()
    # Requires a running loop by design: the only caller is the router's
    # startup handler, and "there is no loop" there means the service is not
    # actually serving — a condition to surface, not to paper over.
    _task = asyncio.get_running_loop().create_task(sched.watch_loop())
    return True


async def start_rag_eval_scheduler() -> None:
    await get_rag_eval_scheduler().watch_loop()


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    asyncio.run(start_rag_eval_scheduler())
