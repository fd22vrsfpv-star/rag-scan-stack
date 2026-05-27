"""
Phase 7 E2E tests:
- Long-running job with intermittent failures.
- Verify pause/resume prevents/permits claims.
- Verify cancel prevents execution.
- Verify retry resets failed tasks to queued and they get executed.
- Check metrics snapshot reflects outcomes (counts and durations observed).
"""
import os
import asyncio
import time
from typing import Dict, Any, List

import psycopg2
import pytest
from psycopg2.extras import RealDictCursor

from utils.task_worker import DBQueueWorker
from utils.nmap_scheduler import Probe
from utils.db_controls import pause_job, resume_job, cancel_task, retry_failed_tasks, get_queue_stats
from utils.metrics import snapshot as metrics_snapshot


TEST_DB_DSN = os.environ.get("TEST_DB_DSN", os.environ.get("DB_DSN", "postgresql://app:app@127.0.0.1:5432/scans"))


def _conn():
    return psycopg2.connect(TEST_DB_DSN)


def _ensure_tables():
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                type text NOT NULL,
                status text NOT NULL DEFAULT 'queued',
                params jsonb NOT NULL DEFAULT '{}'::jsonb,
                total_tasks integer NOT NULL DEFAULT 0,
                finished_tasks integer NOT NULL DEFAULT 0,
                error text,
                created_at timestamptz NOT NULL DEFAULT now(),
                started_at timestamptz,
                finished_at timestamptz
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                job_id uuid REFERENCES jobs(id) ON DELETE CASCADE,
                type text NOT NULL,
                target_host inet,
                target_port integer,
                proto text,
                action text,
                status text NOT NULL DEFAULT 'queued',
                attempt integer NOT NULL DEFAULT 0,
                last_error text,
                created_at timestamptz NOT NULL DEFAULT now(),
                started_at timestamptz,
                finished_at timestamptz
            )""")
        conn.commit()


def _seed_job_with_tasks(n: int) -> str:
    with _conn() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("INSERT INTO jobs (type, status) VALUES ('masscan-nmap','queued') RETURNING id")
        job_id = str(cur.fetchone()["id"])
        for i in range(n):
            cur.execute(
                """INSERT INTO tasks (job_id, type, target_host, target_port, proto, status)
                   VALUES (%s::uuid, 'nmap', %s::inet, %s, 'tcp', 'queued')""",
                (job_id, "198.51.100.1", 10000 + i),
            )
        conn.commit()
        return job_id


@pytest.mark.asyncio
async def test_pause_resume_cancel_retry_and_metrics():
    _ensure_tables()

    # Stateful fake runner: fail every 3rd task to simulate intermittent failures
    state = {"count": 0}

    async def flaky_runner(probe: Probe) -> Dict[str, Any]:
        state["count"] += 1
        await asyncio.sleep(0.05)
        # Fail every 3rd run
        if state["count"] % 3 == 0:
            return {"ok": False, "error": "simulated failure"}
        return {"ok": True}

    job_id = _seed_job_with_tasks(12)
    worker = DBQueueWorker(db_dsn=TEST_DB_DSN, claim_batch=4)

    # Pause job before running
    assert pause_job(job_id) >= 1

    # Start a cycle: since paused, worker should not claim tasks; run_until_idle should return quickly
    stats_paused = await worker.run_until_idle(custom_runner=flaky_runner)
    assert stats_paused["claimed"] == 0

    # Resume and run; expect some fails due to flaky runner
    assert resume_job(job_id) == 1
    stats_run = await worker.run_until_idle(custom_runner=flaky_runner)
    assert stats_run["claimed"] > 0
    # At least one failure expected
    assert stats_run["failed"] > 0

    # Cancel a queued task (create an extra queued task) then verify it's not executed
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO tasks (job_id, type, target_host, target_port, proto, status) VALUES (%s::uuid,'nmap',%s::inet,%s,'tcp','queued') RETURNING id",
                    (job_id, "198.51.100.2", 5555))
        task_id = str(cur.fetchone()[0])
        conn.commit()
    assert cancel_task(task_id) == 1

    # Run again; canceled task should be skipped and remain not finished
    stats_after_cancel = await worker.run_until_idle(custom_runner=flaky_runner)
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT status FROM tasks WHERE id=%s::uuid", (task_id,))
        st = cur.fetchone()[0]
    assert st == "canceled"

    # Retry failed tasks
    retried = retry_failed_tasks(job_id=job_id)
    assert retried >= 1
    stats_after_retry = await worker.run_until_idle(custom_runner=flaky_runner)
    # After retry, ok should increase
    assert stats_after_retry["ok"] >= 1

    # Queue stats should be available
    qstats = get_queue_stats()
    assert "tasks_by_status" in qstats and isinstance(qstats["queue_depth"], int)

    # Metrics snapshot should contain task_status counters and durations
    snap = metrics_snapshot()
    names = {c["name"] for c in snap["counters"]}
    assert "tasks_status" in names
    hist_names = {h["name"] for h in snap["histograms"]}
    assert "task_duration_seconds" in hist_names

