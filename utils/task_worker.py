"""
DB-backed queue worker for horizontal scaling and resilient task processing.

Responsibilities:
- Claim tasks atomically using SKIP LOCKED to allow multiple replicas to work safely in parallel.
- Maintain periodic heartbeats on running tasks (by refreshing started_at).
- Requeue stale tasks if they exceed a configured running timeout (failover handling).
- Dispatch work:
    * type='nmap' tasks dispatched to the asyncio Nmap scheduler.
    * type='followup' tasks dispatched to a plugin runner (tasks.action holds plugin name).
- Persist results for follow-up plugins into followup_findings.
- Observability: record per-task durations and per-plugin success/failure metrics.
- Controls: respect paused jobs (do not claim) and canceled tasks (skip).

Config (env variables):
- DB_DSN                      connection DSN for Postgres
- QUEUE_CLAIM_BATCH          max tasks claimed per cycle (default 10)
- QUEUE_HEARTBEAT_SEC        heartbeat frequency in seconds (default 15)
- QUEUE_STALE_SEC            running task deadline before requeue (default 60)
- QUEUE_IDLE_EXIT_GRACE_SEC  idle exit grace used by run_until_idle (default 5)
"""
import os
import time
import asyncio
import socket
from typing import List, Optional, Dict, Any, Tuple, Callable, Awaitable

import psycopg2
from psycopg2.extras import RealDictCursor, Json

from utils.nmap_scheduler import Scheduler, Probe
from utils.followup_engine import ensure_followup_schema
from utils.followup_plugins import get as get_plugin
from utils.metrics import inc_task_status, inc_plugin_result, observe_task_duration


DEFAULT_DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

