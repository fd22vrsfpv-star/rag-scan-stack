import asyncio
import json
import logging
import os
import pathlib
from datetime import datetime, timedelta, timezone
import httpx
from config import get_settings
from timeouts import TIMEOUT_FAST, TIMEOUT_NORMAL
from ws_hub import hub

log = logging.getLogger("polling")

# In-memory job→service mapping: {job_id: {"service_url": ..., "type": ..., "status": ...}}
active_jobs: dict[str, dict] = {}

# Pending scan queue: URLs waiting to be dispatched when slots open
# Each entry: {"url": str, "service_url": str, "path": str, "payload_template": dict,
#              "proxy": str|None, "engagement_id": str|None, "scope_name": str|None,
#              "scan_type": str, "api_key": str}
pending_queue: list[dict] = []

# Lock guarding compound read-modify-write sequences on active_jobs and
# pending_queue (e.g. count → pop → append). Single-key dict get/set is
# atomic under CPython GIL, so callers performing single-step access don't
# need to acquire this lock; only multi-step decisions do.
jobs_lock: asyncio.Lock = asyncio.Lock()

_PERSIST_DIR = pathlib.Path("/scan_results/.bff_jobs")
_PERSIST_DIR.mkdir(parents=True, exist_ok=True)


def _persist(job_id: str):
    """Save job mapping to disk so it survives restarts."""
    try:
        info = active_jobs.get(job_id)
        if info:
            # Keep last_data for completed AI check jobs (has summary)
            skip_keys = set() if info.get("_bulk_check") else {"last_data"}
            data = {k: v for k, v in info.items() if k not in skip_keys}
            (_PERSIST_DIR / f"{job_id}.json").write_text(json.dumps(data, default=str))
    except Exception as e:
        log.debug("Failed to persist job %s: %s", job_id, e)


_TERMINAL_STATUSES = {"completed", "finished", "failed", "cancelled", "canceled", "stopped", "lost", "error", "partial"}


def _load_persisted():
    """Load previously persisted jobs on startup (include completed for history).

    Any job that was "running" or "queued" at shutdown is demoted to
    "restarting" — an unconfirmed, non-blocking state that does NOT count
    against MAX_CONCURRENT_SCANS. The first successful poll promotes it back
    to its real upstream status; three consecutive 404s mark it "lost".
    This prevents a pile of stale "running" jobs from blocking new-scan
    dispatch after the BFF restarts.
    """
    try:
        for fp in sorted(_PERSIST_DIR.glob("*.json"),
                         key=lambda f: f.stat().st_mtime, reverse=True)[:200]:
            try:
                data = json.loads(fp.read_text())
                jid = fp.stem
                if jid not in active_jobs:
                    data.setdefault("last_data", None)
                    if data.get("status") in ("running", "queued"):
                        data["status"] = "restarting"
                    active_jobs[jid] = data
            except Exception:
                continue
    except Exception as e:
        log.debug("Failed to load persisted jobs: %s", e)


# Load on import
_load_persisted()


def register_job(job_id: str, service_url: str, scan_type: str,
                  proxy: str | None = None, engagement_id: str | None = None,
                  scope_name: str | None = None, target: str | None = None,
                  source_rec_id: str | None = None, kind: str = "runner"):
    """Track an in-flight scan job.

    ``source_rec_id`` is the ``scan_recommendations.id`` that spawned this
    run, when applicable.  Persisted in active_jobs so the polling loop can
    backfill the recommendation row's status when the job reaches a
    terminal state (closes the dispatch→ingest UX loop).

    ``kind`` selects how the poller fetches status: "runner" (default) polls
    ``{service_url}/jobs/{id}``; "kali_exec" polls
    ``{service_url}/tools/executions/{id}`` (the Kali container's tool runs).
    """
    now = datetime.now(timezone.utc).isoformat()
    active_jobs[job_id] = {
        "service_url": service_url,
        "type": scan_type,
        "kind": kind,
        "status": "queued",
        "last_data": None,
        "created_at": now,
        "completed_at": None,
        "proxy": proxy,
        "engagement_id": engagement_id,
        "scope_name": scope_name,
        "target": target,
        "source_rec_id": source_rec_id,
    }
    _persist(job_id)
    # Auto-create a campaign event for engagement-linked scans
    if engagement_id:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_post_scan_campaign_event(
                engagement_id, scan_type, job_id, "started", now))
        except RuntimeError:
            pass  # No running loop (e.g. called during startup)


async def _post_scan_campaign_event(
    engagement_id: str, scan_type: str, job_id: str,
    action: str, timestamp: str,
):
    """Create a campaign event in the rag-api for scan lifecycle milestones."""
    settings = get_settings()
    title = f"Scan {action}: {scan_type}" + (f" (job {job_id[:8]})" if job_id else "")
    body = {
        "kill_chain_phase": "reconnaissance",
        "title": title,
        "description": f"Automated scan event — {scan_type} {action}",
        "timestamp": timestamp,
        "detected": False,
        "operator": "system",
        "metadata": {"job_id": job_id, "scan_type": scan_type, "event": action},
    }
    try:
        async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_FAST) as c:
            await c.post(
                f"{settings.rag_api_url}/engagements/{engagement_id}/campaign-events",
                json=body,
                headers={"x-api-key": settings.api_key},
            )
    except Exception:
        log.debug("Failed to post scan campaign event for job %s", job_id)


# Map BFF job-poll terminal states to scan_recommendations.status enum
# values.  'partial' is treated as completed for the rec lifecycle because
# the run did produce results that ingested -- the operator wants the rec
# off the pending list, just with a note that some targets failed.
_REC_TERMINAL_MAP = {
    "completed": "completed",
    "finished": "completed",
    "partial":   "completed",
    "failed":    "failed",
    "stopped":   "failed",
    "cancelled": "failed",
    "canceled":  "failed",
    "error":     "failed",
    "lost":      "failed",
}


async def _backfill_recommendation_status(
    rec_id: str, job_status: str, job_id: str, engagement_id: str | None,
):
    """Close the scan_recommendations lifecycle loop on a terminal job event.

    Called from _poll_once() when a job linked to a recommendation reaches
    a terminal state.  Two side effects:
      1. Direct UPDATE on scan_recommendations so the row's status moves
         from 'queued'/'running' to 'completed' or 'failed' (no HTTP hop
         through scan_recommender -- the BFF owns the trigger and has DB
         access via dashboard/bff/db.py).
      2. Emit a webhook event so external subscribers (Slack, n8n) see the
         recommendation lifecycle close.  Best-effort -- a webhook delivery
         failure must NOT prevent the DB status update.

    The UPDATE runs in a worker thread via asyncio.to_thread so the polling
    event loop doesn't block on psycopg2's synchronous network I/O.
    """
    settings = get_settings()
    final_status = _REC_TERMINAL_MAP.get(job_status, "failed")

    def _do_update():
        # Lazy import keeps polling.py importable in test environments that
        # don't have psycopg2 installed (e.g. host-side test discovery).
        from db import get_db
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_recommendations
                   SET status = %s,
                       executed_at = COALESCE(executed_at, now()),
                       updated_at = now(),
                       extra = COALESCE(extra, '{}'::jsonb)
                               || jsonb_build_object(
                                    'job_id', %s::text,
                                    'final_job_status', %s::text
                                  )
                 WHERE id = %s::uuid
                """,
                (final_status, job_id, job_status, rec_id),
            )
            conn.commit()
            return cur.rowcount

    try:
        rows = await asyncio.to_thread(_do_update)
        if rows == 0:
            log.warning("rec backfill: rec_id=%s not found in DB", rec_id)
            return
    except Exception as e:
        log.warning("rec backfill UPDATE failed for %s: %s", rec_id, e)
        return

    # Fire-and-forget webhook so external subscribers see the lifecycle close.
    event_type = (
        "scan_recommendation_completed"
        if final_status == "completed"
        else "scan_recommendation_failed"
    )
    try:
        async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_FAST) as c:
            await c.post(
                f"{settings.rag_api_url}/webhooks/emit",
                json={
                    "event_type": event_type,
                    "source": "bff_polling",
                    "data": {
                        "rec_id": rec_id,
                        "job_id": job_id,
                        "final_status": final_status,
                        "raw_job_status": job_status,
                        "engagement_id": engagement_id,
                    },
                },
                headers={"x-api-key": settings.api_key},
            )
    except Exception as e:
        log.debug("Failed to emit %s webhook for rec %s: %s", event_type, rec_id, e)


def _count_active() -> int:
    # "restarting" is intentionally excluded: these are persisted-running
    # jobs loaded at startup whose upstream state hasn't been re-confirmed
    # yet. Counting them would block new-scan dispatch until the poll loop
    # resolves each one (200 → promote, 3×404 → mark "lost").
    return sum(1 for info in active_jobs.values() if info.get("status") in ("running", "queued"))


async def _dispatch_pending(client: httpx.AsyncClient):
    """Dispatch queued scans when slots are available."""
    max_concurrent = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))
    while True:
        async with jobs_lock:
            if not pending_queue or _count_active() >= max_concurrent:
                return
            item = pending_queue.pop(0)
        url = item["url"]
        try:
            payload = dict(item["payload_template"])
            payload["target_url"] = url
            resp = await client.post(
                f"{item['service_url']}{item['path']}",
                json=payload,
                headers={"x-api-key": item["api_key"]},
                timeout=TIMEOUT_NORMAL,
            )
            if resp.status_code < 400:
                data = resp.json()
                jid = data.get("job_id")
                if jid:
                    register_job(jid, item["service_url"], item["scan_type"],
                                 proxy=item.get("proxy"),
                                 engagement_id=item.get("engagement_id"),
                                 scope_name=item.get("scope_name"),
                                 target=url)
                    log.info("Dispatched queued scan %s → %s (%d remaining)",
                             jid[:8], url[:50], len(pending_queue))
        except Exception as e:
            log.warning("Failed to dispatch queued scan for %s: %s", url[:50], e)


_STALE_JOB_TIMEOUT_HOURS = float(os.environ.get("STALE_JOB_TIMEOUT_HOURS", "24"))
_STALE_CHECK_EVERY_N_POLLS = int(os.environ.get("STALE_CHECK_EVERY_N_POLLS", "60"))


def _mark_stale_jobs() -> int:
    """Mark jobs in 'running'/'queued'/'restarting' for >timeout as failed.
    Returns count marked. "restarting" is swept too so post-restart jobs whose
    upstream never responds (service permanently gone) eventually clear."""
    if _STALE_JOB_TIMEOUT_HOURS <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_STALE_JOB_TIMEOUT_HOURS)
    marked = 0
    for jid, info in list(active_jobs.items()):
        if info.get("status") not in ("running", "queued", "restarting"):
            continue
        created = info.get("created_at")
        if not created:
            continue
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except Exception:
            continue
        if created_dt < cutoff:
            info["status"] = "failed"
            info["completed_at"] = datetime.now(timezone.utc).isoformat()
            info["error"] = f"stale: exceeded {_STALE_JOB_TIMEOUT_HOURS}h timeout"
            _persist(jid)
            marked += 1
            log.warning("Job %s marked failed (stale > %.1fh)", jid[:8], _STALE_JOB_TIMEOUT_HOURS)
    return marked


async def poll_loop():
    settings = get_settings()
    interval = settings.poll_interval
    log.info("Starting job polling loop (every %ds, stale_timeout=%.1fh)",
             interval, _STALE_JOB_TIMEOUT_HOURS)
    poll_count = 0
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_NORMAL) as client:
        while True:
            try:
                await _poll_once(client)
                await _dispatch_pending(client)
                poll_count += 1
                if poll_count % _STALE_CHECK_EVERY_N_POLLS == 0:
                    n = _mark_stale_jobs()
                    if n:
                        await hub.broadcast("stale_jobs_swept", {"count": n})
            except Exception:
                log.exception("Poll loop error")
            await asyncio.sleep(interval)


async def _poll_once(client: httpx.AsyncClient):
    settings = get_settings()
    headers = {"x-api-key": settings.api_key}
    finished = []
    for job_id, info in list(active_jobs.items()):
        if info["status"] in _TERMINAL_STATUSES:
            finished.append(job_id)
            continue
        try:
            # Kali tool executions live at a different status endpoint.
            if info.get("kind") == "kali_exec":
                status_url = f"{info['service_url']}/tools/executions/{job_id}"
            else:
                status_url = f"{info['service_url']}/jobs/{job_id}"
            resp = await client.get(status_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                new_status = data.get("status", info["status"])
                # Kali execs use 'timeout' as a terminal state — fold into failed.
                if info.get("kind") == "kali_exec" and new_status == "timeout":
                    new_status = "failed"

                # Post-process status to detect partial failures or timeouts
                if new_status == "completed":
                    # Check for timeout conditions in result data
                    result_data = data.get("result", {}) if isinstance(data.get("result"), dict) else {}
                    error_msg = data.get("error", "") or result_data.get("error", "")

                    # Detect timeout conditions
                    if ("timeout" in str(error_msg).lower() or
                        "timed out" in str(error_msg).lower() or
                        "Command '.+' timed out" in str(data).lower()):
                        new_status = "failed"
                        log.warning(f"Scan {job_id} marked as failed due to timeout: {error_msg}")

                    # Detect nmap service detection failures
                    elif ("nmap.*timed out" in str(data).lower() or
                          "service detection.*failed" in str(data).lower() or
                          "phase2.*error" in str(data).lower()):
                        new_status = "partial"
                        log.warning(f"Scan {job_id} marked as partial due to service detection failure")

                    # Check for error arrays or failure indicators
                    elif (result_data.get("errors") or
                          result_data.get("failed_targets") or
                          "some targets failed" in str(result_data).lower()):
                        new_status = "partial"
                        log.info(f"Scan {job_id} marked as partial due to target failures")

                # Reset stale counter on successful poll
                info.pop("_poll_404_count", None)
                # Always update last_data so command/progress are available
                info["last_data"] = data
                # Capture target from response if not set
                if not info.get("target"):
                    info["target"] = data.get("target_url") or data.get("target") or None
                if new_status != info["status"]:
                    info["status"] = new_status
                    if new_status in ("completed", "failed", "stopped", "partial"):
                        info["completed_at"] = datetime.now(timezone.utc).isoformat()
                    _persist(job_id)
                    await hub.broadcast(
                        "job_status",
                        {
                            "job_id": job_id,
                            "type": info["type"],
                            "status": new_status,
                            "data": data,
                        },
                    )
                    if new_status in ("completed", "failed", "stopped", "partial"):
                        await hub.broadcast(
                            "scan_completed",
                            {"job_id": job_id, "type": info["type"], "status": new_status},
                        )
                        # Auto-create campaign event for engagement-linked scans
                        if info.get("engagement_id"):
                            await _post_scan_campaign_event(
                                info["engagement_id"], info["type"], job_id,
                                new_status, info.get("completed_at", datetime.now(timezone.utc).isoformat()),
                            )
                        # Close the recommendation lifecycle loop: if this
                        # job was spawned by a scan_recommendations row,
                        # backfill that row's status (+ emit webhook) so
                        # the FollowUps / Recommendations UI shows the
                        # terminal state instead of stale 'queued'.
                        src_rec_id = info.get("source_rec_id")
                        if src_rec_id:
                            await _backfill_recommendation_status(
                                rec_id=src_rec_id,
                                job_status=new_status,
                                job_id=job_id,
                                engagement_id=info.get("engagement_id"),
                            )
            elif resp.status_code == 404:
                # Service lost track of the job (container restart, etc.)
                count = info.get("_poll_404_count", 0) + 1
                info["_poll_404_count"] = count
                if count >= 3:
                    # After 3 consecutive 404s, mark as lost
                    info["status"] = "lost"
                    info["completed_at"] = datetime.now(timezone.utc).isoformat()
                    _persist(job_id)
                    log.warning("Job %s marked as lost (service 404 x%d)", job_id, count)
                    await hub.broadcast(
                        "job_status",
                        {"job_id": job_id, "type": info["type"], "status": "lost", "data": None},
                    )
        except Exception:
            log.debug("Failed to poll job %s", job_id)
    # Cleanup old finished jobs (keep last 100)
    for jid in finished:
        if len(active_jobs) > 100:
            del active_jobs[jid]
