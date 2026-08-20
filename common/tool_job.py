"""One background job runner for the tool services.

pd_runner and osint_runner each carried their own `_run_tool_job` — 110 and 138
lines, 78% identical. The difference was not design: osint's copy had simply
accumulated improvements that never travelled back. It recorded the command and
duration in the job result, captured stdout/stderr tails when a tool failed, and
passed an ingest `source`; pd_runner had none of that, so a pd job that failed
told you only that it failed.

This is the union of the two, so both services gain everything either had. The
genuinely service-specific parts are injected rather than branched on:

  * `service_name` / `session_label` — audit and session-directory naming
  * `ingest_results`, `save_session_results`, `scope_refusal` — each service
    reaches the API and the database its own way
  * `on_success` — a post-completion hook. osint uses it to auto-trigger dnsx
    after a subfinder run; pd_runner passes nothing.

Injecting the callables rather than importing them keeps this module free of
service imports, so it can live in the shared base image without dragging either
service's dependencies along with it.
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

# ── Concurrency bound ─────────────────────────────────────────────────────
#
# Nothing bounded these runners. A caller could submit fifty jobs and fifty
# tools would start, which is how the recommender's fan-out saturated the stack
# earlier: one call per open port, each launching a tool, each producing output
# that triggered more calls.
#
# The ceiling is MAX_CONCURRENT_SCANS — the number the operator already sets for
# the engagement — rather than a new knob. Be precise about what it bounds: this
# is PER SERVICE, not engagement-wide. Enforcing one global count would need a
# shared counter (a DB row or a lease service) that this stack does not have, so
# two runners at the limit can still total 2N. That is a large improvement on
# unbounded and an honest description of what it does.
#
# Jobs WAIT for a slot rather than being rejected: they are background tasks
# that have already been accepted and whose targets file is on disk, so queuing
# preserves the work. FastAPI runs sync background tasks in a threadpool, so a
# waiting job occupies a pool thread — hence the timeout, which fails the job
# loudly instead of pinning a thread forever.
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))
SLOT_WAIT_TIMEOUT = int(os.environ.get("SCAN_SLOT_WAIT_TIMEOUT", "1800"))

_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


def active_slot_count() -> int:
    """How many slots are currently in use (best-effort, for diagnostics)."""
    return MAX_CONCURRENT_SCANS - _slots._value        # noqa: SLF001



# Tools legitimately exit 1 to mean "ran fine, found nothing" (httpx, subfinder
# and friends), so only other non-zero codes are treated as failure.
OK_RETURNCODES = (0, 1)

DEFAULT_TIMEOUT = 3600
RAW_OUTPUT_CAP = 10000
STREAM_TAIL_TEST_MODE = 2000
STREAM_TAIL_NORMAL = 500


@contextmanager
def scan_slot(job_id: str = "", label: str = "scan"):
    """Hold one of this service's scan slots for the duration of the block.

    For services whose job runner is not run_tool_job (web_scanner and
    brutus_runner have their own), so the same ceiling applies without them
    reimplementing the accounting:

        with scan_slot(job_id, "web-scan"):
            ...run the tools...

    Raises TimeoutError rather than waiting forever, so a caller fails loudly
    instead of pinning a threadpool worker.
    """
    if not _slots.acquire(timeout=SLOT_WAIT_TIMEOUT):
        raise TimeoutError(
            f"no scan slot within {SLOT_WAIT_TIMEOUT}s "
            f"(MAX_CONCURRENT_SCANS={MAX_CONCURRENT_SCANS})")
    try:
        yield
    finally:
        _slots.release()


def run_tool_job(
    *,
    job_id: str,
    tool: str,
    cmd: list,
    targets_file: str,
    output_file: str,
    service_name: str,
    session_label: str,
    job_tracker: Any,
    emit_webhook_event: Callable,
    write_audit: Callable,
    ingest_results: Callable,
    scope_refusal: Optional[Callable] = None,
    save_session_results: Optional[Callable] = None,
    on_success: Optional[Callable] = None,
    ingest_as: Optional[str] = None,
    env: Optional[dict] = None,
    no_ingest: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> None:
    """Run one tool, record it, ingest its output, and clean up.

    Never raises: this runs as a background task, so a failure is recorded on
    the job rather than lost to an unhandled exception in a worker thread.
    """
    # Scope gate first — refuse before the tool is launched, not after.
    if scope_refusal is not None:
        refusal = scope_refusal(targets_file)
        if refusal:
            log.warning("REFUSED %s job %s: %s", tool, job_id, refusal)
            job_tracker.update_job(job_id, status="failed",
                                   error=f"Out of scope — {refusal}")
            _cleanup(targets_file)
            return

    cmd_str = " ".join(cmd)

    # Wait for a slot before doing anything expensive. Acquired AFTER the scope
    # gate so a refused job never consumes capacity.
    if not _slots.acquire(timeout=SLOT_WAIT_TIMEOUT):
        log.error("[%s] no scan slot within %ss (limit %d) — failing %s",
                  job_id, SLOT_WAIT_TIMEOUT, MAX_CONCURRENT_SCANS, tool)
        job_tracker.update_job(
            job_id, status="failed",
            error=f"no scan slot within {SLOT_WAIT_TIMEOUT}s "
                  f"(MAX_CONCURRENT_SCANS={MAX_CONCURRENT_SCANS})")
        _cleanup(targets_file)
        return
    waited = active_slot_count()
    if waited >= MAX_CONCURRENT_SCANS:
        log.info("[%s] running at the concurrency limit (%d)", job_id, MAX_CONCURRENT_SCANS)

    t0 = time.time()
    try:
        job_tracker.update_job(job_id, status="running",
                               started_at=datetime.now().isoformat())
        job_tracker.push_command(job_id, tool, cmd_str)
        job_tracker.update_progress(job_id, stage="running")

        emit_webhook_event("scan_started", tool, {"job_id": job_id, "scan_type": tool})
        write_audit("scan_started", tool, service_name, {
            "job_id": job_id, "execution_mode": "local", "command": cmd_str,
        })

        log.info("[%s] Running %s: %s", job_id, tool, cmd_str)
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        if cp.returncode not in OK_RETURNCODES:
            raise RuntimeError(f"{tool} exit {cp.returncode}: {cp.stderr[:500]}")

        findings_count, raw_output = _count_findings(output_file)
        job_tracker.update_progress(job_id, findings_count=findings_count)

        ing = None
        if no_ingest:
            log.info("[%s] no_ingest=true, skipping ingestion", job_id)
        else:
            job_tracker.update_progress(job_id, stage="ingesting")
            ingest_tool = ingest_as or tool
            # `source` distinguishes the TOOL that produced the file from the
            # PARSER used to read it, when a tool's output is ingested as
            # another's format.
            ingest_source = tool if ingest_as and ingest_as != tool else None
            ing = ingest_results(ingest_tool, output_file, job_id=job_id,
                                 source=ingest_source)

        duration_s = round(time.time() - t0, 2)
        job_tracker.update_progress(job_id, stage="done")

        tail = STREAM_TAIL_TEST_MODE if no_ingest else STREAM_TAIL_NORMAL
        result_data = {
            "ok": True,
            "findings_count": findings_count,
            "report": output_file,
            "ingest": ing,
            "command": cmd_str,
            "duration_s": duration_s,
            "no_ingest": no_ingest,
            "stdout": cp.stdout[-tail:] if cp.stdout else None,
            "stderr": cp.stderr[-tail:] if cp.stderr else None,
        }
        if no_ingest:
            result_data["raw_output"] = raw_output

        job_tracker.update_job(job_id, status="completed", result=result_data,
                               completed_at=datetime.now().isoformat())
        emit_webhook_event("scan_completed", tool,
                           {"job_id": job_id, "findings_count": findings_count})
        write_audit("scan_completed", tool, service_name, {
            "job_id": job_id, "findings_count": findings_count,
            "duration_s": duration_s, "command": cmd_str,
        })

        if save_session_results and not no_ingest:
            save_session_results(job_id, tool, session_label, [output_file],
                                 metadata={"findings_count": findings_count})

        if on_success:
            # Follow-on work is best-effort: the job itself already succeeded,
            # and a failing hook must not mark it failed.
            try:
                on_success(job_id=job_id, tool=tool, output_file=output_file,
                           findings_count=findings_count)
            except Exception as e:                # pragma: no cover
                log.debug("[%s] post-success hook failed (non-fatal): %s", job_id, e)

    except Exception as e:
        job_tracker.update_job(job_id, status="failed", error=str(e),
                               result={"command": cmd_str, "error": str(e)},
                               completed_at=datetime.now().isoformat())
        job_tracker.update_progress(job_id, stage="failed")
        emit_webhook_event("scan_failed", tool, {"job_id": job_id, "error": str(e)})
        write_audit("scan_failed", tool, service_name,
                    {"job_id": job_id, "error": str(e)})
        log.error("[%s] %s failed: %s", job_id, tool, e)
    finally:
        _slots.release()
        _cleanup(targets_file)


def _count_findings(output_file: str):
    """(non-blank line count, capped raw text). Missing file counts as zero."""
    if not output_file or not os.path.exists(output_file):
        return 0, ""
    try:
        with open(output_file, errors="replace") as fh:
            content = fh.read()
    except OSError:                               # pragma: no cover
        return 0, ""
    return sum(1 for line in content.splitlines() if line.strip()), content[:RAW_OUTPUT_CAP]


def _cleanup(targets_file: str) -> None:
    if targets_file and os.path.exists(targets_file):
        try:
            os.remove(targets_file)
        except OSError:                           # pragma: no cover
            pass
