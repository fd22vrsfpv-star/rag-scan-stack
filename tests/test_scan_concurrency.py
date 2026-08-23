"""Scan initiators must be bounded by the engagement's concurrency limit.

Run on demand:

    pytest tests/test_scan_concurrency.py -v

WHY THIS EXISTS
---------------
Nothing bounded the tool runners. A caller could submit fifty jobs and fifty
tools would start — which is how the recommender's fan-out saturated the stack:
one call per open port, each launching a tool, each producing output that
triggered more calls, until dispatches timed out and were recorded as failures
for scans that had actually started.

The ceiling is MAX_CONCURRENT_SCANS, the number the operator already sets for
the engagement, rather than a new per-service knob.

Runs entirely in-process with a fake subprocess: no containers, no network, and
no real scanning.
"""
import importlib.util
import os
import threading
import time

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
_MODULE = os.path.join(REPO, "common", "tool_job.py")


def _load(limit):
    """Fresh import with MAX_CONCURRENT_SCANS set — the semaphore is built at
    import time, so it has to be re-imported per limit."""
    if not os.path.exists(_MODULE):              # pragma: no cover
        pytest.skip("common/tool_job.py not present")
    os.environ["MAX_CONCURRENT_SCANS"] = str(limit)
    spec = importlib.util.spec_from_file_location(f"tool_job_{limit}", _MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Tracker:
    """Records terminal job states so refusals can be asserted."""
    def __init__(self):
        self.failures = {}
    def update_job(self, job_id, **kw):
        if kw.get("status") == "failed":
            self.failures[job_id] = kw.get("error", "")
    def push_command(self, *a, **k): pass
    def update_progress(self, *a, **k): pass


def _run_many(monkeypatch, mod, count, hold=0.25, **overrides):
    """Run `count` jobs concurrently against a fake subprocess; return peak."""
    peak = 0
    lock = threading.Lock()

    def fake_run(cmd, **kw):
        nonlocal peak
        with lock:
            peak = max(peak, mod.active_slot_count())
        time.sleep(hold)
        class CP:
            returncode, stdout, stderr = 0, "", ""
        return CP()

    # monkeypatch, NOT `mod.subprocess.run = ...`.
    #
    # `mod` is a fresh module object, but `mod.subprocess` is the SHARED
    # subprocess module — so a bare assignment replaces subprocess.run for the
    # WHOLE test session and never restores it. That leak sat here harmlessly
    # until another test used subprocess.run and started failing with
    # "RuntimeError: tool exploded" from a test that had already finished.
    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    tracker = overrides.pop("job_tracker", None) or _Tracker()
    kwargs = dict(tool="x", cmd=["true"], targets_file="", output_file="",
                  service_name="t", session_label="t", job_tracker=tracker,
                  emit_webhook_event=lambda *a, **k: None,
                  write_audit=lambda *a, **k: None,
                  ingest_results=lambda *a, **k: None)
    kwargs.update(overrides)
    threads = [threading.Thread(target=mod.run_tool_job,
                                kwargs=dict(job_id=f"j{i}", **kwargs))
               for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return peak, tracker


@pytest.mark.parametrize("limit", [1, 2, 3])
def test_concurrent_tools_never_exceed_the_limit(limit, monkeypatch):
    mod = _load(limit)
    peak, _ = _run_many(monkeypatch, mod, count=limit * 3, hold=0.15)
    assert peak <= limit, f"limit={limit} but {peak} tools ran at once"


def test_the_test_would_notice_an_unbounded_runner(monkeypatch):
    """Guards the guard: with a high limit the peak must actually exceed 1.

    If the fake never overlaps, the assertions above would pass against a
    completely unbounded runner and prove nothing.
    """
    mod = _load(8)
    peak, _ = _run_many(monkeypatch, mod, count=8, hold=0.3)
    assert peak > 1, (
        f"peak was {peak}: the jobs never ran concurrently, so the bound tests "
        "above cannot distinguish a working limiter from no limiter at all")


def test_limit_comes_from_the_engagement_setting():
    """Not a private knob — the same variable the rest of the stack uses."""
    mod = _load(4)
    assert mod.MAX_CONCURRENT_SCANS == 4


def test_a_refused_job_does_not_consume_a_slot(monkeypatch):
    """An out-of-scope job must not occupy capacity it never used."""
    mod = _load(2)
    tracker = _Tracker()
    peak, tracker = _run_many(monkeypatch, mod, count=4, hold=0.15, job_tracker=tracker,
        scope_refusal=lambda _tf: "out of scope")
    assert peak == 0, f"refused jobs ran a tool anyway (peak {peak})"
    assert len(tracker.failures) == 4
    assert all("Out of scope" in e for e in tracker.failures.values())
    # Slots must be back, not leaked by the early return.
    assert mod.active_slot_count() == 0, "refusal leaked a slot"


def test_slots_are_released_when_a_tool_fails(monkeypatch):
    """A crashing tool must not permanently consume capacity."""
    mod = _load(2)

    def boom(cmd, **kw):
        raise RuntimeError("tool exploded")
    # monkeypatch, NOT `mod.subprocess.run = ...`.
    #
    # `mod` is a fresh module object, but `mod.subprocess` is the SHARED
    # subprocess module — so a bare assignment replaces subprocess.run for the
    # WHOLE test session and never restores it. That leak sat here harmlessly
    # until another test used subprocess.run and started failing with
    # "RuntimeError: tool exploded" from a test that had already finished.
    monkeypatch.setattr(mod.subprocess, "run", boom)
    tracker = _Tracker()
    mod.run_tool_job(job_id="j", tool="x", cmd=["true"], targets_file="",
                     output_file="", service_name="t", session_label="t",
                     job_tracker=tracker, emit_webhook_event=lambda *a, **k: None,
                     write_audit=lambda *a, **k: None,
                     ingest_results=lambda *a, **k: None)
    assert mod.active_slot_count() == 0, "a failed job leaked its slot"
    assert tracker.failures, "failure was not recorded on the job"
