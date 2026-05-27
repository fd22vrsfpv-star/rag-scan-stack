import time
import asyncio
from typing import Dict, Any, List
from utils.nmap_scheduler import Scheduler, Probe, TransientError


def test_scheduler_respects_max_concurrency_and_per_dest_limits():
    # Arrange
    max_conc = 3
    per_dest = 1
    sched = Scheduler(
        max_concurrency=max_conc,
        per_destination_limit=per_dest,
        spawn_rate_per_sec=1000,  # effectively disabled
        max_retries=0,
        backoff_base_sec=0.01,
        backoff_max_sec=0.05,
        backoff_jitter_sec=0.0,
    )

    # Track running counts to assert limits are never exceeded
    running_global = 0
    max_seen_global = 0
    per_host_running: Dict[str, int] = {}
    per_host_max_seen: Dict[str, int] = {}
    lock = asyncio.Lock()

    async def on_start(probe: Probe, attempt: int):
        nonlocal running_global, max_seen_global
        async with lock:
            running_global += 1
            max_seen_global = max(max_seen_global, running_global)
            per_host_running[probe.destination] = per_host_running.get(probe.destination, 0) + 1
            per_host_max_seen[probe.destination] = max(per_host_max_seen.get(probe.destination, 0), per_host_running[probe.destination])

    async def on_finish(probe: Probe, ok: bool, err: Exception | None):
        nonlocal running_global
        async with lock:
            running_global -= 1
            per_host_running[probe.destination] = per_host_running.get(probe.destination, 1) - 1

    # Fake runner that takes 0.1s
    async def fake_runner(probe: Probe) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {"ok": True, "probe": probe.destination}

    # Create 9 probes across 3 destinations (to exercise per-dest throttle)
    probes: List[Probe] = []
    for i in range(3):
        for _ in range(3):
            probes.append(Probe(destination=f"10.0.0.{i+1}", ports=[80, 443]))

    # Act
    sched.on_task_start = on_start
    sched.on_task_finish = on_finish
    start = time.monotonic()
    results = asyncio.run(sched.run(probes, runner=fake_runner))
    elapsed = time.monotonic() - start

    # Assert
    assert all(r.get("ok") for r in results)
    assert max_seen_global <= max_conc, f"Observed global concurrency {max_seen_global} exceeds limit {max_conc}"
    for host, seen in per_host_max_seen.items():
        assert seen <= per_dest, f"Observed per-destination concurrency {seen} for {host} exceeds limit {per_dest}"
    # With 9 tasks at conc=3, expect ~3 waves; each ~0.1s, add slack
    assert elapsed >= 0.25, f"Elapsed {elapsed} too small; expected batching by concurrency"
    assert elapsed < 1.5, f"Elapsed {elapsed} too large for configured concurrency"


def test_scheduler_retries_with_exponential_backoff():
    # Arrange
    sched = Scheduler(
        max_concurrency=1,
        per_destination_limit=1,
        spawn_rate_per_sec=1000,
        max_retries=2,
        backoff_base_sec=0.2,
        backoff_max_sec=1.0,
        backoff_jitter_sec=0.0,  # deterministic
    )

    attempts_started: List[float] = []
    async def on_start(probe: Probe, attempt: int):
        attempts_started.append(time.monotonic())

    sched.on_task_start = on_start

    probe = Probe(destination="192.0.2.1", ports=[22])

    # Fail first two times transiently, then succeed
    state = {"count": 0}
    async def sometimes_failing_runner(p: Probe) -> Dict[str, Any]:
        state["count"] += 1
        if state["count"] < 3:
            raise TransientError("temporary network glitch")
        await asyncio.sleep(0.01)
        return {"ok": True}

    # Act
    t0 = time.monotonic()
    result = asyncio.run(sched.run([probe], runner=sometimes_failing_runner))[0]
    t_total = time.monotonic() - t0

    # Assert success after retries
    assert result["ok"] is True
    assert result["attempts"] == 3
    # Expected backoff: 0.2 + 0.4 = 0.6 (plus tiny runner sleep)
    assert t_total >= 0.55, f"Total elapsed {t_total} shorter than expected backoff"
    assert t_total < 2.5, f"Total elapsed {t_total} unexpectedly long"
    # Ensure we actually had multiple starts recorded
    assert len(attempts_started) >= 3
