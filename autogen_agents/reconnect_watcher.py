"""Reconnect Watcher (Tier 1) — re-establish access that a host reboot dropped.

WHAT THIS DOES (and, deliberately, what it does NOT)
----------------------------------------------------
When a compromised host reboots (e.g. for patches), every live process on it
dies with it: a Meterpreter session, a raw reverse/bind shell — gone. There is
nothing on the far end to *reconnect* to. So this watcher does the one thing that
is actually recoverable without pre-installed persistence: it RE-PROBES.

`etl.access.refresh(target)` re-discovers and re-probes every access on a host
and rewrites `obtained_access` with `live`/`dead`. The kind that comes back this
way is `ssh_credential` — `etl.access._run_ssh_credential` re-opens SSH with the
stored credential on every probe, and the credential still works after a reboot.
A dead `msf_session` / `bind_shell` stays dead: this watcher does NOT re-exploit
and does NOT catch persistence callbacks — those are Tier 2/3 and are recorded in
Docs/OPEN_ITEMS.md.

INVARIANTS HONOURED
-------------------
- SCOPE GATE, FAIL CLOSED. Re-probing sends traffic to the target, so every
  target is checked against `etl.scope_gate` (load_dispatch_scope + check_dispatch)
  before `refresh()` runs. No configured scope => refused. Halt/budget are
  enforced for free because load_dispatch_scope consults them.
- WEBHOOKS. Every action emits via POST /webhooks/emit (source "reconnect-watcher"):
  access_reconnect_attempted, access_reconnected, access_reconnect_failed,
  access_reconnect_blocked.
- NOT A SCAN INITIATOR. It runs `id` through access that already exists; it starts
  no tool and holds no scan slot, so MAX_CONCURRENT_SCANS does not apply. It also
  processes one target at a time, so it cannot amplify concurrency.

Run standalone:  python -m reconnect_watcher   (from autogen_agents/)
"""

import os
import sys
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("reconnect_watcher")

# ── Configuration ────────────────────────────────────────────────────────────
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")

# Seconds between sweeps of the access store.
POLL_INTERVAL = int(os.environ.get("RECONNECT_WATCH_INTERVAL", "120"))
# Minimum seconds between reconnect attempts for the SAME target, so a host that
# stays down is retried on a slow cadence instead of every sweep.
MIN_ATTEMPT_INTERVAL = int(os.environ.get("RECONNECT_MIN_INTERVAL", "300"))
# Probe rounds to pass to refresh(); None => access.py's own STABILITY_PROBES.
_rounds_env = os.environ.get("RECONNECT_PROBE_ROUNDS", "").strip()
PROBE_ROUNDS: Optional[int] = int(_rounds_env) if _rounds_env.isdigit() else None


def _emit_webhook(event_type: str, data: Dict[str, Any]) -> None:
    """Fire-and-forget webhook. RAG_API_URL must be https (rag-api is TLS-only);
    an http value makes every emit fail silently. `source` is required (422
    without it); stored type becomes reconnect-watcher_<event_type>."""
    try:
        import httpx
        httpx.post(
            f"{RAG_API_URL}/webhooks/emit",
            json={"event_type": event_type, "source": "reconnect-watcher", "data": data},
            headers={"x-api-key": API_KEY},
            verify=False,
            timeout=10,
        )
    except Exception:  # noqa: BLE001 — telemetry must never break the loop
        logger.debug("webhook emit failed for %s", event_type, exc_info=True)


class ReconnectWatcher:
    """Polls obtained_access for dead access and re-probes it, scope-gated."""

    def __init__(self):
        self.running = False
        self._last_check: Optional[datetime] = None
        # target -> monotonic-ish wall time of last attempt (throttle)
        self._last_attempt: Dict[str, float] = {}
        self._reconnected_total = 0
        self._attempts_total = 0
        self._blocked_total = 0

    # ── DB ────────────────────────────────────────────────────────────────
    def _conn(self):
        return psycopg2.connect(DB_DSN, connect_timeout=5)

    def _dead_targets(self) -> List[Tuple[str, Optional[str]]]:
        """(target, engagement_id) pairs that have at least one dead, non-rejected
        access. engagement_id is the gate's scope selector; NULL means no
        engagement, which the gate treats as all-engagements and still fails
        closed on an empty scope."""
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT target, engagement_id::text
                  FROM public.obtained_access
                 WHERE status = 'dead'
                   AND target IS NOT NULL AND target <> ''
                """
            )
            return [(r[0], r[1]) for r in cur.fetchall()]

    def _access_state(self, target: str) -> Dict[str, set]:
        """Current (kind, handle) sets by status for a target, so a
        dead->live transition can be measured rather than assumed."""
        state = {"live": set(), "dead": set()}
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT kind, handle, status FROM public.obtained_access "
                "WHERE target = %s", (target,))
            for kind, handle, status in cur.fetchall():
                if status in state:
                    state[status].add((kind, handle))
        return state

    # ── Scope gate (fail closed) ──────────────────────────────────────────
    def _scope_refusal(self, target: str, engagement_id: Optional[str]) -> Optional[str]:
        """Refusal string if this target must NOT be touched, else None."""
        try:
            from etl.scope_gate import load_dispatch_scope, check_dispatch
        except Exception as e:  # noqa: BLE001
            # Cannot prove scope => refuse. An unprovable gate is a closed gate.
            return f"scope gate unavailable ({e}) — refusing to touch {target}"
        try:
            with self._conn() as conn, conn.cursor() as cur:
                rows, source = load_dispatch_scope(cur, engagement_id)
        except Exception as e:  # noqa: BLE001
            return f"scope lookup failed ({e}) — refusing to touch {target}"
        if source == "unavailable":
            return f"scope unavailable — refusing to touch {target}"
        return check_dispatch(target, rows)

    # ── One target ────────────────────────────────────────────────────────
    async def _reconnect_target(self, target: str, engagement_id: Optional[str]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).timestamp()
        last = self._last_attempt.get(target, 0.0)
        if now - last < MIN_ATTEMPT_INTERVAL:
            return {"target": target, "skipped": "throttled"}

        refusal = self._scope_refusal(target, engagement_id)
        if refusal:
            self._blocked_total += 1
            logger.warning("Reconnect BLOCKED for %s: %s", target, refusal)
            _emit_webhook("access_reconnect_blocked", {
                "target": target, "engagement_id": engagement_id, "reason": refusal})
            # Throttle blocked targets too, so a persistently out-of-scope row
            # does not spam the gate every sweep.
            self._last_attempt[target] = now
            return {"target": target, "blocked": refusal}

        self._last_attempt[target] = now
        self._attempts_total += 1
        before = self._access_state(target)
        dead_before = before["dead"]
        logger.info("Reconnect attempt on %s (%d dead access)", target, len(dead_before))
        _emit_webhook("access_reconnect_attempted", {
            "target": target, "engagement_id": engagement_id,
            "dead_before": len(dead_before)})

        # refresh() is synchronous and blocks on probe timeouts (up to
        # ACCESS_PROBE_TIMEOUT per candidate), so run it off the event loop.
        try:
            from etl import access as ax
            result = await asyncio.to_thread(
                ax.refresh, target, rounds=PROBE_ROUNDS, engagement_id=engagement_id)
        except Exception as e:  # noqa: BLE001
            logger.error("refresh() failed for %s: %s", target, e)
            _emit_webhook("access_reconnect_failed", {
                "target": target, "engagement_id": engagement_id,
                "reason": f"refresh error: {str(e)[:200]}"})
            return {"target": target, "error": str(e)}

        after = self._access_state(target)
        recovered = sorted(dead_before & after["live"])
        if recovered:
            self._reconnected_total += len(recovered)
            recovered_kinds = sorted({k for k, _ in recovered})
            logger.info("RECONNECTED %s: %d access back (%s)",
                        target, len(recovered), ", ".join(recovered_kinds))
            _emit_webhook("access_reconnected", {
                "target": target, "engagement_id": engagement_id,
                "recovered": len(recovered), "recovered_kinds": recovered_kinds,
                "live_total": len(after["live"]), "best": result.get("best")})
            return {"target": target, "recovered": len(recovered),
                    "kinds": recovered_kinds}

        reason = (f"{result.get('discovered', 0)} candidate(s) probed, "
                  f"{result.get('live', 0)} answered; "
                  f"{len(dead_before)} still dead")
        logger.info("Reconnect on %s recovered nothing: %s", target, reason)
        _emit_webhook("access_reconnect_failed", {
            "target": target, "engagement_id": engagement_id, "reason": reason,
            "still_dead": len(after["dead"])})
        return {"target": target, "recovered": 0, "reason": reason}

    # ── Loop ──────────────────────────────────────────────────────────────
    async def watch_loop(self):
        logger.info("=" * 60)
        logger.info("RECONNECT WATCHER STARTING (Tier 1: re-probe)")
        logger.info("Poll interval: %ss  |  min per-target interval: %ss  |  rounds: %s",
                    POLL_INTERVAL, MIN_ATTEMPT_INTERVAL, PROBE_ROUNDS or "default")
        logger.info("=" * 60)
        self.running = True
        while self.running:
            try:
                self._last_check = datetime.now(timezone.utc)
                pairs = self._dead_targets()
                done_targets: set = set()
                for target, engagement_id in pairs:
                    if not self.running:
                        break
                    if target in done_targets:
                        continue  # one refresh per target per sweep
                    done_targets.add(target)
                    try:
                        await self._reconnect_target(target, engagement_id)
                    except Exception as e:  # noqa: BLE001
                        logger.error("Error reconnecting %s: %s", target, e)
                # Bound the throttle map so a long-lived process does not leak.
                if len(self._last_attempt) > 2000:
                    cutoff = datetime.now(timezone.utc).timestamp() - MIN_ATTEMPT_INTERVAL * 4
                    self._last_attempt = {k: v for k, v in self._last_attempt.items()
                                          if v > cutoff}
            except Exception as e:  # noqa: BLE001
                logger.error("Error in reconnect watch loop: %s", e)
            await asyncio.sleep(POLL_INTERVAL)

    def stop(self):
        self.running = False
        logger.info("Reconnect watcher stopping...")

    async def get_status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "last_check": self._last_check.isoformat() if self._last_check else None,
            "attempts_total": self._attempts_total,
            "reconnected_total": self._reconnected_total,
            "blocked_total": self._blocked_total,
            "config": {
                "poll_interval": POLL_INTERVAL,
                "min_attempt_interval": MIN_ATTEMPT_INTERVAL,
                "probe_rounds": PROBE_ROUNDS,
            },
        }


# ── Singleton + entrypoints (mirrors exploit_watcher) ─────────────────────────
_watcher: Optional[ReconnectWatcher] = None


def get_reconnect_watcher() -> ReconnectWatcher:
    global _watcher
    if _watcher is None:
        _watcher = ReconnectWatcher()
    return _watcher


async def start_reconnect_watcher():
    watcher = get_reconnect_watcher()
    await watcher.watch_loop()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    asyncio.run(start_reconnect_watcher())
