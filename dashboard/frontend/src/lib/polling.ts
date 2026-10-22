/**
 * Smart polling intervals that pause when the browser tab is hidden.
 * Usage: replace `refetchInterval: 15000` with `refetchInterval: smartInterval(15000)`
 */

/** Returns a function that React Query calls to determine the polling interval.
 *  Returns `false` when the tab is hidden (pauses polling). */
export function smartInterval(ms: number): () => number | false {
  return () => (document.hidden ? false : ms)
}

/** Predefined intervals for common use cases.
 *
 *  LENGTHENED 2026-10-22 (operator: "lets reduce the poll time, 30seconds is
 *  to low"). Every tier was shorter than the endpoint behind it could answer
 *  on a real estate, and an interval shorter than the response time is a
 *  QUEUE, not a poll — each tick starts before the last finishes and they
 *  accumulate. Measured that day on the redteam engagement:
 *
 *      /assets                      >60s   polled at NORMAL (30s)
 *      /software/cves-without-poc   ~137s  polled at FAST   (10s)
 *
 *  29 concurrent copies of the assets query were observed, the oldest 34
 *  minutes old, saturating the database until unrelated pages — News among
 *  them — timed out and rendered blank. Both queries are fixed, but the
 *  intervals were the multiplier and they are the cheap half of the defence:
 *  a slow query costs one request, a slow query on a short poll costs an
 *  unbounded number.
 *
 *  These are dashboard refresh rates, not instrumentation. Nothing here is
 *  watching something that changes second to second — a scan that started
 *  12 seconds ago is still news at 20. Where a view genuinely must feel live,
 *  prefer an explicit refresh button or an event, not a tighter timer. */
export const POLL = {
  /** Real-time: 15s (scan progress, active sessions) — only when tab visible */
  REALTIME: smartInterval(15000),
  /** Fast: 30s (exploits, sync) — only when tab visible */
  FAST: smartInterval(30000),
  /** Normal: 90s (findings, assets, follow-ups) */
  NORMAL: smartInterval(90000),
  /** Slow: 180s (recon, evidence, maintenance) */
  SLOW: smartInterval(180000),
  /** Background: 300s (cloud providers, MCP status, health) */
  BACKGROUND: smartInterval(300000),
}
