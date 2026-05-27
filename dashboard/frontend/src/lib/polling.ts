/**
 * Smart polling intervals that pause when the browser tab is hidden.
 * Usage: replace `refetchInterval: 15000` with `refetchInterval: smartInterval(15000)`
 */

/** Returns a function that React Query calls to determine the polling interval.
 *  Returns `false` when the tab is hidden (pauses polling). */
export function smartInterval(ms: number): () => number | false {
  return () => (document.hidden ? false : ms)
}

/** Predefined intervals for common use cases */
export const POLL = {
  /** Real-time: 3-5s (scan progress, active sessions) — only when tab visible */
  REALTIME: smartInterval(5000),
  /** Fast: 10s (exploits, sync) — only when tab visible */
  FAST: smartInterval(10000),
  /** Normal: 30s (findings, assets, follow-ups) */
  NORMAL: smartInterval(30000),
  /** Slow: 60s (recon, evidence, maintenance) */
  SLOW: smartInterval(60000),
  /** Background: 120s (cloud providers, MCP status, health) */
  BACKGROUND: smartInterval(120000),
}
