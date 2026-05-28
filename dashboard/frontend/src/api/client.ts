const BASE = '/api'

/**
 * Read the currently-selected engagement from the Zustand UI store's
 * localStorage backing.  Read here (not via the React hook) so the value
 * is available outside React render context -- this lets `apiFetch`
 * attach the X-Engagement-Id header on every call from any caller.
 *
 * The matching key/format is defined in `src/stores/ui.ts`.
 */
// Mirrors `ENGAGEMENT_KEY` in src/stores/ui.ts -- keep these in sync.
const ENGAGEMENT_STORAGE_KEY = 'selected-engagement'

function getActiveEngagementId(): string | null {
  try {
    return (typeof localStorage !== 'undefined')
      ? localStorage.getItem(ENGAGEMENT_STORAGE_KEY)
      : null
  } catch {
    return null
  }
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  // Engagement-isolation: every request carries the active engagement so the
  // rag-api middleware captures it into the request-scoped contextvar and
  // every scan-launch / INSERT site stamps it automatically.  Endpoints
  // that need to filter results (scans, audit-log, ...) ALSO accept it as
  // an explicit query param -- this header is the universal default.
  const eid = getActiveEngagementId()
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(eid ? { 'X-Engagement-Id': eid } : {}),
    ...init?.headers,
  }
  const resp = await fetch(`${BASE}${path}`, { ...init, headers })
  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`API ${resp.status}: ${text}`)
  }
  return resp.json()
}

export function apiUrl(path: string): string {
  return `${BASE}${path}`
}
