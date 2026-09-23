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
    // The message format is unchanged -- callers that match on it still work --
    // but the status and the PARSED body are attached as fields. Without them a
    // caller wanting to act on one specific status (e.g. the BFF's 409
    // "confirm local execution") had to regex the message, and the structured
    // detail the server sent was thrown away.
    let parsed: unknown = undefined
    try { parsed = JSON.parse(text) } catch { /* not JSON; leave undefined */ }
    throw new ApiError(`API ${resp.status}: ${text}`, resp.status, parsed)
  }
  return resp.json()
}

/** An HTTP error that kept its status code and decoded body. */
export class ApiError extends Error {
  readonly status: number
  readonly body: unknown

  constructor(message: string, status: number, body?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
    // Required for `instanceof` to work when targeting ES5-era output.
    Object.setPrototypeOf(this, ApiError.prototype)
  }

  /** FastAPI puts HTTPException payloads under `detail`; unwrap it. */
  get detail(): Record<string, unknown> | undefined {
    const b = this.body as { detail?: unknown } | undefined
    const d = b && typeof b === 'object' ? b.detail : undefined
    return d && typeof d === 'object' ? (d as Record<string, unknown>) : undefined
  }
}

export function apiUrl(path: string): string {
  return `${BASE}${path}`
}
