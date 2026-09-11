import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useUIStore } from '@/stores/ui'

/**
 * Drop cached query data when the operator switches engagement or scope.
 *
 * WHY THIS EXISTS
 * ---------------
 * The active engagement reaches the backend as the `X-Engagement-Id` HEADER
 * (apiFetch → BFF → engagement_headers()), and the server filters on it. The
 * header is not part of the URL and not part of the React Query key, so
 * switching engagement changes what the server WOULD return while the key stays
 * identical — and React Query, correctly, serves the previous engagement's rows
 * from cache and never refetches.
 *
 * That is why Assets, Software, Subdomains and Credentials "did not refresh"
 * when the scope line changed: the picker sets engagement and scope together
 * (stores/ui.ts::setEngagement), and none of those queries keyed on either.
 *
 * WHY THIS IS CENTRAL RATHER THAN PER-HOOK
 * ----------------------------------------
 * 492 of the 534 `queryKey` declarations in src/api have no engagement term.
 * Threading one through each is both a large change and a guarantee that the
 * next hook someone adds forgets it — the bug would come back in a corner
 * nobody is looking at. One reset at the root covers every area that exists
 * today and every one added later.
 *
 * WHY `clear()` AND NOT `invalidateQueries()`
 * -------------------------------------------
 * `invalidateQueries` refetches but KEEPS SHOWING the stale data until the new
 * response lands. In this product that stale data is another engagement's
 * hosts, findings and credentials — showing one client's estate under another
 * client's name, even for a second, is not a cosmetic problem. `clear()` drops
 * it, so the tables go to their loading state and come back with the right
 * engagement's rows.
 *
 * A scope change alone is lighter: scope is mostly applied client-side, so an
 * invalidate is enough to pull anything the server filters by scope.
 */
export function useEngagementCacheReset() {
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const scopeName = useUIStore(s => s.selectedScopeName)
  const qc = useQueryClient()
  // Remember what we last reacted to, so the FIRST render does not wipe the
  // cache the app has only just populated.
  const seen = useRef<{ eid: string | null; scope: string | null } | null>(null)

  useEffect(() => {
    const prev = seen.current
    seen.current = { eid: engagementId, scope: scopeName }
    if (prev === null) return                       // initial mount
    if (prev.eid !== engagementId) {
      qc.clear()                                    // no cross-engagement bleed
      return
    }
    if (prev.scope !== scopeName) {
      qc.invalidateQueries()
    }
  }, [engagementId, scopeName, qc])
}
