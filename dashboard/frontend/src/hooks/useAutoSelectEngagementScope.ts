import { useEffect, useRef } from 'react'
import { useUIStore } from '@/stores/ui'
import { useEngagementScopes } from '@/api/engagements'

/**
 * When the active engagement changes, automatically select the scope under
 * that engagement with the highest target_count (alphabetical tiebreaker).
 *
 * Only runs once per engagement-change. After the auto-select, the user is
 * free to switch to "All Scopes" or another scope and the hook won't override.
 *
 * Mount once at the top level (TopBar) so it runs globally.
 */
export function useAutoSelectEngagementScope(): void {
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const setSelectedScope = useUIStore(s => s.setSelectedScope)
  const { data } = useEngagementScopes(engagementId ?? undefined)
  const lastAutoForEid = useRef<string | null>(null)

  useEffect(() => {
    // No engagement: clear the marker so the next selection re-triggers.
    if (!engagementId) {
      lastAutoForEid.current = null
      return
    }
    // Already auto-selected for this engagement — respect any subsequent user choice.
    if (lastAutoForEid.current === engagementId) return

    const scopes = data?.scopes ?? []
    if (scopes.length === 0) return // wait for scopes to load

    // Pick the one with the most targets; tie-break by name for stability.
    const best = [...scopes].sort((a, b) => {
      const diff = (b.target_count || 0) - (a.target_count || 0)
      return diff !== 0 ? diff : a.name.localeCompare(b.name)
    })[0]

    if (best?.name) {
      setSelectedScope(best.name)
      lastAutoForEid.current = engagementId
    }
  }, [engagementId, data, setSelectedScope])
}
