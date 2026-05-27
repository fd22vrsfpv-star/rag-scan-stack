import { useMemo, useCallback } from 'react'
import { useEngagementScopeTargets } from '@/api/engagements'
import { useUIStore } from '@/stores/ui'

/**
 * Returns a filter function that checks if a hostname/IP/URL matches a scope.
 * Uses the currently selected engagement for scope context.
 * When scopeName is empty, returns a passthrough (everything matches).
 */
export function useScopeFilter(scopeName: string) {
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const { data: scopeData } = useEngagementScopeTargets(engagementId ?? undefined, scopeName || undefined)

  // Build a serializable key so useMemo/useCallback properly invalidate
  const targetsList = useMemo(() => {
    if (!scopeName || !scopeData?.targets?.length) return null
    return scopeData.targets.map(t => (t.target || '').toLowerCase().trim()).filter(Boolean)
  }, [scopeName, scopeData])

  const matchesScope = useCallback((val: string): boolean => {
    if (!targetsList) return true
    if (!val) return false
    const v = val.toLowerCase().trim()
    const targets = new Set(targetsList)
    // Direct match
    if (targets.has(v)) return true
    // Strip URL to hostname
    try {
      const url = v.startsWith('http') ? new URL(v) : null
      if (url) {
        const host = url.hostname
        if (targets.has(host)) return true
        for (const t of targets) {
          if (host.endsWith('.' + t)) return true
        }
      }
    } catch { /* not a URL */ }
    // Subdomain match
    for (const t of targets) {
      if (v.endsWith('.' + t)) return true
    }
    return false
  }, [targetsList])

  return { matchesScope, isFiltering: !!targetsList }
}
