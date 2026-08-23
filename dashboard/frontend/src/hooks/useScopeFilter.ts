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
    // No scope selected → no filter, everything matches.
    if (!scopeName) return true
    // A scope IS selected but its target list hasn't arrived yet (React Query
    // is mid-fetch after the user picked a new scope from the dropdown).
    // Return false so the table briefly shows empty rather than flashing the
    // entire unfiltered asset list -- the latter looked like "the scope change
    // didn't take" to operators.  Once targetsList lands, this re-runs and
    // applies the real filter.
    if (!targetsList) return false
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
  }, [scopeName, targetsList])

  /**
   * True when ANY of the given identities is in scope.
   *
   * Call sites used to pass `a.hostname || a.ip` — the FIRST non-empty value,
   * not all of them. A host has both identities and the scope may name either,
   * so an asset named `metasploitable` whose scope entry is the IP
   * `192.168.1.150` was filtered OUT of its own scope. That stayed hidden only
   * because the same host also existed as a second, hostname-less asset row
   * that matched by IP; once those duplicates were merged, the host vanished
   * from the scope view entirely.
   */
  const matchesAnyScope = useCallback((...vals: (string | null | undefined)[]): boolean => {
    if (!scopeName) return true
    const present = vals.filter((v): v is string => !!v && !!v.trim())
    // Nothing to test. Keep the row rather than hiding it: an asset with no
    // identity at all is a data problem, and silently dropping it from a scope
    // view is how one gets missed.
    if (present.length === 0) return true
    return present.some(v => matchesScope(v))
  }, [scopeName, matchesScope])

  // isFiltering reflects user intent (a scope is selected), not load state.
  // This keeps the count chip ("N in <scope>") accurate the instant the user
  // changes the dropdown, rather than blinking off during the targets refetch.
  return { matchesScope, matchesAnyScope, isFiltering: !!scopeName }
}
