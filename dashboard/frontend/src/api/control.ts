import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface ControlStatus {
  halted: boolean
  reason?: string | null
  controls: Array<{
    scope: string; halted: boolean; reason?: string | null
    scan_budget?: number | null; scans_used?: number; host_cap?: number | null
    updated_at?: string
  }>
}

/** Poll the platform control state (global kill-switch). */
export function useControlStatus() {
  return useQuery({
    queryKey: ['control-status'],
    queryFn: () => apiFetch<ControlStatus>('/control/status'),
    refetchInterval: 5000,
    placeholderData: (p: ControlStatus | undefined) => p,
  })
}

export function useHalt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (reason?: string) =>
      apiFetch('/control/halt', {
        method: 'POST',
        body: JSON.stringify({ scope: 'global', reason: reason || 'operator halt' }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['control-status'] }),
  })
}

export function useResume() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch('/control/resume', {
        method: 'POST',
        body: JSON.stringify({ scope: 'global' }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['control-status'] }),
  })
}

// ── Per-engagement scan control ──────────────────────────────────────────────
//
// Same `platform_control` table and the same enforcement point as the global
// kill switch above — a halted scope makes `load_dispatch_scope` return no
// rows, and every gated dispatcher treats an empty scope as "refuse". Flipping
// this does not pause a scan that is already running; it refuses the NEXT
// dispatch.
//
// A GLOBAL halt overrides an engagement that is enabled, so the UI must render
// the effective state, not just this engagement's own row. `globalHalted` is
// returned separately for exactly that reason.

export interface EngagementControl {
  /** Effective: this engagement is halted, OR the whole platform is. */
  halted: boolean
  /** Only this engagement's own row — what the toggle writes. */
  engagementHalted: boolean
  globalHalted: boolean
  reason?: string | null
  actor?: string | null
  updatedAt?: string | null
}

export function useEngagementControl(engagementId?: string | null) {
  return useQuery({
    queryKey: ['control-status', 'engagement', engagementId],
    enabled: !!engagementId,
    refetchInterval: 10000,
    queryFn: async (): Promise<EngagementControl> => {
      const d = await apiFetch<ControlStatus>(
        `/control/status?engagement_id=${encodeURIComponent(engagementId!)}`)
      const own = (d.controls || []).find(c => c.scope === engagementId)
      const glob = (d.controls || []).find(c => c.scope === 'global')
      return {
        halted: !!d.halted,
        engagementHalted: !!own?.halted,
        globalHalted: !!glob?.halted,
        reason: own?.halted ? own?.reason : d.reason,
        actor: (own as any)?.actor ?? null,
        updatedAt: own?.updated_at ?? null,
      }
    },
  })
}

/** Enable or disable dispatch for ONE engagement. */
export function useSetEngagementScans(engagementId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) =>
      apiFetch(enabled ? '/control/resume' : '/control/halt', {
        method: 'POST',
        body: JSON.stringify({
          scope: engagementId,
          reason: enabled ? undefined : 'scans disabled for this engagement',
        }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['control-status'] }),
  })
}
