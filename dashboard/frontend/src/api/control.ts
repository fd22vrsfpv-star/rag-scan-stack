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
