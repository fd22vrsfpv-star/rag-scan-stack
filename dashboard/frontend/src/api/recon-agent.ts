import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

export interface AgentState {
  engagement_id: string
  enabled: boolean
  interval_sec: number
  last_run_at: string | null
  last_scan_at: string | null
  last_dispatch_at: string | null
  pause_until: string | null
  config: Record<string, unknown>
  stats: Record<string, unknown>
  exists: boolean
}

export interface CoverageEntry {
  id: string
  engagement_id: string
  target: string
  stage: number
  stage_name: string
  scan_type: string
  job_id: string | null
  status: string
  started_at: string | null
  completed_at: string | null
}

export function useReconAgentState(eid: string | undefined) {
  return useQuery({
    queryKey: ['recon-agent', eid],
    queryFn: () => apiFetch<AgentState>(`/recon-agent/${eid}`),
    enabled: !!eid,
    refetchInterval: POLL.NORMAL,
  })
}

export function useEnableReconAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ eid, interval_sec, config }: { eid: string; interval_sec?: number; config?: Record<string, unknown> }) =>
      apiFetch(`/recon-agent/${eid}/enable`, {
        method: 'POST',
        body: JSON.stringify({ interval_sec: interval_sec || 300, config }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['recon-agent'] }),
  })
}

export function useDisableReconAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (eid: string) => apiFetch(`/recon-agent/${eid}/disable`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['recon-agent'] }),
  })
}

export function usePauseReconAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ eid, minutes }: { eid: string; minutes: number }) =>
      apiFetch(`/recon-agent/${eid}/pause?minutes=${minutes}`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['recon-agent'] }),
  })
}

export function useRunReconAgentNow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (eid: string) => apiFetch(`/recon-agent/${eid}/run-now`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['recon-agent'] }),
  })
}

export function useReconAgentCoverage(eid: string | undefined) {
  return useQuery({
    queryKey: ['recon-agent-coverage', eid],
    queryFn: () => apiFetch<{ coverage: CoverageEntry[]; count: number }>(`/recon-agent/${eid}/coverage`),
    enabled: !!eid,
    refetchInterval: POLL.NORMAL,
  })
}

export function useReconAgentLog(eid: string | undefined) {
  return useQuery({
    queryKey: ['recon-agent-log', eid],
    queryFn: () => apiFetch<{ events: Record<string, unknown>[] }>(`/recon-agent/${eid}/log`),
    enabled: !!eid,
    refetchInterval: POLL.SLOW,
  })
}
