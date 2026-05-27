import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { ScheduledScan } from '@/lib/types'
import { POLL } from '@/lib/polling'

export interface RecentScan {
  job_id: string
  scan_type: string
  source_ip: string
  hostname: string
  targets: string[]
  target_url: string
  execution_mode: string
  node_id?: string
  started_at: string | null
  ended_at: string | null
  status: string
  error?: string | null
  duration_s?: number | null
}

export function useOpsecTimeline(hours = 24) {
  return useQuery({
    queryKey: ['opsec-timeline', hours],
    queryFn: () => apiFetch<{
      buckets: Array<{ hour: string; count: number }>
      source_ips: Array<{ source: string; count: number }>
      recent_scans: RecentScan[]
    }>(`/opsec/timeline?hours=${hours}`),
    refetchInterval: POLL.SLOW,
  })
}

export function useOpsecAlerts(threshold = 20) {
  return useQuery({
    queryKey: ['opsec-alerts', threshold],
    queryFn: () => apiFetch<{
      alerts: Array<{ type: string; message: string; hour?: string; count?: number }>
      threshold: number
    }>(`/opsec/alerts?threshold=${threshold}`),
    refetchInterval: POLL.SLOW,
  })
}

export function useScheduledScans(status?: string) {
  const params = status ? `?status=${status}` : ''
  return useQuery({
    queryKey: ['scheduled-scans', status],
    queryFn: () => apiFetch<{ scheduled_scans: ScheduledScan[] }>(`/scheduled-scans${params}`),
    refetchInterval: POLL.SLOW,
  })
}

export function useCreateScheduledScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<ScheduledScan>) =>
      apiFetch<ScheduledScan>('/scheduled-scans', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scheduled-scans'] }),
  })
}

export function useCancelScheduledScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/scheduled-scans/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scheduled-scans'] }),
  })
}
