import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { ScanJob } from '@/lib/types'
import { POLL } from '@/lib/polling'

export function useScans() {
  return useQuery({
    queryKey: ['scans'],
    queryFn: () => apiFetch<{ jobs: ScanJob[] }>('/scans'),
    refetchInterval: POLL.REALTIME,
  })
}

/** Lightweight scan count for global badges (TopBar). Polls slowly. */
export function useScanCount() {
  return useQuery({
    queryKey: ['scan-count'],
    queryFn: () => apiFetch<{ jobs: ScanJob[] }>('/scans'),
    refetchInterval: POLL.SLOW,
    select: (data) => data.jobs?.filter(j => j.status === 'running' || j.status === 'queued').length ?? 0,
  })
}

export function useScanDetail(jobId: string) {
  return useQuery({
    queryKey: ['scan', jobId],
    queryFn: () => apiFetch<ScanJob>(`/scans/${jobId}`),
    enabled: !!jobId,
    refetchInterval: POLL.REALTIME,
    placeholderData: (prev: ScanJob | undefined) => prev,
    retry: 1,
  })
}

export function useLaunchScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ type, params }: { type: string; params: Record<string, unknown> }) =>
      apiFetch<{ job_id: string; type: string }>(`/scans/${type}`, {
        method: 'POST',
        body: JSON.stringify(params),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export function useStopScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (jobId: string) =>
      apiFetch<{ ok: boolean; job_id: string; resumable?: boolean }>(`/scans/${jobId}/stop`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export function useResumeScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (jobId: string) =>
      apiFetch<{ ok: boolean; job_id: string; resumed_from: string }>(`/scans/${jobId}/resume`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export interface NmapResumeInfo {
  job_id: string
  status: string
  resumable: boolean
  log_bases: string[]
  log_files: { base: string; nmap: string | null; gnmap: string | null; xml: string | null }[]
}

export function useNmapResumeInfo(jobId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['nmap-resume-info', jobId],
    queryFn: () => apiFetch<NmapResumeInfo>(`/scans/${jobId}/nmap-resume-info`),
    enabled: !!jobId && enabled,
    retry: 0,
  })
}

export function useNmapResume() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { job_id?: string; log_base?: string; timeout_seconds?: number }) =>
      apiFetch<{ ok: boolean; job_id: string; job_ids: string[]; resumed_from: string | null }>(
        `/scans/nmap-resume`,
        { method: 'POST', body: JSON.stringify(body) },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export function useDeleteScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (jobId: string) =>
      apiFetch<{ ok: boolean }>(`/scans/${jobId}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export interface PortSummary {
  hosts_with_ports: number
  total_open_ports: number
  by_service: { service: string; count: number; hosts: string[] }[]
  by_host: { ip: string; hostname: string; open_ports: number; ports: number[] }[]
}

export function usePortSummary(enabled: boolean) {
  return useQuery({
    queryKey: ['port-summary'],
    queryFn: () => apiFetch<PortSummary>('/ports/summary'),
    enabled,
  })
}

// ── Scan Pipelines ──────────────────────────────────────────────────────

export interface Pipeline {
  id: string
  engagement_id: string
  name: string
  status: string
  profile: string
  target_count: number
  jobs_spawned: number
  jobs_completed: number
  jobs_failed: number
  findings_count: number
  host_states: Record<string, { stage: number; stage_name: string; status: string; ports_found: number; services_found: number; urls_found: number; jobs: string[] }>
  progress: Record<string, unknown>
  created_at: string
  updated_at: string
  completed_at: string | null
}

export function usePipelines(engagementId?: string | null) {
  return useQuery({
    queryKey: ['pipelines', engagementId],
    queryFn: () => apiFetch<{ pipelines: Pipeline[] }>(
      `/pipelines${engagementId ? `?engagement_id=${engagementId}` : ''}`
    ),
    refetchInterval: POLL.NORMAL,
  })
}

export function usePipeline(pipelineId: string | undefined) {
  return useQuery({
    queryKey: ['pipeline', pipelineId],
    queryFn: () => apiFetch<Pipeline>(`/pipelines/${pipelineId}`),
    enabled: !!pipelineId,
    refetchInterval: POLL.REALTIME,
  })
}

export function useLaunchPipeline() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      engagement_id: string; name?: string; profile?: string;
      scope_name?: string; config?: Record<string, unknown>
    }) => apiFetch<{ ok: boolean; pipeline_id: string; target_count: number; proxies: number }>(
      '/pipelines', { method: 'POST', body: JSON.stringify(body) },
    ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pipelines'] }),
  })
}

export function useStopPipeline() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (pipelineId: string) =>
      apiFetch<{ ok: boolean }>(`/pipelines/${pipelineId}/stop`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pipelines'] }),
  })
}

export function usePipelineJobs(pipelineId: string | undefined) {
  return useQuery({
    queryKey: ['pipeline-jobs', pipelineId],
    queryFn: () => apiFetch<{ jobs: Record<string, unknown>[]; count: number }>(
      `/pipelines/${pipelineId}/jobs`
    ),
    enabled: !!pipelineId,
    refetchInterval: POLL.NORMAL,
  })
}

export function useClearScanHistory() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; deleted_count: number }>('/scans', { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export interface AuditEntry {
  timestamp: string
  event: string
  scan_type: string
  source: string
  job_id: string
  [key: string]: unknown
}

export function useScanAudit(jobId: string) {
  return useQuery({
    queryKey: ['scan-audit', jobId],
    queryFn: () => apiFetch<{ entries: AuditEntry[]; total: number }>(`/maintenance/audit-log?job_id=${jobId}`),
    enabled: !!jobId,
  })
}
