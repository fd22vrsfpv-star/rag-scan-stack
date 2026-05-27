import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface ScanRun {
  id: string
  tool: string
  target: string | null
  job_id: string | null
  profile: string | null
  started_at: string
  finished_at: string | null
  finding_count: number
  metadata: Record<string, unknown>
}

export interface DeltaFinding {
  id: string
  fingerprint: string
  severity?: string
  // vuln fields
  script?: string
  cve?: string[]
  cvss?: number
  ip?: string
  port?: number
  // web fields
  url?: string
  source?: string
  name?: string
  issue_type?: string
  // recon fields
  finding_type?: string
  target?: string
}

export interface DeltaResult {
  run_a: string
  run_b: string
  summary: {
    new: number
    resolved: number
    unchanged: number
  }
  new: DeltaFinding[]
  resolved: DeltaFinding[]
  unchanged_count: number
}

export interface DedupEntry {
  type: string
  fingerprint: string
  count: number
  tools: string[]
  severities: string[]
}

export function useScanRuns(tool?: string) {
  return useQuery({
    queryKey: ['scan-runs', tool],
    queryFn: () =>
      apiFetch<{ runs: ScanRun[] }>(`/delta/scan-runs${tool ? `?tool=${tool}` : ''}`),
    select: (d) => d.runs,
  })
}

export function useCreateScanRun() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: { tool: string; target?: string; job_id?: string }) => {
      const qs = new URLSearchParams({ tool: params.tool })
      if (params.target) qs.set('target', params.target)
      if (params.job_id) qs.set('job_id', params.job_id)
      return apiFetch<ScanRun>(`/delta/scan-runs?${qs}`, { method: 'POST' })
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-runs'] }),
  })
}

export function useBackfillScanRuns() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<{ created: number; runs: ScanRun[] }>('/delta/scan-runs/backfill', { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-runs'] }),
  })
}

export function useCompareRuns(runA: string, runB: string) {
  return useQuery({
    queryKey: ['delta-compare', runA, runB],
    queryFn: () =>
      apiFetch<DeltaResult>(`/delta/compare?run_a=${runA}&run_b=${runB}`),
    enabled: !!runA && !!runB,
  })
}

export function useBackfillFingerprints() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<{ updated: Record<string, number>; total: number }>('/delta/backfill-fingerprints', { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dedup-report'] }),
  })
}

export function useDedupReport() {
  return useQuery({
    queryKey: ['dedup-report'],
    queryFn: () =>
      apiFetch<{ duplicates: DedupEntry[]; total: number }>('/delta/dedup-report'),
  })
}
