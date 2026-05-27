import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

// ── Types ─────────────────────────────────────────────────────────────

export interface AgentInfo {
  id: string
  name: string
  type: 'session' | 'continuous' | 'on-demand'
  status: 'running' | 'idle' | 'error' | 'unreachable'
  description: string
  last_run?: string | null
  active_sessions?: number
  findings_created?: number
  service_port?: number
  coverage_total?: number
  coverage_completed?: number
  coverage_pending?: number
  coverage_running?: number
  enabled_engagements?: number
  last_dispatch?: string | null
  gaps_found?: number | null
}

export interface GapRecommendation {
  category: string
  category_label: string
  target: string
  scan_type: string
  passive: boolean
  priority: number
  reason: string
}

export interface GapReportSummary {
  total_targets: number
  total_gaps: number
  avg_coverage_pct: number
  passive_recommendations: number
  active_recommendations: number
}

export interface GapTargetDetail {
  target_type: string
  categories: Record<string, {
    label: string
    has_data: boolean
    finding_count: number
    sources_found: string[]
  }>
  present: number
  applicable: number
  missing: number
  coverage_pct: number
}

export interface GapReport {
  id: string
  engagement_id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  report: {
    targets?: Record<string, GapTargetDetail>
    total_gaps?: number
    summary?: GapReportSummary
    message?: string
  }
  gaps_found: number
  scans_dispatched: number
  recommendations: GapRecommendation[]
  created_at: string
  completed_at: string | null
  triggered_by: string
}

// ── Hooks ─────────────────────────────────────────────────────────────

export function useAgentsStatus() {
  return useQuery({
    queryKey: ['agents-status'],
    queryFn: () => apiFetch<{ agents: AgentInfo[] }>('/agents/status'),
    refetchInterval: POLL.NORMAL,
    placeholderData: (prev) => prev as any,
  })
}

export function useGapReport(engagementId: string | null) {
  return useQuery({
    queryKey: ['gap-report', engagementId],
    queryFn: () => apiFetch<{ report: GapReport | null }>(`/gap-analysis/${engagementId}`),
    enabled: !!engagementId,
    refetchInterval: POLL.NORMAL,
    placeholderData: (prev) => prev as any,
  })
}

export function useGapHistory(engagementId: string | null) {
  return useQuery({
    queryKey: ['gap-history', engagementId],
    queryFn: () => apiFetch<{ reports: GapReport[] }>(`/gap-analysis/${engagementId}?all=true`),
    enabled: !!engagementId,
  })
}

export function useTriggerGapAnalysis() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (engagementId: string) =>
      apiFetch<{ ok: boolean; message: string }>(`/gap-analysis/${engagementId}`, { method: 'POST' }),
    onSuccess: (_d, eid) => {
      qc.invalidateQueries({ queryKey: ['gap-report', eid] })
      qc.invalidateQueries({ queryKey: ['agents-status'] })
    },
  })
}

export function useAutoFillGaps() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ engagementId, reportId }: { engagementId: string; reportId?: string }) =>
      apiFetch<{ ok: boolean; scans_dispatched?: number }>(
        `/gap-analysis/${engagementId}/auto-fill${reportId ? `?report_id=${reportId}` : ''}`,
        { method: 'POST' },
      ),
    onSuccess: (_d, vars) => {
      qc.invalidateQueries({ queryKey: ['gap-report', vars.engagementId] })
    },
  })
}


// ── Gap Schedule ──────────────────────────────────────────────────────

export interface GapSchedule {
  enabled: boolean
  interval_minutes: number
  auto_fill: boolean
}

export function useGapSchedule(engagementId: string | null) {
  return useQuery({
    queryKey: ['gap-schedule', engagementId],
    queryFn: () => apiFetch<{ schedule: GapSchedule }>(`/gap-analysis/${engagementId}/schedule`),
    enabled: !!engagementId,
  })
}

export function useSetGapSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ engagementId, ...body }: { engagementId: string; enabled: boolean; interval_minutes: number; auto_fill: boolean }) =>
      apiFetch<{ ok: boolean }>(`/gap-analysis/${engagementId}/schedule`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: (_d, vars) => {
      qc.invalidateQueries({ queryKey: ['gap-schedule', vars.engagementId] })
      qc.invalidateQueries({ queryKey: ['agents-status'] })
    },
  })
}

// ── Model Performance Warning ──────────────────────────────────────────

export interface ModelPerformanceWarning {
  has_warnings: boolean
  current_model: string
  is_slow_model: boolean
  estimated_memory_gb: number
  warnings: string[]
  recommendations: string[]
  severity: 'info' | 'warning' | 'error'
  gpu_memory_usage?: number
  gpu_memory_total?: number
}

export function useModelPerformanceWarning() {
  return useQuery({
    queryKey: ['model-performance-warning'],
    queryFn: () => apiFetch<ModelPerformanceWarning>('/model/performance-warning'),
    staleTime: 30000, // Cache for 30s to avoid repeated calls
  })
}
