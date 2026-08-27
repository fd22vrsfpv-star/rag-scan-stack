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
  // Artifact LLM Review agent
  queue_pending?: number
  queue_processing?: number
  queue_done?: number
  queue_failed?: number
  queue_total?: number
  // Pre-Validation agent
  sessions_validated?: number
  unsupported_claims?: number
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

export interface DrainResult {
  ok: boolean
  claimed?: number
  done?: number
  parked?: number
  requeued_stale?: number
  model?: string
  queue_depth?: Record<string, unknown>
}

export function useDrainArtifacts() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (limit: number = 20) =>
      apiFetch<DrainResult>('/artifacts/drain', {
        method: 'POST',
        body: JSON.stringify({ limit }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents-status'] })
      qc.invalidateQueries({ queryKey: ['artifacts'] })
      qc.invalidateQueries({ queryKey: ['artifact-stats'] })
    },
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

// ── Review queues (agent flags + learned extractors) ──────────────────────
// The dashboard identifies its actions as 'dashboard' for the audit trail; the
// backend stamps acted_by/reviewed_by and emits an *_reviewed webhook event.
const ACTOR_HEADER = { 'X-Operator': 'dashboard' }

export interface AgentFlag {
  id: string
  flagging_agent: string
  target_agent?: string | null
  engagement_id?: string | null
  flag_type: string
  data: Record<string, any>
  status: 'pending' | 'acknowledged' | 'acted' | 'dismissed'
  acted_by?: string | null
  created_at: string
  acted_at?: string | null
}

export function useAgentFlags(status?: string) {
  const params = status ? `?status=${status}` : ''
  return useQuery({
    queryKey: ['agent-flags', status ?? 'all'],
    queryFn: () => apiFetch<{ count: number; flags: AgentFlag[] }>(`/agent-flags${params}`),
    refetchInterval: POLL.NORMAL,
  })
}

export function useActAgentFlag() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'approve' | 'dismiss' }) =>
      apiFetch<{ ok: boolean; status?: string; reason?: string }>(
        `/agent-flags/${id}/${action}`, { method: 'POST', headers: ACTOR_HEADER }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-flags'] })
      qc.invalidateQueries({ queryKey: ['agents-status'] })
    },
  })
}

export interface LearnedExtractor {
  id: string
  tool: string
  kind: 'deterministic' | 'notable' | 'follow_on'
  rule: Record<string, any>
  status: 'active' | 'proposed' | 'rejected'
  confidence?: number | null
  source: string
  reviewed_by?: string | null
  created_at: string
  approved_at?: string | null
}

export function useLearnedExtractors(status?: string) {
  const params = status ? `?status=${status}` : ''
  return useQuery({
    queryKey: ['extractors-learned', status ?? 'all'],
    queryFn: () => apiFetch<{ count: number; learned: LearnedExtractor[] }>(`/extractors/learned${params}`),
    refetchInterval: POLL.SLOW,
  })
}

export function useReviewExtractor() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'approve' | 'reject' }) =>
      apiFetch<{ ok: boolean; status: string }>(
        `/extractors/learned/${id}/${action}`, { method: 'POST', headers: ACTOR_HEADER }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['extractors-learned'] }),
  })
}

export function useExportExtractors() {
  return useMutation({
    mutationFn: (tool?: string) =>
      apiFetch<{ ok: boolean; tools: string[]; yaml: Record<string, string> }>(
        `/extractors/export${tool ? `?tool=${tool}` : ''}`, { method: 'POST' }),
  })
}

// ── Extract & Learn (analyze one artifact / scan raw output) ──────────────
export interface ExtractorFocusResult {
  requested: string
  found: boolean
  field?: string
  value?: unknown
  learned?: boolean
  already_covered?: boolean
  error?: string
}
export interface ExtractorLearnResult {
  tool: string
  learned: string[]
  proposed_notable: string[]
  skipped: string[]
  focus?: ExtractorFocusResult | null
  coverage?: { coverage_pct: number; residual_lines: number; residual_sample: string[] }
}
export interface ExtractorAnalyze {
  ok: boolean
  tool: string
  has_profile: boolean
  source_file?: string | null
  schema: string[]
  deterministic: Record<string, unknown>
  coverage?: { coverage_pct: number; residual_lines: number; residual_sample: string[] } | null
  learn?: ExtractorLearnResult
}
export interface AnalyzeRequest {
  artifact_id?: string
  tool?: string
  output?: string
  focus?: string
  learn?: boolean
  model?: string
}

/** Preview extraction (learn=false) or send to the LLM to distil rules
 *  (learn=true). On a learn run, refresh the learned-rules review queue. */
export function useAnalyzeExtractor() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (req: AnalyzeRequest) =>
      apiFetch<ExtractorAnalyze>('/extractors/analyze', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      }),
    onSuccess: (_data, vars) => {
      if (vars.learn) qc.invalidateQueries({ queryKey: ['extractors-learned'] })
    },
  })
}
