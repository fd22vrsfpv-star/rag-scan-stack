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

// ── Post-execution review (post_review_agent) ─────────────────────────────
//
// Classifies executed work and finds results that were captured but never
// interpreted. It proposes and never dispatches: re-runs land as PENDING
// recommendations a human still has to run, and every proposed target passes
// the scope gate first.

export interface PostReviewFact {
  id: string
  tool: string
  target: string
  severity: string
  title: string
  detail?: string | null
  seen_in?: number
}

export interface PostReviewSummary {
  executions_reviewed: number
  actionable: number
  correct_but_empty: number
  results_not_ingested: number
  notable_facts_in_output: number
  notable_facts_stored: number
  notable_facts_unstored: number
  high_or_worse_unstored: number
  stuck_recommendations: number
  reruns_proposed: number
  reruns_queued: number
  scope_refusals: number
}

export interface PostReviewReport {
  ok: boolean
  report_id: string
  summary: PostReviewSummary
  notable_in_output: PostReviewFact[]
  executions: { groups: Array<{ category: string; remedy: string; actionable: boolean; why: string; count: number; tools: Array<{ tool: string; count: number }> }> }
  reruns: { proposed: number; inserted: number; refused: number; dry_run: boolean }
}

export function useRunPostReview() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ queueReruns = false }: { queueReruns?: boolean } = {}) =>
      apiFetch<PostReviewReport>(
        `/agent/post-review?queue_reruns=${queueReruns}`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['post-review-reports'] }),
  })
}

/** Defaults to a dry run, matching the API. This writes findings that appear in
 *  reports and exports, so the default must not be the destructive one. */
export function useIngestPostReviewFacts() {
  return useMutation({
    mutationFn: ({ dryRun = true }: { dryRun?: boolean } = {}) =>
      apiFetch<{ ok: boolean; facts_found: number; new: number; inserted: number
                 already_stored: number; by_severity: Record<string, number> }>(
        `/agent/post-review/ingest-facts?dry_run=${dryRun}`, { method: 'POST' }),
  })
}

// ── Learned tool selection (tool_selection_learned) ───────────────────────
//
// Rules the platform derived from what tools actually did — nobody typed them.
// The operator's job here is correction, not authoring. Rejecting one is
// permanent: new evidence does not reinstate it.
//
// These rules decide which authorised tool is tried FIRST, never whether
// something may run. Approving one grants no permission.

export interface ToolSelectionRule {
  id: string
  phase: string
  service: string
  failed_tool: string
  failure_signature: string
  preferred_tool: string
  failure_phrase?: string | null
  support: number
  attempts: number
  successes: number
  confidence?: number | null
  status: 'active' | 'proposed' | 'rejected'
  source: string
  reviewed_by?: string | null
  created_at: string
  last_seen_at: string
}

export interface ToolAttempt {
  id: string
  phase: string
  tool: string
  service: string
  target?: string | null
  port?: number | null
  success: boolean
  result_count: number
  failure_signature?: string | null
  failure_phrase?: string | null
  chosen_because?: string | null
  created_at: string
}

export function useToolSelectionRules(status?: string) {
  const params = status ? `?status=${status}` : ''
  return useQuery({
    queryKey: ['tool-selection-learned', status ?? 'all'],
    queryFn: () => apiFetch<{
      count: number
      by_status: Record<string, number>
      learned: ToolSelectionRule[]
    }>(`/tool-selection/learned${params}`),
    refetchInterval: POLL.SLOW,
  })
}

/** The observations behind one rule. Only fetched once a row is expanded — a
 *  rule nobody opened does not need its evidence loaded. */
export function useToolAttempts(signature?: string) {
  return useQuery({
    queryKey: ['tool-selection-attempts', signature ?? 'none'],
    queryFn: () => apiFetch<{ count: number; attempts: ToolAttempt[] }>(
      `/tool-selection/attempts?signature=${encodeURIComponent(signature!)}&limit=25`),
    enabled: !!signature,
  })
}

export function useReviewToolSelectionRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'approve' | 'reject' | 'reset' }) =>
      apiFetch<{ ok: boolean; status: string }>(
        `/tool-selection/learned/${id}/${action}`, { method: 'POST', headers: ACTOR_HEADER }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tool-selection-learned'] }),
  })
}

export function useBackfillToolSelection() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { reset?: boolean; since_hours?: number } = {}) =>
      apiFetch<{ ok: boolean; examined: number; failures: number; fruitless: number; rules: number; cleared: number }>(
        '/tool-selection/backfill', {
          method: 'POST', headers: { 'Content-Type': 'application/json', ...ACTOR_HEADER },
          body: JSON.stringify(body),
        }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tool-selection-learned'] }),
  })
}

// ── Agent activity timeline (webhook event-log) ───────────────────────────
export interface AgentActivityEvent {
  id: string
  event_type: string
  payload: Record<string, any>
  status: string
  created_at: string
}

/** Cross-agent action timeline — every agent action emits an event. */
export function useAgentActivity(eventType?: string) {
  const qs = new URLSearchParams({ limit: '120' })
  if (eventType) qs.set('event_type', eventType)
  return useQuery({
    queryKey: ['agent-activity', eventType ?? 'all'],
    queryFn: () => apiFetch<{ events: AgentActivityEvent[]; total: number }>(`/agent-activity?${qs.toString()}`),
    refetchInterval: POLL.NORMAL,
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
