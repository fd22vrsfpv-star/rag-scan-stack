import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

/**
 * Raw scan output — the complete, untruncated bytes a tool produced.
 *
 * Findings are a lossy derivative of this (8 KB of evidence each, structure
 * inferred from text). These are the originals, kept so results can be read as
 * the tool actually reported them and post-processed later.
 */
export interface Artifact {
  id: string
  tool: string
  command: string | null
  target: string | null
  port: number | null
  service: string | null
  exec_id: string | null
  job_id: string | null
  scan_id: string | null
  source: string
  /** Operator label for a manually uploaded artifact ("what is this"). */
  note?: string | null
  content_format: string
  native_json: boolean
  content_sha256: string
  byte_size: number
  first_seen: string
  last_seen: string
  occurrences: number
  llm_status: string
  llm_model: string | null
  llm_processed_at: string | null
  llm_attempts: number
  llm_error: string | null
  llm_result?: Record<string, unknown> | null
  created_at: string
  /** Present only on the single-artifact fetch. */
  content?: string
  // ── Per-artifact analysis summary (list endpoint only) ──
  /** Findings this run produced (linked by job_id). */
  finding_count?: number | null
  /** Distinct targets across those findings — 1 for a single-host tool. */
  finding_targets?: number | null
  /** The one target, when finding_targets === 1. */
  finding_target_sample?: string | null
  /** Host parsed from the output when no finding target exists (e.g. the host a
   *  failed crawl attempted). */
  attempted_host?: string | null
  /** { info: 40, high: 1, … } */
  severity_counts?: Record<string, number> | null
  /** Command outcome, distinct from the LLM review status (llm_status). */
  outcome?: 'ok' | 'empty' | 'error' | null
  /** True when the output/review carries a failure signature. */
  cmd_error?: boolean | null
}

export interface ArtifactList {
  total: number
  limit: number
  offset: number
  artifacts: Artifact[]
}

export interface ArtifactStats {
  by_status: Record<string, { count: number; bytes: number }>
  total: number
  total_bytes: number
  distinct_tools: number
}

/** A follow-on action derived from an artifact's content. */
export interface ArtifactAction {
  id: string
  category: string
  title: string
  scanner: string
  script: string
  rationale: string
  priority: number
  /** The exact line from the raw output that triggered this suggestion. */
  evidence: string
  /** Command still contains placeholders, or the suggestion has no runnable form.
   *  These cannot be queued as-is — supply an edited script instead. */
  needs_input: boolean
  /** Rule opted into being queued automatically when matching output is stored.
   *  Auto-queued actions are still only ever queued, never executed. */
  auto_queue: boolean
  source: 'rules' | 'llm'
  already_run: {
    ran: boolean
    count: number
    tool_ran_count?: number
    last_exec_id?: string
    last_status?: string
    last_at?: string | null
  }
  queued_status: string | null
}

export interface ArtifactActions {
  artifact_id: string
  tool: string
  target: string | null
  content_format: string
  native_json: boolean
  llm_status: string
  actions: ArtifactAction[]
  counts: { total: number; already_run: number; queued: number; needs_input: number }
}

export interface ArtifactFilters {
  llm_status?: string
  tool?: string
  target?: string
  source?: string
  content_format?: string
  limit?: number
  offset?: number
}

export function useArtifacts(filters: ArtifactFilters = {}) {
  const params = new URLSearchParams()
  Object.entries(filters).forEach(([k, v]) => {
    if (v !== undefined && v !== '' && v !== null) params.set(k, String(v))
  })
  const qs = params.toString()
  return useQuery({
    queryKey: ['artifacts', filters],
    queryFn: () => apiFetch<ArtifactList>(`/artifacts${qs ? `?${qs}` : ''}`),
    refetchInterval: POLL.NORMAL,
  })
}

export function useArtifactStats() {
  return useQuery({
    queryKey: ['artifact-stats'],
    queryFn: () => apiFetch<ArtifactStats>('/artifacts/stats'),
    refetchInterval: POLL.NORMAL,
  })
}

/** Full content for one artifact. Only fetched when a row is opened — these
 *  payloads are whole tool outputs and can be megabytes. */
export function useArtifact(id: string | null) {
  return useQuery({
    queryKey: ['artifact', id],
    queryFn: () => apiFetch<Artifact>(`/artifacts/${id}`),
    enabled: !!id,
  })
}

export interface UploadArtifactPayload {
  tool: string
  content: string
  target?: string
  note?: string
  command?: string
}
export interface UploadArtifactResult {
  ok: boolean
  artifact_id: string
  inserted: boolean
  occurrences: number
  content_format: string
}

/** Upload a scan output file for analysis. The file text is read client-side and
 *  stored as a raw artifact (source='manual-upload') that then behaves like any
 *  other — Extract & Learn, drain, follow-on actions. */
export function useUploadArtifact() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: UploadArtifactPayload) =>
      apiFetch<UploadArtifactResult>('/ingest/raw-artifact', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['artifacts'] })
      qc.invalidateQueries({ queryKey: ['artifact-stats'] })
    },
  })
}

export function useArtifactActions(id: string | null) {
  return useQuery({
    queryKey: ['artifact-actions', id],
    queryFn: () => apiFetch<ArtifactActions>(`/artifacts/${id}/actions`),
    enabled: !!id,
  })
}

export interface CustomAction {
  title: string
  scanner: string
  script: string
  priority?: number
  rationale?: string
}

export interface QueuePayload {
  action_ids?: string[]
  /** action_id -> edited command / priority. The only way to queue a
   *  needs_input action: its placeholders must be filled in first. */
  overrides?: Record<string, { script?: string; priority?: number }>
  custom_actions?: CustomAction[]
}

export function useQueueActions(id: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: QueuePayload) =>
      apiFetch<{ ok: boolean; queued: Array<{ recommendation_id: string; action_id: string }>; unknown_action_ids: string[] }>(
        `/artifacts/${id}/actions/queue`,
        { method: 'POST', body: JSON.stringify(payload) },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['artifact-actions', id] })
      // Queued actions land on the Recommendations page, so refresh it too.
      qc.invalidateQueries({ queryKey: ['scan-recommendations'] })
    },
  })
}

export function useMarkProcessed(id: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { llm_status: string; llm_model?: string; llm_error?: string }) =>
      apiFetch<{ ok: boolean }>(`/artifacts/${id}/processed`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['artifacts'] })
      qc.invalidateQueries({ queryKey: ['artifact', id] })
      qc.invalidateQueries({ queryKey: ['artifact-stats'] })
    },
  })
}

/** Human-readable byte size for the list view. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}


export interface AutoQueueSetting {
  enabled: boolean
  auto_queue_rules: string[]
  rules_loaded: number
  /** A broken rule file silently disables every suggestion — surface it. */
  rule_errors: string[]
}

export function useAutoQueueSetting() {
  return useQuery({
    queryKey: ['artifact-auto-queue'],
    queryFn: () => apiFetch<AutoQueueSetting>('/artifacts/auto-queue'),
  })
}

export function useSetAutoQueue() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) =>
      apiFetch<{ ok: boolean; enabled: boolean }>('/artifacts/auto-queue', {
        method: 'POST',
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['artifact-auto-queue'] }),
  })
}
