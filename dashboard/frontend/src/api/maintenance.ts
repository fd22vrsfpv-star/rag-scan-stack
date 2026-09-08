import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiUrl } from './client'
import { useUIStore } from '@/stores/ui'
import { POLL } from '@/lib/polling'

export type MaintenanceStats = Record<string, number>

export function useMaintenanceStats() {
  return useQuery({
    queryKey: ['maintenance-stats'],
    queryFn: () => apiFetch<MaintenanceStats>('/maintenance/stats'),
    refetchInterval: POLL.BACKGROUND,
  })
}

interface CleanupParams {
  category: string
  older_than_hours?: number
  dry_run?: boolean
  sources?: string
  status?: string
  // Category-specific. tool-executions reconciles rows stuck at 'running';
  // artifacts prunes stored raw output, keeping unprocessed and cited ones.
  stale_after_hours?: number
  older_than_days?: number
  delete_older_than_days?: number
  keep_unprocessed?: boolean
  keep_with_findings?: boolean
}

export function useCleanup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (params: CleanupParams) => {
      const qs = new URLSearchParams()
      if (params.dry_run) qs.set('dry_run', 'true')
      if (params.older_than_hours) qs.set('older_than_hours', String(params.older_than_hours))
      if (params.sources) qs.set('sources', params.sources)
      if (params.status) qs.set('status', params.status)
      if (params.stale_after_hours) qs.set('stale_after_hours', String(params.stale_after_hours))
      if (params.older_than_days) qs.set('older_than_days', String(params.older_than_days))
      if (params.delete_older_than_days) qs.set('delete_older_than_days', String(params.delete_older_than_days))
      // Booleans are sent even when false — omitting them would silently fall
      // back to the endpoint's default of keeping things, which is the opposite
      // of what an operator who unticked the box asked for.
      if (params.keep_unprocessed !== undefined) qs.set('keep_unprocessed', String(params.keep_unprocessed))
      if (params.keep_with_findings !== undefined) qs.set('keep_with_findings', String(params.keep_with_findings))
      return apiFetch<Record<string, unknown>>(
        `/maintenance/cleanup/${params.category}?${qs}`,
        { method: 'POST' },
      )
    },
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: ['maintenance-stats'] })
      // After a real delete (not dry-run), invalidate all data caches
      if (!variables.dry_run) {
        qc.invalidateQueries({ queryKey: ['findings'] })
        qc.invalidateQueries({ queryKey: ['scans'] })
        qc.invalidateQueries({ queryKey: ['jobs'] })
        qc.invalidateQueries({ queryKey: ['recon'] })
        qc.invalidateQueries({ queryKey: ['artifacts'] })
        qc.invalidateQueries({ queryKey: ['artifact-stats'] })
        qc.invalidateQueries({ queryKey: ['params'] })
        qc.invalidateQueries({ queryKey: ['dashboard'] })
        qc.invalidateQueries({ queryKey: ['exploits'] })
        qc.invalidateQueries({ queryKey: ['credentials'] })
        qc.invalidateQueries({ queryKey: ['sessions'] })
        qc.invalidateQueries({ queryKey: ['recommendations'] })
      }
    },
  })
}

// ---- Follow-up bulk update ----

export function useFollowupBulkUpdate() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { action: 'dismiss' | 'accept' | 'delete'; source_status?: string; ids?: string[] }) =>
      apiFetch<{ ok: boolean; action: string; affected: number }>('/followups/bulk-update', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['maintenance-stats'] })
      qc.invalidateQueries({ queryKey: ['followups'] })
    },
  })
}

// ---- Export estimate ----

export interface ExportEstimate {
  screenshots: { file_count: number; total_bytes: number; human: string }
  scan_results: { file_count: number; total_bytes: number; human: string }
  audit_log: { total_bytes: number; human: string; line_count: number }
}

export function useExportEstimate() {
  return useQuery({
    queryKey: ['export-estimate'],
    queryFn: () => apiFetch<ExportEstimate>('/maintenance/export/estimate'),
    staleTime: 60000,
  })
}

// ---- Audit log ----

export interface AuditLogEntry {
  timestamp: string
  event: string
  scan_type: string
  source?: string
  external_ip?: string
  targets?: string[]
  proxy?: string
  duration_s?: number
  findings_count?: number
  [key: string]: unknown
}

export interface AuditLogResponse {
  entries: AuditLogEntry[]
  total: number
}

export function useAuditLog(filters?: { limit?: number; scan_type?: string; event?: string }) {
  // Engagement-isolation: when an engagement is active, only return audit
  // entries explicitly tagged to it.  Legacy / unscoped rows are hidden by
  // the BFF filter (Phase 6), so this matches the rest of the UI.
  const eid = useUIStore(s => s.selectedEngagementId)
  const qs = new URLSearchParams()
  if (filters?.limit) qs.set('limit', String(filters.limit))
  if (filters?.scan_type) qs.set('scan_type', filters.scan_type)
  if (filters?.event) qs.set('event', filters.event)
  if (eid) qs.set('engagement_id', eid)
  const query = qs.toString()
  return useQuery({
    queryKey: ['audit-log', query],
    queryFn: () => apiFetch<AuditLogResponse>(`/maintenance/audit-log${query ? `?${query}` : ''}`),
    staleTime: 30000,
  })
}

export interface AuditLogRotateResponse {
  ok: boolean
  rotated: boolean
  archive_name?: string
  archived_lines?: number
  archived_bytes?: number
  reason?: string
}

/** Archive the active audit.jsonl into a timestamped file and start a fresh
 * empty active log.  Export-then-rotate -- never destructively deletes
 * audit data.  Invalidates the audit-log query so the table re-fetches. */
export function useRotateAuditLog() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<AuditLogRotateResponse>('/maintenance/audit-log/rotate', { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit-log'] })
      qc.invalidateQueries({ queryKey: ['maintenance-stats'] })
    },
  })
}

// ---- Export ----

interface ExportParams {
  format: string
  categories: string[]
  include_screenshots?: boolean
  include_scan_results?: boolean
  include_audit_log?: boolean
}

export function useDataExport() {
  return useMutation({
    mutationFn: async (params: ExportParams) => {
      const qs = new URLSearchParams()
      qs.set('format', params.format)
      qs.set('categories', params.categories.join(','))
      if (params.include_screenshots) qs.set('include_screenshots', 'true')
      if (params.include_scan_results) qs.set('include_scan_results', 'true')
      if (params.include_audit_log) qs.set('include_audit_log', 'true')
      const resp = await fetch(apiUrl(`/maintenance/export?${qs}`))
      if (!resp.ok) throw new Error(`Export failed: ${resp.status}`)
      return resp.blob()
    },
  })
}

// ---- Import ----

export interface ImportResult {
  ok: boolean
  inserted?: Record<string, number>
  total?: number
  // ZIP import fields
  db_import?: { ok?: boolean; inserted?: Record<string, number>; total?: number; error?: string }
  screenshots_restored?: number
  scan_results_restored?: number
  audit_entries_appended?: number
}

export function useDataImport() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (file: File) => {
      const fd = new FormData()
      fd.append('file', file)
      const resp = await fetch(apiUrl('/maintenance/import'), {
        method: 'POST',
        body: fd,
      })
      if (!resp.ok) throw new Error(`Import failed: ${resp.status}`)
      return resp.json() as Promise<ImportResult>
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['maintenance-stats'] })
    },
  })
}

// ---- Node and WireGuard Cleanup ----

export interface RemoteNode {
  id: string
  name: string
  node_type: string
  status: string
  hostname: string
  wg_assigned_ip?: string
  last_seen?: string
}

export interface WireGuardPeer {
  id: string
  name: string
  public_key: string
  assigned_ip: string
  status: string
  last_handshake?: string
}

export interface NodeAnalysis {
  total_nodes: number
  offline_nodes: RemoteNode[]
  error_nodes: RemoteNode[]
  stale_nodes: RemoteNode[]
  total_wg_peers: number
  inactive_wg_peers: WireGuardPeer[]
  duplicate_ips: RemoteNode[]
  orphaned_wg_peers: WireGuardPeer[]
  offline_count: number
  error_count: number
  stale_count: number
  inactive_wg_count: number
  duplicate_count: number
  orphaned_count: number
}

export interface CleanupOptions {
  remove_offline: boolean
  remove_error: boolean
  remove_inactive_wg: boolean
  remove_orphaned_wg: boolean
}

export interface CleanupResults {
  success: string[]
  failed: string[]
  summary: string
}

export function useNodeAnalysis() {
  return useQuery({
    queryKey: ['maintenance', 'nodes', 'analysis'],
    queryFn: () => apiFetch<NodeAnalysis>('/maintenance/nodes/analysis'),
    refetchInterval: 30000, // Refresh every 30s
  })
}

export function useNodeCleanup() {
  const qc = useQueryClient()

  return useMutation({
    mutationFn: (options: CleanupOptions) =>
      apiFetch<CleanupResults>('/maintenance/nodes/cleanup', {
        method: 'POST',
        body: JSON.stringify(options),
      }),
    onSuccess: () => {
      // Invalidate related queries to refresh data
      qc.invalidateQueries({ queryKey: ['maintenance', 'nodes'] })
      qc.invalidateQueries({ queryKey: ['nodes'] })
      qc.invalidateQueries({ queryKey: ['wg-peers'] })
    },
  })
}

// ---- Schema + knowledge repair ----
//
// Two repairs that used to require shelling into the host. The schema CHECK
// already existed server-side (rag-api GET /health/database), so this consumes
// it rather than adding a second source of truth that could disagree.

export interface SchemaCheck {
  status: string
  table_count: number
  expected_tables: number
  missing_tables: string[]
  critical_tables_present?: boolean
  timestamp?: string
}

export function useSchemaCheck() {
  return useQuery({
    queryKey: ['maintenance-schema-check'],
    queryFn: () => apiFetch<SchemaCheck>('/maintenance/schema/check'),
    refetchInterval: POLL.BACKGROUND,
  })
}

export interface SchemaApplyResult {
  ok: boolean
  detail?: string
  canonical_ddl?: string | null
  canonical_applied?: boolean
  canonical_statements_ok?: number
  canonical_statements_failed?: number
  statements_executed?: number
  tables_before?: number
  tables_after?: number
  views_before?: number
  views_after?: number
  warnings?: string[]
  error?: string
}

/** Apply the canonical DDL to create whatever the check reported missing.
 *  Idempotent, but it mutates the database -- the caller confirms first. */
export function useSchemaApply() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<SchemaApplyResult>('/maintenance/schema/apply', { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['maintenance-schema-check'] })
      qc.invalidateQueries({ queryKey: ['maintenance-stats'] })
    },
  })
}

export interface KnowledgeStatus {
  ok: boolean
  prompt_count: number
  seeded: boolean
}

export function useKnowledgeStatus() {
  return useQuery({
    queryKey: ['maintenance-knowledge-status'],
    queryFn: () => apiFetch<KnowledgeStatus>('/maintenance/knowledge/status'),
    refetchInterval: POLL.BACKGROUND,
  })
}

export interface KnowledgeSeedResult {
  ok: boolean
  created: number
  updated: number
  docs: number
  failed: number
  dry_run: boolean
  files: { file: string; created: number; updated: number; docs: number; failed: number }[]
  errors: string[]
}

/** What POST /seed returns for a REAL seed: a job, not a result.
 *
 *  The bundled corpus is ~585 embedding round-trips (~14 min), so the seed runs
 *  in the background. A dry run still answers inline with a KnowledgeSeedResult. */
export interface KnowledgeSeedStarted {
  ok: boolean
  job_id: string
  status: 'running'
  status_url: string
  detail: string
}

export interface KnowledgeSeedJob {
  known: boolean
  job_id?: string
  status?: 'running' | 'completed' | 'completed_with_errors' | 'failed'
  progress?: {
    file: string
    file_index: number
    files_total: number
    doc_index?: number
    docs_in_file?: number
    docs_done: number
    prompts_done: number
  } | null
  result?: KnowledgeSeedResult | null
  error?: string | null
  detail?: string
}

/** Poll one seed job. Omit jobId for the most recent. */
export function fetchKnowledgeSeedStatus(jobId?: string) {
  const q = jobId ? `?job_id=${encodeURIComponent(jobId)}` : ''
  return apiFetch<KnowledgeSeedJob>(`/maintenance/knowledge/seed/status${q}`)
}

/** Load knowledge/seed/*.yaml into service_prompts + the RAG store.
 *  Idempotent: an entry whose selector exists is updated, not duplicated.
 *  A real seed resolves to KnowledgeSeedStarted; a dry run to KnowledgeSeedResult. */
export function useKnowledgeSeed() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { dry_run?: boolean; files?: string[] } = {}) =>
      apiFetch<KnowledgeSeedResult & Partial<KnowledgeSeedStarted>>('/maintenance/knowledge/seed', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['maintenance-knowledge-status'] })
    },
  })
}

// ---- ZAP engine health ----
//
// The ZAP stage is the pipeline's slowest and its most opaque. `messages` is the
// number that predicts a hang: an unbounded session (2.2 GB / 91% of the
// container's memory was measured here) makes ZAP go selectively deaf — cheap
// views still answer while every context action blocks. `reachable: false` is a
// different state from idle and must not be shown as one.

export interface ZapStatusScan {
  id?: string
  progress?: string
  state?: string
  url?: string | null
}

export interface ZapStatus {
  reachable: boolean
  version?: string
  spider?: ZapStatusScan[]
  active_scan?: ZapStatusScan[]
  messages?: number | null
  busy?: boolean
  running_count?: number
  session_warning?: string
  idle_but_expected_busy_hint?: string | null
  error?: string
  detail?: string
}

export function useZapStatus() {
  return useQuery({
    queryKey: ['zap-status'],
    queryFn: () => apiFetch<ZapStatus>('/zap/status'),
    refetchInterval: POLL.BACKGROUND,
  })
}
