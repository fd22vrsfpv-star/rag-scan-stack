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
