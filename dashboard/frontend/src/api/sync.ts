import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

export interface SyncNode {
  node_id: string
  node_name: string
  owner: string | null
  created_at: string
  last_sync: string | null
  is_remote: boolean
}

export interface SyncState {
  node_id: string
  direction: string
  last_lsn: number
  last_sync_at: string
}

export interface SyncStatus {
  node_id: string
  pending_push: number
  pending_conflicts: number
  total_log_entries: number
  max_lsn: number
  last_push_lsn: number
  changes_by_table: { table_name: string; operation: string; cnt: number }[]
}

export interface SyncConflict {
  id: string
  table_name: string
  row_id: string
  local_data: unknown
  remote_data: unknown
  local_changed_at: string
  remote_changed_at: string
  resolution: string
  resolved_at: string | null
  resolved_by: string | null
  created_at: string
}

export interface SyncChange {
  lsn: number
  table_name: string
  row_id: string
  operation: string
  node_id: string
  changed_by: string
  changed_at: string
  row_data: unknown
  old_data: unknown
}

export function useSyncNodes() {
  return useQuery({
    queryKey: ['sync-nodes'],
    queryFn: () => apiFetch<{ nodes: SyncNode[]; states: SyncState[] }>('/sync/nodes'),
  })
}

export function useSyncStatus(nodeId: string) {
  return useQuery({
    queryKey: ['sync-status', nodeId],
    queryFn: () => apiFetch<SyncStatus>(`/sync/status?node_id=${nodeId}`),
    refetchInterval: POLL.FAST,
  })
}

export function useSyncConflicts(status = 'pending') {
  return useQuery({
    queryKey: ['sync-conflicts', status],
    queryFn: () => apiFetch<{ conflicts: SyncConflict[]; count: number }>(`/sync/conflicts?status=${status}`),
  })
}

export function useSyncChanges(sinceLsn: number, limit = 100) {
  return useQuery({
    queryKey: ['sync-changes', sinceLsn, limit],
    queryFn: () =>
      apiFetch<{ changes: SyncChange[]; count: number; has_more: boolean }>(
        `/sync/changes?since_lsn=${sinceLsn}&limit=${limit}`
      ),
    enabled: sinceLsn >= 0,
  })
}

export function useRegisterNode() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: { node_id: string; node_name: string; owner?: string }) => {
      const qs = new URLSearchParams({ node_id: params.node_id, node_name: params.node_name })
      if (params.owner) qs.set('owner', params.owner)
      return apiFetch<{ node: SyncNode }>(`/sync/register-node?${qs}`, { method: 'POST' })
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sync-nodes'] }),
  })
}

export function usePushChanges() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ count: number; max_lsn: number }>(`/sync/push?node_id=${nodeId}`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-status'] })
      qc.invalidateQueries({ queryKey: ['sync-nodes'] })
    },
  })
}

export function usePushToRemote() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: { nodeId: string; strategy?: string }) =>
      apiFetch<{ ok: boolean; message?: string; error?: string; pushed?: number }>(
        `/sync/push-to-remote?node_id=${params.nodeId}&strategy=${params.strategy || 'last_write_wins'}`,
        { method: 'POST' }
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-status'] })
      qc.invalidateQueries({ queryKey: ['sync-nodes'] })
    },
  })
}

export function useSyncSchema() {
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; message?: string; error?: string; tables_before?: number; tables_after?: number; tables_added?: number }>(
        '/sync/sync-schema',
        { method: 'POST' }
      ),
  })
}

export function useResetWatermark() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ ok: boolean; message?: string; error?: string; max_lsn?: number; skipped?: number }>(
        `/sync/reset-watermark?node_id=${nodeId}`,
        { method: 'POST' }
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-status'] })
    },
  })
}

export function useApplyChanges() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: { nodeId: string; changes: SyncChange[]; strategy?: string }) =>
      apiFetch<{ applied: number; conflicts: number; skipped: number }>(
        `/sync/apply?node_id=${params.nodeId}&strategy=${params.strategy || 'last_write_wins'}`,
        { method: 'POST', body: JSON.stringify({ changes: params.changes }), headers: { 'Content-Type': 'application/json' } }
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-status'] })
      qc.invalidateQueries({ queryKey: ['sync-conflicts'] })
    },
  })
}

export function useResolveConflict() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: { conflictId: string; resolution: 'local_wins' | 'remote_wins'; resolvedBy?: string }) =>
      apiFetch(`/sync/conflicts/${params.conflictId}?resolution=${params.resolution}&resolved_by=${params.resolvedBy || 'user'}`, {
        method: 'PATCH',
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sync-conflicts'] }),
  })
}

export function useCreateSnapshot() {
  return useMutation({
    mutationFn: (params: { nodeId: string; tables?: string }) => {
      const qs = new URLSearchParams({ node_id: params.nodeId })
      if (params.tables) qs.set('tables', params.tables)
      return apiFetch<{ total_rows: number; max_lsn: number }>(`/sync/snapshot?${qs}`, { method: 'POST' })
    },
  })
}
