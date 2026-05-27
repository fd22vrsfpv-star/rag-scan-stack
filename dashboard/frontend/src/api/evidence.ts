import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Evidence } from '@/lib/types'
import { POLL } from '@/lib/polling'

const BASE = '/api'

export function useEvidence(filters: { engagement_id?: string; evidence_type?: string; tags?: string } = {}) {
  const params = new URLSearchParams()
  if (filters.engagement_id) params.set('engagement_id', filters.engagement_id)
  if (filters.evidence_type) params.set('evidence_type', filters.evidence_type)
  if (filters.tags) params.set('tags', filters.tags)
  return useQuery({
    queryKey: ['evidence', filters],
    queryFn: () => apiFetch<{ evidence: Evidence[] }>(`/evidence?${params}`),
    refetchInterval: POLL.SLOW,
  })
}

export function useUploadEvidence() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (data: {
      file: File
      title: string
      evidence_type: string
      engagement_id?: string
      description?: string
      uploaded_by?: string
      tags?: string
    }) => {
      const params = new URLSearchParams({ title: data.title, evidence_type: data.evidence_type })
      if (data.engagement_id) params.set('engagement_id', data.engagement_id)
      if (data.description) params.set('description', data.description)
      if (data.uploaded_by) params.set('uploaded_by', data.uploaded_by)
      if (data.tags) params.set('tags', data.tags)
      const form = new FormData()
      form.append('file', data.file)
      const resp = await fetch(`${BASE}/evidence/upload?${params}`, { method: 'POST', body: form })
      if (!resp.ok) throw new Error(`Upload failed: ${resp.status}`)
      return resp.json()
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['evidence'] })
      qc.invalidateQueries({ queryKey: ['finding-evidence'] })
    },
  })
}

export function useLinkEvidence() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ evidenceId, entityType, entityId }: {
      evidenceId: string; entityType: string; entityId: string
    }) => apiFetch(`/evidence/${evidenceId}/link?entity_type=${entityType}&entity_id=${entityId}`, {
      method: 'POST',
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['finding-evidence'] }),
  })
}

export function useFindingEvidence(source?: string, findingId?: string) {
  return useQuery({
    queryKey: ['finding-evidence', source, findingId],
    queryFn: () => apiFetch<{ evidence: Evidence[] }>(`/findings/${source}/${findingId}/evidence`),
    enabled: !!source && !!findingId,
  })
}

export function useDeleteEvidence() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiFetch(`/evidence/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['evidence'] }),
  })
}
