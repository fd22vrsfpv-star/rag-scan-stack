import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Engagement, CampaignEvent } from '@/lib/types'
import { POLL } from '@/lib/polling'

// ── Engagements ──

export function useEngagements(status?: string) {
  const params = status ? `?status=${status}` : ''
  return useQuery({
    queryKey: ['engagements', status],
    queryFn: () => apiFetch<{ engagements: Engagement[] }>(`/engagements${params}`),
    refetchInterval: POLL.SLOW,
    staleTime: 5000,
  })
}

export function useEngagement(id?: string) {
  return useQuery({
    queryKey: ['engagement', id],
    queryFn: () => apiFetch<Engagement>(`/engagements/${id}`),
    enabled: !!id,
  })
}

export function useCreateEngagement() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Engagement>) =>
      apiFetch<Engagement>('/engagements', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['engagements'] })
      qc.invalidateQueries({ queryKey: ['engagement'] })
    },
  })
}

export function useUpdateEngagement() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<Engagement> & { id: string }) =>
      apiFetch<Engagement>(`/engagements/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['engagements'] })
      qc.invalidateQueries({ queryKey: ['engagement'] })
    },
  })
}

export function useDeleteEngagement() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/engagements/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['engagements'] })
      qc.invalidateQueries({ queryKey: ['engagement'] })
    },
  })
}

// ── Campaign Events (H1) ──

export function useCampaignEvents(engagementId?: string) {
  return useQuery({
    queryKey: ['campaign-events', engagementId],
    queryFn: () => apiFetch<{ events: CampaignEvent[] }>(
      `/engagements/${engagementId}/campaign-events`
    ),
    enabled: !!engagementId,
    refetchInterval: POLL.SLOW,
  })
}

export function useCreateCampaignEvent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ engagementId, ...data }: Partial<CampaignEvent> & { engagementId: string }) =>
      apiFetch<CampaignEvent>(`/engagements/${engagementId}/campaign-events`, {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['campaign-events'] }),
  })
}

export function useUpdateCampaignEvent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<CampaignEvent> & { id: string }) =>
      apiFetch<CampaignEvent>(`/campaign-events/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['campaign-events'] }),
  })
}

export function useCampaignSummary(engagementId?: string) {
  return useQuery({
    queryKey: ['campaign-summary', engagementId],
    queryFn: () => apiFetch<{
      phases: Record<string, { count: number; detected: number }>
      techniques: Array<{ mitre_technique: string; mitre_tactic: string; cnt: number }>
    }>(`/engagements/${engagementId}/campaign-summary`),
    enabled: !!engagementId,
  })
}


// ── Engagement-Scoped Scopes ────────────────────────────────────────────

export interface EngagementScope {
  name: string
  target_count: number
  last_updated?: string
}

export interface ScopeTarget {
  id: string
  name: string
  target: string
  target_type: string
  source: string
  engagement_id: string
  added_at?: string
}

export function useEngagementScopes(eid: string | undefined) {
  return useQuery({
    queryKey: ['engagement-scopes', eid],
    queryFn: () => apiFetch<{ scopes: EngagementScope[] }>(`/engagements/${eid}/scopes`),
    enabled: !!eid,
    refetchInterval: POLL.NORMAL,
  })
}

export function useEngagementScopeTargets(eid: string | undefined, scopeName: string | undefined) {
  return useQuery({
    queryKey: ['engagement-scope-targets', eid, scopeName],
    queryFn: () => apiFetch<{ name: string; engagement_id: string; total: number; targets: ScopeTarget[] }>(
      `/engagements/${eid}/scopes/${encodeURIComponent(scopeName!)}`
    ),
    enabled: !!eid && !!scopeName,
    refetchInterval: POLL.NORMAL,
  })
}

export function useAddScopeTargets() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ eid, scopeName, targets, source }: { eid: string; scopeName: string; targets: string[]; source?: string }) =>
      apiFetch(`/engagements/${eid}/scopes/${encodeURIComponent(scopeName)}/targets`, {
        method: 'POST', body: JSON.stringify({ targets, source: source || 'manual' }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['engagement-scopes'] })
      qc.invalidateQueries({ queryKey: ['engagement-scope-targets'] })
    },
  })
}

export function useDeleteScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ eid, scopeName }: { eid: string; scopeName: string }) =>
      apiFetch(`/engagements/${eid}/scopes/${encodeURIComponent(scopeName)}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement-scopes'] }),
  })
}

export function useRenameScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ eid, scopeName, newName }: { eid: string; scopeName: string; newName: string }) =>
      apiFetch(`/engagements/${eid}/scopes/${encodeURIComponent(scopeName)}`, {
        method: 'PUT', body: JSON.stringify({ new_name: newName }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['engagement-scopes'] })
      qc.invalidateQueries({ queryKey: ['engagement-scope-targets'] })
    },
  })
}

export function useMoveTargets() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ eid, scopeName, targets, toEngagementId, toScopeName }: {
      eid: string; scopeName: string; targets: string[]; toEngagementId: string; toScopeName: string
    }) =>
      apiFetch(`/engagements/${eid}/scopes/${encodeURIComponent(scopeName)}/move`, {
        method: 'POST',
        body: JSON.stringify({ targets, to_engagement_id: toEngagementId, to_scope_name: toScopeName }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['engagement-scopes'] })
      qc.invalidateQueries({ queryKey: ['engagement-scope-targets'] })
    },
  })
}

export function useMoveEntireScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ eid, scopeName, toEngagementId }: { eid: string; scopeName: string; toEngagementId: string }) =>
      apiFetch(`/engagements/${eid}/scopes/${encodeURIComponent(scopeName)}/move-all`, {
        method: 'POST',
        body: JSON.stringify({ to_engagement_id: toEngagementId }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['engagement-scopes'] })
      qc.invalidateQueries({ queryKey: ['engagements'] })
    },
  })
}
