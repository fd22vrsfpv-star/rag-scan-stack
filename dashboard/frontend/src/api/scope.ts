import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { ScopeResponse, ScopeName } from '@/lib/types'
import { useUIStore } from '@/stores/ui'

export function useScopeNames() {
  const engagementId = useUIStore(s => s.selectedEngagementId)
  return useQuery({
    queryKey: ['scope-names', engagementId],
    queryFn: async () => {
      if (engagementId) {
        // Return scopes from the selected engagement
        const data = await apiFetch<{ scopes: { name: string; target_count: number }[] }>(
          `/engagements/${engagementId}/scopes`
        )
        return { names: data.scopes.map(s => ({ name: s.name, target_count: s.target_count })) }
      }
      // No engagement selected — return global scope list
      return apiFetch<{ names: ScopeName[] }>('/scope/names')
    },
  })
}

export function useScope(name: string) {
  const engagementId = useUIStore(s => s.selectedEngagementId)
  return useQuery({
    queryKey: ['scope', name, engagementId],
    queryFn: async () => {
      if (engagementId && name) {
        // Fetch from engagement-scoped endpoint
        return apiFetch<ScopeResponse>(
          `/engagements/${engagementId}/scopes/${encodeURIComponent(name)}`
        )
      }
      // Fallback to global scope endpoint
      return apiFetch<ScopeResponse>(`/scope?name=${encodeURIComponent(name)}`)
    },
    enabled: !!name,
    staleTime: 30000,
  })
}

export function useAddToScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { name: string; targets: { target: string; target_type: string; source: string }[] }) =>
      apiFetch<{ ok: boolean; added: number }>('/scope/add', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope-names'] })
      qc.invalidateQueries({ queryKey: ['scope'] })
    },
  })
}

export function useRemoveFromScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { name: string; targets: string[] }) =>
      apiFetch<{ ok: boolean; removed: number }>('/scope/targets', {
        method: 'DELETE',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope-names'] })
      qc.invalidateQueries({ queryKey: ['scope'] })
    },
  })
}


// ── Out-of-scope exclusion (the 'not_in_scope' list) ─────────────────────
// Lets an operator mark a target that "should not have been in scope" — e.g.
// a third-party host that got auto-classified in. Reversible via the same
// endpoint with DELETE. Independent of named scopes.

export interface ExcludedTarget {
  target: string
  source: string
  added_at: string
}

export function useExcludedTargets() {
  return useQuery({
    queryKey: ['scope-excluded'],
    queryFn: () => apiFetch<{ targets: ExcludedTarget[]; total: number }>('/scope/excluded'),
    staleTime: 30000,
  })
}

export function useExcludeFromScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { targets: string[]; source?: string }) =>
      apiFetch<{ ok: boolean; added: number; scope: string }>('/scope/exclude', {
        method: 'POST',
        body: JSON.stringify({ source: 'manual', ...body }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope-excluded'] })
      qc.invalidateQueries({ queryKey: ['scope-names'] })
      qc.invalidateQueries({ queryKey: ['scope'] })
    },
  })
}

export function useRemoveExclusion() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { targets: string[] }) =>
      apiFetch<{ ok: boolean; removed: number }>('/scope/exclude', {
        method: 'DELETE',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope-excluded'] })
      qc.invalidateQueries({ queryKey: ['scope-names'] })
      qc.invalidateQueries({ queryKey: ['scope'] })
    },
  })
}


// ── Scope Auto-Classification ───────────────────────────────────────────

export interface ScopeSuggestion {
  id: string
  target: string
  suggested_scope: string
  confidence: number
  reasoning: string
  method: string
  status: string
  created_at: string
}

export interface ScopeClassificationRule {
  id: string
  name: string
  scope_name: string
  priority: number
  enabled: boolean
  rule_type: string
  conditions: Record<string, unknown>
  auto_apply: boolean
  source?: string
}

export function useScopeSuggestions(status = 'pending') {
  return useQuery({
    queryKey: ['scope-suggestions', status],
    queryFn: () => apiFetch<{ suggestions: ScopeSuggestion[]; total: number }>(`/scope/suggestions?status=${status}`),
  })
}

export function useClassifyUnknown() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (opts?: { auto_apply_threshold?: number; limit?: number }) =>
      apiFetch<{ ok: boolean; total_processed: number; auto_assigned: number; suggested: number; unclassified: number }>(
        '/scope/classify-unknown', { method: 'POST', body: JSON.stringify(opts || {}) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope-suggestions'] })
      qc.invalidateQueries({ queryKey: ['scope'] })
      qc.invalidateQueries({ queryKey: ['scope-names'] })
    },
  })
}

export function useAcceptSuggestion() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean }>(`/scope/suggestions/${id}/accept`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope-suggestions'] })
      qc.invalidateQueries({ queryKey: ['scope'] })
      qc.invalidateQueries({ queryKey: ['scope-names'] })
    },
  })
}

export function useRejectSuggestion() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, correct_scope }: { id: string; correct_scope?: string }) =>
      apiFetch<{ ok: boolean }>(`/scope/suggestions/${id}/reject`, {
        method: 'POST', body: JSON.stringify({ correct_scope }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scope-suggestions'] }),
  })
}

export function useBulkAcceptSuggestions() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (min_confidence: number) =>
      apiFetch<{ ok: boolean; accepted: number }>('/scope/suggestions/bulk-accept', {
        method: 'POST', body: JSON.stringify({ min_confidence }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope-suggestions'] })
      qc.invalidateQueries({ queryKey: ['scope'] })
      qc.invalidateQueries({ queryKey: ['scope-names'] })
    },
  })
}

export function useScopeClassificationRules() {
  return useQuery({
    queryKey: ['scope-classification-rules'],
    queryFn: () => apiFetch<{ rules: ScopeClassificationRule[]; total: number }>('/scope/classification-rules'),
  })
}

export function useCreateClassificationRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (rule: Partial<ScopeClassificationRule>) =>
      apiFetch<{ ok: boolean; id: string }>('/scope/classification-rules', {
        method: 'POST', body: JSON.stringify(rule),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scope-classification-rules'] }),
  })
}

export function useDeleteClassificationRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean }>(`/scope/classification-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scope-classification-rules'] }),
  })
}

export function useLearnRules() {
  return useMutation({
    mutationFn: () =>
      apiFetch<{ suggested_rules: Array<Record<string, unknown>>; total: number }>('/scope/rules/learn', { method: 'POST' }),
  })
}
