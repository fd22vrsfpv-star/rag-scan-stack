import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

export interface FollowUpItem {
  id: string
  finding_source: string | null
  finding_id: string | null
  title: string
  target: string | null
  severity: string
  reason: string | null
  status: string
  priority: string
  assigned_to: string | null
  flagged_by: string
  rule_id: string | null
  confidence: number | null
  tags: string[]
  notes: string | null
  engagement_id: string | null
  resolved_at: string | null
  created_at: string
  updated_at: string
  metadata?: {
    product?: string
    version?: string
    cve_ids?: string[]
    refs?: Array<{ label: string; url: string; type: string }>
    software_link?: string
    source?: string
  }
}

export interface FollowUpStats {
  open: number
  in_progress: number
  resolved: number
  dismissed: number
  critical: number
  high: number
  medium_pri: number
  low_pri: number
  manual: number
  agent: number
  rule_flagged: number
  total: number
}

export interface AgentRule {
  id: string
  name: string
  type: string
  severity: string
  confidence: number
  description: string
  enabled: boolean
  finding_source: string
  source: string  // builtin | custom | adhoc
}

export interface RuleTestResult {
  ok: boolean
  rule_id: string
  matches: number
  results: Array<{
    rule_id: string
    title: string
    target: string
    severity: string
    reason: string
    finding_source: string
    finding_id: string
    confidence: number
  }>
  dry_run: boolean
}

export interface AgentStats {
  total_flagged: number
  dismissed: number
  accepted: number
  feedback_count: number
  accuracy: number | null
}

// ── Follow-Up Hooks ──

export function useFollowUps(filters: {
  status?: string
  exclude_status?: string
  severity?: string
  priority?: string
  flagged_by?: string
  engagement_id?: string
  rule_id?: string
  search?: string
} = {}) {
  const params = new URLSearchParams()
  if (filters.status) params.set('status', filters.status)
  if (filters.exclude_status) params.set('exclude_status', filters.exclude_status)
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.priority) params.set('priority', filters.priority)
  if (filters.flagged_by) params.set('flagged_by', filters.flagged_by)
  if (filters.engagement_id) params.set('engagement_id', filters.engagement_id)
  if (filters.rule_id) params.set('rule_id', filters.rule_id)
  if (filters.search) params.set('search', filters.search)
  return useQuery({
    queryKey: ['follow-ups', filters],
    queryFn: () => apiFetch<{ follow_ups: FollowUpItem[] }>(`/follow-ups?${params}`),
    refetchInterval: POLL.NORMAL,
    placeholderData: (prev) => prev as any,  // keep previous data while refetching
  })
}

export function useFollowUpStats(engagement_id?: string) {
  const params = new URLSearchParams()
  if (engagement_id) params.set('engagement_id', engagement_id)
  const qs = params.toString()
  return useQuery({
    queryKey: ['follow-ups', 'stats', engagement_id],
    queryFn: () => apiFetch<{ stats: FollowUpStats }>(`/follow-ups/stats${qs ? '?' + qs : ''}`),
    refetchInterval: POLL.NORMAL,
    placeholderData: (prev) => prev as any,
  })
}

export interface FollowUpGroup {
  group_key: string
  total: number
  open_count: number
  in_progress_count: number
  resolved_count: number
  dismissed_count: number
  unique_hosts?: number
  host_samples?: string[]
  finding_names?: string[]
}

export function useFollowUpGrouped(groupBy: string, status?: string, engagement_id?: string, exclude_status?: string) {
  const params = new URLSearchParams({ group_by: groupBy })
  if (status) params.set('status', status)
  if (exclude_status) params.set('exclude_status', exclude_status)
  if (engagement_id) params.set('engagement_id', engagement_id)
  return useQuery({
    queryKey: ['follow-ups', 'grouped', groupBy, status, engagement_id, exclude_status],
    queryFn: () => apiFetch<{ groups: FollowUpGroup[]; total_groups: number }>(`/follow-ups/grouped?${params}`),
    refetchInterval: POLL.NORMAL,
    placeholderData: (prev) => prev as any,
  })
}

export function useCreateFollowUp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<FollowUpItem>) =>
      apiFetch<{ ok: boolean; follow_up: FollowUpItem }>('/follow-ups', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['follow-ups'] })
    },
  })
}

export function useUpdateFollowUp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Partial<FollowUpItem>) =>
      apiFetch<{ ok: boolean; follow_up: FollowUpItem }>(`/follow-ups/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['follow-ups'] })
    },
  })
}

export function useDeleteFollowUp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/follow-ups/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['follow-ups'] })
    },
  })
}

export function useBulkUpdateFollowUps() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      ids: string[]
      action: 'dismiss' | 'accept' | 'delete' | 'update'
      status?: string
      priority?: string
      notes?: string
    }) =>
      apiFetch<{ ok: boolean; affected: number }>('/followups/bulk-update', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['follow-ups'] })
      qc.invalidateQueries({ queryKey: ['follow-ups-stats'] })
      qc.invalidateQueries({ queryKey: ['agents-status'] })
    },
  })
}

export function useSubmitFeedback() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, action, notes }: { id: string; action: string; notes?: string }) =>
      apiFetch(`/follow-ups/${id}/feedback`, {
        method: 'POST',
        body: JSON.stringify({ action, notes }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['follow-ups'] })
    },
  })
}

// ── Agent Hooks ──

export function useAgentRules() {
  return useQuery({
    queryKey: ['agent', 'rules'],
    queryFn: () => apiFetch<{ rules: AgentRule[] }>('/agent/rules'),
  })
}

export function useAgentStats() {
  return useQuery({
    queryKey: ['agent', 'stats'],
    queryFn: () => apiFetch<{ stats: AgentStats }>('/agent/stats'),
    refetchInterval: POLL.NORMAL,
  })
}

export function useAgentRule(ruleId?: string) {
  return useQuery({
    queryKey: ['agent', 'rule', ruleId],
    queryFn: () => apiFetch<{ rule: Record<string, unknown>; yaml: string }>(`/agent/rules/${ruleId}`),
    enabled: !!ruleId,
  })
}

export function useTriggerAgentScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (since_minutes: number = 0) =>
      apiFetch('/agent/scan', {
        method: 'POST',
        body: JSON.stringify({ since_minutes }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['follow-ups'] })
      qc.invalidateQueries({ queryKey: ['agent'] })
    },
  })
}

export function useToggleAgentRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) =>
      apiFetch(`/agent/rules/${ruleId}?enabled=${enabled}`, { method: 'PATCH' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent', 'rules'] })
    },
  })
}

export function useReloadRules() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; rules_loaded: number }>('/agent/rules/reload', { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent', 'rules'] })
    },
  })
}

export function useTestRule() {
  return useMutation({
    mutationFn: (data: { rule_id?: string; rule_yaml?: string; since_minutes?: number; limit?: number }) =>
      apiFetch<RuleTestResult>('/agent/rules/test', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
  })
}

export function useCreateAdhocRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (rule_yaml: string) =>
      apiFetch<{ ok: boolean; rule_id: string }>('/agent/rules/adhoc', {
        method: 'POST',
        body: JSON.stringify({ rule_yaml }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent', 'rules'] })
    },
  })
}

export function useDeleteRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (ruleId: string) =>
      apiFetch(`/agent/rules/${ruleId}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent', 'rules'] })
    },
  })
}

// ── Burp Follow-Up Queue Hooks ──

export interface BurpQueueItem {
  id: string
  follow_up_id: string
  title: string
  url: string | null
  target: string | null
  severity: string
  finding_source: string | null
  method: string
  status: string
  queued_at: string
}

export function useBurpQueueStats() {
  return useQuery({
    queryKey: ['burp-queue', 'stats'],
    queryFn: () => apiFetch<{ pending: number; imported: number; dismissed: number; total: number }>('/burp/queue/stats'),
    refetchInterval: POLL.NORMAL,
  })
}

export function useSendToBurpQueue() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (follow_up_ids: string[]) =>
      apiFetch<{ ok: boolean; added: number; skipped: number }>('/burp/queue', {
        method: 'POST',
        body: JSON.stringify({ follow_up_ids }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['burp-queue'] })
    },
  })
}
