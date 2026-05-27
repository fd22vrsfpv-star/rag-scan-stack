import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

export interface CloudRecommendation {
  id: string
  rule_id: string
  rule_name: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  tool: string
  action: string
  command_hint?: string
  import_as?: string
  trigger_source?: string
  trigger_finding_id?: string
  trigger_summary?: string
  provider?: string
  account_id?: string
  status: string
  // AI triage fields (filled by cloud_triage_agent)
  triage_order?: number | null
  triage_reasoning?: string | null
  triaged_at?: string | null
  created_at: string
}

export interface CloudTriageRun {
  present: boolean
  run_id?: string
  engagement_id?: string | null
  provider?: string | null
  open_recs_count?: number
  top_actions?: Array<{ id: string; title: string; why: string }>
  summary?: string
  model?: string
  latency_ms?: number
  error?: string | null
  created_at?: string | null
  cached?: boolean
}

export interface CloudPosture {
  providers: string[]
  sources_imported: Record<string, number>
  total_cloud_findings: number
  by_severity: Record<string, number>
  active_cloud_creds: number
  expiring_creds: number
  open_recommendations: Record<string, number>
  total_open_recommendations: number
}

export function useCloudRecommendations(filters?: {
  provider?: string
  priority?: string
  status?: string
}) {
  const params = new URLSearchParams()
  if (filters?.provider) params.set('provider', filters.provider)
  if (filters?.priority) params.set('priority', filters.priority)
  if (filters?.status) params.set('status', filters.status)
  const qs = params.toString()
  return useQuery({
    queryKey: ['cloud-recommendations', qs],
    queryFn: () =>
      apiFetch<{ recommendations: CloudRecommendation[]; count: number }>(
        `/cloud/recommendations${qs ? `?${qs}` : ''}`
      ),
    refetchInterval: POLL.BACKGROUND,
  })
}

export function useCloudPosture() {
  return useQuery({
    queryKey: ['cloud-posture'],
    queryFn: () => apiFetch<CloudPosture>('/cloud/posture'),
    staleTime: 60_000,
  })
}

export function useRefreshCloudRecommendations() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; evaluated: number; inserted: number; skipped: number }>(
        '/cloud/recommendations/refresh',
        { method: 'POST' }
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-recommendations'] })
      qc.invalidateQueries({ queryKey: ['cloud-posture'] })
    },
  })
}

export function useUpdateCloudRecommendation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch<{ ok: boolean }>(`/cloud/recommendations/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-recommendations'] })
      qc.invalidateQueries({ queryKey: ['cloud-posture'] })
    },
  })
}

// AI triage agent
export function useCloudTriageLatest(filters?: {
  engagement_id?: string
  provider?: string
}) {
  const params = new URLSearchParams()
  if (filters?.engagement_id) params.set('engagement_id', filters.engagement_id)
  if (filters?.provider) params.set('provider', filters.provider)
  const qs = params.toString()
  return useQuery({
    queryKey: ['cloud-triage-latest', qs],
    queryFn: () => apiFetch<CloudTriageRun>(`/cloud/triage/latest${qs ? `?${qs}` : ''}`),
    refetchInterval: POLL.BACKGROUND,
  })
}

export function useRunCloudTriage() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ engagement_id, provider, force, model }: {
      engagement_id?: string; provider?: string; force?: boolean; model?: string
    } = {}) => {
      const params = new URLSearchParams()
      if (engagement_id) params.set('engagement_id', engagement_id)
      if (provider) params.set('provider', provider)
      if (force) params.set('force', 'true')
      if (model) params.set('model', model)
      const qs = params.toString()
      return apiFetch<{
        ok: boolean; run_id?: string; cached?: boolean;
        ranked_count?: number; top_actions?: any[]; summary?: string;
        model?: string; error?: string;
      }>(`/cloud/triage/run${qs ? `?${qs}` : ''}`, { method: 'POST' })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-recommendations'] })
      qc.invalidateQueries({ queryKey: ['cloud-triage-latest'] })
    },
  })
}
