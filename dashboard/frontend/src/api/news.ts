import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'
import type {
  NewsItem, NewsSource, NewsRun, NewsStats, NewsStatus, NewsDeepSearchResult,
} from '@/lib/types'

export interface NewsListResponse {
  total: number
  limit: number
  offset: number
  results: NewsItem[]
}

export interface NewsRunsResponse {
  results: NewsRun[]
}

export interface NewsListFilters {
  status?: NewsStatus
  hide_statuses?: string  // CSV
  cve?: string
  kev_listed?: boolean
  rce?: boolean
  red_team_only?: boolean
  q?: string
  since?: string  // ISO timestamp; items with last_seen >= since
  include_deleted?: boolean
  limit?: number
  offset?: number
}

function _qs(filters: NewsListFilters | undefined): string {
  if (!filters) return ''
  const p = new URLSearchParams()
  Object.entries(filters).forEach(([k, v]) => {
    if (v === undefined || v === null || v === '') return
    p.set(k, String(v))
  })
  const s = p.toString()
  return s ? `?${s}` : ''
}

export function useNewsItems(filters?: NewsListFilters) {
  return useQuery({
    queryKey: ['news', 'items', filters || {}],
    queryFn: () => apiFetch<NewsListResponse>(`/news/items${_qs(filters)}`),
    refetchInterval: POLL.NORMAL,
  })
}

export function useNewsItem(id: string | null) {
  return useQuery({
    queryKey: ['news', 'item', id],
    queryFn: () => apiFetch<NewsItem>(`/news/items/${id}`),
    enabled: !!id,
  })
}

export function useNewsStats() {
  return useQuery({
    queryKey: ['news', 'stats'],
    queryFn: () => apiFetch<NewsStats>('/news/stats'),
    refetchInterval: POLL.NORMAL,
  })
}

export function useNewsSources() {
  return useQuery({
    queryKey: ['news', 'sources'],
    queryFn: () => apiFetch<{ results: NewsSource[] }>('/news/sources'),
    refetchInterval: POLL.SLOW,
  })
}

export function useNewsRuns(limit = 20) {
  return useQuery({
    queryKey: ['news', 'runs', limit],
    queryFn: () => apiFetch<NewsRunsResponse>(`/news/runs?limit=${limit}`),
    refetchInterval: POLL.NORMAL,
  })
}

export function useNewsRun(runId: string | null) {
  return useQuery({
    queryKey: ['news', 'run', runId],
    queryFn: () => apiFetch<NewsRun>(`/news/runs/${runId}`),
    enabled: !!runId,
    refetchInterval: (data) => (data as any)?.status === 'running' ? 1500 : false,
  })
}

export function useTriggerIngest() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (sourceId?: string) =>
      apiFetch<{ ok: boolean; run_id: string }>(
        sourceId ? `/news/ingest?source_id=${sourceId}` : '/news/ingest',
        { method: 'POST' },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['news', 'runs'] })
    },
  })
}

export function useUpdateNewsItem() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...patch }: { id: string } & Partial<{
      status: NewsStatus; notes: string; tags: string[]; acknowledged_by: string
    }>) =>
      apiFetch<NewsItem>(`/news/items/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(patch),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['news', 'items'] })
      qc.invalidateQueries({ queryKey: ['news', 'stats'] })
    },
  })
}

export function useBulkNewsAction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { ids: string[]; action: string; value?: string }) =>
      apiFetch<{ updated: number }>('/news/items/bulk', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['news', 'items'] })
      qc.invalidateQueries({ queryKey: ['news', 'stats'] })
    },
  })
}

export function useMatchAssets() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean; asset_hits: number }>(`/news/items/${id}/match-assets`, {
        method: 'POST',
      }),
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: ['news', 'item', id] })
      qc.invalidateQueries({ queryKey: ['news', 'items'] })
    },
  })
}

export function useGithubSearch() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean; repos: number }>(`/news/items/${id}/github-search`, {
        method: 'POST',
      }),
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: ['news', 'item', id] })
      qc.invalidateQueries({ queryKey: ['news', 'items'] })
    },
  })
}

export function useEnrichItem() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean; enriched: number }>(`/news/items/${id}/enrich`, {
        method: 'POST',
      }),
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: ['news', 'item', id] })
      qc.invalidateQueries({ queryKey: ['news', 'items'] })
    },
  })
}

export function useDeepSearch() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { topic: string; refresh_llm?: boolean; max_items?: number; include_deleted?: boolean }) =>
      apiFetch<{ ok: boolean; run_id: string; topic: string }>('/news/deep-search', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['news', 'items'] })
      qc.invalidateQueries({ queryKey: ['news', 'runs'] })
    },
  })
}

export function useUpdateSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...patch }: { id: string } & Partial<{
      enabled: boolean; url: string; name: string
    }>) =>
      apiFetch<{ ok: boolean }>(`/news/sources/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(patch),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['news', 'sources'] }),
  })
}

export function useRefetchSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean; run_id: string }>(`/news/sources/${id}/refetch`, {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['news', 'runs'] })
      qc.invalidateQueries({ queryKey: ['news', 'sources'] })
    },
  })
}

export function useCreateSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { name: string; url: string; parser?: string; enabled?: boolean }) =>
      apiFetch<NewsSource>('/news/sources', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['news', 'sources'] })
    },
  })
}
