import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

// ── Types ──

export interface ApiCollection {
  id: string
  name: string
  base_url: string
  openapi_version: string
  auth_type: string
  auth_config: Record<string, any> | null
  source_file: string
  source_url: string | null
  endpoint_count: number
  created_at: string
  updated_at: string
}

export interface ApiEndpoint {
  id: string
  collection_id: string
  method: string
  path: string
  operation_id: string
  summary: string
  parameters: Array<{
    name: string
    in: string
    required: boolean
    type: string
    format: string
    description: string
  }>
  request_body: {
    content_type: string
    schema_name: string
    required: boolean
    fields: Array<{ name: string; type: string; required: boolean; description: string }>
  } | null
  responses: Record<string, { description: string; schema_name?: string }>
  security: any[]
  tags: string[]
  created_at: string
}

export interface TestSession {
  id: string
  collection_id: string | null
  name: string | null
  jwt_token: string | null
  proxy_url: string | null
  variables: Record<string, string>
  created_at: string
  updated_at: string
}

export interface TestResult {
  id: string
  session_id: string
  endpoint_id: string
  method: string
  url: string
  request_headers: Record<string, string>
  request_body: string | null
  status_code: number | null
  response_headers: Record<string, string>
  response_body: string | null
  duration_ms: number | null
  error: string | null
  created_at: string
}

// ── Collection Hooks ──

export function useApiCollections() {
  return useQuery({
    queryKey: ['api-collections'],
    queryFn: () => apiFetch<{ collections: ApiCollection[] }>('/api-collections'),
  })
}

export function useApiCollection(id: string | null) {
  return useQuery({
    queryKey: ['api-collections', id],
    queryFn: () => apiFetch<{ collection: ApiCollection }>(`/api-collections/${id}`),
    enabled: !!id,
  })
}

export function useApiEndpoints(collectionId: string | null, filters?: { method?: string; tag?: string; search?: string }) {
  const params = new URLSearchParams()
  if (filters?.method) params.set('method', filters.method)
  if (filters?.tag) params.set('tag', filters.tag)
  if (filters?.search) params.set('search', filters.search)
  const qs = params.toString()
  return useQuery({
    queryKey: ['api-endpoints', collectionId, filters],
    queryFn: () => apiFetch<{ endpoints: ApiEndpoint[] }>(`/api-collections/${collectionId}/endpoints${qs ? `?${qs}` : ''}`),
    enabled: !!collectionId,
  })
}

export function useImportDir() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; imported: any[]; total: number }>('/api-collections/import-dir', { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-collections'] })
    },
  })
}

export function useImportUrl() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (url: string) =>
      apiFetch<{ ok: boolean; collection_id: string; endpoint_count: number; source_url: string; saved_to: string | null }>('/api-collections/import-url', {
        method: 'POST',
        body: JSON.stringify({ url }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-collections'] })
    },
  })
}

export function useDeleteCollection() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api-collections/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-collections'] })
    },
  })
}

// ── Session Hooks ──

export function useTestSessions() {
  return useQuery({
    queryKey: ['api-test-sessions'],
    queryFn: () => apiFetch<{ sessions: TestSession[] }>('/api-test/sessions'),
  })
}

export function useCreateSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name?: string; collection_id?: string; jwt_token?: string; proxy_url?: string; variables?: Record<string, string> }) =>
      apiFetch<{ ok: boolean; session: TestSession }>('/api-test/sessions', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-test-sessions'] })
    },
  })
}

export function useUpdateSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string; jwt_token?: string; proxy_url?: string; variables?: Record<string, string>; name?: string }) =>
      apiFetch<{ ok: boolean; session: TestSession }>(`/api-test/sessions/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-test-sessions'] })
    },
  })
}

export function useDeleteSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api-test/sessions/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-test-sessions'] })
    },
  })
}

// ── Execute + History ──

export function useExecuteTest() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { session_id: string; endpoint_id: string; params?: Record<string, string>; body?: Record<string, any>; headers?: Record<string, string> }) =>
      apiFetch<{ ok: boolean; result: TestResult }>('/api-test/execute', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-test-history'] })
    },
  })
}

export function useTestHistory(sessionId: string | null, endpointId?: string | null) {
  const params = new URLSearchParams()
  if (endpointId) params.set('endpoint_id', endpointId)
  const qs = params.toString()
  return useQuery({
    queryKey: ['api-test-history', sessionId, endpointId],
    queryFn: () => apiFetch<{ history: TestResult[] }>(`/api-test/sessions/${sessionId}/history${qs ? `?${qs}` : ''}`),
    enabled: !!sessionId,
    refetchInterval: 10000,
  })
}

// ── Clear history ──

export function useClearHistory() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (sessionId: string) =>
      apiFetch<{ ok: boolean; deleted: number }>(`/api-test/sessions/${sessionId}/history`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-test-history'] })
    },
  })
}

// ── Common parameters ──

export interface CommonParam {
  name: string
  in: string
  type: string
  format: string
  required: boolean
  description: string
  used_in: string[]
}

export function useCommonParams(collectionId: string | null) {
  return useQuery({
    queryKey: ['api-common-params', collectionId],
    queryFn: () => apiFetch<{ collection_id: string; params: CommonParam[]; total: number }>(
      `/api-collections/${collectionId}/common-params`,
    ),
    enabled: !!collectionId,
  })
}

// ── Param Configs (persisted as JSON files) ──

export interface ParamConfig {
  id: string
  collection_id: string
  name: string
  config: Record<string, string>
  auth_header?: string
  created_at: string
  updated_at: string
}

export function useParamConfigs(collectionId: string | null) {
  return useQuery({
    queryKey: ['api-param-configs', collectionId],
    queryFn: () => apiFetch<{ configs: ParamConfig[]; total: number }>(
      `/api-collections/${collectionId}/param-configs`,
    ),
    enabled: !!collectionId,
  })
}

export function useSaveParamConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { collection_id: string; name: string; config: Record<string, string>; auth_header?: string }) =>
      apiFetch<ParamConfig>(
        `/api-collections/${data.collection_id}/param-configs`,
        { method: 'POST', body: JSON.stringify(data) },
      ),
    onSuccess: (_d, vars) => {
      qc.invalidateQueries({ queryKey: ['api-param-configs', vars.collection_id] })
    },
  })
}

export function useUpdateParamConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { id: string; name?: string; config?: Record<string, string>; auth_header?: string }) =>
      apiFetch<ParamConfig>(
        `/api-param-configs/${data.id}`,
        { method: 'PUT', body: JSON.stringify(data) },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-param-configs'] })
    },
  })
}

export function useDeleteParamConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean }>(`/api-param-configs/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-param-configs'] })
    },
  })
}

export function useImportParamConfigs() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { collection_id: string; configs: Array<{ name: string; config: Record<string, string>; auth_header?: string }> }) =>
      apiFetch<{ ok: boolean; imported: number }>(
        `/api-collections/${data.collection_id}/param-configs/import`,
        { method: 'POST', body: JSON.stringify({ configs: data.configs }) },
      ),
    onSuccess: (_d, vars) => {
      qc.invalidateQueries({ queryKey: ['api-param-configs', vars.collection_id] })
    },
  })
}

// ── Run all endpoints ──

export interface RunAllResult {
  endpoint_id: string
  method: string
  path: string
  url?: string
  status: 'ok' | 'skipped'
  status_code?: number
  duration_ms?: number
  error?: string
  reason?: string
  result_id?: string
}

export function useRunAll() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: {
      session_id: string
      collection_id: string
      variables?: Record<string, string>
      headers?: Record<string, string>
    }) =>
      apiFetch<{ ok: boolean; total: number; executed: number; skipped: number; results: RunAllResult[] }>(
        '/api-test/run-all',
        { method: 'POST', body: JSON.stringify(data) },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-test-history'] })
    },
  })
}
