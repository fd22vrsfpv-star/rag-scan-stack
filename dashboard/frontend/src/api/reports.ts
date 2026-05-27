import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiUrl } from './client'
import { POLL } from '@/lib/polling'

export function useReportSummary(sessionId?: string) {
  const params = sessionId ? `?session_id=${sessionId}` : ''
  return useQuery({
    queryKey: ['report-summary', sessionId],
    queryFn: () => apiFetch<Record<string, unknown>>(`/reports/summary${params}`),
    enabled: false, // manual trigger
  })
}

export function useReportFull(target?: string, sessionId?: string, scopeName?: string) {
  const params = new URLSearchParams()
  if (target) params.set('target', target)
  if (sessionId) params.set('session_id', sessionId)
  if (scopeName) params.set('scope_name', scopeName)
  const qs = params.toString()
  return useQuery({
    queryKey: ['report-full', target, sessionId, scopeName],
    queryFn: () => apiFetch<{ rendered?: string; summary?: Record<string, unknown>; vulnerabilities?: Record<string, unknown[]> }>(`/reports/full${qs ? '?' + qs : ''}`),
    enabled: false,
  })
}

export function useExportPdf() {
  return useMutation({
    mutationFn: async (params: {
      title?: string
      target?: string
      severity_filter?: string[]
      source_filter?: string[]
    }) => {
      const resp = await fetch(apiUrl('/reports/export'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })
      if (!resp.ok) throw new Error('PDF export failed')
      return resp.blob()
    },
  })
}

export function useExportBurp() {
  return useMutation({
    mutationFn: async (params: {
      target?: string
      severity_filter?: string[]
      source_filter?: string[]
    }) => {
      const resp = await fetch(apiUrl('/reports/export-burp'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })
      if (!resp.ok) throw new Error('Burp XML export failed')
      return resp.blob()
    },
  })
}

export function useExportZapXml() {
  return useMutation({
    mutationFn: async () => {
      const resp = await fetch(apiUrl('/reports/export-zap-xml'))
      if (!resp.ok) throw new Error('ZAP XML export failed')
      return resp.blob()
    },
  })
}

export function useProxyReplay() {
  return useMutation({
    mutationFn: async (params: {
      proxy_url: string
      severity?: string[]
      source?: string[]
      ip?: string
      limit?: number
      delay_ms?: number
      include_params?: boolean
      include_auth?: boolean
      include_payloads?: boolean
      order?: 'sequential' | 'severity' | 'random'
      dry_run?: boolean
    }) => {
      const resp = await fetch(apiUrl('/reports/proxy-replay'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })
      if (!resp.ok) throw new Error(`Proxy replay failed: ${resp.statusText}`)
      return resp.json() as Promise<{ ok: boolean; queued: number; proxy: string; message: string }>
    },
  })
}

export function useExportHar() {
  return useMutation({
    mutationFn: async (params: {
      target?: string
      severity_filter?: string[]
      source_filter?: string[]
      search?: string
    }) => {
      const resp = await fetch(apiUrl('/reports/export-har'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })
      if (!resp.ok) throw new Error('HAR export failed')
      return resp.blob()
    },
  })
}

export function useExportZapReport() {
  return useMutation({
    mutationFn: async (params: {
      target?: string
      severity_filter?: string[]
      source_filter?: string[]
    }) => {
      const resp = await fetch(apiUrl('/reports/export-zap-report'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })
      if (!resp.ok) throw new Error('ZAP report export failed')
      return resp.blob()
    },
  })
}

export function useExportSarif() {
  return useMutation({
    mutationFn: async (params: { severity?: string; source?: string }) => {
      const qs = new URLSearchParams()
      if (params.severity) qs.set('severity', params.severity)
      if (params.source) qs.set('source', params.source)
      const resp = await fetch(apiUrl(`/sarif-export?${qs}`))
      if (!resp.ok) throw new Error('SARIF export failed')
      return resp.blob()
    },
  })
}

export function useExportUrlList() {
  return useMutation({
    mutationFn: async (params: { domain?: string }) => {
      const qs = params.domain ? `?domain=${encodeURIComponent(params.domain)}` : ''
      const resp = await fetch(apiUrl(`/content-intel/sitemap/export/urls${qs}`))
      if (!resp.ok) throw new Error('URL list export failed')
      return resp.blob()
    },
  })
}

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => apiFetch<{ status: string; services: Record<string, { status: string; [key: string]: unknown }>; warnings?: { type: string; message: string; severity: string }[] }>('/health'),
    refetchInterval: POLL.SLOW,
  })
}

// ── Service profile control ──

export interface ProfileStatus {
  containers: { name: string; status: string; running: boolean }[]
  running: number
  total: number
  active: boolean
}

export function useServiceStatus() {
  return useQuery({
    queryKey: ['service-status'],
    queryFn: () => apiFetch<{ profiles: Record<string, ProfileStatus> }>('/services/status'),
    refetchInterval: POLL.SLOW,
  })
}

export function useServiceControl() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ action, profile }: { action: 'start' | 'stop'; profile: string }) => {
      return apiFetch<{ ok: boolean; profile: string; action: string; results: unknown[] }>(
        `/services/${action}/${profile}`,
        { method: 'POST' },
      )
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['service-status'] })
      qc.invalidateQueries({ queryKey: ['health'] })
    },
  })
}

export function useContainerControl() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ action, name }: { action: 'start' | 'stop'; name: string }) => {
      return apiFetch<{ ok: boolean; name: string; action: string }>(
        `/services/${action}/container/${name}`,
        { method: 'POST' },
      )
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['service-status'] })
      qc.invalidateQueries({ queryKey: ['health'] })
    },
  })
}

// ── Diagnostics ──

export interface DiagnosticError {
  timestamp: string | null
  message: string
}

export interface ContainerDiagnostic {
  container: string
  status: string
  error_count: number
  errors: DiagnosticError[]
}

export interface DiagnosticsResult {
  ok: boolean
  scanned: number
  since_minutes: number
  total_errors: number
  containers_with_errors: number
  containers: ContainerDiagnostic[]
  error?: string
}

export function useDiagnostics(sinceMinutes = 30, enabled = false) {
  return useQuery({
    queryKey: ['diagnostics', sinceMinutes],
    queryFn: () => apiFetch<DiagnosticsResult>(`/diagnostics/errors?since_minutes=${sinceMinutes}`),
    enabled,
    staleTime: 60000,
  })
}

export interface OllamaGpu {
  name: string
  type?: 'apple_silicon' | 'nvidia'
  vram_total_mb: number
  vram_used_mb: number
  vram_free_mb: number
  vram_total_human: string
  vram_used_human: string
  vram_free_human: string
  utilization_pct: number | null
  temperature_c: number | null
  power_w: number | null
  power_cap_w: number | null
  fan_pct: number | null
  driver_version: string | null
  cuda_version: string | null
  pci_bus: string | null
}

export interface OllamaLoadedModel {
  name: string
  parameter_size: string
  quantization: string
  family: string
  total_bytes: number
  total_human: string
  vram_bytes: number
  vram_human: string
  gpu_percent: number
  backend: 'gpu' | 'cpu' | 'gpu+cpu'
  context_length: number
  expires_at: string
}

export interface OllamaAvailableModel {
  name: string
  size: number
  size_human: string
  parameter_size: string
  quantization: string
  family: string
}

export interface OllamaStatus {
  gpu: OllamaGpu | null
  loaded_models: OllamaLoadedModel[]
  available_models: OllamaAvailableModel[]
  version: string | null
}

export function useOllamaStatus() {
  return useQuery({
    queryKey: ['ollama-status'],
    queryFn: () => apiFetch<OllamaStatus>('/ollama/status'),
    refetchInterval: POLL.SLOW,
  })
}

export async function ollamaLoadModel(name: string) {
  return apiFetch<{ ok: boolean; model: string; action: string; error?: string }>('/ollama/model/load', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
}

export async function ollamaUnloadModel(name: string) {
  return apiFetch<{ ok: boolean; model: string; action: string; error?: string }>('/ollama/model/unload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
}

export async function ollamaPullModel(name: string) {
  return apiFetch<{ ok: boolean; model: string; action: string; error?: string }>('/ollama/model/pull', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
}

export function useActiveModel() {
  return useQuery({
    queryKey: ['ollama-active-model'],
    queryFn: () => apiFetch<{ ok: boolean; model: string }>('/ollama/model/active'),
  })
}

export async function setActiveModel(name: string) {
  return apiFetch<{ ok: boolean; model: string; action: string; error?: string }>('/ollama/model/active', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
}

// ── Content Extractions ──

export interface ContentExtraction {
  id: string
  scan_id: string | null
  asset_id: string | null
  url: string
  emails: string[]
  names: string[]
  internal_paths: string[]
  api_endpoints: string[]
  exposed_keys: { type: string; value_preview: string; full_match: string }[]
  tech_indicators: { type: string; value: string }[]
  comments: { content: string; keywords: string[] }[]
  hidden_inputs: { name: string; value: string }[]
  interesting_files: { path: string; category: string; content?: string; source?: string }[]
  file_metadata: { path: string; url: string; file_type: string; size_bytes: number; metadata: Record<string, string>; alerts: { type: string; detail: string }[] }[]
  login_pages: { type: string; url: string; confidence: string; form_actions?: string[]; password_field_count?: number; username_fields?: string[]; indicator_text?: string }[]
  js_configs: Record<string, unknown>
  word_corpus: string | null
  created_at: string | null
}

export interface ContentSummary {
  total_extractions: number
  total_emails: number
  total_names: number
  total_paths: number
  total_api_endpoints: number
  total_exposed_keys: number
  total_tech_indicators: number
  total_comments: number
  total_hidden_inputs: number
  total_interesting_files: number
  total_file_metadata: number
  total_login_pages: number
}

export function useContentExtractions(search?: string, scanId?: string) {
  const params = new URLSearchParams()
  if (search) params.set('search', search)
  if (scanId) params.set('scan_id', scanId)
  const qs = params.toString()
  return useQuery({
    queryKey: ['content-extractions', search, scanId],
    queryFn: () => apiFetch<{ ok: boolean; extractions: ContentExtraction[]; count: number }>(
      `/content-extractions${qs ? '?' + qs : ''}`
    ),
  })
}

export function useContentSummary(search?: string) {
  const params = search ? `?search=${encodeURIComponent(search)}` : ''
  return useQuery({
    queryKey: ['content-summary', search],
    queryFn: () => apiFetch<{ ok: boolean; summary: ContentSummary }>(
      `/content-extractions/summary${params}`
    ),
  })
}

export function useGenerateWordlist() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      asset_id?: string
      scan_id?: string
      list_type?: string
      min_word_length?: number
      max_lines?: number
      enable_mutations?: boolean
      mutations?: string[]
      include_sources?: string[]
    }) => apiFetch<{
      ok: boolean
      wordlist_id: string
      name: string
      line_count: number
      size_bytes: number
      path: string
    }>('/wordlists/generate', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wordlists'] })
    },
  })
}

// ── Credential Guess (LLM-powered) ──

export interface CredentialGuess {
  value: string
  rationale: string
}

export interface CredentialGuessResult {
  ok: boolean
  usernames: CredentialGuess[]
  passwords: CredentialGuess[]
  analysis: string
  model: string
  intel_summary: {
    emails_found: number
    names_found: number
    tech_indicators: number
    login_pages: number
  }
  parse_error?: string
}

export function useCredentialGuess() {
  return useMutation({
    mutationFn: (body: { login_url: string; asset_id?: string; extraction_id?: string }) =>
      apiFetch<CredentialGuessResult>('/content-intel/credential-guess', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  })
}

// ── Content Intel Sitemap ──

export interface SitemapEntry {
  url: string
  methods: string[]
  sources: string[]
  status_codes: number[]
  findings: number
  params: { name: string; type: string; location: string }[]
  severities: string[]
}

export function useSitemap(domain?: string, search?: string) {
  const params = new URLSearchParams()
  if (domain) params.set('domain', domain)
  if (search) params.set('search', search)
  const qs = params.toString()
  return useQuery({
    queryKey: ['sitemap', domain, search],
    queryFn: () => apiFetch<{ ok: boolean; urls: SitemapEntry[]; total: number; domain: string | null }>(
      `/content-intel/sitemap${qs ? '?' + qs : ''}`
    ),
    enabled: !!(domain || search),
  })
}

// ── Content Intel Patterns ──

export interface ContentPattern {
  id: string
  category: string
  name: string
  pattern: string
  label: string | null
  enabled: boolean
  is_builtin: boolean
  description: string | null
  created_at: string | null
  updated_at: string | null
}

export function useContentPatterns(category?: string) {
  const params = category ? `?category=${category}` : ''
  return useQuery({
    queryKey: ['content-patterns', category],
    queryFn: () => apiFetch<{ ok: boolean; patterns: ContentPattern[] }>(
      `/content-intel/patterns${params}`
    ),
  })
}

export function useCreatePattern() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      category: string
      name: string
      pattern: string
      label?: string
      enabled?: boolean
      description?: string
    }) => apiFetch<{ ok: boolean; id: string }>('/content-intel/patterns', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['content-patterns'] }),
  })
}

export function useUpdatePattern() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string } & Partial<ContentPattern>) =>
      apiFetch<{ ok: boolean }>(`/content-intel/patterns/${id}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['content-patterns'] }),
  })
}

export function useDeletePattern() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean }>(`/content-intel/patterns/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['content-patterns'] }),
  })
}

// ── Content Extraction editing ──

export function useUpdateExtraction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string } & Record<string, unknown>) =>
      apiFetch<{ ok: boolean }>(`/content-extractions/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['content-extractions'] })
      qc.invalidateQueries({ queryKey: ['content-summary'] })
    },
  })
}

export function useDeleteExtraction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean }>(`/content-extractions/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['content-extractions'] })
      qc.invalidateQueries({ queryKey: ['content-summary'] })
    },
  })
}

export function useWordlists() {
  return useQuery({
    queryKey: ['wordlists'],
    queryFn: () => apiFetch<{ ok: boolean; wordlists: Array<{ id: string; name: string; path: string; source: string; list_type: string; line_count: number; size_bytes: number; description: string | null; created_at: string }> }>('/wordlists'),
  })
}
