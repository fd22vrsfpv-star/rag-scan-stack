import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { ReconSearchResponse, ScreenshotMetadata } from '@/lib/types'
import { POLL } from '@/lib/polling'

export interface ReconFilter {
  source?: string[]
  finding_type?: string[]
  provider?: string[]
  target?: string
  search?: string
  severity?: string[]
  date_from?: string
  date_to?: string
  limit?: number
  offset?: number
}

export function useReconFindings(filters: ReconFilter = {}) {
  const params = new URLSearchParams()
  if (filters.source?.length) filters.source.forEach(s => params.append('source', s))
  if (filters.finding_type?.length) filters.finding_type.forEach(s => params.append('finding_type', s))
  if (filters.provider?.length) filters.provider.forEach(s => params.append('provider', s))
  if (filters.target) params.set('target', filters.target)
  if (filters.search) params.set('search', filters.search)
  if (filters.severity?.length) filters.severity.forEach(s => params.append('severity', s))
  if (filters.date_from) params.set('date_from', filters.date_from)
  if (filters.date_to) params.set('date_to', filters.date_to)
  params.set('limit', String(filters.limit ?? 200))
  params.set('offset', String(filters.offset ?? 0))

  return useQuery({
    queryKey: ['recon', filters],
    queryFn: () => apiFetch<ReconSearchResponse>(`/recon?${params}`),
    refetchInterval: POLL.SLOW,
  })
}

// ── Discovered Parameters ────────────────────────────────

export interface ParamFilter {
  url_pattern?: string
  param_name?: string
  param_type?: string
  min_occurrences?: number
  limit?: number
  offset?: number
}

export interface DiscoveredParam {
  id: string
  asset_id: string | null
  url_pattern: string
  param_name: string
  param_type: string
  http_method: string
  param_location: string
  sample_values: string[]
  occurrence_count: number
  discovery_source: string
  first_seen: string
  last_seen: string
}

export interface ParamsResponse {
  params: DiscoveredParam[]
  total: number
}

export interface ParamSummaryItem {
  param_name: string
  types: string[]
  locations: string[]
  total_occurrences: number
  url_count: number
}

export interface ParamsSummaryResponse {
  summary: ParamSummaryItem[]
}

export function useParams(filters: ParamFilter = {}) {
  const params = new URLSearchParams()
  if (filters.url_pattern) params.set('url_pattern', filters.url_pattern)
  if (filters.param_name) params.set('param_name', filters.param_name)
  if (filters.param_type) params.set('param_type', filters.param_type)
  if (filters.min_occurrences && filters.min_occurrences > 1) params.set('min_occurrences', String(filters.min_occurrences))
  params.set('limit', String(filters.limit ?? 200))
  params.set('offset', String(filters.offset ?? 0))

  return useQuery({
    queryKey: ['params', filters],
    queryFn: () => apiFetch<ParamsResponse>(`/params?${params}`),
    refetchInterval: POLL.SLOW,
  })
}

export function useParamsSummary(minOccurrences: number = 1) {
  const params = new URLSearchParams()
  if (minOccurrences > 1) params.set('min_occurrences', String(minOccurrences))
  params.set('limit', '100')

  return useQuery({
    queryKey: ['params-summary', minOccurrences],
    queryFn: () => apiFetch<ParamsSummaryResponse>(`/params/summary?${params}`),
    refetchInterval: POLL.SLOW,
  })
}

// ── Domain Overview ──────────────────────────────────────

export interface DomainSummary {
  domain: string
  subdomain_count: number
  dns_count: number
  http_count: number
  tls_count: number
  ct_count: number
  total: number
  last_seen: string | null
}

export interface DomainsResponse {
  domains: DomainSummary[]
  total: number
}

export interface DomainSubdomain {
  name: string
  resolved_ip: string
  first_seen: string
}

export interface DomainDnsEntry {
  target: string
  values: string[] | unknown
  data: Record<string, unknown>
}

export interface DomainHttpService {
  url: string
  status_code: string | number
  title: string
  webserver: string
  tech: string[]
  content_length: string | number
  created_at: string
}

export interface DomainTlsCert {
  host: string
  subject_cn: string
  issuer: string
  not_after: string
  not_before: string
  serial: string
  created_at: string
}

export interface DomainCtCert {
  common_name: string
  issuer_name: string
  not_after: string
  serial: string
  created_at: string
}

export interface DomainAsnMapping {
  ip: string
  asn: string | number
  org: string
  country: string
  cidr: string
  created_at: string
}

export interface DomainWafDetection {
  url: string
  detected: boolean
  firewall: string
  manufacturer: string
  created_at: string
}

export interface DomainWebFinding {
  url: string
  source: string
  name: string
  severity: string
  issue_type: string
  first_seen: string
}

export interface DomainParam {
  name: string
  count: number
  types: string[]
  locations: string[]
}

export interface DomainOverview {
  domain: string
  stats: {
    total_findings: number
    first_seen: string | null
    last_seen: string | null
    by_source: Record<string, number>
    web_findings_count?: number
    content_extractions_count?: number
    playwright_findings_count?: number
  }
  subdomains: DomainSubdomain[]
  dns_records: Record<string, DomainDnsEntry[]>
  http_services: DomainHttpService[]
  tls_certs: DomainTlsCert[]
  ct_certs: DomainCtCert[]
  asn_mappings: DomainAsnMapping[]
  waf_detections: DomainWafDetection[]
  web_findings?: DomainWebFinding[]
  discovered_params?: DomainParam[]
}

export function useReconDomains(search?: string, includeExcluded = false) {
  const params = new URLSearchParams()
  if (search) params.set('search', search)
  if (includeExcluded) params.set('include_excluded', 'true')
  params.set('limit', '50')

  return useQuery({
    queryKey: ['recon-domains', search, includeExcluded],
    queryFn: () => apiFetch<DomainsResponse & { excluded_count?: number }>(`/recon/domains?${params}`),
    refetchInterval: POLL.SLOW,
  })
}

export function useAutoAssignUnknownScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; added: number; total_unscoped: number; message: string }>('/scope/auto-assign-unknown', {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['recon-domains'] })
      qc.invalidateQueries({ queryKey: ['scope'] })
    },
  })
}

export function useExcludeDomain() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (domains: string[]) =>
      apiFetch<{ ok: boolean; added: number }>('/scope/exclude', {
        method: 'POST',
        body: JSON.stringify({ targets: domains, source: 'manual' }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['recon-domains'] })
    },
  })
}

export function useRestoreDomain() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (domains: string[]) =>
      apiFetch<{ ok: boolean; removed: number }>('/scope/exclude', {
        method: 'DELETE',
        body: JSON.stringify({ name: 'not_in_scope', targets: domains }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['recon-domains'] })
    },
  })
}

export function useExcludedDomains() {
  return useQuery({
    queryKey: ['excluded-domains'],
    queryFn: () => apiFetch<{ targets: Array<{ target: string; source: string; added_at: string }>; total: number }>('/scope/excluded'),
  })
}

export interface SitemapUrl {
  url: string
  path: string
  source: string
  status_code: number | null
  first_seen: string
}

export function useDomainSitemap(domain: string | null) {
  return useQuery({
    queryKey: ['domain-sitemap', domain],
    queryFn: () => apiFetch<{ domain: string; total_urls: number; urls: SitemapUrl[] }>(`/recon/domains/${domain}/sitemap`),
    enabled: !!domain,
  })
}

export function useReconDomainOverview(domain: string | null) {
  return useQuery({
    queryKey: ['recon-domain-overview', domain],
    queryFn: () => apiFetch<DomainOverview>(`/recon/domains/${domain}/overview`),
    enabled: !!domain,
    refetchInterval: POLL.SLOW,
  })
}

export function useServiceEnumFindings(domain: string | null) {
  return useQuery({
    queryKey: ['service-enum-findings', domain],
    queryFn: async () => {
      const email = await apiFetch<{ findings: any[] }>(`/recon/search?source=email-enum&target=${domain}&limit=20`)
      const dns = await apiFetch<{ findings: any[] }>(`/recon/search?source=dns-enum&target=${domain}&limit=20`)
      return { email: email.findings ?? [], dns: dns.findings ?? [] }
    },
    enabled: !!domain,
  })
}

// ── Screenshots (GoWitness) ────────────────────────────────

export interface ScreenshotEntry {
  path: string
  filename: string
  directory: string
  size: number
}

export interface ScreenshotsResponse {
  screenshots: ScreenshotEntry[]
  total: number
}

export function useScreenshots(search?: string) {
  const params = new URLSearchParams()
  if (search) params.set('search', search)

  return useQuery({
    queryKey: ['screenshots', search],
    queryFn: () => apiFetch<ScreenshotsResponse>(`/screenshots/list?${params}`),
    refetchInterval: POLL.SLOW,
  })
}

// ── Screenshot Metadata (TIER 8) ──

export function useScreenshotMetadata(path?: string) {
  return useQuery({
    queryKey: ['screenshot-metadata', path],
    queryFn: () => apiFetch<{ metadata: ScreenshotMetadata | null }>(`/screenshots/metadata?path=${encodeURIComponent(path!)}`),
    enabled: !!path,
  })
}

export function useAllScreenshotMetadata() {
  return useQuery({
    queryKey: ['screenshot-metadata-all'],
    queryFn: () => apiFetch<{ metadata: ScreenshotMetadata[] }>('/screenshots/metadata'),
    staleTime: 30000,
  })
}

export function useUpdateScreenshotMetadata() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      path: string; filename: string; directory?: string
      tags?: string[]; notes?: string; added_to_scope?: string
    }) => apiFetch<{ ok: boolean; metadata: ScreenshotMetadata }>('/screenshots/metadata', {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['screenshot-metadata'] })
      qc.invalidateQueries({ queryKey: ['screenshot-metadata-all'] })
    },
  })
}
