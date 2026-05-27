import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { FindingsResponse, FindingActivity, WorkflowStatus } from '@/lib/types'
import { POLL } from '@/lib/polling'

export interface FindingsFilter {
  severity?: string[]
  source?: string[]
  ip?: string
  cve?: string
  search?: string
  port?: number
  workflow_status?: string[]
  engagement_id?: string
  tags?: string[]
  limit?: number
  offset?: number
}

export function useFindings(filters: FindingsFilter = {}) {
  const params = new URLSearchParams()
  if (filters.severity?.length) filters.severity.forEach(s => params.append('severity', s))
  if (filters.source?.length) filters.source.forEach(s => params.append('source', s))
  if (filters.ip) params.set('ip', filters.ip)
  if (filters.cve) params.set('cve', filters.cve)
  if (filters.search) params.set('search', filters.search)
  if (filters.port) params.set('port', String(filters.port))
  if (filters.workflow_status?.length) filters.workflow_status.forEach(s => params.append('workflow_status', s))
  if (filters.engagement_id) params.set('engagement_id', filters.engagement_id)
  if (filters.tags?.length) filters.tags.forEach(t => params.append('tags', t))
  params.set('limit', String(filters.limit ?? 100))
  params.set('offset', String(filters.offset ?? 0))

  return useQuery({
    queryKey: ['findings', filters],
    queryFn: () => apiFetch<FindingsResponse>(`/findings?${params}`),
    refetchInterval: POLL.NORMAL,
  })
}

export function useVulns(ip?: string) {
  const params = ip ? `?ip=${encodeURIComponent(ip)}` : ''
  return useQuery({
    queryKey: ['vulns', ip],
    queryFn: () => apiFetch<{ vulns: unknown[] }>(`/vulns${params}`),
  })
}

// ── Finding Workflow (C1) ──

export function useUpdateFindingWorkflow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ source, id, ...data }: {
      source: string; id: string
      workflow_status?: WorkflowStatus
      assigned_to?: string
      verified_by?: string
      tester_notes?: string
      original_severity?: string
      report_ready?: boolean
    }) => apiFetch(`/findings/${source}/${id}/workflow`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  })
}

// ── Finding Activity (C2) ──

export function useFindingActivity(source?: string, id?: string) {
  return useQuery({
    queryKey: ['finding-activity', source, id],
    queryFn: () => apiFetch<{ activity: FindingActivity[] }>(`/findings/${source}/${id}/activity`),
    enabled: !!source && !!id,
  })
}

export function useAddFindingComment() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ source, id, comment, actor }: {
      source: string; id: string; comment: string; actor?: string
    }) => apiFetch(`/findings/${source}/${id}/comments`, {
      method: 'POST',
      body: JSON.stringify({ comment, actor }),
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['finding-activity'] }),
  })
}

// ── Exploit Matching (J2) ──

export function useExploitMatches(source?: string, id?: string) {
  return useQuery({
    queryKey: ['exploit-matches', source, id],
    queryFn: () => apiFetch<{ matches: unknown[]; finding: unknown }>(
      `/findings/${source}/${id}/exploit-matches`
    ),
    enabled: !!source && !!id,
  })
}

// ── Scope Intelligence (E1) ──

export interface ScopeIntelSubdomain {
  name: string
  resolved_ip: string
  first_seen: string
}

export interface ScopeIntelDnsEntry {
  target: string
  values: string[] | unknown
  data: Record<string, unknown>
}

export interface ScopeIntelHttpService {
  url: string
  status_code: string | number
  title: string
  webserver: string
  tech: string[]
  content_length: string | number
  created_at: string
}

export interface ScopeIntelTlsCert {
  host: string
  subject_cn: string
  issuer: string
  not_after: string
  not_before: string
  serial: string
}

export interface ScopeIntelCtCert {
  common_name: string
  issuer_name: string
  not_after: string
  serial: string
}

export interface ScopeIntelAsnMapping {
  ip: string
  asn: string | number
  org: string
  country: string
  cidr: string
}

export interface ScopeIntelWafDetection {
  url: string
  detected: boolean
  firewall: string
  manufacturer: string
  created_at: string
}

export interface ScopeIntelWhoisRecord {
  domain: string
  registrar: string
  org: string
  creation_date: string
  expiry_date: string
  name_servers: string[]
  registrant_name: string
  registrant_email: string
  registrant_country: string
  dnssec: string
  status: string[]
  created_at: string
}

export interface ScopeIntelligenceData {
  scope_name: string
  stats: {
    total_findings: number
    first_seen: string | null
    last_seen: string | null
    by_source: Record<string, number>
  }
  domains: string[]
  subdomains: ScopeIntelSubdomain[]
  dns_records: Record<string, ScopeIntelDnsEntry[]>
  http_services: ScopeIntelHttpService[]
  tls_certs: ScopeIntelTlsCert[]
  ct_certs: ScopeIntelCtCert[]
  asn_mappings: ScopeIntelAsnMapping[]
  whois_records: ScopeIntelWhoisRecord[]
  waf_detections: ScopeIntelWafDetection[]
  ip_addresses: string[]
  technologies: Array<{ name: string; count: number }>
  open_services: Record<string, number>
}

export function useScopeIntelligence(scopeName?: string) {
  return useQuery({
    queryKey: ['scope-intelligence', scopeName],
    queryFn: () => apiFetch<ScopeIntelligenceData>(`/scope/${scopeName}/intelligence`),
    enabled: !!scopeName,
  })
}

// ── Scope Analysis (Red Team Recon) ──

export interface PrioritizedTarget {
  target: string
  ip: string | null
  port: number | null
  service: string | null
  reasons: string[]
  priority: 'high' | 'medium' | 'low'
  category: string
  tech: string[]
}

export interface SuggestedStep {
  scan_type: string
  target: string | null
  rationale: string
  stealth_level: 'passive' | 'low' | 'medium'
  tool: string
}

export interface InterestingService {
  host: string
  port: number
  service: string
  product: string | null
  version: string | null
  banner: string | null
  interest_reason: string
  tech: string[]
}

export interface SensitivePage {
  url: string
  page_type: string
  evidence: string
  source: string
  tech: string[]
}

export interface LoginPageEntry {
  url: string
  form_action: string | null
  fields: string[]
  has_csrf: boolean
  source: string
  tech: string[]
}

export interface OutOfScopeCandidate {
  target: string
  reason: string
}

export interface ScopeAnalysisData {
  scope_name: string
  prioritized_targets: PrioritizedTarget[]
  suggested_next_steps: SuggestedStep[]
  interesting_services: InterestingService[]
  sensitive_pages: SensitivePage[]
  login_pages: LoginPageEntry[]
  out_of_scope_candidates: OutOfScopeCandidate[]
  technology_index: Record<string, { urls: string[]; ips: string[]; subdomains: string[] }>
}

export function useScopeAnalysis(scopeName?: string) {
  return useQuery({
    queryKey: ['scope-analysis', scopeName],
    queryFn: () => apiFetch<ScopeAnalysisData>(`/scope/${scopeName}/analysis`),
    enabled: !!scopeName,
  })
}

export function useExcludeFromScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ targets, source = 'manual' }: { targets: string[]; source?: string }) =>
      apiFetch<{ ok: boolean }>('/scope/exclude', {
        method: 'POST',
        body: JSON.stringify({ targets, source }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope-analysis'] })
      qc.invalidateQueries({ queryKey: ['scope-intelligence'] })
    },
  })
}

export function useExcludedTargets() {
  return useQuery({
    queryKey: ['scope-excluded'],
    queryFn: () => apiFetch<{ excluded: Array<{ target: string; source: string; added_at: string }> }>('/scope/excluded'),
  })
}

// ── Finding Tags (TIER 8) ──

export function useUpdateFindingTags() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ source, id, tags, action = 'set' }: {
      source: string; id: string; tags: string[]; action?: 'set' | 'add' | 'remove'
    }) => apiFetch<{ ok: boolean; tags: string[] }>(`/findings/${source}/${id}/tags`, {
      method: 'PATCH',
      body: JSON.stringify({ tags, action }),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['finding-activity'] })
    },
  })
}

export function useTagSuggestions() {
  return useQuery({
    queryKey: ['tag-suggestions'],
    queryFn: () => apiFetch<{ tags: string[]; predefined: string[] }>('/tags/suggestions'),
    staleTime: 60000,
  })
}

export function useDeleteFindings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (ids: string[]) =>
      apiFetch<{ ok: boolean; deleted: number }>('/findings/bulk', {
        method: 'DELETE',
        body: JSON.stringify({ ids }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  })
}

export function useDeleteReconFindings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (ids: string[]) =>
      apiFetch<{ ok: boolean; deleted: number }>('/recon/findings/bulk', {
        method: 'DELETE',
        body: JSON.stringify({ ids }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['recon'] })
      qc.invalidateQueries({ queryKey: ['recon-domains'] })
    },
  })
}

export function useAssignToScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ scopeName, targets }: { scopeName: string; targets: { target: string; target_type?: string }[] }) =>
      apiFetch<{ ok: boolean; added: number }>('/scope/add', {
        method: 'POST',
        body: JSON.stringify({ name: scopeName, targets: targets.map(t => ({ target: t.target, target_type: t.target_type || 'domain', source: 'manual' })) }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope'] })
      qc.invalidateQueries({ queryKey: ['scope-names'] })
      qc.invalidateQueries({ queryKey: ['recon-domains'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}

export function useMoveToScope() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ fromScope, toScope, targets }: { fromScope: string; toScope: string; targets: string[] }) =>
      apiFetch<{ ok: boolean; removed: number; added: number }>('/scope/move', {
        method: 'POST',
        body: JSON.stringify({ from_scope: fromScope, to_scope: toScope, targets }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope'] })
      qc.invalidateQueries({ queryKey: ['scope-names'] })
      qc.invalidateQueries({ queryKey: ['recon-domains'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['recon'] })
    },
  })
}
