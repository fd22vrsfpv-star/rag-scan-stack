import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Asset, Port, Vuln, ScanRecommendation } from '@/lib/types'
import { POLL } from '@/lib/polling'

export function useAssets(limit = 100, assetKind?: 'hosts-only' | 'cloud-only') {
  const params = new URLSearchParams({ limit: String(limit) })
  if (assetKind) params.set('asset_kind', assetKind)

  return useQuery({
    queryKey: ['assets', limit, assetKind],
    queryFn: () => apiFetch<{ count: number; assets: Asset[] }>(`/assets?${params.toString()}`),
    refetchInterval: POLL.NORMAL,
  })
}

export function useAssetPorts(ip: string) {
  return useQuery({
    queryKey: ['asset-ports', ip],
    queryFn: () => apiFetch<{ count: number; items: Port[] }>(`/assets/${encodeURIComponent(ip)}/ports`),
    enabled: !!ip,
  })
}

export function useAssetVulns(ip: string) {
  return useQuery({
    queryKey: ['asset-vulns', ip],
    queryFn: () => apiFetch<{ vulns: Vuln[] }>(`/assets/${encodeURIComponent(ip)}/vulns`),
    enabled: !!ip,
  })
}

export interface Subdomain {
  subdomain: string
  parent_domain: string
  resolved_ip: string
  discovery_source: string
  created_at: string
}

export function useSubdomains(domain?: string) {
  const params = new URLSearchParams()
  if (domain) params.set('domain', domain)
  const qs = params.toString()
  return useQuery({
    queryKey: ['subdomains', domain],
    queryFn: () => apiFetch<{ count: number; subdomains: Subdomain[] }>(
      `/recon/subdomains${qs ? '?' + qs : ''}`
    ),
    refetchInterval: POLL.NORMAL,
  })
}

export function usePortRecommendations(ip: string, service?: string, banner?: string, port?: number) {
  const params = new URLSearchParams()
  if (service) params.set('service', service)
  if (banner) params.set('banner', banner)
  if (port) params.set('port', String(port))
  const qs = params.toString()
  return useQuery({
    queryKey: ['port-recommendations', ip, service, banner, port],
    queryFn: () => apiFetch<{ recommendations: ScanRecommendation[] }>(
      `/assets/${encodeURIComponent(ip)}/recommendations${qs ? '?' + qs : ''}`
    ),
    enabled: !!ip && !!service,
    staleTime: 60_000,
  })
}

export interface StoredRecommendation {
  id: string
  ip: string | null
  service: string | null
  banner: string | null
  scanner: string
  action: string | null
  script: string | null
  template: string | null
  source: string
  confidence: number | null
  priority: number
  status: string
  executed_at: string | null
  created_at: string
  purpose_group?: string | null
}

export function useScanRecommendations(status = 'pending', engagementId?: string | null) {
  // The active engagement reaches scan_recommender via the X-Engagement-Id
  // header (apiFetch → BFF → engagement_headers()), which scopes the result
  // server-side. engagementId is included in the queryKey so switching
  // engagements busts the cache and refetches immediately.
  return useQuery({
    queryKey: ['scan-recommendations', status, engagementId ?? null],
    queryFn: () => apiFetch<{ recommendations: StoredRecommendation[]; total: number }>(
      `/scan-recommendations?status=${status}`
    ),
    refetchInterval: POLL.NORMAL,
  })
}

// Generate recommendations on demand for all currently-detected open ports
// that don't have one yet (no time window). Populates the scan_recommendations
// table so suggested scans can be dispatched against ports scanned earlier.
export function useGenerateRecommendations() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (ip?: string) =>
      apiFetch<{ ok: boolean; ports_considered: number; generated: number }>(
        `/recommendations/generate${ip ? `?ip=${encodeURIComponent(ip)}` : ''}`,
        { method: 'POST' },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-recommendations'] }),
  })
}

// ---- KB tool-recommend (per-port "Suggest from KB" modal) ----
//
// Backed by the BFF proxy GET /api/rag/tools/recommend which forwards to
// scan_recommender's /rag/tools/recommend.  Returns structured tool
// suggestions plus an optional RAG playbook excerpt for the service.

export interface KbToolSuggestion {
  name: string
  purpose: string
  command?: string | null
}
export interface KbMetasploitModule {
  module: string
  purpose?: string | null
}
export interface KbToolRecommendation {
  service: string
  description?: string | null
  common_ports: number[]
  port_used?: number | null
  tools: KbToolSuggestion[]
  metasploit: KbMetasploitModule[]
  nuclei_tags: string[]
  common_vulns: string[]
  rag_context?: string | null
  error?: string | null
}

export function useKbToolRecommend(
  service: string | undefined,
  port: number | undefined,
  enabled: boolean = true,
) {
  const params = new URLSearchParams()
  if (service) params.set('service', service)
  if (port !== undefined) params.set('port', String(port))
  return useQuery({
    queryKey: ['rag-tools-recommend', service ?? '', port ?? ''],
    queryFn: () => apiFetch<KbToolRecommendation>(
      `/rag/tools/recommend?${params.toString()}`
    ),
    enabled: enabled && (!!service || port !== undefined),
    staleTime: 30_000,
  })
}

// ---- POST /api/scan-recommendations (KB-driven manual add) ----
//
// Materializes one of the KbToolRecommendation suggestions as a stored
// scan_recommendations row with source='kb_manual'.  Dedupes via the
// fingerprint column on the BFF side -- a second add of the same target
// + tool returns the existing row instead of creating a duplicate.

export interface AddScanRecommendationPayload {
  ip: string
  port?: number
  service?: string
  scanner: string
  action?: string
  script?: string
  template?: string
  priority?: number
  extra?: Record<string, unknown>
}
export interface AddScanRecommendationResponse {
  ok: boolean
  created: boolean   // false when fingerprint dedup hit an existing row
  id: string
  status: string
  created_at: string | null
}

export function useAddScanRecommendation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: AddScanRecommendationPayload) =>
      apiFetch<AddScanRecommendationResponse>('/scan-recommendations', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-recommendations'] })
    },
  })
}

export function useDeleteAssets() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (ips: string[]) =>
      apiFetch<{ ok: boolean; deleted: number }>('/assets', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}

// ── credential_findings.metadata.audit shape ──────────────────────────────
//
// Populated by the credential-check path
// (nmap_scanner/cred_checker.check_default_credentials).  Captures the
// per-attempt audit trail so AssetBrowser → Credentials can show
// "here's what we tried, what failed, and why" alongside each row.
//
// Brutus-runner rows do NOT have this field (brutus is a Go binary
// that doesn't expose per-attempt detail).  The expander handles
// absent audit gracefully.

export interface CredentialAttempt {
  username: string
  password_masked: string  // e.g. "msf*****"; full password lives only in the in-memory job record
  success: boolean
  failure_mode: string | null  // "kex_mismatch" | "connection_error" | "auth_failed" | "timeout" | "unknown"
  error_excerpt: string | null
}

export interface CredentialMethodAudit {
  method: string                       // "hydra" | "nmap"
  script?: string | null               // populated when method=="nmap" with the NSE script used
  attempts: CredentialAttempt[]
  kex_legacy_detected?: boolean        // hydra-only signal
  unsupported_service?: string | null  // populated when the service had no module map
}

export interface CredentialAudit {
  credential_source: string                 // e.g. "cred_checker:default_credentials_dict"
  users_tried: string[]
  passwords_tried_masked: string[]
  credentials_tested: number
  methods_used: string[]                    // ordered, e.g. ["hydra"] or ["hydra","nmap"]
  method_audits: CredentialMethodAudit[]
  kex_legacy_detected: boolean              // OR of per-method signals
  fell_back_to_nmap: boolean
  summary: string                           // human-readable
}

export interface CredentialMetadata {
  job_id?: string
  audit?: CredentialAudit
  // Other keys (e.g. node_id from manual KB-driven dispatch) may appear too.
  [key: string]: unknown
}

export interface CredentialFinding {
  id: string
  ip: string
  port: number
  protocol: string
  username: string
  valid_cred: boolean
  auth_type: string
  secret_type: string
  severity: string
  banner: string | null
  source: string
  status: string
  discovered_at: string | null
  last_verified_at: string | null
  duration_ms: number | null
  metadata: CredentialMetadata
  created_at: string
}

export function useAllCredentials(status?: string, protocol?: string, source?: string) {
  const params = new URLSearchParams()
  if (status) params.set('status', status)
  if (protocol) params.set('protocol', protocol)
  if (source) params.set('source', source)
  const qs = params.toString()
  return useQuery({
    queryKey: ['all-credentials', status, protocol, source],
    queryFn: () => apiFetch<{ count: number; credentials: CredentialFinding[] }>(
      `/credentials${qs ? '?' + qs : ''}`
    ),
    refetchInterval: POLL.NORMAL,
  })
}

export function useAssetCredentials(ip: string) {
  return useQuery({
    queryKey: ['asset-credentials', ip],
    queryFn: () => apiFetch<{ credentials: CredentialFinding[] }>(`/assets/${encodeURIComponent(ip)}/credentials`),
    enabled: !!ip,
  })
}

export interface CreateCredentialParams {
  ip?: string
  port?: number
  protocol?: string
  username?: string
  secret_value?: string
  secret_type?: string
  status?: string
  source?: string
  banner?: string
}

export function useCreateCredential() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: CreateCredentialParams) => {
      const qs = new URLSearchParams()
      if (params.ip) qs.set('ip', params.ip)
      if (params.port !== undefined) qs.set('port', String(params.port))
      if (params.protocol) qs.set('protocol', params.protocol)
      if (params.username) qs.set('username', params.username)
      if (params.secret_value) qs.set('secret_value', params.secret_value)
      if (params.secret_type) qs.set('secret_type', params.secret_type)
      if (params.status) qs.set('status', params.status)
      if (params.source) qs.set('source', params.source)
      if (params.banner) qs.set('banner', params.banner)
      return apiFetch<CredentialFinding>(`/credentials?${qs.toString()}`, { method: 'POST' })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['all-credentials'] })
      qc.invalidateQueries({ queryKey: ['asset-credentials'] })
    },
  })
}

export function useDeleteCredential() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean; deleted: string }>(`/credentials/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['all-credentials'] })
      qc.invalidateQueries({ queryKey: ['asset-credentials'] })
    },
  })
}

export function useUpdateCredentialStatus() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch<CredentialFinding>(`/credential-findings/${id}/status?status=${status}`, {
        method: 'PATCH',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['asset-credentials'] })
      qc.invalidateQueries({ queryKey: ['all-credentials'] })
    },
  })
}

export interface PurgeResult {
  ok?: boolean
  dry_run?: boolean
  domain: string
  total_rows?: number
  total_deleted?: number
  tables: Record<string, number>
}

export function usePurgeDomain() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ domain, dryRun }: { domain: string; dryRun: boolean }) =>
      apiFetch<PurgeResult>(`/targets/${encodeURIComponent(domain)}?dry_run=${dryRun}`, {
        method: 'DELETE',
      }),
    onSuccess: (_, { dryRun }) => {
      if (!dryRun) {
        qc.invalidateQueries({ queryKey: ['assets'] })
        qc.invalidateQueries({ queryKey: ['subdomains'] })
        qc.invalidateQueries({ queryKey: ['all-credentials'] })
      }
    },
  })
}

export function useDeleteSubdomains() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (subdomains: string[]) =>
      apiFetch<{ ok: boolean; deleted: number }>('/recon/subdomains', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subdomains }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['subdomains'] })
    },
  })
}

export interface PurgePatternResult {
  ok: boolean
  pattern: string
  dry_run: boolean
  total: number
  details: Record<string, number | string>
}

export function usePurgePattern() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ pattern, dry_run }: { pattern: string; dry_run: boolean }) =>
      apiFetch<PurgePatternResult>('/purge/pattern', {
        method: 'DELETE',
        body: JSON.stringify({ pattern, dry_run }),
      }),
    onSuccess: (_, vars) => {
      if (!vars.dry_run) {
        qc.invalidateQueries({ queryKey: ['assets'] })
        qc.invalidateQueries({ queryKey: ['subdomains'] })
        qc.invalidateQueries({ queryKey: ['findings'] })
        qc.invalidateQueries({ queryKey: ['recon'] })
        qc.invalidateQueries({ queryKey: ['recon-domains'] })
      }
    },
  })
}

export interface CveFlag {
  title: string
  severity: string
  reason: string
  tags: string[] | null
  status?: string
}

export interface DetectedSoftware {
  ip: string
  hostname: string | null
  port: number | null
  protocol: string | null
  product: string
  version: string | null
  source: string
  detection_type: string
  first_seen: string
  last_seen: string
  occurrence_count?: number
  cve_flags?: CveFlag[]
}

export interface SoftwareSummary {
  asset_count: number
  product_count: number
  total_detections: number
  source_count: number
}

export function useDetectedSoftware(search?: string, product?: string, source?: string) {
  const params = new URLSearchParams()
  if (search) params.set('search', search)
  else if (product) params.set('product', product)
  if (source) params.set('source', source)
  const qs = params.toString()
  return useQuery({
    queryKey: ['detected-software', search, product, source],
    queryFn: () => apiFetch<{ count: number; summary: SoftwareSummary; items: DetectedSoftware[] }>(
      `/software${qs ? '?' + qs : ''}`
    ),
    refetchInterval: POLL.NORMAL,
  })
}

// ── Software exploit lookup ──

export interface SearchsploitResult {
  id: string
  title: string
  type: string
  platform: string
  verified: boolean
  date: string
  codes: string
  edb_url: string
  applies?: boolean | null
  ai_severity?: string
  ai_reason?: string
}

export function useSearchsploit(product?: string, version?: string, analyze?: boolean, targetVersion?: string) {
  const params = new URLSearchParams()
  if (product) params.set('product', product)
  if (version) params.set('version', version)
  if (targetVersion) params.set('target_version', targetVersion)
  if (analyze) params.set('analyze', 'true')
  return useQuery({
    queryKey: ['searchsploit', product, version, analyze, targetVersion],
    queryFn: () => apiFetch<{ product: string; version: string; count: number; analyzed: boolean; used_cache: boolean; cached_cves: Array<{cve_id: string; summary: string; cvss: number | null}>; exploits: SearchsploitResult[]; inventory_flagged: number }>(
      `/software/searchsploit?${params.toString()}`
    ),
    enabled: !!product,
  })
}

export function getDdgSearchUrls(product: string, version?: string) {
  const q = `${product} ${version || ''}`.trim().replace(/ /g, '+')
  // Short product name for vendor-specific searches
  const words = product.split(' ').filter(w => w.length >= 4 && !['server', 'data', 'center', 'cloud'].includes(w.toLowerCase()))
  const short = words[words.length - 1] || product
  const shortQ = `${short}+${version || ''}`.replace(/ /g, '+')
  return [
    { label: 'Exploits', url: `https://duckduckgo.com/?q=${q}+exploit` },
    { label: 'CVEs', url: `https://duckduckgo.com/?q=${q}+CVE` },
    { label: 'ExploitDB', url: `https://duckduckgo.com/?q=site%3Aexploit-db.com+${q}` },
    { label: 'Tenable', url: `https://www.tenable.com/plugins/search?q=${shortQ}` },
    { label: 'Releases', url: `https://duckduckgo.com/?q=${shortQ}+release+notes` },
  ]
}

export interface DdgAnalysisResult {
  title: string
  url: string
  cve_id?: string
  severity?: string
  relevance?: number
  applies?: boolean | string
  probability?: number
  reason?: string
}

export interface DdgSearchResponse {
  product: string
  version: string
  version_date_info?: {
    release_date?: string
    release_year?: number
    release_url?: string
    copyright_years?: string[]
    version_year_hint?: number
    estimated_release_year?: number
  }
  query: string
  quick_links: Array<{ label: string; url: string }>
  nvd_cves?: Array<{ cve_id: string; summary: string; cvss: number | null; source?: string; url?: string }>
  nvd_count?: number
  vendor_sources?: { found: boolean; cve_count: number; pages_scraped: number; urls: string[]; note: string }
  raw_results: Array<{ title: string; url: string; snippet: string }>
  analysis: DdgAnalysisResult[]
  confirmed_cves?: string[]
  likely_cves?: string[]
  nuclei_templates?: Array<{ id: string; template_path: string; severity: string; tags: string; description: string }>
  nuclei_recs_created?: number
  github_pocs?: Array<{ repo: string; url: string; stars: number; updated: string; description: string; language: string | null; topics: string[] }>
  count: number
  inventory_flagged?: number
}

export function useDdgSearch(product?: string, version?: string) {
  return useQuery({
    queryKey: ['ddg-search', product, version],
    queryFn: () => apiFetch<DdgSearchResponse>(
      `/software/ddg-search?product=${encodeURIComponent(product!)}&version=${encodeURIComponent(version || '')}`
    ),
    enabled: false,  // manual trigger only
  })
}

export interface ResearchCacheEntry {
  source: string
  results: any
  cve_ids: string[]
  created_at: string
  updated_at: string
}

export function useResearchCache(product?: string, version?: string) {
  return useQuery({
    queryKey: ['research-cache', product, version],
    queryFn: () => apiFetch<{ product: string; version: string; entries: ResearchCacheEntry[]; has_cache: boolean }>(
      `/software/research-cache?product=${encodeURIComponent(product!)}&version=${encodeURIComponent(version || '')}`
    ),
    enabled: !!product,
  })
}

export interface VulnxFinding {
  id: string
  title: string
  severity: string
  cve: string[]
  product: string
  version: string
  port: string
  cvss_score: number
  ip: string
  hostname: string
  created_at: string
  output: string
}

export interface VulnxCveSummary {
  cve_id: string
  cvss_score: number
  severity: string
  affected_assets: Array<{
    ip: string
    hostname: string
    port: string
    product: string
    version: string
  }>
}

export function useVulnxFindings(product: string, version?: string, ip?: string) {
  return useQuery({
    queryKey: ['vulnx-findings', product, version || '', ip || ''],
    queryFn: () => {
      const params = new URLSearchParams({ product })
      if (version) params.set('version', version)
      if (ip) params.set('ip', ip)
      return apiFetch<{
        product: string
        version: string
        total_findings: number
        unique_cves: number
        findings: VulnxFinding[]
        cve_summary: VulnxCveSummary[]
      }>(`/software/vulnx-findings?${params.toString()}`)
    },
    enabled: !!product,
  })
}

export interface BulkDismissParams {
  product?: string
  cve_year_before?: number
  title_contains?: string
  reason: string
  engagement_id?: string
}

export function useBulkDismissSoftware() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: BulkDismissParams) =>
      apiFetch<{ ok: boolean; dismissed: number; feedback_created: number; message: string }>(
        '/software/bulk-dismiss',
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params) },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['detected-software'] })
      qc.invalidateQueries({ queryKey: ['follow-ups'] })
    },
  })
}

export interface CveTuning {
  age_penalty_2yr: number
  age_penalty_3yr: number
  age_penalty_5yr: number
  min_confidence_threshold: number
  skip_products: string
  extra_aliases: string
}

export function useCveTuning() {
  return useQuery({
    queryKey: ['cve-tuning'],
    queryFn: () => apiFetch<{ tuning: CveTuning }>('/software/cve-tuning'),
  })
}

export function useUpdateCveTuning() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: Partial<CveTuning>) =>
      apiFetch<{ ok: boolean; updated: Partial<CveTuning> }>(
        '/software/cve-tuning',
        { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params) },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cve-tuning'] })
      qc.invalidateQueries({ queryKey: ['detected-software'] })
    },
  })
}
