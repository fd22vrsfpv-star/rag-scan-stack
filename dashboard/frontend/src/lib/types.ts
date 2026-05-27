export interface Asset {
  id?: string
  ip: string
  os?: string
  hostname?: string
  tags?: string[]
  engagement_id?: string | null
  open_ports_count?: number
  recon_findings_count?: number
  discovered_by?: string[]
  first_seen?: string
  last_seen?: string
  // Cloud-hosting tags. Populated by ETL parsers from CNAME / TLS cert /
  // HTTP header signals — covers vanity domains the hostname doesn't reveal.
  provider?: string[]
  provider_evidence?: Record<string, string[]>
}

export interface Port {
  ip: string
  proto: string
  port: number
  service: string
  product?: string
  version?: string
  banner?: string
  os?: string
  finding_count?: number
  max_severity?: string | null
}

export interface Finding {
  id?: string
  title: string
  severity: string
  source: string
  ip?: string
  hostname?: string
  port?: number
  cve?: string
  cwe?: string
  evidence?: string
  output?: string
  url?: string
  created_at?: string
  description?: string
  solution?: string
  reference?: string
  cvss?: number
  confidence?: string
  method?: string
  tags?: string[]
}

export interface ScreenshotMetadata {
  id: string
  path: string
  filename: string
  directory?: string
  tags: string[]
  notes?: string
  added_to_scope?: string
  created_at: string
  updated_at: string
}

export interface Vuln {
  id?: string
  script: string
  output: string
  ip: string
  port: number
  proto: string
  service?: string
  product?: string
  version?: string
  created_at?: string
}

export interface ScanRecommendation {
  scanner: string
  action?: string | null
  script?: string | null
  template?: string | null
}

export interface ScanJob {
  job_id: string
  type: string
  status: string
  service_url?: string
  last_data?: Record<string, unknown>
  progress?: { stage?: string; details?: string; command?: string }
  params?: Record<string, unknown>
  created_at?: string
  completed_at?: string
  result?: unknown
  error?: string
  proxy?: string | null
  engagement_id?: string | null
  scope_name?: string | null
  target?: string | null
  targets?: string[] | null
}

export interface Exploit {
  id: string
  source?: string              // "exploitdb" | "metasploit"
  exploit_id?: string          // EDB-ID or MSF module path
  title?: string
  module_path?: string
  edb_id?: string
  exploit_type?: string        // "rce" | "sqli" | "xss" | "lfi" | "ssrf" | "other" etc.
  exploit_category?: string    // "webapp" | "network" | "local" | "dos" | "other"
  target_ip?: string
  target_port?: number
  target_service?: string
  target_version?: string
  customized_command?: string
  match_confidence?: number    // 0.0-1.0
  match_reasoning?: string
  vulnx_confirmed?: boolean    // VulnX confirmed vulnerability
  status: string               // pending|approved|rejected|executed|failed
  requested_by?: string
  metadata?: Record<string, unknown>
  cve?: string
  created_at?: string
}

export interface ExploitResult {
  id: string
  exploit_id: string
  success: boolean
  output?: string
  session_id?: string
  created_at?: string
}

export interface MsfSession {
  id: string
  type: string
  info?: string
  target_host?: string
  via_exploit?: string
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system'
  content: string
  tool_calls?: ToolCallEvent[]
}

export interface ToolCallEvent {
  name: string
  arguments: Record<string, unknown>
  result?: unknown
  status: 'executing' | 'done'
}

export interface ServiceHealth {
  status: 'healthy' | 'degraded' | 'unreachable'
  code?: number
  error?: string
}

export interface HealthResponse {
  status: string
  services: Record<string, ServiceHealth>
}

export interface FindingsResponse {
  findings: Finding[]
  total: number
  aggregations: {
    by_severity: Record<string, number>
    by_source: Record<string, number>
  }
}

export interface ReconFinding {
  id: string
  source: string
  finding_type: string
  target: string
  data: Record<string, unknown>
  severity?: string
  resolved_ip?: string
  hostname?: string
  // Cloud-hosting tags inherited from the linked asset (assets.provider).
  // Multi-valued: ['aws','azure'] when a CDN sits in front of a different-origin host.
  provider?: string[]
  provider_evidence?: Record<string, string[]>
  created_at?: string
}

export interface ReconSearchResponse {
  findings: ReconFinding[]
  total: number
  aggregations: {
    by_source: Record<string, number>
    by_finding_type: Record<string, number>
    by_provider?: Record<string, number>
  }
}

export interface Feedback {
  id: string
  rating: number
  comment?: string
  session_id?: string
  created_at?: string
}

export interface WSEvent {
  type: string
  data: Record<string, unknown>
}

export interface ScopeTarget {
  id: string
  name: string
  target: string
  target_type: string
  source: string
  added_at?: string
}

export interface ScopeResponse {
  targets: ScopeTarget[]
  total: number
  name: string
}

export interface ScopeName {
  name: string
  target_count: number
  last_updated: string
}

// Remote node types for distributed scanning
export interface RemoteNode {
  id: string
  name: string
  node_type: 'sliver' | 'chisel' | 'ssh' | 'wireguard'
  status: 'online' | 'offline' | 'degraded' | 'provisioning' | 'connecting' | 'error' | 'rotating'
  os?: string
  hostname?: string
  internal_ip?: string
  external_ip?: string
  network_segment?: string
  proxy_port?: number
  proxy_type?: string
  sliver_session_id?: string
  chisel_client_id?: string
  tunnel_method?: 'ssh' | 'wireguard' | 'hybrid'
  wg_public_key?: string
  wg_assigned_ip?: string
  wg_peer_id?: string
  capabilities?: string[]
  metadata?: Record<string, unknown>
  last_seen?: string
  first_seen?: string
  created_at?: string
  updated_at?: string
}

export interface InstallationTask {
  id: string
  node_id: string
  task_type: 'software' | 'wireguard'
  status: 'pending' | 'running' | 'completed' | 'failed'
  tools?: string[]
  progress_log: Array<{
    timestamp: string
    event: string
    tool?: string
    status?: string
    error?: string
    [key: string]: unknown
  }>
  error_message?: string
  started_at?: string
  completed_at?: string
  created_at: string
  updated_at: string
  can_close_window: boolean
}

export interface NodeScanJob {
  id: string
  node_id: string
  scan_type: string
  job_id?: string
  status: string
  targets?: unknown[]
  parameters?: Record<string, unknown>
  result_summary?: Record<string, unknown>
  error?: string
  created_at?: string
  started_at?: string
  completed_at?: string
}

export interface ADAttackResult {
  id: string
  node_id?: string
  attack_type: string
  status: string
  target_domain?: string
  tool?: string
  command_used?: string
  output?: string
  parsed_results?: Record<string, unknown>
  findings_count?: number
  error?: string
  created_at?: string
  completed_at?: string
}

export interface ADAttackType {
  id: string
  tool: string
  description: string
  category: string
  default_args: string
}

// ── Engagements (A1) ──

export interface Engagement {
  id: string
  name: string
  client?: string
  engagement_type: string
  methodology: string
  status: string
  start_date?: string
  end_date?: string
  scope_name?: string
  rules_of_engagement?: string
  notes?: string
  metadata?: Record<string, unknown>
  created_at?: string
  updated_at?: string
  stats?: {
    findings_by_severity: Record<string, number>
    asset_count: number
    scan_count: number
  }
  scopes?: { name: string; target_count: number }[]
}

// ── Finding Workflow (C1) ──

export type WorkflowStatus = 'new' | 'triaging' | 'confirmed' | 'false_positive' | 'accepted_risk' | 'in_report' | 'deferred'

export interface FindingWorkflow {
  workflow_status?: WorkflowStatus
  assigned_to?: string
  verified_by?: string
  verified_at?: string
  tester_notes?: string
  original_severity?: string
  report_ready?: boolean
  finding_source?: string
  engagement_id?: string
}

// ── Finding Activity (C2) ──

export interface FindingActivity {
  id: string
  finding_source: string
  finding_id: string
  activity_type: 'comment' | 'status_change' | 'severity_change' | 'assignment' | 'evidence_added'
  actor?: string
  old_value?: string
  new_value?: string
  comment?: string
  created_at: string
}

// ── Evidence (B1) ──

export interface Evidence {
  id: string
  engagement_id?: string
  evidence_type: string
  title: string
  description?: string
  content_type?: string
  file_size?: number
  content_hash?: string
  tags?: string[]
  uploaded_by?: string
  created_at: string
}

export interface EvidenceLink {
  id: string
  evidence_id: string
  entity_type: string
  entity_id: string
  created_at: string
}

// ── Campaign Events / Kill Chain (H1) ──

export type KillChainPhase =
  | 'reconnaissance' | 'weaponization' | 'delivery' | 'exploitation'
  | 'installation' | 'command_control' | 'actions_on_objectives'

export interface CampaignEvent {
  id: string
  engagement_id: string
  kill_chain_phase: KillChainPhase
  mitre_tactic?: string
  mitre_technique?: string
  title: string
  description?: string
  target_asset_id?: string
  exploit_result_id?: string
  node_id?: string
  timestamp: string
  detected: boolean
  detection_time?: string
  operator?: string
  metadata?: Record<string, unknown>
  created_at: string
}

// ── Credential Vault (H2) ──

export interface Credential {
  id: string
  engagement_id?: string
  username: string
  domain?: string
  credential_type: string
  credential_value?: string
  cracked_value?: string
  source: string
  source_entity_id?: string
  status: string
  access_level?: string
  grants_access_to?: string[]
  notes?: string
  created_at: string
  updated_at: string
}

// ── Scheduled Scans (I2) ──

export interface ScheduledScan {
  id: string
  engagement_id?: string
  scan_type: string
  targets: Record<string, unknown>
  parameters?: Record<string, unknown>
  scheduled_at: string
  jitter_seconds: number
  max_rate?: number
  status: string
  job_id?: string
  created_at: string
}

// ── News Intelligence ──

export type NewsStatus = 'new' | 'reviewed' | 'follow_up' | 'applies' | 'research' | 'future' | 'deleted'

export interface NewsArticle {
  source: string
  title: string
  link: string
  published?: string
  raw_excerpt?: string
}

export interface NewsAssetMatch {
  cve: string
  severity?: string | null
  asset_id: string
  ip?: string | null
  hostname?: string | null
  engagement_id?: string | null
  match_reason: string
}

export interface NewsGithubLink {
  repo: string
  url: string
  stars: number
  updated?: string
  description?: string
  language?: string | null
  topics?: string[]
}

export interface NewsItem {
  id: string
  title: string
  summary: string | null
  primary_cve: string | null
  all_cves: string[]
  status: NewsStatus
  acknowledged_by: string | null
  acknowledged_at: string | null
  kev_listed: boolean | null
  rce: boolean | null
  easily_exploitable: boolean | null
  malware_exploitable: boolean | null
  active_internet_breach: boolean | null
  patch_available: boolean | null
  articles: NewsArticle[]
  github_links: NewsGithubLink[]
  asset_matches: NewsAssetMatch[]
  first_seen: string
  last_seen: string
  enriched_at: string | null
  github_searched_at: string | null
  asset_matched_at: string | null
  notes: string | null
  tags: string[]
}

export interface NewsSource {
  id: string
  name: string
  url: string
  parser: string
  enabled: boolean
  last_fetched_at: string | null
  last_status: string | null
  last_error: string | null
  created_at: string
}

export interface NewsRun {
  id: string
  triggered_by: string
  status: 'running' | 'completed' | 'failed'
  started_at: string
  completed_at: string | null
  sources_fetched: number
  articles_seen: number
  items_new: number
  items_updated: number
  items_enriched: number
  topic: string | null
  error?: string | null
  per_source?: Array<{
    id: string
    name: string
    articles: number
    new: number
    updated: number
    error: string | null
  }>
}

export interface NewsStats {
  by_status: Record<NewsStatus, number>
  deleted: number
  kev_listed: number
  last_fetched_at: string | null
  auto_fetch_enabled: boolean
}

export interface NewsDeepSearchResult {
  topic: string
  matched_items: number
  asset_hits_total: number
  github_repos_total: number
  items: Array<{ id: string; title: string; primary_cve: string | null; asset_hits: number; github_repos: number }>
}
