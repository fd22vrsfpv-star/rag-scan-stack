import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * Per-service / per-port prompt rules.
 *
 * These are injected into the LLM's tool-selection prompt whenever a matching
 * service or port is discovered, and their `training_notes` are indexed into
 * the RAG store so they can also be retrieved as context. Backed by
 * public.service_prompts via scan-recommender's /kb/prompts endpoints.
 */

export type SelectorType = 'service' | 'port' | 'port_service' | 'tech'

export interface ServicePrompt {
  id: string
  selector_type: SelectorType
  service: string | null
  /** Detected technology this rule targets (wordpress, tomcat, ...) */
  tech: string | null
  port: number | null
  title: string
  prompt: string
  training_notes: string | null
  tags: string[]
  priority: number
  enabled: boolean
  engagement_id: string | null
  rag_ingested_at: string | null
  created_at: string
  updated_at: string
}

export interface ServicePromptInput {
  selector_type: SelectorType
  title: string
  prompt: string
  service?: string | null
  tech?: string | null
  port?: number | null
  training_notes?: string | null
  tags?: string[]
  priority?: number
  enabled?: boolean
  engagement_id?: string | null
}

/** What the LLM would actually receive for a given (service, port). */
export interface ResolvedPrompts {
  service: string | null
  port: number | null
  tech?: string[]
  matched: Array<Pick<ServicePrompt, 'id' | 'selector_type' | 'service' | 'tech' | 'port' | 'title' | 'prompt' | 'priority' | 'engagement_id'>>
  guidance_block: string
  training_context: string
}

export function useServicePrompts() {
  return useQuery({
    queryKey: ['service-prompts'],
    queryFn: () => apiFetch<{ prompts: ServicePrompt[] }>('/kb/prompts'),
    staleTime: 15_000,
  })
}

/** Preview panel — runs the same resolution the LLM path uses. */
export function useResolvePrompts(
  service: string, port: string, tech: string, enabled: boolean,
) {
  const params = new URLSearchParams()
  if (service) params.set('service', service)
  if (port) params.set('port', port)
  if (tech) params.set('tech', tech)
  return useQuery({
    queryKey: ['service-prompts-resolve', service, port, tech],
    queryFn: () => apiFetch<ResolvedPrompts>(`/kb/prompts/resolve?${params.toString()}`),
    enabled: enabled && (!!service || !!port || !!tech),
  })
}

function invalidate(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['service-prompts'] })
  qc.invalidateQueries({ queryKey: ['service-prompts-resolve'] })
}

export function useCreateServicePrompt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: ServicePromptInput) =>
      apiFetch<{ ok: boolean; id: string }>('/kb/prompts', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => invalidate(qc),
  })
}

export function useUpdateServicePrompt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: ServicePromptInput }) =>
      apiFetch<{ ok: boolean; id: string }>(`/kb/prompts/${id}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    onSuccess: () => invalidate(qc),
  })
}

export function useDeleteServicePrompt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean }>(`/kb/prompts/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidate(qc),
  })
}

/** Human-readable selector, e.g. "http on 8080". */
export function describeSelector(p: Pick<ServicePrompt, 'selector_type' | 'service' | 'tech' | 'port'>): string {
  switch (p.selector_type) {
    case 'port_service': return `${p.service} on ${p.port}`
    case 'tech':         return `tech: ${p.tech}`
    case 'port':         return `port ${p.port}`
    default:             return p.service ?? '—'
  }
}

/* ────────────── Walkthrough → drafted rules ────────────── */

export interface DraftedFlag {
  kind: 'prompt' | 'service_doc'
  index: number
  title: string | null
  reasons: string[]
}

/**
 * What the second pass did. The first pass asks the model to find everything in a
 * chunk, which a local model does unreliably; whatever it missed is then re-asked
 * for one service at a time.
 */
export interface GapPassReport {
  /** Services re-asked individually. Empty when the first pass missed nothing. */
  attempted: string[]
  recovered: number
  /** Missed services beyond WALKTHROUGH_GAP_MAX — reported, not silently dropped. */
  skipped_cap: number
}

/** Which services the source mentions vs. which became rules. `{}` if the KB is down. */
export interface CoverageReport {
  mentioned?: string[]
  covered?: string[]
  missed?: string[]
  skipped?: Array<{ service?: string; tech?: string; reason?: string }>
  coverage_pct?: number
  rules_total?: number
  /** Rules for things the KB has no name for (e.g. dvwa) — covered, but uncounted above. */
  rules_outside_kb_vocabulary?: string[]
}

export interface WalkthroughConversion {
  ok: boolean
  source: string
  model: string
  prompts: ServicePromptInput[]
  coverage?: CoverageReport
  gap_pass?: GapPassReport
  service_docs: Array<Record<string, unknown>>
  /** Entries that look box-specific (credentials, flags, lab IPs) — review before accepting. */
  flagged: DraftedFlag[]
  rejected: Array<{ entry: string; reason: string }>
  existing_considered: Array<Record<string, unknown>>
  /** Ready-to-import seed file, with flagged entries commented out. */
  yaml: string
}

/**
 * Draft rules from a walkthrough. Returns proposals only — nothing is written
 * until the operator accepts individual entries.
 */
export function useConvertWalkthrough() {
  return useMutation({
    mutationFn: (body: {
      content: string; filename?: string; focus?: string
      include_existing?: boolean
      /** Defaults to true server-side. Off trades coverage for a much shorter run. */
      gap_pass?: boolean
    }) =>
      apiFetch<WalkthroughConversion>('/kb/walkthrough/convert', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  })
}

export interface WalkthroughPrompt {
  prompt: string
  default: string
  using_custom: boolean
  default_path: string
  default_available: boolean
}

export function useWalkthroughPrompt() {
  return useQuery({
    queryKey: ['walkthrough-prompt'],
    queryFn: () => apiFetch<WalkthroughPrompt>('/kb/walkthrough-prompt'),
    staleTime: 60_000,
  })
}

/** Save a guiding-prompt override. An empty string reverts to the shipped default. */
export function useSetWalkthroughPrompt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (prompt: string) =>
      apiFetch<{ ok: boolean; using_custom: boolean }>('/kb/walkthrough-prompt', {
        method: 'PUT',
        body: JSON.stringify({ prompt }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['walkthrough-prompt'] }),
  })
}

/** Result of importing a published guide by URL. Extends the walkthrough shape. */
export interface UrlConversion extends WalkthroughConversion {
  url: string
  pages: Array<{ url: string; title: string; chars: number }>
  fetch_errors: Array<{ url: string; error: string }>
  /** Cleaned prose for knowledge/playbooks/ — returned, not written (the mount is read-only). */
  playbook_markdown: string
  playbook_filename: string
  seed_filename: string
}

/**
 * Fetch a published guide and draft knowledge from it. Returns proposals only.
 *
 * The server refuses private/loopback/metadata addresses unless allow_internal
 * is set, and re-validates every redirect hop.
 */
export function useConvertUrl() {
  return useMutation({
    mutationFn: (body: {
      url: string; depth?: number; max_pages?: number
      allow_internal?: boolean; focus?: string; make_playbook?: boolean
      /** Defaults to true server-side. Off trades coverage for a much shorter run. */
      gap_pass?: boolean
    }) =>
      apiFetch<UrlConversion>('/kb/url/convert', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  })
}

/* ────────────── Validator catalog ────────────── */

export interface ToolCatalogInfo {
  path: string
  exists: boolean
  counts: Record<string, number>
  /** ISO timestamp of the last refresh, or null when the catalog is missing. */
  generated_at: string | null
  /** Seconds since generation. The catalog cannot detect its own staleness. */
  age_seconds: number | null
  /** Only these scanners are gated; everything else passes unvalidated. */
  validated_scanners: string[]
  supplement: {
    path: string | null
    exists: boolean
    counts: Record<string, number>
    notes?: string[]
    error?: string
  }
  nodes?: Array<{ name: string; status: string; tools: number }>
  error?: string
}

/**
 * What the recommendation validator knows, and how old that knowledge is.
 *
 * The catalog is a deliberate snapshot — validation must not require live
 * containers — so it goes stale silently unless someone re-runs the refresh.
 */
export function useToolCatalog() {
  return useQuery({
    queryKey: ['tool-catalog'],
    queryFn: () => apiFetch<ToolCatalogInfo>('/kb/tool-catalog'),
    staleTime: 30_000,
  })
}
