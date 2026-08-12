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
