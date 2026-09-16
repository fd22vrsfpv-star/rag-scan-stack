import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

// A "flow" is an enumeration/dispatch rule: fact -> propose (tool + command).
// The YAML catalogue is read-only in the container; operator-authored flows
// live in the DB overlay (custom_enumeration_rules) and are what this UI edits.
// Endpoints are served by rag-api (apiFetch prepends /api, so pass bare paths).

export interface FlowWhen {
  fact: string
  where?: Record<string, unknown>
}

export interface FlowPropose {
  tool?: string
  command: string
  priority?: number
  [k: string]: unknown
}

export interface FlowRule {
  id: string
  when: FlowWhen
  propose: FlowPropose
  why?: string
  enabled?: boolean
  engagement_id?: string | null
}

export interface FlowRulesResponse {
  yaml_rules: FlowRule[]
  custom_rules: FlowRule[]
  total: number
}

export interface FlowProposal {
  rule: string
  tool?: string
  target: string
  command: string
  matched_fact: { fact?: string; service?: string; port?: number | string }
  would_dispatch: boolean
  refused?: string
}

export interface FlowTestResult {
  target: string
  engagement_id?: string | null
  rules_tested: number
  facts: number
  matched: number
  proposals: FlowProposal[]
  refusals: FlowProposal[]
  scope: string
  error?: string
}

// Every flow: the shipped YAML catalogue plus the editable DB overlay.
export function useFlowRules() {
  return useQuery({
    queryKey: ['flow-rules'],
    queryFn: () => apiFetch<FlowRulesResponse>('/rules'),
  })
}

// DRY-RUN a candidate flow (or the whole live catalogue) against a host's real
// facts. Never queues or dispatches. Pass rule=undefined to test the catalogue.
export function useTestFlow() {
  return useMutation({
    mutationFn: (body: {
      rule?: Partial<FlowRule>
      target: string
      engagement_id?: string | null
    }) =>
      apiFetch<FlowTestResult>('/rules/test', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  })
}

// Add or update a custom flow in the DB overlay.
export function useAddFlow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (rule: FlowRule) =>
      apiFetch<{ ok: boolean; id: string; rag_loaded?: boolean }>('/rules', {
        method: 'POST',
        body: JSON.stringify(rule),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['flow-rules'] }),
  })
}

// Embed every flow (YAML + overlay) into rag_documents so the planner can
// retrieve authored dispatch rules the same way it retrieves other knowledge.
export function useSyncFlowsToRag() {
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; flows: number; rag_loaded: number }>('/rules/sync-rag', {
        method: 'POST',
      }),
  })
}

// Remove a custom flow (YAML rules are not affected).
export function useDeleteFlow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean; deleted: string }>(`/rules/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['flow-rules'] }),
  })
}
