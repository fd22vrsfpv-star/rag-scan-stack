import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface ReconCommand {
  tool: string
  purpose: string
  command: string
  template?: string
  risk: 'safe' | 'active' | 'exploit'
  has_parser: boolean
  auto_ingest_type: string | null
  category: 'tool' | 'recommendation' | 'metasploit'
}

export interface ReconNode {
  id: string
  name: string
  type: string
}

export interface ReconLookupResult {
  target: string
  port: number | null
  service: string | null
  service_description: string | null
  common_vulns: string[]
  commands: ReconCommand[]
  nodes: ReconNode[]
}

export interface ExecuteResult {
  ok: boolean
  node_id: string
  tool: string
  target: string
  command_executed: string
  stdout: string
  stderr: string
  exit_code: number | null
  ingest_result: Record<string, unknown> | null
  structured_result: {
    ok: boolean
    stats: {
      parse_method: string
      findings_inserted: number
      vulns_inserted: number
      web_findings_inserted: number
      recon_findings_inserted: number
      evidence_stored: number
      finding_ids: string[]
      errors: string[]
    }
  } | null
  duration_ms: number | null
}

export function useTargetedReconLookup(target: string, port?: number, service?: string) {
  return useQuery({
    queryKey: ['targeted-recon', target, port, service],
    queryFn: () =>
      apiFetch<ReconLookupResult>('/targeted-recon', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          port: port || undefined,
          service: service || undefined,
        }),
      }),
    enabled: !!target,
    staleTime: 60_000,
    placeholderData: (prev) => prev,
  })
}

export function useTargetedReconExecute() {
  return useMutation({
    mutationFn: (params: {
      node_id: string
      command: string
      tool_name: string
      target: string
      port?: number
      service?: string
      timeout?: number
      auto_ingest?: boolean
      engagement_id?: string
    }) =>
      apiFetch<ExecuteResult>('/targeted-recon/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      }),
  })
}
