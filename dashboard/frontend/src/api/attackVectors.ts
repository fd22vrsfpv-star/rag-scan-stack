import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

export interface AttackVector {
  technique: string
  technique_name?: string
  tactic?: string
  severity?: string
  risk_score: number
  finding_count?: number
  finding_source?: string
  target?: string
  asset_id?: string
  finding_id?: string
  rationale?: string
  risk_factors?: Record<string, number>
}

export interface AttackGraphNode { id: string; type: string; label: string; risk: number }
export interface AttackGraphEdge { from: string; to: string; type?: string; risk: number }
export interface AttackGraph { nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; count: number }

export function useAttackVectors(minRisk = 0, limit = 100, engagementId?: string | null) {
  // engagementId is included in the queryKey so switching the active engagement
  // immediately refetches (rather than serving the prior engagement's cached
  // rows until the next poll). It is also forwarded as an explicit query param;
  // the rag-api already scopes by the X-Engagement-Id header, but passing it
  // explicitly keeps the request deterministic and cache-correct.
  return useQuery({
    queryKey: ['attack-vectors', minRisk, limit, engagementId ?? null],
    queryFn: () => apiFetch<{ count: number; vectors: AttackVector[] }>(
      `/attack-vectors?limit=${limit}&min_risk=${minRisk}${engagementId ? `&engagement_id=${encodeURIComponent(engagementId)}` : ''}`,
    ),
    refetchInterval: POLL.NORMAL,
  })
}

export function useAttackGraph(engagementId?: string | null) {
  // engagementId in the queryKey so the graph refetches on engagement switch
  // (the rag-api scopes by the X-Engagement-Id header, but an unvaried key would
  // serve the prior engagement's graph until the next poll). Forwarded as a param
  // too for determinism — the BFF /attack-vectors/graph route accepts it.
  return useQuery({
    queryKey: ['attack-graph', engagementId ?? null],
    queryFn: () => apiFetch<AttackGraph>(
      `/attack-vectors/graph${engagementId ? `?engagement_id=${encodeURIComponent(engagementId)}` : ''}`,
    ),
    refetchInterval: POLL.NORMAL,
  })
}

export function useComputeAttackVectors() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<{ ok: boolean; findings_considered: number; vectors_written: number; edges_written: number }>(
      '/attack-vectors/compute', { method: 'POST' },
    ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['attack-vectors'] })
      qc.invalidateQueries({ queryKey: ['attack-graph'] })
    },
  })
}
