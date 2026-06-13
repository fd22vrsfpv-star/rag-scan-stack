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
  rationale?: string
  risk_factors?: Record<string, number>
}

export interface AttackGraphNode { id: string; type: string; label: string; risk: number }
export interface AttackGraphEdge { from: string; to: string; type?: string; risk: number }
export interface AttackGraph { nodes: AttackGraphNode[]; edges: AttackGraphEdge[]; count: number }

export function useAttackVectors(minRisk = 0, limit = 100) {
  return useQuery({
    queryKey: ['attack-vectors', minRisk, limit],
    queryFn: () => apiFetch<{ count: number; vectors: AttackVector[] }>(
      `/attack-vectors?limit=${limit}&min_risk=${minRisk}`,
    ),
    refetchInterval: POLL.NORMAL,
  })
}

export function useAttackGraph() {
  return useQuery({
    queryKey: ['attack-graph'],
    queryFn: () => apiFetch<AttackGraph>('/attack-vectors/graph'),
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
