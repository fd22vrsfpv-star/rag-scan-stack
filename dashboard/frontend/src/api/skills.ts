import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

// Vuln-class skills: read-only YAML packs + an operator DB overlay (served by
// rag-api; apiFetch prepends /api). Mirrors api/flows.ts.
export interface VulnSkillEntry {
  aliases?: string[]
  web_hint?: string
  synth_methodology?: string
  enabled?: boolean
}

export interface SkillsResponse {
  yaml_skills: Record<string, VulnSkillEntry>
  custom_skills: Record<string, VulnSkillEntry>
  total: number
}

export function useSkills() {
  return useQuery({
    queryKey: ['skills'],
    queryFn: () => apiFetch<SkillsResponse>('/skills'),
  })
}

export function useAddSkill() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: {
      id: string; aliases?: string[]; web_hint?: string
      synth_methodology?: string; enabled?: boolean
    }) =>
      apiFetch<{ ok: boolean; id: string; rag_loaded?: boolean }>('/skills', {
        method: 'POST', body: JSON.stringify(v),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['skills'] }),
  })
}

export function useDeleteSkill() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean; deleted: string }>(`/skills/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['skills'] }),
  })
}

export function useTestSkill() {
  return useMutation({
    mutationFn: (v: { issue_type?: string; cwe?: string; name?: string }) =>
      apiFetch<{ matched: boolean; skill: VulnSkillEntry & { canonical?: string } | null }>(
        '/skills/test', { method: 'POST', body: JSON.stringify(v) }),
  })
}

// ── Learned skill overlays (self-improvement from scans + operator additions) ──
export interface LearnedOverlay {
  id: string
  kind: string
  name: string
  entry: Record<string, unknown>
  evidence?: Record<string, unknown>
  active: boolean
  source: string
  engagement_id?: string | null
  created_at: string
  updated_at: string
}

export function useLearnedOverlays(kind?: string) {
  const qs = kind ? `?kind=${encodeURIComponent(kind)}` : ''
  return useQuery({
    queryKey: ['skills-learned', kind || 'all'],
    queryFn: () => apiFetch<{ learned: LearnedOverlay[] }>(`/skills/learned${qs}`),
    refetchInterval: 30_000,
  })
}

export function useDeleteLearnedOverlay() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ ok: boolean; deleted: number }>(`/skills/learned/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['skills-learned'] }),
  })
}
