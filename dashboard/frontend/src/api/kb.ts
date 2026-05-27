import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface KBServiceSummary {
  name: string
  source: 'yaml' | 'override' | 'both'
  ports: number[]
  description: string
  tool_count: number
  msf_count: number
  nuclei_tags: string[]
  common_vulns: string[]
}

export interface KBTool {
  name: string
  purpose?: string
  command?: string
}

export interface KBMsfModule {
  module: string
  purpose?: string
  type?: string
}

export interface KBServiceDetail {
  name: string
  source: 'yaml' | 'override' | 'both'
  data: {
    description?: string
    ports?: number[]
    tools?: KBTool[]
    metasploit?: KBMsfModule[]
    nuclei_tags?: string[]
    common_vulns?: string[]
  }
}

export function useKBServices() {
  return useQuery({
    queryKey: ['kb-services'],
    queryFn: () =>
      apiFetch<{ services: KBServiceSummary[]; count: number }>('/kb/services'),
    staleTime: 30_000,
  })
}

export function useKBService(name: string) {
  return useQuery({
    queryKey: ['kb-service', name],
    queryFn: () => apiFetch<KBServiceDetail>(`/kb/services/${encodeURIComponent(name)}`),
    enabled: !!name,
  })
}

export function useUpsertKBService() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ name, data }: { name: string; data: Record<string, unknown> }) =>
      apiFetch<{ ok: boolean }>(`/kb/services/${encodeURIComponent(name)}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['kb-services'] })
      qc.invalidateQueries({ queryKey: ['kb-service'] })
    },
  })
}

export function useDeleteKBOverride() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) =>
      apiFetch<{ ok: boolean }>(`/kb/services/${encodeURIComponent(name)}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['kb-services'] })
      qc.invalidateQueries({ queryKey: ['kb-service'] })
    },
  })
}
