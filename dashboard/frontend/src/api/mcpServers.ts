import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

export interface McpServer {
  name: string
  description?: string
  source?: string
  package?: string
  path?: string
  repo?: string
  entry?: string
  transport?: string
  port: number
  env?: Record<string, string>
  args?: string[]
  enabled: boolean
  builtin: boolean
  healthy: boolean
  tools?: number
}

export function useMcpServers() {
  return useQuery({
    queryKey: ['mcp-servers'],
    queryFn: () => apiFetch<{ servers: McpServer[] }>('/settings/mcp-servers'),
    refetchInterval: POLL.BACKGROUND,
  })
}

export function useAddMcpServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (server: Omit<McpServer, 'builtin' | 'healthy'>) =>
      apiFetch<{ ok: boolean }>('/settings/mcp-servers', {
        method: 'POST',
        body: JSON.stringify(server),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mcp-servers'] }),
  })
}

export function useToggleMcpServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) =>
      apiFetch<{ ok: boolean; enabled: boolean }>(`/settings/mcp-servers/${name}/toggle`, {
        method: 'PATCH',
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mcp-servers'] }),
  })
}

export function useDeleteMcpServer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) =>
      apiFetch<{ ok: boolean }>(`/settings/mcp-servers/${name}`, {
        method: 'DELETE',
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mcp-servers'] }),
  })
}

export function useUpdateMcpoConfig() {
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; servers: number }>('/settings/mcp-servers/update-mcpo', {
        method: 'POST',
      }),
  })
}
