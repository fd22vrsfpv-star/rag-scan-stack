import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

// Reconnect watcher runtime status (autogen-agents, proxied by the BFF).
export interface ReconnectWatcherStatus {
  running: boolean
  enabled: boolean
  active: boolean
  last_check: string | null
  attempts_total: number
  reconnected_total: number
  blocked_total: number
  config?: Record<string, any>
}

// Exploit watcher runtime status.
export interface ExploitWatcherStatus {
  running: boolean
  enabled?: boolean
  last_check: string | null
  processed_vuln_count?: number
  processed_port_count?: number
  processed_web_finding_count?: number
  config?: Record<string, any>
}

export interface NoCallbackRow {
  id: string
  exploit_title: string
  source: string
  exploit_type: string | null
  module_class: 'foothold' | 'recon'
  target: string | null
  target_port: number | null
  target_service: string | null
  status: string
  rejection_reason: string | null
  updated_at: string
  callback_status: string | null
}

export function useReconnectWatcherStatus() {
  return useQuery({
    queryKey: ['reconnect-watcher-status'],
    queryFn: () => apiFetch<ReconnectWatcherStatus>('/reconnect-watcher/status'),
    refetchInterval: 15_000,
  })
}

export function useExploitWatcherStatus() {
  return useQuery({
    queryKey: ['exploit-watcher-status'],
    queryFn: () => apiFetch<ExploitWatcherStatus>('/exploit-watcher/status'),
    refetchInterval: 15_000,
  })
}

export function useFootholdNoCallback(limit = 50) {
  return useQuery({
    queryKey: ['foothold-no-callback', limit],
    queryFn: () => apiFetch<{ count: number; rows: NoCallbackRow[]; recon_excluded: number }>(
      `/foothold/no-callback?limit=${limit}`),
    refetchInterval: 30_000,
  })
}
