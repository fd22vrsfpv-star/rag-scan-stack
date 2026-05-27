import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

export interface BurpStatus {
  connected: boolean
  url?: string
  error?: string
  scans?: unknown[]
}

export interface BurpScanResult {
  ok: boolean
  task_id?: string
  message?: string
  error?: string
  status_url?: string
}

export interface BurpScanStatus {
  task_id: string
  status?: string
  metrics?: Record<string, unknown>
  issue_events?: unknown[]
  audit_items_count?: number
  error?: string
}

export function useBurpStatus() {
  return useQuery({
    queryKey: ['burp-status'],
    queryFn: () => apiFetch<BurpStatus>('/burp/status'),
    refetchInterval: POLL.BACKGROUND,
  })
}

export function useStartBurpScan() {
  return useMutation({
    mutationFn: (params: {
      urls: string[]
      scope?: { include: { rule: string }[]; exclude: { rule: string }[] }
      scan_config?: string
      proxy?: string
      credentials?: { username: string; password: string }[]
    }) => apiFetch<BurpScanResult>('/burp/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    }),
  })
}

export function useBurpScanStatus(taskId: string) {
  return useQuery({
    queryKey: ['burp-scan', taskId],
    queryFn: () => apiFetch<BurpScanStatus>(`/burp/scan/${taskId}`),
    enabled: !!taskId,
    refetchInterval: POLL.FAST,
  })
}

export function useConfigureBurpProxy() {
  return useMutation({
    mutationFn: (params: {
      proxy_host: string
      proxy_port: number
      socks_version?: number
      enabled?: boolean
    }) => apiFetch<{ ok: boolean; message: string; config?: unknown }>('/burp/configure-proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    }),
  })
}

export function useImportBurpResults() {
  return useMutation({
    mutationFn: (taskId: string) =>
      apiFetch<{ ok: boolean; imported: number; total: number }>(`/burp/scan/${taskId}/import`, {
        method: 'POST',
      }),
  })
}
