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

/** Download the RAG Scan Bridge Jython extension (`RagScanBridge.py`) that
 *  the operator loads into Burp Pro (Settings → Extensions → Add → Python).
 *  Streams through the BFF; the file lives in the rag-api image. */
export async function downloadBurpBridgeExtension() {
  const resp = await fetch('/api/burp/extension')
  if (!resp.ok) throw new Error(`Burp extension download failed: ${resp.status}`)
  const blob = await resp.blob()
  const cd = resp.headers.get('content-disposition') || ''
  const m = cd.match(/filename="?([^"]+)"?/)
  const fname = m ? m[1] : 'RagScanBridge.py'
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = fname
  document.body.appendChild(a); a.click(); a.remove()
  URL.revokeObjectURL(url)
}

/** README markdown for the Burp bridge extension — install steps + feature
 *  list. The UI renders it inline next to the download button. */
export function useBurpBridgeReadme(enabled = true) {
  return useQuery({
    queryKey: ['burp-bridge-readme'],
    enabled,
    queryFn: async () => {
      const resp = await fetch('/api/burp/extension/readme')
      if (!resp.ok) throw new Error(`readme fetch failed: ${resp.status}`)
      return resp.text()
    },
    staleTime: 10 * 60 * 1000,  // README is immutable per build
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
