import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiUrl } from './client'

/**
 * Import a web scan report produced by another tool.
 *
 * The BFF proxies to rag-api, which auto-detects which scanner made the file
 * (content-based, not by extension) and dispatches to the matching parser.
 * Findings land in web_findings and deduplicate against existing ones via the
 * shared fingerprint, so re-importing the same report is safe.
 */

export interface SupportedTool {
  id: string
  label: string
  formats: string[]
}

export interface WebImportFormats {
  tools: SupportedTool[]
  max_bytes: number
}

export interface WebImportStats {
  format?: string
  inserted: number
  skipped_duplicate: number
  skipped_false_positive?: number
  skipped_no_url?: number
  by_severity: Record<string, number>
  errors: string[]
}

export interface WebImportResult {
  ok: boolean
  tool: string
  stats: WebImportStats
}

export function useWebImportFormats() {
  return useQuery({
    queryKey: ['web-import-formats'],
    queryFn: () => apiFetch<WebImportFormats>('/import/web-scan/formats'),
    staleTime: 10 * 60_000,
  })
}

export function useImportWebScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ file, tool }: { file: File; tool?: string }) => {
      const fd = new FormData()
      fd.append('file', file)
      // `tool` forces a parser; omitted means auto-detect.
      const qs = tool ? `?tool=${encodeURIComponent(tool)}` : ''
      const resp = await fetch(apiUrl(`/import/web-scan${qs}`), {
        method: 'POST',
        body: fd,
      })
      if (!resp.ok) {
        // The API's detail explains what to fix (wrong format, empty file, …).
        let detail = `Import failed (${resp.status})`
        try {
          const body = await resp.json()
          if (body?.detail) detail = typeof body.detail === 'string'
            ? body.detail : JSON.stringify(body.detail)
        } catch { /* keep the status-code message */ }
        throw new Error(detail)
      }
      return resp.json() as Promise<WebImportResult>
    },
    onSuccess: () => {
      // Imported rows show up in findings views immediately.
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['web-findings'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}
