import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiUrl } from './client'

/** One combined GoWitness view — every screenshot with its status code and
 *  title, instead of a grid of unlabelled thumbnails.
 *
 *  The data was always complete (recon_findings carries url, status_code,
 *  title, server, technologies, TLS and the screenshot path for every
 *  gowitness row); what was missing was a way to look at it without opening
 *  669 images one at a time.
 */
export type GowitnessRow = {
  url: string
  final_url: string
  status_code: number | ''
  title: string
  server: string
  technologies: string
  redirect_to: string
  tls_issuer: string
  tls_protocol: string
  screenshot: string
  target: string
}

export type GowitnessReport = {
  ok: boolean
  label: string
  count: number
  engagement_id: string | null
  all_engagements: boolean
  status_counts: Record<string, number>
  rows: GowitnessRow[]
}

export function useGowitnessReport(
  opts: { match?: string; status?: string; allEngagements?: boolean; enabled?: boolean } = {},
) {
  const params = new URLSearchParams()
  if (opts.match) params.set('match', opts.match)
  if (opts.status) params.set('status', opts.status)
  if (opts.allEngagements) params.set('all_engagements', 'true')
  const qs = params.toString()
  return useQuery({
    queryKey: ['gowitness-report', opts.match ?? '', opts.status ?? '', !!opts.allEngagements],
    queryFn: () => apiFetch<GowitnessReport>(`/recon/gowitness-report${qs ? `?${qs}` : ''}`),
    enabled: opts.enabled !== false,
  })
}

/** Download the report as a file.
 *
 *  Not apiFetch: that parses JSON, and these bodies are text/csv and
 *  text/html. Mirrors downloadScopeTargetsCsv — same engagement header, same
 *  Content-Disposition handling so the browser offers the server's filename,
 *  and errors throw with the server's text so a failure is readable instead
 *  of landing inside the downloaded file.
 */
export async function downloadGowitnessReport(
  fmt: 'csv' | 'html',
  opts: { match?: string; status?: string; allEngagements?: boolean } = {},
): Promise<void> {
  const params = new URLSearchParams({ fmt })
  if (opts.match) params.set('match', opts.match)
  if (opts.status) params.set('status', opts.status)
  if (opts.allEngagements) params.set('all_engagements', 'true')
  const eid = (() => { try { return localStorage.getItem('selected-engagement') } catch { return null } })()
  const resp = await fetch(apiUrl(`/recon/gowitness-report?${params.toString()}`), {
    headers: eid ? { 'X-Engagement-Id': eid } : {},
  })
  if (!resp.ok) throw new Error(`Report ${resp.status}: ${await resp.text()}`)
  const blob = await resp.blob()
  const cd = resp.headers.get('content-disposition') || ''
  const m = cd.match(/filename="?([^"]+)"?/)
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = m ? m[1] : `gowitness.${fmt}`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
