/**
 * Top-level Recommendations page.
 *
 * Until now, scan recommendations lived in two places: the FollowUps
 * page (embedded panel) and the AssetBrowser port-detail modal.
 * Operators had to dig into one of those to see "what should I run /
 * what did I run / what finished".  This page promotes the same data
 * to a first-class destination so the whole pipeline is visible at a
 * glance, with filters to narrow by status / service / IP / source.
 *
 * It re-uses the shared ScanRecommendationsPanel in always-expanded
 * mode -- same UI, same dispatch + status logic -- and just hangs a
 * filter bar above it.  Filtering is client-side; data volume is
 * small enough that pushing it to the BFF query string would buy us
 * nothing.
 */

import { useState } from 'react'
import { Crosshair, X } from 'lucide-react'
import { ScanRecommendationsPanel } from '@/components/recommendations/ScanRecommendationsTable'

const STATUS_OPTIONS = [
  { value: '',           label: 'All' },
  { value: 'pending',    label: 'Pending' },
  { value: 'queued',     label: 'Queued' },
  { value: 'running',    label: 'Running' },
  { value: 'completed',  label: 'Completed' },
  { value: 'failed',     label: 'Failed' },
  { value: 'skipped',    label: 'Skipped' },
]

const SOURCE_OPTIONS = [
  { value: '',           label: 'All sources' },
  { value: 'rules',      label: 'Rules (auto-generated)' },
  { value: 'kb_manual',  label: 'KB suggestion (manual)' },
  { value: 'model',      label: 'Model' },
]

export default function Recommendations() {
  const [status, setStatus] = useState('')
  const [service, setService] = useState('')
  const [ip, setIp] = useState('')
  const [source, setSource] = useState('')

  const filters = {
    status: status || undefined,
    service: service || undefined,
    ip: ip || undefined,
    source: source || undefined,
  }
  const anyFilter = status || service || ip || source

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Crosshair className="h-4 w-4 text-blue-400" />
        <h2 className="text-base font-semibold">Scan Recommendations</h2>
        <span className="text-xs text-muted-foreground">
          Dispatch suggested scans against detected ports; the status loop
          surfaces queued → running → completed/failed in real time.
        </span>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {/* Status chip group */}
        <div className="flex items-center gap-1">
          {STATUS_OPTIONS.map(opt => (
            <button
              key={opt.value}
              onClick={() => setStatus(opt.value)}
              className={`px-2 py-1 text-xs rounded border ${
                status === opt.value
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <input
          value={service}
          onChange={e => setService(e.target.value)}
          placeholder="Service contains…"
          className="h-7 px-2 text-xs rounded border border-border bg-background text-foreground outline-none focus:border-primary w-44"
        />

        <input
          value={ip}
          onChange={e => setIp(e.target.value)}
          placeholder="IP contains…"
          className="h-7 px-2 text-xs rounded border border-border bg-background text-foreground outline-none focus:border-primary w-40"
        />

        <select
          value={source}
          onChange={e => setSource(e.target.value)}
          className="h-7 px-2 text-xs rounded border border-border bg-background text-foreground outline-none focus:border-primary"
        >
          {SOURCE_OPTIONS.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>

        {anyFilter && (
          <button
            onClick={() => { setStatus(''); setService(''); setIp(''); setSource('') }}
            className="h-7 px-2 text-xs rounded border border-border text-muted-foreground hover:text-foreground flex items-center gap-1"
            title="Clear all filters"
          >
            <X className="h-3 w-3" /> Clear
          </button>
        )}
      </div>

      <ScanRecommendationsPanel embedded={false} filters={filters} />
    </div>
  )
}
