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
import { useSearchParams } from 'react-router-dom'
import { Crosshair, X, Sparkles } from 'lucide-react'
import { ScanRecommendationsPanel } from '@/components/recommendations/ScanRecommendationsTable'
import { useGenerateRecommendations } from '@/api/assets'
import InfoTip from '@/components/InfoTip'

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
  const [searchParams] = useSearchParams()
  const [status, setStatus] = useState('')
  const [service, setService] = useState('')
  // Seed the IP filter from a deep link (e.g. the Attack Map "Recommendations" link).
  const [ip, setIp] = useState(() => searchParams.get('ip') || '')
  const [source, setSource] = useState('')
  const generateRecs = useGenerateRecommendations()

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
        <InfoTip side="bottom" text={
          <>
            Suggested next scans for each detected service/port. <b>Run</b> dispatches a
            scan to its tool (native runner, or the Kali container / a node) and the status
            tracks <b>queued → running → completed/failed</b> live.
            <br /><br />
            <b>Metasploit</b> recs aren’t auto-run — Run queues them in the Exploit Manager
            for approval. Overlapping tools (e.g. nmap <code>-sV</code> vs metasploit
            <code>*_version</code>) are collapsed so you see one per job, and tools the KB
            marks as non-scanners (e.g. vulnx) don’t appear here.
          </>
        } />
        <span className="text-xs text-muted-foreground">
          Dispatch suggested scans against detected ports; the status loop
          surfaces queued → running → completed/failed in real time.
        </span>
        <span className="ml-auto flex items-center gap-1">
          <button
            onClick={() => generateRecs.mutate(ip || undefined)}
            disabled={generateRecs.isPending}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded border border-primary/50 bg-primary/10 text-primary hover:bg-primary/20 disabled:opacity-50"
          >
            <Sparkles className="h-3.5 w-3.5" />
            {generateRecs.isPending ? 'Generating…' : 'Generate from detected ports'}
          </button>
          <InfoTip side="left" text={
            <>
              Generates recommendations for <b>every currently-detected open port</b> that
              doesn’t have one yet — useful for targets scanned earlier (the automatic
              trigger only covers ports seen in the last 10 minutes). Honors the IP filter
              if set. Idempotent: re-running only fills gaps.
            </>
          } />
        </span>
      </div>
      {generateRecs.isSuccess && (
        <div className="text-xs text-muted-foreground">
          Considered {generateRecs.data?.ports_considered ?? 0} port(s), generated {generateRecs.data?.generated ?? 0}.
        </div>
      )}
      {generateRecs.isError && (
        <div className="text-xs text-red-400">Generation failed — see logs.</div>
      )}

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {/* Status chip group */}
        <div className="flex items-center gap-1">
          <InfoTip side="bottom" className="mr-0.5" text={
            <>
              Lifecycle of a recommendation: <b>pending</b> (not run) → <b>queued</b>
              (dispatched / awaiting approval for metasploit) → <b>running</b> →
              <b>completed</b> or <b>failed</b>. <b>skipped</b> = no handler or a manual
              tool. Filter the list by any state.
            </>
          } />
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
