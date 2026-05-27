import { useState, useMemo } from 'react'
import { useScanRuns, useCompareRuns, useDedupReport, useBackfillScanRuns, useBackfillFingerprints } from '../api/delta'
import type { ScanRun, DeltaFinding, DedupEntry } from '../api/delta'

const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-400',
  info: 'bg-gray-400',
}

function SevBadge({ severity }: { severity?: string }) {
  const s = severity || 'info'
  return (
    <span className={`px-2 py-0.5 rounded text-xs text-white ${SEV_COLORS[s] || 'bg-gray-400'}`}>
      {s}
    </span>
  )
}

function RunSelector({
  label,
  runs,
  value,
  onChange,
}: {
  label: string
  runs: ScanRun[]
  value: string
  onChange: (id: string) => void
}) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-sm text-gray-400">{label}</label>
      <select
        className="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">Select a scan run...</option>
        {runs.map((r) => (
          <option key={r.id} value={r.id}>
            {r.tool} — {r.target || 'all'} — {new Date(r.started_at).toLocaleString()} ({r.finding_count} findings)
          </option>
        ))}
      </select>
    </div>
  )
}

function FindingRow({ f, type }: { f: DeltaFinding; type: 'new' | 'resolved' }) {
  const color = type === 'new' ? 'border-l-green-500' : 'border-l-red-500'
  return (
    <div className={`border-l-4 ${color} bg-gray-800 p-3 rounded-r mb-2`}>
      <div className="flex items-center gap-2 mb-1">
        <SevBadge severity={f.severity} />
        <span className="text-sm font-medium">
          {f.script || f.name || f.finding_type || 'Unknown'}
        </span>
        {f.cve && f.cve.length > 0 && (
          <span className="text-xs text-blue-400">{f.cve.join(', ')}</span>
        )}
      </div>
      <div className="text-xs text-gray-400 flex gap-4">
        {f.ip && <span>IP: {f.ip}</span>}
        {f.port && <span>Port: {f.port}</span>}
        {f.url && <span className="truncate max-w-md">URL: {f.url}</span>}
        {f.target && <span>Target: {f.target}</span>}
      </div>
    </div>
  )
}

function DedupTable({ entries }: { entries: DedupEntry[] }) {
  if (!entries.length) {
    return <p className="text-gray-500 text-sm">No duplicate findings found.</p>
  }
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-gray-400 border-b border-gray-700">
          <th className="pb-2">Type</th>
          <th className="pb-2">Duplicates</th>
          <th className="pb-2">Tools</th>
          <th className="pb-2">Severities</th>
          <th className="pb-2">Fingerprint</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i} className="border-b border-gray-800">
            <td className="py-2">{e.type}</td>
            <td className="py-2 font-bold">{e.count}</td>
            <td className="py-2">
              {e.tools.map((t) => (
                <span key={t} className="bg-gray-700 px-1.5 py-0.5 rounded text-xs mr-1">
                  {t}
                </span>
              ))}
            </td>
            <td className="py-2">
              {e.severities.map((s) => (
                <SevBadge key={s} severity={s} />
              ))}
            </td>
            <td className="py-2 text-gray-500 font-mono text-xs">{e.fingerprint.slice(0, 12)}...</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function DeltaCompare() {
  const [tab, setTab] = useState<'compare' | 'dedup'>('compare')
  const [runA, setRunA] = useState('')
  const [runB, setRunB] = useState('')
  const [toolFilter, setToolFilter] = useState('')

  const { data: runs = [], isLoading: runsLoading } = useScanRuns(toolFilter || undefined)
  const { data: delta, isLoading: deltaLoading } = useCompareRuns(runA, runB)
  const { data: dedupData } = useDedupReport()
  const backfill = useBackfillScanRuns()
  const fpBackfill = useBackfillFingerprints()

  const tools = useMemo(() => {
    const set = new Set(runs.map((r) => r.tool))
    return Array.from(set).sort()
  }, [runs])

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Delta Compare</h1>

      {/* Tab bar */}
      <div className="flex gap-4 mb-6 border-b border-gray-700 pb-2">
        <button
          className={`pb-1 ${tab === 'compare' ? 'border-b-2 border-blue-500 text-white' : 'text-gray-400'}`}
          onClick={() => setTab('compare')}
        >
          Run Comparison
        </button>
        <button
          className={`pb-1 ${tab === 'dedup' ? 'border-b-2 border-blue-500 text-white' : 'text-gray-400'}`}
          onClick={() => setTab('dedup')}
        >
          Dedup Report
        </button>
      </div>

      {tab === 'compare' && (
        <>
          {/* Tool filter */}
          <div className="mb-4">
            <select
              className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm"
              value={toolFilter}
              onChange={(e) => { setToolFilter(e.target.value); setRunA(''); setRunB('') }}
            >
              <option value="">All tools</option>
              {tools.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Run selectors */}
          <div className="grid grid-cols-2 gap-4 mb-6">
            <RunSelector label="Baseline (older)" runs={runs} value={runA} onChange={setRunA} />
            <RunSelector label="Current (newer)" runs={runs} value={runB} onChange={setRunB} />
          </div>

          {/* Delta results */}
          {deltaLoading && <p className="text-gray-400">Comparing runs...</p>}

          {delta && (
            <div>
              {/* Summary cards */}
              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="bg-green-900/30 border border-green-700 rounded p-4 text-center">
                  <div className="text-3xl font-bold text-green-400">{delta.summary.new}</div>
                  <div className="text-sm text-green-300">New Findings</div>
                </div>
                <div className="bg-red-900/30 border border-red-700 rounded p-4 text-center">
                  <div className="text-3xl font-bold text-red-400">{delta.summary.resolved}</div>
                  <div className="text-sm text-red-300">Resolved</div>
                </div>
                <div className="bg-gray-800 border border-gray-600 rounded p-4 text-center">
                  <div className="text-3xl font-bold text-gray-300">{delta.summary.unchanged}</div>
                  <div className="text-sm text-gray-400">Unchanged</div>
                </div>
              </div>

              {/* New findings */}
              {delta.new.length > 0 && (
                <div className="mb-6">
                  <h2 className="text-lg font-semibold text-green-400 mb-3">
                    New Findings ({delta.new.length})
                  </h2>
                  {delta.new.map((f) => (
                    <FindingRow key={f.id} f={f} type="new" />
                  ))}
                </div>
              )}

              {/* Resolved findings */}
              {delta.resolved.length > 0 && (
                <div className="mb-6">
                  <h2 className="text-lg font-semibold text-red-400 mb-3">
                    Resolved Findings ({delta.resolved.length})
                  </h2>
                  {delta.resolved.map((f) => (
                    <FindingRow key={f.id} f={f} type="resolved" />
                  ))}
                </div>
              )}

              {delta.summary.new === 0 && delta.summary.resolved === 0 && (
                <p className="text-gray-400 text-center py-8">
                  No changes between these two runs.
                </p>
              )}
            </div>
          )}

          {!runsLoading && runs.length === 0 && (
            <div className="text-center py-8 border border-gray-700 rounded bg-gray-800/50">
              <p className="text-gray-400 mb-3">
                No scan runs recorded yet. Generate runs from your existing findings to enable comparison.
              </p>
              <button
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-medium disabled:opacity-50"
                disabled={backfill.isPending}
                onClick={() => backfill.mutate()}
              >
                {backfill.isPending ? 'Generating...' : 'Generate Scan Runs from History'}
              </button>
              {backfill.isSuccess && (
                <p className="text-green-400 text-sm mt-2">
                  Created {backfill.data?.created ?? 0} scan runs
                </p>
              )}
              {backfill.isError && (
                <p className="text-red-400 text-sm mt-2">
                  Failed to generate runs. Check console for details.
                </p>
              )}
            </div>
          )}

          {runs.length > 0 && !runA && !runB && (
            <p className="text-gray-500 text-center py-8">
              Select two scan runs to compare findings between them.
            </p>
          )}
        </>
      )}

      {tab === 'dedup' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <p className="text-gray-400 text-sm">
              Findings that appear more than once (same fingerprint, different records).
              These may be the same vulnerability discovered by different tools.
            </p>
            <button
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm whitespace-nowrap ml-4 disabled:opacity-50"
              disabled={fpBackfill.isPending}
              onClick={() => fpBackfill.mutate()}
            >
              {fpBackfill.isPending ? 'Computing...' : 'Recompute Fingerprints'}
            </button>
          </div>
          {fpBackfill.isSuccess && (
            <p className="text-green-400 text-sm mb-3">
              Updated {fpBackfill.data?.total ?? 0} findings ({Object.entries(fpBackfill.data?.updated ?? {}).map(([k, v]) => `${k}: ${v}`).join(', ')})
            </p>
          )}
          <DedupTable entries={dedupData?.duplicates || []} />
        </div>
      )}
    </div>
  )
}
