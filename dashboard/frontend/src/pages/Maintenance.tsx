import { useState, useRef } from 'react'
import {
  useMaintenanceStats,
  useCleanup,
  useDataExport,
  useDataImport,
  useExportEstimate,
  useAuditLog,
  useRotateAuditLog,
  useFollowupBulkUpdate,
  ImportResult,
} from '@/api/maintenance'

interface CleanupAction {
  key: string
  label: string
  description: string
  category: string
  hasAge: boolean
  danger?: boolean
}

const ACTIONS: CleanupAction[] = [
  {
    key: 'findings',
    label: 'Findings',
    description: 'Delete web_findings, playwright_findings, and vulns',
    category: 'findings',
    hasAge: true,
  },
  {
    key: 'jobs',
    label: 'Jobs & Tasks',
    description: 'Delete finished/failed/canceled jobs and their tasks',
    category: 'jobs',
    hasAge: true,
  },
  {
    key: 'sessions',
    label: 'Agent Sessions',
    description: 'Delete agent sessions and messages',
    category: 'sessions',
    hasAge: true,
  },
  {
    key: 'scans',
    label: 'Scan Records',
    description: 'Delete completed scan records',
    category: 'scans',
    hasAge: true,
  },
  {
    key: 'recommendations',
    label: 'Recommendations',
    description: 'Delete scan recommendations',
    category: 'recommendations',
    hasAge: true,
  },
  {
    key: 'followups',
    label: 'Follow-Ups',
    description: 'Delete follow-up items and associated agent feedback',
    category: 'followups',
    hasAge: true,
  },
  {
    key: 'engagements',
    label: 'Engagements',
    description: 'Delete engagements and their campaign events. Nulls engagement_id on findings/assets.',
    category: 'engagements',
    hasAge: true,
  },
  {
    key: 'exploits',
    label: 'All Exploits',
    description: 'Delete ALL exploit data — pending exploits, exploit results, and exploit chunks/embeddings',
    category: 'exploits',
    hasAge: false,
    danger: true,
  },
  {
    key: 'assets',
    label: 'Everything',
    description: 'Delete ALL data — assets, ports, findings, scans, jobs, sessions, recommendations',
    category: 'assets',
    hasAge: false,
    danger: true,
  },
]

const EXPORT_CATEGORIES = [
  { key: 'assets', label: 'Assets & Ports', description: 'IP addresses, hostnames, open ports' },
  { key: 'findings', label: 'Findings', description: 'Vulns, web findings, playwright findings' },
  { key: 'recon', label: 'Recon', description: 'DNS, TLS, subdomains, httpx, whatweb' },
  { key: 'credentials', label: 'Credentials', description: 'Discovered credentials (Brutus)' },
  { key: 'params', label: 'Parameters', description: 'Discovered URL parameters' },
  { key: 'exploits', label: 'Exploits', description: 'Pending exploits and results' },
  { key: 'screenshots', label: 'Screenshot Metadata', description: 'Screenshot tags and annotations (DB)' },
]

function formatCount(n: number): string {
  if (n < 0) return '—'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

type MaintTab = 'overview' | 'cleanup'

function MaintenanceTabs({ tab, setTab }: { tab: MaintTab; setTab: (t: MaintTab) => void }) {
  const tabs: Array<{ id: MaintTab; label: string }> = [
    { id: 'overview', label: 'Overview' },
    { id: 'cleanup', label: 'Cleanup' },
  ]
  return (
    <div className="flex gap-1 border-b border-border">
      {tabs.map(t => (
        <button key={t.id} onClick={() => setTab(t.id)}
          className={`px-3 py-1.5 text-sm border-b-2 -mb-px ${
            tab === t.id
              ? 'border-blue-500 text-foreground'
              : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
          {t.label}
        </button>
      ))}
    </div>
  )
}

/**
 * Run the cleanup tasks by hand.
 *
 * These endpoints existed and nothing could reach them: the UI had no control,
 * the scheduled script did not parse, and the cron was never installed — so
 * 41 tool executions sat stuck at 'running' for days and raw artifacts only
 * ever grew.
 *
 * Every task is dry-run first. The result of a dry run is shown before anything
 * is deleted, because these operations are not reversible.
 */
function CleanupPanel() {
  const cleanup = useCleanup()
  const [result, setResult] = useState<{ task: string; dry: boolean; data: unknown } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [keepUnprocessed, setKeepUnprocessed] = useState(true)
  const [keepCited, setKeepCited] = useState(true)
  const [artifactDays, setArtifactDays] = useState(90)
  const [staleHours, setStaleHours] = useState(6)

  async function run(task: string, dry: boolean) {
    setBusy(`${task}:${dry}`)
    setError(null)
    try {
      const base: Record<string, unknown> = { category: task, dry_run: dry }
      if (task === 'tool-executions') base.stale_after_hours = staleHours
      if (task === 'artifacts') {
        base.older_than_days = artifactDays
        base.keep_unprocessed = keepUnprocessed
        base.keep_with_findings = keepCited
      }
      const data = await cleanup.mutateAsync(base as never)
      setResult({ task, dry, data })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Cleanup failed')
    } finally {
      setBusy(null)
    }
  }

  const TASKS: Array<{ id: string; label: string; blurb: string }> = [
    {
      id: 'tool-executions',
      label: 'Stuck tool executions',
      blurb: 'A row is marked running before the tool starts. If the process dies — restart, ' +
             'OOM, a wedged tool — nothing reconciled it and the row stayed running for ever.',
    },
    {
      id: 'artifacts',
      label: 'Raw artifacts',
      blurb: 'Stored tool output. Contains recovered credentials in plaintext, so old ' +
             'artifacts are standing exposure, not just disk usage.',
    },
    { id: 'jobs', label: 'Finished jobs', blurb: 'Completed, failed and cancelled jobs with their tasks.' },
    { id: 'scans', label: 'Old scans', blurb: 'Scan records past the retention window.' },
  ]

  return (
    <div className="space-y-4">
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-xs text-amber-300">
        <b>Nothing here runs on a schedule yet.</b> The cleanup cron is not installed —
        run <code>scripts/setup-cleanup-cron.sh</code> on the host for that. Until then these
        are manual. Deletions are not reversible; check a dry run first.
      </div>

      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-semibold">Options</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <label className="flex items-center gap-2">
            <span className="text-muted-foreground w-40">Reconcile executions after</span>
            <input type="number" min={1} value={staleHours}
              onChange={e => setStaleHours(Number(e.target.value))}
              className="w-20 px-2 py-1 bg-background border border-border rounded" />
            <span className="text-muted-foreground">hours</span>
          </label>
          <label className="flex items-center gap-2">
            <span className="text-muted-foreground w-40">Prune artifacts older than</span>
            <input type="number" min={1} value={artifactDays}
              onChange={e => setArtifactDays(Number(e.target.value))}
              className="w-20 px-2 py-1 bg-background border border-border rounded" />
            <span className="text-muted-foreground">days</span>
          </label>
          <label className="flex items-center gap-2" title="Artifacts still queued for LLM processing">
            <input type="checkbox" checked={keepUnprocessed}
              onChange={e => setKeepUnprocessed(e.target.checked)} />
            <span>Keep unprocessed artifacts</span>
          </label>
          <label className="flex items-center gap-2" title="Artifacts a recommendation cites as evidence">
            <input type="checkbox" checked={keepCited}
              onChange={e => setKeepCited(e.target.checked)} />
            <span>Keep artifacts cited by a finding</span>
          </label>
        </div>
        {keepUnprocessed && (
          <p className="text-[11px] text-muted-foreground">
            With this ticked and no LLM consumer running, artifacts never leave the
            queue and pruning will match almost nothing — the dry run reports how
            many were held back.
          </p>
        )}
      </div>

      {TASKS.map(t => (
        <div key={t.id} className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <h3 className="text-sm font-semibold">{t.label}</h3>
              <p className="text-xs text-muted-foreground mt-0.5">{t.blurb}</p>
            </div>
            <div className="flex gap-2 shrink-0">
              <button onClick={() => run(t.id, true)} disabled={!!busy}
                className="px-3 py-1 text-xs rounded bg-muted/30 hover:bg-muted/50 disabled:opacity-40">
                {busy === `${t.id}:true` ? 'Checking…' : 'Dry run'}
              </button>
              <button onClick={() => run(t.id, false)} disabled={!!busy}
                className="px-3 py-1 text-xs rounded bg-red-600/80 hover:bg-red-600 disabled:opacity-40">
                {busy === `${t.id}:false` ? 'Running…' : 'Run'}
              </button>
            </div>
          </div>
          {result?.task === t.id && (
            <div className={`mt-3 text-xs rounded p-2 border ${
              result.dry ? 'border-blue-500/30 bg-blue-500/10' : 'border-green-500/30 bg-green-500/10'}`}>
              <div className="font-medium mb-1">{result.dry ? 'Dry run — nothing changed' : 'Completed'}</div>
              <pre className="whitespace-pre-wrap break-all">{JSON.stringify(result.data, null, 2)}</pre>
            </div>
          )}
        </div>
      ))}

      {error && (
        <div className="text-xs rounded p-2 border border-red-500/30 bg-red-500/10 text-red-400">{error}</div>
      )}
    </div>
  )
}

export default function Maintenance() {
  const { data: stats, isLoading: statsLoading } = useMaintenanceStats()
  const cleanup = useCleanup()
  const [tab, setTab] = useState<'overview' | 'cleanup'>('overview')
  const dataExport = useDataExport()
  const dataImport = useDataImport()
  const { data: estimate } = useExportEstimate()
  const bulkUpdate = useFollowupBulkUpdate()

  // Follow-up bulk action state
  const [bulkStatus, setBulkStatus] = useState('open')
  const [bulkAction, setBulkAction] = useState<'dismiss' | 'accept' | 'delete'>('dismiss')
  const [bulkResult, setBulkResult] = useState('')

  const [ages, setAges] = useState<Record<string, string>>({})
  const [results, setResults] = useState<Record<string, string>>({})

  // Export state
  const [selectedCats, setSelectedCats] = useState<Set<string>>(
    new Set(EXPORT_CATEGORIES.map(c => c.key))
  )
  const [exportFormat, setExportFormat] = useState<string>('json')
  const [exportStatus, setExportStatus] = useState<string>('')
  const [includeScreenshots, setIncludeScreenshots] = useState(false)
  const [includeScanResults, setIncludeScanResults] = useState(false)
  const [includeAuditLog, setIncludeAuditLog] = useState(false)

  // Import state
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [importResult, setImportResult] = useState<ImportResult | null>(null)
  const [importStatus, setImportStatus] = useState<string>('')

  // Audit log state
  const [auditLimit, setAuditLimit] = useState(100)
  const { data: auditData, isLoading: auditLoading } = useAuditLog({ limit: auditLimit })
  const rotateAuditLog = useRotateAuditLog()
  const [rotateMsg, setRotateMsg] = useState<string>('')

  const setAge = (key: string, val: string) =>
    setAges(prev => ({ ...prev, [key]: val }))

  const toggleCat = (key: string) => {
    setSelectedCats(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const run = async (action: CleanupAction, dryRun: boolean) => {
    const ageVal = ages[action.key] ? Number(ages[action.key]) : undefined

    if (!dryRun) {
      const msg = action.danger
        ? `WARNING: This will permanently delete ALL ${action.label}. This cannot be undone. Continue?`
        : `Delete ${action.label}${ageVal ? ` older than ${ageVal}h` : ''}?`
      if (!window.confirm(msg)) return
    }

    setResults(prev => ({ ...prev, [action.key]: 'Running...' }))

    try {
      const data = await cleanup.mutateAsync({
        category: action.category,
        older_than_hours: ageVal,
        dry_run: dryRun,
      })

      const counts = Object.entries(data)
        .filter(([k]) => k !== 'dry_run' && k !== 'message')
        .map(([k, v]) => `${k}: ${v}`)
        .join(', ')

      setResults(prev => ({
        ...prev,
        [action.key]: dryRun ? `Preview — ${counts}` : `Deleted — ${counts}`,
      }))
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error'
      setResults(prev => ({ ...prev, [action.key]: `Error: ${msg}` }))
    }
  }

  const anyFileIncluded = includeScreenshots || includeScanResults || includeAuditLog

  const handleExport = async () => {
    if (selectedCats.size === 0 && !anyFileIncluded) {
      setExportStatus('Select at least one category or file section')
      return
    }
    setExportStatus('Exporting...')
    try {
      const blob = await dataExport.mutateAsync({
        format: exportFormat,
        categories: Array.from(selectedCats),
        include_screenshots: includeScreenshots,
        include_scan_results: includeScanResults,
        include_audit_log: includeAuditLog,
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      const ext = anyFileIncluded ? 'zip' : exportFormat === 'csv' ? 'zip' : exportFormat === 'nessus' ? 'nessus' : 'json'
      a.href = url
      a.download = `pentest_export.${ext}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      setExportStatus('Export complete')
    } catch (err: unknown) {
      setExportStatus(`Error: ${err instanceof Error ? err.message : 'Unknown'}`)
    }
  }

  const handleImport = async () => {
    const file = fileInputRef.current?.files?.[0]
    if (!file) {
      setImportStatus('Select a file first')
      return
    }
    setImportStatus('Importing...')
    setImportResult(null)
    try {
      const result = await dataImport.mutateAsync(file)
      setImportResult(result)
      if (result.db_import) {
        const total = result.db_import.total ?? 0
        const parts = [`${total} DB records`]
        if (result.screenshots_restored) parts.push(`${result.screenshots_restored} screenshots`)
        if (result.scan_results_restored) parts.push(`${result.scan_results_restored} scan files`)
        if (result.audit_entries_appended) parts.push(`${result.audit_entries_appended} audit entries`)
        setImportStatus(`Imported: ${parts.join(', ')}`)
      } else {
        setImportStatus(`Imported ${result.total ?? 0} records`)
      }
    } catch (err: unknown) {
      setImportStatus(`Error: ${err instanceof Error ? err.message : 'Unknown'}`)
    }
  }

  if (tab === 'cleanup') {
    return (
      <div className="space-y-6">
        <h2 className="text-lg font-semibold">Maintenance</h2>
        <MaintenanceTabs tab={tab} setTab={setTab} />
        <CleanupPanel />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-semibold">Maintenance</h2>
      <MaintenanceTabs tab={tab} setTab={setTab} />

      {/* Database Overview */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Database Overview</h3>
        {statsLoading ? (
          <p className="text-sm text-muted-foreground">Loading stats...</p>
        ) : stats ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2">
            {Object.entries(stats).map(([table, count]) => (
              <div
                key={table}
                className="flex flex-col items-center py-2 px-3 rounded-md bg-muted/30"
              >
                <span className="text-lg font-bold">{formatCount(count)}</span>
                <span className="text-xs text-muted-foreground truncate w-full text-center">
                  {table}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Could not load stats</p>
        )}
      </div>

      {/* Data Export */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Data Export</h3>
        <div className="space-y-3">
          {/* Category checkboxes */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xs text-muted-foreground">DB Categories:</span>
              <button
                onClick={() => setSelectedCats(new Set(EXPORT_CATEGORIES.map(c => c.key)))}
                className="text-xs text-primary hover:underline"
              >
                All
              </button>
              <button
                onClick={() => setSelectedCats(new Set())}
                className="text-xs text-primary hover:underline"
              >
                None
              </button>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {EXPORT_CATEGORIES.map(cat => (
                <label
                  key={cat.key}
                  className="flex items-start gap-2 p-2 rounded-md bg-muted/20 border border-border cursor-pointer hover:bg-muted/40"
                >
                  <input
                    type="checkbox"
                    checked={selectedCats.has(cat.key)}
                    onChange={() => toggleCat(cat.key)}
                    className="mt-0.5"
                  />
                  <div>
                    <p className="text-xs font-medium">{cat.label}</p>
                    <p className="text-xs text-muted-foreground">{cat.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* File include checkboxes */}
          <div>
            <span className="text-xs text-muted-foreground block mb-2">
              Include Files (produces ZIP):
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <label className="flex items-start gap-2 p-2 rounded-md bg-muted/20 border border-border cursor-pointer hover:bg-muted/40">
                <input
                  type="checkbox"
                  checked={includeScreenshots}
                  onChange={() => setIncludeScreenshots(!includeScreenshots)}
                  className="mt-0.5"
                />
                <div>
                  <p className="text-xs font-medium">Screenshot files</p>
                  <p className="text-xs text-muted-foreground">
                    {estimate?.screenshots
                      ? `${estimate.screenshots.file_count} files, ${estimate.screenshots.human}`
                      : 'PNG images from gowitness'}
                  </p>
                </div>
              </label>
              <label className="flex items-start gap-2 p-2 rounded-md bg-muted/20 border border-border cursor-pointer hover:bg-muted/40">
                <input
                  type="checkbox"
                  checked={includeScanResults}
                  onChange={() => setIncludeScanResults(!includeScanResults)}
                  className="mt-0.5"
                />
                <div>
                  <p className="text-xs font-medium">Raw scan results</p>
                  <p className="text-xs text-muted-foreground">
                    {estimate?.scan_results
                      ? `${estimate.scan_results.file_count} files, ${estimate.scan_results.human}`
                      : 'Manifests and output files'}
                  </p>
                </div>
              </label>
              <label className="flex items-start gap-2 p-2 rounded-md bg-muted/20 border border-border cursor-pointer hover:bg-muted/40">
                <input
                  type="checkbox"
                  checked={includeAuditLog}
                  onChange={() => setIncludeAuditLog(!includeAuditLog)}
                  className="mt-0.5"
                />
                <div>
                  <p className="text-xs font-medium">Scan audit log</p>
                  <p className="text-xs text-muted-foreground">
                    {estimate?.audit_log
                      ? `${estimate.audit_log.line_count} entries, ${estimate.audit_log.human}`
                      : 'JSONL audit trail'}
                  </p>
                </div>
              </label>
            </div>
          </div>

          {/* Format radio buttons */}
          <div className="flex items-center gap-4">
            <span className="text-xs text-muted-foreground">Format:</span>
            {[
              { value: 'json', label: 'JSON' },
              { value: 'csv', label: 'CSV (ZIP)' },
              { value: 'nessus', label: 'Nessus XML' },
            ].map(fmt => (
              <label key={fmt.value} className="flex items-center gap-1 text-xs cursor-pointer">
                <input
                  type="radio"
                  name="exportFormat"
                  value={fmt.value}
                  checked={exportFormat === fmt.value}
                  onChange={() => setExportFormat(fmt.value)}
                  disabled={anyFileIncluded}
                />
                {fmt.label}
              </label>
            ))}
            {anyFileIncluded && (
              <span className="text-xs text-muted-foreground italic">
                (ZIP format when files are included)
              </span>
            )}
          </div>

          {/* Export button + status */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleExport}
              disabled={dataExport.isPending || (selectedCats.size === 0 && !anyFileIncluded)}
              className="h-8 px-4 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {dataExport.isPending ? 'Exporting...' : anyFileIncluded ? 'Export ZIP' : 'Export'}
            </button>
            {exportStatus && (
              <span className="text-xs font-mono text-primary">{exportStatus}</span>
            )}
          </div>
          {exportFormat === 'nessus' && !anyFileIncluded && (
            <p className="text-xs text-muted-foreground">
              Nessus XML exports findings tables only (vulns, web findings, playwright findings, credentials).
            </p>
          )}
        </div>
      </div>

      {/* Data Import */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Data Import</h3>
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Import from a previous export. Supports JSON (DB only) or ZIP (DB + screenshots + scan results + audit log).
            Existing records are skipped (by ID).
          </p>
          <div className="flex items-center gap-3">
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,.zip"
              className="text-xs file:mr-2 file:h-8 file:px-3 file:rounded-md file:border file:border-border file:bg-background file:text-xs file:cursor-pointer"
            />
            <button
              onClick={handleImport}
              disabled={dataImport.isPending}
              className="h-8 px-4 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {dataImport.isPending ? 'Importing...' : 'Import'}
            </button>
          </div>
          {importStatus && (
            <span className="text-xs font-mono text-primary">{importStatus}</span>
          )}
          {importResult && importResult.inserted && (
            <div className="text-xs font-mono space-y-0.5">
              {Object.entries(importResult.inserted)
                .filter(([, v]) => v > 0)
                .map(([k, v]) => (
                  <div key={k}>
                    {k}: {v} inserted
                  </div>
                ))}
            </div>
          )}
          {importResult && importResult.db_import && (
            <div className="text-xs font-mono space-y-0.5">
              {importResult.db_import.inserted &&
                Object.entries(importResult.db_import.inserted)
                  .filter(([, v]) => v > 0)
                  .map(([k, v]) => (
                    <div key={k}>
                      {k}: {v} inserted
                    </div>
                  ))}
              {(importResult.screenshots_restored ?? 0) > 0 && (
                <div>screenshots restored: {importResult.screenshots_restored}</div>
              )}
              {(importResult.scan_results_restored ?? 0) > 0 && (
                <div>scan result files restored: {importResult.scan_results_restored}</div>
              )}
              {(importResult.audit_entries_appended ?? 0) > 0 && (
                <div>audit log entries appended: {importResult.audit_entries_appended}</div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Scan Audit Log */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Scan Audit Log</h3>
        <p className="text-xs text-muted-foreground mb-3">
          Timestamped record of all scans executed — useful for post-engagement audit reports.
          Use <strong>Rotate</strong> to archive the current log to a timestamped file and start a fresh one;
          archived files stay on disk in <code className="font-mono">/scan_audit/</code> and can be exported.
        </p>
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          <span className="text-xs text-muted-foreground">Show:</span>
          {[50, 100, 500].map(n => (
            <button
              key={n}
              onClick={() => setAuditLimit(n)}
              className={`h-6 px-2 text-xs rounded border ${
                auditLimit === n
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border hover:bg-muted/40'
              }`}
            >
              {n}
            </button>
          ))}
          <div className="ml-auto flex items-center gap-2">
            {rotateMsg && (
              <span className="text-xs font-mono text-primary">{rotateMsg}</span>
            )}
            <button
              onClick={async () => {
                if (!window.confirm(
                  'Archive the active audit log to a timestamped file and start a fresh one?\n\n' +
                  'The archive is preserved on disk in /scan_audit/ (not deleted).'
                )) return
                setRotateMsg('Rotating…')
                try {
                  const res = await rotateAuditLog.mutateAsync()
                  if (res.rotated) {
                    setRotateMsg(`Archived to ${res.archive_name} (${res.archived_lines} lines)`)
                  } else {
                    setRotateMsg(res.reason ?? 'No active log to rotate')
                  }
                } catch (err: unknown) {
                  setRotateMsg(`Error: ${err instanceof Error ? err.message : 'Unknown'}`)
                }
              }}
              disabled={rotateAuditLog.isPending}
              className="h-6 px-3 text-xs rounded border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 disabled:opacity-50"
              title="Archive active audit log and start a fresh one"
            >
              {rotateAuditLog.isPending ? 'Rotating…' : 'Rotate'}
            </button>
          </div>
        </div>
        {auditLoading ? (
          <p className="text-xs text-muted-foreground">Loading audit log...</p>
        ) : auditData && auditData.entries.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2">Timestamp</th>
                  <th className="py-1.5 px-2">Event</th>
                  <th className="py-1.5 px-2">Scan Type</th>
                  <th className="py-1.5 px-2">Targets</th>
                  <th className="py-1.5 px-2">External IP</th>
                  <th className="py-1.5 px-2">Proxy</th>
                  <th className="py-1.5 px-2">Duration</th>
                  <th className="py-1.5 px-2">Findings</th>
                </tr>
              </thead>
              <tbody>
                {auditData.entries.map((entry, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="py-1.5 px-2 font-mono whitespace-nowrap">
                      {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '—'}
                    </td>
                    <td className="py-1.5 px-2">
                      <span
                        className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${
                          entry.event === 'completed'
                            ? 'bg-green-500/20 text-green-400'
                            : entry.event === 'failed'
                            ? 'bg-red-500/20 text-red-400'
                            : 'bg-blue-500/20 text-blue-400'
                        }`}
                      >
                        {entry.event}
                      </span>
                    </td>
                    <td className="py-1.5 px-2">{entry.scan_type || '—'}</td>
                    <td className="py-1.5 px-2 max-w-[200px] truncate">
                      {Array.isArray(entry.targets) ? entry.targets.join(', ') : String(entry.targets || '—')}
                    </td>
                    <td className="py-1.5 px-2 font-mono">{entry.external_ip || '—'}</td>
                    <td className="py-1.5 px-2 font-mono text-[10px]">{entry.proxy || '—'}</td>
                    <td className="py-1.5 px-2">
                      {entry.duration_s != null ? `${entry.duration_s.toFixed(1)}s` : '—'}
                    </td>
                    <td className="py-1.5 px-2">{entry.findings_count ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-xs text-muted-foreground mt-2">
              Showing {auditData.entries.length} of {auditData.total} entries
            </p>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">No audit log entries found</p>
        )}
      </div>

      {/* Follow-Up Bulk Actions */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Follow-Up Bulk Actions</h3>
        <p className="text-xs text-muted-foreground mb-3">
          Bulk dismiss, accept, or delete follow-up items filtered by status.
        </p>
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground">Status:</label>
            <select
              className="h-8 px-2 text-xs rounded-md border border-border bg-background"
              value={bulkStatus}
              onChange={e => setBulkStatus(e.target.value)}
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground">Action:</label>
            <select
              className="h-8 px-2 text-xs rounded-md border border-border bg-background"
              value={bulkAction}
              onChange={e => setBulkAction(e.target.value as 'dismiss' | 'accept' | 'delete')}
            >
              <option value="dismiss">Dismiss All</option>
              <option value="accept">Accept All (→ In Progress)</option>
              <option value="delete">Delete All</option>
            </select>
          </div>
          <button
            onClick={async () => {
              const label = `${bulkAction} all "${bulkStatus}" follow-ups`
              if (!window.confirm(`Are you sure you want to ${label}?`)) return
              setBulkResult('Running...')
              try {
                const data = await bulkUpdate.mutateAsync({
                  action: bulkAction,
                  source_status: bulkStatus,
                })
                setBulkResult(`${data.action}: ${data.affected} follow-ups affected`)
              } catch (err: unknown) {
                setBulkResult(`Error: ${err instanceof Error ? err.message : 'Unknown'}`)
              }
            }}
            disabled={bulkUpdate.isPending}
            className={
              'h-8 px-4 text-xs rounded-md text-white disabled:opacity-50 ' +
              (bulkAction === 'delete'
                ? 'bg-red-600 hover:bg-red-700'
                : 'bg-primary hover:bg-primary/90')
            }
          >
            {bulkUpdate.isPending ? 'Running...' : 'Apply'}
          </button>
          {bulkResult && (
            <span className="text-xs font-mono text-primary">{bulkResult}</span>
          )}
        </div>
      </div>

      {/* Cleanup Actions */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Cleanup Actions</h3>
        <div className="space-y-4">
          {ACTIONS.map(action => (
            <div
              key={action.key}
              className="flex flex-col sm:flex-row sm:items-center gap-2 p-3 rounded-md bg-muted/20 border border-border"
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium">{action.label}</p>
                <p className="text-xs text-muted-foreground">{action.description}</p>
                {results[action.key] && (
                  <p className="text-xs mt-1 font-mono text-primary">{results[action.key]}</p>
                )}
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {action.hasAge && (
                  <input
                    type="number"
                    min={1}
                    placeholder="hours"
                    value={ages[action.key] || ''}
                    onChange={e => setAge(action.key, e.target.value)}
                    className="w-20 h-8 rounded-md border border-border bg-background px-2 text-xs"
                  />
                )}
                <button
                  onClick={() => run(action, true)}
                  disabled={cleanup.isPending}
                  className="h-8 px-3 text-xs rounded-md border border-border bg-background hover:bg-accent disabled:opacity-50"
                >
                  Preview
                </button>
                <button
                  onClick={() => run(action, false)}
                  disabled={cleanup.isPending}
                  className={
                    'h-8 px-3 text-xs rounded-md text-white disabled:opacity-50 ' +
                    (action.danger
                      ? 'bg-red-600 hover:bg-red-700'
                      : 'bg-destructive hover:bg-destructive/90')
                  }
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
