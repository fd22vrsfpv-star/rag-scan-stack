import { useState, useMemo, useEffect, useRef, Fragment } from 'react'
import {
  useArtifacts, useArtifactStats, useArtifact, useArtifactActions,
  useQueueActions, useAutoQueueSetting, useSetAutoQueue, useUploadArtifact, formatBytes,
  type ArtifactAction, type CustomAction,
} from '@/api/artifacts'
import { useAnalyzeExtractor, type ExtractorAnalyze } from '@/api/agents'
import {
  FileText, Braces, Loader2, Search, X, Copy, Check, Download, Play,
  AlertTriangle, CheckCircle2, Clock, Zap, RefreshCw, ChevronRight, Sparkles,
  Pencil, Plus, Bot, RotateCcw, Wand2, Lightbulb, ArrowRight, Upload,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * Scan Results — the raw output every tool produced, and what to do next.
 *
 * Two things drove this page. First, results were only ever visible as
 * findings, which are a lossy derivative: 8 KB of evidence, structure inferred
 * from text, and for a long time the tool's own JSON was deleted after parsing.
 * Second, deciding the next step meant reading that output by hand.
 *
 * So the page shows the complete bytes AND the follow-on actions derived from
 * them — each action citing the exact line that triggered it, because a
 * suggestion an operator cannot justify is one they cannot act on.
 */

const STATUS_BADGE: Record<string, string> = {
  pending: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  processing: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  done: 'bg-green-500/15 text-green-400 border-green-500/30',
  failed: 'bg-red-500/15 text-red-400 border-red-500/30',
  skipped: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

/** Command outcome — whether the TOOL RUN succeeded, distinct from whether the
 *  LLM reviewed it. A failed crawl that was reviewed is llm_status=done (green)
 *  but outcome=error (red): the review finished, the command did not. */
const OUTCOME_BADGE: Record<string, string> = {
  ok:    'bg-green-500/15 text-green-400 border-green-500/30',
  empty: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
  error: 'bg-red-500/15 text-red-400 border-red-500/30',
}
const OUTCOME_LABEL: Record<string, string> = { ok: 'ok', empty: 'no items', error: 'error' }

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400',
  low: 'text-blue-400', info: 'text-gray-400',
}

const CATEGORY_COLOR: Record<string, string> = {
  smb: 'text-purple-400', web: 'text-blue-400', ftp: 'text-cyan-400',
  exploit: 'text-red-400', credentials: 'text-orange-400', database: 'text-emerald-400',
  recon: 'text-yellow-400', tls: 'text-indigo-400', nfs: 'text-pink-400',
  snmp: 'text-teal-400', ssh: 'text-lime-400', llm: 'text-fuchsia-400',
}

/** LOWER priority runs first — the convention the rest of the stack uses
 *  (scan_recommender.py: "lower int = runs first", which assigns 5 to a curated
 *  Metasploit module). This was inverted originally, so the most urgent
 *  suggestions were coloured as the least urgent. */
function priorityTone(p: number): string {
  if (p <= 20) return 'bg-red-500/15 text-red-400 border-red-500/30'
  if (p <= 35) return 'bg-orange-500/15 text-orange-400 border-orange-500/30'
  if (p <= 50) return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
  return 'bg-gray-500/15 text-gray-400 border-gray-500/30'
}

export default function ScanResults() {
  const [filters, setFilters] = useState<{ tool?: string; target?: string; llm_status?: string; content_format?: string }>({})
  const [page, setPage] = useState(0)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showUpload, setShowUpload] = useState(false)
  const PAGE_SIZE = 25

  const { data, isLoading } = useArtifacts({ ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE })
  const { data: stats } = useArtifactStats()

  const tools = useMemo(
    () => Array.from(new Set((data?.artifacts || []).map(a => a.tool))).sort(),
    [data],
  )
  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <FileText className="w-6 h-6 text-blue-400" />
            Scan Results
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Complete raw output from every tool run — and the follow-on actions it suggests.
          </p>
          {/* Stated where the operator meets the data, not only in the docs.
              Output is stored unredacted by design, so recovered passwords and
              hashes are in here verbatim. */}
          <p className="text-xs text-amber-400/90 mt-1 flex items-start gap-1">
            <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
            <span>
              Raw output is stored unredacted — it contains recovered credentials in
              plaintext. Treat this view, the database and its backups as credential
              material.
            </span>
          </p>
        </div>
        {stats && (
          <div className="flex gap-2 flex-wrap justify-end">
            <StatCard label="Artifacts" value={stats.total} />
            <StatCard label="Stored" value={formatBytes(stats.total_bytes)} />
            <StatCard label="Tools" value={stats.distinct_tools} />
            {Object.entries(stats.by_status).map(([status, s]) => (
              <StatCard key={status} label={status} value={s.count} tone={STATUS_BADGE[status]} />
            ))}
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap items-center bg-gray-900/50 border border-gray-800 rounded-lg p-3">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-2.5 top-2.5 text-gray-500" />
          <input
            className="pl-8 pr-3 py-1.5 bg-gray-950 border border-gray-700 rounded text-sm w-56"
            placeholder="Filter by target…"
            value={filters.target || ''}
            onChange={e => { setFilters(f => ({ ...f, target: e.target.value || undefined })); setPage(0) }}
          />
        </div>
        <Select value={filters.tool} onChange={v => { setFilters(f => ({ ...f, tool: v })); setPage(0) }}
                placeholder="All tools" options={tools} />
        <Select value={filters.llm_status} onChange={v => { setFilters(f => ({ ...f, llm_status: v })); setPage(0) }}
                placeholder="Any status" options={['pending', 'processing', 'done', 'failed', 'skipped']} />
        <Select value={filters.content_format} onChange={v => { setFilters(f => ({ ...f, content_format: v })); setPage(0) }}
                placeholder="Any format" options={['json', 'jsonl', 'xml', 'text']} />
        {(filters.tool || filters.target || filters.llm_status || filters.content_format) && (
          <button onClick={() => { setFilters({}); setPage(0) }}
                  className="text-xs text-gray-400 hover:text-white flex items-center gap-1">
            <X className="w-3 h-3" /> Clear
          </button>
        )}
        <button onClick={() => setShowUpload(true)}
                className="ml-auto px-3 py-1.5 bg-blue-600/80 hover:bg-blue-600 rounded text-sm flex items-center gap-1.5">
          <Upload className="w-4 h-4" /> Upload output
        </button>
        <div className="text-xs text-gray-500">
          {data ? `${data.total} result${data.total === 1 ? '' : 's'}` : ''}
        </div>
      </div>

      {/* List */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">
            <Loader2 className="w-5 h-5 animate-spin mx-auto" />
          </div>
        ) : !data?.artifacts.length ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            No raw output stored yet. Results appear here as tools run.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-gray-400 text-xs uppercase">
              <tr>
                <th className="text-left px-3 py-2">Tool</th>
                <th className="text-left px-3 py-2">Target</th>
                <th className="text-left px-3 py-2">Format</th>
                <th className="text-right px-3 py-2">Size</th>
                <th className="text-right px-3 py-2">Runs</th>
                <th className="text-left px-3 py-2">Processing</th>
                <th className="text-left px-3 py-2">Last seen</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {data.artifacts.map(a => {
                const nTargets = a.finding_targets || 0
                const targetLabel = nTargets === 1 && a.finding_target_sample
                  ? a.finding_target_sample
                  : nTargets > 1 ? `${nTargets} hosts`
                  : (a.target || '—')
                const outcome = a.outcome || undefined
                const showSummary = (a.finding_count || 0) > 0 || outcome === 'error'
                const open = () => setSelectedId(a.id)
                return (
                  <Fragment key={a.id}>
                    <tr onClick={open}
                        className={cn('border-t border-gray-800 hover:bg-gray-800/40 cursor-pointer',
                                      showSummary && 'border-b-0')}>
                      <td className="px-3 py-2 font-mono align-top">{a.tool}</td>
                      <td className="px-3 py-2 text-gray-300 align-top">{targetLabel}</td>
                      <td className="px-3 py-2 align-top">
                        <span className="inline-flex items-center gap-1 text-xs">
                          {a.native_json
                            ? <><Braces className="w-3 h-3 text-green-400" /><span className="text-green-400">{a.content_format}</span></>
                            : <span className="text-gray-400">{a.content_format}</span>}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-right text-gray-400 align-top">{formatBytes(a.byte_size)}</td>
                      <td className="px-3 py-2 text-right text-gray-400 align-top">{a.occurrences}</td>
                      <td className="px-3 py-2 align-top">
                        <div className="flex items-center gap-1.5">
                          {outcome && (
                            <span className={cn('px-1.5 py-0.5 rounded border text-xs', OUTCOME_BADGE[outcome])}
                                  title="Command outcome — did the tool run succeed?">
                              {OUTCOME_LABEL[outcome]}
                            </span>
                          )}
                          <span className={cn('px-1.5 py-0.5 rounded border text-xs', STATUS_BADGE[a.llm_status])}
                                title="Processing — LLM review status">
                            {a.llm_status}
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-2 text-gray-500 text-xs align-top">
                        {new Date(a.last_seen).toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-gray-600 align-top"><ChevronRight className="w-4 h-4" /></td>
                    </tr>
                    {showSummary && (
                      <tr onClick={open} className="hover:bg-gray-800/40 cursor-pointer">
                        <td></td>
                        <td colSpan={7} className="px-3 pb-2 pt-0">
                          <SummaryLine a={a} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 text-sm">
          <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
                  className="px-3 py-1 bg-gray-800 rounded disabled:opacity-40">Previous</button>
          <span className="text-gray-400">Page {page + 1} of {totalPages}</span>
          <button disabled={page + 1 >= totalPages} onClick={() => setPage(p => p + 1)}
                  className="px-3 py-1 bg-gray-800 rounded disabled:opacity-40">Next</button>
        </div>
      )}

      {selectedId && <DetailDrawer id={selectedId} onClose={() => setSelectedId(null)} />}
      {showUpload && (
        <UploadModal
          onClose={() => setShowUpload(false)}
          onUploaded={(id) => { setShowUpload(false); setSelectedId(id) }}
        />
      )}
    </div>
  )
}

/** The per-item second line: how many findings the run produced and their
 *  severities — or, for a failed command, that it produced none. */
function SummaryLine({ a }: { a: import('@/api/artifacts').Artifact }) {
  const sev = a.severity_counts || {}
  const n = a.finding_count || 0
  const chips = SEV_ORDER.filter(s => sev[s]).map(s => (
    <span key={s} className={cn('whitespace-nowrap', SEV_COLOR[s])}>{sev[s]} {s}</span>
  ))
  return (
    <div className="flex items-center gap-2 text-xs text-gray-500 flex-wrap">
      <ChevronRight className="w-3 h-3 text-gray-700 shrink-0" />
      {a.outcome === 'error' ? (
        <span className="text-red-400 flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" /> run failed
          {n > 0 ? <span className="text-gray-500">· {n} item{n === 1 ? '' : 's'} extracted before failure</span>
                 : <span className="text-gray-500">· no items extracted</span>}
        </span>
      ) : (
        <>
          <span className="text-gray-400">{n} item{n === 1 ? '' : 's'} found &amp; added</span>
          {chips.length > 0 && <span className="text-gray-700">·</span>}
          <span className="flex items-center gap-2">{chips}</span>
        </>
      )}
    </div>
  )
}

function StatCard({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className={cn('px-3 py-1.5 rounded border bg-gray-900/60 border-gray-800 text-center min-w-[72px]', tone)}>
      <div className="text-lg font-semibold leading-tight">{value}</div>
      <div className="text-[10px] uppercase tracking-wide text-gray-500">{label}</div>
    </div>
  )
}

function Select({ value, onChange, options, placeholder }: {
  value?: string; onChange: (v: string | undefined) => void; options: string[]; placeholder: string
}) {
  return (
    <select value={value || ''} onChange={e => onChange(e.target.value || undefined)}
            className="px-2 py-1.5 bg-gray-950 border border-gray-700 rounded text-sm">
      <option value="">{placeholder}</option>
      {options.map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  )
}

/** Detail view: the complete output, plus what to do next. */
/** Upload a scan output file for analysis. The operator names the tool that
 *  produced it and (optionally) a note for what it is; the file text is read in
 *  the browser and stored as a raw artifact. On success we open it straight on
 *  the Extract & Learn tab so it can be analysed / taught immediately. */
function UploadModal({ onClose, onUploaded }: { onClose: () => void; onUploaded: (id: string) => void }) {
  const upload = useUploadArtifact()
  const [tool, setTool] = useState('')
  const [target, setTarget] = useState('')
  const [note, setNote] = useState('')
  const [content, setContent] = useState('')
  const [fileName, setFileName] = useState('')
  const [err, setErr] = useState<string | null>(null)

  async function pickFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (!f) return
    setErr(null)
    try {
      const text = await f.text()
      setContent(text)
      setFileName(f.name)
      // Offer a tool name from the filename stem if the operator hasn't typed one.
      if (!tool) {
        const stem = f.name.replace(/\.[^.]+$/, '').split(/[._-]/)[0]
        if (stem) setTool(stem.toLowerCase())
      }
    } catch (e: any) { setErr(`Could not read file: ${e?.message || e}`) }
  }

  async function submit() {
    setErr(null)
    if (!tool.trim()) { setErr('Tool name is required.'); return }
    if (!content.trim()) { setErr('Choose a file or paste the output.'); return }
    try {
      const res = await upload.mutateAsync({
        tool: tool.trim(), content,
        target: target.trim() || undefined,
        note: note.trim() || undefined,
        command: fileName ? `upload:${fileName}` : undefined,
      })
      onUploaded(res.artifact_id)
    } catch (e: any) { setErr(String(e?.message || e)) }
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-gray-950 border border-gray-800 rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-gray-800 p-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Upload className="w-5 h-5 text-blue-400" /> Upload output for analysis
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-4 space-y-4">
          <p className="text-xs text-gray-400">
            Bring in output captured elsewhere. It's stored like any scan result — then you can
            open <span className="text-gray-300">Extract &amp; Learn</span> to see what's extracted
            and teach new rules, or process it in the LLM review queue.
          </p>

          <div className="grid grid-cols-2 gap-3">
            <label className="text-xs text-gray-400 space-y-1">
              <span>Tool name <span className="text-red-400">*</span></span>
              <input value={tool} onChange={e => setTool(e.target.value)}
                     placeholder="e.g. snmpwalk, smbmap, gobuster"
                     className="w-full bg-black border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 font-mono" />
            </label>
            <label className="text-xs text-gray-400 space-y-1">
              <span>Target (optional)</span>
              <input value={target} onChange={e => setTarget(e.target.value)}
                     placeholder="e.g. 10.0.0.5 or host.example.com"
                     className="w-full bg-black border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 font-mono" />
            </label>
          </div>

          <label className="text-xs text-gray-400 space-y-1 block">
            <span>Note — what is this? (optional)</span>
            <input value={note} onChange={e => setNote(e.target.value)}
                   placeholder="e.g. SNMP walk of the DMZ jump host, community 'public'"
                   className="w-full bg-black border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200" />
          </label>

          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <label className="px-2 py-1.5 bg-gray-800 hover:bg-gray-700 rounded cursor-pointer flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" /> Choose file
                <input type="file" className="hidden" onChange={pickFile} />
              </label>
              {fileName && <span className="text-gray-300 font-mono truncate">{fileName}</span>}
              {content && <span className="ml-auto text-gray-500">{formatBytes(new Blob([content]).size)}</span>}
            </div>
            <textarea value={content} onChange={e => { setContent(e.target.value); if (!fileName) setFileName('') }}
                      placeholder="…or paste the raw tool output here"
                      className="w-full h-40 bg-black border border-gray-700 rounded p-2 text-xs font-mono text-gray-200 placeholder:text-gray-600 resize-y" />
          </div>

          {err && <div className="text-xs text-red-300 bg-black border border-red-900/40 rounded p-2 break-words">{err}</div>}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-gray-800 p-4">
          <button onClick={onClose} className="px-3 py-1.5 text-sm text-gray-400 hover:text-white">Cancel</button>
          <button onClick={submit} disabled={upload.isPending}
                  className="px-3 py-1.5 bg-blue-600/80 hover:bg-blue-600 disabled:opacity-50 rounded text-sm flex items-center gap-2">
            {upload.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
            {upload.isPending ? 'Uploading…' : 'Upload & open'}
          </button>
        </div>
      </div>
    </div>
  )
}

function DetailDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: artifact, isLoading } = useArtifact(id)
  const [tab, setTab] = useState<'review' | 'output' | 'actions' | 'learn'>('review')
  const { data: actions, isLoading: actionsLoading, refetch } = useArtifactActions(id)
  const [copied, setCopied] = useState(false)

  const pretty = useMemo(() => {
    if (!artifact?.content) return ''
    // Pretty-print JSON so the tool's own structure is readable rather than
    // arriving as one long line.
    if (artifact.content_format === 'json') {
      try { return JSON.stringify(JSON.parse(artifact.content), null, 2) } catch { /* fall through */ }
    }
    if (artifact.content_format === 'jsonl') {
      try {
        return artifact.content.split('\n').filter(Boolean)
          .map(l => JSON.stringify(JSON.parse(l), null, 2)).join('\n\n')
      } catch { /* fall through */ }
    }
    return artifact.content
  }, [artifact])

  function copy() {
    navigator.clipboard.writeText(artifact?.content || '')
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  function download() {
    const ext = artifact?.content_format === 'text' ? 'txt' : artifact?.content_format || 'txt'
    const blob = new Blob([artifact?.content || ''], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${artifact?.tool || 'artifact'}-${(artifact?.target || 'output').replace(/[^\w.-]/g, '_')}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex justify-end" onClick={onClose}>
      <div className="bg-gray-950 border-l border-gray-800 w-full max-w-4xl h-full overflow-y-auto"
           onClick={e => e.stopPropagation()}>
        <div className="sticky top-0 bg-gray-950 border-b border-gray-800 p-4 z-10">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <span className="font-mono">{artifact?.tool}</span>
                {artifact?.native_json && (
                  <span className="text-xs px-1.5 py-0.5 rounded border border-green-500/30 bg-green-500/15 text-green-400 flex items-center gap-1">
                    <Braces className="w-3 h-3" /> native JSON
                  </span>
                )}
              </h2>
              <p className="text-sm text-gray-400 truncate">{artifact?.target}</p>
              {artifact?.command && (
                <p className="text-xs text-gray-600 font-mono mt-1 truncate">$ {artifact.command}</p>
              )}
              {artifact?.note && (
                <p className="text-xs text-blue-300/80 mt-1 flex items-center gap-1">
                  <Lightbulb className="w-3 h-3 shrink-0" /> {artifact.note}
                </p>
              )}
            </div>
            <button onClick={onClose} className="text-gray-500 hover:text-white">
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="flex gap-1 mt-3">
            <TabButton active={tab === 'review'} onClick={() => setTab('review')}
                       icon={<Sparkles className="w-4 h-4" />} label="LLM Review"
                       badge={artifact?.llm_status} />
            <TabButton active={tab === 'output'} onClick={() => setTab('output')}
                       icon={<FileText className="w-4 h-4" />} label="Raw Output"
                       badge={artifact ? formatBytes(artifact.byte_size) : undefined} />
            <TabButton active={tab === 'actions'} onClick={() => setTab('actions')}
                       icon={<Zap className="w-4 h-4" />} label="Follow-On Actions"
                       badge={actions ? String(actions.counts.total) : undefined} />
            <TabButton active={tab === 'learn'} onClick={() => setTab('learn')}
                       icon={<Wand2 className="w-4 h-4" />} label="Extract & Learn" />
          </div>
        </div>

        <div className="p-4">
          {isLoading ? (
            <div className="p-8 text-center"><Loader2 className="w-5 h-5 animate-spin mx-auto text-gray-500" /></div>
          ) : tab === 'review' ? (
            <ReviewPanel artifact={artifact} />
          ) : tab === 'output' ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 flex-wrap text-xs text-gray-400">
                <Meta label="Format" value={artifact?.content_format} />
                <Meta label="Occurrences" value={artifact?.occurrences} />
                <Meta label="First seen" value={artifact && new Date(artifact.first_seen).toLocaleString()} />
                <Meta label="SHA-256" value={artifact?.content_sha256.slice(0, 12)} mono />
                <div className="ml-auto flex gap-2">
                  <button onClick={copy} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1">
                    {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                  <button onClick={download} className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1">
                    <Download className="w-3 h-3" /> Download
                  </button>
                </div>
              </div>
              <pre className="bg-black border border-gray-800 rounded p-3 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-words max-h-[65vh] overflow-y-auto">
                {pretty}
              </pre>
            </div>
          ) : tab === 'learn' ? (
            <LearnPanel artifact={artifact} />
          ) : (
            <ActionsPanel id={id} actions={actions} loading={actionsLoading} onRefresh={() => refetch()} />
          )}
        </div>
      </div>
    </div>
  )
}

/** Extract & Learn — turn a scan's raw output into reusable extraction rules.
 *
 *  Shows what the deterministic profile pulls out of this artifact RIGHT NOW
 *  (code-only, no model), then lets the reviewer point the LLM at "anything new
 *  to focus on". Whatever the LLM extracts that the regexes missed becomes an
 *  ACTIVE deterministic rule (extracted for free next time) plus a PROPOSED
 *  finding rule for review in AI Agents → Learned Extractors. This is the
 *  "I see something worth extracting" → "the tool learns it" loop. */
function LearnPanel({ artifact }: { artifact?: import('@/api/artifacts').Artifact }) {
  const analyze = useAnalyzeExtractor()
  const [view, setView] = useState<ExtractorAnalyze | null>(null)
  const [focus, setFocus] = useState('')
  const [learning, setLearning] = useState(false)
  const [learned, setLearned] = useState<ExtractorAnalyze['learn'] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const previewedFor = useRef<string | null>(null)

  // Preview (learn=false) once per artifact: no model call, no writes.
  useEffect(() => {
    if (!artifact?.id || previewedFor.current === artifact.id) return
    previewedFor.current = artifact.id
    setView(null); setLearned(null); setErr(null); setFocus('')
    analyze.mutateAsync({ artifact_id: artifact.id, learn: false })
      .then(setView).catch(e => setErr(String(e?.message || e)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [artifact?.id])

  async function runLearn() {
    if (!artifact?.id) return
    setLearning(true); setErr(null); setLearned(null)
    try {
      const r = await analyze.mutateAsync({
        artifact_id: artifact.id, learn: true, focus: focus.trim() || undefined,
      })
      setView(r); setLearned(r.learn ?? null)
    } catch (e: any) { setErr(String(e?.message || e)) }
    finally { setLearning(false) }
  }

  const det = view?.deterministic || {}
  const detKeys = Object.keys(det)
  const cov = view?.coverage
  const focusRes = learned?.focus

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 text-xs text-gray-400 bg-fuchsia-500/5 border border-fuchsia-500/20 rounded p-3">
        <Wand2 className="w-4 h-4 text-fuchsia-400 shrink-0 mt-0.5" />
        <p>See what the extractor pulls from this output today, then point the LLM at anything
           it's missing. What it learns becomes a reusable deterministic rule — no model needed
           next time — and a proposed finding you approve in <span className="text-gray-300">AI Agents → Learned Extractors</span>.</p>
      </div>

      {/* What is extracted normally */}
      <section className="space-y-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Braces className="w-4 h-4 text-green-400" /> Extracted normally (code-only)
          {view && (
            <span className="text-xs text-gray-500 font-normal">
              {view.has_profile ? `profile: ${view.source_file}` : 'no profile yet'}
            </span>
          )}
        </div>
        {!view && !err ? (
          <div className="p-4 text-center"><Loader2 className="w-4 h-4 animate-spin mx-auto text-gray-500" /></div>
        ) : !view?.has_profile ? (
          <p className="text-xs text-gray-500 bg-black border border-gray-800 rounded p-3">
            No extractor profile for <span className="font-mono text-gray-300">{view?.tool}</span> yet.
            Use the box below to teach one from this output — the first thing it learns creates the profile.
          </p>
        ) : detKeys.length === 0 ? (
          <p className="text-xs text-gray-500 bg-black border border-gray-800 rounded p-3">
            The profile matched no fields in this particular output.
          </p>
        ) : (
          <div className="bg-black border border-gray-800 rounded divide-y divide-gray-900">
            {detKeys.map(k => (
              <div key={k} className="flex gap-3 px-3 py-1.5 text-xs">
                <span className="font-mono text-fuchsia-300 shrink-0 w-40 truncate">{k}</span>
                <span className="font-mono text-gray-300 break-all">
                  {Array.isArray((det as any)[k]) ? ((det as any)[k] as any[]).join(', ') : String((det as any)[k])}
                </span>
              </div>
            ))}
          </div>
        )}
        {cov && (
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <div className="h-1.5 flex-1 bg-gray-800 rounded overflow-hidden">
              <div className="h-full bg-green-500/60" style={{ width: `${cov.coverage_pct}%` }} />
            </div>
            <span>{cov.coverage_pct}% covered · {cov.residual_lines} line(s) unexplained</span>
          </div>
        )}
      </section>

      {/* Focus + learn */}
      <section className="space-y-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Lightbulb className="w-4 h-4 text-yellow-400" /> Anything new to focus on?
        </div>
        <textarea
          value={focus} onChange={e => setFocus(e.target.value)}
          placeholder="Optional: name what you want extracted, e.g. 'the SMB signing requirement' or 'the certificate serial number'. Leave blank to let the LLM fill any gaps in the profile's schema."
          className="w-full h-20 bg-black border border-gray-800 rounded p-2 text-xs font-mono text-gray-200 placeholder:text-gray-600 resize-y" />
        <button onClick={runLearn} disabled={learning || !view}
                className="px-3 py-1.5 bg-fuchsia-600/80 hover:bg-fuchsia-600 disabled:opacity-50 rounded text-sm flex items-center gap-2">
          {learning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
          {learning ? 'Sending to LLM…' : 'Send to LLM & Learn'}
        </button>
      </section>

      {err && (
        <div className="text-xs text-red-300 bg-black border border-red-900/40 rounded p-2 break-words">{err}</div>
      )}

      {/* Learn results */}
      {learned && (
        <section className="space-y-2">
          <div className="flex items-center gap-2 text-sm font-medium">
            <CheckCircle2 className="w-4 h-4 text-green-400" /> Result
          </div>
          {focusRes && (
            <div className={cn('text-xs rounded p-2 border',
              focusRes.found ? 'bg-green-500/5 border-green-500/20' : 'bg-gray-800/40 border-gray-700')}>
              {focusRes.found ? (
                <div className="flex items-start gap-2">
                  <ArrowRight className="w-3 h-3 text-green-400 mt-0.5 shrink-0" />
                  <span>
                    Focus <span className="font-mono text-gray-200">"{focusRes.requested}"</span> →
                    field <span className="font-mono text-fuchsia-300">{focusRes.field}</span>
                    {focusRes.already_covered
                      ? ' — already covered by an existing rule.'
                      : focusRes.learned ? ' — learned as a new deterministic rule.' : ' — extracted, but no stable regex could be authored.'}
                    {focusRes.value != null && (
                      <span className="block text-gray-400 mt-0.5 font-mono break-all">
                        value: {Array.isArray(focusRes.value) ? (focusRes.value as any[]).join(', ') : String(focusRes.value)}
                      </span>)}
                  </span>
                </div>
              ) : (
                <span className="text-gray-400">Focus <span className="font-mono">"{focusRes.requested}"</span> was not found in this output{focusRes.error ? ` (${focusRes.error})` : '.'}</span>
              )}
            </div>
          )}
          <div className="grid grid-cols-3 gap-2 text-xs">
            <ResultStat label="Rules learned" value={learned.learned.length} tone="text-green-400" />
            <ResultStat label="Findings proposed" value={learned.proposed_notable.length} tone="text-yellow-400" />
            <ResultStat label="Skipped" value={learned.skipped.length} tone="text-gray-400" />
          </div>
          {learned.learned.length > 0 && (
            <p className="text-xs text-gray-400">
              New deterministic field(s): <span className="font-mono text-fuchsia-300">{learned.learned.join(', ')}</span>.
              These extract for free from now on. Approve the proposed finding(s) in{' '}
              <span className="text-gray-300">AI Agents → Learned Extractors</span>, then Export to write them into the tool's YAML.
            </p>
          )}
          {learned.learned.length === 0 && !focusRes?.found && (
            <p className="text-xs text-gray-500">Nothing new to learn — the profile already covers this output.</p>
          )}
        </section>
      )}
    </div>
  )
}

function ResultStat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="bg-black border border-gray-800 rounded p-2 text-center">
      <div className={cn('text-lg font-semibold', tone)}>{value}</div>
      <div className="text-gray-500">{label}</div>
    </div>
  )
}

/** The LLM enrichment pass over one artifact: its summary of what the raw
 *  output actually shows. Stored in raw_artifacts.llm_result by the artifact
 *  consumer (/artifacts/drain). Answers "what did the review find?" without
 *  making the operator read the raw bytes. */
function ReviewPanel({ artifact }: { artifact?: import('@/api/artifacts').Artifact }) {
  if (!artifact) return null
  const status = artifact.llm_status
  const r = (artifact.llm_result || {}) as Record<string, any>
  const summary: string = typeof r.summary === 'string' ? r.summary : ''
  const asList = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter(x => typeof x === 'string' && x.trim()) : []
  const findings = asList(r.findings)
  const services = asList(r.services)
  const nextSteps = asList(r.next_steps)
  const confidence: string | undefined = typeof r.confidence === 'string' ? r.confidence : undefined
  const meta = (r._meta || {}) as Record<string, any>

  if (status === 'pending' || status === 'processing') {
    return (
      <div className="p-6 text-center space-y-2">
        <Clock className="w-6 h-6 mx-auto text-yellow-400" />
        <p className="text-sm text-gray-300">
          {status === 'processing' ? 'Review in progress…' : 'Not reviewed yet.'}
        </p>
        <p className="text-xs text-gray-500 max-w-md mx-auto">
          Run the LLM review pass from the <span className="text-gray-300">AI Agents → Artifact LLM Review → Process Queue</span> button.
          The review summarises this output so you don't have to read the raw bytes.
        </p>
      </div>
    )
  }
  if (status === 'skipped') {
    return (
      <div className="p-6 space-y-2">
        <div className="flex items-center gap-2 text-gray-400"><AlertTriangle className="w-4 h-4" /> Skipped</div>
        <p className="text-xs text-gray-500">{artifact.llm_error || 'This artifact was skipped by the review pass.'}</p>
      </div>
    )
  }
  if (status === 'failed') {
    return (
      <div className="p-6 space-y-2">
        <div className="flex items-center gap-2 text-red-400"><AlertTriangle className="w-4 h-4" /> Review failed</div>
        <pre className="text-xs text-red-300/80 whitespace-pre-wrap break-words bg-black border border-red-900/40 rounded p-2">{artifact.llm_error || 'unknown error'}</pre>
      </div>
    )
  }
  if (!summary && !findings.length && !services.length && !nextSteps.length) {
    return <div className="p-6 text-sm text-gray-500">Reviewed, but the model returned nothing of interest.</div>
  }

  const confTone = confidence === 'high' ? 'text-green-400 border-green-500/30 bg-green-500/10'
    : confidence === 'low' ? 'text-red-400 border-red-500/30 bg-red-500/10'
    : 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10'

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap text-xs">
        {confidence && <span className={cn('px-2 py-0.5 rounded border', confTone)}>confidence: {confidence}</span>}
        {artifact.llm_model && <Meta label="Model" value={artifact.llm_model} mono />}
        {typeof meta.latency_ms === 'number' && <Meta label="Latency" value={`${meta.latency_ms} ms`} />}
        {artifact.llm_processed_at && <Meta label="Reviewed" value={new Date(artifact.llm_processed_at).toLocaleString()} />}
      </div>

      {summary && (
        <div className="bg-gray-900/60 border border-gray-800 rounded p-3">
          <p className="text-sm text-gray-200">{summary}</p>
        </div>
      )}

      <ReviewList title="Findings" items={findings} icon={<AlertTriangle className="w-4 h-4 text-amber-400" />} tone="text-amber-300" />
      <ReviewList title="Services / versions" items={services} icon={<Braces className="w-4 h-4 text-blue-400" />} tone="text-blue-300" />
      <ReviewList title="Suggested next steps" items={nextSteps} icon={<ChevronRight className="w-4 h-4 text-green-400" />} tone="text-green-300" />

      <p className="text-[11px] text-gray-600">
        Runnable follow-ons (with a Queue button) are on the <span className="text-gray-400">Follow-On Actions</span> tab.
      </p>
    </div>
  )
}

function ReviewList({ title, items, icon, tone }: {
  title: string; items: string[]; icon: React.ReactNode; tone: string
}) {
  if (!items.length) return null
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-300">{icon} {title} <span className="text-gray-600">({items.length})</span></div>
      <ul className="space-y-1">
        {items.map((it, i) => (
          <li key={i} className={cn('text-sm flex gap-2', tone)}>
            <span className="text-gray-600 select-none">•</span>
            <span className="text-gray-200">{it}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function TabButton({ active, onClick, icon, label, badge }: {
  active: boolean; onClick: () => void; icon: React.ReactNode; label: string; badge?: string
}) {
  return (
    <button onClick={onClick}
            className={cn('px-3 py-1.5 rounded text-sm flex items-center gap-1.5 border',
              active ? 'bg-blue-500/15 text-blue-400 border-blue-500/30'
                     : 'bg-gray-900 text-gray-400 border-gray-800 hover:text-white')}>
      {icon}{label}
      {badge && <span className="text-xs px-1 rounded bg-gray-800 text-gray-400">{badge}</span>}
    </button>
  )
}

function Meta({ label, value, mono }: { label: string; value?: string | number | null; mono?: boolean }) {
  if (value === undefined || value === null) return null
  return (
    <span className="px-2 py-1 bg-gray-900 border border-gray-800 rounded">
      <span className="text-gray-600">{label}:</span>{' '}
      <span className={cn('text-gray-300', mono && 'font-mono')}>{value}</span>
    </span>
  )
}

/** Follow-on actions: rule-derived, editable, plus operator-written ones. */
function ActionsPanel({ id, actions, loading, onRefresh }: {
  id: string
  actions?: { actions: ArtifactAction[]; counts: Record<string, number>; target: string | null }
  loading: boolean
  onRefresh: () => void
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  // action_id -> edited command. Kept separate from the suggestion itself so
  // "Reset" can always restore what the rule actually proposed.
  const [edits, setEdits] = useState<Record<string, string>>({})
  const [editing, setEditing] = useState<string | null>(null)
  const [custom, setCustom] = useState<CustomAction[]>([])
  const [showCustom, setShowCustom] = useState(false)
  const queue = useQueueActions(id)
  const { data: autoQ } = useAutoQueueSetting()
  const setAutoQ = useSetAutoQueue()

  function toggle(actionId: string) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(actionId) ? next.delete(actionId) : next.add(actionId)
      return next
    })
  }

  if (loading) {
    return <div className="p-8 text-center"><Loader2 className="w-5 h-5 animate-spin mx-auto text-gray-500" /></div>
  }

  const list = actions?.actions || []
  const chosen = Array.from(selected)
  // An action needing input can only be queued once its placeholders are
  // filled, so an unedited one blocks the submit rather than failing at the API.
  const blocked = chosen.filter(cid => {
    const a = list.find(x => x.id === cid)
    return a?.needs_input && !edits[cid]
  })
  const canQueue = (chosen.length > 0 || custom.length > 0) && blocked.length === 0

  function submit() {
    const overrides: Record<string, { script?: string }> = {}
    chosen.forEach(cid => { if (edits[cid]) overrides[cid] = { script: edits[cid] } })
    queue.mutate(
      { action_ids: chosen, overrides, custom_actions: custom },
      { onSuccess: () => { setSelected(new Set()); setCustom([]); setEdits({}) } },
    )
  }

  return (
    <div className="space-y-3">
      {/* Automation state — what happens without anyone clicking. */}
      <div className="flex items-center gap-2 flex-wrap text-xs bg-gray-900/60 border border-gray-800 rounded p-2">
        <Bot className="w-4 h-4 text-blue-400" />
        <span className="text-gray-300">
          Auto-queue is <b>{autoQ?.enabled ? 'on' : 'off'}</b>
        </span>
        <span className="text-gray-500">
          — {autoQ?.enabled
            ? `${autoQ.auto_queue_rules.length} rule(s) queue themselves as pending when matching output arrives. Nothing runs until you press Run.`
            : 'every follow-up must be queued by hand.'}
        </span>
        <button
          onClick={() => setAutoQ.mutate(!(autoQ?.enabled))}
          className="ml-auto px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded">
          Turn {autoQ?.enabled ? 'off' : 'on'}
        </button>
      </div>

      {!!autoQ?.rule_errors?.length && (
        <div className="text-xs bg-red-500/10 border border-red-500/30 text-red-400 rounded p-2">
          <b>Rule file problems</b> — affected rules are not running:
          <ul className="list-disc ml-4 mt-1">
            {autoQ.rule_errors.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap text-xs">
        <span className="text-gray-400">{list.length} suggested</span>
        {!!actions?.counts.already_run && <span className="text-gray-500">· {actions.counts.already_run} already run</span>}
        {!!actions?.counts.queued && <span className="text-blue-400">· {actions.counts.queued} queued</span>}
        <button onClick={onRefresh} className="ml-auto px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1">
          <RefreshCw className="w-3 h-3" /> Re-analyse
        </button>
        <button onClick={() => setShowCustom(v => !v)}
                className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded flex items-center gap-1">
          <Plus className="w-3 h-3" /> Add your own
        </button>
        <button disabled={!canQueue || queue.isPending} onClick={submit}
                className="px-3 py-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 rounded flex items-center gap-1">
          {queue.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
          Queue {chosen.length + custom.length || ''}
        </button>
      </div>

      {blocked.length > 0 && (
        <div className="text-xs bg-orange-500/10 border border-orange-500/30 text-orange-400 rounded p-2">
          {blocked.length} selected action(s) still contain placeholders. Edit the
          command to fill them in — an unresolved command cannot run.
        </div>
      )}

      {showCustom && <CustomActionForm target={actions?.target || ''} onAdd={a => setCustom(c => [...c, a])} />}

      {custom.map((c, i) => (
        <div key={`c${i}`} className="border border-emerald-500/40 bg-emerald-500/5 rounded-lg p-3">
          <div className="flex items-center gap-2">
            <span className="text-xs px-1.5 py-0.5 rounded border border-emerald-500/30 text-emerald-400">manual</span>
            <span className="font-medium text-sm">{c.title}</span>
            <button onClick={() => setCustom(list => list.filter((_, j) => j !== i))}
                    className="ml-auto text-gray-500 hover:text-white"><X className="w-4 h-4" /></button>
          </div>
          <pre className="text-xs font-mono bg-black border border-gray-800 rounded px-2 py-1 mt-2 overflow-x-auto">{c.script}</pre>
        </div>
      ))}

      {queue.isSuccess && (
        <div className="text-xs bg-green-500/10 border border-green-500/30 text-green-400 rounded p-2">
          Queued as pending scan recommendations — run them from the Recommendations page.
        </div>
      )}
      {queue.isError && (
        <div className="text-xs bg-red-500/10 border border-red-500/30 text-red-400 rounded p-2">
          {(queue.error as Error).message}
        </div>
      )}

      {!list.length && !custom.length && (
        <div className="p-8 text-center text-gray-500 text-sm">
          No follow-on actions matched this output.
          <p className="text-xs text-gray-600 mt-1">
            Suggestions are evidence-based — nothing is proposed unless something in
            the output supports it. You can still add your own above.
          </p>
        </div>
      )}

      {list.map(a => {
        const script = edits[a.id] ?? a.script
        const isEdited = edits[a.id] !== undefined && edits[a.id] !== a.script
        return (
          <div key={a.id}
               className={cn('border rounded-lg p-3 space-y-2',
                 selected.has(a.id) ? 'border-blue-500/50 bg-blue-500/5' : 'border-gray-800 bg-gray-900/40')}>
            <div className="flex items-start gap-3">
              <input type="checkbox" className="mt-1" checked={selected.has(a.id)}
                     onChange={() => toggle(a.id)} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium">{a.title}</span>
                  <span title="Lower runs first"
                        className={cn('text-xs px-1.5 py-0.5 rounded border', priorityTone(a.priority))}>
                    P{a.priority}
                  </span>
                  <span className={cn('text-xs', CATEGORY_COLOR[a.category] || 'text-gray-400')}>{a.category}</span>
                  {a.auto_queue && (
                    <span className="text-xs px-1.5 py-0.5 rounded border border-blue-500/30 bg-blue-500/10 text-blue-400 flex items-center gap-1">
                      <Bot className="w-3 h-3" /> auto-queues
                    </span>
                  )}
                  {a.source === 'llm' && (
                    <span className="text-xs px-1.5 py-0.5 rounded border border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-400 flex items-center gap-1">
                      <Sparkles className="w-3 h-3" /> LLM
                    </span>
                  )}
                  {a.already_run.ran && (
                    <span className="text-xs px-1.5 py-0.5 rounded border border-gray-600 bg-gray-800 text-gray-300 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> ran {a.already_run.count}×
                    </span>
                  )}
                  {a.queued_status && (
                    <span className="text-xs px-1.5 py-0.5 rounded border border-blue-500/30 bg-blue-500/10 text-blue-400 flex items-center gap-1">
                      <Clock className="w-3 h-3" /> queued ({a.queued_status})
                    </span>
                  )}
                  {a.needs_input && !edits[a.id] && (
                    <span className="text-xs px-1.5 py-0.5 rounded border border-orange-500/30 bg-orange-500/10 text-orange-400 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> needs input
                    </span>
                  )}
                  {isEdited && (
                    <span className="text-xs px-1.5 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">edited</span>
                  )}
                </div>
                <p className="text-xs text-gray-400 mt-1">{a.rationale}</p>

                {editing === a.id ? (
                  <div className="mt-2 space-y-1">
                    <textarea
                      className="w-full bg-black border border-blue-500/40 rounded px-2 py-1 text-xs font-mono"
                      rows={2} value={script}
                      onChange={e => setEdits(p => ({ ...p, [a.id]: e.target.value }))} />
                    <div className="flex gap-2">
                      <button onClick={() => setEditing(null)}
                              className="px-2 py-0.5 bg-gray-800 hover:bg-gray-700 rounded text-xs">Done</button>
                      <button onClick={() => { setEdits(p => { const n = { ...p }; delete n[a.id]; return n }); setEditing(null) }}
                              className="px-2 py-0.5 bg-gray-800 hover:bg-gray-700 rounded text-xs flex items-center gap-1">
                        <RotateCcw className="w-3 h-3" /> Reset
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-start gap-2 mt-2">
                    <pre className="flex-1 text-xs font-mono bg-black border border-gray-800 rounded px-2 py-1 overflow-x-auto">{script}</pre>
                    <button onClick={() => setEditing(a.id)} title="Edit command"
                            className="px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded">
                      <Pencil className="w-3 h-3" />
                    </button>
                  </div>
                )}

                {a.evidence && (
                  <div className="mt-2 text-xs">
                    <span className="text-gray-600">Evidence from output: </span>
                    <code className="text-yellow-300/80 bg-yellow-500/5 px-1 rounded break-all">{a.evidence}</code>
                  </div>
                )}
                {a.already_run.ran && a.already_run.last_at && (
                  <p className="text-[11px] text-gray-600 mt-1">
                    Last run {new Date(a.already_run.last_at).toLocaleString()} ({a.already_run.last_status})
                    — queue again to re-run.
                  </p>
                )}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

/** Operator-written follow-up, for anything the rules do not cover. */
function CustomActionForm({ target, onAdd }: { target: string; onAdd: (a: CustomAction) => void }) {
  const [title, setTitle] = useState('')
  const [scanner, setScanner] = useState('')
  const [script, setScript] = useState('')
  const [priority, setPriority] = useState(60)

  // The scanner must be a bare tool name: it selects the dispatch route, and
  // the executor validates it against the tool allowlist.
  const validScanner = /^[a-zA-Z0-9_.-]+$/.test(scanner)
  const ready = title.trim() && validScanner && script.trim()

  return (
    <div className="border border-gray-700 bg-gray-900/60 rounded-lg p-3 space-y-2">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        <input className="px-2 py-1 bg-gray-950 border border-gray-700 rounded text-sm"
               placeholder="What is this for?" value={title} onChange={e => setTitle(e.target.value)} />
        <input className={cn('px-2 py-1 bg-gray-950 border rounded text-sm font-mono',
                 scanner && !validScanner ? 'border-red-500/60' : 'border-gray-700')}
               placeholder="tool (e.g. rpcinfo)" value={scanner} onChange={e => setScanner(e.target.value)} />
        <input type="number" min={0} max={100}
               className="px-2 py-1 bg-gray-950 border border-gray-700 rounded text-sm"
               value={priority} onChange={e => setPriority(Number(e.target.value))} />
      </div>
      <textarea className="w-full px-2 py-1 bg-black border border-gray-700 rounded text-xs font-mono"
                rows={2} placeholder={`command to run, e.g. rpcinfo -p ${target || '<target>'}`}
                value={script} onChange={e => setScript(e.target.value)} />
      {scanner && !validScanner && (
        <p className="text-xs text-red-400">
          Tool name must be a bare command name — no spaces or shell characters.
        </p>
      )}
      <button disabled={!ready}
              onClick={() => { onAdd({ title, scanner, script, priority }); setTitle(''); setScanner(''); setScript('') }}
              className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 rounded text-sm flex items-center gap-1">
        <Plus className="w-3 h-3" /> Add to queue list
      </button>
    </div>
  )
}
