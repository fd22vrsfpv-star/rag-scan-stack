import { useState, useMemo } from 'react'
import {
  useArtifacts, useArtifactStats, useArtifact, useArtifactActions,
  useQueueActions, useAutoQueueSetting, useSetAutoQueue, formatBytes,
  type ArtifactAction, type CustomAction,
} from '@/api/artifacts'
import {
  FileText, Braces, Loader2, Search, X, Copy, Check, Download, Play,
  AlertTriangle, CheckCircle2, Clock, Zap, RefreshCw, ChevronRight, Sparkles,
  Pencil, Plus, Bot, RotateCcw,
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

const CATEGORY_COLOR: Record<string, string> = {
  smb: 'text-purple-400', web: 'text-blue-400', ftp: 'text-cyan-400',
  exploit: 'text-red-400', credentials: 'text-orange-400', database: 'text-emerald-400',
  recon: 'text-yellow-400', tls: 'text-indigo-400', nfs: 'text-pink-400',
  snmp: 'text-teal-400', ssh: 'text-lime-400', llm: 'text-fuchsia-400',
}

function priorityTone(p: number): string {
  if (p >= 80) return 'bg-red-500/15 text-red-400 border-red-500/30'
  if (p >= 65) return 'bg-orange-500/15 text-orange-400 border-orange-500/30'
  if (p >= 50) return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
  return 'bg-gray-500/15 text-gray-400 border-gray-500/30'
}

export default function ScanResults() {
  const [filters, setFilters] = useState<{ tool?: string; target?: string; llm_status?: string; content_format?: string }>({})
  const [page, setPage] = useState(0)
  const [selectedId, setSelectedId] = useState<string | null>(null)
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
        <div className="ml-auto text-xs text-gray-500">
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
              {data.artifacts.map(a => (
                <tr key={a.id}
                    onClick={() => setSelectedId(a.id)}
                    className="border-t border-gray-800 hover:bg-gray-800/40 cursor-pointer">
                  <td className="px-3 py-2 font-mono">{a.tool}</td>
                  <td className="px-3 py-2 text-gray-300">{a.target || '—'}</td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1 text-xs">
                      {a.native_json
                        ? <><Braces className="w-3 h-3 text-green-400" /><span className="text-green-400">{a.content_format}</span></>
                        : <span className="text-gray-400">{a.content_format}</span>}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right text-gray-400">{formatBytes(a.byte_size)}</td>
                  <td className="px-3 py-2 text-right text-gray-400">{a.occurrences}</td>
                  <td className="px-3 py-2">
                    <span className={cn('px-1.5 py-0.5 rounded border text-xs', STATUS_BADGE[a.llm_status])}>
                      {a.llm_status}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-gray-500 text-xs">
                    {new Date(a.last_seen).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-gray-600"><ChevronRight className="w-4 h-4" /></td>
                </tr>
              ))}
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
function DetailDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: artifact, isLoading } = useArtifact(id)
  const [tab, setTab] = useState<'output' | 'actions'>('output')
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
            </div>
            <button onClick={onClose} className="text-gray-500 hover:text-white">
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="flex gap-1 mt-3">
            <TabButton active={tab === 'output'} onClick={() => setTab('output')}
                       icon={<FileText className="w-4 h-4" />} label="Raw Output"
                       badge={artifact ? formatBytes(artifact.byte_size) : undefined} />
            <TabButton active={tab === 'actions'} onClick={() => setTab('actions')}
                       icon={<Zap className="w-4 h-4" />} label="Follow-On Actions"
                       badge={actions ? String(actions.counts.total) : undefined} />
          </div>
        </div>

        <div className="p-4">
          {isLoading ? (
            <div className="p-8 text-center"><Loader2 className="w-5 h-5 animate-spin mx-auto text-gray-500" /></div>
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
          ) : (
            <ActionsPanel id={id} actions={actions} loading={actionsLoading} onRefresh={() => refetch()} />
          )}
        </div>
      </div>
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
                  <span className={cn('text-xs px-1.5 py-0.5 rounded border', priorityTone(a.priority))}>P{a.priority}</span>
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
