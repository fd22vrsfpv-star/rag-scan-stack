import { useState, useRef } from 'react'
import PageHelp from '@/components/PageHelp'
import {
  useEngagements, useEngagement, useCreateEngagement, useUpdateEngagement, useDeleteEngagement,
  useCampaignEvents, useCreateCampaignEvent, useUpdateCampaignEvent, useCampaignSummary,
  useEngagementScopes, useEngagementScopeTargets, useAddScopeTargets, useDeleteScope,
  useRenameScope, useMoveTargets, useMoveEntireScope,
  type EngagementScope, type ScopeTarget,
} from '@/api/engagements'
import { useScopeNames } from '@/api/scope'
import { cn } from '@/lib/utils'
import type { Engagement, CampaignEvent, KillChainPhase } from '@/lib/types'
import { Briefcase, Plus, X, ChevronRight, Eye, Trash2, Pencil, ArrowRight, Loader2, Upload, FileText } from 'lucide-react'
import { ReconAgentPanel } from '@/components/common/ReconAgentPanel'
import { GapAnalysisAgentPanel } from '@/components/common/GapAnalysisPanel'

const ENGAGEMENT_TYPES = [
  'external_pentest', 'internal_pentest', 'web_app', 'red_team', 'purple_team', 'phishing', 'other',
] as const

const STATUS_FLOW = ['planning', 'active', 'paused', 'reporting', 'complete', 'archived'] as const

const STATUS_COLORS: Record<string, string> = {
  planning: 'bg-blue-500/10 text-blue-400',
  active: 'bg-green-500/10 text-green-400',
  paused: 'bg-yellow-500/10 text-yellow-400',
  reporting: 'bg-purple-500/10 text-purple-400',
  complete: 'bg-gray-500/10 text-gray-400',
  archived: 'bg-gray-500/10 text-gray-500',
}

const KILL_CHAIN_PHASES: KillChainPhase[] = [
  'reconnaissance', 'weaponization', 'delivery', 'exploitation',
  'installation', 'command_control', 'actions_on_objectives',
]

const KC_COLORS: Record<string, string> = {
  reconnaissance: 'bg-sky-500',
  weaponization: 'bg-orange-500',
  delivery: 'bg-yellow-500',
  exploitation: 'bg-red-500',
  installation: 'bg-purple-500',
  command_control: 'bg-pink-500',
  actions_on_objectives: 'bg-rose-600',
}

type Tab = 'list' | 'detail'

export default function Engagements() {
  const [tab, setTab] = useState<Tab>('list')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  return (
    <div className="space-y-4">
      <PageHelp id="engagements" title="How to use Engagements">
        <p>Create an engagement for each project (pentest, red team op, etc.). Select it in the <strong>top bar</strong> to filter all scans, findings, and exports to that project. Set status (planning → active → reporting → complete), add notes, and track the campaign timeline.</p>
      </PageHelp>
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Briefcase className="h-5 w-5" /> Engagements
        </h2>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-primary text-primary-foreground text-sm"
        >
          <Plus className="h-4 w-4" /> New Engagement
        </button>
      </div>

      {showCreate && <CreateEngagementDialog onClose={() => setShowCreate(false)} />}

      {selectedId ? (
        <EngagementDetail id={selectedId} onBack={() => setSelectedId(null)} />
      ) : (
        <EngagementList onSelect={setSelectedId} />
      )}
    </div>
  )
}

// ── Engagement List ──

function EngagementList({ onSelect }: { onSelect: (id: string) => void }) {
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const { data, isLoading } = useEngagements(statusFilter)
  const engagements = data?.engagements ?? []

  return (
    <div className="space-y-3">
      <div className="flex gap-1 flex-wrap">
        <button
          onClick={() => setStatusFilter(undefined)}
          className={cn('px-2 py-1 text-xs rounded', !statusFilter ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground')}
        >All</button>
        {STATUS_FLOW.filter(s => s !== 'archived').map(s => (
          <button key={s} onClick={() => setStatusFilter(s)}
            className={cn('px-2 py-1 text-xs rounded capitalize', statusFilter === s ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground')}
          >{s}</button>
        ))}
      </div>

      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading...</div>
      ) : engagements.length === 0 ? (
        <div className="text-sm text-muted-foreground">No engagements found. Create one to get started.</div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {engagements.map(eng => (
            <button
              key={eng.id}
              onClick={() => onSelect(eng.id)}
              className="text-left p-4 rounded-lg border border-border bg-card hover:border-primary/50 transition-colors"
            >
              <div className="flex items-start justify-between">
                <div className="font-medium text-sm">{eng.name}</div>
                <span className={cn('px-2 py-0.5 text-xs rounded-full capitalize', STATUS_COLORS[eng.status] || 'bg-muted')}>
                  {eng.status}
                </span>
              </div>
              {eng.client && <div className="text-xs text-muted-foreground mt-1">{eng.client}</div>}
              <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                <span className="capitalize">{eng.engagement_type?.replace('_', ' ')}</span>
                {eng.start_date && <span>| {eng.start_date}</span>}
              </div>
              <div className="flex items-center gap-1 mt-2">
                <ChevronRight className="h-3 w-3 text-muted-foreground" />
                <span className="text-xs text-muted-foreground">View details</span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Create Dialog ──

function CreateEngagementDialog({ onClose }: { onClose: () => void }) {
  const create = useCreateEngagement()
  const { data: scopeData } = useScopeNames()
  const [form, setForm] = useState({
    name: '', client: '', engagement_type: 'external_pentest', methodology: 'custom',
    start_date: '', end_date: '', scope_name: '', rules_of_engagement: '',
  })

  const handleSubmit = () => {
    if (!form.name) return
    create.mutate(form, { onSuccess: onClose })
  }

  return (
    <div className="p-4 border border-border rounded-lg bg-card space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Create Engagement</h3>
        <button onClick={onClose}><X className="h-4 w-4" /></button>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <input placeholder="Engagement Name *" value={form.name}
          onChange={e => setForm({ ...form, name: e.target.value })}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm" />
        <input placeholder="Client" value={form.client}
          onChange={e => setForm({ ...form, client: e.target.value })}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm" />
        <select value={form.engagement_type}
          onChange={e => setForm({ ...form, engagement_type: e.target.value })}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm">
          {ENGAGEMENT_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
        </select>
        <select value={form.scope_name}
          onChange={e => setForm({ ...form, scope_name: e.target.value })}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm">
          <option value="">Select Scope</option>
          {(scopeData?.names ?? []).map((n: any) => <option key={n.name} value={n.name}>{n.name}</option>)}
        </select>
        <input type="date" value={form.start_date}
          onChange={e => setForm({ ...form, start_date: e.target.value })}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm" />
        <input type="date" value={form.end_date}
          onChange={e => setForm({ ...form, end_date: e.target.value })}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm" />
      </div>
      <textarea placeholder="Rules of Engagement" value={form.rules_of_engagement}
        onChange={e => setForm({ ...form, rules_of_engagement: e.target.value })}
        className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm h-20" />
      <button onClick={handleSubmit} disabled={create.isPending || !form.name}
        className="px-4 py-1.5 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
        {create.isPending ? 'Creating...' : 'Create'}
      </button>
    </div>
  )
}

// ── Engagement Detail + Campaign ──

// ── Scope Management Tab ─────────────────────────────────────────────────

function BulkImportTargets({ engagementId, scopeName, onDone }: {
  engagementId: string; scopeName: string; onDone: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [bulkText, setBulkText] = useState('')
  const [importing, setImporting] = useState(false)
  const [result, setResult] = useState<{ added: number; skipped: number } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const addTargets = useAddScopeTargets()

  const parseTargets = (text: string): string[] => {
    // Split by newlines, commas, semicolons, spaces — deduplicate
    const raw = text
      .split(/[\n\r,;]+/)
      .map(t => t.trim())
      .filter(t => t && !t.startsWith('#') && !t.startsWith('//'))
    // Deduplicate
    return [...new Set(raw)]
  }

  const handleImport = () => {
    const targets = parseTargets(bulkText)
    if (!targets.length) return
    setImporting(true)
    setResult(null)
    addTargets.mutate(
      { eid: engagementId, scopeName, targets, source: 'bulk_import' },
      {
        onSuccess: () => {
          setResult({ added: targets.length, skipped: 0 })
          setBulkText('')
          setImporting(false)
          onDone()
        },
        onError: () => {
          setImporting(false)
        },
      },
    )
  }

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result as string
      setBulkText(prev => prev ? prev + '\n' + text : text)
      setExpanded(true)
    }
    reader.readAsText(file)
    // Reset so same file can be re-selected
    if (fileRef.current) fileRef.current.value = ''
  }

  const targetCount = parseTargets(bulkText).length

  if (!expanded) {
    return (
      <div className="flex items-center gap-2">
        <button
          onClick={() => setExpanded(true)}
          className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-muted hover:bg-muted/80 border border-border text-muted-foreground"
        >
          <FileText className="h-2.5 w-2.5" /> Bulk Import
        </button>
        <label className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-muted hover:bg-muted/80 border border-border text-muted-foreground cursor-pointer">
          <Upload className="h-2.5 w-2.5" /> Import File
          <input ref={fileRef} type="file" accept=".txt,.csv,.lst,.list,.scope" onChange={handleFile} className="hidden" />
        </label>
      </div>
    )
  }

  return (
    <div className="bg-muted/30 border border-border rounded p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium flex items-center gap-1">
          <FileText className="h-3 w-3" /> Bulk Import Targets into "{scopeName}"
        </span>
        <button onClick={() => { setExpanded(false); setBulkText(''); setResult(null) }}
          className="text-muted-foreground hover:text-foreground"><X className="h-3 w-3" /></button>
      </div>
      <textarea
        value={bulkText}
        onChange={e => { setBulkText(e.target.value); setResult(null) }}
        placeholder={"Paste targets — one per line, or comma/semicolon separated.\nDomains, IPs, CIDRs, URLs accepted.\nLines starting with # are ignored."}
        rows={6}
        className="w-full bg-background rounded px-2 py-1.5 text-xs border border-border font-mono resize-y"
      />
      <div className="flex items-center gap-2">
        <button
          onClick={handleImport}
          disabled={importing || targetCount === 0}
          className="flex items-center gap-1 px-3 py-1 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {importing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
          Import {targetCount > 0 ? `${targetCount} target${targetCount !== 1 ? 's' : ''}` : ''}
        </button>
        <label className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-muted hover:bg-muted/80 border border-border cursor-pointer">
          <Upload className="h-3 w-3" /> Load File
          <input ref={fileRef} type="file" accept=".txt,.csv,.lst,.list,.scope" onChange={handleFile} className="hidden" />
        </label>
        {targetCount > 0 && (
          <span className="text-[10px] text-muted-foreground">{targetCount} unique target{targetCount !== 1 ? 's' : ''} parsed</span>
        )}
        {result && (
          <span className="text-[10px] text-green-400">Added {result.added} targets</span>
        )}
      </div>
    </div>
  )
}


function ScopeTab({ engagementId }: { engagementId: string }) {
  const { data: scopesData, isLoading: scopesLoading, refetch: refetchScopes } = useEngagementScopes(engagementId)
  const scopes = scopesData?.scopes ?? []
  const [selectedScope, setSelectedScope] = useState<string | null>(null)

  // Auto-select first scope when data loads
  const activeScope = selectedScope || scopes[0]?.name || null
  // If selected scope no longer exists, reset
  if (selectedScope && scopes.length > 0 && !scopes.find(s => s.name === selectedScope)) {
    setSelectedScope(null)
  }
  const [newScopeName, setNewScopeName] = useState('')
  const [newTarget, setNewTarget] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [renaming, setRenaming] = useState<string | null>(null)
  const [renameVal, setRenameVal] = useState('')
  const [showMove, setShowMove] = useState(false)
  const [moveToEng, setMoveToEng] = useState('')
  const [moveToScope, setMoveToScope] = useState('')
  const [moveNewScope, setMoveNewScope] = useState('')

  const { data: targetsData, refetch: refetchTargets } = useEngagementScopeTargets(engagementId, activeScope ?? undefined)
  const targets = targetsData?.targets ?? []
  const addTargets = useAddScopeTargets()
  const deleteScope = useDeleteScope()
  const renameScope = useRenameScope()
  const moveTargets = useMoveTargets()
  const moveEntireScope = useMoveEntireScope()
  const [showMoveScope, setShowMoveScope] = useState(false)
  const [moveScopeToEng, setMoveScopeToEng] = useState('')
  const { data: engData } = useEngagements()
  const allEngagements = engData?.engagements ?? []
  const destEngId = moveToEng || engagementId
  const { data: destScopesData } = useEngagementScopes(showMove ? destEngId : undefined)
  const destScopes = destScopesData?.scopes ?? []

  const handleAddScope = () => {
    if (!newScopeName.trim()) return
    addTargets.mutate({ eid: engagementId, scopeName: newScopeName.trim(), targets: [], source: 'manual' }, {
      onSuccess: () => { setNewScopeName(''); setSelectedScope(newScopeName.trim()); refetchScopes() },
    })
  }

  const handleAddTarget = () => {
    if (!newTarget.trim() || !activeScope) return
    addTargets.mutate(
      { eid: engagementId, scopeName: activeScope, targets: [newTarget.trim()] },
      { onSuccess: () => { setNewTarget(''); refetchTargets(); refetchScopes() } },
    )
  }

  const handleDeleteScope = () => {
    if (!activeScope || !confirm(`Delete scope "${activeScope}" and all its targets?`)) return
    deleteScope.mutate({ eid: engagementId, scopeName: activeScope }, {
      onSuccess: () => { setSelectedScope(null); refetchScopes() },
    })
  }

  const handleRename = () => {
    if (!renaming || !renameVal.trim()) return
    renameScope.mutate({ eid: engagementId, scopeName: renaming, newName: renameVal.trim() }, {
      onSuccess: () => { setSelectedScope(renameVal.trim()); setRenaming(null); refetchScopes() },
    })
  }

  const handleMove = () => {
    const finalScope = moveToScope === '__new__' ? moveNewScope.trim() : moveToScope
    if (!activeScope || !finalScope || selected.size === 0) return
    const targetList = targets.filter(t => selected.has(t.id)).map(t => t.target)
    moveTargets.mutate({
      eid: engagementId,
      scopeName: activeScope,
      targets: targetList,
      toEngagementId: moveToEng || engagementId,
      toScopeName: finalScope,
    }, {
      onSuccess: () => { setSelected(new Set()); setShowMove(false); setMoveToScope(''); setMoveNewScope(''); refetchTargets(); refetchScopes() },
    })
  }

  return (
    <div className="flex gap-4" style={{ minHeight: 400 }}>
      {/* Scope List */}
      <div className="w-56 shrink-0 space-y-2">
        <div className="flex gap-1">
          <input
            value={newScopeName} onChange={e => setNewScopeName(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAddScope()}
            placeholder="New scope name"
            className="flex-1 bg-muted rounded px-2 py-1 text-xs border border-border"
          />
          <button onClick={handleAddScope} className="px-2 py-1 text-xs rounded bg-primary text-primary-foreground">
            <Plus className="h-3 w-3" />
          </button>
        </div>
        {scopes.map(s => (
          <button
            key={s.name}
            onClick={() => { setSelectedScope(s.name); setSelected(new Set()) }}
            className={cn(
              'w-full text-left px-3 py-2 rounded text-xs border transition-colors',
              activeScope === s.name
                ? 'border-primary bg-primary/10 text-foreground'
                : 'border-border bg-card hover:bg-muted/50 text-muted-foreground'
            )}
          >
            <div className="font-medium">{s.name}</div>
            <div className="text-[10px] text-muted-foreground">{s.target_count} targets</div>
          </button>
        ))}
        {scopes.length === 0 && (
          <p className="text-xs text-muted-foreground px-2">No scopes yet. Create one above.</p>
        )}
      </div>

      {/* Scope Detail */}
      <div className="flex-1 space-y-3">
        {activeScope && (
          <>
            {/* Header */}
            <div className="flex items-center gap-2">
              {renaming === activeScope ? (
                <div className="flex items-center gap-1">
                  <input value={renameVal} onChange={e => setRenameVal(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleRename()}
                    className="bg-muted rounded px-2 py-1 text-xs border border-border w-40" autoFocus />
                  <button onClick={handleRename} className="text-xs text-green-500">Save</button>
                  <button onClick={() => setRenaming(null)} className="text-xs text-muted-foreground">Cancel</button>
                </div>
              ) : (
                <>
                  <h4 className="text-sm font-semibold">{activeScope}</h4>
                  <button onClick={() => { setRenaming(activeScope); setRenameVal(activeScope) }}
                    className="text-muted-foreground hover:text-foreground"><Pencil className="h-3 w-3" /></button>
                  <button onClick={() => { setShowMoveScope(true); setMoveScopeToEng('') }}
                    className="text-blue-400 hover:text-blue-300" title="Move entire scope to another engagement"><ArrowRight className="h-3 w-3" /></button>
                  <button onClick={handleDeleteScope}
                    className="text-red-400 hover:text-red-300"><Trash2 className="h-3 w-3" /></button>
                </>
              )}
              <div className="flex-1" />
              {selected.size > 0 && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">{selected.size} selected</span>
                  <button onClick={() => setShowMove(true)}
                    className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-blue-600 text-white hover:bg-blue-500">
                    <ArrowRight className="h-3 w-3" /> Move
                  </button>
                </div>
              )}
            </div>

            {/* Move entire scope dialog */}
            {showMoveScope && activeScope && (
              <div className="bg-blue-500/5 border border-blue-500/30 rounded p-3 space-y-2">
                <div className="text-xs font-medium">Move scope "{activeScope}" ({targets.length} targets) to:</div>
                <div className="flex items-center gap-2">
                  <select value={moveScopeToEng} onChange={e => setMoveScopeToEng(e.target.value)}
                    className="bg-muted rounded px-2 py-1 text-xs border border-border">
                    <option value="">Select engagement...</option>
                    {allEngagements.filter(e => e.id !== engagementId).map(e => (
                      <option key={e.id} value={e.id}>{e.name}</option>
                    ))}
                  </select>
                  <button
                    onClick={() => {
                      if (!moveScopeToEng) return
                      moveEntireScope.mutate({ eid: engagementId, scopeName: activeScope, toEngagementId: moveScopeToEng }, {
                        onSuccess: () => { setShowMoveScope(false); setSelectedScope(null); refetchScopes() },
                      })
                    }}
                    disabled={!moveScopeToEng || moveEntireScope.isPending}
                    className="px-3 py-1 text-xs rounded bg-blue-600 text-white disabled:opacity-50"
                  >
                    {moveEntireScope.isPending ? 'Moving...' : 'Move Scope'}
                  </button>
                  <button onClick={() => setShowMoveScope(false)} className="text-xs text-muted-foreground">Cancel</button>
                </div>
              </div>
            )}

            {/* Move targets dialog */}
            {showMove && (
              <div className="bg-muted/50 border border-border rounded p-3 space-y-2">
                <div className="text-xs font-medium">Move {selected.size} target(s) to:</div>
                <div className="flex items-center gap-2 flex-wrap">
                  <label className="text-[10px] text-muted-foreground">Engagement:</label>
                  <select value={moveToEng} onChange={e => { setMoveToEng(e.target.value); setMoveToScope('') }}
                    className="bg-muted rounded px-2 py-1 text-xs border border-border">
                    <option value="">Same engagement</option>
                    {allEngagements.filter(e => e.id !== engagementId).map(e => (
                      <option key={e.id} value={e.id}>{e.name}</option>
                    ))}
                  </select>

                  <label className="text-[10px] text-muted-foreground">Scope:</label>
                  <select value={moveToScope} onChange={e => setMoveToScope(e.target.value)}
                    className="bg-muted rounded px-2 py-1 text-xs border border-border">
                    <option value="">Select scope...</option>
                    {destScopes.filter(s => s.name !== activeScope || moveToEng).map(s => (
                      <option key={s.name} value={s.name}>{s.name} ({s.target_count})</option>
                    ))}
                    <option value="__new__">+ New scope...</option>
                  </select>

                  {moveToScope === '__new__' && (
                    <input value={moveNewScope} onChange={e => setMoveNewScope(e.target.value)}
                      placeholder="New scope name" autoFocus
                      className="bg-muted rounded px-2 py-1 text-xs border border-border w-36" />
                  )}

                  <button onClick={handleMove}
                    disabled={!moveToScope || (moveToScope === '__new__' && !moveNewScope.trim())}
                    className="px-3 py-1 text-xs rounded bg-blue-600 text-white disabled:opacity-50">Move</button>
                  <button onClick={() => { setShowMove(false); setMoveToScope(''); setMoveNewScope('') }}
                    className="text-xs text-muted-foreground">Cancel</button>
                </div>
              </div>
            )}

            {/* Targets table */}
            <div className="border border-border rounded overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-muted/30 border-b border-border">
                    <th className="w-8 px-2 py-1.5">
                      <input type="checkbox"
                        checked={selected.size === targets.length && targets.length > 0}
                        onChange={() => setSelected(selected.size === targets.length ? new Set() : new Set(targets.map(t => t.id)))}
                        className="rounded" />
                    </th>
                    <th className="text-left px-3 py-1.5 font-medium">Target</th>
                    <th className="text-left px-3 py-1.5 font-medium w-20">Type</th>
                    <th className="text-left px-3 py-1.5 font-medium w-20">Source</th>
                    <th className="text-left px-3 py-1.5 font-medium w-32">Added</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.map(t => (
                    <tr key={t.id} className={cn('border-b border-border/30 hover:bg-muted/10', selected.has(t.id) && 'bg-blue-500/5')}>
                      <td className="px-2 py-1 text-center">
                        <input type="checkbox" checked={selected.has(t.id)}
                          onChange={() => {
                            const next = new Set(selected)
                            next.has(t.id) ? next.delete(t.id) : next.add(t.id)
                            setSelected(next)
                          }} className="rounded" />
                      </td>
                      <td className="px-3 py-1 font-mono">{t.target}</td>
                      <td className="px-3 py-1 text-muted-foreground">{t.target_type}</td>
                      <td className="px-3 py-1 text-muted-foreground">{t.source}</td>
                      <td className="px-3 py-1 text-muted-foreground">{t.added_at ? new Date(t.added_at).toLocaleDateString() : '-'}</td>
                    </tr>
                  ))}
                  {targets.length === 0 && (
                    <tr><td colSpan={5} className="px-3 py-4 text-center text-muted-foreground">No targets in this scope</td></tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Add target */}
            <div className="flex gap-1">
              <input value={newTarget} onChange={e => setNewTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleAddTarget()}
                placeholder="Add target (IP, domain, CIDR, URL)"
                className="flex-1 bg-muted rounded px-2 py-1 text-xs border border-border font-mono" />
              <button onClick={handleAddTarget}
                className="px-3 py-1 text-xs rounded bg-primary text-primary-foreground">Add</button>
            </div>

            {/* Bulk import */}
            <BulkImportTargets engagementId={engagementId} scopeName={activeScope} onDone={() => { refetchTargets(); refetchScopes() }} />
          </>
        )}
        {!activeScope && (
          <p className="text-sm text-muted-foreground text-center py-12">Create a scope to manage targets</p>
        )}
      </div>
    </div>
  )
}

type DetailTab = 'overview' | 'scope' | 'notes' | 'campaign' | 'agents'

function EngagementDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const [detailTab, setDetailTab] = useState<DetailTab>('overview')
  const { data: eng } = useEngagement(id)
  const update = useUpdateEngagement()
  const [notesValue, setNotesValue] = useState<string | null>(null)
  const [notesSaved, setNotesSaved] = useState(false)

  if (!eng) return <div className="text-sm text-muted-foreground">Loading...</div>

  return (
    <div className="space-y-4">
      <button onClick={onBack} className="text-xs text-muted-foreground hover:text-foreground">
        &larr; Back to list
      </button>

      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold">{eng.name}</h3>
          {eng.client && <div className="text-xs text-muted-foreground">{eng.client}</div>}
        </div>
        <div className="flex items-center gap-2">
          <select
            value={eng.status}
            onChange={e => update.mutate({ id, status: e.target.value })}
            className={cn(
              'px-2 py-1 text-xs rounded-full capitalize border-0 cursor-pointer appearance-none pr-6 font-medium',
              STATUS_COLORS[eng.status],
            )}
            style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E")`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 6px center' }}
          >
            {STATUS_FLOW.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {(['overview', 'scope', 'notes', 'campaign', 'agents'] as DetailTab[]).map(t => (
          <button key={t} onClick={() => { setDetailTab(t); if (t === 'notes' && notesValue === null) setNotesValue(eng.notes || '') }}
            className={cn('px-3 py-1.5 text-sm border-b-2 capitalize transition-colors',
              detailTab === t ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'
            )}>{t}</button>
        ))}
      </div>

      {detailTab === 'overview' && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard label="Type" value={eng.engagement_type?.replace('_', ' ')} />
          <StatCard label="Methodology" value={eng.methodology} />
          <StatCard label="Start" value={eng.start_date || 'N/A'} />
          <StatCard label="End" value={eng.end_date || 'N/A'} />
          {eng.stats && Object.entries(eng.stats.findings_by_severity).map(([sev, cnt]) => (
            <StatCard key={sev} label={`${sev} findings`} value={String(cnt)} />
          ))}
          {eng.stats && <StatCard label="Assets" value={String(eng.stats.asset_count)} />}
          {eng.scope_name && <StatCard label="Scope" value={eng.scope_name} />}
          {eng.rules_of_engagement && (
            <div className="sm:col-span-2 lg:col-span-4 p-3 rounded border border-border bg-card">
              <div className="text-xs font-medium text-muted-foreground mb-1">Rules of Engagement</div>
              <div className="text-sm whitespace-pre-wrap">{eng.rules_of_engagement}</div>
            </div>
          )}
        </div>
      )}

      {detailTab === 'scope' && (
        <ScopeTab engagementId={id} />
      )}

      {detailTab === 'notes' && (
        <div className="space-y-3">
          <textarea
            value={notesValue ?? eng.notes ?? ''}
            onChange={e => { setNotesValue(e.target.value); setNotesSaved(false) }}
            placeholder="Add engagement notes, observations, TODO items..."
            rows={16}
            className="w-full bg-muted rounded-md px-4 py-3 text-sm border border-border outline-none focus:border-primary resize-y font-mono leading-relaxed"
          />
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                update.mutate({ id, notes: notesValue ?? '' }, {
                  onSuccess: () => { setNotesSaved(true); setTimeout(() => setNotesSaved(false), 2000) },
                })
              }}
              disabled={update.isPending}
              className="px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              {update.isPending ? 'Saving...' : 'Save Notes'}
            </button>
            {notesSaved && <span className="text-xs text-green-500">Saved!</span>}
          </div>
        </div>
      )}

      {detailTab === 'campaign' && <CampaignTab engagementId={id} />}
      {detailTab === 'agents' && (
        <div className="space-y-4">
          <ReconAgentPanel engagementId={id} />
          <GapAnalysisAgentPanel engagementId={id} />
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-3 rounded border border-border bg-card">
      <div className="text-xs text-muted-foreground capitalize">{label}</div>
      <div className="text-sm font-medium capitalize mt-0.5">{value}</div>
    </div>
  )
}

// ── Campaign Tab (H1) ──

function CampaignTab({ engagementId }: { engagementId: string }) {
  const { data: evtData } = useCampaignEvents(engagementId)
  const { data: summary } = useCampaignSummary(engagementId)
  const createEvent = useCreateCampaignEvent()
  const updateEvent = useUpdateCampaignEvent()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    kill_chain_phase: 'reconnaissance' as KillChainPhase,
    title: '', mitre_technique: '', mitre_tactic: '', description: '', operator: '',
  })

  const events = evtData?.events ?? []
  const phases = summary?.phases ?? {}

  const handleCreate = () => {
    if (!form.title) return
    createEvent.mutate({
      engagementId,
      ...form,
      mitre_technique: form.mitre_technique || undefined,
      mitre_tactic: form.mitre_tactic || undefined,
      description: form.description || undefined,
      operator: form.operator || undefined,
    }, {
      onSuccess: () => {
        setShowForm(false)
        setForm({ kill_chain_phase: 'reconnaissance', title: '', mitre_technique: '', mitre_tactic: '', description: '', operator: '' })
      },
    })
  }

  return (
    <div className="space-y-4">
      {/* Kill chain phase summary */}
      <div className="flex gap-1 flex-wrap">
        {KILL_CHAIN_PHASES.map(phase => {
          const info = phases[phase]
          return (
            <div key={phase} className="flex flex-col items-center p-2 rounded border border-border min-w-[100px]">
              <div className={cn('h-2 w-full rounded mb-1', KC_COLORS[phase])} />
              <div className="text-[10px] text-muted-foreground capitalize">{phase.replace('_', ' ')}</div>
              <div className="text-sm font-medium">{info?.count ?? 0}</div>
              {info && info.detected > 0 && (
                <div className="text-[10px] text-red-400">{info.detected} detected</div>
              )}
            </div>
          )
        })}
      </div>

      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium">Timeline</h4>
        <button onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-primary text-primary-foreground">
          <Plus className="h-3 w-3" /> Add Event
        </button>
      </div>

      {showForm && (
        <div className="p-3 border border-border rounded-lg bg-card space-y-2">
          <div className="grid gap-2 sm:grid-cols-2">
            <select value={form.kill_chain_phase}
              onChange={e => setForm({ ...form, kill_chain_phase: e.target.value as KillChainPhase })}
              className="px-2 py-1 text-sm rounded border border-border bg-background capitalize">
              {KILL_CHAIN_PHASES.map(p => <option key={p} value={p}>{p.replace('_', ' ')}</option>)}
            </select>
            <input placeholder="Title *" value={form.title}
              onChange={e => setForm({ ...form, title: e.target.value })}
              className="px-2 py-1 text-sm rounded border border-border bg-background" />
            <input placeholder="MITRE Technique (e.g. T1059.001)" value={form.mitre_technique}
              onChange={e => setForm({ ...form, mitre_technique: e.target.value })}
              className="px-2 py-1 text-sm rounded border border-border bg-background" />
            <input placeholder="Operator" value={form.operator}
              onChange={e => setForm({ ...form, operator: e.target.value })}
              className="px-2 py-1 text-sm rounded border border-border bg-background" />
          </div>
          <textarea placeholder="Description" value={form.description}
            onChange={e => setForm({ ...form, description: e.target.value })}
            className="w-full px-2 py-1 text-sm rounded border border-border bg-background h-16" />
          <button onClick={handleCreate} disabled={!form.title || createEvent.isPending}
            className="px-3 py-1 text-xs rounded bg-primary text-primary-foreground disabled:opacity-50">
            {createEvent.isPending ? 'Adding...' : 'Add Event'}
          </button>
        </div>
      )}

      {/* Timeline */}
      <div className="space-y-2">
        {events.length === 0 ? (
          <div className="text-xs text-muted-foreground">No campaign events yet.</div>
        ) : events.map(evt => (
          <div key={evt.id} className={cn(
            'flex items-start gap-3 p-3 rounded border bg-card',
            evt.operator === 'system' ? 'border-blue-500/30 bg-blue-500/5' : 'border-border'
          )}>
            <div className={cn('h-3 w-3 rounded-full mt-1 shrink-0', KC_COLORS[evt.kill_chain_phase])} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{evt.title}</span>
                {evt.operator === 'system' && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400">SCAN</span>
                )}
                {evt.mitre_technique && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{evt.mitre_technique}</span>
                )}
                {evt.detected && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">DETECTED</span>
                )}
              </div>
              <div className="text-xs text-muted-foreground capitalize">{evt.kill_chain_phase.replace('_', ' ')}</div>
              {evt.description && <div className="text-xs mt-1">{evt.description}</div>}
              <div className="text-[10px] text-muted-foreground mt-1">
                {new Date(evt.timestamp).toLocaleString()} {evt.operator && evt.operator !== 'system' && `| ${evt.operator}`}
              </div>
            </div>
            {!evt.detected && evt.operator !== 'system' && (
              <button
                onClick={() => updateEvent.mutate({ id: evt.id, detected: true, detection_time: new Date().toISOString() })}
                className="text-[10px] px-2 py-0.5 rounded border border-border text-muted-foreground hover:text-red-400"
              >Mark Detected</button>
            )}
          </div>
        ))}
      </div>

      {/* MITRE technique summary */}
      {summary?.techniques && summary.techniques.length > 0 && (
        <div>
          <h4 className="text-sm font-medium mb-2">MITRE Techniques Used</h4>
          <div className="flex gap-1 flex-wrap">
            {summary.techniques.map((t, i) => (
              <span key={i} className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground">
                {t.mitre_technique} ({t.cnt})
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
