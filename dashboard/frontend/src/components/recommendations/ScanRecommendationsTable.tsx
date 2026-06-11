/**
 * Shared scan-recommendations panel.
 *
 * Originally lived inline in pages/FollowUps.tsx as `ScanRecommendationsPanel`.
 * Extracted so the top-level Recommendations page can render it in
 * always-expanded mode while FollowUps keeps the collapsible-embed UX.
 *
 * Filtering is intentionally client-side -- the data volume is small
 * (hundreds of recs max per engagement) and `useScanRecommendations('all')`
 * is already polled via React Query.  If volume grows we can push filters
 * to the BFF query string in a later iteration without changing this
 * component's surface.
 */

import { useState } from 'react'
import { useScanRecommendations, useGenerateRecommendations, type StoredRecommendation } from '@/api/assets'
import {
  Wand2, ChevronDown, ChevronRight, Eye, Play, Loader2,
} from 'lucide-react'

// ---- grouping helpers ----

const TOOL_GROUPS: Record<string, { label: string; tools: string[] }> = {
  content_discovery: { label: 'Directory & File Discovery', tools: ['gobuster', 'feroxbuster', 'dirsearch', 'wfuzz', 'ffuf'] },
  web_vuln_scan:     { label: 'Web Vulnerability Scanning', tools: ['nikto', 'nuclei'] },
  tech_fingerprint:  { label: 'Technology Fingerprinting',  tools: ['whatweb', 'wappalyzer'] },
  sql_injection:     { label: 'SQL Injection Testing',      tools: ['sqlmap'] },
}
const TOOL_TO_GROUP: Record<string, string> = {}
for (const [g, { tools }] of Object.entries(TOOL_GROUPS)) {
  for (const t of tools) TOOL_TO_GROUP[t] = g
}

interface GroupedRec {
  group: string | null
  groupLabel: string | null
  items: StoredRecommendation[]
}

function deduplicateByScanner(items: StoredRecommendation[]): StoredRecommendation[] {
  // Merge entries with same scanner+action into one, combining templates.
  const byKey: Record<string, StoredRecommendation & { _templates: string[] }> = {}
  for (const r of items) {
    const key = `${r.scanner}|${r.action || ''}`
    if (byKey[key]) {
      if (r.template) byKey[key]._templates.push(r.template)
    } else {
      byKey[key] = { ...r, _templates: r.template ? [r.template] : [] }
    }
  }
  return Object.values(byKey).map(r => {
    if (r._templates.length > 1) {
      return { ...r, template: r._templates.join(', '), action: `${r.action || 'scan'} (${r._templates.length} template sets)` }
    }
    if (r._templates.length === 1) {
      return { ...r, template: r._templates[0] }
    }
    return r
  })
}

function groupByPurpose(items: StoredRecommendation[]): GroupedRec[] {
  const groups: Record<string, StoredRecommendation[]> = {}
  const ungrouped: StoredRecommendation[] = []
  for (const r of items) {
    const g = r.purpose_group || TOOL_TO_GROUP[r.scanner.toLowerCase()]
    if (g) {
      (groups[g] ??= []).push(r)
    } else {
      ungrouped.push(r)
    }
  }
  const result: GroupedRec[] = []
  for (const [g, gItems] of Object.entries(groups)) {
    result.push({ group: g, groupLabel: TOOL_GROUPS[g]?.label || g, items: deduplicateByScanner(gItems) })
  }
  for (const r of deduplicateByScanner(ungrouped)) {
    result.push({ group: null, groupLabel: null, items: [r] })
  }
  return result
}

// ---- Props ----

export interface ScanRecommendationsPanelProps {
  /**
   * When true (default) the panel renders inside a collapsible card with a
   * summary header -- suitable for embedding next to other panels (e.g.
   * FollowUps).  When false the panel is always-expanded and the header
   * chrome is omitted -- suitable for a standalone page where the page
   * title already names the surface.
   */
  embedded?: boolean
  /**
   * Optional client-side filters.  Each is applied independently with AND
   * semantics.  Empty / undefined fields mean "no filter for this column".
   *
   * `status`: exact match (e.g. 'pending', 'queued', 'completed').
   * `service`: case-insensitive substring match against rec.service.
   * `ip`: substring match against rec.ip.
   * `source`: exact match (e.g. 'rules', 'kb_manual', 'model').
   */
  filters?: {
    status?: string
    service?: string
    ip?: string
    source?: string
  }
}

// ---- Component ----

export function ScanRecommendationsPanel({
  embedded = true,
  filters,
}: ScanRecommendationsPanelProps = {}) {
  const [expanded, setExpanded] = useState(!embedded)  // standalone page: start expanded
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [runResult, setRunResult] = useState<any>(null)
  const [running, setRunning] = useState(false)
  const [useKali, setUseKali] = useState(true)
  const [toolCheck, setToolCheck] = useState<any>(null)
  const [checking, setChecking] = useState(false)
  const [installing, setInstalling] = useState(false)
  const { data, isLoading, refetch } = useScanRecommendations('all')
  const generateRecs = useGenerateRecommendations()
  const allRecs = data?.recommendations ?? []

  // Apply optional client-side filters.
  const recs = allRecs.filter(r => {
    if (filters?.status && r.status !== filters.status) return false
    if (filters?.service && !(r.service || '').toLowerCase().includes(filters.service.toLowerCase())) return false
    if (filters?.ip && !(r.ip || '').includes(filters.ip)) return false
    if (filters?.source && r.source !== filters.source) return false
    return true
  })
  const pending = recs.filter(r => r.status === 'pending').length

  const runSelected = async () => {
    if (!selected.size) return
    setRunning(true)
    setRunResult(null)
    try {
      const res = await fetch('/api/scan-recommendations/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: Array.from(selected), use_kali: useKali }),
      })
      const data = await res.json()
      setRunResult(data)
      setSelected(new Set())
      refetch()
    } catch (e) {
      setRunResult({ ok: false, error: String(e) })
    }
    setRunning(false)
  }

  // Get unique tool names from selected recommendations
  const selectedTools = [...new Set(
    recs.filter(r => selected.has(r.id)).map(r => r.scanner.toLowerCase())
  )]

  const checkTools = async () => {
    if (!selectedTools.length) return
    setChecking(true)
    setToolCheck(null)
    try {
      const res = await fetch('/api/tools/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_id: 'kali-local', tools: selectedTools }),
      })
      setToolCheck(await res.json())
    } catch (e) {
      setToolCheck({ ok: false, error: String(e) })
    }
    setChecking(false)
  }

  const installMissing = async () => {
    if (!toolCheck?.missing?.length) return
    setInstalling(true)
    try {
      const res = await fetch('/api/tools/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_id: 'kali-local', tools: toolCheck.missing.map((t: any) => t.tool) }),
      })
      const data = await res.json()
      setToolCheck((prev: any) => ({ ...prev, install_result: data }))
    } catch (e) {
      setToolCheck((prev: any) => ({ ...prev, install_result: { error: String(e) } }))
    }
    setInstalling(false)
  }

  // When embedded and there's nothing to show, render nothing (the parent
  // page is probably showing other content -- don't take up vertical space).
  // When standalone, show an empty state so the user knows the page loaded.
  if (!recs.length && !isLoading) {
    if (embedded) return null
    const filtersActive = !!(filters && (filters.status || filters.service || filters.ip || filters.source))
    return (
      <div className="border border-border rounded-lg p-6 text-center text-sm text-muted-foreground space-y-3">
        <div>
          No scan recommendations
          {filtersActive
            ? ' match the current filters.'
            : ' yet. If a port scan has already run, generate recommendations for the detected ports.'}
        </div>
        {!filtersActive && (
          <div>
            <button
              onClick={() => generateRecs.mutate(undefined, { onSuccess: () => refetch() })}
              disabled={generateRecs.isPending}
              className="px-3 py-1.5 rounded-md text-sm font-medium border border-primary/50 bg-primary/10 text-primary hover:bg-primary/20 disabled:opacity-50"
            >
              {generateRecs.isPending ? 'Generating…' : 'Generate from detected ports'}
            </button>
            {generateRecs.isError && (
              <div className="mt-2 text-xs text-red-400">Generation failed — see logs.</div>
            )}
            {generateRecs.isSuccess && (
              <div className="mt-2 text-xs text-muted-foreground">
                Considered {generateRecs.data?.ports_considered ?? 0} port(s), generated{' '}
                {generateRecs.data?.generated ?? 0}. {generateRecs.data?.generated ? 'Refreshing…' : 'No new ports needed recommendations.'}
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  const toggleSelect = (id: string) => {
    const next = new Set(selected)
    next.has(id) ? next.delete(id) : next.add(id)
    setSelected(next)
  }
  const toggleAll = () => {
    const pendingIds = recs.filter(r => r.status === 'pending').map(r => r.id)
    setSelected(selected.size === pendingIds.length ? new Set() : new Set(pendingIds))
  }
  const toggleGroup = (key: string) => {
    const next = new Set(expandedGroups)
    next.has(key) ? next.delete(key) : next.add(key)
    setExpandedGroups(next)
  }

  // Group by IP → then by purpose
  const byIp: Record<string, StoredRecommendation[]> = {}
  for (const r of recs) {
    const key = r.ip || 'unknown'
    ;(byIp[key] ??= []).push(r)
  }

  const body = (
    <>
      {/* Action bar */}
      <div className="px-3 py-1.5 bg-muted/20 flex items-center gap-2 border-b border-border">
        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
          <input type="checkbox" checked={selected.size > 0 && selected.size === pending}
            onChange={toggleAll} className="rounded" />
          Select all pending
        </label>
        <label className="flex items-center gap-1 text-[10px] cursor-pointer" title="Route manual tools (hydra, ssh-audit, etc.) to internal Kali container">
          <input type="checkbox" checked={useKali} onChange={() => setUseKali(!useKali)} className="rounded" />
          Use Kali
        </label>
        {selected.size > 0 && (
          <>
            <button
              onClick={checkTools}
              disabled={checking}
              className="h-6 px-2 text-[10px] rounded bg-amber-600 hover:bg-amber-500 text-white flex items-center gap-1 disabled:opacity-50"
              title="Check if selected tools are installed on Kali"
            >
              {checking ? <Loader2 className="h-3 w-3 animate-spin" /> : <Eye className="h-3 w-3" />}
              Check Tools
            </button>
            <button
              onClick={runSelected}
              disabled={running}
              className="h-6 px-2 text-[10px] rounded bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1 disabled:opacity-50"
            >
              {running ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
              {running ? 'Dispatching...' : `Run ${selected.size} Selected`}
            </button>
          </>
        )}
        {runResult && (
          <span className={`text-[10px] ${runResult.ok ? 'text-green-400' : 'text-red-400'}`}>
            {runResult.dispatched > 0 && `${runResult.dispatched} dispatched`}
            {runResult.queued > 0 && ` ${runResult.queued} queued for approval`}
            {runResult.failed > 0 && ` ${runResult.failed} failed`}
            {runResult.skipped > 0 && ` ${runResult.skipped} skipped`}
            {runResult.error && runResult.error}
          </span>
        )}
      </div>
      {/* Tool check results */}
      {toolCheck && (
        <div className="px-3 py-1.5 bg-muted/10 border-b border-border text-[10px]">
          {toolCheck.error ? (
            <span className="text-red-400">{String(toolCheck.error)}</span>
          ) : (
            <div className="flex items-center gap-3 flex-wrap">
              {toolCheck.found?.length > 0 && (
                <span className="text-green-400">Installed: {toolCheck.found.join(', ')}</span>
              )}
              {toolCheck.missing?.length > 0 && (
                <>
                  <span className="text-red-400">Missing: {toolCheck.missing.map((m: any) => m.tool).join(', ')}</span>
                  <button
                    onClick={installMissing}
                    disabled={installing}
                    className="h-5 px-2 text-[9px] rounded bg-green-600 hover:bg-green-500 text-white flex items-center gap-1 disabled:opacity-50"
                  >
                    {installing ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Play className="h-2.5 w-2.5" />}
                    Install {toolCheck.missing.length} Missing
                  </button>
                </>
              )}
              {toolCheck.missing?.length === 0 && toolCheck.found?.length > 0 && (
                <span className="text-green-400">All tools ready</span>
              )}
              {toolCheck.install_result && (
                <span className={`${toolCheck.install_result.installed > 0 ? 'text-green-400' : 'text-red-400'}`}>
                  Installed: {toolCheck.install_result.installed || 0}, Failed: {toolCheck.install_result.failed || 0}
                </span>
              )}
            </div>
          )}
        </div>
      )}

      {/* Per-IP sections */}
      {Object.entries(byIp).map(([ip, items]) => {
        const grouped = groupByPurpose(items)
        return (
          <div key={ip} className="border-b border-border/30 last:border-b-0">
            <div className="px-3 py-1.5 bg-muted/10 text-xs font-mono font-medium text-muted-foreground flex items-center justify-between">
              <span>{ip} ({items.length} recommendations)</span>
            </div>

            {grouped.map((grp, gi) => {
              const groupKey = `${ip}:${grp.group || gi}`
              const isMultiTool = grp.group && grp.items.length > 1
              const isGroupExpanded = expandedGroups.has(groupKey)

              if (isMultiTool) {
                return (
                  <div key={groupKey} className="border-t border-border/10">
                    <button
                      className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-muted/10 text-left text-xs"
                      onClick={() => toggleGroup(groupKey)}
                    >
                      {isGroupExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                      <span className="font-medium text-blue-400">{grp.groupLabel}</span>
                      <span className="text-muted-foreground">
                        ({grp.items.length} tools: {grp.items.map(r => r.scanner).join(', ')})
                      </span>
                      <span className="text-[10px] text-muted-foreground/60 ml-1">— select one to run</span>
                    </button>
                    {isGroupExpanded && (
                      <div className="pl-6 pb-1">
                        {grp.items.map(r => (
                          <div key={r.id} className={`flex items-center gap-2 px-2 py-1 rounded text-xs hover:bg-muted/10 ${selected.has(r.id) ? 'bg-blue-500/5' : ''}`}>
                            {r.status === 'pending' && (
                              <input type="checkbox" checked={selected.has(r.id)}
                                onChange={() => toggleSelect(r.id)} className="rounded" />
                            )}
                            <span className="font-mono w-24">{r.scanner}</span>
                            <span className="text-muted-foreground flex-1">{r.action || '—'}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${statusBadgeClass(r.status)}`}>{r.status}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              }

              // Single tool (no group or single-member group)
              const r = grp.items[0]
              return (
                <div key={r.id} className={`flex items-center gap-2 px-3 py-1.5 text-xs border-t border-border/10 hover:bg-muted/10 ${selected.has(r.id) ? 'bg-blue-500/5' : ''}`}>
                  {r.status === 'pending' && (
                    <input type="checkbox" checked={selected.has(r.id)}
                      onChange={() => toggleSelect(r.id)} className="rounded" />
                  )}
                  {r.status !== 'pending' && <div className="w-4" />}
                  <span className="font-mono w-24">{r.scanner}</span>
                  <span className="flex-1">
                    {r.action || '—'}
                    {r.template && <span className="ml-1 text-muted-foreground text-[10px]">(template: {r.template})</span>}
                  </span>
                  <span className="text-muted-foreground w-20">{r.service || '—'}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${statusBadgeClass(r.status)}`}>{r.status}</span>
                </div>
              )
            })}
          </div>
        )
      })}
    </>
  )

  // Embedded mode: wrap in collapsible card with summary header.  Always-
  // expanded standalone mode: skip the chrome and just return the table.
  if (!embedded) {
    return (
      <div className="border border-border rounded-lg overflow-hidden">
        {body}
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <div className="border border-border rounded-lg overflow-hidden">
        <button
          className="w-full flex items-center justify-between px-3 py-2 bg-muted/30 hover:bg-muted/50 text-left"
          onClick={() => setExpanded(!expanded)}
        >
          <div className="flex items-center gap-2">
            <Wand2 className="h-3.5 w-3.5 text-blue-400" />
            <span className="text-sm font-medium">Scan & Exploit Recommendations</span>
            <span className="text-xs text-muted-foreground">({recs.length} scans, {pending} pending)</span>
          </div>
          <div className="flex items-center gap-2">
            {selected.size > 0 && <span className="text-xs text-blue-400">{selected.size} selected</span>}
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </div>
        </button>
        {expanded && (
          <div className="border-t border-border">
            {body}
          </div>
        )}
      </div>
    </div>
  )
}

// Status pill colors -- separated so they're easy to keep in sync with the
// updated lifecycle enum (queued / running / failed in addition to the
// pre-existing pending / completed / skipped).
function statusBadgeClass(status: string): string {
  switch (status) {
    case 'completed': return 'bg-green-500/15 text-green-400 border-green-500/30'
    case 'pending':   return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
    case 'queued':    return 'bg-blue-500/15 text-blue-400 border-blue-500/30'
    case 'running':   return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30'
    case 'failed':    return 'bg-red-500/15 text-red-400 border-red-500/30'
    case 'skipped':   return 'bg-gray-500/15 text-gray-400 border-gray-500/30'
    default:          return 'bg-gray-500/15 text-gray-400 border-gray-500/30'
  }
}
