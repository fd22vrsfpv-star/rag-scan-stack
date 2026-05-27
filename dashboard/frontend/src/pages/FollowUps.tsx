import { useState, useMemo, useEffect, Fragment } from 'react'
import {
  useFollowUps, useFollowUpStats, useFollowUpGrouped, useCreateFollowUp,
  useUpdateFollowUp, useDeleteFollowUp, useSubmitFeedback,
  useBulkUpdateFollowUps, useSendToBurpQueue, useBurpQueueStats,
  useAgentRules, useAgentStats, useTriggerAgentScan, useToggleAgentRule,
  useReloadRules, useTestRule, useCreateAdhocRule, useDeleteRule, useAgentRule,
  type FollowUpItem, type FollowUpGroup, type RuleTestResult,
} from '@/api/followups'
import { useScanRecommendations, type StoredRecommendation } from '@/api/assets'
import { useExcludeFromScope } from '@/api/findings'
import { useScopeNames, useAddToScope } from '@/api/scope'
import { useUIStore } from '@/stores/ui'
import {
  Flag, Plus, X, CheckCircle, XCircle, Clock, AlertTriangle, Loader2,
  ChevronRight, ChevronDown, Bot, RefreshCw, Eye, Trash2, Play, Wand2, RotateCcw, Pencil, ExternalLink, Send,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { SEVERITY_BG } from '@/lib/constants'

const PRIORITY_ICON: Record<string, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-blue-400',
}

const STATUS_BADGE: Record<string, string> = {
  open: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  in_progress: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  resolved: 'bg-green-500/15 text-green-400 border-green-500/30',
  dismissed: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

// Group labels for overlapping tools
const TOOL_GROUPS: Record<string, { label: string; tools: string[] }> = {
  content_discovery: { label: 'Directory & File Discovery', tools: ['gobuster', 'feroxbuster', 'dirsearch', 'wfuzz', 'ffuf'] },
  web_vuln_scan: { label: 'Web Vulnerability Scanning', tools: ['nikto', 'nuclei'] },
  tech_fingerprint: { label: 'Technology Fingerprinting', tools: ['whatweb', 'wappalyzer'] },
  sql_injection: { label: 'SQL Injection Testing', tools: ['sqlmap'] },
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
  // Merge entries with same scanner+action into one, combining templates
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
  // Deduplicate ungrouped too, then each is its own "group"
  for (const r of deduplicateByScanner(ungrouped)) {
    result.push({ group: null, groupLabel: null, items: [r] })
  }
  return result
}

function ScanRecommendationsPanel() {
  const [expanded, setExpanded] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [runResult, setRunResult] = useState<any>(null)
  const [running, setRunning] = useState(false)
  const [useKali, setUseKali] = useState(true)
  const [toolCheck, setToolCheck] = useState<any>(null)
  const [checking, setChecking] = useState(false)
  const [installing, setInstalling] = useState(false)
  const { data, isLoading, refetch } = useScanRecommendations('all')
  const recs = data?.recommendations ?? []
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

  if (!recs.length && !isLoading) return null

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

  return (
    <div className="space-y-2">
      {/* Scan Recommendations */}
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
                      // Collapsible group for overlapping tools
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
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                                    r.status === 'completed' ? 'bg-green-500/15 text-green-400 border-green-500/30'
                                    : r.status === 'pending' ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
                                    : 'bg-gray-500/15 text-gray-400 border-gray-500/30'
                                  }`}>{r.status}</span>
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
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                          r.status === 'completed' ? 'bg-green-500/15 text-green-400 border-green-500/30'
                          : r.status === 'pending' ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
                          : 'bg-gray-500/15 text-gray-400 border-gray-500/30'
                        }`}>{r.status}</span>
                      </div>
                    )
                  })}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

export default function FollowUps() {
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const [filters, setFilters] = useState<{
    status?: string; severity?: string; priority?: string; flagged_by?: string; search?: string
  }>({})
  const [hideDismissed, setHideDismissed] = useState(true)
  const [selected, setSelected] = useState<FollowUpItem | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [showRules, setShowRules] = useState(false)
  const [showAdhoc, setShowAdhoc] = useState(false)
  const [editRuleId, setEditRuleId] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<RuleTestResult | null>(null)
  const [ruleSinceMinutes, setRuleSinceMinutes] = useState(1440) // default 24h

  const [searchFilter, setSearchFilter] = useState('')
  const [groupBy, setGroupBy] = useState<'none' | 'title' | 'target'>('title')
  const [filterByEngagement, setFilterByEngagement] = useState(false)
  const activeEngagementId = filterByEngagement && engagementId ? engagementId : undefined
  const { data: statsData } = useFollowUpStats(activeEngagementId)
  const excludeStatus = hideDismissed && filters.status !== 'dismissed' ? 'dismissed' : undefined
  const { data: groupedData } = useFollowUpGrouped(groupBy, filters.status, activeEngagementId, excludeStatus)
  const { data, isLoading } = useFollowUps({
    ...filters,
    exclude_status: excludeStatus,
    search: searchFilter.trim() || undefined,
    engagement_id: filterByEngagement && engagementId ? engagementId : undefined,
  })
  const { data: agentStatsData } = useAgentStats()
  const { data: rulesData } = useAgentRules()
  const triggerScan = useTriggerAgentScan()
  const toggleRule = useToggleAgentRule()
  const reloadRules = useReloadRules()
  const testRule = useTestRule()
  const deleteRule = useDeleteRule()
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkAction, setBulkAction] = useState<string>('')
  const [bulkNotes, setBulkNotes] = useState('')
  const bulkUpdate = useBulkUpdateFollowUps()
  const sendToBurp = useSendToBurpQueue()
  const { data: burpQueueStats } = useBurpQueueStats()
  const excludeFromScope = useExcludeFromScope()
  const addToScope = useAddToScope()
  const { data: scopeData } = useScopeNames()
  const scopeNames = (scopeData?.names ?? []).map((n: any) => typeof n === 'string' ? n : n.name) as string[]
  const allItems = data?.follow_ups ?? []
  const stats = statsData?.stats
  const agentStats = agentStatsData?.stats
  const rules = rulesData?.rules ?? []

  // Parse search: "+term" include, "-term" exclude, plain = include
  const items = useMemo(() => {
    const q = searchFilter.trim()
    if (!q) return allItems
    const tokens = q.split(/\s+/)
    const include: string[] = []
    const exclude: string[] = []
    for (const tok of tokens) {
      if (tok.startsWith('-') && tok.length > 1) exclude.push(tok.slice(1).toLowerCase())
      else if (tok.startsWith('+') && tok.length > 1) include.push(tok.slice(1).toLowerCase())
      else include.push(tok.toLowerCase())
    }
    return allItems.filter(item => {
      const text = `${item.title} ${item.target} ${item.reason || ''} ${item.rule_id || ''} ${(item.tags || []).join(' ')}`.toLowerCase()
      if (exclude.some(ex => text.includes(ex))) return false
      if (include.length > 0 && !include.some(inc => text.includes(inc))) return false
      return true
    })
  }, [allItems, searchFilter])

  // Extract host from target URL
  const extractHost = (target: string | null) => {
    if (!target) return 'No target'
    try {
      const u = new URL(target.startsWith('http') ? target : `https://${target}`)
      return u.hostname
    } catch {
      return target.split('/')[0].split(':')[0] || target
    }
  }

  // Extract finding name (prefix before separator: " -- " or " — " or " - ")
  // For software CVE titles: "Vulnerable: IIS 10.0 on 1.2.3.4 — CVE-..." → "Vulnerable: IIS 10.0"
  const extractFindingName = (title: string) => {
    const t = title || 'Untitled'
    // Software CVE titles: group by product+version (before " on ")
    if (t.startsWith('Vulnerable: ') && t.includes(' on ')) {
      return t.slice(0, t.indexOf(' on ')).trim()
    }
    // Try em dash first (most common in agent-generated titles)
    const emIdx = t.indexOf(' \u2014 ')
    if (emIdx >= 0) return t.slice(0, emIdx).trim()
    // Try double dash
    const dashIdx = t.indexOf(' -- ')
    if (dashIdx >= 0) return t.slice(0, dashIdx).trim()
    // Try en dash
    const enIdx = t.indexOf(' \u2013 ')
    if (enIdx >= 0) return t.slice(0, enIdx).trim()
    // Rule Match prefix
    const ruleIdx = t.indexOf('Rule Match:')
    if (ruleIdx >= 0) return 'Rule Match'
    return t
  }

  // Simple grouping: one level only
  const grouped = useMemo(() => {
    if (groupBy === 'none') return null
    const groups: Record<string, FollowUpItem[]> = {}
    for (const item of items) {
      const key = groupBy === 'title'
        ? extractFindingName(item.title)   // "Login Page" (everything before " -- ")
        : extractHost(item.target)          // "app.example.com"
      if (!groups[key]) groups[key] = []
      groups[key].push(item)
    }
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length)
  }, [items, groupBy])

  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const toggleGroup = (key: string) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  // Group-level helpers
  // Cache of server-fetched group IDs so checkbox state works without re-fetching
  const [groupIdCache, setGroupIdCache] = useState<Record<string, string[]>>({})
  const [loadingGroup, setLoadingGroup] = useState<string | null>(null)

  // Fetch all IDs for a group from the server (not limited by local page size)
  const fetchGroupIds = async (groupKey: string): Promise<string[]> => {
    // Return cached if available
    if (groupIdCache[groupKey]?.length) return groupIdCache[groupKey]
    try {
      const params = new URLSearchParams({ group_key: groupKey, group_by: groupBy })
      if (filters.status) params.set('status', filters.status)
      if (excludeStatus) params.set('exclude_status', excludeStatus)
      if (activeEngagementId) params.set('engagement_id', activeEngagementId)
      const resp = await fetch(`/api/follow-ups/group-ids?${params}`)
      const data = await resp.json()
      const ids = data.ids || []
      setGroupIdCache(prev => ({ ...prev, [groupKey]: ids }))
      return ids
    } catch { return [] }
  }

  const isGroupAllSelected = (groupKey: string): boolean => {
    const ids = groupIdCache[groupKey]
    if (!ids?.length) return false
    return ids.every(id => selectedIds.has(id))
  }
  const isGroupPartiallySelected = (groupKey: string): boolean => {
    const ids = groupIdCache[groupKey]
    if (!ids?.length) return selectedIds.size > 0 // can't know for sure without IDs
    return ids.some(id => selectedIds.has(id)) && !ids.every(id => selectedIds.has(id))
  }
  const toggleGroupSelect = async (groupKey: string) => {
    setLoadingGroup(groupKey)
    const ids = await fetchGroupIds(groupKey)
    setLoadingGroup(null)
    if (!ids.length) return
    setSelectedIds(prev => {
      const next = new Set(prev)
      const allSelected = ids.every(id => next.has(id))
      if (allSelected) {
        ids.forEach(id => next.delete(id))
      } else {
        ids.forEach(id => next.add(id))
      }
      return next
    })
  }
  const sendGroupToBurp = async (groupKey: string) => {
    const ids = await fetchGroupIds(groupKey)
    if (ids.length) handleSendToBurp(ids)
  }

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }
  const toggleSelectAll = () => {
    if (selectedIds.size === items.length) setSelectedIds(new Set())
    else setSelectedIds(new Set(items.map(i => i.id)))
  }
  const handleBulkAction = (action: string) => {
    const ids = Array.from(selectedIds)
    if (!ids.length) return
    if (action === 'delete' && !confirm(`Delete ${ids.length} follow-up(s)?`)) return
    if (action === 'dismiss' || action === 'accept' || action === 'delete') {
      bulkUpdate.mutate({ ids, action: action as 'dismiss' | 'accept' | 'delete' }, {
        onSuccess: () => setSelectedIds(new Set()),
      })
    }
  }
  const handleBulkUpdate = (fields: { status?: string; priority?: string; notes?: string }) => {
    const ids = Array.from(selectedIds)
    if (!ids.length) return
    bulkUpdate.mutate({ ids, action: 'update', ...fields }, {
      onSuccess: () => { setSelectedIds(new Set()); setBulkAction(''); setBulkNotes('') },
    })
  }
  const handleBulkExclude = () => {
    const targets = items
      .filter(i => selectedIds.has(i.id) && i.target)
      .map(i => i.target!)
    const unique = [...new Set(targets)]
    if (!unique.length) return
    excludeFromScope.mutate({ targets: unique, source: 'follow-up-bulk' })
    handleBulkAction('dismiss')
  }
  const handleAddToScope = (scopeName: string) => {
    const targets = items
      .filter(i => selectedIds.has(i.id) && i.target)
      .map(i => i.target!)
    const unique = [...new Set(targets)]
    if (!unique.length) return
    addToScope.mutate({
      name: scopeName,
      targets: unique.map(t => ({ target: t, target_type: 'domain', source: 'follow-up-bulk' })),
    })
  }
  const handleSendToBurp = (ids?: string[]) => {
    // Send follow-up items to Burp queue. Any item with a target (URL, domain,
    // or IP) is valid — the backend enriches with request/response data.
    const idsToSend = ids || Array.from(selectedIds)
    const validIds = items
      .filter(i => idsToSend.includes(i.id))
      .filter(i => !!(i.target))
      .map(i => i.id)
    if (!validIds.length) {
      alert('No items with a target selected')
      return
    }
    sendToBurp.mutate(validIds)
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Flag className="h-5 w-5" /> Follow-Up Panel
        </h2>
        <div className="flex items-center gap-2">
          <a
            href="/exploits"
            className="h-7 px-3 text-xs rounded border border-orange-500/50 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 flex items-center gap-1.5 font-medium"
          >
            <AlertTriangle className="h-3 w-3" />
            Exploit Manager
          </a>
          <button
            onClick={() => triggerScan.mutate(0)}
            disabled={triggerScan.isPending}
            title="Scan all findings against enabled rules"
            className="h-7 px-3 text-xs rounded border border-border bg-background hover:bg-accent flex items-center gap-1"
          >
            <Bot className="h-3 w-3" />
            {triggerScan.isPending ? 'Scanning...' : 'Run Agent'}
          </button>
          <button
            onClick={() => setShowRules(!showRules)}
            className={cn(
              "h-7 px-3 text-xs rounded border border-border bg-background hover:bg-accent",
              showRules && "bg-accent"
            )}
          >
            Rules ({rules.length})
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="h-7 px-3 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90 flex items-center gap-1"
          >
            <Plus className="h-3 w-3" /> Add Manual
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-4 gap-2">
          <StatCard
            label="Open" count={stats.open}
            color="text-yellow-400" active={filters.status === 'open'}
            onClick={() => setFilters(f => ({ ...f, status: f.status === 'open' ? undefined : 'open' }))}
          />
          <StatCard
            label="In Progress" count={stats.in_progress}
            color="text-blue-400" active={filters.status === 'in_progress'}
            onClick={() => setFilters(f => ({ ...f, status: f.status === 'in_progress' ? undefined : 'in_progress' }))}
          />
          <StatCard
            label="Resolved" count={stats.resolved}
            color="text-green-400" active={filters.status === 'resolved'}
            onClick={() => setFilters(f => ({ ...f, status: f.status === 'resolved' ? undefined : 'resolved' }))}
          />
          <StatCard
            label="Dismissed" count={stats.dismissed}
            color="text-gray-400" active={filters.status === 'dismissed'}
            onClick={() => setFilters(f => ({ ...f, status: f.status === 'dismissed' ? undefined : 'dismissed' }))}
          />
        </div>
      )}

      {/* Scan Recommendations */}
      <ScanRecommendationsPanel />

      {/* Filter row */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-[400px]">
          <input
            value={searchFilter}
            onChange={e => setSearchFilter(e.target.value)}
            placeholder="Search title, site, target, rule... (+include -exclude, e.g. example.com -expired)"
            className="w-full h-7 px-2 text-xs rounded border border-border bg-background placeholder:text-muted-foreground/60"
          />
          {searchFilter && (
            <button onClick={() => setSearchFilter('')}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
              <X className="h-3 w-3" />
            </button>
          )}
        </div>
        <select
          value={filters.severity || ''}
          onChange={e => setFilters(f => ({ ...f, severity: e.target.value || undefined }))}
          className="h-7 px-2 text-xs rounded border border-border bg-background"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select
          value={filters.priority || ''}
          onChange={e => setFilters(f => ({ ...f, priority: e.target.value || undefined }))}
          className="h-7 px-2 text-xs rounded border border-border bg-background"
        >
          <option value="">All Priorities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filters.flagged_by || ''}
          onChange={e => setFilters(f => ({ ...f, flagged_by: e.target.value || undefined }))}
          className="h-7 px-2 text-xs rounded border border-border bg-background"
        >
          <option value="">All Sources</option>
          <option value="manual">Manual</option>
          <option value="osint_agent">Agent</option>
        </select>
        {engagementId && (
          <button
            onClick={() => setFilterByEngagement(!filterByEngagement)}
            className={cn(
              'h-7 px-2 text-xs rounded border',
              filterByEngagement
                ? 'border-primary bg-primary/15 text-primary'
                : 'border-border bg-background text-muted-foreground hover:bg-accent'
            )}
          >
            {filterByEngagement ? 'Engagement Only' : 'All Engagements'}
          </button>
        )}
        <button
          onClick={() => setHideDismissed(!hideDismissed)}
          className={cn(
            'h-7 px-2 text-xs rounded border',
            hideDismissed
              ? 'border-gray-500/30 bg-gray-500/15 text-gray-400'
              : 'border-border bg-background text-muted-foreground hover:bg-accent'
          )}
        >
          {hideDismissed ? 'Hiding Dismissed' : 'Show All'}
        </button>
        {Object.values(filters).some(Boolean) && (
          <button
            onClick={() => setFilters({})}
            className="h-7 px-2 text-xs rounded border border-border bg-background hover:bg-accent text-muted-foreground"
          >
            Clear Filters
          </button>
        )}
        {searchFilter && (
          <span className="text-xs text-muted-foreground">
            {items.length} of {allItems.length}
          </span>
        )}
        {agentStats && (
          <span className="ml-auto text-xs text-muted-foreground">
            Agent: {agentStats.total_flagged} flagged
            {agentStats.accuracy != null && ` | ${Math.round(agentStats.accuracy * 100)}% accuracy`}
          </span>
        )}
        {/* Group by toggle */}
        <div className="flex items-center gap-1 ml-2">
          <span className="text-[10px] text-muted-foreground">Group:</span>
          {(['none', 'title', 'target'] as const).map(mode => (
            <button
              key={mode}
              onClick={() => { setGroupBy(mode); setExpandedGroups(new Set()) }}
              className={cn(
                'px-2 py-0.5 text-[10px] rounded border',
                groupBy === mode ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground',
              )}
            >
              {mode === 'none' ? 'Flat' : mode === 'title' ? 'By Finding' : 'By Host'}
            </button>
          ))}
        </div>
      </div>

      {/* Agent Rules Panel */}
      {showRules && (
        <div className="p-3 rounded-lg border border-border bg-card space-y-2">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-medium text-muted-foreground">Detection Rules</h3>
            <div className="flex items-center gap-1.5">
              <select
                value={ruleSinceMinutes}
                onChange={e => setRuleSinceMinutes(Number(e.target.value))}
                className="h-6 px-1.5 text-[10px] rounded border border-border bg-background"
                title="Time range for rule testing"
              >
                <option value={60}>Last 1h</option>
                <option value={360}>Last 6h</option>
                <option value={720}>Last 12h</option>
                <option value={1440}>Last 24h</option>
                <option value={4320}>Last 3d</option>
                <option value={10080}>Last 7d</option>
                <option value={43200}>Last 30d</option>
                <option value={999999}>All time</option>
              </select>
              <button
                onClick={() => reloadRules.mutate()}
                disabled={reloadRules.isPending}
                className="h-6 px-2 text-[10px] rounded border border-border bg-background hover:bg-accent flex items-center gap-1"
                title="Reload rules from YAML files"
              >
                <RotateCcw className={cn("h-3 w-3", reloadRules.isPending && "animate-spin")} />
                Reload
              </button>
              <button
                onClick={() => setShowAdhoc(true)}
                className="h-6 px-2 text-[10px] rounded border border-primary/50 text-primary hover:bg-primary/10 flex items-center gap-1"
              >
                <Wand2 className="h-3 w-3" /> New Rule
              </button>
            </div>
          </div>
          {rules.map(rule => (
            <div key={rule.id} className="flex items-center justify-between text-xs py-1 border-b border-border/50 last:border-0">
              <div className="flex items-center gap-2 min-w-0">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={() => toggleRule.mutate({ ruleId: rule.id, enabled: !rule.enabled })}
                  className="h-3 w-3 flex-shrink-0"
                />
                <span className={cn('font-medium truncate', !rule.enabled && 'text-muted-foreground line-through')}>
                  {rule.name}
                </span>
                <span className={cn(
                  'px-1.5 py-0.5 rounded text-[10px] border flex-shrink-0',
                  SEVERITY_BG[rule.severity as keyof typeof SEVERITY_BG] || 'bg-gray-500 text-white',
                )}>
                  {rule.severity}
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] border border-border bg-muted/50 text-muted-foreground flex-shrink-0">
                  {rule.type}
                </span>
                <span className={cn(
                  'px-1.5 py-0.5 rounded text-[10px] border flex-shrink-0',
                  rule.source === 'builtin' ? 'border-blue-500/30 text-blue-400 bg-blue-500/10' :
                  rule.source === 'custom' ? 'border-green-500/30 text-green-400 bg-green-500/10' :
                  'border-purple-500/30 text-purple-400 bg-purple-500/10'
                )}>
                  {rule.source}
                </span>
              </div>
              <div className="flex items-center gap-1.5 flex-shrink-0 ml-2">
                <button
                  onClick={() => {
                    testRule.mutate({ rule_id: rule.id, since_minutes: ruleSinceMinutes, limit: 10 }, {
                      onSuccess: (data) => setTestResults(data),
                    })
                  }}
                  disabled={testRule.isPending}
                  className="h-5 px-1.5 text-[10px] rounded border border-border bg-background hover:bg-accent flex items-center gap-0.5"
                  title="Test rule (dry run)"
                >
                  <Play className="h-2.5 w-2.5" /> Test
                </button>
                <button
                  onClick={() => setEditRuleId(rule.id)}
                  className="h-5 px-1.5 text-[10px] rounded border border-border bg-background hover:bg-accent flex items-center gap-0.5"
                  title="Edit rule"
                >
                  <Pencil className="h-2.5 w-2.5" />
                </button>
                {rule.source === 'adhoc' && (
                  <button
                    onClick={() => deleteRule.mutate(rule.id)}
                    className="h-5 px-1 text-[10px] rounded border border-red-500/30 text-red-400 hover:bg-red-500/10"
                    title="Delete ad-hoc rule"
                  >
                    <Trash2 className="h-2.5 w-2.5" />
                  </button>
                )}
              </div>
            </div>
          ))}

          {/* Test Results Preview */}
          {testResults && (
            <div className="mt-2 p-2 rounded border border-cyan-500/30 bg-cyan-500/5">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-cyan-400 font-medium">
                  Test: {testResults.rule_id} — {testResults.matches} match{testResults.matches !== 1 ? 'es' : ''}
                </span>
                <button onClick={() => setTestResults(null)} className="text-muted-foreground hover:text-foreground">
                  <X className="h-3 w-3" />
                </button>
              </div>
              {testResults.results.length > 0 ? (
                <div className="space-y-1.5 max-h-60 overflow-y-auto">
                  {testResults.results.slice(0, 10).map((r, i) => (
                    <div key={i} className="text-[10px] border border-border/50 rounded p-1.5 bg-card/50">
                      <div className="flex items-center gap-2">
                        <span className={cn(
                          'px-1 py-0.5 rounded border shrink-0',
                          SEVERITY_BG[r.severity as keyof typeof SEVERITY_BG] || 'bg-gray-500 text-white',
                        )}>{r.severity}</span>
                        <span className="font-medium truncate">{r.title}</span>
                      </div>
                      {r.target && (
                        <div className="mt-0.5 text-muted-foreground font-mono truncate pl-1">
                          Target: {r.target}
                        </div>
                      )}
                      {r.reason && (
                        <div className="mt-0.5 text-muted-foreground pl-1 leading-tight">
                          {r.reason}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <span className="text-[10px] text-muted-foreground">No matches found</span>
              )}
            </div>
          )}
        </div>
      )}

      {/* Bulk Action Bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-2 flex-wrap px-3 py-2 rounded border border-primary/30 bg-primary/5">
          <span className="text-xs font-medium">{selectedIds.size} selected</span>
          <div className="h-4 border-l border-border" />
          <button onClick={() => handleBulkAction('dismiss')} disabled={bulkUpdate.isPending}
            className="h-6 px-2 text-[11px] rounded border border-border bg-background hover:bg-accent">Dismiss</button>
          <button onClick={() => handleBulkAction('accept')} disabled={bulkUpdate.isPending}
            className="h-6 px-2 text-[11px] rounded border border-border bg-background hover:bg-accent">Accept</button>
          <select value={bulkAction} onChange={e => {
            const val = e.target.value
            if (val === 'status' || val === 'priority') setBulkAction(val)
            else setBulkAction('')
          }} className="h-6 px-1 text-[11px] rounded border border-border bg-background">
            <option value="">Set...</option>
            <option value="status">Status</option>
            <option value="priority">Priority</option>
          </select>
          {bulkAction === 'status' && (
            <select onChange={e => { if (e.target.value) { handleBulkUpdate({ status: e.target.value }); } }}
              className="h-6 px-1 text-[11px] rounded border border-border bg-background">
              <option value="">Pick status...</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="dismissed">Dismissed</option>
            </select>
          )}
          {bulkAction === 'priority' && (
            <select onChange={e => { if (e.target.value) { handleBulkUpdate({ priority: e.target.value }); } }}
              className="h-6 px-1 text-[11px] rounded border border-border bg-background">
              <option value="">Pick priority...</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          )}
          <div className="h-4 border-l border-border" />
          <input value={bulkNotes} onChange={e => setBulkNotes(e.target.value)}
            placeholder="Add notes..."
            onKeyDown={e => { if (e.key === 'Enter' && bulkNotes.trim()) { handleBulkUpdate({ notes: bulkNotes.trim() }); setBulkNotes('') } }}
            className="h-6 px-2 text-[11px] rounded border border-border bg-background w-40" />
          {bulkNotes.trim() && (
            <button onClick={() => { handleBulkUpdate({ notes: bulkNotes.trim() }); setBulkNotes('') }}
              className="h-6 px-2 text-[11px] rounded border border-border bg-background hover:bg-accent">Save Notes</button>
          )}
          <div className="h-4 border-l border-border" />
          <select
            onChange={e => {
              const val = e.target.value
              if (!val) return
              if (val === '__oos__') handleBulkExclude()
              else handleAddToScope(val)
              e.target.value = ''
            }}
            disabled={excludeFromScope.isPending || addToScope.isPending}
            className="h-6 px-1 text-[11px] rounded border border-orange-500/30 bg-orange-500/10 text-orange-400"
          >
            <option value="">Add to scope...</option>
            <option value="__oos__">Out-of-Scope (dismiss + exclude)</option>
            {scopeNames.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <button onClick={() => handleSendToBurp()} disabled={sendToBurp.isPending}
            title="Queue selected findings for import in Burp Suite's RagScanBridge extension"
            className="h-6 px-2 text-[11px] rounded border border-orange-500/30 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 flex items-center gap-1">
            <Send className="h-3 w-3" /> {sendToBurp.isPending ? 'Sending...' : 'Send to Burp'}
            {(burpQueueStats?.pending ?? 0) > 0 && (
              <span className="ml-1 px-1 py-0 rounded-full bg-orange-500/20 text-[9px]">{burpQueueStats?.pending}</span>
            )}
          </button>
          <button onClick={() => handleBulkAction('delete')} disabled={bulkUpdate.isPending}
            className="h-6 px-2 text-[11px] rounded border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20">Delete</button>
          <button onClick={() => setSelectedIds(new Set())} className="ml-auto h-6 px-2 text-[11px] rounded border border-border text-muted-foreground hover:bg-accent">
            Clear
          </button>
        </div>
      )}

      {/* Table */}
      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading...</div>
      ) : items.length === 0 ? (
        <div className="text-sm text-muted-foreground p-8 text-center border border-dashed border-border rounded-lg">
          No follow-up items yet. Run the agent or add items manually.
        </div>
      ) : (
        <div className="border border-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-muted/50">
              <tr>
                <th className="px-2 py-2 w-8">
                  <input type="checkbox"
                    checked={selectedIds.size === items.length && items.length > 0}
                    onChange={toggleSelectAll}
                    className="rounded border-border" />
                </th>
                <th className="text-left px-3 py-2 font-medium">Priority</th>
                <th className="text-left px-3 py-2 font-medium">Title</th>
                <th className="text-left px-3 py-2 font-medium">Target</th>
                <th className="text-left px-3 py-2 font-medium">Severity</th>
                <th className="text-left px-3 py-2 font-medium">Flagged By</th>
                <th className="text-left px-3 py-2 font-medium">Status</th>
                <th className="text-left px-3 py-2 font-medium">Created</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {groupBy !== 'none' && groupedData?.groups ? (
                /* Server-side grouped view — accurate counts across all items */
                groupedData.groups.map((g: FollowUpGroup) => {
                  const isOpen = expandedGroups.has(g.group_key)
                  const summary = groupBy === 'title'
                    ? (g.host_samples || []).slice(0, 3).join(', ') + (g.unique_hosts && g.unique_hosts > 3 ? ` +${g.unique_hosts - 3}` : '')
                    : (g.finding_names || []).slice(0, 3).join(', ')
                  return (
                    <Fragment key={g.group_key}>
                      <tr className="bg-muted/20 hover:bg-muted/40 cursor-pointer" onClick={() => toggleGroup(g.group_key)}>
                        <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                          {loadingGroup === g.group_key ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                          ) : (
                            <input
                              type="checkbox"
                              checked={isGroupAllSelected(g.group_key)}
                              ref={el => { if (el) el.indeterminate = isGroupPartiallySelected(g.group_key) }}
                              onChange={() => toggleGroupSelect(g.group_key)}
                              className="rounded border-border"
                              title={`Select all ${g.total} items in "${g.group_key}"`}
                            />
                          )}
                        </td>
                        <td className="px-3 py-2">
                          {isOpen ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
                        </td>
                        <td colSpan={4} className="px-3 py-2">
                          <span className={cn('font-medium', groupBy === 'target' && 'font-mono')}>{g.group_key}</span>
                          <span className="ml-2 px-1.5 py-0.5 rounded-full bg-primary/10 text-[10px] font-semibold text-primary">{g.total}</span>
                          {g.open_count > 0 && <span className="ml-1 px-1.5 py-0.5 rounded-full bg-yellow-500/10 text-[10px] text-yellow-400">{g.open_count} open</span>}
                          {g.in_progress_count > 0 && <span className="ml-1 px-1.5 py-0.5 rounded-full bg-blue-500/10 text-[10px] text-blue-400">{g.in_progress_count} in progress</span>}
                          {g.dismissed_count > 0 && <span className="ml-1 px-1.5 py-0.5 rounded-full bg-muted text-[10px] text-muted-foreground">{g.dismissed_count} dismissed</span>}
                          <span className="ml-2" onClick={e => e.stopPropagation()}>
                            <button
                              onClick={async () => {
                                if (window.confirm(`Dismiss all ${g.total} items in "${g.group_key}"?`)) {
                                  const ids = await fetchGroupIds(g.group_key)
                                  if (ids.length > 0) {
                                    bulkUpdate.mutate({ ids, action: 'dismiss', status: 'dismissed' }, {
                                      onSuccess: () => setSelectedIds(new Set()),
                                    })
                                  }
                                }
                              }}
                              disabled={bulkUpdate.isPending}
                              title={`Dismiss all "${g.group_key}" items`}
                              className="h-5 px-1.5 text-[10px] rounded border border-gray-500/30 bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 inline-flex items-center gap-0.5"
                            >
                              Dismiss
                            </button>
                            <button
                              onClick={() => sendGroupToBurp(g.group_key)}
                              disabled={sendToBurp.isPending}
                              title={`Send all "${g.group_key}" items to Burp Suite`}
                              className="ml-1 h-5 px-1.5 text-[10px] rounded border border-orange-500/30 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 inline-flex items-center gap-0.5"
                            >
                              <Send className="h-2.5 w-2.5" /> Burp
                            </button>
                          </span>
                          {groupBy === 'title' && g.unique_hosts && <span className="ml-2 text-[10px] text-muted-foreground">{g.unique_hosts} host{g.unique_hosts !== 1 ? 's' : ''}</span>}
                        </td>
                        <td colSpan={3} className="px-3 py-2 text-xs text-muted-foreground">
                          <span className={groupBy === 'title' ? 'font-mono truncate' : 'truncate'}>{summary}</span>
                        </td>
                      </tr>
                      {isOpen && (
                        <GroupItems
                          groupKey={g.group_key}
                          groupBy={groupBy}
                          total={g.total}
                          statusFilter={filters.status}
                          excludeStatus={excludeStatus}
                          selected={selected}
                          selectedIds={selectedIds}
                          toggleSelect={toggleSelect}
                          setSelected={setSelected}
                        />
                      )}
                    </Fragment>
                  )
                })
              ) : (
                items.map(item => (
                  <FollowUpRow key={item.id} item={item} selected={selected} selectedIds={selectedIds}
                    toggleSelect={toggleSelect} setSelected={setSelected} />
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Detail slide-over */}
      {selected && (
        <DetailPanel item={selected} onClose={() => setSelected(null)} />
      )}

      {/* Create modal */}
      {showCreate && (
        <CreateModal onClose={() => setShowCreate(false)} />
      )}

      {/* Ad-hoc Rule Builder / Editor modal */}
      {(showAdhoc || editRuleId) && (
        <AdhocRuleModal editRuleId={editRuleId ?? undefined} onClose={() => { setShowAdhoc(false); setEditRuleId(null) }} />
      )}
    </div>
  )
}

// ── Stat Card ──
function StatCard({ label, count, color, active, onClick }: {
  label: string; count: number; color: string; active: boolean; onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'p-3 rounded-lg border text-left transition-colors',
        active ? 'border-primary bg-primary/5' : 'border-border bg-card hover:bg-muted/30',
      )}
    >
      <div className={cn('text-2xl font-bold', color)}>{count}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </button>
  )
}

// ── Detail Panel ──
function DetailPanel({ item, onClose }: { item: FollowUpItem; onClose: () => void }) {
  const update = useUpdateFollowUp()
  const del = useDeleteFollowUp()
  const feedback = useSubmitFeedback()
  const sendToBurp = useSendToBurpQueue()
  const [notes, setNotes] = useState(item.notes || '')
  const [status, setStatus] = useState(item.status)
  const [priority, setPriority] = useState(item.priority)

  const handleSave = () => {
    update.mutate({ id: item.id, status, priority, notes })
  }

  const handleFeedback = (action: string) => {
    feedback.mutate({ id: item.id, action, notes })
  }

  return (
    <div className="fixed inset-y-0 right-0 w-[420px] bg-card border-l border-border shadow-xl z-50 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <h3 className="text-sm font-semibold truncate">{item.title}</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Target — clickable link to asset */}
        {item.target && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">Target</div>
            <a href={`/assets?ip=${encodeURIComponent(item.target)}`}
              className="text-sm font-mono text-primary hover:underline inline-flex items-center gap-1">
              {item.target}
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        )}

        {/* Software product + version (if present in metadata) */}
        {item.metadata?.product && (
          <div className="bg-muted/30 border border-border rounded p-3 space-y-2">
            <div className="text-xs text-muted-foreground">Software Detection</div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold">{item.metadata.product}</span>
              {item.metadata.version && (
                <span className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">{item.metadata.version}</span>
              )}
              {item.target && (
                <span className="text-xs text-muted-foreground">on {item.target}</span>
              )}
            </div>
            {/* Direct link: Asset → Software → specific product */}
            <a
              href={`/assets?tab=software&search=${encodeURIComponent(item.metadata.product)}${item.target ? `&ip=${encodeURIComponent(item.target)}` : ''}`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs border border-purple-500/40 text-purple-400 hover:bg-purple-500/10 font-medium"
            >
              View in Assets → Software → {item.metadata.product} {item.metadata.version || ''}
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        )}

        {/* CVE IDs from metadata */}
        {item.metadata?.cve_ids && item.metadata.cve_ids.length > 0 && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">CVEs ({item.metadata.cve_ids.length})</div>
            <div className="flex flex-wrap gap-1.5">
              {item.metadata.cve_ids.map((cve: string, i: number) => (
                <a key={i} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs border border-red-500/40 text-red-400 hover:bg-red-500/10">
                  {cve} <ExternalLink className="h-2.5 w-2.5" />
                </a>
              ))}
            </div>
          </div>
        )}

        {/* External references (NVD, EDB links) */}
        {item.metadata?.refs && item.metadata.refs.length > 0 && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">References</div>
            <div className="flex flex-wrap gap-1.5">
              {item.metadata.refs.map((ref: any, i: number) => (
                <a key={i} href={ref.url} target="_blank" rel="noopener noreferrer"
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs border ${
                    ref.type === 'cve' ? 'border-red-500/40 text-red-400 hover:bg-red-500/10' :
                    ref.type === 'edb' ? 'border-orange-500/40 text-orange-400 hover:bg-orange-500/10' :
                    'border-border text-muted-foreground hover:bg-muted/30'
                  }`}>
                  {ref.label}
                  <ExternalLink className="h-2.5 w-2.5" />
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Reason / description */}
        {item.reason && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">Reason</div>
            <div className="text-sm whitespace-pre-wrap">{item.reason}</div>
          </div>
        )}

        {/* Agent confidence + severity badges */}
        <div className="flex items-center gap-4">
          {item.confidence != null && (
            <div>
              <div className="text-xs text-muted-foreground mb-1">Confidence</div>
              <div className="text-sm font-medium">{Math.round(item.confidence * 100)}%</div>
            </div>
          )}
          {item.severity && (
            <div>
              <div className="text-xs text-muted-foreground mb-1">Severity</div>
              <span className={cn('px-2 py-0.5 rounded text-xs font-medium',
                item.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                item.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                item.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-muted text-muted-foreground'
              )}>{item.severity}</span>
            </div>
          )}
        </div>

        {/* Flagged by */}
        <div>
          <div className="text-xs text-muted-foreground mb-1">Flagged By</div>
          <div className="text-sm flex items-center gap-1">
            {item.flagged_by === 'osint_agent' && <Bot className="h-3 w-3 text-cyan-400" />}
            {item.flagged_by === 'recon_agent' && <Bot className="h-3 w-3 text-green-400" />}
            {item.flagged_by}
            {item.rule_id && <span className="text-muted-foreground ml-1">({item.rule_id})</span>}
          </div>
        </div>

        {/* Finding source link */}
        {item.finding_source && item.finding_id && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">Original Finding</div>
            <a href={`/findings?search=${encodeURIComponent(item.finding_id)}`}
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
              View in Findings ({item.finding_source})
              <ExternalLink className="h-2.5 w-2.5" />
            </a>
          </div>
        )}

        {/* Status + Priority controls */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <div className="text-xs text-muted-foreground mb-1">Status</div>
            <select
              value={status}
              onChange={e => setStatus(e.target.value)}
              className="w-full h-7 px-2 text-xs rounded border border-border bg-background"
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </div>
          <div>
            <div className="text-xs text-muted-foreground mb-1">Priority</div>
            <select
              value={priority}
              onChange={e => setPriority(e.target.value)}
              className="w-full h-7 px-2 text-xs rounded border border-border bg-background"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        {/* Notes */}
        <div>
          <div className="text-xs text-muted-foreground mb-1">Notes</div>
          <textarea
            value={notes}
            onChange={e => setNotes(e.target.value)}
            rows={3}
            className="w-full px-2 py-1 text-xs rounded border border-border bg-background resize-none"
            placeholder="Add notes..."
          />
        </div>

        {/* Tags */}
        {item.tags && item.tags.length > 0 && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">Tags</div>
            <div className="flex flex-wrap gap-1">
              {item.tags.map(tag => (
                <span key={tag} className="px-1.5 py-0.5 text-[10px] rounded bg-muted text-muted-foreground">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Finding link */}
        {item.finding_source && item.finding_id && (
          <div>
            <div className="text-xs text-muted-foreground mb-1">Original Finding</div>
            <a
              href={item.finding_source === 'recon' ? '/recon' : '/findings'}
              className="text-xs text-primary hover:underline flex items-center gap-1"
            >
              <Eye className="h-3 w-3" />
              View in {item.finding_source === 'recon' ? 'OSINT Explorer' : 'Findings Explorer'}
            </a>
          </div>
        )}
      </div>

      {/* Actions footer */}
      <div className="border-t border-border p-3 space-y-2">
        {/* Agent feedback buttons (for agent-flagged items) */}
        {item.flagged_by === 'osint_agent' && item.status === 'open' && (
          <div className="flex gap-2">
            <button
              onClick={() => handleFeedback('accepted')}
              disabled={feedback.isPending}
              className="flex-1 h-7 text-xs rounded bg-green-600 text-white hover:bg-green-700 flex items-center justify-center gap-1"
            >
              <CheckCircle className="h-3 w-3" /> Accept
            </button>
            <button
              onClick={() => handleFeedback('dismissed')}
              disabled={feedback.isPending}
              className="flex-1 h-7 text-xs rounded bg-gray-600 text-white hover:bg-gray-700 flex items-center justify-center gap-1"
            >
              <XCircle className="h-3 w-3" /> Dismiss
            </button>
          </div>
        )}

        <div className="flex gap-2">
          <button
            onClick={handleSave}
            disabled={update.isPending}
            className="flex-1 h-7 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90"
          >
            {update.isPending ? 'Saving...' : 'Save Changes'}
          </button>
          <button
            onClick={() => sendToBurp.mutate([item.id])}
            disabled={sendToBurp.isPending}
            title="Queue this finding for Burp Suite import via RagScanBridge"
            className="h-7 px-3 text-xs rounded border border-orange-500/30 text-orange-400 hover:bg-orange-500/10 flex items-center gap-1"
          >
            <Send className="h-3 w-3" /> {sendToBurp.isPending ? '...' : 'Burp'}
          </button>
          <button
            onClick={() => { del.mutate(item.id); onClose() }}
            className="h-7 px-3 text-xs rounded border border-red-500/30 text-red-400 hover:bg-red-500/10"
          >
            <Trash2 className="h-3 w-3" />
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Create Modal ──
function CreateModal({ onClose }: { onClose: () => void }) {
  const create = useCreateFollowUp()
  const [form, setForm] = useState({
    title: '', target: '', severity: 'medium', reason: '', priority: 'medium',
    tags: '',
  })

  const handleSubmit = () => {
    create.mutate({
      title: form.title,
      target: form.target || undefined,
      severity: form.severity,
      reason: form.reason || undefined,
      priority: form.priority,
      tags: form.tags ? form.tags.split(',').map(t => t.trim()) : undefined,
      flagged_by: 'manual',
    }, {
      onSuccess: () => onClose(),
    })
  }

  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="bg-card rounded-lg border border-border w-[400px] p-4 space-y-3" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold">Add Follow-Up Item</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-2">
          <input
            value={form.title}
            onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
            placeholder="Title *"
            className="w-full h-7 px-2 text-xs rounded border border-border bg-background"
          />
          <input
            value={form.target}
            onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
            placeholder="Target (IP, URL, hostname)"
            className="w-full h-7 px-2 text-xs rounded border border-border bg-background"
          />
          <div className="grid grid-cols-2 gap-2">
            <select
              value={form.severity}
              onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select
              value={form.priority}
              onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <textarea
            value={form.reason}
            onChange={e => setForm(f => ({ ...f, reason: e.target.value }))}
            placeholder="Reason / notes"
            rows={2}
            className="w-full px-2 py-1 text-xs rounded border border-border bg-background resize-none"
          />
          <input
            value={form.tags}
            onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
            placeholder="Tags (comma-separated)"
            className="w-full h-7 px-2 text-xs rounded border border-border bg-background"
          />
        </div>

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="h-7 px-3 text-xs rounded border border-border bg-background hover:bg-accent">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={!form.title || create.isPending}
            className="h-7 px-3 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {create.isPending ? 'Creating...' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Ad-hoc Rule Builder Modal ──
const RULE_TABLES = ['recon_findings', 'web_findings', 'vulns', 'credential_vault', 'playwright_findings']
const RULE_TYPES = ['simple', 'pattern']

function AdhocRuleModal({ onClose, editRuleId }: { onClose: () => void; editRuleId?: string }) {
  const createAdhoc = useCreateAdhocRule()
  const testRuleMut = useTestRule()
  const [testResults, setTestResults] = useState<RuleTestResult | null>(null)
  const [testSinceMinutes, setTestSinceMinutes] = useState(1440)
  const { data: editData } = useAgentRule(editRuleId)
  const [loaded, setLoaded] = useState(false)

  const [form, setForm] = useState({
    id: '',
    name: '',
    type: 'pattern' as string,
    severity: 'medium',
    confidence: '0.9',
    description: '',
    title_template: '',
    reason_template: '',
    finding_source: 'recon',
    table: 'recon_findings',
    pattern: '',
    pattern_fields: 'target',
    where_source: '',
  })

  // Pre-populate form when editing an existing rule
  useEffect(() => {
    if (editData?.rule && !loaded) {
      const r = editData.rule as Record<string, any>
      const query = r.query || {}
      const match = r.match || {}
      setForm({
        id: r.id || '',
        name: r.name || '',
        type: r.type || 'pattern',
        severity: r.severity || 'medium',
        confidence: String(r.confidence ?? '0.9'),
        description: r.description || '',
        title_template: r.title_template || '',
        reason_template: r.reason_template || '',
        finding_source: r.finding_source || 'recon',
        table: query.table || 'recon_findings',
        pattern: match.pattern || '',
        pattern_fields: (match.fields || query.columns || ['target']).filter((c: string) => c !== 'id').join(', '),
        where_source: query.where?.source || query.where?.source_in?.join(', ') || '',
      })
      setLoaded(true)
    }
  }, [editData, loaded])

  const buildYaml = () => {
    const lines: string[] = [
      `id: ${form.id}`,
      `name: "${form.name}"`,
      `type: ${form.type}`,
      `enabled: true`,
      `severity: ${form.severity}`,
      `confidence: ${form.confidence}`,
      `description: "${form.description}"`,
      `title_template: "${form.title_template}"`,
      `reason_template: "${form.reason_template}"`,
      `finding_source: ${form.finding_source}`,
      `query:`,
      `  table: ${form.table}`,
      `  columns: [id, ${form.pattern_fields}]`,
      `  time_column: created_at`,
    ]
    if (form.where_source) {
      lines.push(`  where:`)
      lines.push(`    source: ${form.where_source}`)
    }
    if (form.type === 'pattern' && form.pattern) {
      lines.push(`match:`)
      lines.push(`  type: regex`)
      lines.push(`  fields: [${form.pattern_fields}]`)
      lines.push(`  pattern: "${form.pattern}"`)
      lines.push(`  case_insensitive: true`)
    }
    return lines.join('\n')
  }

  const handleTest = () => {
    const yaml = buildYaml()
    testRuleMut.mutate({ rule_yaml: yaml, since_minutes: testSinceMinutes, limit: 10 }, {
      onSuccess: (data) => setTestResults(data),
    })
  }

  const handleSave = () => {
    const yaml = buildYaml()
    createAdhoc.mutate(yaml, { onSuccess: () => onClose() })
  }

  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="bg-card rounded-lg border border-border w-[520px] max-h-[90vh] overflow-y-auto p-4 space-y-3" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold flex items-center gap-1.5">
            <Wand2 className="h-4 w-4" /> {editRuleId ? 'Edit Detection Rule' : 'New Detection Rule'}
          </h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <input
              value={form.id}
              onChange={e => setForm(f => ({ ...f, id: e.target.value.replace(/[^a-z0-9_]/g, '') }))}
              placeholder="Rule ID (e.g. my_rule)"
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            />
            <input
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="Display name"
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            />
          </div>

          <div className="grid grid-cols-3 gap-2">
            <select
              value={form.type}
              onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            >
              {RULE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <select
              value={form.severity}
              onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            >
              {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <input
              value={form.confidence}
              onChange={e => setForm(f => ({ ...f, confidence: e.target.value }))}
              placeholder="Confidence (0-1)"
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            />
          </div>

          <input
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            placeholder="Description"
            className="w-full h-7 px-2 text-xs rounded border border-border bg-background"
          />

          <div className="grid grid-cols-2 gap-2">
            <select
              value={form.table}
              onChange={e => setForm(f => ({ ...f, table: e.target.value }))}
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            >
              {RULE_TABLES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <select
              value={form.finding_source}
              onChange={e => setForm(f => ({ ...f, finding_source: e.target.value }))}
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            >
              {['recon', 'web', 'vuln', 'credential'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          <input
            value={form.where_source}
            onChange={e => setForm(f => ({ ...f, where_source: e.target.value }))}
            placeholder="Filter by source (optional, e.g. wafw00f)"
            className="w-full h-7 px-2 text-xs rounded border border-border bg-background"
          />

          <input
            value={form.pattern_fields}
            onChange={e => setForm(f => ({ ...f, pattern_fields: e.target.value }))}
            placeholder="Fields to match (comma-separated, e.g. target, url)"
            className="w-full h-7 px-2 text-xs rounded border border-border bg-background"
          />

          {form.type === 'pattern' && (
            <input
              value={form.pattern}
              onChange={e => setForm(f => ({ ...f, pattern: e.target.value }))}
              placeholder="Regex pattern (e.g. login|admin|auth)"
              className="w-full h-7 px-2 text-xs rounded border border-border bg-background font-mono"
            />
          )}

          <div className="grid grid-cols-2 gap-2">
            <input
              value={form.title_template}
              onChange={e => setForm(f => ({ ...f, title_template: e.target.value }))}
              placeholder="Title template (e.g. Found — {target})"
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            />
            <input
              value={form.reason_template}
              onChange={e => setForm(f => ({ ...f, reason_template: e.target.value }))}
              placeholder="Reason template"
              className="h-7 px-2 text-xs rounded border border-border bg-background"
            />
          </div>

          {/* YAML Preview */}
          <div>
            <div className="text-[10px] text-muted-foreground mb-1">Generated YAML</div>
            <pre className="p-2 text-[10px] rounded border border-border bg-muted/30 font-mono whitespace-pre-wrap max-h-32 overflow-y-auto">
              {buildYaml()}
            </pre>
          </div>

          {/* Test Results */}
          {testResults && (
            <div className="p-2 rounded border border-cyan-500/30 bg-cyan-500/5">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-cyan-400 font-medium">
                  {testResults.matches} match{testResults.matches !== 1 ? 'es' : ''} found
                </span>
                <button onClick={() => setTestResults(null)} className="text-muted-foreground hover:text-foreground">
                  <X className="h-3 w-3" />
                </button>
              </div>
              {testResults.results.length > 0 && (
                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {testResults.results.slice(0, 5).map((r, i) => (
                    <div key={i} className="text-[10px] border border-border/50 rounded p-1.5 bg-card/50">
                      <div className="flex items-center gap-1.5">
                        <span className={cn(
                          'px-1 py-0.5 rounded border shrink-0',
                          SEVERITY_BG[r.severity as keyof typeof SEVERITY_BG] || 'bg-gray-500 text-white',
                        )}>{r.severity}</span>
                        <span className="font-medium truncate">{r.title}</span>
                      </div>
                      {r.target && (
                        <div className="mt-0.5 text-muted-foreground font-mono truncate pl-1">
                          Target: {r.target}
                        </div>
                      )}
                      {r.reason && (
                        <div className="mt-0.5 text-muted-foreground pl-1 leading-tight">
                          {r.reason}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="h-7 px-3 text-xs rounded border border-border bg-background hover:bg-accent">
            Cancel
          </button>
          <select
            value={testSinceMinutes}
            onChange={e => setTestSinceMinutes(Number(e.target.value))}
            className="h-7 px-1.5 text-[10px] rounded border border-border bg-background"
          >
            <option value={60}>1h</option>
            <option value={360}>6h</option>
            <option value={720}>12h</option>
            <option value={1440}>24h</option>
            <option value={4320}>3d</option>
            <option value={10080}>7d</option>
            <option value={43200}>30d</option>
            <option value={999999}>All</option>
          </select>
          <button
            onClick={handleTest}
            disabled={!form.id || testRuleMut.isPending}
            className="h-7 px-3 text-xs rounded border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 flex items-center gap-1 disabled:opacity-50"
          >
            <Play className="h-3 w-3" /> {testRuleMut.isPending ? 'Testing...' : 'Test'}
          </button>
          <button
            onClick={handleSave}
            disabled={!form.id || !form.name || createAdhoc.isPending}
            className="h-7 px-3 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {createAdhoc.isPending ? 'Saving...' : editRuleId ? 'Update Rule' : 'Save Rule'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Group Items (fetches its own data on expand) ────
function GroupItems({ groupKey, groupBy, total, statusFilter, excludeStatus, selected, selectedIds, toggleSelect, setSelected }: {
  groupKey: string; groupBy: string; total: number; statusFilter?: string; excludeStatus?: string
  selected: FollowUpItem | null; selectedIds: Set<string>
  toggleSelect: (id: string) => void; setSelected: (item: FollowUpItem) => void
}) {
  const { data, isLoading } = useFollowUps({
    search: groupKey,
    status: statusFilter,
    exclude_status: excludeStatus,
  })
  // Filter to only items that actually match this group.
  // MUST use the same extraction logic as the parent's extractFindingName
  // (which strips " on <host>" for software CVE titles) — otherwise the
  // group key won't match and "No matching items found" appears.
  const extractFinding = (title: string) => {
    const t = title || ''
    // Software CVE: "Vulnerable: IIS 10.0 on 1.2.3.4 — CVE-..." → "Vulnerable: IIS 10.0"
    if (t.startsWith('Vulnerable: ') && t.includes(' on ')) {
      return t.slice(0, t.indexOf(' on ')).trim()
    }
    for (const sep of [' \u2014 ', ' -- ', ' \u2013 ']) {
      const idx = t.indexOf(sep)
      if (idx >= 0) return t.slice(0, idx).trim()
    }
    return t.trim()
  }
  const extractHost = (target: string | null) => {
    if (!target) return ''
    try { return new URL(target.startsWith('http') ? target : `https://${target}`).hostname }
    catch { return target.split('/')[0].split(':')[0] }
  }

  const items = useMemo(() => {
    const all = data?.follow_ups ?? []
    return all.filter(i => {
      if (groupBy === 'title') return extractFinding(i.title) === groupKey
      return extractHost(i.target) === groupKey
    })
  }, [data, groupKey, groupBy])

  // Auto-open detail panel for single-item groups (common for unique CVE findings).
  // MUST be before any early returns (React rules of hooks).
  useEffect(() => {
    if (items.length === 1 && !selected) {
      setSelected(items[0])
    }
  }, [items.length])

  if (isLoading) {
    return <tr><td colSpan={9} className="px-6 py-2 text-xs text-muted-foreground">Loading {total} items...</td></tr>
  }

  if (items.length === 0) {
    return <tr><td colSpan={9} className="px-6 py-2 text-xs text-muted-foreground italic">No matching items found for "{groupKey}"</td></tr>
  }
  return (
    <>
      {items.map(item => (
        <FollowUpRow key={item.id} item={item} selected={selected} selectedIds={selectedIds}
          toggleSelect={toggleSelect} setSelected={setSelected} indented
          showFullTarget={groupBy === 'title'} />
      ))}
      {items.length < total && (
        <tr><td colSpan={9} className="px-6 py-1 text-[10px] text-muted-foreground">
          Showing {items.length} of {total}
        </td></tr>
      )}
    </>
  )
}

// ─── Follow-Up Table Row ─────────────────────────────
function FollowUpRow({ item, selected, selectedIds, toggleSelect, setSelected, indented, showFullTarget }: {
  item: FollowUpItem; selected: FollowUpItem | null; selectedIds: Set<string>
  toggleSelect: (id: string) => void; setSelected: (item: FollowUpItem) => void
  indented?: boolean; showFullTarget?: boolean
}) {
  // Extract host/IP from target for display
  const displayTarget = useMemo(() => {
    const t = item.target || ''
    if (showFullTarget) {
      // Show path portion for grouped-by-finding expanded rows
      try {
        const u = new URL(t.startsWith('http') ? t : `https://${t}`)
        return u.hostname + (u.pathname !== '/' ? u.pathname : '')
      } catch {
        return t
      }
    }
    try {
      const u = new URL(t.startsWith('http') ? t : `https://${t}`)
      return u.hostname
    } catch {
      return t.split('/')[0].split(':')[0] || t
    }
  }, [item.target, showFullTarget])

  return (
    <tr
      className={cn(
        'hover:bg-muted/30 cursor-pointer transition-colors',
        selected?.id === item.id && 'bg-primary/5',
        selectedIds.has(item.id) && 'bg-primary/10',
        indented && 'bg-card/50',
      )}
      onClick={() => setSelected(item)}
    >
      <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
        <input type="checkbox" checked={selectedIds.has(item.id)} onChange={() => toggleSelect(item.id)}
          className="rounded border-border" />
      </td>
      <td className="px-3 py-2">
        <AlertTriangle className={cn('h-4 w-4', PRIORITY_ICON[item.priority] || 'text-gray-400')} />
      </td>
      <td className={cn('px-3 py-2 font-medium max-w-[250px]', indented && 'pl-6')}>
        <div className="truncate">{item.title}</div>
        {item.metadata?.product && (
          <a
            href={`/assets?tab=software&search=${encodeURIComponent(item.metadata.product)}${item.target ? `&ip=${encodeURIComponent(item.target)}` : ''}`}
            onClick={e => e.stopPropagation()}
            className="text-[10px] text-purple-400 font-mono truncate hover:underline inline-flex items-center gap-1"
          >
            {item.metadata.product} {item.metadata.version || ''}
            {item.metadata.cve_ids?.length ? ` (${item.metadata.cve_ids.length} CVEs)` : ''}
            <ExternalLink className="h-2 w-2 shrink-0" />
          </a>
        )}
      </td>
      <td className="px-3 py-2 text-muted-foreground max-w-[180px] truncate font-mono" title={item.target || ''}>
        <a href={`/assets?ip=${encodeURIComponent(item.target || '')}`}
          onClick={e => e.stopPropagation()}
          className="hover:text-primary hover:underline">
          {displayTarget}
        </a>
      </td>
      <td className="px-3 py-2">
        <span className={cn(
          'px-1.5 py-0.5 rounded text-[10px] border',
          SEVERITY_BG[item.severity as keyof typeof SEVERITY_BG] || 'bg-gray-500 text-white',
        )}>
          {item.severity}
        </span>
      </td>
      <td className="px-3 py-2">
        {item.flagged_by === 'osint_agent' ? (
          <span className="flex items-center gap-1 text-cyan-400"><Bot className="h-3 w-3" /> Agent</span>
        ) : item.flagged_by === 'manual' ? (
          <span className="text-muted-foreground">Manual</span>
        ) : (
          <span className="text-muted-foreground">{item.flagged_by}</span>
        )}
      </td>
      <td className="px-3 py-2">
        <span className={cn(
          'px-1.5 py-0.5 rounded text-[10px] border',
          STATUS_BADGE[item.status] || STATUS_BADGE.open,
        )}>
          {item.status}
        </span>
      </td>
      <td className="px-3 py-2 text-muted-foreground">
        {new Date(item.created_at).toLocaleDateString()}
      </td>
      <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
        {item.metadata?.product ? (
          <a
            href={`/assets?tab=software&search=${encodeURIComponent(item.metadata.product)}${item.target ? `&ip=${encodeURIComponent(item.target)}` : ''}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border border-purple-500/40 text-purple-400 hover:bg-purple-500/10 whitespace-nowrap"
            title={`View ${item.metadata.product} ${item.metadata.version || ''} on ${item.target || 'assets'}`}
          >
            View <ExternalLink className="h-2.5 w-2.5" />
          </a>
        ) : (
          <ChevronRight className="h-3 w-3 text-muted-foreground" />
        )}
      </td>
    </tr>
  )
}
