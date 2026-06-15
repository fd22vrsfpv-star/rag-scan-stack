import { useState, useMemo, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import PageHelp from '@/components/PageHelp'
import InfoTip from '@/components/InfoTip'
import { useInfiniteFindings, useUpdateFindingWorkflow, useFindingActivity, useAddFindingComment, useExploitMatches, useUpdateFindingTags, useTagSuggestions, useDeleteFindings, type FindingsFilter } from '@/api/findings'
import { ScopeAssignModal } from '@/components/common/ScopeAssignModal'
import { useFindingEvidence, useUploadEvidence, useLinkEvidence } from '@/api/evidence'
import { useScopeNames, useAddToScope, useScope } from '@/api/scope'
import { ScopeFilter } from '@/components/common/ScopeFilter'
import { useScopeFilter } from '@/hooks/useScopeFilter'
import { useScreenshots } from '@/api/recon'
import { apiUrl } from '@/api/client'
import { ScreenshotThumbnail, MicroScreenshot } from '@/components/common/ScreenshotThumbnail'
import { useUIStore } from '@/stores/ui'
import { useCreateFeedback } from '@/api/feedback'
import { useCreateFollowUp, useCreateAdhocRule } from '@/api/followups'
import { useAssetPorts, useAssetVulns } from '@/api/assets'
import { SeverityBadge } from '@/components/common/SeverityBadge'
import { SourceBadge } from '@/components/common/SourceBadge'
import { SEVERITY_LEVELS, PREDEFINED_TAGS, TAG_COLORS, TAG_COLOR_DEFAULT } from '@/lib/constants'
import type { Finding, WorkflowStatus } from '@/lib/types'
import { X, ThumbsUp, ThumbsDown, Check, ChevronRight, ChevronDown, Upload, MessageSquare, Swords, Tag, Crosshair, Zap, Loader2, Globe, Trash2, Flag } from 'lucide-react'
import { useGeneratePocs, useQueuePoc, type WebPayload } from '@/api/exploits'
import { cn, formatDate } from '@/lib/utils'

const WORKFLOW_STATUSES: WorkflowStatus[] = [
  'new', 'triaging', 'confirmed', 'false_positive', 'accepted_risk', 'in_report', 'deferred',
]
const WF_COLORS: Record<string, string> = {
  new: 'bg-blue-500/10 text-blue-400',
  triaging: 'bg-yellow-500/10 text-yellow-400',
  confirmed: 'bg-green-500/10 text-green-400',
  false_positive: 'bg-gray-500/10 text-gray-400',
  accepted_risk: 'bg-orange-500/10 text-orange-400',
  in_report: 'bg-purple-500/10 text-purple-400',
  deferred: 'bg-gray-500/10 text-gray-500',
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 1, high: 2, medium: 3, low: 4, info: 5, recon: 6,
}

/** Create a readable display title for findings */
function displayTitle(f: Finding): string {
  // If title is useful (not empty, not "Unknown", not null, and not just an IP address)
  if (f.title && f.title !== 'Unknown' && f.title !== 'None' && f.title !== 'null'
      && f.title !== f.ip && !f.title.match(/^\d+\.\d+\.\d+\.\d+$/)) return f.title
  // Extract hostname + path from URL (more informative than raw IP)
  if (f.url) {
    try {
      const u = new URL(f.url)
      const path = u.pathname === '/' ? '' : u.pathname
      if (path) return `${u.hostname}${path.length > 40 ? path.slice(0, 40) + '...' : path}`
      return u.hostname
    } catch {
      // url might be "192.168.1.150:22" (not a valid URL)
      return f.url.slice(0, 60)
    }
  }
  // Fall back to source + host (never show bare IP as a title)
  if (f.source && (f.hostname || f.ip)) return `${f.source} — ${f.hostname || f.ip}`
  return f.hostname || f.source || f.ip || 'Unknown'
}

/** Extract screenshot path from gowitness evidence */
function extractScreenshotPath(f: Finding): string | null {
  if (f.source !== 'gowitness' || !f.evidence) return null
  const m = f.evidence.match(/Screenshot captured: (.+\.png)/)
  return m ? m[1] : null
}

/** Strip /32 CIDR mask from IP addresses */
function cleanIp(ip: string | null | undefined): string {
  if (!ip) return ''
  return ip.replace(/\/32$/, '')
}

/** Extract hostname from a finding for display */
function displayHost(f: Finding): string {
  if (f.hostname) return f.hostname
  if (f.url) {
    try { return new URL(f.url).hostname } catch { /* */ }
  }
  return cleanIp(f.ip)
}

interface FindingGroup {
  title: string
  severity: string
  source: string
  findings: Finding[]
}

function groupFindings(findings: Finding[]): (Finding | FindingGroup)[] {
  // Group by display title + source for meaningful grouping
  const titleCounts = new Map<string, Finding[]>()
  for (const f of findings) {
    // For recon sources (katana, httpx, whatweb), group by hostname
    const key = (f.source === 'katana' || f.source === 'httpx' || f.source === 'whatweb' || f.source === 'gowitness' || f.source === 'portscan')
      ? `${f.source}:${displayHost(f)}`
      : (f.title && f.title !== 'Unknown' && f.title !== 'None') ? f.title : `${f.source}:${displayHost(f)}`
    if (!titleCounts.has(key)) titleCounts.set(key, [])
    titleCounts.get(key)!.push(f)
  }

  const result: (Finding | FindingGroup)[] = []
  const seen = new Set<string>()
  for (const f of findings) {
    const key = (f.source === 'katana' || f.source === 'httpx' || f.source === 'whatweb' || f.source === 'gowitness' || f.source === 'portscan')
      ? `${f.source}:${displayHost(f)}`
      : (f.title && f.title !== 'Unknown' && f.title !== 'None') ? f.title : `${f.source}:${displayHost(f)}`
    if (seen.has(key)) continue
    seen.add(key)
    const group = titleCounts.get(key)!
    if (group.length > 1) {
      const groupTitle = (f.source === 'katana' || f.source === 'httpx' || f.source === 'whatweb' || f.source === 'gowitness' || f.source === 'portscan')
        ? `${displayHost(f)} (${f.source})`
        : displayTitle(f)
      result.push({
        title: groupTitle,
        severity: f.severity,
        source: f.source,
        findings: group,
      })
    } else {
      result.push(f)
    }
  }
  return result
}

function isGroup(item: Finding | FindingGroup): item is FindingGroup {
  return 'findings' in item && Array.isArray((item as FindingGroup).findings)
}

export default function FindingsExplorer() {
  const globalScope = useUIStore(s => s.selectedScopeName)
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const [scopeFilter, setScopeFilter] = useState(globalScope || '')
  const { matchesScope, isFiltering: isScopeFiltering } = useScopeFilter(scopeFilter)
  const [searchParams] = useSearchParams()
  // Seed the host filter from a deep link (e.g. the Attack Map "Findings" link
  // passes ?ip=<host>). Applied once on mount via the lazy initializer.
  const [filters, setFilters] = useState<FindingsFilter>(() => {
    const ip = searchParams.get('ip')
    const search = searchParams.get('search')
    return { ...(ip ? { ip } : {}), ...(search ? { search } : {}) }
  })
  // Merge engagement_id into the active filter set so the API pre-filters server-side
  const activeFilters = useMemo(() => ({
    ...filters,
    ...(engagementId ? { engagement_id: engagementId } : {}),
  }), [filters, engagementId])

  // Sync with global engagement scope (clear when engagement changes)
  useEffect(() => {
    setScopeFilter(globalScope || '')
  }, [globalScope])

  // Clear selections + source filter on scope/engagement change
  useEffect(() => {
    setSelectedIds(new Set())
  }, [scopeFilter])
  useEffect(() => {
    // Reset source filter when engagement changes — old sources may not exist in new scope
    setFilters(f => ({ ...f, source: undefined }))
    setSelectedIds(new Set())
  }, [engagementId])
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const topCreateFollowUp = useCreateFollowUp()
  const topCreateAdhocRule = useCreateAdhocRule()
  const [showScopeModal, setShowScopeModal] = useState(false)
  const deleteFindings = useDeleteFindings()
  const { data, isLoading, error, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteFindings(activeFilters)

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  }

  const allFindings = useMemo(() => (data?.pages ?? []).flatMap(p => p.findings ?? []), [data])
  const findings = useMemo(() => {
    if (!isScopeFiltering) return allFindings
    return allFindings.filter(f => matchesScope(f.hostname || f.ip || f.url || ''))
  }, [allFindings, isScopeFiltering, matchesScope])
  // total = server-side count for the active filter set (respects severity/source/status).
  const serverTotal = data?.pages?.[0]?.total ?? 0
  const total = isScopeFiltering ? findings.length : serverTotal
  const loadedCount = allFindings.length

  const toggleSelectAll = () => {
    if (selectedIds.size === findings.length) setSelectedIds(new Set())
    else setSelectedIds(new Set(findings.filter(f => f.id).map(f => f.id!)))
  }
  const handleBulkDelete = () => {
    if (!selectedIds.size) return
    if (!window.confirm(`Delete ${selectedIds.size} finding(s)? This cannot be undone.`)) return
    deleteFindings.mutate([...selectedIds], { onSuccess: () => setSelectedIds(new Set()) })
  }
  const selectedTargets = useMemo(() => {
    return findings.filter(f => f.id && selectedIds.has(f.id || '')).map(f => ({
      target: f.hostname || f.ip || f.url || '',
      target_type: f.ip ? 'ip' as const : 'domain' as const,
    })).filter(t => t.target)
  }, [selectedIds, findings])
  // Source counts from the loaded + scope-filtered findings (what the user can
  // currently see), used as the chip count when scope filtering is active.
  const scopedBySource = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const f of findings) {
      const src = f.source || 'unknown'
      counts[src] = (counts[src] || 0) + 1
    }
    return counts
  }, [findings])
  // Global source aggregations from the API — these list EVERY source in the
  // dataset (not just the loaded page), so all sources are always filterable.
  const aggBySource = useMemo(
    () => data?.pages?.[0]?.aggregations?.by_source ?? {},
    [data],
  )
  // Show the union of every source the API knows about plus any currently
  // loaded, so no source is ever missing a filter chip.
  const activeSources = useMemo(() => {
    const set = new Set<string>([...Object.keys(aggBySource), ...Object.keys(scopedBySource)])
    return [...set].sort()
  }, [aggBySource, scopedBySource])

  const grouped = useMemo(() => groupFindings(findings), [findings])

  const toggleGroup = (title: string) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      if (next.has(title)) next.delete(title)
      else next.add(title)
      return next
    })
  }

  const toggleFilter = (key: 'severity' | 'source', value: string) => {
    const current = filters[key] || []
    const next = current.includes(value)
      ? current.filter(v => v !== value)
      : [...current, value]
    setFilters({ ...filters, [key]: next.length ? next : undefined })
  }

  return (
    <div className="space-y-4">
      <PageHelp id="findings" title="How to use Findings">
        <p>All findings from every scan tool in one place. Use the filters to narrow by <strong>severity</strong>, <strong>source tool</strong>, <strong>host</strong>, or <strong>port</strong>. Click any finding to see full evidence, set workflow status, assign to team members, and add tester notes. Use the checkboxes for bulk actions (delete, export). Findings with the same title auto-group — expand to see individual instances.</p>
      </PageHelp>
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Findings Explorer</h2>
        <div className="flex items-center gap-3">
          <ScopeFilter value={scopeFilter} onChange={setScopeFilter} />
          <span className="text-xs text-muted-foreground">
            {isScopeFiltering
              ? `${total.toLocaleString()} findings in ${scopeFilter}`
              : loadedCount < total
                ? `${loadedCount.toLocaleString()} of ${total.toLocaleString()} findings`
                : `${total.toLocaleString()} findings`}
          </span>
        </div>
      </div>

      {/* Filters */}
      <div className="space-y-2">
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-xs text-muted-foreground py-1">Severity:</span>
          {SEVERITY_LEVELS.map(s => (
            <button
              key={s}
              onClick={() => toggleFilter('severity', s)}
              className={cn(
                'px-2.5 py-1 rounded-md text-sm font-medium border transition-colors capitalize',
                filters.severity?.includes(s) ? 'border-primary bg-primary/15 text-primary ring-1 ring-primary/30' : 'border-border bg-muted/50 text-foreground hover:border-primary/50',
              )}
            >
              {s}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-xs text-muted-foreground py-1 inline-flex items-center gap-1">
            Source:
            <InfoTip side="bottom" text={
              <>
                Every scan tool that produced findings — listed from the dataset-wide
                aggregations, so <b>all sources appear even if not in the rows loaded so
                far</b>. The count is the dataset total for that source (the current
                scope-filter narrows it). Click to filter; the list refetches server-side.
              </>
            } />
          </span>
          {activeSources.map(s => {
            const active = filters.source?.includes(s)
            // When scope filtering (client-side), show what's visible; otherwise
            // show the global per-source total from the API aggregations.
            const count = isScopeFiltering ? (scopedBySource[s] ?? 0) : (aggBySource[s] ?? 0)
            return (
              <button
                key={s}
                onClick={() => toggleFilter('source', s)}
                className={cn(
                  'px-2.5 py-1 rounded-md text-sm font-mono font-medium border transition-colors',
                  active
                    ? 'border-primary bg-primary/15 text-primary ring-1 ring-primary/30'
                    : 'border-border bg-muted/50 text-foreground hover:border-primary/50',
                )}
              >
                {s}
                <span className={cn('ml-1.5 text-xs', active ? 'text-primary/70' : 'text-muted-foreground')}>
                  {count.toLocaleString()}
                </span>
              </button>
            )
          })}
        </div>
        <div className="flex flex-wrap gap-1.5">
          <span className="text-xs text-muted-foreground py-1">Status:</span>
          {WORKFLOW_STATUSES.map(s => (
            <button
              key={s}
              onClick={() => {
                const cur = filters.workflow_status || []
                const next = cur.includes(s) ? cur.filter(v => v !== s) : [...cur, s]
                setFilters({ ...filters, workflow_status: next.length ? next : undefined })
              }}
              className={cn(
                'px-2 py-0.5 rounded text-xs border capitalize',
                filters.workflow_status?.includes(s) ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground',
              )}
            >
              {s.replace('_', ' ')}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5">
          <span className="text-xs text-muted-foreground py-1">Tags:</span>
          {PREDEFINED_TAGS.map(t => (
            <button
              key={t}
              onClick={() => {
                const cur = filters.tags || []
                const next = cur.includes(t) ? cur.filter(v => v !== t) : [...cur, t]
                setFilters({ ...filters, tags: next.length ? next : undefined })
              }}
              className={cn(
                'px-2 py-0.5 rounded text-xs border',
                filters.tags?.includes(t) ? TAG_COLORS[t] || TAG_COLOR_DEFAULT : 'border-border text-muted-foreground',
              )}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            placeholder="IP filter"
            value={filters.ip || ''}
            onChange={e => setFilters({ ...filters, ip: e.target.value || undefined })}
            className="bg-muted rounded-md px-3 py-1 text-sm border border-border outline-none focus:border-primary w-36"
          />
          <input
            placeholder="Port"
            type="number"
            value={filters.port ?? ''}
            onChange={e => setFilters({ ...filters, port: e.target.value ? Number(e.target.value) : undefined })}
            className="bg-muted rounded-md px-3 py-1 text-sm border border-border outline-none focus:border-primary w-20"
          />
          <input
            placeholder="CVE search"
            value={filters.cve || ''}
            onChange={e => setFilters({ ...filters, cve: e.target.value || undefined })}
            className="bg-muted rounded-md px-3 py-1 text-sm border border-border outline-none focus:border-primary w-40"
          />
          <input
            placeholder="Free text search"
            value={filters.search || ''}
            onChange={e => setFilters({ ...filters, search: e.target.value || undefined })}
            className="bg-muted rounded-md px-3 py-1 text-sm border border-border outline-none focus:border-primary flex-1"
          />
        </div>
      </div>

      {/* Bulk action bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 bg-primary/10 border border-primary/30 rounded-lg px-4 py-2">
          <span className="text-sm font-medium">{selectedIds.size} selected</span>
          <button
            onClick={() => setShowScopeModal(true)}
            className="flex items-center gap-1.5 px-3 py-1 text-xs rounded border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
          >
            <Globe className="h-3 w-3" /> Assign to Scope
          </button>
          <button
            onClick={handleBulkDelete}
            disabled={deleteFindings.isPending}
            className="flex items-center gap-1.5 px-3 py-1 text-xs rounded border border-red-500/30 text-red-400 hover:bg-red-500/10"
          >
            <Trash2 className="h-3 w-3" /> Delete
          </button>
          <button onClick={() => setSelectedIds(new Set())} className="ml-auto text-xs text-muted-foreground hover:text-foreground">Clear</button>
        </div>
      )}

      {showScopeModal && (
        <ScopeAssignModal
          targets={selectedTargets}
          fromScope={scopeFilter || undefined}
          onClose={() => setShowScopeModal(false)}
          onSuccess={() => setSelectedIds(new Set())}
        />
      )}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : error ? (
        <p className="text-sm text-red-400">Error loading findings: {error.message}</p>
      ) : findings.length === 0 && engagementId ? (
        <div className="text-center py-8">
          <p className="text-sm text-muted-foreground mb-4">
            No findings found for the selected engagement.
          </p>
          <button
            onClick={() => useUIStore.getState().setSelectedEngagement(null)}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm"
          >
            Clear Engagement Filter
          </button>
        </div>
      ) : findings.length === 0 ? (
        <p className="text-sm text-muted-foreground text-center py-8">No findings found.</p>
      ) : (
        <div className="border border-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/50">
                  <th className="px-2 py-2 w-8">
                    <input type="checkbox" checked={selectedIds.size === findings.length && findings.length > 0} onChange={toggleSelectAll} className="rounded border-border" />
                  </th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground w-6"></th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{ width: 90 }}>Severity</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">Title</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">Host</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{ width: 60 }}>Port</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{ width: 80 }}>Source</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{ width: 160 }}>Tags</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{ width: 120 }}>CVE</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{ width: 140 }}>Date</th>
                  <th className="px-2 py-2 w-8"></th>
                </tr>
              </thead>
              <tbody>
                {grouped.map((item, idx) => {
                  if (isGroup(item)) {
                    const expanded = expandedGroups.has(item.title)
                    return (
                      <>
                        <tr
                          key={`group-${idx}`}
                          className="border-b border-border/50 bg-muted/20 hover:bg-muted/40 cursor-pointer transition-colors"
                          onClick={() => toggleGroup(item.title)}
                        >
                          <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                            <input type="checkbox"
                              checked={item.findings.every(f => selectedIds.has(f.id || ''))}
                              onChange={() => {
                                const ids = item.findings.map(f => f.id || '').filter(Boolean)
                                setSelectedIds(prev => {
                                  const n = new Set(prev)
                                  ids.every(id => n.has(id)) ? ids.forEach(id => n.delete(id)) : ids.forEach(id => n.add(id))
                                  return n
                                })
                              }}
                              className="rounded border-border"
                            />
                          </td>
                          <td className="px-3 py-2 text-muted-foreground">
                            {expanded
                              ? <ChevronDown className="h-3.5 w-3.5" />
                              : <ChevronRight className="h-3.5 w-3.5" />}
                          </td>
                          <td className="px-3 py-2"><SeverityBadge severity={item.severity} /></td>
                          <td className="px-3 py-2">
                            <span className="text-sm font-medium">{item.title}</span>
                            <span className="ml-2 px-1.5 py-0.5 rounded-full bg-primary/10 text-[10px] font-semibold text-primary">
                              {item.findings.length}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-xs">
                            {(() => {
                              const hosts = [...new Set(item.findings.map(f => displayHost(f)).filter(Boolean))]
                              return <span className="font-mono">{hosts.slice(0, 3).join(', ')}{hosts.length > 3 ? '...' : ''}</span>
                            })()}
                          </td>
                          <td className="px-3 py-2"></td>
                          <td className="px-3 py-2"><SourceBadge source={item.source} /></td>
                          <td className="px-3 py-2"></td>
                          <td className="px-3 py-2"></td>
                          <td className="px-3 py-2"></td>
                          <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                            <FindingQuickActions
                              title={item.title}
                              source={item.source}
                              severity={item.severity}
                              target={item.findings[0]?.url || item.findings[0]?.hostname || item.findings[0]?.ip || ''}
                              findingId={item.findings[0]?.id}
                              onCreateFollowUp={topCreateFollowUp}
                              onCreateRule={topCreateAdhocRule}
                            />
                          </td>
                        </tr>
                        {expanded && item.findings.map((f, fi) => (
                          <tr
                            key={`group-${idx}-${fi}`}
                            className="border-b border-border/50 hover:bg-muted/30 cursor-pointer transition-colors bg-card/50"
                            onClick={() => setSelectedFinding(f)}
                          >
                            <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                              <input type="checkbox" checked={selectedIds.has(f.id || '')} onChange={() => toggleSelect(f.id || '')} className="rounded border-border" />
                            </td>
                            <td className="px-3 py-2"></td>
                            <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
                            <td className="px-3 py-2 pl-6">
                              <div className="flex items-center gap-2">
                                {extractScreenshotPath(f) && <MicroScreenshot path={extractScreenshotPath(f)!} alt={displayTitle(f)} />}
                                <span className="text-xs text-muted-foreground font-mono">{displayTitle(f)}</span>
                              </div>
                            </td>
                            <td className="px-3 py-2">
                              <span className="text-xs font-mono">{displayHost(f)}</span>
                              {f.ip && f.hostname && <span className="text-[10px] text-muted-foreground ml-1">{cleanIp(f.ip)}</span>}
                            </td>
                            <td className="px-3 py-2 text-xs font-mono">{f.port ?? ''}</td>
                            <td className="px-3 py-2"><SourceBadge source={f.source} /></td>
                            <td className="px-3 py-2">
                              <div className="flex flex-wrap gap-0.5">
                                {(f.tags || []).slice(0, 3).map(t => (
                                  <span key={t} className={cn('px-1.5 py-0 rounded text-[9px] border', TAG_COLORS[t] || TAG_COLOR_DEFAULT)}>{t}</span>
                                ))}
                              </div>
                            </td>
                            <td className="px-3 py-2 text-xs">{f.cve ?? ''}</td>
                            <td className="px-3 py-2">
                              <span className="text-xs text-muted-foreground">{f.created_at ? formatDate(f.created_at) : ''}</span>
                            </td>
                            <td className="px-2 py-2"></td>
                          </tr>
                        ))}
                      </>
                    )
                  }
                  // Single finding — no grouping
                  const f = item as Finding
                  return (
                    <tr
                      key={`single-${idx}`}
                      className="border-b border-border/50 hover:bg-muted/30 cursor-pointer transition-colors"
                      onClick={() => setSelectedFinding(f)}
                    >
                      <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                        <input type="checkbox" checked={selectedIds.has(f.id || '')} onChange={() => toggleSelect(f.id || '')} className="rounded border-border" />
                      </td>
                      <td className="px-3 py-2"></td>
                      <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          {extractScreenshotPath(f) && <MicroScreenshot path={extractScreenshotPath(f)!} alt={displayTitle(f)} />}
                          <span className="text-sm">{displayTitle(f)}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <span className="text-xs font-mono">{displayHost(f)}</span>
                        {f.ip && f.hostname && <span className="text-[10px] text-muted-foreground ml-1">{cleanIp(f.ip)}</span>}
                      </td>
                      <td className="px-3 py-2 text-xs font-mono">{f.port ?? ''}</td>
                      <td className="px-3 py-2"><SourceBadge source={f.source} /></td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-0.5">
                          {(f.tags || []).slice(0, 3).map(t => (
                            <span key={t} className={cn('px-1.5 py-0 rounded text-[9px] border', TAG_COLORS[t] || TAG_COLOR_DEFAULT)}>{t}</span>
                          ))}
                          {(f.tags || []).length > 3 && <span className="text-[9px] text-muted-foreground">+{(f.tags || []).length - 3}</span>}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-xs">{f.cve ?? ''}</td>
                      <td className="px-3 py-2">
                        <span className="text-xs text-muted-foreground">{f.created_at ? formatDate(f.created_at) : ''}</span>
                      </td>
                      <td className="px-2 py-2" onClick={e => e.stopPropagation()}>
                        <FindingQuickActions
                          title={f.title}
                          source={f.source}
                          severity={f.severity}
                          target={f.url || f.hostname || f.ip || ''}
                          findingId={f.id}
                          onCreateFollowUp={topCreateFollowUp}
                          onCreateRule={topCreateAdhocRule}
                        />
                      </td>
                    </tr>
                  )
                })}
                {grouped.length === 0 && (
                  <tr>
                    <td colSpan={9} className="px-3 py-8 text-center text-muted-foreground text-sm">
                      No data
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Load more — accumulate additional pages until all findings are loaded */}
      {!isLoading && !isScopeFiltering && total > 0 && (
        <div className="flex items-center justify-center gap-3 py-2">
          <span className="text-xs text-muted-foreground inline-flex items-center gap-1">
            Showing {loadedCount.toLocaleString()} of {total.toLocaleString()}
            <InfoTip side="top" text={
              <>
                Findings load in pages of 500. <b>Load more</b> fetches the next page and
                appends it. <code>total</code> reflects the current severity / source /
                status filters (applied server-side), so narrowing the filters is the fast
                way to reach a specific finding instead of paging through everything.
              </>
            } />
          </span>
          {hasNextPage && (
            <button
              onClick={() => fetchNextPage()}
              disabled={isFetchingNextPage}
              className="px-3 py-1.5 rounded-md text-sm font-medium border border-border bg-muted/50 text-foreground hover:border-primary/50 disabled:opacity-50"
            >
              {isFetchingNextPage ? 'Loading…' : 'Load more'}
            </button>
          )}
        </div>
      )}

      {/* Detail slide-over */}
      {selectedFinding && (
        <FindingDetailPanel
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  )
}

// ─── Detail Panel (separate component to use hooks) ───
function FindingDetailPanel({
  finding,
  onClose,
}: {
  finding: Finding
  onClose: () => void
}) {
  const f = finding as Finding & { finding_source?: string; workflow_status?: string; assigned_to?: string; verified_by?: string; tester_notes?: string; original_severity?: string; report_ready?: boolean }
  const fSource = f.finding_source || (f.source === 'playwright' ? 'playwright' : f.source === 'zap' || f.source === 'gobuster' ? 'web' : 'vuln')

  const createFeedback = useCreateFeedback()
  const updateWorkflow = useUpdateFindingWorkflow()
  const updateTags = useUpdateFindingTags()
  const addComment = useAddFindingComment()
  const { data: activityData } = useFindingActivity(fSource, f.id)
  const { data: evidenceData } = useFindingEvidence(fSource, f.id)
  const { data: exploitData } = useExploitMatches(fSource, f.id)
  const { data: suggestionsData } = useTagSuggestions()
  const scopeNames = useScopeNames()
  const addToScope = useAddToScope()
  const uploadEvidence = useUploadEvidence()
  const linkEvidence = useLinkEvidence()

  const [feedbackRating, setFeedbackRating] = useState<5 | 1 | null>(null)
  const [feedbackComment, setFeedbackComment] = useState('')
  const [feedbackSent, setFeedbackSent] = useState(false)
  const [newComment, setNewComment] = useState('')
  const [assignedTo, setAssignedTo] = useState(f.assigned_to || '')
  const [testerNotes, setTesterNotes] = useState(f.tester_notes || '')
  const [tagInput, setTagInput] = useState('')
  const [scopeTarget, setScopeTarget] = useState('')
  const [scopeAdded, setScopeAdded] = useState(false)
  const createFollowUp = useCreateFollowUp()
  const createAdhocRule = useCreateAdhocRule()
  const [followUpCreated, setFollowUpCreated] = useState(false)
  const [ruleCreated, setRuleCreated] = useState(false)

  // Fetch screenshots matching this finding's hostname
  const screenshotSearch = finding.hostname || finding.ip || (finding.url ? new URL(finding.url).hostname : '') || ''
  const { data: screenshotsData } = useScreenshots(screenshotSearch || undefined)
  const matchingScreenshots = (screenshotsData?.screenshots ?? []).slice(0, 6)

  // Fetch port context when finding has IP + port
  const { data: portsData } = useAssetPorts(finding.ip || '')
  const { data: vulnsData } = useAssetVulns(finding.ip || '')

  const portInfo = useMemo(() => {
    if (!portsData?.items || !finding.port) return null
    return portsData.items.find(p => p.port === finding.port) ?? null
  }, [portsData, finding.port])

  const portVulns = useMemo(() => {
    if (!vulnsData?.vulns || !finding.port) return []
    return vulnsData.vulns
      .filter(v => v.port === finding.port)
      .filter((v, i, arr) => arr.findIndex(u => u.script === v.script && u.output === v.output) === i)
      .filter(v => v.script !== finding.title)
  }, [vulnsData, finding.port, finding.title])

  const handleFindingFeedback = () => {
    if (!feedbackRating) return
    createFeedback.mutate({
      rating: feedbackRating,
      comment: feedbackComment || undefined,
      context: {
        type: 'finding_feedback',
        finding_id: finding.id,
        title: finding.title,
        severity: finding.severity,
        source: finding.source,
        ip: finding.ip,
        port: finding.port,
        cve: finding.cve,
        evidence: finding.evidence || finding.output,
      },
    }, {
      onSuccess: () => {
        setFeedbackSent(true)
        setTimeout(() => { setFeedbackSent(false); setFeedbackRating(null); setFeedbackComment('') }, 3000)
      },
    })
  }

  const handleStatusChange = (status: WorkflowStatus) => {
    if (!f.id) return
    updateWorkflow.mutate({ source: fSource, id: f.id, workflow_status: status })
  }

  const handleVerify = () => {
    if (!f.id) return
    updateWorkflow.mutate({ source: fSource, id: f.id, workflow_status: 'confirmed', verified_by: assignedTo || 'tester' })
  }

  const handleSaveNotes = () => {
    if (!f.id) return
    const data: Record<string, unknown> = { source: fSource, id: f.id }
    if (testerNotes !== (f.tester_notes || '')) data.tester_notes = testerNotes
    if (assignedTo !== (f.assigned_to || '')) data.assigned_to = assignedTo
    updateWorkflow.mutate(data as Parameters<typeof updateWorkflow.mutate>[0])
  }

  const handleAddComment = () => {
    if (!newComment.trim() || !f.id) return
    addComment.mutate({ source: fSource, id: f.id, comment: newComment, actor: assignedTo || undefined }, {
      onSuccess: () => setNewComment(''),
    })
  }

  const handleEvidenceUpload = (files: FileList | null) => {
    if (!files || !f.id) return
    const file = files[0]
    uploadEvidence.mutate({
      file,
      title: file.name,
      evidence_type: file.type.startsWith('image/') ? 'screenshot' : 'file',
    }, {
      onSuccess: (data) => {
        if (data?.id) {
          const entityType = fSource === 'vuln' ? 'finding' : fSource === 'web' ? 'web_finding' : 'playwright_finding'
          linkEvidence.mutate({ evidenceId: data.id, entityType, entityId: f.id! })
        }
      },
    })
  }

  const activities = activityData?.activity ?? []
  const evidenceList = evidenceData?.evidence ?? []
  const exploitMatches = exploitData?.matches ?? []

  // Web PoC generation state
  const generatePocs = useGeneratePocs()
  const queuePoc = useQueuePoc()
  const [pocPayloads, setPocPayloads] = useState<WebPayload[]>([])
  const [selectedPayloads, setSelectedPayloads] = useState<Set<number>>(new Set())
  const [pocQueued, setPocQueued] = useState(false)

  const WEB_POC_TYPES = new Set([
    'xss', 'cross-site scripting', 'sqli', 'sql-injection', 'sql injection',
    'command-injection', 'command injection', 'ssrf', 'lfi', 'path-traversal',
    'directory-traversal', 'xxe', 'csrf', 'open-redirect', 'open redirect',
  ])
  const issueType = ((f as any).issue_type || (f as any).finding_type || '').toLowerCase()
  const canGeneratePoc = WEB_POC_TYPES.has(issueType) || fSource === 'web' || fSource === 'playwright'

  const handleGeneratePocs = () => {
    if (!f.id) return
    setPocPayloads([])
    setSelectedPayloads(new Set())
    setPocQueued(false)
    generatePocs.mutate(
      { source: fSource, findingId: f.id },
      {
        onSuccess: (data) => {
          setPocPayloads(data?.payloads ?? [])
          // Auto-select all
          setSelectedPayloads(new Set((data?.payloads ?? []).map((_: any, i: number) => i)))
        },
      },
    )
  }

  const handleQueuePocs = () => {
    if (!f.id || selectedPayloads.size === 0) return
    const selected = pocPayloads.filter((_, i) => selectedPayloads.has(i))
    queuePoc.mutate(
      { source: fSource, findingId: f.id, payloads: selected },
      {
        onSuccess: () => setPocQueued(true),
      },
    )
  }

  return (
    <div className="fixed inset-y-0 right-0 w-[500px] bg-card border-l border-border shadow-xl z-50 overflow-y-auto">
      <div className="flex items-center justify-between p-4 border-b border-border">
        <h3 className="text-sm font-semibold">Finding Detail</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="p-4 space-y-3">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <SourceBadge source={finding.source} />
          {f.workflow_status && (
            <span className={cn('px-2 py-0.5 text-[10px] rounded-full capitalize', WF_COLORS[f.workflow_status] || 'bg-muted')}>
              {f.workflow_status.replace('_', ' ')}
            </span>
          )}
        </div>
        <h4 className="text-sm font-medium">{finding.title}</h4>

        {/* ── Workflow Controls (C1) ── */}
        <div className="border border-border rounded-md p-2.5 space-y-2">
          <h5 className="text-xs font-medium text-muted-foreground">Workflow</h5>
          <div className="flex flex-wrap gap-1">
            {WORKFLOW_STATUSES.map(s => (
              <button key={s} onClick={() => handleStatusChange(s)}
                className={cn('px-2 py-0.5 text-[10px] rounded capitalize border',
                  f.workflow_status === s ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'
                )}>{s.replace('_', ' ')}</button>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-2">
            <input placeholder="Assigned To" value={assignedTo}
              onChange={e => setAssignedTo(e.target.value)}
              className="px-2 py-1 text-xs rounded border border-border bg-background" />
            <button onClick={handleVerify}
              className="px-2 py-1 text-xs rounded bg-green-500/10 text-green-400 border border-green-500/30 hover:bg-green-500/20">
              Mark Verified
            </button>
          </div>
          <textarea placeholder="Tester Notes" value={testerNotes}
            onChange={e => setTesterNotes(e.target.value)}
            className="w-full px-2 py-1 text-xs rounded border border-border bg-background h-16" />
          <button onClick={handleSaveNotes} disabled={updateWorkflow.isPending}
            className="px-3 py-1 text-xs rounded bg-primary text-primary-foreground disabled:opacity-50">
            Save
          </button>
        </div>

        {/* ── Tags (TIER 8) ── */}
        <div className="border border-border rounded-md p-2.5 space-y-2">
          <h5 className="text-xs font-medium text-muted-foreground flex items-center gap-1">
            <Tag className="h-3 w-3" /> Tags
          </h5>
          <div className="flex flex-wrap gap-1">
            {(f.tags || []).map((t: string) => (
              <span key={t} className={cn('px-2 py-0.5 text-[10px] rounded border flex items-center gap-1', TAG_COLORS[t] || TAG_COLOR_DEFAULT)}>
                {t}
                <button onClick={() => f.id && updateTags.mutate({ source: fSource, id: f.id, tags: [t], action: 'remove' })}
                  className="hover:text-foreground"><X className="h-2.5 w-2.5" /></button>
              </span>
            ))}
            {(f.tags || []).length === 0 && <span className="text-[10px] text-muted-foreground">No tags</span>}
          </div>
          <div className="flex gap-1">
            <input placeholder="Add tag..." value={tagInput} onChange={e => setTagInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && tagInput.trim() && f.id) {
                  updateTags.mutate({ source: fSource, id: f.id, tags: [tagInput.trim().toLowerCase()], action: 'add' })
                  setTagInput('')
                }
              }}
              className="flex-1 px-2 py-0.5 text-xs rounded border border-border bg-background" list="tag-suggestions" />
            <datalist id="tag-suggestions">
              {(suggestionsData?.tags ?? []).map(t => <option key={t} value={t} />)}
            </datalist>
          </div>
          <div className="flex flex-wrap gap-1">
            {PREDEFINED_TAGS.filter(t => !(f.tags || []).includes(t)).slice(0, 6).map(t => (
              <button key={t} onClick={() => f.id && updateTags.mutate({ source: fSource, id: f.id, tags: [t], action: 'add' })}
                className={cn('px-1.5 py-0 text-[9px] rounded border hover:opacity-80', TAG_COLORS[t] || TAG_COLOR_DEFAULT)}>
                + {t}
              </button>
            ))}
          </div>
        </div>

        {/* ── Add to Scope (TIER 8) ── */}
        <div className="border border-border rounded-md p-2.5 space-y-2">
          <h5 className="text-xs font-medium text-muted-foreground flex items-center gap-1">
            <Crosshair className="h-3 w-3" /> Add to Scope
          </h5>
          <div className="flex gap-2">
            <select value={scopeTarget} onChange={e => setScopeTarget(e.target.value)}
              className="flex-1 px-2 py-1 text-xs rounded border border-border bg-background">
              <option value="">Select scope...</option>
              {(scopeNames.data?.names ?? []).map((n: any) => {
                const name = typeof n === 'string' ? n : n.name
                return <option key={name} value={name}>{name}</option>
              })}
            </select>
            <button
              disabled={!scopeTarget || addToScope.isPending}
              onClick={() => {
                const target = f.url || f.hostname || f.ip
                if (!target || !scopeTarget) return
                const targetType = f.url ? 'url' : f.hostname ? 'domain' : 'ip'
                addToScope.mutate({ name: scopeTarget, targets: [{ target, target_type: targetType, source: 'finding-tag' }] }, {
                  onSuccess: () => { setScopeAdded(true); setTimeout(() => setScopeAdded(false), 2000) },
                })
              }}
              className="px-3 py-1 text-xs rounded bg-primary text-primary-foreground disabled:opacity-50">
              {scopeAdded ? 'Added!' : addToScope.isPending ? '...' : 'Add'}
            </button>
          </div>
          <span className="text-[10px] text-muted-foreground">
            Target: {f.url || f.hostname || f.ip || 'none'}
          </span>
        </div>

        {/* ── Create Follow-Up ── */}
        <div className="border border-border rounded-md p-2.5 space-y-2">
          <h5 className="text-xs font-medium text-muted-foreground flex items-center gap-1">
            <Flag className="h-3 w-3" /> Create Follow-Up
          </h5>
          <p className="text-[10px] text-muted-foreground">
            Flag this finding for follow-up investigation or create a detection rule to match similar findings.
          </p>
          <div className="flex gap-2">
            <button
              disabled={createFollowUp.isPending || followUpCreated}
              onClick={() => {
                createFollowUp.mutate({
                  finding_source: fSource,
                  finding_id: f.id,
                  title: f.title || 'Untitled finding',
                  target: f.url || f.hostname || f.ip || null,
                  severity: f.severity || 'info',
                  reason: `Flagged from Findings Explorer: ${f.source} — ${f.title || ''}`.slice(0, 500),
                  status: 'open',
                  priority: f.severity === 'critical' || f.severity === 'high' ? 'high' : 'medium',
                  flagged_by: 'manual',
                  tags: [f.source, f.severity].filter(Boolean),
                } as any, {
                  onSuccess: () => { setFollowUpCreated(true); setTimeout(() => setFollowUpCreated(false), 3000) },
                })
              }}
              className="px-3 py-1 text-xs rounded bg-amber-600 text-white hover:bg-amber-700 disabled:opacity-50 flex items-center gap-1"
            >
              <Flag className="h-3 w-3" />
              {followUpCreated ? 'Created!' : createFollowUp.isPending ? 'Creating...' : 'Flag for Follow-Up'}
            </button>
            <button
              disabled={createAdhocRule.isPending || ruleCreated}
              onClick={() => {
                const matchName = (f.title || '').replace(/[^\w\s-]/g, '').trim()
                const ruleId = `detect_${f.source}_${matchName.toLowerCase().replace(/\s+/g, '_').slice(0, 40)}`
                const table = f.source === 'nmap' || f.source === 'masscan' ? 'vulns'
                  : ['zap', 'gobuster', 'nikto', 'katana', 'playwright', 'gowitness', 'wafw00f', 'ffuf', 'golinkfinder', 'exif', 'pdf'].includes(f.source) ? 'web_findings'
                  : ['subfinder', 'dnsx', 'httpx', 'tlsx', 'whatweb', 'crtsh', 'email-enum', 'dns-enum'].includes(f.source) ? 'recon_findings'
                  : 'web_findings'
                const nameCol = table === 'vulns' ? 'script' : table === 'recon_findings' ? 'finding_type' : 'name'
                const yaml = [
                  `id: "${ruleId}"`,
                  `name: "Detect: ${matchName}"`,
                  `description: "Auto-generated rule from finding: ${(f.title || '').slice(0, 100)}"`,
                  `type: pattern`,
                  `severity: ${f.severity || 'info'}`,
                  `confidence: 0.8`,
                  `finding_source: ${f.source}`,
                  `enabled: true`,
                  `query:`,
                  `  table: ${table}`,
                  `  columns: [id, ${nameCol}]`,
                  `  time_column: created_at`,
                  `match:`,
                  `  type: regex`,
                  `  fields: [${nameCol}]`,
                  `  pattern: "${matchName.replace(/"/g, '\\"')}"`,
                  `  case_insensitive: true`,
                ].join('\n')
                createAdhocRule.mutate(yaml, {
                  onSuccess: () => { setRuleCreated(true); setTimeout(() => setRuleCreated(false), 3000) },
                })
              }}
              className="px-3 py-1 text-xs rounded bg-violet-600 text-white hover:bg-violet-700 disabled:opacity-50 flex items-center gap-1"
            >
              <Zap className="h-3 w-3" />
              Create Detection Rule
            </button>
          </div>
          {followUpCreated && (
            <p className="text-[10px] text-green-500">Follow-up created — view on Follow-Ups page</p>
          )}
          {ruleCreated && (
            <p className="text-[10px] text-green-500">Detection rule created — view on Follow-Ups page under Rules</p>
          )}
        </div>

        {/* ── Web PoC Generation ── */}
        {canGeneratePoc && (
          <div className="border border-border rounded-md p-2.5 space-y-2">
            <h5 className="text-xs font-medium text-muted-foreground flex items-center gap-1">
              <Zap className="h-3 w-3" /> Web PoC
            </h5>
            {pocPayloads.length === 0 && !generatePocs.isPending && !pocQueued && (
              <button
                onClick={handleGeneratePocs}
                disabled={generatePocs.isPending}
                className="px-3 py-1.5 text-xs rounded bg-orange-600 text-white hover:bg-orange-700 flex items-center gap-1"
              >
                <Zap className="h-3 w-3" /> Generate PoC Payloads
              </button>
            )}
            {generatePocs.isPending && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" /> Generating payloads...
              </div>
            )}
            {pocPayloads.length > 0 && !pocQueued && (
              <div className="space-y-1.5">
                <p className="text-[10px] text-muted-foreground">{pocPayloads.length} payloads generated — select which to queue:</p>
                {pocPayloads.map((p, i) => (
                  <label key={i} className="flex items-start gap-2 p-1.5 rounded border border-border hover:bg-muted/30 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedPayloads.has(i)}
                      onChange={() => {
                        setSelectedPayloads(prev => {
                          const next = new Set(prev)
                          if (next.has(i)) next.delete(i)
                          else next.add(i)
                          return next
                        })
                      }}
                      className="mt-0.5 rounded"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="text-[10px] font-medium">{p.description}</div>
                      <code className="text-[9px] text-orange-400 break-all block">{p.payload.slice(0, 80)}{p.payload.length > 80 ? '...' : ''}</code>
                      <div className="flex gap-2 mt-0.5">
                        <span className="text-[9px] text-muted-foreground">{p.injection_point}</span>
                        <span className="text-[9px] text-muted-foreground">conf: {Math.round(p.confidence * 100)}%</span>
                        {p.source === 'llm' && <span className="text-[9px] text-purple-400">AI</span>}
                      </div>
                    </div>
                  </label>
                ))}
                <button
                  onClick={handleQueuePocs}
                  disabled={selectedPayloads.size === 0 || queuePoc.isPending}
                  className="px-3 py-1 text-xs rounded bg-green-600 text-white hover:bg-green-700 disabled:opacity-50"
                >
                  {queuePoc.isPending ? 'Queueing...' : `Queue ${selectedPayloads.size} PoC(s) for Approval`}
                </button>
              </div>
            )}
            {pocQueued && (
              <div className="text-xs text-green-400 flex items-center gap-1">
                <Check className="h-3 w-3" /> PoCs queued — view in Exploit Manager
              </div>
            )}
            {generatePocs.isError && (
              <p className="text-[10px] text-red-400">Failed to generate payloads</p>
            )}
          </div>
        )}

        {/* Core finding info */}
        <div className="grid grid-cols-2 gap-2 text-xs">
          {finding.hostname && <div className="col-span-2"><span className="text-muted-foreground">Hostname:</span> <span className="font-mono">{finding.hostname}</span></div>}
          <div><span className="text-muted-foreground">IP:</span> <span className="font-mono">{cleanIp(finding.ip)}</span></div>
          <div><span className="text-muted-foreground">Port:</span> {finding.port}</div>
          {finding.cve && <div><span className="text-muted-foreground">CVE:</span> {finding.cve}</div>}
          {finding.cwe && <div><span className="text-muted-foreground">CWE:</span> {finding.cwe}</div>}
          {finding.cvss != null && <div><span className="text-muted-foreground">CVSS:</span> {finding.cvss}</div>}
          {finding.confidence && <div><span className="text-muted-foreground">Confidence:</span> {finding.confidence}</div>}
          {finding.method && <div><span className="text-muted-foreground">Method:</span> {finding.method}</div>}
          {finding.url && <div className="col-span-2"><span className="text-muted-foreground">URL:</span> <span className="break-all">{finding.url}</span></div>}
        </div>

        {portInfo && (
          <div className="border border-border rounded-md p-2.5">
            <h5 className="text-xs font-medium text-muted-foreground mb-1.5">
              Port {portInfo.port}/{portInfo.proto ?? 'tcp'} — Service Details
            </h5>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              <div><span className="text-muted-foreground">Service:</span> {portInfo.service || '—'}</div>
              <div><span className="text-muted-foreground">Product:</span> {portInfo.product || '—'}</div>
              <div><span className="text-muted-foreground">Version:</span> {portInfo.version || '—'}</div>
              {portInfo.banner && (
                <div className="col-span-2">
                  <span className="text-muted-foreground">Banner:</span>{' '}
                  <span className="font-mono break-all">{portInfo.banner}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {finding.description && (
          <div>
            <h5 className="text-xs font-medium text-muted-foreground mb-1">Description</h5>
            <p className="text-xs text-foreground/90 whitespace-pre-wrap">{finding.description}</p>
          </div>
        )}
        {(finding.evidence || finding.output) && (
          <div>
            <h5 className="text-xs font-medium text-muted-foreground mb-1">Evidence</h5>
            <pre className="text-[10px] bg-muted rounded p-2 overflow-x-auto max-h-64 whitespace-pre-wrap">
              {finding.evidence || finding.output}
            </pre>
          </div>
        )}
        {finding.solution && (
          <div>
            <h5 className="text-xs font-medium text-muted-foreground mb-1">Solution / Remediation</h5>
            <p className="text-xs text-foreground/90 whitespace-pre-wrap">{finding.solution}</p>
          </div>
        )}
        {finding.reference && (
          <div>
            <h5 className="text-xs font-medium text-muted-foreground mb-1">References</h5>
            <p className="text-xs text-foreground/90 whitespace-pre-wrap break-all">{finding.reference}</p>
          </div>
        )}

        {/* ── Evidence Gallery (B1) ── */}
        <div className="border-t border-border pt-3">
          <div className="flex items-center justify-between mb-2">
            <h5 className="text-xs font-medium text-muted-foreground flex items-center gap-1">
              <Upload className="h-3 w-3" /> Evidence ({evidenceList.length})
            </h5>
            <label className="px-2 py-0.5 text-[10px] rounded bg-primary/10 text-primary cursor-pointer hover:bg-primary/20">
              Add Evidence
              <input type="file" className="hidden" onChange={e => handleEvidenceUpload(e.target.files)} />
            </label>
          </div>
          {evidenceList.length > 0 ? (
            <div className="grid grid-cols-3 gap-2">
              {evidenceList.map(ev => (
                <div key={ev.id} className="border border-border rounded p-1.5">
                  {ev.content_type?.startsWith('image/') ? (
                    <img
                      src={`/api/evidence/${ev.id}/thumbnail`}
                      alt={ev.title}
                      className="w-full h-16 object-cover rounded"
                    />
                  ) : (
                    <div className="h-16 flex items-center justify-center text-[10px] text-muted-foreground bg-muted rounded">
                      {ev.evidence_type}
                    </div>
                  )}
                  <div className="text-[10px] mt-1 truncate">{ev.title}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[10px] text-muted-foreground">No evidence attached. Upload screenshots, requests, or notes.</div>
          )}
        </div>

        {/* ── Exploit Matches (J2) ── */}
        {exploitMatches.length > 0 && (
          <div className="border-t border-border pt-3">
            <h5 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1">
              <Swords className="h-3 w-3" /> Exploit Matches ({exploitMatches.length})
            </h5>
            {exploitMatches.slice(0, 5).map((m: any, i: number) => (
              <div key={i} className="border border-border rounded p-2 mb-1.5 text-xs">
                <div className="font-medium">{m.title || m.module_path || 'Unknown'}</div>
                <div className="flex items-center gap-2 text-[10px] text-muted-foreground mt-0.5">
                  {m.match_confidence != null && (
                    <span className={cn('px-1.5 py-0.5 rounded',
                      m.match_confidence > 0.7 ? 'bg-green-500/10 text-green-400' : m.match_confidence > 0.4 ? 'bg-yellow-500/10 text-yellow-400' : 'bg-muted',
                    )}>
                      {Math.round(m.match_confidence * 100)}% match
                    </span>
                  )}
                  {m.source && <span>{m.source}</span>}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── GoWitness Screenshots ── */}
        {matchingScreenshots.length > 0 && (
          <div className="border-t border-border pt-3">
            <h5 className="text-xs font-medium text-muted-foreground mb-2">
              Screenshots ({matchingScreenshots.length})
            </h5>
            <div className="grid grid-cols-2 gap-2">
              {matchingScreenshots.map((s, i) => (
                <ScreenshotThumbnail key={i} path={s.path} filename={s.filename} />
              ))}
            </div>
          </div>
        )}

        {/* ── Activity Log & Comments (C2) ── */}
        <div className="border-t border-border pt-3">
          <h5 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1">
            <MessageSquare className="h-3 w-3" /> Activity ({activities.length})
          </h5>
          <div className="flex gap-2 mb-2">
            <input placeholder="Add a comment..." value={newComment}
              onChange={e => setNewComment(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAddComment()}
              className="flex-1 px-2 py-1 text-xs rounded border border-border bg-background" />
            <button onClick={handleAddComment} disabled={!newComment.trim() || addComment.isPending}
              className="px-2 py-1 text-xs rounded bg-primary text-primary-foreground disabled:opacity-50">
              Post
            </button>
          </div>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {activities.map(a => (
              <div key={a.id} className="text-[10px] p-1.5 rounded bg-muted/50">
                <div className="flex items-center gap-1.5">
                  {a.activity_type === 'comment' ? (
                    <span className="text-primary font-medium">{a.actor || 'anonymous'}</span>
                  ) : (
                    <span className="text-muted-foreground capitalize">{a.activity_type.replace('_', ' ')}</span>
                  )}
                  <span className="text-muted-foreground">{new Date(a.created_at).toLocaleString()}</span>
                </div>
                {a.comment && <div className="mt-0.5">{a.comment}</div>}
                {a.new_value && !a.comment && <div className="mt-0.5 text-muted-foreground">&rarr; {a.new_value}</div>}
              </div>
            ))}
          </div>
        </div>

        {/* Other vulns on same port */}
        {portVulns.length > 0 && (
          <div className="border-t border-border pt-3">
            <h5 className="text-xs font-medium text-muted-foreground mb-2">
              Other Vulnerabilities on Port {finding.port} ({portVulns.length})
            </h5>
            {portVulns.map((v, i) => (
              <div key={i} className="border border-border rounded-md p-2 mb-2">
                <p className="text-xs font-medium">{v.script}</p>
                <pre className="text-[10px] mt-1 bg-muted rounded p-1 overflow-x-auto max-h-24">
                  {v.output?.slice(0, 500)}
                </pre>
              </div>
            ))}
          </div>
        )}

        {/* Training Feedback */}
        <div className="border-t border-border pt-3">
          <h5 className="text-xs font-medium text-muted-foreground mb-2">Training Feedback</h5>
          {feedbackSent ? (
            <div className="flex items-center gap-1.5 text-green-400 text-xs">
              <Check className="h-3.5 w-3.5" /> Feedback sent!
            </div>
          ) : (
            <>
              <div className="flex gap-2">
                <button onClick={() => setFeedbackRating(5)}
                  className={cn('flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs border',
                    feedbackRating === 5 ? 'border-green-500 bg-green-500/10 text-green-400' : 'border-border text-muted-foreground',
                  )}>
                  <ThumbsUp className="h-3.5 w-3.5" /> True Positive
                </button>
                <button onClick={() => setFeedbackRating(1)}
                  className={cn('flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs border',
                    feedbackRating === 1 ? 'border-red-500 bg-red-500/10 text-red-400' : 'border-border text-muted-foreground',
                  )}>
                  <ThumbsDown className="h-3.5 w-3.5" /> False Positive
                </button>
              </div>
              {feedbackRating !== null && (
                <div className="mt-2 space-y-2">
                  <textarea placeholder="Optional comment..." value={feedbackComment}
                    onChange={e => setFeedbackComment(e.target.value)}
                    className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary resize-none h-16" />
                  <button onClick={handleFindingFeedback} disabled={createFeedback.isPending}
                    className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-xs disabled:opacity-50">
                    {createFeedback.isPending ? 'Submitting...' : 'Submit Feedback'}
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}


// ─── Quick Actions (inline on finding rows) ─────────
function FindingQuickActions({
  title, source, severity, target, findingId,
  onCreateFollowUp, onCreateRule,
}: {
  title: string; source: string; severity: string; target: string; findingId?: string
  onCreateFollowUp: ReturnType<typeof useCreateFollowUp>
  onCreateRule: ReturnType<typeof useCreateAdhocRule>
}) {
  const [done, setDone] = useState<'followup' | 'rule' | null>(null)

  const matchName = (title || '').replace(/[^\w\s-]/g, '').trim()
  const fSource = source === 'playwright' ? 'playwright' : source === 'zap' || source === 'gobuster' ? 'web' : 'vuln'

  const handleFollowUp = () => {
    onCreateFollowUp.mutate({
      finding_source: fSource,
      finding_id: findingId,
      title: title || 'Untitled',
      target: target || null,
      severity: severity || 'info',
      reason: `Flagged from Findings Explorer: ${source} — ${title}`.slice(0, 500),
      status: 'open',
      priority: severity === 'critical' || severity === 'high' ? 'high' : 'medium',
      flagged_by: 'manual',
      tags: [source, severity].filter(Boolean),
    } as any, {
      onSuccess: () => { setDone('followup'); setTimeout(() => setDone(null), 2000) },
    })
  }

  const handleRule = () => {
    const ruleId = `detect_${source}_${matchName.toLowerCase().replace(/\s+/g, '_').slice(0, 40)}`
    const table = source === 'nmap' || source === 'masscan' ? 'vulns'
      : ['zap', 'gobuster', 'nikto', 'katana', 'playwright', 'gowitness', 'wafw00f', 'ffuf', 'golinkfinder', 'exif', 'pdf'].includes(source) ? 'web_findings'
      : ['subfinder', 'dnsx', 'httpx', 'tlsx', 'whatweb', 'crtsh', 'email-enum', 'dns-enum'].includes(source) ? 'recon_findings'
      : 'web_findings'
    const nameCol = table === 'vulns' ? 'script' : table === 'recon_findings' ? 'finding_type' : 'name'
    const yaml = [
      `id: "${ruleId}"`,
      `name: "Detect: ${matchName}"`,
      `description: "Auto-generated rule from finding: ${(title || '').slice(0, 100)}"`,
      `type: pattern`,
      `severity: ${severity || 'info'}`,
      `confidence: 0.8`,
      `finding_source: ${source}`,
      `table: ${table}`,
      `column: ${nameCol}`,
      `pattern: "${matchName.replace(/"/g, '\\"')}"`,
      `match_type: contains`,
      `enabled: true`,
    ].join('\n')
    onCreateRule.mutate(yaml, {
      onSuccess: () => { setDone('rule'); setTimeout(() => setDone(null), 2000) },
    })
  }

  if (done === 'followup') return <span className="text-[9px] text-green-500">Flagged</span>
  if (done === 'rule') return <span className="text-[9px] text-green-500">Rule created</span>

  return (
    <div className="flex items-center gap-0.5">
      <button
        onClick={handleFollowUp}
        className="p-1 rounded text-muted-foreground hover:text-amber-400 hover:bg-amber-500/10"
        title="Flag for follow-up"
      >
        <Flag className="h-3 w-3" />
      </button>
      <button
        onClick={handleRule}
        className="p-1 rounded text-muted-foreground hover:text-violet-400 hover:bg-violet-500/10"
        title="Create detection rule"
      >
        <Zap className="h-3 w-3" />
      </button>
    </div>
  )
}

