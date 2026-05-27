import { useState, useEffect, useMemo } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  Newspaper, Search, RefreshCw, Loader2, X, ExternalLink, Github, Server,
  Trash2, CheckSquare, Square, Eye, Settings as SettingsIcon, Wand2,
  HelpCircle, Globe, ShieldAlert, Plus,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import PageHelp from '@/components/PageHelp'
import {
  useNewsItems, useNewsItem, useNewsStats, useNewsSources, useNewsRun,
  useTriggerIngest, useUpdateNewsItem, useBulkNewsAction,
  useMatchAssets, useGithubSearch, useEnrichItem,
  useDeepSearch, useUpdateSource, useRefetchSource, useCreateSource,
} from '@/api/news'
import type { NewsItem, NewsStatus, NewsSource } from '@/lib/types'

const STATUS_TABS: { id: NewsStatus; label: string }[] = [
  { id: 'new',       label: 'NEW' },
  { id: 'reviewed',  label: 'Reviewed' },
  { id: 'follow_up', label: 'Follow-up' },
  { id: 'applies',   label: 'Applies' },
  { id: 'research',  label: 'Research' },
  { id: 'future',    label: 'Future' },
]

const STATUS_COLOR: Record<NewsStatus, string> = {
  new:       'bg-amber-500/15 text-amber-400 border-amber-500/30',
  reviewed:  'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
  follow_up: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  applies:   'bg-red-500/15 text-red-400 border-red-500/30',
  research:  'bg-purple-500/15 text-purple-400 border-purple-500/30',
  future:    'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  deleted:   'bg-zinc-700/40 text-zinc-500 border-zinc-700/50',
}

function FlagPill({ value, label, kind }: { value: boolean | null; label: string; kind?: 'good' | 'bad' }) {
  if (value === true) {
    const cls = kind === 'good'
      ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
      : 'bg-red-500/15 text-red-400 border-red-500/30'
    return <span className={cn('px-1.5 py-0.5 text-[10px] rounded border whitespace-nowrap', cls)}>{label}</span>
  }
  if (value === false) {
    return <span className="px-1.5 py-0.5 text-[10px] rounded border bg-zinc-500/10 text-zinc-500 border-zinc-500/20 whitespace-nowrap">no {label}</span>
  }
  return (
    <span className="px-1.5 py-0.5 text-[10px] rounded border bg-zinc-700/30 text-zinc-400 border-zinc-700/50 inline-flex items-center gap-0.5" title={`${label}: UNKNOWN`}>
      <HelpCircle className="h-3 w-3" /> {label}
    </span>
  )
}

export default function News() {
  const qc = useQueryClient()
  const [activeStatus, setActiveStatus] = useState<NewsStatus | 'all'>('new')
  const [search, setSearch] = useState('')
  const [cveFilter, setCveFilter] = useState('')
  const [kevOnly, setKevOnly] = useState(false)
  const [rceOnly, setRceOnly] = useState(false)
  const [redTeamOnly, setRedTeamOnly] = useState(true)
  const [hideStatuses, setHideStatuses] = useState<Set<NewsStatus>>(new Set(['deleted']))
  const [maxAgeDays, setMaxAgeDays] = useState<number | null>(30)
  const [hideDeleted] = useState(true)

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [openItemId, setOpenItemId] = useState<string | null>(null)
  const [sourcesOpen, setSourcesOpen] = useState(false)

  // Active ingest run state — driven by triggerIngest, polled until done.
  const [activeRunId, setActiveRunId] = useState<string | null>(null)
  const runQ = useNewsRun(activeRunId)
  useEffect(() => {
    if (runQ.data && (runQ.data.status === 'completed' || runQ.data.status === 'failed')) {
      // freeze on screen for 1s then clear, refresh items
      qc.invalidateQueries({ queryKey: ['news', 'items'] })
      qc.invalidateQueries({ queryKey: ['news', 'stats'] })
      const t = setTimeout(() => setActiveRunId(null), 1500)
      return () => clearTimeout(t)
    }
  }, [runQ.data, qc])

  // Deep search state
  const [topic, setTopic] = useState('')
  const [deepRefreshLLM, setDeepRefreshLLM] = useState(false)
  const [deepRunId, setDeepRunId] = useState<string | null>(null)
  const deepRunQ = useNewsRun(deepRunId)

  const filters = useMemo(() => {
    const since = maxAgeDays
      ? new Date(Date.now() - maxAgeDays * 86400_000).toISOString()
      : undefined
    // hide_statuses only applies in the 'all' view; on a single-status tab
    // the pin already restricts results.
    const hideCsv = activeStatus === 'all' && hideStatuses.size
      ? [...hideStatuses].join(',') : undefined
    return {
      status: activeStatus === 'all' ? undefined : activeStatus,
      hide_statuses: hideCsv,
      cve: cveFilter || undefined,
      kev_listed: kevOnly || undefined,
      rce: rceOnly || undefined,
      red_team_only: redTeamOnly || undefined,
      q: search || undefined,
      since,
      // Show deleted items only when explicitly tabbed-to OR when 'all'-view
      // and the hide-list does not include 'deleted'.
      include_deleted: activeStatus === 'deleted'
        || (activeStatus === 'all' && !hideStatuses.has('deleted')),
      limit: 200,
      offset: 0,
    }
  }, [activeStatus, hideStatuses, maxAgeDays, cveFilter, kevOnly, rceOnly, redTeamOnly, search])

  const itemsQ = useNewsItems(filters)
  const statsQ = useNewsStats()
  const sourcesQ = useNewsSources()
  const sources = sourcesQ.data?.results ?? []

  const items: NewsItem[] = itemsQ.data?.results ?? []

  const triggerIngest = useTriggerIngest()
  const updateItem = useUpdateNewsItem()
  const bulkAction = useBulkNewsAction()
  const matchAssets = useMatchAssets()
  const githubSearch = useGithubSearch()
  const enrichItem = useEnrichItem()
  const deepSearch = useDeepSearch()
  const updateSource = useUpdateSource()
  const refetchSource = useRefetchSource()
  const createSource = useCreateSource()

  const toggleSelect = (id: string) =>
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  const toggleSelectAll = () =>
    setSelectedIds(prev => {
      if (prev.size === items.length && items.length > 0) return new Set()
      return new Set(items.map(i => i.id))
    })
  const clearSelection = () => setSelectedIds(new Set())

  // Reset selection when filters change to avoid stale IDs
  useEffect(() => clearSelection(), [
    activeStatus, cveFilter, search, kevOnly, rceOnly, redTeamOnly,
    hideStatuses, maxAgeDays,
  ])

  const onRunIngest = async () => {
    const r = await triggerIngest.mutateAsync(undefined)
    setActiveRunId(r.run_id)
  }

  const onRunDeepSearch = async () => {
    if (!topic.trim()) return
    const r = await deepSearch.mutateAsync({
      topic: topic.trim(),
      refresh_llm: deepRefreshLLM,
      max_items: 50,
    })
    setDeepRunId(r.run_id)
  }

  const moveSelectedTo = (status: NewsStatus) =>
    bulkAction.mutate(
      { ids: [...selectedIds], action: 'set_status', value: status },
      { onSuccess: clearSelection },
    )
  const deleteSelected = () =>
    bulkAction.mutate(
      { ids: [...selectedIds], action: 'delete' },
      { onSuccess: clearSelection },
    )
  const acknowledgeSelected = () =>
    bulkAction.mutate(
      { ids: [...selectedIds], action: 'acknowledge', value: 'operator' },
      { onSuccess: clearSelection },
    )

  const stats = statsQ.data
  const lastFetched = stats?.last_fetched_at
  const ingestRunning = !!activeRunId && runQ.data?.status === 'running'
  const deepRunning = !!deepRunId && deepRunQ.data?.status === 'running'

  return (
    <div className="space-y-4">
      <PageHelp id="news" title="How to use News">
        <p>Pulls from {sources.length} security news sources, dedupes by vulnerability/CVE, and LLM-enriches each item with structured flags (CVE, KEV, RCE, easily exploitable, malware exploitable, active in-the-wild, patch available). Move items through the triage pipeline (NEW → Reviewed → Follow-up → Applies → Research → Future) and run per-item asset-match + GitHub PoC search. Use <strong>Topic Deep Search</strong> to fan out asset/PoC hunting across every story matching a free-text term (e.g. "ScreenConnect"). Daily auto-fetch — operator-triggered ingest also available.</p>
      </PageHelp>

      <div className="flex items-center gap-2">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Newspaper className="h-5 w-5" /> News Intelligence
        </h2>
      </div>

      {/* Status header tiles — "All" tile shown first so the operator can
          jump to a multi-status view; the 6 status tiles act as quick pins. */}
      <div className="grid grid-cols-4 sm:grid-cols-7 gap-2">
        {(() => {
          const isActive = activeStatus === 'all'
          // Sum visible statuses (everything except those in hideStatuses)
          const visibleTotal = stats
            ? STATUS_TABS.reduce((acc, t) => acc + (hideStatuses.has(t.id) ? 0 : (stats.by_status?.[t.id] ?? 0)), 0)
            : 0
          return (
            <button
              key="all"
              onClick={() => setActiveStatus('all')}
              className={cn(
                'rounded-lg border px-3 py-2 text-left transition',
                isActive ? 'bg-primary/15 text-primary border-primary/40' : 'bg-card border-border hover:bg-muted',
              )}
              title="Show every status not in the Hide list"
            >
              <div className="text-[10px] uppercase tracking-wide opacity-70">All</div>
              <div className="text-xl font-semibold">{visibleTotal.toLocaleString()}</div>
            </button>
          )
        })()}
        {STATUS_TABS.map(t => {
          const n = stats?.by_status?.[t.id] ?? 0
          const isActive = activeStatus === t.id
          return (
            <button
              key={t.id}
              onClick={() => setActiveStatus(t.id)}
              className={cn(
                'rounded-lg border px-3 py-2 text-left transition',
                isActive ? STATUS_COLOR[t.id] : 'bg-card border-border hover:bg-muted',
              )}
            >
              <div className="text-[10px] uppercase tracking-wide opacity-70">{t.label}</div>
              <div className="text-xl font-semibold">{n.toLocaleString()}</div>
            </button>
          )
        })}
      </div>

      {/* Action bar */}
      <div className="bg-card border border-border rounded-lg p-3 grid gap-3 lg:grid-cols-[auto_1fr_auto] items-start">
        {/* Run ingest now */}
        <div>
          <button
            onClick={onRunIngest}
            disabled={ingestRunning || triggerIngest.isPending}
            className="px-3 py-2 rounded bg-primary text-primary-foreground text-sm flex items-center gap-2 disabled:opacity-60"
          >
            {ingestRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Run ingest now
          </button>
          <div className="mt-1 text-[11px] text-muted-foreground">
            {ingestRunning && runQ.data
              ? `${runQ.data.sources_fetched}/${sources.length} sources · ${runQ.data.items_new} new · ${runQ.data.items_updated} updated · ${runQ.data.items_enriched} enriched`
              : lastFetched
                ? `Last fetched: ${new Date(lastFetched).toLocaleString()} · Daily auto-refresh`
                : 'Never fetched yet'}
          </div>
        </div>

        {/* Topic deep search */}
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <Wand2 className="h-4 w-4 text-purple-400" />
            <input
              type="text"
              value={topic}
              onChange={e => setTopic(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') onRunDeepSearch() }}
              placeholder="Topic deep search (e.g. ScreenConnect, CVE-2024-1709, MOVEit)"
              className="flex-1 bg-muted rounded px-2 py-2 text-sm outline-none border border-transparent focus:border-purple-500/40"
            />
            <label className="flex items-center gap-1 text-xs text-muted-foreground" title="Re-run LLM enrichment on matching items too">
              <input type="checkbox" checked={deepRefreshLLM} onChange={e => setDeepRefreshLLM(e.target.checked)} />
              refresh LLM
            </label>
            <button
              onClick={onRunDeepSearch}
              disabled={!topic.trim() || deepRunning}
              className="px-3 py-2 rounded bg-purple-500/20 text-purple-300 text-sm border border-purple-500/40 disabled:opacity-50 flex items-center gap-1"
            >
              {deepRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              Run deep search
            </button>
          </div>
          {deepRunQ.data && deepRunQ.data.status === 'completed' && (
            <div className="text-[11px] text-muted-foreground">
              Topic <code>{deepRunQ.data.topic}</code> — matched {deepRunQ.data.items_enriched} items.
            </div>
          )}
        </div>

        {/* Sources drawer toggle */}
        <button
          onClick={() => setSourcesOpen(s => !s)}
          className="px-3 py-2 rounded border border-border hover:bg-muted text-sm flex items-center gap-2"
        >
          <SettingsIcon className="h-4 w-4" /> Sources ({sources.length})
        </button>
      </div>

      {/* Filter bar — primary controls */}
      <div className="bg-card border border-border rounded-lg p-3 flex flex-wrap items-center gap-3">
        <button
          onClick={() => setRedTeamOnly(v => !v)}
          className={cn(
            'px-3 py-1 rounded text-sm border flex items-center gap-1.5 font-medium',
            redTeamOnly
              ? 'bg-red-500/15 text-red-300 border-red-500/40'
              : 'bg-muted border-border text-muted-foreground',
          )}
          title="Show only items the LLM flagged as KEV / RCE / easily exploitable / actively breached / malware-friendly — relevant to both pentesting and red-team workflows"
        >
          <ShieldAlert className="h-3.5 w-3.5" />
          {redTeamOnly ? 'Offensive security focus' : 'Show all (commentary too)'}
        </button>
        <div className="flex items-center gap-1 bg-muted rounded-md px-2 py-1">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="search title / summary"
            className="bg-transparent outline-none text-sm w-64"
          />
        </div>
        <input
          type="text" value={cveFilter} onChange={e => setCveFilter(e.target.value.toUpperCase())}
          placeholder="CVE-####-####"
          className="bg-muted rounded-md px-2 py-1 text-sm font-mono w-40 outline-none border border-transparent focus:border-border"
        />
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={kevOnly} onChange={e => setKevOnly(e.target.checked)} />
          KEV only
        </label>
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={rceOnly} onChange={e => setRceOnly(e.target.checked)} />
          RCE only
        </label>
        {/* Article age window */}
        <label className="flex items-center gap-1 text-sm" title="Hide items whose last-seen timestamp is older than this">
          <span className="text-muted-foreground">Last</span>
          <select
            value={maxAgeDays === null ? 'all' : String(maxAgeDays)}
            onChange={e => setMaxAgeDays(e.target.value === 'all' ? null : Number(e.target.value))}
            className="bg-muted rounded px-1.5 py-0.5 outline-none border border-transparent focus:border-border"
          >
            <option value="1">24h</option>
            <option value="7">7d</option>
            <option value="30">30d</option>
            <option value="90">90d</option>
            <option value="365">1y</option>
            <option value="all">All time</option>
          </select>
        </label>
        <span className="ml-auto text-xs text-muted-foreground">
          {itemsQ.isFetching ? 'loading…' : `${(itemsQ.data?.total ?? 0).toLocaleString()} matching`}
        </span>
      </div>

      {/* Status-hide chips — applies in addition to the active tab; default
          hides 'deleted'. Chip toggled = status excluded from the table. */}
      <div className="bg-card border border-border rounded-lg p-2 flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground pl-1">Hide:</span>
        {(['new','reviewed','follow_up','applies','research','future','deleted'] as NewsStatus[]).map(s => {
          const active = hideStatuses.has(s)
          return (
            <button
              key={s}
              onClick={() => setHideStatuses(prev => {
                const next = new Set(prev)
                if (next.has(s)) next.delete(s); else next.add(s)
                return next
              })}
              className={cn(
                'px-2 py-0.5 text-[11px] rounded border',
                active
                  ? 'bg-zinc-700/40 text-zinc-400 border-zinc-700/60 line-through'
                  : 'bg-muted border-border hover:bg-muted/70',
              )}
              title={active ? `Click to show ${s} items again` : `Click to hide ${s} items from every view`}
            >
              {s}
            </button>
          )
        })}
        {hideStatuses.size > 0 && (
          <button
            onClick={() => setHideStatuses(new Set())}
            className="text-[11px] text-muted-foreground hover:text-foreground ml-auto"
          >
            clear hide list
          </button>
        )}
      </div>

      {/* Bulk action toolbar */}
      {selectedIds.size > 0 && (
        <div className="bg-primary/10 border border-primary/30 rounded-lg p-2 flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium">{selectedIds.size} selected</span>
          <button onClick={() => moveSelectedTo('reviewed')} className="px-2 py-1 text-xs rounded border border-border bg-card hover:bg-muted">Mark Reviewed</button>
          <button onClick={() => moveSelectedTo('follow_up')} className="px-2 py-1 text-xs rounded border border-border bg-card hover:bg-muted">→ Follow-up</button>
          <button onClick={() => moveSelectedTo('applies')} className="px-2 py-1 text-xs rounded border border-border bg-card hover:bg-muted">→ Applies</button>
          <button onClick={() => moveSelectedTo('research')} className="px-2 py-1 text-xs rounded border border-border bg-card hover:bg-muted">→ Research</button>
          <button onClick={() => moveSelectedTo('future')} className="px-2 py-1 text-xs rounded border border-border bg-card hover:bg-muted">→ Future</button>
          <button onClick={acknowledgeSelected} className="px-2 py-1 text-xs rounded border border-border bg-card hover:bg-muted flex items-center gap-1"><Eye className="h-3 w-3" />Acknowledge</button>
          <button onClick={deleteSelected} className="px-2 py-1 text-xs rounded border border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20 flex items-center gap-1"><Trash2 className="h-3 w-3" />Delete</button>
          <button onClick={clearSelection} className="ml-auto px-2 py-1 text-xs text-muted-foreground hover:text-foreground">Clear</button>
        </div>
      )}

      {/* Table */}
      <div className="flex gap-4">
        <div className="flex-1 min-w-0 bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left w-8">
                  <button onClick={toggleSelectAll} className="text-muted-foreground hover:text-foreground">
                    {selectedIds.size === items.length && items.length > 0
                      ? <CheckSquare className="h-4 w-4" />
                      : <Square className="h-4 w-4" />}
                  </button>
                </th>
                <th className="px-3 py-2 text-left">Title</th>
                <th className="px-3 py-2 text-left">CVE</th>
                <th className="px-3 py-2 text-left">Flags</th>
                <th className="px-3 py-2 text-left">Sources</th>
                <th className="px-3 py-2 text-left">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && !itemsQ.isFetching && (
                <tr><td colSpan={6} className="px-3 py-8 text-center text-muted-foreground">
                  No items in <strong>{activeStatus}</strong>. Click <em>Run ingest now</em> to pull the feeds.
                </td></tr>
              )}
              {items.map(item => (
                <tr
                  key={item.id}
                  onClick={() => setOpenItemId(item.id)}
                  className={cn(
                    'border-t border-border cursor-pointer hover:bg-muted/30',
                    openItemId === item.id && 'bg-muted/50',
                    selectedIds.has(item.id) && 'bg-primary/5',
                    item.status === 'deleted' && 'opacity-60',
                  )}
                >
                  <td className="px-3 py-2 w-8" onClick={e => { e.stopPropagation(); toggleSelect(item.id) }}>
                    {selectedIds.has(item.id)
                      ? <CheckSquare className="h-4 w-4 text-primary" />
                      : <Square className="h-4 w-4 text-muted-foreground hover:text-foreground" />}
                  </td>
                  <td className="px-3 py-2 max-w-[36rem]">
                    <div className="font-medium">{item.title}</div>
                    {item.summary
                      ? <div className="text-xs text-muted-foreground mt-1 leading-relaxed line-clamp-3" title={item.summary.replace(/\s+/g, ' ').trim()}>{item.summary.replace(/\s+/g, ' ').trim()}</div>
                      : item.enriched_at
                        ? <div className="text-xs text-muted-foreground italic mt-1">no summary returned</div>
                        : <div className="text-xs text-amber-500/70 italic mt-1">enriching…</div>}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {item.primary_cve
                      ? <span className="font-mono text-amber-400">{item.primary_cve}</span>
                      : <span className="text-muted-foreground italic">UNKNOWN</span>}
                    {item.all_cves.length > 1 && (
                      <span className="ml-1 text-muted-foreground">+{item.all_cves.length - 1}</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      <FlagPill value={item.kev_listed} label="KEV" />
                      <FlagPill value={item.rce} label="RCE" />
                      <FlagPill value={item.easily_exploitable} label="Easy" />
                      <FlagPill value={item.malware_exploitable} label="Malware" />
                      <FlagPill value={item.active_internet_breach} label="ITW" />
                      <FlagPill value={item.patch_available} label="Patch" kind="good" />
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <div className="flex flex-wrap gap-1">
                      {item.articles.slice(0, 4).map((a, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded border bg-muted/50 border-border">{a.source}</span>
                      ))}
                      {item.articles.length > 4 && <span className="text-muted-foreground">+{item.articles.length - 4}</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(item.last_seen).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detail drawer */}
        {openItemId && (
          <DetailDrawer
            id={openItemId}
            onClose={() => setOpenItemId(null)}
            onMatchAssets={(id) => matchAssets.mutate(id)}
            onGithubSearch={(id) => githubSearch.mutate(id)}
            onEnrich={(id) => enrichItem.mutate(id)}
            onUpdate={(id, patch) => updateItem.mutate({ id, ...patch })}
            onDeepSearchTopic={(t) => { setTopic(t); onRunDeepSearch() }}
            busyMatch={matchAssets.isPending}
            busyGithub={githubSearch.isPending}
            busyEnrich={enrichItem.isPending}
          />
        )}
      </div>

      {/* Sources side drawer */}
      {sourcesOpen && (
        <SourcesDrawer
          sources={sources}
          onClose={() => setSourcesOpen(false)}
          onToggle={(id, enabled) => updateSource.mutate({ id, enabled })}
          onRefetch={(id) => {
            refetchSource.mutate(id, {
              onSuccess: (r) => setActiveRunId(r.run_id),
            })
          }}
          onCreate={(data) => createSource.mutate(data)}
          busy={refetchSource.isPending}
          createBusy={createSource.isPending}
        />
      )}
    </div>
  )
}


// ============================================================================
// Detail Drawer
// ============================================================================

function DetailDrawer({
  id, onClose, onMatchAssets, onGithubSearch, onEnrich, onUpdate, onDeepSearchTopic,
  busyMatch, busyGithub, busyEnrich,
}: {
  id: string
  onClose: () => void
  onMatchAssets: (id: string) => void
  onGithubSearch: (id: string) => void
  onEnrich: (id: string) => void
  onUpdate: (id: string, patch: Partial<{ status: NewsStatus; notes: string; tags: string[]; acknowledged_by: string }>) => void
  onDeepSearchTopic: (topic: string) => void
  busyMatch: boolean
  busyGithub: boolean
  busyEnrich: boolean
}) {
  const itemQ = useNewsItem(id)
  const item = itemQ.data
  const [notesDraft, setNotesDraft] = useState('')
  useEffect(() => { setNotesDraft(item?.notes ?? '') }, [item?.id])

  if (!item) {
    return (
      <div className="w-[28rem] shrink-0 bg-card border border-border rounded-lg p-4 self-start sticky top-4">
        <div className="text-xs text-muted-foreground">loading…</div>
      </div>
    )
  }

  const acked = !!item.acknowledged_by

  return (
    <div className="w-[30rem] shrink-0 bg-card border border-border rounded-lg p-4 self-start sticky top-4 space-y-3 max-h-[calc(100vh-6rem)] overflow-y-auto">
      <div className="flex items-start justify-between">
        <h3 className="text-sm font-semibold pr-2">{item.title}</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
      </div>

      <div className="flex flex-wrap gap-1">
        {item.primary_cve && <span className="px-1.5 py-0.5 text-[10px] rounded border bg-amber-500/15 text-amber-400 border-amber-500/30 font-mono">{item.primary_cve}</span>}
        <FlagPill value={item.kev_listed} label="KEV" />
        <FlagPill value={item.rce} label="RCE" />
        <FlagPill value={item.easily_exploitable} label="Easy" />
        <FlagPill value={item.malware_exploitable} label="Malware" />
        <FlagPill value={item.active_internet_breach} label="ITW" />
        <FlagPill value={item.patch_available} label="Patch" kind="good" />
      </div>

      {item.summary && (
        <div className="text-xs leading-relaxed bg-muted/30 rounded p-2">{item.summary.replace(/\s+/g, ' ').trim()}</div>
      )}

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <div className="text-muted-foreground mb-0.5">Status</div>
          <select
            value={item.status}
            onChange={e => onUpdate(item.id, { status: e.target.value as NewsStatus })}
            className="w-full bg-muted rounded px-1.5 py-1 outline-none border border-transparent focus:border-border"
          >
            {(['new','reviewed','follow_up','applies','research','future','deleted'] as NewsStatus[])
              .map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div>
          <div className="text-muted-foreground mb-0.5">Acknowledged</div>
          <button
            onClick={() => onUpdate(item.id, {
              acknowledged_by: acked ? '' : 'operator',
            })}
            className={cn(
              'w-full text-left px-2 py-1 rounded border',
              acked
                ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                : 'bg-muted border-border',
            )}
          >
            {acked
              ? `${item.acknowledged_by} · ${item.acknowledged_at ? new Date(item.acknowledged_at).toLocaleDateString() : ''}`
              : 'mark seen'}
          </button>
        </div>
      </div>

      {/* Action buttons */}
      <div className="grid grid-cols-3 gap-2">
        <button
          onClick={() => onMatchAssets(item.id)}
          disabled={busyMatch}
          className="text-xs px-2 py-1 rounded border border-border hover:bg-muted flex items-center justify-center gap-1 disabled:opacity-50"
        >
          {busyMatch ? <Loader2 className="h-3 w-3 animate-spin" /> : <Server className="h-3 w-3" />}
          Match assets
        </button>
        <button
          onClick={() => onGithubSearch(item.id)}
          disabled={busyGithub}
          className="text-xs px-2 py-1 rounded border border-border hover:bg-muted flex items-center justify-center gap-1 disabled:opacity-50"
        >
          {busyGithub ? <Loader2 className="h-3 w-3 animate-spin" /> : <Github className="h-3 w-3" />}
          GitHub PoCs
        </button>
        <button
          onClick={() => onEnrich(item.id)}
          disabled={busyEnrich}
          className="text-xs px-2 py-1 rounded border border-border hover:bg-muted flex items-center justify-center gap-1 disabled:opacity-50"
        >
          {busyEnrich ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
          Re-enrich
        </button>
      </div>

      {/* Re-run deep search on this topic */}
      <button
        onClick={() => onDeepSearchTopic(item.primary_cve || item.title.split(' ').slice(0, 4).join(' '))}
        className="w-full text-xs px-2 py-1 rounded border border-purple-500/40 bg-purple-500/10 text-purple-300 hover:bg-purple-500/20 flex items-center justify-center gap-1"
      >
        <Wand2 className="h-3 w-3" /> Re-run deep search on this topic
      </button>

      {/* Articles */}
      <div>
        <div className="text-muted-foreground text-xs mb-1">Articles ({item.articles.length})</div>
        <ul className="space-y-1 text-xs">
          {item.articles.map((a, i) => (
            <li key={i} className="border border-border rounded px-2 py-1">
              <a href={a.link} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline flex items-center gap-1">
                <ExternalLink className="h-3 w-3 shrink-0" />
                <span className="truncate">{a.title}</span>
              </a>
              <div className="text-[10px] text-muted-foreground">{a.source}{a.published ? ` · ${a.published}` : ''}</div>
            </li>
          ))}
        </ul>
      </div>

      {/* Asset matches */}
      <div>
        <div className="text-muted-foreground text-xs mb-1 flex items-center gap-1">
          <Server className="h-3 w-3" /> Asset matches ({item.asset_matches.length})
        </div>
        {item.asset_matches.length === 0 ? (
          <div className="text-xs text-muted-foreground italic">none yet — click <em>Match assets</em></div>
        ) : (
          <ul className="space-y-1 text-xs">
            {item.asset_matches.slice(0, 20).map((m, i) => (
              <li key={i} className="border border-border rounded px-2 py-1">
                <span className="font-mono text-amber-400">{m.cve}</span>
                <span className="ml-2">{m.hostname || m.ip}</span>
                {m.severity && <span className="ml-1 text-muted-foreground">({m.severity})</span>}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* GitHub repos */}
      <div>
        <div className="text-muted-foreground text-xs mb-1 flex items-center gap-1">
          <Github className="h-3 w-3" /> GitHub PoC repos ({item.github_links.length})
        </div>
        {item.github_links.length === 0 ? (
          <div className="text-xs text-muted-foreground italic">none yet — click <em>GitHub PoCs</em></div>
        ) : (
          <ul className="space-y-1 text-xs">
            {item.github_links.slice(0, 15).map((g, i) => (
              <li key={i} className="border border-border rounded px-2 py-1">
                <a href={g.url} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline flex items-center gap-1">
                  <ExternalLink className="h-3 w-3 shrink-0" />
                  <span className="truncate">{g.repo}</span>
                </a>
                <div className="text-[10px] text-muted-foreground">★ {g.stars}{g.language ? ` · ${g.language}` : ''}</div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Notes */}
      <div>
        <div className="text-muted-foreground text-xs mb-1">Notes</div>
        <textarea
          value={notesDraft}
          onChange={e => setNotesDraft(e.target.value)}
          onBlur={() => { if (notesDraft !== item.notes) onUpdate(item.id, { notes: notesDraft }) }}
          rows={3}
          className="w-full bg-muted rounded px-2 py-1 text-xs outline-none border border-transparent focus:border-border"
          placeholder="triage notes…"
        />
      </div>
    </div>
  )
}


// ============================================================================
// Sources Drawer
// ============================================================================

function SourcesDrawer({
  sources, onClose, onToggle, onRefetch, onCreate, busy, createBusy,
}: {
  sources: NewsSource[]
  onClose: () => void
  onToggle: (id: string, enabled: boolean) => void
  onRefetch: (id: string) => void
  onCreate: (data: { name: string; url: string; parser?: string; enabled?: boolean }) => void
  busy: boolean
  createBusy: boolean
}) {
  const [showAddForm, setShowAddForm] = useState(false)
  const [newSource, setNewSource] = useState<{
    name: string
    url: string
    parser: 'rss' | 'atom' | 'html'
    enabled: boolean
  }>({
    name: '',
    url: '',
    parser: 'rss',
    enabled: true,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!newSource.name.trim() || !newSource.url.trim()) return
    onCreate(newSource)
    setNewSource({ name: '', url: '', parser: 'rss', enabled: true })
    setShowAddForm(false)
  }
  return (
    <div className="fixed top-0 right-0 bottom-0 w-[28rem] bg-card border-l border-border z-30 p-4 overflow-y-auto shadow-2xl">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Globe className="h-4 w-4" /> News Sources
        </h3>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs"
          >
            <Plus className="h-4 w-4" />
            Add Source
          </button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
        </div>
      </div>

      {/* Add new source form */}
      {showAddForm && (
        <form onSubmit={handleSubmit} className="mb-4 p-3 border border-border rounded bg-muted/10">
          <h4 className="text-sm font-medium mb-2">Add News Source</h4>
          <div className="space-y-2">
            <div>
              <label className="block text-xs text-muted-foreground mb-1">Name</label>
              <input
                type="text"
                value={newSource.name}
                onChange={(e) => setNewSource(prev => ({ ...prev, name: e.target.value }))}
                placeholder="Source name"
                className="w-full px-2 py-1 text-xs border border-border rounded bg-background"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">URL</label>
              <input
                type="url"
                value={newSource.url}
                onChange={(e) => setNewSource(prev => ({ ...prev, url: e.target.value }))}
                placeholder="https://example.com/feed/"
                className="w-full px-2 py-1 text-xs border border-border rounded bg-background"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-muted-foreground mb-1">Parser</label>
              <select
                value={newSource.parser}
                onChange={(e) => setNewSource(prev => ({ ...prev, parser: e.target.value as 'rss' | 'atom' | 'html' }))}
                className="w-full px-2 py-1 text-xs border border-border rounded bg-background"
              >
                <option value="rss">RSS</option>
                <option value="atom">Atom</option>
                <option value="html">HTML</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="enabled"
                checked={newSource.enabled}
                onChange={(e) => setNewSource(prev => ({ ...prev, enabled: e.target.checked }))}
                className="text-xs"
              />
              <label htmlFor="enabled" className="text-xs text-muted-foreground">Enabled</label>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-3">
            <button
              type="submit"
              disabled={createBusy || !newSource.name.trim() || !newSource.url.trim()}
              className="px-3 py-1 text-xs bg-primary text-primary-foreground rounded disabled:opacity-50 flex items-center gap-1"
            >
              {createBusy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
              Add Source
            </button>
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="px-3 py-1 text-xs border border-border rounded hover:bg-muted"
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      <ul className="space-y-2">
        {sources.map(s => (
          <li key={s.id} className="border border-border rounded p-2 text-xs">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <div className="font-medium">{s.name}</div>
                <div className="text-[10px] text-muted-foreground truncate">{s.url}</div>
              </div>
              <label className="flex items-center gap-1 shrink-0">
                <input
                  type="checkbox" checked={s.enabled}
                  onChange={e => onToggle(s.id, e.target.checked)}
                />
              </label>
            </div>
            <div className="mt-1 flex items-center justify-between gap-2">
              <div className="text-[10px] text-muted-foreground">
                {s.last_fetched_at
                  ? `${s.last_status === 'ok' ? '✓' : '⚠'} ${new Date(s.last_fetched_at).toLocaleString()}`
                  : 'never fetched'}
              </div>
              <button
                onClick={() => onRefetch(s.id)}
                disabled={busy || !s.enabled}
                className="px-2 py-0.5 text-[10px] rounded border border-border hover:bg-muted disabled:opacity-50 flex items-center gap-1"
              >
                {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                Refetch
              </button>
            </div>
            {s.last_error && <div className="mt-1 text-[10px] text-red-400">{s.last_error}</div>}
          </li>
        ))}
      </ul>
    </div>
  )
}
