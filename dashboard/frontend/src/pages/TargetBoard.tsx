/**
 * Target Board — a per-target triage view that combines, side by side, the
 * three workflow surfaces that are otherwise on separate pages:
 *
 *   [ Attack vectors ] [ Follow-ups ] [ Recommendations ]
 *
 * One swimlane (row) per target host. The join key across all three data
 * sources is the bare host (see hostOf): attack vectors are host→technique,
 * follow-ups carry a target, recommendations carry an ip. Each card links out
 * to the full page for that host, reusing the deep-link contract the Attack
 * Map established (?ip= / ?search=).
 *
 * Read-only aggregation over already-fetched data — no new API.
 */
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { LayoutGrid, Crosshair, Flag, Lightbulb, Search, ExternalLink, Globe, Plus, Check, Ban } from 'lucide-react'
import { useAttackVectors, type AttackVector } from '@/api/attackVectors'
import { useFollowUps, type FollowUpItem } from '@/api/followups'
import { useScanRecommendations, type StoredRecommendation } from '@/api/assets'
import { ScopeFilter } from '@/components/common/ScopeFilter'
import { useScopeNames, useAddToScope, useExcludeFromScope, useExcludedTargets } from '@/api/scope'
import { useAddScopeTargets } from '@/api/engagements'
import { useScopeFilter } from '@/hooks/useScopeFilter'
import { useUIStore } from '@/stores/ui'
import PageHelp from '@/components/PageHelp'
import InfoTip from '@/components/InfoTip'

type SortKey = 'risk' | 'followups' | 'recommendations'

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-600', high: 'bg-orange-500', medium: 'bg-yellow-400',
  low: 'bg-blue-500', info: 'bg-gray-500',
}

function riskColor(risk: number): string {
  const r = Math.max(0, Math.min(100, risk)) / 100
  return `hsl(${(1 - r) * 120}, 70%, 45%)`
}

// Bare host/IP — strips scheme/path/port so the three sources bucket together.
function hostOf(target?: string | null): string {
  if (!target) return ''
  try { return new URL(target).hostname } catch { /* not a URL */ }
  return target.split('/')[0].split(':')[0]
}

function middleTruncate(s: string, max = 42): string {
  if (!s || s.length <= max) return s
  const head = Math.ceil((max - 1) * 0.45)
  return `${s.slice(0, head)}…${s.slice(s.length - (max - 1 - head))}`
}

interface TargetRow {
  host: string
  vectors: AttackVector[]
  followups: FollowUpItem[]
  recommendations: StoredRecommendation[]
  maxRisk: number
}

export default function TargetBoard() {
  // Engagement isolation: the active engagement scopes all three data sources.
  //  - attack vectors: rag-api filters by the explicit engagement_id param.
  //  - follow-ups:     rag-api filters by the explicit engagement_id param.
  //  - recommendations: scan_recommender filters by the X-Engagement-Id header.
  // Passing the id also varies each hook's React Query key so switching the
  // engagement in the TopBar refetches immediately instead of showing stale rows.
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const globalScope = useUIStore(s => s.selectedScopeName)

  // Scope filter: defaults to the engagement's global scope, mirrors the
  // AssetBrowser / FindingsExplorer pattern. matchesScope(host) restricts the
  // swimlanes to hosts inside the selected scope; "" means All Scopes.
  const [scopeFilter, setScopeFilter] = useState(globalScope || '')
  const { matchesScope, isFiltering: isScopeFiltering } = useScopeFilter(scopeFilter)
  // Reset the scope filter whenever the engagement OR its global scope changes.
  // engagementId MUST be a dependency: scope names are per-engagement, so a scope
  // selected under one engagement (e.g. jabil's "main_jabil") is meaningless under
  // another (home_scan's scopes are "msf"). Without this, switching engagements
  // left a stale cross-engagement scope selected — the dropdown showed the wrong
  // engagement's scope and matchesScope filtered against a non-existent target set.
  // (selectedScopeName is empty for engagements with no default scope, so watching
  // globalScope alone never fires on an engagement switch.)
  useEffect(() => { setScopeFilter(globalScope || '') }, [globalScope, engagementId])

  const { data: avData, isLoading: avLoading } = useAttackVectors(0, 100, engagementId)
  // Open follow-ups only (exclude dismissed) — the actionable set.
  const { data: fuData, isLoading: fuLoading } = useFollowUps({
    exclude_status: 'dismissed',
    engagement_id: engagementId ?? undefined,
  })
  const { data: recData, isLoading: recLoading } = useScanRecommendations('pending', engagementId)

  // Out-of-scope set: hosts the operator marked as "should not be in scope".
  // These are dropped from the board so noise (e.g. third-party www.owasp.org)
  // disappears the moment it's excluded.
  const { data: excludedData } = useExcludedTargets()
  const excludedSet = useMemo(
    () => new Set((excludedData?.targets || []).map(t => t.target.toLowerCase().trim())),
    [excludedData],
  )

  const [sortBy, setSortBy] = useState<SortKey>('risk')
  const [hostSearch, setHostSearch] = useState('')

  const isLoading = avLoading || fuLoading || recLoading

  const rows = useMemo<TargetRow[]>(() => {
    const map = new Map<string, TargetRow>()
    const get = (host: string): TargetRow => {
      let r = map.get(host)
      if (!r) { r = { host, vectors: [], followups: [], recommendations: [], maxRisk: 0 }; map.set(host, r) }
      return r
    }
    for (const v of avData?.vectors || []) {
      const r = get(hostOf(v.target) || 'unknown')
      r.vectors.push(v)
      r.maxRisk = Math.max(r.maxRisk, v.risk_score || 0)
    }
    for (const f of fuData?.follow_ups || []) {
      get(hostOf(f.target) || 'unknown').followups.push(f)
    }
    for (const rec of recData?.recommendations || []) {
      get(hostOf(rec.ip) || 'unknown').recommendations.push(rec)
    }
    // Sort each column's items by its natural priority.
    for (const r of map.values()) {
      r.vectors.sort((a, b) => b.risk_score - a.risk_score)
      r.followups.sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0))
      r.recommendations.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0))
    }
    return [...map.values()]
  }, [avData, fuData, recData])

  const displayRows = useMemo(() => {
    let list = rows
    // Drop hosts marked out-of-scope, regardless of scope/engagement selection.
    if (excludedSet.size) list = list.filter((r) => !excludedSet.has(r.host.toLowerCase().trim()))
    // Scope gate: when a scope is selected, drop hosts outside it. The
    // 'unknown' bucket (rows with no resolvable host) can never match a scope,
    // so it is hidden while filtering.
    if (isScopeFiltering) list = list.filter((r) => r.host !== 'unknown' && matchesScope(r.host))
    const q = hostSearch.trim().toLowerCase()
    if (q) list = list.filter((r) => r.host.toLowerCase().includes(q))
    return [...list].sort((a, b) => {
      if (sortBy === 'followups') return b.followups.length - a.followups.length
      if (sortBy === 'recommendations') return b.recommendations.length - a.recommendations.length
      return b.maxRisk - a.maxRisk
    })
  }, [rows, hostSearch, sortBy, isScopeFiltering, matchesScope, excludedSet])

  return (
    <div className="p-4 space-y-4">
      <PageHelp id="target-board" title="How to use the Target Board">
        <p>One row per <strong>target host</strong>, with its <strong>attack vectors</strong>,
        open <strong>follow-ups</strong>, and pending scan <strong>recommendations</strong> side by
        side — the "what's the risk / what do I owe / what should I run next" view for each host.
        Rows sort by highest attack-vector risk by default. Every card links out to the full page
        for that host. Data combines the Attack Map, Follow-Ups, and Recommendations sources.</p>
      </PageHelp>

      <div className="flex items-center gap-2 flex-wrap">
        <LayoutGrid className="h-4 w-4 text-primary" />
        <h2 className="text-base font-semibold">Target Board</h2>
        <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono text-muted-foreground">
          {displayRows.length}{displayRows.length !== rows.length ? ` / ${rows.length}` : ''} targets
          {isScopeFiltering ? ` in ${scopeFilter}` : ''}
        </span>
        <InfoTip side="bottom" text="Combines attack vectors, open follow-ups, and pending recommendations per host, scoped to the active engagement and scope. Cards link out to the full pages, filtered to that host." />

        <div className="ml-auto flex items-center gap-2">
          <ScopeFilter value={scopeFilter} onChange={setScopeFilter} />
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              value={hostSearch}
              onChange={(e) => setHostSearch(e.target.value)}
              placeholder="Filter hosts…"
              className="pl-7 pr-2 py-1 text-xs rounded border border-border bg-card w-40 focus:outline-none focus:border-primary"
            />
          </div>
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-muted-foreground">Sort</span>
            {([['risk', 'Risk'], ['followups', 'Follow-ups'], ['recommendations', 'Recs']] as [SortKey, string][]).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setSortBy(key)}
                className={`px-1.5 py-0.5 rounded text-[10px] border transition-colors ${
                  sortBy === key ? 'border-primary bg-primary/15 text-primary' : 'border-border bg-muted/40 text-muted-foreground hover:border-primary/50'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading…</div>
      ) : displayRows.length === 0 ? (
        <div className="text-sm text-muted-foreground border border-border rounded-lg p-6 text-center">
          No targets to show. Run scans and click Recompute on the Attack Map, or check Follow-Ups / Recommendations.
        </div>
      ) : (
        <div className="space-y-3">
          {displayRows.map((row) => (
            <TargetSwimlane key={row.host} row={row} />
          ))}
        </div>
      )}
    </div>
  )
}

function TargetSwimlane({ row }: { row: TargetRow }) {
  const q = encodeURIComponent(row.host === 'unknown' ? '' : row.host)
  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      {/* Host header */}
      <div className="flex items-center gap-2 px-3 py-2 bg-muted/40 border-b border-border">
        <span className="font-mono text-sm text-foreground truncate" title={row.host}>{row.host}</span>
        {row.maxRisk > 0 && (
          <span className="font-mono px-1.5 py-0.5 rounded text-white text-[10px]" style={{ background: riskColor(row.maxRisk) }}>
            risk {row.maxRisk}
          </span>
        )}
        <span className="ml-auto flex items-center gap-3 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1"><Crosshair className="h-3 w-3 text-red-400" />{row.vectors.length}</span>
          <span className="flex items-center gap-1"><Flag className="h-3 w-3 text-amber-400" />{row.followups.length}</span>
          <span className="flex items-center gap-1"><Lightbulb className="h-3 w-3 text-cyan-400" />{row.recommendations.length}</span>
        </span>
        <AssignScopeControl host={row.host} />
      </div>

      {/* Three columns */}
      <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-border">
        <BoardColumn
          icon={Crosshair} iconColor="text-red-400" title="Attack vectors" count={row.vectors.length}
          to={`/attack-map`} emptyText="No attack vectors"
        >
          {row.vectors.slice(0, 6).map((v, i) => (
            <Link key={i} to={`/findings?ip=${q}`} className="block rounded border border-border bg-muted/30 hover:bg-muted/60 hover:border-primary/50 p-1.5 transition-colors">
              <div className="flex items-center gap-1.5">
                <span className="font-mono px-1 py-0.5 rounded text-white text-[10px]" style={{ background: riskColor(v.risk_score) }}>{v.risk_score}</span>
                <span className="font-mono text-[11px] text-foreground">{v.technique}</span>
                {v.severity && <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[v.severity] || 'bg-gray-500'}`} />}
                <span className="ml-auto text-[10px] text-muted-foreground">{v.finding_count ?? 0}×</span>
              </div>
              <div className="text-[10px] text-muted-foreground truncate">{v.technique_name}</div>
            </Link>
          ))}
        </BoardColumn>

        <BoardColumn
          icon={Flag} iconColor="text-amber-400" title="Follow-ups" count={row.followups.length}
          to={`/follow-ups?search=${q}`} emptyText="No open follow-ups"
        >
          {row.followups.slice(0, 6).map((f) => (
            <Link key={f.id} to={`/follow-ups?search=${q}`} className="block rounded border border-border bg-muted/30 hover:bg-muted/60 hover:border-primary/50 p-1.5 transition-colors">
              <div className="flex items-center gap-1.5">
                <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${SEV_DOT[f.severity] || 'bg-gray-500'}`} />
                <span className="text-[11px] text-foreground truncate">{middleTruncate(f.title)}</span>
              </div>
              <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground capitalize">
                <span>{f.status}</span>·<span>{f.priority} pri</span>
              </div>
            </Link>
          ))}
        </BoardColumn>

        <BoardColumn
          icon={Lightbulb} iconColor="text-cyan-400" title="Recommendations" count={row.recommendations.length}
          to={`/recommendations?ip=${q}`} emptyText="No pending recommendations"
        >
          {row.recommendations.slice(0, 6).map((rec) => (
            <Link key={rec.id} to={`/recommendations?ip=${q}`} className="block rounded border border-border bg-muted/30 hover:bg-muted/60 hover:border-primary/50 p-1.5 transition-colors">
              <div className="flex items-center gap-1.5">
                <span className="font-mono text-[11px] text-foreground">{rec.scanner}</span>
                {rec.service && <span className="text-[10px] text-muted-foreground">{rec.service}</span>}
              </div>
              {(rec.action || rec.template || rec.script) && (
                <div className="text-[10px] text-muted-foreground truncate">{rec.action || rec.template || rec.script}</div>
              )}
            </Link>
          ))}
        </BoardColumn>
      </div>
    </div>
  )
}

function BoardColumn({
  icon: Icon, iconColor, title, count, to, emptyText, children,
}: {
  icon: typeof Crosshair; iconColor: string; title: string; count: number
  to: string; emptyText: string; children: React.ReactNode
}) {
  const hasItems = count > 0
  return (
    <div className="p-2 space-y-1.5 min-w-0">
      <div className="flex items-center gap-1.5 text-[11px] font-semibold text-foreground">
        <Icon className={`h-3.5 w-3.5 ${iconColor}`} />
        {title}
        <span className="text-[10px] text-muted-foreground">({count})</span>
        {hasItems && (
          <Link to={to} className="ml-auto text-[10px] text-primary hover:underline flex items-center gap-0.5" title={`Open ${title} for this host`}>
            open <ExternalLink className="h-2.5 w-2.5" />
          </Link>
        )}
      </div>
      {hasItems ? children : <div className="text-[10px] text-muted-foreground/70 italic">{emptyText}</div>}
      {count > 6 && (
        <Link to={to} className="block text-[10px] text-primary hover:underline">+{count - 6} more…</Link>
      )}
    </div>
  )
}

// Bare-IPv4 test — decides the target_type when assigning to a *global* scope
// (the engagement-scoped endpoint infers type server-side, so it's only needed
// on the no-engagement path).
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/

/**
 * Inline "assign this host to a scope" control shown in each swimlane header.
 * Picks the right backend per context, matching the rest of the app:
 *   - engagement active → POST /engagements/{eid}/scopes/{name}/targets
 *   - no engagement     → POST /scope/add (global scope list)
 * The scope list comes from useScopeNames (already engagement-aware), and a
 * free-text box lets the operator create-and-assign a brand-new scope in one
 * step. Assigning invalidates the scope-targets cache, so the Scope filter and
 * matchesScope() pick up the new membership immediately.
 */
function AssignScopeControl({ host }: { host: string }) {
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const { data: scopeData } = useScopeNames()
  const scopes = scopeData?.names ?? []
  const addToScope = useAddToScope()
  const addEngTargets = useAddScopeTargets()
  const excludeFromScope = useExcludeFromScope()

  const [open, setOpen] = useState(false)
  const [newScope, setNewScope] = useState('')
  const [assignedTo, setAssignedTo] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const disabled = !host || host === 'unknown'
  const saving = addToScope.isPending || addEngTargets.isPending || excludeFromScope.isPending

  function markOutOfScope() {
    if (disabled) return
    setError(null)
    excludeFromScope.mutate(
      { targets: [host], source: 'target-board' },
      {
        // The host vanishes from the board once the excluded list refetches
        // (useExcludedTargets is invalidated by the mutation).
        onSuccess: () => setOpen(false),
        onError: (e: unknown) => setError(e instanceof Error ? e.message : 'Failed to exclude'),
      },
    )
  }

  function assign(scopeName: string) {
    const name = scopeName.trim()
    if (!name || disabled) return
    setError(null)
    const onSuccess = () => {
      setAssignedTo(name)
      setNewScope('')
      setOpen(false)
    }
    const onError = (e: unknown) => setError(e instanceof Error ? e.message : 'Failed to assign')
    if (engagementId) {
      addEngTargets.mutate(
        { eid: engagementId, scopeName: name, targets: [host], source: 'target-board' },
        { onSuccess, onError },
      )
    } else {
      const target_type = IPV4_RE.test(host) ? 'ip' : 'domain'
      addToScope.mutate(
        { name, targets: [{ target: host, target_type, source: 'target-board' }] },
        { onSuccess, onError },
      )
    }
  }

  if (disabled) return null

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] border transition-colors ${
          assignedTo
            ? 'border-green-600/50 bg-green-600/15 text-green-500'
            : 'border-border bg-muted/40 text-muted-foreground hover:border-primary/50 hover:text-foreground'
        }`}
        title={assignedTo ? `Added to scope "${assignedTo}"` : 'Assign this host to a scope'}
      >
        {assignedTo ? <Check className="h-3 w-3" /> : <Globe className="h-3 w-3" />}
        {assignedTo ? assignedTo : 'scope'}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 z-20 w-52 rounded-lg border border-border bg-card shadow-lg p-2 space-y-1.5">
          <div className="text-[10px] font-semibold text-muted-foreground px-1">
            Add <span className="font-mono text-foreground">{host}</span> to scope
          </div>
          {scopes.length > 0 && (
            <div className="max-h-40 overflow-auto space-y-0.5">
              {scopes.map(s => (
                <button
                  key={s.name}
                  type="button"
                  disabled={saving}
                  onClick={() => assign(s.name)}
                  className="w-full flex items-center justify-between gap-2 px-1.5 py-1 rounded text-[11px] text-left hover:bg-muted/60 disabled:opacity-50"
                >
                  <span className="truncate">{s.name}</span>
                  <span className="text-[9px] text-muted-foreground shrink-0">{s.target_count}</span>
                </button>
              ))}
            </div>
          )}
          <form
            onSubmit={(e) => { e.preventDefault(); assign(newScope) }}
            className="flex items-center gap-1 border-t border-border pt-1.5"
          >
            <input
              value={newScope}
              onChange={(e) => setNewScope(e.target.value)}
              placeholder="New scope…"
              className="flex-1 min-w-0 px-1.5 py-1 text-[11px] rounded border border-border bg-background focus:outline-none focus:border-primary"
            />
            <button
              type="submit"
              disabled={saving || !newScope.trim()}
              className="flex items-center gap-0.5 px-1.5 py-1 rounded text-[10px] border border-primary bg-primary/15 text-primary hover:bg-primary/25 disabled:opacity-50"
            >
              <Plus className="h-3 w-3" /> add
            </button>
          </form>
          {error && <div className="text-[10px] text-red-500 px-1">{error}</div>}
          {!engagementId && (
            <div className="text-[9px] text-muted-foreground/70 px-1">Adds to the global scope list (no engagement selected).</div>
          )}
          <button
            type="button"
            disabled={saving}
            onClick={markOutOfScope}
            className="w-full flex items-center gap-1 px-1.5 py-1 rounded text-[10px] border border-red-600/40 bg-red-600/10 text-red-500 hover:bg-red-600/20 disabled:opacity-50 border-t"
            title="Mark this host as out of scope — it won't be shown on the board"
          >
            <Ban className="h-3 w-3" /> Mark out of scope
          </button>
        </div>
      )}
    </div>
  )
}
