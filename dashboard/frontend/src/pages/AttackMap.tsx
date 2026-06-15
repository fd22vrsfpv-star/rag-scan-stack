import { useMemo, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import ReactFlow, {
  Background, Controls, MiniMap, ReactFlowProvider, useReactFlow,
  type Node, type Edge,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { Crosshair, RefreshCw, Loader2, Bug, Flag, Lightbulb, Zap, ExternalLink } from 'lucide-react'
import { useAttackVectors, useAttackGraph, useComputeAttackVectors, type AttackVector } from '@/api/attackVectors'
import PageHelp from '@/components/PageHelp'
import InfoTip from '@/components/InfoTip'

type SortKey = 'risk' | 'findings' | 'severity'

// Severity rank for sorting/ordering (high → low). Unknown sorts last.
const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-600', high: 'bg-orange-500', medium: 'bg-yellow-400',
  low: 'bg-blue-500', info: 'bg-gray-500',
}

// Risk 0..100 → green→amber→red.
function riskColor(risk: number): string {
  const r = Math.max(0, Math.min(100, risk)) / 100
  const hue = (1 - r) * 120 // 120=green .. 0=red
  return `hsl(${hue}, 70%, 45%)`
}

const COL_X: Record<string, number> = { target: 20, technique: 380, tactic: 760 }

// Shorten the MIDDLE so both the host and the distinguishing tail (e.g. the
// URL path …/vulnerabilities/sqli) stay visible.
function middleTruncate(s: string, max = 52): string {
  if (!s || s.length <= max) return s
  const head = Math.ceil((max - 1) * 0.45)
  const tail = max - 1 - head
  return `${s.slice(0, head)}…${s.slice(s.length - tail)}`
}

// The graph node ids a ranked vector maps to (see attack_vectors.get_graph).
function vectorNodeIds(v: AttackVector): { target: string; technique: string; tactic: string } {
  return {
    target: `target:${v.target || 'unknown'}`,
    technique: `technique:${v.technique}`,
    tactic: `tactic:${v.tactic || 'unknown'}`,
  }
}

// Stable identity for a ranked vector row (target+technique is unique per row).
function vectorKey(v: AttackVector): string {
  return `${v.target || 'unknown'}||${v.technique}`
}

// The bare host/IP for cross-page filtering — strips scheme/path/port off a URL
// target so it matches the host key the other explorers filter on.
function hostOf(target?: string): string {
  if (!target) return ''
  try { return new URL(target).hostname } catch { /* not a URL */ }
  return target.split('/')[0].split(':')[0]
}

// Deep links from a selected vector to the workflow pages that hold its related
// records. Keyed on host (the common filter across Findings/Recs/Exploits) plus
// a text search for Follow-ups (which has no host filter, only free-text).
function LinkedRecords({ vector }: { vector: AttackVector }) {
  const host = hostOf(vector.target)
  const q = encodeURIComponent(host)
  const links = [
    { to: `/findings?ip=${q}`, icon: Bug, label: 'Findings', count: vector.finding_count, color: 'text-red-400' },
    { to: `/follow-ups?search=${q}`, icon: Flag, label: 'Follow-ups', color: 'text-amber-400' },
    { to: `/recommendations?ip=${q}`, icon: Lightbulb, label: 'Recommendations', color: 'text-cyan-400' },
    { to: `/exploits?ip=${q}`, icon: Zap, label: 'Exploits', color: 'text-fuchsia-400' },
  ]
  return (
    <div className="mb-3 rounded-lg border border-primary/40 bg-primary/5 p-2.5">
      <div className="text-[11px] font-semibold text-foreground mb-1.5 flex items-center gap-1.5">
        <span className="font-mono text-primary">{vector.technique}</span>
        <span className="text-muted-foreground">{vector.technique_name}</span>
      </div>
      <div className="text-[10px] text-muted-foreground/80 font-mono mb-2 truncate" title={vector.target}>
        {host || vector.target || 'unknown target'}
      </div>
      <div className="grid grid-cols-2 gap-1.5">
        {links.map(({ to, icon: Icon, label, count, color }) => (
          <Link
            key={label}
            to={to}
            className="flex items-center gap-1.5 px-2 py-1.5 rounded border border-border bg-card hover:border-primary/60 hover:bg-muted/60 text-[11px] transition-colors group"
          >
            <Icon className={`h-3.5 w-3.5 ${color}`} />
            <span className="text-foreground">{label}</span>
            {count != null && count > 0 && (
              <span className="text-[10px] text-muted-foreground">×{count}</span>
            )}
            <ExternalLink className="h-3 w-3 ml-auto text-muted-foreground/50 group-hover:text-primary" />
          </Link>
        ))}
      </div>
      <div className="text-[10px] text-muted-foreground/70 mt-1.5">
        Opens each workflow page filtered to <span className="font-mono">{host || 'this target'}</span>.
      </div>
    </div>
  )
}

function AttackMapInner() {
  const { data: graph, isLoading } = useAttackGraph()
  const { data: ranked } = useAttackVectors(0, 100)
  const compute = useComputeAttackVectors()
  const rf = useReactFlow()

  // The currently-selected ranked vector (its key), and the node ids of its path.
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [selectedVector, setSelectedVector] = useState<AttackVector | null>(null)
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(new Set())

  // Ranked-list controls: sort key, hide vectors with no findings, severity filter.
  const [sortBy, setSortBy] = useState<SortKey>('risk')
  const [hideEmpty, setHideEmpty] = useState(false)
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set())

  const allVectors = ranked?.vectors || []

  // After the "has findings" filter (but before the severity filter) — the basis
  // for the severity chip counts, so toggling a severity doesn't shift the counts.
  const baseVectors = useMemo(
    () => (hideEmpty ? allVectors.filter((v) => (v.finding_count ?? 0) > 0) : allVectors),
    [allVectors, hideEmpty],
  )

  // Severity → count over baseVectors. Only severities with >0 get a chip, so a
  // severity with zero matches is simply not offered as a filter.
  const sevCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const v of baseVectors) {
      const s = v.severity || 'unknown'
      m[s] = (m[s] || 0) + 1
    }
    return m
  }, [baseVectors])

  // The list actually rendered: severity-filtered then sorted by the active key.
  const displayVectors = useMemo(() => {
    let list = baseVectors
    if (sevFilter.size) list = list.filter((v) => sevFilter.has(v.severity || 'unknown'))
    const sorted = [...list].sort((a, b) => {
      if (sortBy === 'findings') return (b.finding_count ?? 0) - (a.finding_count ?? 0)
      if (sortBy === 'severity') {
        const d = (SEV_RANK[b.severity || ''] ?? 0) - (SEV_RANK[a.severity || ''] ?? 0)
        return d !== 0 ? d : b.risk_score - a.risk_score
      }
      return b.risk_score - a.risk_score
    })
    return sorted
  }, [baseVectors, sevFilter, sortBy])

  const toggleSeverity = useCallback((sev: string) => {
    setSevFilter((prev) => {
      const next = new Set(prev)
      next.has(sev) ? next.delete(sev) : next.add(sev)
      return next
    })
  }, [])

  const { nodes, edges } = useMemo(() => {
    const g = graph || { nodes: [], edges: [] }
    const hasSelection = selectedNodeIds.size > 0
    const perCol: Record<string, number> = { target: 0, technique: 0, tactic: 0 }
    const nodes: Node[] = g.nodes.map((n) => {
      const idx = perCol[n.type] ?? 0
      perCol[n.type] = idx + 1
      const isSel = selectedNodeIds.has(n.id)
      const dimmed = hasSelection && !isSel
      return {
        id: n.id,
        position: { x: COL_X[n.type] ?? 0, y: idx * 64 + 20 },
        data: { label: n.label },
        style: {
          background: riskColor(n.risk),
          color: '#fff', borderRadius: 8,
          fontSize: 11, width: 200, padding: 6,
          border: isSel ? '2px solid #fff' : 'none',
          boxShadow: isSel ? '0 0 0 3px rgba(255,255,255,0.55), 0 0 12px rgba(248,113,113,0.9)' : 'none',
          opacity: dimmed ? 0.18 : 1,
          transition: 'opacity 200ms ease, box-shadow 200ms ease',
        },
        zIndex: isSel ? 10 : 0,
        sourcePosition: 'right' as any,
        targetPosition: 'left' as any,
      }
    })
    const edges: Edge[] = g.edges.map((e, i) => {
      const onPath = selectedNodeIds.has(e.from) && selectedNodeIds.has(e.to)
      const dimmed = hasSelection && !onPath
      const enables = e.type === 'enables'
      return {
        id: `e${i}`,
        source: e.from,
        target: e.to,
        animated: enables || onPath,
        style: {
          stroke: onPath ? '#fff' : enables ? '#f87171' : '#52525b',
          strokeWidth: onPath ? 2.5 : enables ? 2 : 1,
          opacity: dimmed ? 0.12 : 1,
          transition: 'opacity 200ms ease',
        },
        zIndex: onPath ? 9 : 0,
      }
    })
    return { nodes, edges }
  }, [graph, selectedNodeIds])

  // Click a ranked vector → highlight its path and pan/zoom the graph to it.
  const focusVector = useCallback((v: AttackVector) => {
    const key = vectorKey(v)
    if (key === selectedKey) {
      // toggle off — clear highlight, zoom back out to the whole map
      setSelectedKey(null)
      setSelectedVector(null)
      setSelectedNodeIds(new Set())
      rf.fitView({ duration: 500, padding: 0.1 })
      return
    }
    const ids = vectorNodeIds(v)
    setSelectedKey(key)
    setSelectedVector(v)
    setSelectedNodeIds(new Set([ids.target, ids.technique, ids.tactic]))
    // Frame the full target → technique → tactic path. Nodes that don't exist
    // in the graph are ignored by fitView.
    rf.fitView({
      nodes: [{ id: ids.target }, { id: ids.technique }, { id: ids.tactic }],
      duration: 650,
      padding: 0.35,
      maxZoom: 1.5,
    })
  }, [rf, selectedKey])

  const clearSelection = useCallback(() => {
    if (!selectedKey) return
    setSelectedKey(null)
    setSelectedVector(null)
    setSelectedNodeIds(new Set())
  }, [selectedKey])

  return (
    <div className="p-4 space-y-4">
      <PageHelp id="attack-map" title="How to use the Attack Map">
        <p>Findings are mapped to <strong>MITRE ATT&CK</strong> techniques and scored by risk
        (severity, CVSS, CISA KEV, exploit availability, ATT&CK tactic position, asset criticality).
        The graph reads <strong>target → technique → tactic</strong>; red animated edges show
        <strong> attack progression</strong> (one technique enabling a later-stage one on the same host).
        Click any row in the <strong>ranked list</strong> to jump the graph to that attack path and
        highlight it; click it again (or the graph background) to zoom back out. A selected row
        also reveals <strong>linked records</strong> — one-click into the Findings, Follow-ups,
        Recommendations, and Exploits for that target.
        Click <strong>Recompute</strong> after new scans to refresh.</p>
      </PageHelp>

      <div className="flex items-center gap-2">
        <Crosshair className="h-4 w-4 text-red-400" />
        <h2 className="text-base font-semibold">Attack Map</h2>
        <InfoTip side="bottom" text={
          <>Node color = risk (green→red). Columns: targets, ATT&CK techniques, tactics.
          Red animated edges = attack progression. Click a ranked row to focus its path.
          Same data the agents prioritize from (<code>get_attack_vectors</code>).</>
        } />
        <button
          onClick={() => compute.mutate()}
          disabled={compute.isPending}
          className="ml-auto flex items-center gap-1.5 px-2.5 py-1 text-xs rounded border border-primary/50 bg-primary/10 text-primary hover:bg-primary/20 disabled:opacity-50"
        >
          {compute.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          Recompute
        </button>
      </div>
      {compute.isSuccess && (
        <div className="text-xs text-muted-foreground">
          {compute.data?.findings_considered} findings → {compute.data?.vectors_written} vectors,
          {' '}{compute.data?.edges_written} path edges.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Graph */}
        <div className="lg:col-span-2 h-[600px] rounded-lg border border-border bg-card">
          {isLoading ? (
            <div className="h-full flex items-center justify-center text-sm text-muted-foreground">Loading…</div>
          ) : nodes.length === 0 ? (
            <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
              No attack vectors yet — run scans, then click Recompute.
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              fitView
              minZoom={0.1}
              proOptions={{ hideAttribution: true }}
              onPaneClick={clearSelection}
            >
              <Background />
              <Controls />
              <MiniMap pannable zoomable nodeColor={(n) => (n.style?.background as string) || '#888'} />
            </ReactFlow>
          )}
        </div>

        {/* Ranked next-best-action list */}
        <div className="rounded-lg border border-border bg-card overflow-auto h-[600px]">
          {/* Sticky controls — count + sort + filters stay pinned while the list scrolls */}
          <div className="sticky top-0 z-10 bg-card border-b border-border px-3 pt-3 pb-2 space-y-2">
            <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              Top attack vectors
              <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono text-muted-foreground">
                {displayVectors.length}{displayVectors.length !== allVectors.length ? ` / ${allVectors.length}` : ''}
              </span>
              <InfoTip text="Distinct attack paths (one per target+technique). Sort by risk, finding count, or severity; filter out vectors with no findings or by severity. Click a row to jump the graph to it and link out to its records." />
            </div>

            <div className="flex items-center gap-1 flex-wrap">
              <span className="text-[10px] text-muted-foreground mr-0.5">Sort</span>
              {([['risk', 'Risk'], ['findings', 'Findings'], ['severity', 'Severity']] as [SortKey, string][]).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setSortBy(key)}
                  className={`px-1.5 py-0.5 rounded text-[10px] border transition-colors ${
                    sortBy === key
                      ? 'border-primary bg-primary/15 text-primary'
                      : 'border-border bg-muted/40 text-muted-foreground hover:border-primary/50'
                  }`}
                >
                  {label}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setHideEmpty((v) => !v)}
                title="Hide attack vectors that have 0 findings"
                className={`ml-auto px-1.5 py-0.5 rounded text-[10px] border transition-colors ${
                  hideEmpty
                    ? 'border-primary bg-primary/15 text-primary'
                    : 'border-border bg-muted/40 text-muted-foreground hover:border-primary/50'
                }`}
              >
                Has findings
              </button>
            </div>

            {/* Severity filter — only severities present in the data get a chip */}
            <div className="flex items-center gap-1 flex-wrap">
              <span className="text-[10px] text-muted-foreground mr-0.5">Severity</span>
              {SEV_ORDER.filter((s) => sevCounts[s]).map((s) => {
                const active = sevFilter.has(s)
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => toggleSeverity(s)}
                    className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] border capitalize transition-colors ${
                      active
                        ? 'border-primary bg-primary/15 text-foreground'
                        : 'border-border bg-muted/40 text-muted-foreground hover:border-primary/50'
                    }`}
                  >
                    <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[s] || 'bg-gray-500'}`} />
                    {s}
                    <span className="text-muted-foreground/70">{sevCounts[s]}</span>
                  </button>
                )
              })}
              {sevFilter.size > 0 && (
                <button
                  type="button"
                  onClick={() => setSevFilter(new Set())}
                  className="text-[10px] text-primary hover:underline ml-0.5"
                >
                  clear
                </button>
              )}
            </div>
          </div>

          <div className="p-3 space-y-1.5">
            {selectedVector && <LinkedRecords vector={selectedVector} />}
            {displayVectors.map((v, i) => {
              const isSel = vectorKey(v) === selectedKey
              return (
                <button
                  key={i}
                  type="button"
                  onClick={() => focusVector(v)}
                  className={`w-full text-left text-xs border rounded p-2 transition-colors cursor-pointer ${
                    isSel
                      ? 'border-primary bg-primary/15 ring-1 ring-primary'
                      : 'border-border bg-muted/30 hover:bg-muted/60 hover:border-primary/50'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono px-1.5 py-0.5 rounded text-white text-[10px]" style={{ background: riskColor(v.risk_score) }}>
                      {v.risk_score}
                    </span>
                    <span className="font-mono text-foreground">{v.technique}</span>
                    <span className="text-muted-foreground">{v.tactic}</span>
                    {v.severity && (
                      <span className="flex items-center gap-1 text-[10px] text-muted-foreground capitalize">
                        <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[v.severity] || 'bg-gray-500'}`} />
                        {v.severity}
                      </span>
                    )}
                    <span className="ml-auto text-[10px] text-muted-foreground" title={`${v.finding_count ?? 0} finding(s)`}>
                      {v.finding_count ?? 0} <Bug className="inline h-3 w-3 -mt-0.5" />
                    </span>
                  </div>
                  <div className="text-muted-foreground mt-0.5">{v.technique_name}</div>
                  <div className="text-muted-foreground/80 font-mono text-[10px]" title={v.target}>
                    {middleTruncate(v.target || '')}
                  </div>
                </button>
              )
            })}
            {allVectors.length === 0 ? (
              <div className="text-xs text-muted-foreground">No vectors. Click Recompute.</div>
            ) : displayVectors.length === 0 ? (
              <div className="text-xs text-muted-foreground">No vectors match the current filters.</div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function AttackMap() {
  // ReactFlowProvider lets the ranked list (a sibling of <ReactFlow>) drive the
  // viewport via useReactFlow().
  return (
    <ReactFlowProvider>
      <AttackMapInner />
    </ReactFlowProvider>
  )
}
