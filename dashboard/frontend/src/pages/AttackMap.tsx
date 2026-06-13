import { useMemo } from 'react'
import ReactFlow, { Background, Controls, MiniMap, type Node, type Edge } from 'reactflow'
import 'reactflow/dist/style.css'
import { Crosshair, RefreshCw, Loader2 } from 'lucide-react'
import { useAttackVectors, useAttackGraph, useComputeAttackVectors } from '@/api/attackVectors'
import PageHelp from '@/components/PageHelp'
import InfoTip from '@/components/InfoTip'

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

export default function AttackMap() {
  const { data: graph, isLoading } = useAttackGraph()
  const { data: ranked } = useAttackVectors(0, 100)
  const compute = useComputeAttackVectors()

  const { nodes, edges } = useMemo(() => {
    const g = graph || { nodes: [], edges: [] }
    const perCol: Record<string, number> = { target: 0, technique: 0, tactic: 0 }
    const nodes: Node[] = g.nodes.map((n) => {
      const idx = perCol[n.type] ?? 0
      perCol[n.type] = idx + 1
      return {
        id: n.id,
        position: { x: COL_X[n.type] ?? 0, y: idx * 64 + 20 },
        data: { label: n.label },
        style: {
          background: riskColor(n.risk),
          color: '#fff', border: 'none', borderRadius: 8,
          fontSize: 11, width: 200, padding: 6,
        },
        sourcePosition: 'right' as any,
        targetPosition: 'left' as any,
      }
    })
    const edges: Edge[] = g.edges.map((e, i) => ({
      id: `e${i}`,
      source: e.from,
      target: e.to,
      animated: e.type === 'enables',
      style: { stroke: e.type === 'enables' ? '#f87171' : '#52525b', strokeWidth: e.type === 'enables' ? 2 : 1 },
    }))
    return { nodes, edges }
  }, [graph])

  return (
    <div className="p-4 space-y-4">
      <PageHelp id="attack-map" title="How to use the Attack Map">
        <p>Findings are mapped to <strong>MITRE ATT&CK</strong> techniques and scored by risk
        (severity, CVSS, CISA KEV, exploit availability, ATT&CK tactic position, asset criticality).
        The graph reads <strong>target → technique → tactic</strong>; red animated edges show
        <strong> attack progression</strong> (one technique enabling a later-stage one on the same host).
        The ranked list is the prioritized <strong>next-best-action</strong> the AI agents also consume.
        Click <strong>Recompute</strong> after new scans to refresh.</p>
      </PageHelp>

      <div className="flex items-center gap-2">
        <Crosshair className="h-4 w-4 text-red-400" />
        <h2 className="text-base font-semibold">Attack Map</h2>
        <InfoTip side="bottom" text={
          <>Node color = risk (green→red). Columns: targets, ATT&CK techniques, tactics.
          Red animated edges = attack progression. Same data the agents prioritize from
          (<code>get_attack_vectors</code>).</>
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
            <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.1} proOptions={{ hideAttribution: true }}>
              <Background />
              <Controls />
              <MiniMap pannable zoomable nodeColor={(n) => (n.style?.background as string) || '#888'} />
            </ReactFlow>
          )}
        </div>

        {/* Ranked next-best-action list */}
        <div className="rounded-lg border border-border bg-card p-3 overflow-auto h-[600px]">
          <div className="text-xs font-semibold text-foreground mb-2 flex items-center gap-1">
            Top attack vectors
            <InfoTip text="Distinct attack paths (one per target+technique), highest risk first — the prioritized next-best-action list." />
          </div>
          <div className="space-y-1.5">
            {(ranked?.vectors || []).slice(0, 40).map((v, i) => (
              <div key={i} className="text-xs border border-border rounded p-2 bg-muted/30">
                <div className="flex items-center gap-2">
                  <span className="font-mono px-1.5 py-0.5 rounded text-white text-[10px]" style={{ background: riskColor(v.risk_score) }}>
                    {v.risk_score}
                  </span>
                  <span className="font-mono text-foreground">{v.technique}</span>
                  <span className="text-muted-foreground">{v.tactic}</span>
                  {v.finding_count && v.finding_count > 1 && (
                    <span className="text-[10px] text-muted-foreground">×{v.finding_count}</span>
                  )}
                </div>
                <div className="text-muted-foreground mt-0.5">{v.technique_name}</div>
                <div className="text-muted-foreground/80 font-mono text-[10px]" title={v.target}>
                  {middleTruncate(v.target || '')}
                </div>
              </div>
            ))}
            {(ranked?.vectors || []).length === 0 && (
              <div className="text-xs text-muted-foreground">No vectors. Click Recompute.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
