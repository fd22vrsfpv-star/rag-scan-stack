import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { usePipeline, usePipelines, useLaunchPipeline, useStopPipeline } from '@/api/scans'
import { useEngagements, useEngagementScopes } from '@/api/engagements'
import { useUIStore } from '@/stores/ui'
import { ArrowLeft, Play, Square, RefreshCw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatDate } from '@/lib/utils'

const STAGE_COLORS: Record<string, string> = {
  pending: 'bg-muted text-muted-foreground',
  passive_recon: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
  discovery: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
  fingerprint: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  exploit: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
  aggregate: 'bg-purple-500/20 text-purple-400 border-purple-500/40',
  analysis: 'bg-green-500/20 text-green-400 border-green-500/40',
  done: 'bg-green-600/20 text-green-400 border-green-600/40',
  failed: 'bg-red-500/20 text-red-400 border-red-500/40',
}

const STAGE_LABELS = ['Passive', 'Discovery', 'Fingerprint', 'Exploit', 'Aggregate', 'Analysis']

export default function PipelineMonitor() {
  const { pipelineId } = useParams<{ pipelineId: string }>()
  const navigate = useNavigate()
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const { data: engData } = useEngagements()
  const engagements = engData?.engagements?.filter(e => e.status !== 'archived') ?? []
  const { data: scopesData } = useEngagementScopes(engagementId ?? undefined)
  const scopes = scopesData?.scopes ?? []

  // Pipeline list (when no specific pipeline selected)
  const { data: pipelinesData } = usePipelines(engagementId)
  const pipelines = pipelinesData?.pipelines ?? []

  // Single pipeline detail
  const { data: pipeline } = usePipeline(pipelineId)
  const stopPipeline = useStopPipeline()
  const launchPipeline = useLaunchPipeline()

  // Launch form
  const [launchScope, setLaunchScope] = useState('')
  const [launchProfile, setLaunchProfile] = useState('pentest')
  const [useTunnels, setUseTunnels] = useState(false)

  const handleLaunch = () => {
    if (!engagementId) return
    launchPipeline.mutate({
      engagement_id: engagementId,
      scope_name: launchScope || undefined,
      profile: launchProfile,
      config: { use_tunnels: useTunnels },
    }, {
      onSuccess: (res) => navigate(`/pipelines/${res.pipeline_id}`),
    })
  }

  // ── Detail view ──────────────────────────────────────────────────────
  if (pipelineId && pipeline) {
    const hostEntries = Object.entries(pipeline.host_states || {})
    const isActive = pipeline.status === 'running' || pipeline.status === 'pending'

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <Link to="/pipelines" className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <h2 className="text-lg font-semibold">Pipeline: {pipeline.name}</h2>
          <span className={cn('px-2 py-0.5 text-xs rounded-full border',
            pipeline.status === 'completed' ? 'bg-green-500/20 text-green-400 border-green-500/40' :
            pipeline.status === 'running' ? 'bg-blue-500/20 text-blue-400 border-blue-500/40' :
            pipeline.status === 'failed' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
            'bg-muted text-muted-foreground'
          )}>{pipeline.status}</span>
          <span className="text-xs text-muted-foreground">{pipeline.profile}</span>
          <div className="flex-1" />
          {isActive && (
            <button onClick={() => stopPipeline.mutate(pipelineId)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-destructive text-destructive-foreground rounded text-xs">
              <Square className="h-3 w-3" /> Stop
            </button>
          )}
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-5 gap-3">
          {[
            ['Targets', pipeline.target_count],
            ['Jobs', `${pipeline.jobs_completed}/${pipeline.jobs_spawned}`],
            ['Failed', pipeline.jobs_failed],
            ['Findings', pipeline.findings_count],
            ['Duration', pipeline.completed_at
              ? `${((new Date(pipeline.completed_at).getTime() - new Date(pipeline.created_at).getTime()) / 60000).toFixed(1)}m`
              : isActive ? 'running...' : '-'],
          ].map(([label, val]) => (
            <div key={String(label)} className="bg-card border border-border rounded-lg p-3 text-center">
              <div className="text-lg font-bold">{val}</div>
              <div className="text-[10px] text-muted-foreground">{label}</div>
            </div>
          ))}
        </div>

        {/* Per-host stage table */}
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                <th className="px-3 py-2 text-left font-medium">Host</th>
                {STAGE_LABELS.map(s => (
                  <th key={s} className="px-2 py-2 text-center font-medium w-20">{s}</th>
                ))}
                <th className="px-3 py-2 text-left font-medium w-16">Status</th>
              </tr>
            </thead>
            <tbody>
              {hostEntries.map(([host, hs]) => (
                <tr key={host} className="border-b border-border/50 hover:bg-muted/30">
                  <td className="px-3 py-1.5 font-mono">{host}</td>
                  {STAGE_LABELS.map((_, i) => {
                    const active = hs.stage === i && hs.status === 'running'
                    const done = hs.stage > i || (hs.stage === i && hs.status === 'done')
                    const failed = hs.stage === i && hs.status === 'failed'
                    return (
                      <td key={i} className="px-2 py-1.5 text-center">
                        <span className={cn(
                          'inline-block w-3 h-3 rounded-full border',
                          done ? 'bg-green-500 border-green-600' :
                          active ? 'bg-blue-500 border-blue-600 animate-pulse' :
                          failed ? 'bg-red-500 border-red-600' :
                          'bg-muted border-border',
                        )} />
                      </td>
                    )
                  })}
                  <td className="px-3 py-1.5">
                    <span className={cn('px-1.5 py-0.5 rounded text-[10px]',
                      STAGE_COLORS[hs.status] || STAGE_COLORS[hs.stage_name] || 'bg-muted')}>
                      {hs.stage_name || hs.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {hostEntries.length === 0 && (
            <p className="text-center text-xs text-muted-foreground py-4">No host data yet...</p>
          )}
        </div>
      </div>
    )
  }

  // ── List view + launch form ──────────────────────────────────────────
  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Scan Pipelines</h2>

      {/* Launch form */}
      {engagementId && (
        <div className="bg-card border border-border rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold">Launch Pipeline</h3>
          <div className="flex items-center gap-3">
            <select value={launchScope} onChange={e => setLaunchScope(e.target.value)}
              className="bg-muted rounded px-2 py-1.5 text-xs border border-border">
              <option value="">All scope targets</option>
              {scopes.map(s => <option key={s.name} value={s.name}>{s.name} ({s.target_count})</option>)}
            </select>
            <select value={launchProfile} onChange={e => setLaunchProfile(e.target.value)}
              className="bg-muted rounded px-2 py-1.5 text-xs border border-border">
              <option value="pentest">Pentest</option>
              <option value="redteam">Redteam</option>
            </select>
            <label className="flex items-center gap-1.5 text-xs">
              <input type="checkbox" checked={useTunnels} onChange={e => setUseTunnels(e.target.checked)} />
              Spread across tunnels
            </label>
            <button onClick={handleLaunch}
              disabled={launchPipeline.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded text-xs disabled:opacity-50">
              <Play className="h-3 w-3" />
              {launchPipeline.isPending ? 'Launching...' : 'Launch'}
            </button>
          </div>
          {launchPipeline.error && (
            <p className="text-xs text-red-400">{String(launchPipeline.error)}</p>
          )}
        </div>
      )}
      {!engagementId && (
        <p className="text-xs text-muted-foreground">Select an engagement to launch a pipeline.</p>
      )}

      {/* Pipeline list */}
      <div className="space-y-2">
        {pipelines.map(p => (
          <Link key={p.id} to={`/pipelines/${p.id}`}
            className="block bg-card border border-border rounded-lg p-3 hover:border-primary/50 transition-colors">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs text-muted-foreground">{p.id.slice(0, 8)}</span>
              <span className="text-sm font-medium">{p.name}</span>
              <span className={cn('px-2 py-0.5 text-[10px] rounded-full border',
                p.status === 'completed' ? 'bg-green-500/20 text-green-400 border-green-500/40' :
                p.status === 'running' ? 'bg-blue-500/20 text-blue-400 border-blue-500/40 animate-pulse' :
                p.status === 'failed' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                'bg-muted text-muted-foreground'
              )}>{p.status}</span>
              <span className="text-xs text-muted-foreground">{p.profile}</span>
              <div className="flex-1" />
              <span className="text-xs">{p.target_count} targets</span>
              <span className="text-xs text-muted-foreground">{p.jobs_completed}/{p.jobs_spawned} jobs</span>
              <span className="text-[10px] text-muted-foreground">{formatDate(p.created_at)}</span>
            </div>
          </Link>
        ))}
        {pipelines.length === 0 && (
          <p className="text-xs text-muted-foreground">No pipelines yet.</p>
        )}
      </div>
    </div>
  )
}
