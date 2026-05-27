import { useState, useEffect } from 'react'
import {
  useReconAgentState, useEnableReconAgent, useDisableReconAgent,
  usePauseReconAgent, useRunReconAgentNow, useReconAgentCoverage,
  useReconAgentLog,
} from '@/api/recon-agent'
import { useEngagementScopes } from '@/api/engagements'
import { useNodes } from '@/api/nodes'
import { apiFetch } from '@/api/client'
import { useScanDefaultsStore } from '@/stores/scanDefaults'
import { Play, Pause, Square, RefreshCw, Zap } from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatDate } from '@/lib/utils'

const STAGE_LABELS = ['Passive', 'Discovery', 'Fingerprint', 'Exploit']
const STATUS_COLORS: Record<string, string> = {
  completed: 'bg-green-500',
  running: 'bg-blue-500 animate-pulse',
  pending: 'bg-muted',
  failed: 'bg-red-500',
  skipped: 'bg-yellow-500/50',
}

export function ReconAgentPanel({ engagementId }: { engagementId: string }) {
  const { data: state } = useReconAgentState(engagementId)
  const { data: coverageData } = useReconAgentCoverage(engagementId)
  const { data: logData } = useReconAgentLog(engagementId)
  const enableAgent = useEnableReconAgent()
  const disableAgent = useDisableReconAgent()
  const pauseAgent = usePauseReconAgent()
  const runNow = useRunReconAgentNow()
  const { data: scopesData } = useEngagementScopes(engagementId)
  const scopes = scopesData?.scopes ?? []
  const { data: nodesData } = useNodes()
  const onlineTunnels = (nodesData?.nodes ?? []).filter(n => n.status === 'online' && n.proxy_port)
  const [interval, setInterval] = useState(300)
  const [selectedScopes, setSelectedScopes] = useState<string[]>([])
  const [selectedTunnel, setSelectedTunnel] = useState<string>('')  // '' = direct, 'round-robin', or 'socks5://...'
  const [excludedTunnels, setExcludedTunnels] = useState<Set<string>>(new Set())
  const globalProfile = useScanDefaultsStore(s => s.activeProfile) as 'pentest' | 'redteam'
  const activeConfig = state?.config as Record<string, unknown> | undefined
  const activeScopes = activeConfig?.scope_names as string[] | undefined
  const activeProxy = activeConfig?.proxy as string | undefined
  const activeUseTunnels = activeConfig?.use_tunnels as boolean | undefined

  const PROFILE_PRESETS = {
    pentest:  { ports: '--top-ports 1000', interval: 300,  label: 'Pentest — top 1000 ports, 5 min cycle' },
    redteam:  { ports: '21,22,25,80,443,8080,8443,3389,445,3306,5432', interval: 600, label: 'Redteam — targeted ports, 10 min cycle, jitter' },
    custom:   { ports: '--top-ports 1000', interval: 300, label: 'Custom' },
  }

  // Initialize from: saved agent config > global Settings profile > default
  const savedProfile = (activeConfig?.profile as string) || ''
  const initProfile = (savedProfile === 'pentest' || savedProfile === 'redteam') ? savedProfile
    : (globalProfile === 'pentest' || globalProfile === 'redteam') ? globalProfile : 'pentest'
  const [agentProfile, setAgentProfile] = useState<'pentest' | 'redteam' | 'custom'>(initProfile)
  const [ports, setPorts] = useState(
    (activeConfig?.ports as string) || PROFILE_PRESETS[initProfile]?.ports || '--top-ports 1000'
  )

  // Sync when global profile changes in Settings (only if agent isn't already running with custom config)
  useEffect(() => {
    if (!enabled && (globalProfile === 'pentest' || globalProfile === 'redteam')) {
      setAgentProfile(globalProfile)
      setPorts(PROFILE_PRESETS[globalProfile].ports)
      setInterval(PROFILE_PRESETS[globalProfile].interval)
    }
  }, [globalProfile])
  const [blockLocal, setBlockLocal] = useState(false)
  useEffect(() => {
    apiFetch<{ value: string }>('/settings/config/block_local_scans')
      .then(r => setBlockLocal(r?.value?.toLowerCase() === 'true'))
      .catch(() => {})
  }, [])

  const enabled = state?.enabled ?? false
  const coverage = coverageData?.coverage ?? []
  const events = logData?.events ?? []

  // Group coverage by target
  const coverageByTarget: Record<string, Record<string, string>> = {}
  for (const c of coverage) {
    if (!coverageByTarget[c.target]) coverageByTarget[c.target] = {}
    coverageByTarget[c.target][`${c.stage}-${c.scan_type}`] = c.status
  }
  const targets = Object.keys(coverageByTarget).sort()

  return (
    <div className="space-y-4">
      {/* Help / explanation */}
      <div className="bg-muted/30 border border-border rounded-lg p-3 text-xs text-muted-foreground space-y-1.5">
        <p className="font-medium text-foreground">What the Recon Agent does:</p>
        <ul className="list-disc pl-4 space-y-0.5">
          <li><strong>Detects new findings</strong> — runs detection rules every cycle and creates follow-up items for anything flagged (CVEs, exposed services, weak creds, etc.)</li>
          <li><strong>Fills coverage gaps</strong> — checks which scope targets haven't been scanned yet at each stage (Discovery → Fingerprint → Exploit) and auto-dispatches scans</li>
          <li><strong>Never duplicates</strong> — tracks every (target + stage + scan type) in the coverage table AND checks in-flight jobs before dispatching. A target that already has a completed or running nmap scan won't get another one</li>
          <li><strong>Respects profile</strong> — pentest mode dispatches up to 5 scans/cycle; redteam mode limits to 2 with random jitter (0-120s) per dispatch to avoid IDS detection</li>
          <li><strong>Logs everything</strong> — every cycle's decisions are recorded in the Campaign Timeline (operator: recon_agent) for full audit trail</li>
        </ul>
        <p className="text-[10px]">Stages: <strong>Discovery</strong> (masscan+nmap) → <strong>Fingerprint</strong> (httpx probe) → <strong>Exploit</strong> (nuclei CVE scan). Each target progresses independently.</p>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        {enabled ? (
          <>
            <div className="flex items-center gap-2">
              <div className="h-2.5 w-2.5 rounded-full bg-green-500 animate-pulse" />
              <span className="text-sm font-medium text-green-400">Agent Active</span>
            </div>
            <button onClick={() => disableAgent.mutate(engagementId)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-destructive text-destructive-foreground rounded text-xs">
              <Square className="h-3 w-3" /> Disable
            </button>
            <button onClick={() => pauseAgent.mutate({ eid: engagementId, minutes: 60 })}
              className="flex items-center gap-1.5 px-3 py-1.5 border border-border rounded text-xs">
              <Pause className="h-3 w-3" /> Pause 1hr
            </button>
            <button onClick={() => runNow.mutate(engagementId)}
              disabled={runNow.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded text-xs disabled:opacity-50">
              <Zap className="h-3 w-3" /> {runNow.isPending ? 'Triggering...' : 'Run Now'}
            </button>
          </>
        ) : (
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <div className="h-2.5 w-2.5 rounded-full bg-muted" />
              <span className="text-sm text-muted-foreground">Agent Disabled</span>
            </div>
            <div className="flex items-center gap-1.5">
              <label className="text-xs text-muted-foreground">Profile:</label>
              <select value={agentProfile} onChange={e => {
                  const p = e.target.value as 'pentest' | 'redteam' | 'custom'
                  setAgentProfile(p)
                  if (p !== 'custom') {
                    setPorts(PROFILE_PRESETS[p].ports)
                    setInterval(PROFILE_PRESETS[p].interval)
                  }
                }}
                className="bg-muted rounded px-2 py-1 text-xs border border-border">
                <option value="pentest">Pentest</option>
                <option value="redteam">Redteam</option>
                <option value="custom">Custom</option>
              </select>
              <span className="text-[9px] text-muted-foreground">{PROFILE_PRESETS[agentProfile].label}</span>
            </div>
            {agentProfile === 'custom' && (
              <>
                <div className="flex items-center gap-1.5">
                  <label className="text-xs text-muted-foreground">Interval:</label>
                  <select value={interval} onChange={e => setInterval(Number(e.target.value))}
                    className="bg-muted rounded px-2 py-1 text-xs border border-border">
                    <option value={60}>1 min</option>
                    <option value={300}>5 min</option>
                    <option value={600}>10 min</option>
                    <option value={1800}>30 min</option>
                  </select>
                </div>
                <div className="flex items-center gap-1.5">
                  <label className="text-xs text-muted-foreground">Ports:</label>
                  <input value={ports} onChange={e => setPorts(e.target.value)}
                    placeholder="--top-ports 1000"
                    className="bg-muted rounded px-2 py-1 text-xs border border-border w-48" />
                </div>
              </>
            )}
            {scopes.length > 0 && (
              <div className="flex items-center gap-1.5">
                <label className="text-xs text-muted-foreground">Scopes:</label>
                <div className="flex flex-wrap gap-1">
                  {scopes.map(s => (
                    <label key={s.name} className={cn(
                      'inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] border cursor-pointer',
                      selectedScopes.includes(s.name)
                        ? 'border-primary bg-primary/15 text-primary'
                        : 'border-border text-muted-foreground hover:border-primary/50',
                    )}>
                      <input type="checkbox" className="hidden"
                        checked={selectedScopes.includes(s.name)}
                        onChange={e => {
                          if (e.target.checked) setSelectedScopes([...selectedScopes, s.name])
                          else setSelectedScopes(selectedScopes.filter(x => x !== s.name))
                        }}
                      />
                      {s.name} ({s.target_count})
                    </label>
                  ))}
                </div>
                <span className="text-[9px] text-muted-foreground">{selectedScopes.length === 0 ? '(all scopes)' : ''}</span>
              </div>
            )}
            {onlineTunnels.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center gap-1.5">
                  <label className="text-xs text-muted-foreground">Tunnel:</label>
                  <select value={selectedTunnel} onChange={e => { setSelectedTunnel(e.target.value); setExcludedTunnels(new Set()) }}
                    className="bg-muted rounded px-2 py-1 text-xs border border-border">
                    {!blockLocal && <option value="">Direct (no proxy)</option>}
                    {blockLocal && !selectedTunnel && <option value="" disabled>Select a tunnel (local blocked)</option>}
                    <option value="round-robin">Round-robin tunnels</option>
                    {onlineTunnels.map(n => (
                      <option key={n.id} value={`socks5://node-manager:${n.proxy_port}`}>
                        {n.name} (:{n.proxy_port})
                      </option>
                    ))}
                  </select>
                </div>
                {selectedTunnel === 'round-robin' && (
                  <div className="flex flex-wrap gap-1 pl-[52px]">
                    {onlineTunnels.map(n => {
                      const key = `socks5://node-manager:${n.proxy_port}`
                      const excluded = excludedTunnels.has(key)
                      return (
                        <label key={n.id} className={cn(
                          'inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] border cursor-pointer',
                          excluded
                            ? 'border-red-500/40 bg-red-500/10 text-red-400 line-through'
                            : 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400',
                        )}>
                          <input type="checkbox" className="hidden"
                            checked={!excluded}
                            onChange={() => {
                              const next = new Set(excludedTunnels)
                              excluded ? next.delete(key) : next.add(key)
                              setExcludedTunnels(next)
                            }}
                          />
                          {n.name} (:{n.proxy_port})
                        </label>
                      )
                    })}
                    <span className="text-[9px] text-muted-foreground self-center">
                      {onlineTunnels.length - excludedTunnels.size} of {onlineTunnels.length} active
                    </span>
                  </div>
                )}
              </div>
            )}
            <button onClick={() => {
                const config: Record<string, unknown> = { profile: agentProfile, ports }
                if (selectedScopes.length > 0) config.scope_names = selectedScopes
                if (selectedTunnel === 'round-robin') {
                  config.use_tunnels = true
                  if (excludedTunnels.size > 0) {
                    config.exclude_tunnels = [...excludedTunnels]
                  }
                } else if (selectedTunnel) {
                  config.proxy = selectedTunnel
                }
                enableAgent.mutate({ eid: engagementId, interval_sec: interval, config })
              }}
              disabled={enableAgent.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 text-white rounded text-xs disabled:opacity-50">
              <Play className="h-3 w-3" /> Enable
            </button>
          </div>
        )}
      </div>

      {/* Status info */}
      {state?.exists && (
        <div className="flex gap-4 text-xs text-muted-foreground flex-wrap">
          {state.last_run_at && <span>Last run: {formatDate(state.last_run_at)}</span>}
          {state.last_dispatch_at && <span>Last dispatch: {formatDate(state.last_dispatch_at)}</span>}
          {coverage.length > 0 && (
            <span>Coverage: {coverage.filter(c => c.status === 'completed').length}/{coverage.length} stages done</span>
          )}
          {activeScopes && activeScopes.length > 0 && (
            <span>Scopes: {activeScopes.join(', ')}</span>
          )}
          {(!activeScopes || activeScopes.length === 0) && enabled && (
            <span>Scopes: all</span>
          )}
          {!!activeConfig?.profile && (
            <span>Profile: {String(activeConfig.profile)}</span>
          )}
          {!!activeConfig?.ports && (
            <span>Ports: {String(activeConfig.ports)}</span>
          )}
          {activeUseTunnels && (
            <span className="text-cyan-400">
              Tunnel: round-robin
              {((state?.config as Record<string, unknown>)?.exclude_tunnels as string[] | undefined)?.length
                ? ` (${((state?.config as Record<string, unknown>).exclude_tunnels as string[]).length} excluded)`
                : ''}
            </span>
          )}
          {activeProxy && !activeUseTunnels && <span className="text-cyan-400">Tunnel: {activeProxy}</span>}
          {!activeProxy && !activeUseTunnels && enabled && <span>Tunnel: direct</span>}
          {state.pause_until && <span className="text-yellow-400">Paused until: {formatDate(state.pause_until)}</span>}
          <span>Interval: {state.interval_sec}s</span>
        </div>
      )}

      {/* Coverage summary + matrix */}
      {coverage.length > 0 && (() => {
        const completed = coverage.filter(c => c.status === 'completed').length
        const running = coverage.filter(c => c.status === 'running').length
        const failed = coverage.filter(c => c.status === 'failed').length
        const pending = coverage.filter(c => c.status === 'pending').length
        const uniqueTargets = new Set(coverage.map(c => c.target)).size
        return (
          <div className="space-y-2">
            {/* Summary cards */}
            <div className="grid grid-cols-5 gap-2">
              <div className="bg-card border border-border rounded p-2 text-center">
                <div className="text-lg font-bold">{uniqueTargets}</div>
                <div className="text-[9px] text-muted-foreground">Targets</div>
              </div>
              <div className="bg-card border border-green-500/30 rounded p-2 text-center">
                <div className="text-lg font-bold text-green-400">{completed}</div>
                <div className="text-[9px] text-muted-foreground">Completed</div>
              </div>
              <div className="bg-card border border-blue-500/30 rounded p-2 text-center">
                <div className="text-lg font-bold text-blue-400">{running}</div>
                <div className="text-[9px] text-muted-foreground">Running</div>
              </div>
              <div className="bg-card border border-red-500/30 rounded p-2 text-center">
                <div className="text-lg font-bold text-red-400">{failed}</div>
                <div className="text-[9px] text-muted-foreground">Failed</div>
              </div>
              <div className="bg-card border border-border rounded p-2 text-center">
                <div className="text-lg font-bold">{pending}</div>
                <div className="text-[9px] text-muted-foreground">Pending</div>
              </div>
            </div>

            {/* Coverage matrix (collapsible for large target lists) */}
            <details className="bg-card border border-border rounded-lg overflow-hidden">
              <summary className="px-3 py-2 text-xs font-semibold cursor-pointer hover:bg-muted/30">
                Coverage Matrix — {uniqueTargets} targets × {STAGE_LABELS.length} stages ({coverage.length} entries)
              </summary>
              <div className="max-h-64 overflow-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-card">
                    <tr className="border-b border-border">
                      <th className="px-3 py-1.5 text-left font-medium">Target</th>
                      {STAGE_LABELS.map(s => (
                        <th key={s} className="px-2 py-1.5 text-center font-medium w-20">{s}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {targets.map(target => (
                      <tr key={target} className="border-b border-border/50 hover:bg-muted/30">
                        <td className="px-3 py-1.5 font-mono text-[10px] truncate max-w-[200px]" title={target}>{target}</td>
                        {[0, 1, 2, 3].map(stage => {
                          const scanTypes = ['subfinder', 'nmap', 'httpx', 'nuclei']
                          const key = `${stage}-${scanTypes[stage]}`
                          const status = coverageByTarget[target]?.[key]
                          return (
                            <td key={stage} className="px-2 py-1.5 text-center">
                              <span className={cn(
                                'inline-block w-3 h-3 rounded-full border border-border',
                                status ? (STATUS_COLORS[status] || 'bg-muted') : 'bg-muted',
                              )} title={status || 'not started'} />
                            </td>
                          )
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          </div>
        )
      })()}

      {targets.length === 0 && enabled && (
        <p className="text-xs text-muted-foreground">No coverage data yet. The agent will populate this on its next cycle.</p>
      )}

      {/* Recent agent log */}
      {events.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <h4 className="text-xs font-semibold px-3 py-2 border-b border-border">Recent Agent Actions</h4>
          <div className="max-h-48 overflow-y-auto">
            {events.map((ev, i) => (
              <div key={i} className="px-3 py-1.5 text-xs border-b border-border/30 flex items-center gap-2">
                <span className="text-muted-foreground w-32 shrink-0">
                  {ev.timestamp ? formatDate(ev.timestamp as string) : ''}
                </span>
                <span className="font-medium">{ev.title as string || ''}</span>
                <span className="text-muted-foreground truncate flex-1">{ev.description as string || ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
