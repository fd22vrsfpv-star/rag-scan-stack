import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useScans, useStopScan, useResumeScan, useDeleteScan, useClearScanHistory } from '@/api/scans'
import { useScopeNames } from '@/api/scope'
import { useScheduledScans, useCancelScheduledScan } from '@/api/opsec'
import { useAgentSessions, useSessionScans } from '@/api/agentSessions'
import { useNodes } from '@/api/nodes'
import type { AgentSession, SessionScansResponse } from '@/api/agentSessions'
import { StatusDot } from '@/components/common/StatusDot'
import { Square, ExternalLink, Bot, ChevronDown, ChevronRight, Radio, Play, Wifi, Trash2, Shield, Search, X, Clock, CalendarClock, Timer, Activity } from 'lucide-react'
import { apiFetch } from '@/api/client'
import { cn, formatDate } from '@/lib/utils'
import { useState, useMemo, useEffect } from 'react'

// Helper function to extract proxy details
function getProxyDetails(proxy: string, nodes: any[]) {
  if (!proxy) return null

  // Extract port from proxy URL (e.g., socks5://node-manager:10127)
  const portMatch = proxy.match(/:(\d+)$/)
  if (!portMatch) return { protocol: 'Unknown', displayText: 'Proxy' }

  const port = parseInt(portMatch[1])
  const node = nodes.find(n => n.proxy_port === port)

  if (node) {
    // Determine tunnel type
    const tunnelType = node.wg_assigned_ip ? 'WireGuard' :
                      node.node_type === 'ssh' ? 'SSH' :
                      node.node_type.toUpperCase()

    return {
      protocol: tunnelType,
      hostIP: node.hostname || node.external_ip || 'Unknown',
      nodeName: node.name,
      displayText: `${tunnelType} via ${node.name}`,
      fullDetails: `${tunnelType} tunnel via ${node.name} (${node.hostname || node.external_ip || 'Unknown IP'})`
    }
  }

  // Fallback for unknown proxies
  return {
    protocol: proxy.includes('ssh-tunnel') ? 'SSH' : 'Unknown',
    displayText: proxy.includes('ssh-tunnel') ? 'SSH Tunnel' : 'Proxy'
  }
}

function AgentSessionCard({ session }: { session: AgentSession }) {
  const { data: scanData } = useSessionScans(session.session_id)
  const [expanded, setExpanded] = useState(true)

  const scans = scanData?.scans ?? []
  const summary = scanData?.summary
  const currentPhase = scanData?.current_phase

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      {/* Session header */}
      <Link
        to={`/agent-sessions/${session.session_id}`}
        className="p-3 flex items-center gap-3 hover:bg-muted/50 transition-colors"
      >
        <StatusDot status="active" />
        <Bot className="h-4 w-4 text-primary shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">{session.session_name}</span>
            <span className="text-xs text-muted-foreground">{session.target_description}</span>
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-xs text-muted-foreground">
              Round {session.current_round ?? '?'} / {session.max_rounds ?? session.configuration?.max_rounds ?? '?'}
            </span>
            {currentPhase && (
              <span className="text-xs text-blue-400">
                Phase: {currentPhase}
              </span>
            )}
          </div>
        </div>
        <span className="text-xs text-green-500 font-medium">running</span>
      </Link>

      {/* Scan breakdown */}
      {scans.length > 0 && (
        <div className="border-t border-border">
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
          >
            {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            <span>
              {summary?.total_scans ?? scans.length} scan{scans.length !== 1 ? 's' : ''}
            </span>
            {(summary?.running ?? 0) > 0 && (
              <span className="text-blue-500">{summary?.running} running</span>
            )}
            {(summary?.completed ?? 0) > 0 && (
              <span className="text-green-500">{summary?.completed} completed</span>
            )}
            {(summary?.failed ?? 0) > 0 && (
              <span className="text-red-500">{summary?.failed} failed</span>
            )}
          </button>
          {expanded && (
            <div className="px-3 pb-2 space-y-1">
              {scans.map(scan => {
                const duration = scan.duration_seconds != null
                  ? scan.duration_seconds < 60 ? `${scan.duration_seconds.toFixed(0)}s` : `${(scan.duration_seconds / 60).toFixed(1)}m`
                  : null
                return (
                  <div
                    key={scan.job_id}
                    className="flex items-center gap-2 py-1 px-2 rounded text-xs bg-muted/30"
                  >
                    <StatusDot status={scan.status} />
                    <span className="font-medium">{scan.type}</span>
                    <span className="text-muted-foreground font-mono">{scan.job_id?.slice(0, 8)}</span>
                    <span className={cn(
                      'px-1.5 py-0.5 rounded',
                      scan.status === 'completed' ? 'bg-green-500/10 text-green-500'
                        : scan.status === 'running' ? 'bg-blue-500/10 text-blue-500'
                        : scan.status === 'failed' ? 'bg-red-500/10 text-red-500'
                        : 'bg-yellow-500/10 text-yellow-500',
                    )}>
                      {scan.status}
                    </span>
                    {duration && <span className="text-muted-foreground">{duration}</span>}
                    <div className="flex-1" />
                    {scan.job_id && (
                      <Link
                        to={`/scans/${scan.job_id}`}
                        className="text-muted-foreground hover:text-foreground"
                        onClick={e => e.stopPropagation()}
                      >
                        <ExternalLink className="h-3 w-3" />
                      </Link>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function ScanMonitor() {
  const { data, isLoading } = useScans()
  const stopScan = useStopScan()
  const resumeScan = useResumeScan()
  const deleteScan = useDeleteScan()
  const clearHistory = useClearScanHistory()
  const navigate = useNavigate()
  const { data: sessionsData } = useAgentSessions()
  const { data: scheduledData } = useScheduledScans('pending')
  const { data: nodesData } = useNodes()
  const cancelScheduled = useCancelScheduledScan()
  const { data: scopeData } = useScopeNames()
  const [search, setSearch] = useState('')
  const [scopeFilter, setScopeFilter] = useState('')
  const [hoursFilter, setHoursFilter] = useState(0) // 0 = all time

  const jobs = data?.jobs ?? []
  const nodes = nodesData?.nodes ?? []
  const allScopeNames = (scopeData?.names ?? []).map(n => typeof n === 'string' ? n : n.name)
  const byNewest = (a: typeof jobs[number], b: typeof jobs[number]) =>
    new Date(b.created_at ?? 0).getTime() - new Date(a.created_at ?? 0).getTime()

  const matchesFilter = useMemo(() => {
    const q = search.trim().toLowerCase()
    const cutoff = hoursFilter > 0 ? Date.now() - hoursFilter * 3600_000 : 0
    return (job: typeof jobs[number]) => {
      // Scope dropdown filter
      if (scopeFilter && (job.scope_name || '') !== scopeFilter) return false
      // Time filter
      if (cutoff > 0) {
        const ts = new Date(job.created_at ?? 0).getTime()
        if (ts < cutoff) return false
      }
      // Text search (includes status)
      if (!q) return true
      const target = (typeof job.target === 'string' ? job.target : '').toLowerCase()
      const targets = (Array.isArray(job.targets) ? job.targets.map(String).join(' ') : '').toLowerCase()
      const scope = (job.scope_name || '').toLowerCase()
      const type = (job.type || '').toLowerCase()
      const id = (job.job_id || '').toLowerCase()
      const status = (job.status || '').toLowerCase()
      return scope.includes(q) || target.includes(q) || targets.includes(q) || type.includes(q) || id.includes(q) || status.includes(q)
    }
  }, [search, scopeFilter, hoursFilter, jobs])

  const active = jobs.filter(j => (j.status === 'running' || j.status === 'queued') && matchesFilter(j)).sort(byNewest)
  const completed = jobs.filter(j => (j.status === 'completed' || j.status === 'failed' || j.status === 'stopped' || j.status === 'lost') && matchesFilter(j))
    .sort((a, b) => new Date(b.completed_at ?? b.created_at ?? 0).getTime() - new Date(a.completed_at ?? a.created_at ?? 0).getTime())

  const { data: limitsData } = useQuery({
    queryKey: ['scan-limits'],
    queryFn: () => apiFetch<{ active: number; max: number; available: number; pending_queue: number }>('/scans/limits'),
    refetchInterval: 5000,
  })
  const limActive = limitsData?.active ?? 0
  const limMax = limitsData?.max ?? 5
  const limPending = limitsData?.pending_queue ?? 0

  const sessions = sessionsData?.sessions ?? []
  const activeSessions = sessions.filter(s => s.status === 'active')

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h2 className="text-lg font-semibold">Scan Monitor</h2>
          {/* Compact concurrency indicator */}
          <div className="flex items-center gap-2 px-3 py-1 bg-card border border-border rounded-lg">
            <Activity className="h-3.5 w-3.5 text-muted-foreground" />
            <div className="flex items-center gap-1.5">
              <span className={cn('text-sm font-medium', limActive >= limMax ? 'text-red-500' : limActive > 0 ? 'text-blue-400' : 'text-muted-foreground')}>
                {limActive}/{limMax}
              </span>
              <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                <div
                  className={cn('h-full rounded-full transition-all', limActive >= limMax ? 'bg-red-500' : limActive > 0 ? 'bg-blue-500' : 'bg-muted')}
                  style={{ width: `${limMax > 0 ? Math.round((limActive / limMax) * 100) : 0}%` }}
                />
              </div>
            </div>
            {limPending > 0 && (
              <span className="text-xs text-amber-500 font-medium" title={`${limPending} scans queued, auto-dispatching as slots open`}>
                +{limPending} queued
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a
            href="http://localhost:8000/webhooks/ui"
            target="_blank"
            rel="noopener noreferrer"
            className="px-3 py-1.5 border border-border text-muted-foreground hover:text-foreground rounded-md text-sm flex items-center gap-1.5 transition-colors"
          >
            <Radio className="h-3.5 w-3.5" />
            Webhooks
          </a>
          <Link to="/scans/launch" className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm">
            New Scan
          </Link>
        </div>
      </div>

      {/* AI Bulk Check Status */}
      <AiCheckStatus />

      {/* Search / Filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative">
          <Shield className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
          <select
            value={scopeFilter}
            onChange={e => setScopeFilter(e.target.value)}
            className={cn(
              'pl-8 pr-6 py-1.5 text-sm bg-background border rounded-md appearance-none cursor-pointer min-w-[160px]',
              scopeFilter ? 'border-purple-500/50 text-purple-400' : 'border-border text-muted-foreground',
            )}
          >
            <option value="">All Scopes</option>
            {allScopeNames.map(name => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
        </div>
        <div className="relative">
          <Clock className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
          <select
            value={hoursFilter}
            onChange={e => setHoursFilter(Number(e.target.value))}
            className={cn(
              'pl-8 pr-6 py-1.5 text-sm bg-background border rounded-md appearance-none cursor-pointer min-w-[140px]',
              hoursFilter !== 0 ? 'border-blue-500/50 text-blue-400' : 'border-border text-muted-foreground',
            )}
          >
            <option value={0}>All Time</option>
            <option value={1}>Last 1h</option>
            <option value={2}>Last 2h</option>
            <option value={4}>Last 4h</option>
            <option value={8}>Last 8h</option>
            <option value={12}>Last 12h</option>
            <option value={24}>Last 24h</option>
            <option value={48}>Last 48h</option>
            <option value={72}>Last 3 days</option>
            <option value={168}>Last 7 days</option>
            <option disabled>──────────</option>
            <option value={-1}>Next 1h</option>
            <option value={-4}>Next 4h</option>
            <option value={-12}>Next 12h</option>
            <option value={-24}>Next 24h</option>
            <option value={-48}>Next 48h</option>
            <option value={-168}>Next 7 days</option>
            <option value={-999}>All Scheduled</option>
          </select>
        </div>
        <div className="relative flex-1 min-w-[200px] max-w-[400px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search target, type, status, or job ID..."
            className="w-full pl-8 pr-8 py-1.5 text-sm bg-background border border-border rounded-md"
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
        {(scopeFilter || search || hoursFilter > 0) && (
          <button
            onClick={() => { setScopeFilter(''); setSearch(''); setHoursFilter(0) }}
            className="px-2 py-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            Clear filters
          </button>
        )}
      </div>

      {isLoading && <p className="text-sm text-muted-foreground">Loading...</p>}

      {/* Active Agent Sessions */}
      {activeSessions.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-muted-foreground mb-2">
            Agent Sessions ({activeSessions.length})
          </h3>
          <div className="space-y-2">
            {activeSessions.map(session => (
              <AgentSessionCard key={session.session_id} session={session} />
            ))}
          </div>
        </div>
      )}

      {/* Active Scans */}
      {active.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-muted-foreground mb-2">Active Scans ({active.length})</h3>
          <div className="space-y-2">
            {active.map(job => (
              <div key={job.job_id} className="bg-card border border-border rounded-lg p-3 flex items-center gap-3">
                <StatusDot status={job.status} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{job.type}</span>
                    <span className="text-xs text-muted-foreground font-mono">{job.job_id.slice(0, 8)}</span>
                    {job.scope_name && (
                      <span className="flex items-center gap-1 px-1.5 py-0.5 bg-purple-500/10 text-purple-400 text-[10px] rounded-full border border-purple-500/30" title={`Scope: ${job.scope_name}`}>
                        <Shield className="h-2.5 w-2.5" />
                        {job.scope_name}
                      </span>
                    )}
                  </div>
                  {(job.target || job.targets) && (
                    <p className="text-xs text-muted-foreground font-mono mt-0.5 truncate max-w-[400px]">
                      {typeof job.target === 'string' ? job.target : Array.isArray(job.targets) ? job.targets.map(String).slice(0, 3).join(', ') + (job.targets.length > 3 ? ` +${job.targets.length - 3} more` : '') : String(job.target || '')}
                      {(() => {
                        const tc = (job.progress as any)?.total_targets ?? (job.progress as any)?.targets_total ?? (job.last_data as any)?.total_targets ?? (Array.isArray(job.targets) ? job.targets.length : 0)
                        return tc > 1 ? ` (${tc} targets)` : ''
                      })()}
                    </p>
                  )}
                  {(job.last_data as any)?.command && (
                    <p className="text-[10px] text-muted-foreground font-mono mt-0.5 truncate max-w-[500px]" title={String((job.last_data as any).command)}>
                      $ {String((job.last_data as any).command)}
                    </p>
                  )}
                  {job.created_at && (
                    <span className="text-xs text-muted-foreground mt-0.5">Started {formatDate(job.created_at)}</span>
                  )}
                  {job.progress?.stage && (
                    <p className="text-xs text-muted-foreground mt-0.5">{job.progress.stage}</p>
                  )}
                </div>
                {job.proxy && (() => {
                  const proxyInfo = getProxyDetails(job.proxy, nodes)
                  return (
                    <span className="flex items-center gap-1 px-2 py-0.5 bg-blue-500/10 text-blue-400 text-[10px] rounded-full border border-blue-500/30"
                          title={proxyInfo?.fullDetails || job.proxy}>
                      <Wifi className="h-3 w-3" />
                      {proxyInfo?.displayText || 'Proxy'}
                    </span>
                  )
                })()}
                <div className="flex items-center gap-2">
                  <Link to={`/scans/${job.job_id}`} className="text-muted-foreground hover:text-foreground">
                    <ExternalLink className="h-4 w-4" />
                  </Link>
                  <button
                    onClick={() => stopScan.mutate(job.job_id)}
                    className="p-1 text-red-500 hover:bg-red-500/10 rounded"
                    title="Stop scan"
                  >
                    <Square className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scheduled Scans */}
      {(() => {
        const now = Date.now()
        const futureCutoff = hoursFilter < 0
          ? (hoursFilter === -999 ? Infinity : now + Math.abs(hoursFilter) * 3600_000)
          : Infinity  // show all scheduled when not filtering future
        const showScheduled = hoursFilter <= 0  // show when "All Time" or any future filter
        const scheduled = (scheduledData?.scheduled_scans ?? [])
          .filter(s => s.status === 'pending' && showScheduled)
          .filter(s => new Date(s.scheduled_at).getTime() <= futureCutoff)
          .sort((a, b) => new Date(a.scheduled_at).getTime() - new Date(b.scheduled_at).getTime())
        if (scheduled.length === 0) return null

        const formatCountdown = (dt: string) => {
          const diff = new Date(dt).getTime() - Date.now()
          if (diff <= 0) return 'imminent'
          const mins = Math.floor(diff / 60000)
          if (mins < 60) return `${mins}m`
          const hrs = Math.floor(mins / 60)
          if (hrs < 24) return `${hrs}h ${mins % 60}m`
          return `${Math.floor(hrs / 24)}d ${hrs % 24}h`
        }

        return (
          <div>
            <h3 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-1.5">
              <CalendarClock className="h-3.5 w-3.5" />
              Scheduled ({scheduled.length})
            </h3>
            <div className="space-y-1">
              {scheduled.map(s => {
                const targetsObj = s.targets || {}
                const targetList = (targetsObj as any).targets || (targetsObj as any).domains || []
                const targetStr = Array.isArray(targetList)
                  ? targetList.map(String).slice(0, 3).join(', ') + (targetList.length > 3 ? ` +${targetList.length - 3}` : '')
                  : String((targetsObj as any).target || (targetsObj as any).target_url || '')
                return (
                  <div key={s.id} className="py-2 px-3 rounded-md bg-card border border-dashed border-border flex items-center gap-3">
                    <Timer className="h-4 w-4 text-amber-500 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{s.scan_type}</span>
                        <span className="text-xs text-muted-foreground font-mono">{s.id.slice(0, 8)}</span>
                        {targetStr && (
                          <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[250px]">
                            {targetStr}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-0.5">
                        <span className="text-xs text-muted-foreground">
                          {formatDate(s.scheduled_at)}
                        </span>
                        {s.jitter_seconds > 0 && (
                          <span className="text-[10px] text-muted-foreground">
                            ±{s.jitter_seconds}s jitter
                          </span>
                        )}
                        {s.max_rate && (
                          <span className="text-[10px] text-muted-foreground">
                            rate: {s.max_rate}/s
                          </span>
                        )}
                      </div>
                    </div>
                    <span className="px-2 py-0.5 bg-amber-500/10 text-amber-500 text-xs rounded-full border border-amber-500/30 shrink-0">
                      in {formatCountdown(s.scheduled_at)}
                    </span>
                    <button
                      onClick={() => { if (window.confirm(`Cancel scheduled ${s.scan_type} scan?`)) cancelScheduled.mutate(s.id) }}
                      className="p-1 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded shrink-0"
                      title="Cancel scheduled scan"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )
              })}
            </div>
          </div>
        )
      })()}

      {/* Completed Scans — hidden when viewing future scheduled only */}
      {hoursFilter >= 0 && <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-medium text-muted-foreground">
            History ({completed.length})
          </h3>
          {completed.length > 0 && (
            <button
              onClick={() => {
                if (window.confirm(`Delete all ${completed.length} completed/failed scans from history?`))
                  clearHistory.mutate()
              }}
              disabled={clearHistory.isPending}
              className="flex items-center gap-1 px-2 py-1 text-xs text-red-500 hover:bg-red-500/10 rounded-md transition-colors disabled:opacity-50"
            >
              <Trash2 className="h-3 w-3" />
              {clearHistory.isPending ? 'Clearing...' : 'Clear History'}
            </button>
          )}
        </div>
        <div className="space-y-1">
          {completed.map(job => {
            const isMasscanStopped = job.status === 'stopped' &&
              ((job.type || '').includes('masscan') || job.type === 'nmap' || job.type === 'full')
            return (
              <div key={job.job_id} className="py-2 px-3 rounded-md hover:bg-muted/50 transition-colors">
                <Link
                  to={`/scans/${job.job_id}`}
                  className="flex items-center gap-3 flex-1 min-w-0"
                >
                  <StatusDot status={job.status} />
                  <span className="text-sm">{job.type}</span>
                  <span className="text-xs text-muted-foreground font-mono">{job.job_id.slice(0, 8)}</span>
                  {job.scope_name && (
                    <span className="flex items-center gap-1 px-1.5 py-0.5 bg-purple-500/10 text-purple-400 text-[10px] rounded-full border border-purple-500/30 shrink-0" title={`Scope: ${job.scope_name}`}>
                      <Shield className="h-2.5 w-2.5" />
                      {job.scope_name}
                    </span>
                  )}
                  {(job.target || job.targets) && (
                    <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[250px]" title={typeof job.target === 'string' ? job.target : Array.isArray(job.targets) ? job.targets.map(String).join(', ') : undefined}>
                      {typeof job.target === 'string' ? job.target : Array.isArray(job.targets) ? job.targets.map(String).slice(0, 2).join(', ') + (job.targets.length > 2 ? ` +${job.targets.length - 2}` : '') : String(job.target || '')}
                      {(() => {
                        const tc = (job.progress as any)?.total_targets ?? (job.progress as any)?.targets_total ?? (job.last_data as any)?.total_targets ?? (Array.isArray(job.targets) ? job.targets.length : 0)
                        return tc > 1 ? ` (${tc})` : ''
                      })()}
                    </span>
                  )}
                  {job.proxy && (() => {
                    const proxyInfo = getProxyDetails(job.proxy, nodes)
                    return (
                      <span className="flex items-center gap-1 px-1.5 py-0.5 bg-blue-500/10 text-blue-400 text-[10px] rounded-full border border-blue-500/30"
                            title={proxyInfo?.fullDetails || job.proxy}>
                        <Wifi className="h-2.5 w-2.5" />
                        {proxyInfo?.displayText || 'Proxy'}
                      </span>
                    )
                  })()}
                  <span className="text-xs text-muted-foreground flex-1">
                    {job.completed_at ? formatDate(job.completed_at) : job.created_at ? formatDate(job.created_at) : ''}
                  </span>
                  <span className={cn(
                    'text-xs',
                    job.status === 'completed' ? 'text-green-500' : job.status === 'failed' ? 'text-red-500' : 'text-yellow-500',
                  )}>
                    {job.status}
                  </span>
                </Link>
                {(job.last_data as any)?.command && (
                  <p className="text-[10px] text-muted-foreground font-mono truncate ml-7 -mt-1 mb-0.5 max-w-[600px]" title={String((job.last_data as any).command)}>
                    $ {String((job.last_data as any).command)}
                  </p>
                )}
                {isMasscanStopped && (
                  <button
                    onClick={() => resumeScan.mutate(job.job_id, {
                      onSuccess: (res) => { if (res.job_id) navigate(`/scans/${res.job_id}`) },
                    })}
                    className="p-1 text-green-500 hover:bg-green-500/10 rounded"
                    title="Resume scan"
                  >
                    <Play className="h-4 w-4" />
                  </button>
                )}
                <button
                  onClick={() => deleteScan.mutate(job.job_id)}
                  className="p-1 text-muted-foreground hover:text-red-500 hover:bg-red-500/10 rounded"
                  title="Delete from history"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            )
          })}
          {completed.length === 0 && (
            <p className="text-sm text-muted-foreground py-4 text-center">No completed scans</p>
          )}
        </div>
      </div>}
    </div>
  )
}


function AiCheckStatus() {
  const [status, setStatus] = useState<any>(null)

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const resp = await fetch('/api/software/bulk-check/status')
        if (resp.ok) setStatus(await resp.json())
      } catch {}
    }
    fetchStatus()
    const poll = setInterval(fetchStatus, 2000)
    return () => clearInterval(poll)
  }, [])

  const isRunning = status?.running === true
  const wasCancelled = status?.cancelled === true
  const p = status?.progress || {}
  const hasProgress = (p.total || 0) > 0
  const pct = p.total ? Math.round(((p.completed || 0) / p.total) * 100) : 0
  const isDone = !isRunning && hasProgress && (p.completed || 0) >= (p.total || 1)

  return (
    <div className={`border rounded-lg p-3 ${isRunning ? 'border-purple-500/50 bg-purple-500/5' : 'border-border bg-card'}`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isRunning ? (
            <div className="h-3.5 w-3.5 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
          ) : (
            <Search className="h-3.5 w-3.5 text-purple-400" />
          )}
          <span className={`text-sm font-medium ${isRunning ? 'text-purple-400' : 'text-muted-foreground'}`}>
            AI Exploit Check
          </span>
          {isRunning && (
            <span className="text-xs text-purple-300">
              {p.completed || 0}/{p.total || '?'} products
              {p.skipped ? ` (${p.skipped} skipped)` : ''}
            </span>
          )}
          {isDone && (
            <span className="text-xs text-green-400">
              Done: {p.completed}/{p.total} checked
              {p.skipped ? `, ${p.skipped} skipped` : ''}
            </span>
          )}
          {wasCancelled && !isRunning && <span className="text-xs text-yellow-400">Cancelled at {p.completed}/{p.total}</span>}
          {!isRunning && !hasProgress && (
            <span className="text-xs text-muted-foreground">
              Ready — select products on Software tab to check
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {(p.flagged || 0) > 0 && <span className="text-xs text-red-400 font-medium">{p.flagged} flagged</span>}
          {(p.errors || 0) > 0 && <span className="text-xs text-yellow-400">{p.errors} errors</span>}
          {isRunning && (
            <button onClick={async () => {
              await fetch('/api/software/bulk-check/cancel', { method: 'POST' })
            }} className="px-2 py-0.5 text-[10px] rounded border border-red-500/40 text-red-400 hover:bg-red-500/10">
              Cancel
            </button>
          )}
          <Link to="/assets" className="px-2 py-0.5 text-[10px] rounded border border-purple-500/40 text-purple-400 hover:bg-purple-500/10">
            Software Tab
          </Link>
        </div>
      </div>
      {isRunning && (p.total || 0) > 0 && (
        <div className="mt-2 space-y-1">
          <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
            <div className="h-full bg-purple-500 rounded-full transition-all" style={{ width: `${pct}%` }} />
          </div>
          {p.stage && p.stage !== 'Cancelled' && (
            <p className="text-[10px] text-purple-300 truncate">{p.stage}</p>
          )}
          {p.current && p.current !== p.stage && p.current !== 'Cancelled' && (
            <p className="text-[10px] text-muted-foreground truncate">Product: {p.current}</p>
          )}
          {p.stages_run && (
            <div className="flex gap-3 text-[9px] text-muted-foreground">
              {p.stages_run.searchsploit > 0 && <span>SearchSploit: {p.stages_run.searchsploit}</span>}
              {p.stages_run.nvd > 0 && <span>NVD: {p.stages_run.nvd}</span>}
              {p.stages_run.ddg > 0 && <span>DDG: {p.stages_run.ddg}</span>}
              {p.stages_run.cve_cache > 0 && <span>Cache: {p.stages_run.cve_cache}</span>}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
