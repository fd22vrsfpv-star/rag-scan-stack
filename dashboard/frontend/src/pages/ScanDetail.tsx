import { useState, useMemo } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useScanDetail, useStopScan, useResumeScan, useScanAudit, usePortSummary, useNmapResumeInfo, useNmapResume } from '@/api/scans'
import { useEngagements } from '@/api/engagements'
import { StatusDot } from '@/components/common/StatusDot'
import { JsonViewer } from '@/components/common/JsonViewer'
import { ArrowLeft, Square, Play, Wifi, Briefcase, Target, Globe, Terminal, FileText, Clock } from 'lucide-react'
import { SourceBadge } from '@/components/common/SourceBadge'
import { formatDate } from '@/lib/utils'

type Tab = 'overview' | 'commands' | 'results'

// Keys that are structural/not useful as scan metrics
const RESULT_SKIP_KEYS = new Set(['ok', 'report', 'ingest', 'no_ingest', 'raw_output', 'stdout', 'stderr', 'command', 'masscan_out'])
const AUDIT_SKIP_KEYS = new Set(['timestamp', 'event', 'scan_type', 'source', 'job_id', 'hostname', 'external_ip', 'content_intel'])

export default function ScanDetail() {
  const { jobId } = useParams<{ jobId: string }>()
  const { data, isLoading, error } = useScanDetail(jobId || '')
  const stopScan = useStopScan()
  const resumeScan = useResumeScan()
  const navigate = useNavigate()
  const engagementsQuery = useEngagements()
  const engagements = engagementsQuery.data?.engagements ?? []
  const auditQuery = useScanAudit(jobId || '')
  const [tab, setTab] = useState<Tab>('overview')

  // Hooks below MUST be called unconditionally (React rules of hooks).
  // Pre-compute eligibility from `data` if present, gate via query `enabled`.
  const _type = (data?.type || '')
  const _status = data?.status || ''
  const _isActive = _status === 'running' || _status === 'queued'
  // Resume eligibility — only the TCP/full nmap variants. UDP isn't worth resuming
  // (per-port responses are quick once filtered) and masscan has its own paused.conf flow.
  const _isResumableNmap = /^(nmap|nmap-tcp|nmap-resume|full|masscan-then-nmap)$/.test(_type)
  const canTryNmapResume = _isResumableNmap && !_isActive && _status !== 'completed'
  const nmapResumeInfo = useNmapResumeInfo(jobId, canTryNmapResume)
  const nmapResume = useNmapResume()
  // Port-scan summary hook also unconditional — its own `enabled` flag handles non-port-scan types
  const _isPortScan = /(nmap|masscan|full)/.test(_type)
  const { data: portSummaryData } = usePortSummary(_isPortScan)
  const _r = (data?.result ?? null) as Record<string, unknown> | null
  const portStats = useMemo(() => {
    if (!_isPortScan || !_r) return null
    const stats = _r.stats as Record<string, unknown> | undefined
    if (!stats) return null
    return {
      hostsScanned: Number(stats.hosts_scanned ?? stats.total_hosts ?? 0),
      hostsWithPorts: Number(stats.hosts_with_ports ?? stats.hosts_up ?? 0),
      totalPorts: Number(stats.total_ports ?? stats.open_ports ?? 0),
      portDetails: stats.port_details as Array<Record<string, unknown>> | undefined,
    }
  }, [_isPortScan, _r])

  // Filter the global /ports/summary by the scan's own targets so the
  // "Open Ports by Host" block doesn't leak unrelated hosts. Handles plain
  // IPs, CIDRs, and hostname/URL targets.
  const _params = data?.params ?? {}
  const _rawTargets: string[] =
    Array.isArray(_params.targets) ? (_params.targets as string[]) :
    Array.isArray(_params.domains) ? (_params.domains as string[]) :
    _params.target ? [_params.target as string] :
    _params.target_url ? [_params.target_url as string] :
    _params.query ? [_params.query as string] :
    _params.domain ? [_params.domain as string] : []
  const scanTargets = useMemo(() => _rawTargets.map(t => String(t).trim()).filter(Boolean), [_rawTargets])
  const byHostScoped = useMemo(() => {
    const all = portSummaryData?.by_host || []
    if (!_isPortScan || all.length === 0 || scanTargets.length === 0) return all
    const exactIps = new Set<string>()
    const hostnameSubstr: string[] = []
    const cidrs: { net: bigint; mask: bigint; bits: number }[] = []
    const ipv4ToBig = (ip: string): bigint | null => {
      const p = ip.split('.')
      if (p.length !== 4) return null
      let n = 0n
      for (const oct of p) {
        const v = Number(oct)
        if (!Number.isFinite(v) || v < 0 || v > 255) return null
        n = (n << 8n) | BigInt(v)
      }
      return n
    }
    for (const raw of scanTargets) {
      const t = raw.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '')
      if (t.includes('/')) {
        // CIDR
        const [ip, bitsStr] = t.split('/')
        const big = ipv4ToBig(ip)
        const bits = Number(bitsStr)
        if (big !== null && Number.isFinite(bits) && bits >= 0 && bits <= 32) {
          const mask = bits === 0 ? 0n : ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - bits)) - 1n)
          cidrs.push({ net: big & mask, mask, bits })
          continue
        }
      }
      const ipBig = ipv4ToBig(t)
      if (ipBig !== null) {
        exactIps.add(t)
      } else if (t) {
        hostnameSubstr.push(t.toLowerCase())
      }
    }
    return all.filter(h => {
      if (h.ip && exactIps.has(h.ip)) return true
      const ipBig = h.ip ? ipv4ToBig(h.ip) : null
      if (ipBig !== null) {
        for (const c of cidrs) {
          if ((ipBig & c.mask) === c.net) return true
        }
      }
      if (h.hostname) {
        const hn = h.hostname.toLowerCase()
        if (hostnameSubstr.some(s => hn === s || hn.endsWith('.' + s))) return true
      }
      return false
    })
  }, [_isPortScan, portSummaryData, scanTargets])

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading...</p>
  if (error) return <p className="text-sm text-red-500">Error: {String(error)}</p>
  if (!data || (!data.job_id && !data.type)) return <p className="text-sm text-muted-foreground">Job not found</p>

  // Safety: ensure all top-level string fields are actually strings
  // (prevents React #310 "Objects are not valid as React child")
  const safeStr = (v: unknown): string =>
    v == null ? '' : typeof v === 'string' ? v : typeof v === 'object' ? JSON.stringify(v) : String(v)

  const isActive = _isActive
  const isStopped = data.status === 'stopped'
  const isMasscanType = (data.type || '').includes('masscan') || data.type === 'nmap' || data.type === 'full'

  // Extract targets from params
  const params = data.params ?? {}
  const targets: string[] = Array.isArray(params.targets)
    ? params.targets
    : Array.isArray(params.domains)
      ? params.domains
      : params.target ? [params.target as string]
        : params.target_url ? [params.target_url as string]
          : params.query ? [params.query as string]
            : params.domain ? [params.domain as string]
              : []

  // Proxy info
  const proxyUrl = data.proxy || (params.proxy as string) || null

  // Engagement & Scope
  const engagementId = data.engagement_id || null
  const engagement = engagementId ? engagements.find(e => e.id === engagementId) : null
  const scopeName = data.scope_name || (params.scope_name as string) || null

  // Duration
  const r = data.result as Record<string, unknown> | null
  const elapsed: number | null = (
    r && 'elapsed_sec' in r ? Number(r.elapsed_sec)
      : r && 'duration_s' in r ? Number(r.duration_s)
        : data.created_at && data.completed_at
          ? (new Date(data.completed_at).getTime() - new Date(data.created_at).getTime()) / 1000
          : null
  )

  // Helper: extract string values from result safely
  const rStdout = r ? String(r['stdout'] || '') : ''
  const rStderr = r ? String(r['stderr'] || '') : ''
  const hasOutput = !!(rStdout || rStderr)

  // Commands — from progress.commands array, result, progress, or audit
  const auditEntries = auditQuery.data?.entries ?? []
  const commandFromResult = r?.command ? String(r.command) : null
  const commandFromProgress = data.progress?.command ?? null
  const commandFromAudit = auditEntries.find(e => e['command'])?.['command'] as string | null
  const primaryCommand = commandFromResult || commandFromProgress || commandFromAudit

  // Pipeline commands array (live-updated as each stage runs)
  type CmdEntry = { stage: string; command: string; ts: string }
  const pipelineCommands: CmdEntry[] = (data.progress as Record<string, unknown>)?.commands as CmdEntry[] ?? []

  // Extract numeric metrics from result for overview display
  const resultMetrics: { label: string; value: string }[] = []
  if (r && typeof r === 'object') {
    for (const [k, v] of Object.entries(r)) {
      if (RESULT_SKIP_KEYS.has(k)) continue
      if (typeof v === 'number') {
        resultMetrics.push({ label: k.replace(/_/g, ' '), value: String(v) })
      } else if (typeof v === 'string' && v.length < 100 && !v.startsWith('/') && !v.startsWith('{')) {
        resultMetrics.push({ label: k.replace(/_/g, ' '), value: v })
      } else if (typeof v === 'boolean') {
        resultMetrics.push({ label: k.replace(/_/g, ' '), value: v ? 'yes' : 'no' })
      }
    }
  }

  // (port scan summary + portStats now computed above as unconditional hooks)
  const isPortScan = _isPortScan

  // Scan config options (non-target params)
  const scanConfig = Object.entries(params).filter(([k]) =>
    !['targets', 'domains', 'target', 'target_url', 'query', 'domain', 'proxy', 'scope_name', 'engagement_id'].includes(k)
  )

  const tabs: { id: Tab; label: string; icon: React.ReactNode; badge?: number }[] = [
    { id: 'overview', label: 'Overview', icon: <FileText className="h-3.5 w-3.5" /> },
    { id: 'commands', label: 'Commands & Audit', icon: <Terminal className="h-3.5 w-3.5" />, badge: auditEntries.length },
    { id: 'results', label: 'Results', icon: <Globe className="h-3.5 w-3.5" /> },
  ]

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link to="/scans" className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" />
        </Link>
        <h2 className="text-lg font-semibold">Scan Detail</h2>
        <span className="px-2 py-0.5 bg-muted text-xs font-mono rounded">{safeStr(data.type) || 'unknown'}</span>
        <div className="flex-1" />
        {isActive && (
          <button
            onClick={() => stopScan.mutate(jobId!)}
            className="flex items-center gap-2 px-3 py-1.5 bg-destructive text-destructive-foreground rounded-md text-sm"
          >
            <Square className="h-3.5 w-3.5" /> Stop Scan
          </button>
        )}
        {isStopped && isMasscanType && (
          <button
            onClick={() =>
              resumeScan.mutate(jobId!, {
                onSuccess: (res) => {
                  if (res.job_id) navigate(`/scans/${res.job_id}`)
                },
              })
            }
            disabled={resumeScan.isPending}
            className="flex items-center gap-2 px-3 py-1.5 bg-green-600 text-white rounded-md text-sm hover:bg-green-700 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            {resumeScan.isPending ? 'Resuming...' : 'Resume Scan'}
          </button>
        )}
        {canTryNmapResume && nmapResumeInfo.data?.resumable && (
          <button
            onClick={() =>
              nmapResume.mutate(
                { job_id: jobId },
                { onSuccess: (res) => { if (res.job_id) navigate(`/scans/${res.job_id}`) } },
              )
            }
            disabled={nmapResume.isPending}
            className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700 disabled:opacity-50"
            title={`Resume from ${nmapResumeInfo.data.log_bases.length} log file(s)`}
          >
            <Play className="h-3.5 w-3.5" />
            {nmapResume.isPending ? 'Resuming nmap...' : `Resume Nmap (${nmapResumeInfo.data.log_bases.length})`}
          </button>
        )}
      </div>
      {resumeScan.error && <p className="text-xs text-red-500">{String(resumeScan.error)}</p>}
      {nmapResume.error && <p className="text-xs text-red-500">{String(nmapResume.error)}</p>}

      {/* Scope / Sites / Context card */}
      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Target className="h-4 w-4 text-cyan-400" />
          Scope & Targets
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full border"
            style={{
              borderColor: data.status === 'completed' ? 'rgba(34,197,94,0.3)' : data.status === 'failed' ? 'rgba(239,68,68,0.3)' : 'rgba(59,130,246,0.3)',
              backgroundColor: data.status === 'completed' ? 'rgba(34,197,94,0.1)' : data.status === 'failed' ? 'rgba(239,68,68,0.1)' : 'rgba(59,130,246,0.1)',
              color: data.status === 'completed' ? '#22c55e' : data.status === 'failed' ? '#ef4444' : '#3b82f6',
            }}
          >
            <StatusDot status={data.status} />
            {data.status}
          </span>
          {scopeName && (
            <span className="flex items-center gap-1.5 px-2.5 py-1 bg-cyan-500/10 text-cyan-400 text-xs rounded-full border border-cyan-500/30">
              <Globe className="h-3 w-3" />Scope: {scopeName}
            </span>
          )}
          {engagement && (
            <Link to="/engagements" className="flex items-center gap-1.5 px-2.5 py-1 bg-purple-500/10 text-purple-400 text-xs rounded-full border border-purple-500/30 hover:bg-purple-500/20 transition-colors">
              <Briefcase className="h-3 w-3" />{engagement.name}
            </Link>
          )}
          {proxyUrl && (
            <span className="flex items-center gap-1.5 px-2.5 py-1 bg-blue-500/10 text-blue-400 text-xs rounded-full border border-blue-500/30">
              <Wifi className="h-3 w-3" />
              {proxyUrl.includes('ssh-tunnel') ? 'SSH Tunnel' : 'SOCKS Proxy'}: {proxyUrl.replace(/^socks[45]:\/\//, '')}
            </span>
          )}
        </div>

        {targets.length > 0 && (
          <div>
            <span className="text-xs text-muted-foreground">Targets ({targets.length})</span>
            <div className="flex flex-wrap gap-1.5 mt-1">
              {targets.slice(0, 30).map((t, i) => (
                <span key={i} className="px-2 py-0.5 bg-muted text-xs font-mono rounded border border-border">{String(t)}</span>
              ))}
              {targets.length > 30 && <span className="px-2 py-0.5 text-xs text-muted-foreground">+{targets.length - 30} more</span>}
            </div>
          </div>
        )}

        {scanConfig.length > 0 && (
          <div className="pt-2 border-t border-border">
            <span className="text-xs text-muted-foreground">Scan Options</span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-1">
              {scanConfig.map(([k, v]) => (
                <div key={k} className="text-xs">
                  <span className="text-muted-foreground">{k}: </span>
                  <span className="font-mono">{typeof v === 'boolean' ? (v ? 'on' : 'off') : String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-sm transition-colors border-b-2 ${
              tab === t.id ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {t.icon}
            {t.label}
            {t.badge ? <span className="ml-1 px-1.5 py-0.5 bg-muted text-[10px] rounded-full">{t.badge}</span> : null}
          </button>
        ))}
      </div>

      {/* ═══════════ Overview Tab ═══════════ */}
      {tab === 'overview' && (
        <div className="space-y-4">
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-xs text-muted-foreground">Job ID</span>
                <p className="font-mono text-xs">{data.job_id || jobId}</p>
              </div>
              {data.created_at && (
                <div>
                  <span className="text-xs text-muted-foreground">Started</span>
                  <p className="text-xs">{formatDate(data.created_at)}</p>
                </div>
              )}
              {data.completed_at && (
                <div>
                  <span className="text-xs text-muted-foreground">Completed</span>
                  <p className="text-xs">{formatDate(data.completed_at)}</p>
                </div>
              )}
              {elapsed != null && (
                <div>
                  <span className="text-xs text-muted-foreground">Duration</span>
                  <p className="text-xs">{elapsed < 60 ? `${elapsed.toFixed(1)}s` : `${(elapsed / 60).toFixed(1)}m`}</p>
                </div>
              )}
              {data.progress?.stage && (
                <div>
                  <span className="text-xs text-muted-foreground">Stage</span>
                  <p className="text-xs">{safeStr(data.progress.stage)}</p>
                </div>
              )}
              {(params.ports as string) && (
                <div>
                  <span className="text-xs text-muted-foreground">Ports</span>
                  <p className="text-xs font-mono">{String(params.ports)}</p>
                </div>
              )}
            </div>
          </div>

          {/* Result metrics — works for ALL scan types */}
          {resultMetrics.length > 0 && (
            <div className="bg-card border border-border rounded-lg p-4">
              <h3 className="text-xs font-semibold text-muted-foreground mb-3">Scan Results</h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {resultMetrics.map(m => (
                  <div key={m.label} className="bg-muted rounded p-2.5">
                    <span className="text-[10px] text-muted-foreground capitalize">{m.label}</span>
                    <p className="text-sm font-semibold">{m.value}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Port scan summary — only show for completed scans, from result stats or global summary */}
          {isPortScan && data.status === 'completed' && (portStats?.totalPorts || byHostScoped.length > 0) ? (
            <div className="bg-card border border-orange-500/30 rounded-lg p-4">
              <h3 className="text-xs font-semibold text-orange-400 mb-3">Port Scan Results</h3>
              <div className="grid grid-cols-3 gap-3 mb-3">
                <div className="bg-muted rounded p-2.5 text-center">
                  <div className="text-xl font-bold">{portStats?.hostsScanned || targets.length}</div>
                  <div className="text-[10px] text-muted-foreground">Hosts Scanned</div>
                </div>
                <div className="bg-muted rounded p-2.5 text-center">
                  <div className="text-xl font-bold text-green-400">{portStats?.hostsWithPorts || byHostScoped.length}</div>
                  <div className="text-[10px] text-muted-foreground">Hosts with Open Ports</div>
                </div>
                <div className="bg-muted rounded p-2.5 text-center">
                  <div className="text-xl font-bold text-primary">{portStats?.totalPorts || byHostScoped.reduce((sum, h) => sum + (h.open_ports || 0), 0)}</div>
                  <div className="text-[10px] text-muted-foreground">Total Open Ports</div>
                </div>
              </div>
              {byHostScoped && byHostScoped.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-medium text-muted-foreground mb-1.5">
                    Open Ports by Host
                    <span className="text-muted-foreground ml-1">(this scan&apos;s targets only)</span>
                  </h4>
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {byHostScoped.map((h, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs bg-muted/50 rounded px-2 py-1">
                        <span className="font-mono font-medium w-32 shrink-0">{h.ip}</span>
                        <span className="text-muted-foreground truncate flex-1">{h.hostname || '-'}</span>
                        <span className="font-mono text-primary">{h.open_ports} ports</span>
                        <span className="text-[10px] text-muted-foreground truncate max-w-[200px]">{Array.isArray(h.ports) ? h.ports.join(', ') : safeStr(h.ports)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : isPortScan && data.status === 'running' ? (
            <div className="bg-card border border-blue-500/30 rounded-lg p-3">
              <div className="flex items-center gap-2 text-sm">
                <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
                <span className="text-blue-400 font-medium">Port scan in progress...</span>
                <span className="text-xs text-muted-foreground">Results will appear when the scan completes.</span>
              </div>
            </div>
          ) : null}

          {/* Command preview — quick glance */}
          {primaryCommand && (
            <div className="bg-card border border-border rounded-lg p-3">
              <h3 className="text-xs font-semibold text-muted-foreground mb-1.5">Command</h3>
              <pre className="text-xs font-mono bg-background rounded p-2 border border-border whitespace-pre-wrap break-all">{primaryCommand}</pre>
            </div>
          )}

          {/* Stdout / Stderr */}
          {hasOutput ? (
            <div className="bg-card border border-border rounded-lg p-3 space-y-2">
              <h3 className="text-xs font-semibold text-muted-foreground">Tool Output</h3>
              {rStdout ? (
                <div>
                  <span className="text-[10px] text-muted-foreground">stdout</span>
                  <pre className="text-xs font-mono bg-background rounded p-2 border border-border max-h-40 overflow-y-auto whitespace-pre-wrap">{rStdout}</pre>
                </div>
              ) : null}
              {rStderr ? (
                <div>
                  <span className="text-[10px] text-red-400">stderr</span>
                  <pre className="text-xs font-mono bg-red-500/5 rounded p-2 border border-red-500/20 max-h-40 overflow-y-auto whitespace-pre-wrap text-red-400">{rStderr}</pre>
                </div>
              ) : null}
            </div>
          ) : null}

          {data.error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
              <h3 className="text-sm font-semibold text-red-500 mb-1">Error</h3>
              <pre className="text-xs text-red-400 whitespace-pre-wrap">{typeof data.error === 'string' ? data.error : JSON.stringify(data.error, null, 2)}</pre>
            </div>
          )}
        </div>
      )}

      {/* ═══════════ Commands & Audit Tab ═══════════ */}
      {tab === 'commands' && (
        <div className="space-y-4">
          {/* Pipeline commands (live-updated per stage) */}
          {pipelineCommands.length > 0 && (
            <div className="bg-card border border-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-semibold text-muted-foreground">
                  Commands Run ({pipelineCommands.length} stages)
                </h3>
                <button
                  onClick={() => {
                    const all = pipelineCommands.map(c => `# --- ${c.stage} ---\n${c.command}`).join('\n\n')
                    navigator.clipboard.writeText(all)
                  }}
                  className="px-2 py-1 text-[10px] bg-muted hover:bg-muted/80 rounded border border-border transition-colors"
                >
                  Copy All
                </button>
              </div>
              <div className="space-y-2">
                {pipelineCommands.map((cmd, i) => (
                  <div key={i} className="group">
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          i < pipelineCommands.length - 1 || data.status === 'completed' ? 'bg-green-500' : 'bg-blue-500 animate-pulse'
                        }`} />
                        <span className="text-xs font-semibold">{cmd.stage}</span>
                        <span className="text-[10px] text-muted-foreground">{formatDate(cmd.ts)}</span>
                      </div>
                      <button
                        onClick={() => navigator.clipboard.writeText(cmd.command)}
                        className="px-2 py-0.5 text-[10px] bg-muted hover:bg-muted/80 rounded border border-border opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        Copy
                      </button>
                    </div>
                    <pre className="text-xs font-mono bg-background rounded p-2 border border-border whitespace-pre-wrap break-all select-all cursor-text">{cmd.command}</pre>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Single command (non-pipeline scans) */}
          {pipelineCommands.length === 0 && primaryCommand && (
            <div className="bg-card border border-border rounded-lg p-3">
              <div className="flex items-center justify-between mb-1.5">
                <h3 className="text-xs font-semibold text-muted-foreground">Command Executed</h3>
                <button
                  onClick={() => navigator.clipboard.writeText(primaryCommand)}
                  className="px-2 py-0.5 text-[10px] bg-muted hover:bg-muted/80 rounded border border-border transition-colors"
                >
                  Copy
                </button>
              </div>
              <pre className="text-xs font-mono bg-background rounded p-2 border border-border whitespace-pre-wrap break-all select-all cursor-text">{primaryCommand}</pre>
            </div>
          )}

          {/* Scan parameters */}
          {scanConfig.length > 0 && (
            <div className="bg-card border border-border rounded-lg p-3">
              <h3 className="text-xs font-semibold text-muted-foreground mb-1.5">Scan Parameters</h3>
              <div className="bg-background rounded p-2 border border-border text-xs font-mono space-y-0.5">
                {scanConfig.map(([k, v]) => (
                  <div key={k}>
                    <span className="text-muted-foreground">{k}=</span>
                    <span>{typeof v === 'boolean' ? (v ? 'true' : 'false') : typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Stdout / Stderr */}
          {hasOutput ? (
            <div className="bg-card border border-border rounded-lg p-3 space-y-2">
              <h3 className="text-xs font-semibold text-muted-foreground">Tool Output</h3>
              {rStdout ? (
                <div>
                  <span className="text-[10px] text-muted-foreground">stdout</span>
                  <pre className="text-xs font-mono bg-background rounded p-2 border border-border max-h-60 overflow-y-auto whitespace-pre-wrap">{rStdout}</pre>
                </div>
              ) : null}
              {rStderr ? (
                <div>
                  <span className="text-[10px] text-red-400">stderr</span>
                  <pre className="text-xs font-mono bg-red-500/5 rounded p-2 border border-red-500/20 max-h-60 overflow-y-auto whitespace-pre-wrap text-red-400">{rStderr}</pre>
                </div>
              ) : null}
            </div>
          ) : null}

          {/* Audit trail timeline */}
          <div className="bg-card border border-border rounded-lg p-4">
            <h3 className="text-xs font-semibold text-muted-foreground mb-3">
              Audit Trail ({auditEntries.length} events)
            </h3>
            {auditEntries.length === 0 ? (
              <p className="text-xs text-muted-foreground">No audit entries found for this job.</p>
            ) : (
              <div className="space-y-3">
                {auditEntries.map((entry, i) => (
                  <div key={i} className="flex gap-3 text-xs">
                    <div className="flex flex-col items-center">
                      <div className={`w-2.5 h-2.5 rounded-full mt-1 ${
                        entry.event.includes('completed') ? 'bg-green-500' :
                        entry.event.includes('failed') ? 'bg-red-500' :
                        entry.event.includes('started') ? 'bg-blue-500' : 'bg-gray-500'
                      }`} />
                      {i < auditEntries.length - 1 && <div className="w-px flex-1 bg-border mt-1" />}
                    </div>
                    <div className="flex-1 pb-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-semibold">{entry.event}</span>
                        <span className="text-muted-foreground flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {formatDate(entry.timestamp)}
                        </span>
                      </div>
                      <div className="bg-muted rounded p-2 space-y-1">
                        <div className="flex items-center gap-1"><span className="text-muted-foreground">Source:</span> <SourceBadge source={entry.source} /></div>
                        {entry['command'] ? (
                          <div>
                            <span className="text-muted-foreground">Command: </span>
                            <code className="bg-background px-1 py-0.5 rounded text-[10px] border border-border break-all">{String(entry['command'])}</code>
                          </div>
                        ) : null}
                        {entry['execution_mode'] ? (
                          <div><span className="text-muted-foreground">Execution: </span>{String(entry['execution_mode'])}</div>
                        ) : null}
                        {entry['proxy'] ? (
                          <div><span className="text-muted-foreground">Proxy: </span>{String(entry['proxy'])}</div>
                        ) : null}
                        {entry['node_id'] ? (
                          <div><span className="text-muted-foreground">Node: </span><span className="font-mono">{String(entry['node_id'])}</span></div>
                        ) : null}
                        {entry['target_url'] ? (
                          <div><span className="text-muted-foreground">Target: </span>{String(entry['target_url'])}</div>
                        ) : null}
                        {entry['targets'] ? (
                          <div><span className="text-muted-foreground">Targets: </span>{JSON.stringify(entry['targets'])}</div>
                        ) : null}
                        {entry['parameters'] ? (
                          <div><span className="text-muted-foreground">Parameters: </span><code className="text-[10px]">{JSON.stringify(entry['parameters'])}</code></div>
                        ) : null}
                        {/* Result metrics for completed events */}
                        {entry.event.includes('completed') && (() => {
                          const metrics = Object.entries(entry).filter(([k, v]) =>
                            !AUDIT_SKIP_KEYS.has(k) && !['command', 'execution_mode', 'proxy', 'node_id', 'target_url', 'targets', 'parameters'].includes(k)
                            && (typeof v === 'number' || typeof v === 'string')
                          )
                          if (metrics.length === 0) return null
                          return (
                            <div className="mt-1 pt-1 border-t border-border">
                              <span className="text-muted-foreground">Results: </span>
                              <div className="flex flex-wrap gap-2 mt-0.5">
                                {metrics.map(([k, v]) => (
                                  <span key={k} className="px-1.5 py-0.5 bg-background rounded text-[10px] font-mono border border-border">
                                    {k}: {String(v)}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )
                        })()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {data.error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
              <h3 className="text-sm font-semibold text-red-500 mb-1">Error</h3>
              <pre className="text-xs text-red-400 whitespace-pre-wrap">{typeof data.error === 'string' ? data.error : JSON.stringify(data.error, null, 2)}</pre>
            </div>
          )}
        </div>
      )}

      {/* ═══════════ Results Tab ═══════════ */}
      {tab === 'results' && (
        <div className="space-y-4">
          {data.result != null ? (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-semibold">Raw Results</h3>
                <button
                  onClick={() => {
                    const content = JSON.stringify(data.result, null, 2)
                    const w = Math.min(1200, window.screen.width - 100)
                    const h = Math.min(800, window.screen.height - 100)
                    const left = (window.screen.width - w) / 2
                    const top = (window.screen.height - h) / 2
                    const popup = window.open('', '_blank', `width=${w},height=${h},left=${left},top=${top},toolbar=no,menubar=no,scrollbars=yes,resizable=yes`)
                    if (popup) {
                      popup.document.write(`<!DOCTYPE html><html><head><title>Scan Results — ${data.type || 'unknown'} — ${jobId?.slice(0,8)}</title>
                        <style>body{background:#111;color:#e5e5e5;font-family:monospace;font-size:12px;padding:16px;margin:0;white-space:pre-wrap;word-break:break-all;}
                        .key{color:#93c5fd}.str{color:#86efac}.num{color:#fde68a}.bool{color:#c4b5fd}.null{color:#6b7280}</style></head>
                        <body>${content.replace(/&/g,'&amp;').replace(/</g,'&lt;')
                          .replace(/"([^"]+)":/g, '<span class="key">"$1"</span>:')
                          .replace(/: "([^"]*?)"/g, ': <span class="str">"$1"</span>')
                          .replace(/: (\d+\.?\d*)/g, ': <span class="num">$1</span>')
                          .replace(/: (true|false)/g, ': <span class="bool">$1</span>')
                          .replace(/: null/g, ': <span class="null">null</span>')
                        }</body></html>`)
                      popup.document.close()
                    }
                  }}
                  className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded border border-border hover:bg-muted transition-colors"
                >
                  <Globe className="h-3 w-3" /> View in Popup
                </button>
              </div>
              <JsonViewer data={data.result} maxHeight="500px" />
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No results available yet.</p>
          )}

          {data.progress && (
            <div>
              <h3 className="text-sm font-semibold mb-2">Progress State</h3>
              <JsonViewer data={data.progress} maxHeight="300px" />
            </div>
          )}

          {Object.keys(params).length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2">Launch Parameters</h3>
              <JsonViewer data={params} maxHeight="300px" />
            </div>
          )}
        </div>
      )}
    </div>
  )
}
