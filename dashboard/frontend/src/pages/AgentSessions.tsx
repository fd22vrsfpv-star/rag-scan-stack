import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  useAgentSessions,
  useAgentSession,
  useAgentMessages,
  useSessionScans,
  useSessionFlowSummary,
  useStartSession,
  useStopSession,
  useResumeSession,
  useDeleteSession,
  useClearSessionHistory,
  usePendingApproval,
  useApproveSession,
} from '@/api/agentSessions'
import type { AgentSession, AgentMessage, SessionScan } from '@/api/agentSessions'
import { useModelPerformanceWarning } from '@/api/agents'
import { apiFetch } from '@/api/client'
import { useScopeNames, useScope } from '@/api/scope'
import { StatusDot } from '@/components/common/StatusDot'
import { JsonViewer } from '@/components/common/JsonViewer'
import { ModelPerformanceWarningModal } from '@/components/common/ModelPerformanceWarningModal'
import { cn } from '@/lib/utils'
import { ArrowLeft, Plus, Square, Play, X, Wrench, Terminal, ChevronDown, ChevronRight, ExternalLink, Trash2, Shield, Crosshair, Wifi, Puzzle, AlertTriangle, ListChecks, PauseCircle, Check, Ban } from 'lucide-react'
import { useScanDefaultsStore } from '@/stores/scanDefaults'
import { useNodes } from '@/api/nodes'
import { usePortProfiles } from '@/api/portProfiles'
import { useWebProfiles } from '@/api/webProfiles'

const SESSION_PROFILES = {
  'full-pentest': {
    label: 'Full Pentest',
    desc: 'Active scanning: port scans, vuln scans, web pipeline, credential testing',
    task: `Conduct a full penetration test of the target:

1. Reconnaissance — discover hosts, enumerate DNS, gather OSINT
2. Port scanning — run a full port scan (1-65535) to identify all open services
3. Vulnerability scanning — based on discovered services, run targeted vuln scans (only for services actually found)
4. Web scanning — if HTTP/HTTPS ports are open, run the web scan pipeline (WAF detect, Katana, Playwright crawl, Gobuster, Nikto, Nuclei, ZAP)
5. Credential testing — if auth services are found (SSH, FTP, MySQL, PostgreSQL, VNC), test for default/weak credentials
6. Analysis — correlate all findings, assess risk levels and exploitability
7. Exploit recommendations — match discovered vulnerabilities to known exploits and recommend which to use, with justification`,
  },
  'passive-recon': {
    label: 'Passive Recon',
    desc: 'Passive only: subdomain enum, DNS, crt.sh, cert chaining, historical URLs — no active scanning',
    task: `Conduct passive reconnaissance only — NO active scanning allowed:

1. Use start_passive_recon to run the passive pipeline (subfinder, findomain, dnsdumpster, dnsx, crtsh, httpx, tlsx, cert-chain, gau, gowitness, whatweb)
2. Enable cert serial chaining to discover related infrastructure via shared TLS certificates
3. Review discovered subdomains, technologies, and certificate relationships
4. If a scope is set, new domains from cert chaining will be auto-added to scope
5. Analyze results — map out the target's external footprint, identify interesting technologies and exposed services
6. Summarize findings: subdomain count, technology stack, cert relationships, historical URLs found

IMPORTANT: Do NOT use any active scanning tools (nmap, masscan, nuclei, naabu, shuffledns, ffuf, brutus). Only passive tools are allowed.`,
  },
}

type SessionProfile = keyof typeof SESSION_PROFILES
const DEFAULT_PROFILE: SessionProfile = 'full-pentest'

const AGENT_COLORS: Record<string, string> = {
  coordinator: 'bg-blue-600',
  recon_agent: 'bg-cyan-600',
  scanner_agent: 'bg-green-600',
  exploit_agent: 'bg-red-600',
  analyst_agent: 'bg-purple-600',
  reporter_agent: 'bg-amber-600',
  tool_executor: 'bg-gray-600',
}

function agentBadgeColor(name: string) {
  const key = name.toLowerCase().replace(/\s+/g, '_')
  return AGENT_COLORS[key] || 'bg-slate-600'
}

function timeAgo(dateStr: string) {
  if (!dateStr) return ''
  const time = new Date(dateStr).getTime()
  if (isNaN(time)) return ''
  const diff = Date.now() - time
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ${mins % 60}m ago`
  return `${Math.floor(hrs / 24)}d ago`
}

/* ────────────── Message classification helpers ────────────── */

type MessageType = 'tool_call' | 'tool_result' | 'conversation'

function classifyMessage(msg: AgentMessage): MessageType {
  // Check metadata first (new messages)
  if (msg.metadata?.message_type === 'tool_call') return 'tool_call'
  if (msg.metadata?.message_type === 'tool_result') return 'tool_result'
  // Fallback to content-pattern matching for historical messages
  if (msg.content?.includes('Suggested tool Call')) return 'tool_call'
  if (msg.content?.startsWith('Response from calling tool')) return 'tool_result'
  return 'conversation'
}

function extractToolName(msg: AgentMessage): string | null {
  // From metadata
  if (msg.metadata?.tool_calls?.length) {
    return msg.metadata.tool_calls.map(tc => tc.function).join(', ')
  }
  // From content pattern: "Suggested tool Call (call_xxx)\n...function_name"
  const callMatch = msg.content?.match(/Suggested tool Call[^]*?(\w+)\s*\(/)
  if (callMatch) return callMatch[1]
  // From tool result: "Response from calling tool "function_name""
  const resultMatch = msg.content?.match(/Response from calling tool "([^"]+)"/)
  if (resultMatch) return resultMatch[1]
  return null
}

/* ────────────── Scan Card ────────────── */

/* ────────────── End-of-session scan flow summary ──────────────
 *
 * Built at teardown by scan_tools.build_flow_summary() and persisted to
 * agent_sessions.metadata.scan_flow_summary, so it survives the process. It was
 * previously written to logs and a webhook only — invisible in the UI, which is
 * where an operator actually reviews a finished run.
 *
 * The signal that earns its place at the top: produced_nothing. A scan type that
 * COMPLETED while producing nothing is the exact shape of a silently-broken tool
 * (ZAP once reported "0 alerts" from 207 seeded URLs after its session was
 * wiped) and is indistinguishable from a clean run if you only count statuses.
 */

interface FlowType {
  scan_type: string
  runs: number
  completed: number
  running: number
  failed: number
  targets: string[]
  results: Record<string, number>
  failures: { job_id?: string; error?: string }[]
  produced_nothing: boolean
  total_duration_seconds: number
}

interface KbCoverage {
  available: boolean
  reason?: string
  acted_on?: number
  ignored?: number
  coverage_pct?: number
  recommendations?: number
  by_source?: Record<string, number>
  recommended_but_never_run?: { scanner: string; recommendations?: number }[]
}

interface FlowSummary {
  total_scans: number
  scan_types_run: number
  flow_order: string[]
  by_scan_type: FlowType[]
  types_that_produced_nothing: string[]
  types_with_failures: string[]
  kb_coverage?: KbCoverage
  generated_at?: string
  /** Types still running when the teardown snapshot was taken. Non-empty means
   *  the numbers are provisional until the post-session refresh lands. */
  in_flight_at_teardown?: string[]
  refreshed_at?: string
  source?: string
}

interface ClaimValidation {
  ok?: boolean
  by_kind?: Record<string, { total: number; unsupported: number }>
  notable?: { kind: string; value: string; detail?: string; context?: string }[]
}

function dur(seconds: number | null | undefined): string {
  if (seconds == null || seconds === 0) return '—'
  return seconds < 60 ? `${seconds.toFixed(1)}s` : `${(seconds / 60).toFixed(1)}m`
}

function ScanFlowSummary({ summary, validation }: {
  summary: FlowSummary
  validation?: ClaimValidation
}) {
  const [expanded, setExpanded] = useState(true)
  const kb = summary.kb_coverage
  const quiet = summary.types_that_produced_nothing ?? []
  const broken = summary.types_with_failures ?? []
  const inFlight = summary.in_flight_at_teardown ?? []

  return (
    <div className="bg-card border border-border rounded-lg">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-muted/30 transition-colors"
      >
        {expanded ? <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />}
        <ListChecks className="h-4 w-4 shrink-0 text-muted-foreground" />
        <span className="text-sm font-medium flex-1">Session flow summary</span>
        <span className="text-xs text-muted-foreground">
          {summary.total_scans} scans · {summary.scan_types_run} types
        </span>
        {quiet.length > 0 && (
          <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-500">
            {quiet.length} produced nothing
          </span>
        )}
        {broken.length > 0 && (
          <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/10 text-red-500">
            {broken.length} with failures
          </span>
        )}
        {inFlight.length > 0 && (
          <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-500">
            {inFlight.length} still running
          </span>
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-border pt-3">
          {/* Flow order — the actual sequence the session ran, not alphabetical */}
          {summary.flow_order?.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap text-xs">
              {summary.flow_order.map((t, i) => (
                <span key={t} className="flex items-center gap-1.5">
                  {i > 0 && <span className="text-muted-foreground">→</span>}
                  <span className="px-1.5 py-0.5 rounded bg-muted/50 font-mono">{t}</span>
                </span>
              ))}
            </div>
          )}

          {/* Per-type outcomes */}
          <div className="space-y-1.5">
            {(summary.by_scan_type ?? []).map(t => {
              const produced = Object.entries(t.results ?? {})
              return (
                <div key={t.scan_type} className="text-xs border border-border/60 rounded px-3 py-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono font-medium">{t.scan_type}</span>
                    <span className="text-muted-foreground">{t.runs} run{t.runs === 1 ? '' : 's'}</span>
                    {t.completed > 0 && <span className="text-green-500">{t.completed} completed</span>}
                    {t.running > 0 && <span className="text-blue-500">{t.running} running</span>}
                    {t.failed > 0 && <span className="text-red-500">{t.failed} failed</span>}
                    <span className="text-muted-foreground ml-auto">{dur(t.total_duration_seconds)}</span>
                  </div>

                  {/* What it PRODUCED — the question status counts cannot answer */}
                  <div className="mt-1 flex items-center gap-2 flex-wrap text-muted-foreground">
                    {produced.length > 0 ? (
                      produced.map(([k, v]) => (
                        <span key={k} className="px-1.5 py-0.5 rounded bg-muted/40">
                          {k.replace(/_/g, ' ')}: <span className="text-foreground">{String(v)}</span>
                        </span>
                      ))
                    ) : t.produced_nothing ? (
                      <span className="flex items-center gap-1 text-yellow-500">
                        <AlertTriangle className="h-3 w-3" />
                        completed but produced nothing
                      </span>
                    ) : (
                      <span>no results recorded yet</span>
                    )}
                    {t.targets?.length > 0 && (
                      <span className="ml-auto font-mono">{t.targets.join(', ')}</span>
                    )}
                  </div>

                  {t.failures?.length > 0 && (
                    <div className="mt-1 space-y-0.5">
                      {t.failures.map((f, i) => (
                        <div key={i} className="text-red-400 font-mono truncate">
                          {f.error || 'no error recorded'}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* KB coverage — did the run do what the knowledge base said to do */}
          {kb && (
            <div className="text-xs border-t border-border pt-3">
              <div className="font-medium mb-1">Knowledge-base coverage</div>
              {kb.available === false ? (
                <p className="text-muted-foreground">Unavailable{kb.reason ? ` — ${kb.reason}` : ''}</p>
              ) : (
                <div className="flex items-center gap-3 flex-wrap text-muted-foreground">
                  <span>acted on <span className="text-foreground">{kb.acted_on ?? 0}</span> of <span className="text-foreground">{kb.recommendations ?? 0}</span></span>
                  {kb.coverage_pct != null && (
                    <span className={cn(kb.coverage_pct < 50 ? 'text-yellow-500' : 'text-green-500')}>
                      {kb.coverage_pct}% coverage
                    </span>
                  )}
                  {kb.by_source && Object.entries(kb.by_source).map(([src, n]) => (
                    <span key={src} className="px-1.5 py-0.5 rounded bg-muted/40">{src}: {n}</span>
                  ))}
                </div>
              )}
              {(kb.recommended_but_never_run?.length ?? 0) > 0 && (
                <div className="mt-1 text-muted-foreground">
                  never run:{' '}
                  <span className="font-mono">
                    {kb.recommended_but_never_run!.slice(0, 8).map(r => r.scanner).join(', ')}
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Agent claims checked against what the scans actually recorded */}
          {validation?.by_kind && (
            <div className="text-xs border-t border-border pt-3">
              <div className="font-medium mb-1">Agent claim validation</div>
              <div className="flex items-center gap-3 flex-wrap text-muted-foreground">
                {Object.entries(validation.by_kind).map(([kind, v]) => (
                  <span key={kind} className="px-1.5 py-0.5 rounded bg-muted/40">
                    {kind}: <span className="text-foreground">{v.total}</span>
                    {v.unsupported > 0 && (
                      <span className="text-yellow-500"> · {v.unsupported} unsupported</span>
                    )}
                  </span>
                ))}
              </div>
              {/* "Unsupported" is deliberately not called "false": it can equally
                  mean ingestion broke, which is why it reads beside the produced
                  counts above rather than on its own. */}
              <p className="mt-1 text-muted-foreground">
                Unsupported = not found in recorded scan data. That can mean a fabricated
                claim <em>or</em> that ingestion failed — compare with what each type produced above.
              </p>
            </div>
          )}

          {/* Say plainly that the numbers are provisional. Without this a scan
              that simply had not finished is indistinguishable from one that
              genuinely found nothing. */}
          {inFlight.length > 0 && (
            <p className="text-xs text-blue-400">
              Still running when this was taken: <span className="font-mono">{inFlight.join(', ')}</span>.
              Counts for these are provisional and refresh when the scans report in.
            </p>
          )}

          {(summary.generated_at || summary.refreshed_at) && (
            <p className="text-[11px] text-muted-foreground">
              {summary.generated_at && <>generated {new Date(summary.generated_at).toLocaleString()}</>}
              {summary.refreshed_at && <> · refreshed {new Date(summary.refreshed_at).toLocaleString()}</>}
              {summary.source && <> · {summary.source}</>}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function ScanCard({ scan }: { scan: SessionScan }) {
  const [expanded, setExpanded] = useState(false)
  const p = scan.progress

  const durationStr = scan.duration_seconds != null
    ? scan.duration_seconds < 60 ? `${scan.duration_seconds.toFixed(1)}s` : `${(scan.duration_seconds / 60).toFixed(1)}m`
    : p?.elapsed_seconds != null
      ? p.elapsed_seconds < 60 ? `${p.elapsed_seconds.toFixed(0)}s` : `${(p.elapsed_seconds / 60).toFixed(1)}m`
      : '—'

  const phaseLabel = p?.stage?.replace(':done', '').replace(':skipped', '') ?? ''
  const progressPct = p?.phase_number && p?.total_phases
    ? Math.round((p.phase_number / p.total_phases) * 100) : null

  return (
    <div className="bg-card border border-border rounded-lg">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-muted/30 transition-colors"
      >
        {expanded ? <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />}
        <span className="text-sm font-medium flex-1 truncate">{scan.type}</span>
        <code className="text-xs text-muted-foreground font-mono">{scan.job_id?.slice(0, 8)}</code>
        <StatusDot status={scan.status} />
        <span className={cn(
          'text-xs px-1.5 py-0.5 rounded',
          scan.status === 'completed' ? 'bg-green-500/10 text-green-500'
            : scan.status === 'running' ? 'bg-blue-500/10 text-blue-500'
            : scan.status === 'failed' ? 'bg-red-500/10 text-red-500'
            : 'bg-yellow-500/10 text-yellow-500',
        )}>
          {scan.status}
        </span>
        <span className="text-xs text-muted-foreground">{durationStr}</span>
      </button>

      {/* Live progress bar for running scans */}
      {scan.status === 'running' && p && (
        <div className="px-4 pb-2 space-y-1.5">
          {/* Phase progress bar */}
          {progressPct != null && (
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-500 rounded-full transition-all duration-500"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
              <span className="text-[10px] text-muted-foreground shrink-0">
                {p.phase_number}/{p.total_phases}
              </span>
            </div>
          )}
          {/* Current stage + detail */}
          <div className="flex items-center justify-between text-xs">
            <span className="text-blue-400 font-medium">{phaseLabel}</span>
            {p.total_hosts_discovered != null && p.total_hosts_discovered > 0 && (
              <span className="text-muted-foreground">
                {p.total_hosts_discovered} hosts discovered
              </span>
            )}
          </div>
          {p.detail && (
            <p className="text-[10px] text-muted-foreground">{p.detail}</p>
          )}
        </div>
      )}

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-border pt-3">
          <div className="flex gap-6 text-xs text-muted-foreground">
            {scan.started_at && <span>Started: {new Date(scan.started_at).toLocaleString()}</span>}
            {scan.completed_at && <span>Completed: {new Date(scan.completed_at).toLocaleString()}</span>}
            {p?.input_domains != null && <span>Input: {p.input_domains} domain(s)</span>}
            {p?.total_hosts_discovered != null && <span>Hosts: {p.total_hosts_discovered}</span>}
            {p?.elapsed_seconds != null && (
              <span>Elapsed: {p.elapsed_seconds < 60 ? `${p.elapsed_seconds.toFixed(0)}s` : `${(p.elapsed_seconds / 60).toFixed(1)}m`}</span>
            )}
          </div>

          {/* Phase-by-phase checkpoint results */}
          {p?.phases_completed && Object.keys(p.phases_completed).length > 0 && (
            <div>
              <span className="text-xs text-muted-foreground block mb-1.5">Phase Results</span>
              <div className="space-y-1">
                {Object.entries(p.phases_completed).map(([phase, result]) => (
                  <div key={phase} className="flex items-center gap-2 text-xs">
                    <span className="text-green-500 shrink-0">&#10003;</span>
                    <span className="font-medium w-24 shrink-0">{phase}</span>
                    <span className="text-muted-foreground">
                      {typeof result === 'string'
                        ? result
                        : typeof result === 'object' && result !== null
                          ? Object.entries(result as Record<string, unknown>)
                              .map(([k, v]) => `${k}: ${v}`)
                              .join(', ')
                          : String(result)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {scan.params && Object.keys(scan.params).length > 0 && (
            <div>
              <span className="text-xs text-muted-foreground block mb-1">Parameters</span>
              <JsonViewer data={scan.params} />
            </div>
          )}
          {scan.result_summary && Object.keys(scan.result_summary).length > 0 && (
            <div>
              <span className="text-xs text-muted-foreground block mb-1">Result Summary</span>
              <JsonViewer data={scan.result_summary} />
            </div>
          )}
          {scan.job_id && (
            <Link
              to={`/scans/${scan.job_id}`}
              className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline"
            >
              <ExternalLink className="h-3 w-3" />
              View full scan details
            </Link>
          )}
        </div>
      )}
    </div>
  )
}

/* ────────────── Session Detail ────────────── */

function SessionDetail({ sessionId }: { sessionId: string }) {
  const navigate = useNavigate()
  const { data: session } = useAgentSession(sessionId)
  const { data: msgData } = useAgentMessages(sessionId)
  const { data: scanData } = useSessionScans(sessionId)
  const stopSession = useStopSession()
  const resumeSession = useResumeSession()

  const [showResume, setShowResume] = useState(false)
  const [resumeInstructions, setResumeInstructions] = useState('')
  const [resumeRounds, setResumeRounds] = useState(200)
  const [resumeNodeId, setResumeNodeId] = useState('')
  const nodesQuery = useNodes()
  const resumeOnlineNodes = (nodesQuery.data?.nodes ?? []).filter(n => n.status === 'online')
  // Prefer the dedicated endpoint: it serves the LIVE tracker while the session
  // is active and the persisted copy once it has ended. session.metadata holds
  // only the teardown snapshot, which is taken while scans are frequently still
  // running, so it under-reports until the post-session refresh lands.
  const { data: liveFlow } = useSessionFlowSummary(sessionId)
  const sessionMeta = (session as unknown as { metadata?: Record<string, unknown> } | undefined)?.metadata
  const storedFlow = sessionMeta?.scan_flow_summary as FlowSummary | undefined
  // `source: "none"` means the endpoint found nothing — fall back rather than
  // rendering an empty panel over a summary we already have.
  const flowSummary = (liveFlow && (liveFlow as { total_scans?: number }).total_scans
    ? (liveFlow as unknown as FlowSummary)
    : storedFlow)
  const claimValidation = sessionMeta?.claim_validation as ClaimValidation | undefined
  const [activeTab, setActiveTab] = useState<'messages' | 'scans'>('messages')
  const [showToolCalls, setShowToolCalls] = useState(true)

  const logRef = useRef<HTMLDivElement>(null)
  const messages = msgData?.messages ?? []
  const scans: SessionScan[] = scanData?.scans ?? []

  const filteredMessages = showToolCalls
    ? messages
    : messages.filter(m => classifyMessage(m) === 'conversation')

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [filteredMessages.length])

  const canResume = session && ['failed', 'stalled', 'stopped', 'completed', 'rounds_exhausted', 'agent_failure'].includes(session.status)
  const canStop = session?.status === 'active'
  const isRoundsExhausted = session?.status === 'rounds_exhausted'
  const isAgentFailure = session?.status === 'agent_failure'
  // Paused on a LangGraph approval interrupt. NOT a stall: the graph is
  // checkpointed in Postgres and resumes from this exact point once answered,
  // which is why /resume (a new child session) is the wrong control here.
  const isAwaitingApproval = session?.status === 'awaiting_approval'
  const { data: pendingApproval } = usePendingApproval(sessionId, isAwaitingApproval)
  const approveSession = useApproveSession()
  const [approveExploitId, setApproveExploitId] = useState('')
  const [approveNote, setApproveNote] = useState('')

  const handleResume = () => {
    const selectedNode = resumeOnlineNodes.find(n => n.id === resumeNodeId)
    const proxy = selectedNode ? `socks5://node-manager:${selectedNode.proxy_port}` : undefined
    resumeSession.mutate(
      {
        id: sessionId,
        max_rounds: resumeRounds,
        additional_instructions: resumeInstructions || undefined,
        proxy,
      },
      { onSuccess: () => { setShowResume(false); setResumeNodeId('') } },
    )
  }

  // Scan summary counts
  const scanCounts = {
    total: scans.length,
    completed: scans.filter(s => s.status === 'completed').length,
    running: scans.filter(s => s.status === 'running').length,
    failed: scans.filter(s => s.status === 'failed').length,
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate('/agent-sessions')}
          className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <h2 className="text-lg font-semibold flex-1 truncate">
          {session?.session_name ?? sessionId.slice(0, 8)}
        </h2>
        {session && <StatusDot status={session.status} />}
        {session && (
          <span
            className={cn(
              'text-xs px-2 py-0.5 rounded',
              session.status === 'active'
                ? 'bg-green-500/10 text-green-500'
                : session.status === 'failed'
                  ? 'bg-red-500/10 text-red-500'
                  : session.status === 'completed'
                    ? 'bg-green-500/10 text-green-500'
                    : session.status === 'agent_failure'
                      ? 'bg-orange-500/10 text-orange-500'
                      : session.status === 'rounds_exhausted'
                        ? 'bg-yellow-500/10 text-yellow-500'
                        : session.status === 'awaiting_approval'
                          ? 'bg-purple-500/10 text-purple-400'
                          : 'bg-yellow-500/10 text-yellow-500',
            )}
          >
            {session.status === 'rounds_exhausted'
              ? 'needs more rounds'
              : session.status === 'agent_failure'
                ? 'agent failed — resumable'
                : session.status === 'awaiting_approval'
                  ? 'awaiting approval'
                  : session.status}
          </span>
        )}
      </div>

      {/* Session info */}
      {session && (
        <div className="bg-card border border-border rounded-lg p-4 space-y-2 text-sm">
          <div>
            <span className="text-muted-foreground">Target: </span>
            <span>{session.target_description}</span>
          </div>
          <div className="flex gap-6">
            <div>
              <span className="text-muted-foreground">Max Rounds: </span>
              <span>{session.max_rounds ?? session.configuration?.max_rounds ?? '—'}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Auto Execute: </span>
              <span>{(session.auto_execute_scans ?? session.configuration?.auto_execute_scans) ? 'Yes' : 'No'}</span>
            </div>
            {/* Which engine this session actually ran on. Persisted per session,
                so a run stays labelled after the service default is flipped —
                without it an A/B comparison is unreadable. */}
            {session.configuration?.engine && (
              <div>
                <span className="text-muted-foreground">Engine: </span>
                <span className={cn(
                  'font-mono text-xs px-1.5 py-0.5 rounded',
                  session.configuration.engine === 'langgraph'
                    ? 'bg-blue-500/10 text-blue-400'
                    : 'bg-muted text-muted-foreground',
                )}>{session.configuration.engine}</span>
              </div>
            )}
            {session.configuration?.enable_exploit_phase && (
              <div>
                <span className="text-muted-foreground">Exploit phase: </span>
                <span className="text-purple-400">on (needs approval)</span>
              </div>
            )}
            {session.configuration?.proxy && (
              <div className="flex items-center gap-1.5">
                <Wifi className="h-3 w-3 text-blue-400" />
                <span className="text-muted-foreground">Proxy: </span>
                <span className="font-mono text-blue-400 text-xs">{session.configuration.proxy}</span>
              </div>
            )}
            {session.current_round !== undefined && (
              <div>
                <span className="text-muted-foreground">Current Round: </span>
                <span>{session.current_round}</span>
              </div>
            )}
          </div>
          {session.error && (
            <p className="text-xs text-red-500">Error: {typeof session.error === 'string' ? session.error : JSON.stringify(session.error)}</p>
          )}
        </div>
      )}

      {/* Awaiting-approval banner.
          A paused session MUST be labelled, not left looking like a running
          one: the graph does nothing at all until this is answered, and a
          silent pause is indistinguishable from a hang. */}
      {isAwaitingApproval && (
        <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg px-4 py-3 space-y-3">
          <div className="flex items-start gap-3">
            <PauseCircle className="h-5 w-5 text-purple-400 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-purple-400">
                Paused — waiting for your approval
              </p>
              <p className="text-xs text-muted-foreground">
                The graph is checkpointed in Postgres and resumes from this exact
                point. Nothing has been executed.
              </p>
              {pendingApproval?.pending?.candidate && (
                <pre className="mt-2 text-xs bg-background/60 border border-border rounded p-2 max-h-48 overflow-auto whitespace-pre-wrap">
                  {pendingApproval.pending.candidate}
                </pre>
              )}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={approveExploitId}
              onChange={e => setApproveExploitId(e.target.value)}
              placeholder="pending_exploit_id (required to approve)"
              className="flex-1 min-w-[18rem] px-2 py-1.5 bg-background border border-border rounded-md text-xs font-mono"
            />
            <input
              value={approveNote}
              onChange={e => setApproveNote(e.target.value)}
              placeholder="note (optional)"
              className="flex-1 min-w-[10rem] px-2 py-1.5 bg-background border border-border rounded-md text-xs"
            />
            <button
              onClick={() => approveSession.mutate({
                id: sessionId,
                approved: true,
                pending_exploit_id: approveExploitId.trim(),
                note: approveNote || undefined,
              })}
              disabled={!approveExploitId.trim() || approveSession.isPending}
              title={approveExploitId.trim()
                ? 'Execute the queued exploit and continue'
                : 'Enter the pending_exploit_id to approve'}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-600 text-white rounded-md text-sm hover:bg-purple-700 disabled:opacity-50"
            >
              <Check className="h-3.5 w-3.5" /> Approve &amp; run
            </button>
            <button
              onClick={() => approveSession.mutate({
                id: sessionId,
                approved: false,
                note: approveNote || undefined,
              })}
              disabled={approveSession.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 border border-border rounded-md text-sm hover:bg-muted disabled:opacity-50"
            >
              <Ban className="h-3.5 w-3.5" /> Decline
            </button>
          </div>
          {approveSession.isError && (
            <p className="text-xs text-red-500">
              {(approveSession.error as Error)?.message ?? 'Approval failed'}
            </p>
          )}
          <Link
            to="/exploits"
            className="inline-flex items-center gap-1 text-xs text-purple-400 hover:underline"
          >
            <ExternalLink className="h-3 w-3" /> Find the id in Pending Exploits
          </Link>
        </div>
      )}

      {/* Rounds exhausted banner */}
      {isRoundsExhausted && !showResume && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg px-4 py-3 flex items-center gap-3">
          <div className="flex-1">
            <p className="text-sm font-medium text-yellow-500">Session ran out of rounds</p>
            <p className="text-xs text-muted-foreground">
              The session used all {session?.max_rounds ?? session?.configuration?.max_rounds ?? '—'} rounds before finishing. Resume with more rounds to continue scanning and analysis.
            </p>
          </div>
          <button
            onClick={() => setShowResume(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-yellow-600 text-white rounded-md text-sm hover:bg-yellow-700 shrink-0"
          >
            <Play className="h-3.5 w-3.5" /> Add Rounds
          </button>
        </div>
      )}

      {/* Agent failure banner */}
      {isAgentFailure && !showResume && (
        <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg px-4 py-3 flex items-center gap-3">
          <div className="flex-1">
            <p className="text-sm font-medium text-orange-500">Session ended early — agent failed to respond</p>
            <p className="text-xs text-muted-foreground">
              An agent stopped responding (LLM timeout or error). Resume the session to continue where it left off.
            </p>
          </div>
          <button
            onClick={() => setShowResume(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-600 text-white rounded-md text-sm hover:bg-orange-700 shrink-0"
          >
            <Play className="h-3.5 w-3.5" /> Resume
          </button>
        </div>
      )}

      {/* Controls */}
      <div className="flex gap-2">
        {canStop && (
          <button
            onClick={() => stopSession.mutate(sessionId)}
            disabled={stopSession.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 text-white rounded-md text-sm hover:bg-red-700 disabled:opacity-50"
          >
            <Square className="h-3.5 w-3.5" /> Stop
          </button>
        )}
        {canResume && !showResume && !isRoundsExhausted && !isAgentFailure && (
          <button
            onClick={() => setShowResume(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
          >
            <Play className="h-3.5 w-3.5" /> Resume
          </button>
        )}
      </div>

      {/* Resume form */}
      {showResume && (
        <div className="bg-card border border-border rounded-lg p-4 space-y-3 max-w-xl">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium">Resume Session</h3>
            <button onClick={() => setShowResume(false)} className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Max Rounds</label>
            <input
              type="number"
              value={resumeRounds}
              onChange={e => setResumeRounds(Number(e.target.value))}
              className="w-32 bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Additional Instructions (optional)</label>
            <textarea
              value={resumeInstructions}
              onChange={e => setResumeInstructions(e.target.value)}
              rows={3}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary resize-none"
              placeholder="e.g. Focus on web application vulnerabilities..."
            />
          </div>
          {resumeOnlineNodes.length > 0 && (
            <div>
              <label className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                <Wifi className="h-3 w-3" /> Route Through Proxy
              </label>
              <select
                value={resumeNodeId}
                onChange={e => setResumeNodeId(e.target.value)}
                className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              >
                <option value="">Direct (no proxy)</option>
                {resumeOnlineNodes.map(n => (
                  <option key={n.id} value={n.id}>
                    {n.name} — {n.hostname || n.id.slice(0, 8)} (:{n.proxy_port})
                  </option>
                ))}
              </select>
              {resumeNodeId && (
                <p className="text-[10px] text-amber-400 mt-0.5">Resumed scans will route through this proxy</p>
              )}
            </div>
          )}
          <button
            onClick={handleResume}
            disabled={resumeSession.isPending}
            className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90 disabled:opacity-50"
          >
            {resumeSession.isPending ? 'Resuming...' : 'Resume'}
          </button>
          {resumeSession.error && (
            <p className="text-xs text-red-500">{String(resumeSession.error)}</p>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-border">
        <button
          onClick={() => setActiveTab('messages')}
          className={cn(
            'px-3 py-2 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'messages'
              ? 'border-primary text-foreground'
              : 'border-transparent text-muted-foreground hover:text-foreground',
          )}
        >
          Messages ({messages.length})
        </button>
        <button
          onClick={() => setActiveTab('scans')}
          className={cn(
            'px-3 py-2 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'scans'
              ? 'border-primary text-foreground'
              : 'border-transparent text-muted-foreground hover:text-foreground',
          )}
        >
          Scans & Tools ({scans.length})
        </button>
      </div>

      {/* Messages tab */}
      {activeTab === 'messages' && (
        <div>
          <div className="flex items-center gap-3 mb-2">
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground select-none cursor-pointer">
              <input
                type="checkbox"
                checked={showToolCalls}
                onChange={e => setShowToolCalls(e.target.checked)}
                className="rounded border-border"
              />
              Show tool calls
            </label>
          </div>
          <div
            ref={logRef}
            className="bg-card border border-border rounded-lg p-3 space-y-2 max-h-[60vh] overflow-y-auto overflow-x-hidden"
          >
            {filteredMessages.length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-8">
                {session?.status === 'active' ? 'Waiting for agent messages...' : 'No messages'}
              </p>
            )}
            {filteredMessages.map((msg, i) => {
              const msgType = classifyMessage(msg)
              const toolName = msgType !== 'conversation' ? extractToolName(msg) : null
              return (
                <div
                  key={i}
                  className={cn(
                    'flex gap-2 text-sm rounded-md px-2 py-1.5',
                    msgType === 'tool_call' && 'border-l-2 border-l-blue-500 bg-blue-500/5',
                    msgType === 'tool_result' && 'border-l-2 border-l-green-500 bg-green-500/5',
                  )}
                >
                  <div className="flex flex-col items-center gap-1 shrink-0">
                    <span
                      className={cn(
                        'px-1.5 py-0.5 rounded text-xs text-white font-medium',
                        agentBadgeColor(msg.agent_name),
                      )}
                    >
                      {msg.agent_name}
                    </span>
                    {msgType === 'tool_call' && <Wrench className="h-3 w-3 text-blue-500" />}
                    {msgType === 'tool_result' && <Terminal className="h-3 w-3 text-green-500" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    {toolName && (
                      <span className={cn(
                        'inline-block text-[10px] font-mono px-1.5 py-0.5 rounded mb-1',
                        msgType === 'tool_call' ? 'bg-blue-500/10 text-blue-400' : 'bg-green-500/10 text-green-400',
                      )}>
                        {toolName}
                      </span>
                    )}
                    <p className="whitespace-pre-wrap break-words overflow-hidden text-sm" style={{ overflowWrap: 'anywhere' }}>{msg.content}</p>
                    <span className="text-xs text-muted-foreground">
                      {new Date(msg.timestamp).toLocaleTimeString()}
                      {msg.round !== undefined && ` · round ${msg.round}`}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Scans & Tools tab */}
      {activeTab === 'scans' && (
        <div className="space-y-3">
          {/* End-of-session flow summary. Rendered FIRST: it answers "did each
              kind of scan do its job", which is the question an operator opens a
              finished session to ask. The per-scan cards below answer "what ran". */}
          {flowSummary && (
            <ScanFlowSummary summary={flowSummary} validation={claimValidation} />
          )}
          {/* Summary bar */}
          <div className="flex items-center gap-4 text-xs">
            <span className="text-muted-foreground">
              Total: <span className="text-foreground font-medium">{scanCounts.total}</span>
            </span>
            {scanCounts.completed > 0 && (
              <span className="text-green-500">
                Completed: {scanCounts.completed}
              </span>
            )}
            {scanCounts.running > 0 && (
              <span className="text-blue-500">
                Running: {scanCounts.running}
              </span>
            )}
            {scanCounts.failed > 0 && (
              <span className="text-red-500">
                Failed: {scanCounts.failed}
              </span>
            )}
          </div>
          {/* Scan cards */}
          {scans.length === 0 && (
            <p className="text-sm text-muted-foreground text-center py-8">
              {session?.status === 'active' ? 'No scans started yet...' : 'No scans recorded'}
            </p>
          )}
          <div className="space-y-2">
            {scans.map(scan => (
              <ScanCard key={scan.scan_id || scan.job_id} scan={scan} />
            ))}
          </div>

          {/* Available MCP Tools */}
          <AvailableMcpTools />
        </div>
      )}
    </div>
  )
}

/* ────────────── Available MCP Tools Panel ────────────── */

interface McpToolInfo { name: string; server: string; description: string }
interface McpToolsResponse {
  total_discovered: number; native_duplicates: number; registered_for_agents: number
  servers: Record<string, number>; tools: McpToolInfo[]
}

function AvailableMcpTools() {
  const { data, isLoading } = useQuery({
    queryKey: ['agent-mcp-tools'],
    queryFn: () => apiFetch<McpToolsResponse>('/agent-mcp-tools'),
    staleTime: 60000,
  })
  const [expanded, setExpanded] = useState(false)
  const [expandedServers, setExpandedServers] = useState<Set<string>>(new Set())

  if (isLoading || !data || data.registered_for_agents === 0) return null

  const serverNames = Object.keys(data.servers).sort()
  const toggleServer = (s: string) => {
    setExpandedServers(prev => {
      const next = new Set(prev)
      next.has(s) ? next.delete(s) : next.add(s)
      return next
    })
  }

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-2.5 flex items-center gap-2 hover:bg-accent/30 transition-colors"
      >
        <Puzzle className="h-4 w-4 text-primary" />
        <span className="text-sm font-medium">Available MCP Tools</span>
        <span className="text-xs text-muted-foreground">
          {data.registered_for_agents} tools from {serverNames.length} servers
        </span>
        {data.native_duplicates > 0 && (
          <span className="text-[10px] text-muted-foreground">
            (+{data.native_duplicates} built-in)
          </span>
        )}
        <ChevronDown className={cn('h-3.5 w-3.5 ml-auto text-muted-foreground transition-transform', expanded ? 'rotate-180' : '')} />
      </button>
      {expanded && (
        <div className="border-t border-border divide-y divide-border">
          {serverNames.map(server => {
            const tools = data.tools.filter(t => t.server === server)
            const isOpen = expandedServers.has(server)
            return (
              <div key={server}>
                <button
                  onClick={() => toggleServer(server)}
                  className="w-full px-4 py-2 flex items-center gap-2 hover:bg-accent/20 text-xs"
                >
                  <ChevronRight className={cn('h-3 w-3 text-muted-foreground transition-transform', isOpen ? 'rotate-90' : '')} />
                  <span className="font-medium">{server}</span>
                  <span className="text-muted-foreground">{tools.length} tools</span>
                </button>
                {isOpen && (
                  <div className="px-4 pb-2 space-y-1">
                    {tools.map(t => (
                      <div key={t.name} className="flex items-start gap-2 py-0.5">
                        <Wrench className="h-3 w-3 text-muted-foreground mt-0.5 shrink-0" />
                        <div>
                          <span className="text-xs font-mono font-medium">{t.name}</span>
                          <span className="text-[10px] text-muted-foreground ml-2">{t.description}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

/* ────────────── Session List ────────────── */

export default function AgentSessions() {
  const { sessionId } = useParams()

  if (sessionId) {
    return <SessionDetail sessionId={sessionId} />
  }

  return <SessionList />
}

function SessionList() {
  const navigate = useNavigate()
  const { data, isLoading } = useAgentSessions()
  const startSession = useStartSession()
  const stopSession = useStopSession()
  const deleteSession = useDeleteSession()
  const clearHistory = useClearSessionHistory()
  const { defaultTargets } = useScanDefaultsStore()
  const performanceWarningQuery = useModelPerformanceWarning()

  const [showForm, setShowForm] = useState(false)
  const [showWarningModal, setShowWarningModal] = useState(false)
  const [pendingSessionData, setPendingSessionData] = useState<any>(null)
  const [activeScope, setActiveScope] = useState('')
  const [sessionProfile, setSessionProfile] = useState<SessionProfile>(DEFAULT_PROFILE)
  const [selectedNodeId, setSelectedNodeId] = useState('')
  const [portProfile, setPortProfile] = useState('')   // '' = agent's built-in quick/deep policy
  const { data: portProfilesData } = usePortProfiles()
  const portProfiles = portProfilesData?.profiles ?? []
  const [webProfile, setWebProfile] = useState('')     // '' = each web tool's own defaults
  const { data: webProfilesData } = useWebProfiles()
  const webProfiles = webProfilesData?.profiles ?? []
  const [form, setForm] = useState({
    target_description: defaultTargets,
    session_name: '',
    initial_task: SESSION_PROFILES[DEFAULT_PROFILE].task,
    max_rounds: 200,
    auto_execute_scans: true,
    // '' = use the service default (AGENT_ENGINE), which is the only engine
    // there is now. Kept as a field because the API still accepts it and saved
    // launch presets may carry one.
    engine: '',
    // Off by default: with it on the session pauses for an approval, so an
    // operator who walks away comes back to a parked session.
    enable_exploit_phase: false,
  })

  // Node + scope selector data
  const nodesQuery = useNodes()
  const onlineNodes = (nodesQuery.data?.nodes ?? []).filter(n => n.status === 'online')
  const { data: scopeNamesData } = useScopeNames()
  const { data: scopeData } = useScope(activeScope)
  const scopeNames = scopeNamesData?.names ?? []

  // Auto-fill targets when scope data loads
  useEffect(() => {
    if (activeScope && scopeData?.targets?.length) {
      const targets = scopeData.targets.map(t => t.target).join(', ')
      setForm(f => ({ ...f, target_description: targets }))
    }
  }, [activeScope, scopeData])

  const sessions: AgentSession[] = data?.sessions ?? []
  // A session paused on an approval interrupt is LIVE, not history: it is
  // waiting on the operator and resumes the moment it is answered. Filing it
  // under history is how an approval sits unnoticed for hours.
  const LIVE_STATUSES = ['active', 'awaiting_approval']
  const active = sessions.filter(s => LIVE_STATUSES.includes(s.status))
  const history = sessions.filter(s => !LIVE_STATUSES.includes(s.status))

  const handleScopeClear = () => {
    setActiveScope('')
    setForm(f => ({ ...f, target_description: defaultTargets }))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    // Resolve proxy URL from selected node
    const selectedNode = onlineNodes.find(n => n.id === selectedNodeId)
    const proxy = selectedNode
      ? `socks5://node-manager:${selectedNode.proxy_port}`
      : undefined

    // port_profile is omitted entirely when unset, so the scanner agent keeps
    // its built-in quick (1-1000+web) then deep (1001-65535) policy.
    // engine: '' means "no override" — sending the key at all would make the
    // service treat an empty string as a choice. There is no selector any more,
    // but the field survives so a saved launch preset carrying an engine still
    // forwards it (the service warns and runs LangGraph if it is the retired one).
    const { engine, ...formRest } = form
    const sessionData = {
      ...formRest, proxy,
      ...(engine ? { engine } : {}),
      ...(portProfile ? { port_profile: portProfile } : {}),
      ...(webProfile ? { web_profile: webProfile } : {}),
    }

    // Check for model performance warnings
    if (performanceWarningQuery.data) {
      const warning = performanceWarningQuery.data
      // If there are warnings, show modal first
      if (warning.has_warnings) {
        setPendingSessionData(sessionData)
        setShowWarningModal(true)
        return
      }
    }

    // No warnings or no warning data available, proceed directly
    startSessionWithData(sessionData)
  }

  const startSessionWithData = (sessionData: any) => {
    startSession.mutate(sessionData, {
      onSuccess: () => {
        setShowForm(false)
        setShowWarningModal(false)
        setPendingSessionData(null)
        setActiveScope('')
        setSelectedNodeId('')
        setSessionProfile(DEFAULT_PROFILE)
        setForm({
          target_description: defaultTargets,
          session_name: '',
          initial_task: SESSION_PROFILES[DEFAULT_PROFILE].task,
          max_rounds: 200,
          auto_execute_scans: true,
          engine: '',
          enable_exploit_phase: false,
        })
      },
    })
  }

  const handleContinueWithWarnings = () => {
    if (pendingSessionData) {
      startSessionWithData(pendingSessionData)
    }
  }

  const handleCancelWarning = () => {
    setShowWarningModal(false)
    setPendingSessionData(null)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Agent Sessions</h2>
        <button
          onClick={() => setShowForm(v => !v)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm"
        >
          {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showForm ? 'Cancel' : 'New Session'}
        </button>
      </div>

      {/* Launch form */}
      {showForm && (
        <form onSubmit={handleSubmit} className="bg-card border border-border rounded-lg p-4 max-w-xl space-y-3">
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Session Name</label>
            <input
              required
              value={form.session_name}
              onChange={e => setForm(f => ({ ...f, session_name: e.target.value }))}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              placeholder="e.g. Corporate Network Scan"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1.5 block">Session Type</label>
            <div className="grid grid-cols-2 gap-2">
              {(Object.entries(SESSION_PROFILES) as [SessionProfile, { label: string; desc: string; task: string }][]).map(([key, profile]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => {
                    setSessionProfile(key)
                    setForm(f => ({ ...f, initial_task: profile.task }))
                  }}
                  className={cn(
                    'flex items-start gap-2 p-3 rounded-lg border text-left transition-colors',
                    sessionProfile === key
                      ? 'border-primary bg-primary/10'
                      : 'border-border hover:border-primary/50 hover:bg-muted/50',
                  )}
                >
                  <div className="mt-0.5">
                    {key === 'full-pentest'
                      ? <Crosshair className={cn('h-4 w-4', sessionProfile === key ? 'text-primary' : 'text-muted-foreground')} />
                      : <Shield className={cn('h-4 w-4', sessionProfile === key ? 'text-primary' : 'text-muted-foreground')} />}
                  </div>
                  <div className="min-w-0">
                    <span className={cn('text-sm font-medium block', sessionProfile === key ? 'text-primary' : 'text-foreground')}>
                      {profile.label}
                    </span>
                    <span className="text-[10px] text-muted-foreground leading-tight block">{profile.desc}</span>
                  </div>
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Scope (optional)</label>
            <div className="flex items-center gap-2">
              <select
                value={activeScope}
                onChange={e => setActiveScope(e.target.value)}
                className="flex-1 bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              >
                <option value="">— Manual targets —</option>
                {scopeNames.map(s => (
                  <option key={s.name} value={s.name}>{s.name} ({s.target_count} targets)</option>
                ))}
              </select>
              {activeScope && (
                <button type="button" onClick={handleScopeClear} className="p-1 text-muted-foreground hover:text-foreground" title="Clear scope">
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Target Description</label>
            <input
              required
              value={form.target_description}
              onChange={e => setForm(f => ({ ...f, target_description: e.target.value }))}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              placeholder="e.g. 192.168.1.0/24"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Initial Task</label>
            <textarea
              required
              value={form.initial_task}
              onChange={e => setForm(f => ({ ...f, initial_task: e.target.value }))}
              rows={8}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary resize-y"
              placeholder="e.g. Perform a full reconnaissance and vulnerability assessment of the target network..."
            />
          </div>
          <div className="flex gap-4 items-end flex-wrap">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Max Rounds</label>
              <input
                type="number"
                value={form.max_rounds}
                onChange={e => setForm(f => ({ ...f, max_rounds: Number(e.target.value) }))}
                className="w-28 bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              />
            </div>
            {/* Port scope for the scanner agent's discovery scans. Leaving this
                on "Agent default" preserves the built-in quick-then-deep policy. */}
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Port Scope</label>
              <select
                value={portProfile}
                onChange={e => setPortProfile(e.target.value)}
                className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              >
                <option value="">Agent default (quick, then deep)</option>
                {portProfiles.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.label} ({p.port_count.toLocaleString()})
                  </option>
                ))}
              </select>
            </div>
            {/* Web scan depth for this session's web tools. */}
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Web Depth</label>
              <select
                value={webProfile}
                onChange={e => setWebProfile(e.target.value)}
                className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              >
                <option value="">Tool defaults</option>
                {webProfiles.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.label} ({p.stage_count} stages)
                  </option>
                ))}
              </select>
            </div>
            {/* The engine selector is gone: AutoGen was retired, so LangGraph is
                the only engine. Offering a second option that the service
                warns about and then silently overrides would be a control that
                claims to do something it does not — worse than no control.
                GET /api/agent-sessions/engine reports what is running. */}
            <label className="flex items-center gap-2 text-sm pb-1">
              <input
                type="checkbox"
                checked={form.auto_execute_scans}
                onChange={e => setForm(f => ({ ...f, auto_execute_scans: e.target.checked }))}
                className="rounded border-border"
              />
              Auto Execute Scans
            </label>
            <label
              className="flex items-center gap-2 text-sm pb-1"
              title="LangGraph only. Adds the exploit phase: one candidate is queued and the session PAUSES until you approve it."
            >
              <input
                type="checkbox"
                checked={form.enable_exploit_phase}
                onChange={e => setForm(f => ({ ...f, enable_exploit_phase: e.target.checked }))}
                className="rounded border-border"
              />
              Exploit phase <span className="text-xs text-muted-foreground">(pauses for approval)</span>
            </label>
          </div>
          {/* Remote proxy node */}
          {onlineNodes.length > 0 && (
            <div>
              <label className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                <Wifi className="h-3 w-3" /> Route Through Remote Node
              </label>
              <select
                value={selectedNodeId}
                onChange={e => setSelectedNodeId(e.target.value)}
                className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              >
                <option value="">Direct (no proxy)</option>
                {onlineNodes.map(n => (
                  <option key={n.id} value={n.id}>
                    {n.name} — {n.hostname || n.id.slice(0, 8)} (:{n.proxy_port})
                  </option>
                ))}
              </select>
              {selectedNodeId && (
                <p className="text-[10px] text-amber-400 mt-0.5">
                  All scans will be routed through this node's SOCKS proxy
                </p>
              )}
            </div>
          )}
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={startSession.isPending}
              className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90 disabled:opacity-50"
            >
              {startSession.isPending ? 'Starting...' : 'Start Session'}
            </button>
          </div>
          {startSession.error && (
            <p className="text-xs text-red-500">{String(startSession.error)}</p>
          )}
        </form>
      )}

      {isLoading && <p className="text-sm text-muted-foreground">Loading...</p>}

      {/* Active sessions */}
      {active.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-muted-foreground mb-2">Active ({active.length})</h3>
          <div className="space-y-2">
            {active.map(s => (
              <div key={s.session_id} className="bg-card border border-border rounded-lg p-3 flex items-center gap-3">
                <StatusDot status={s.status} />
                <div
                  className="flex-1 min-w-0 cursor-pointer"
                  onClick={() => navigate(`/agent-sessions/${s.session_id}`)}
                >
                  <div className="text-sm font-medium truncate flex items-center gap-2">
                    {s.session_name}
                    {s.configuration?.proxy && (
                      <span className="flex items-center gap-1 px-1.5 py-0.5 bg-blue-500/10 text-blue-400 text-[10px] rounded-full border border-blue-500/30 shrink-0">
                        <Wifi className="h-2.5 w-2.5" /> Proxy
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-muted-foreground truncate">{s.target_description}</div>
                </div>
                <span className="text-xs text-muted-foreground shrink-0">{timeAgo(s.created_at)}</span>
                <button
                  onClick={() => stopSession.mutate(s.session_id)}
                  className="p-1 text-red-500 hover:bg-red-500/10 rounded"
                  title="Stop session"
                >
                  <Square className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* History */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <h3 className="text-sm font-medium text-muted-foreground">History ({history.length})</h3>
          {history.length > 0 && (
            <button
              onClick={() => {
                if (window.confirm('Delete ALL session history? This cannot be undone.')) {
                  clearHistory.mutate()
                }
              }}
              disabled={clearHistory.isPending}
              className="text-xs text-red-500 hover:text-red-400 disabled:opacity-50"
            >
              {clearHistory.isPending ? 'Clearing...' : 'Clear History'}
            </button>
          )}
        </div>
        <div className="space-y-1">
          {history.map(s => (
            <div
              key={s.session_id}
              onClick={() => navigate(`/agent-sessions/${s.session_id}`)}
              className="flex items-center gap-3 py-2 px-3 rounded-md hover:bg-muted/50 transition-colors cursor-pointer group"
            >
              <StatusDot status={s.status} />
              <span className="text-sm truncate flex-1">{s.session_name}</span>
              <span
                className={cn(
                  'text-xs',
                  s.status === 'completed'
                    ? 'text-green-500'
                    : s.status === 'failed'
                      ? 'text-red-500'
                      : s.status === 'agent_failure'
                        ? 'text-orange-500'
                        : s.status === 'rounds_exhausted'
                          ? 'text-yellow-500'
                          : s.status === 'awaiting_approval'
                            ? 'text-purple-400'
                            : 'text-yellow-500',
                )}
              >
                {s.status === 'rounds_exhausted'
                  ? 'needs more rounds'
                  : s.status === 'agent_failure'
                    ? 'agent failed'
                    : s.status === 'awaiting_approval'
                      ? 'awaiting approval'
                      : s.status}
              </span>
              <span className="text-xs text-muted-foreground">{timeAgo(s.end_time || s.updated_at || s.created_at)}</span>
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  if (window.confirm(`Delete session "${s.session_name}"?`)) {
                    deleteSession.mutate(s.session_id)
                  }
                }}
                className="p-1 text-muted-foreground hover:text-red-500 opacity-0 group-hover:opacity-100 transition-opacity"
                title="Delete session"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
          {history.length === 0 && !isLoading && (
            <p className="text-sm text-muted-foreground py-4 text-center">No completed sessions</p>
          )}
        </div>
      </div>

      {/* Model Performance Warning Modal */}
      {showWarningModal && performanceWarningQuery.data && (
        <ModelPerformanceWarningModal
          onClose={handleCancelWarning}
          onContinue={handleContinueWithWarnings}
          warning={performanceWarningQuery.data}
          isLoading={startSession.isPending}
        />
      )}
    </div>
  )
}
