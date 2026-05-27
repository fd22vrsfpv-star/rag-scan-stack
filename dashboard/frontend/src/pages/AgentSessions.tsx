import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  useAgentSessions,
  useAgentSession,
  useAgentMessages,
  useSessionScans,
  useStartSession,
  useStopSession,
  useResumeSession,
  useDeleteSession,
  useClearSessionHistory,
} from '@/api/agentSessions'
import type { AgentSession, AgentMessage, SessionScan } from '@/api/agentSessions'
import { useModelPerformanceWarning } from '@/api/agents'
import { apiFetch } from '@/api/client'
import { useScopeNames, useScope } from '@/api/scope'
import { StatusDot } from '@/components/common/StatusDot'
import { JsonViewer } from '@/components/common/JsonViewer'
import { ModelPerformanceWarningModal } from '@/components/common/ModelPerformanceWarningModal'
import { cn } from '@/lib/utils'
import { ArrowLeft, Plus, Square, Play, X, Wrench, Terminal, ChevronDown, ChevronRight, ExternalLink, Trash2, Shield, Crosshair, Wifi, Puzzle } from 'lucide-react'
import { useScanDefaultsStore } from '@/stores/scanDefaults'
import { useNodes } from '@/api/nodes'

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
                        : 'bg-yellow-500/10 text-yellow-500',
            )}
          >
            {session.status === 'rounds_exhausted'
              ? 'needs more rounds'
              : session.status === 'agent_failure'
                ? 'agent failed — resumable'
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
  const [form, setForm] = useState({
    target_description: defaultTargets,
    session_name: '',
    initial_task: SESSION_PROFILES[DEFAULT_PROFILE].task,
    max_rounds: 200,
    auto_execute_scans: true,
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
  const active = sessions.filter(s => s.status === 'active')
  const history = sessions.filter(s => s.status !== 'active')

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

    const sessionData = { ...form, proxy }

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
          <div className="flex gap-4 items-end">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Max Rounds</label>
              <input
                type="number"
                value={form.max_rounds}
                onChange={e => setForm(f => ({ ...f, max_rounds: Number(e.target.value) }))}
                className="w-28 bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              />
            </div>
            <label className="flex items-center gap-2 text-sm pb-1">
              <input
                type="checkbox"
                checked={form.auto_execute_scans}
                onChange={e => setForm(f => ({ ...f, auto_execute_scans: e.target.checked }))}
                className="rounded border-border"
              />
              Auto Execute Scans
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
                          : 'text-yellow-500',
                )}
              >
                {s.status === 'rounds_exhausted'
                  ? 'needs more rounds'
                  : s.status === 'agent_failure'
                    ? 'agent failed'
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
