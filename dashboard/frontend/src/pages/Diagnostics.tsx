import { useState } from 'react'
import {
  useRecentDiagnosticSessions,
  useDiagnosticBundle,
  formatDiagnosticMarkdown,
} from '@/api/diagnostics'
import type { DiagnosticBundle, ScanEntry, LogEntry, AgentMessage, WebhookEvent } from '@/api/diagnostics'
import { useChatStore } from '@/stores/chat'
import { useUIStore } from '@/stores/ui'
import { StatusDot } from '@/components/common/StatusDot'
import {
  AlertTriangle, CheckCircle2, Copy, MessageSquare, ChevronDown,
  ChevronRight, Clock, Target, Loader2, RefreshCw, Activity,
} from 'lucide-react'

// ── Session Selector ─────────────────────────────────────────────────────

function SessionSelector({
  selected,
  onSelect,
  hours,
  onHoursChange,
}: {
  selected: string | undefined
  onSelect: (id: string) => void
  hours: number
  onHoursChange: (h: number) => void
}) {
  const { data, isLoading } = useRecentDiagnosticSessions(hours)
  const sessions = data?.sessions || []

  return (
    <div className="flex items-center gap-4 flex-wrap">
      <div className="flex items-center gap-2">
        <label className="text-sm text-zinc-400">Session:</label>
        <select
          className="bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm min-w-[300px]"
          value={selected || ''}
          onChange={e => onSelect(e.target.value)}
          disabled={isLoading}
        >
          {!selected && <option value="">Select a session...</option>}
          {sessions.map(s => (
            <option key={s.session_id} value={s.session_id}>
              {s.session_name} — {s.target_description} [{s.status}] ({new Date(s.created_at).toLocaleTimeString()})
            </option>
          ))}
          {sessions.length === 0 && <option value="" disabled>No sessions in last {hours}h</option>}
        </select>
      </div>
      <div className="flex items-center gap-2">
        <label className="text-sm text-zinc-400">Lookback:</label>
        <select
          className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-sm"
          value={hours}
          onChange={e => onHoursChange(Number(e.target.value))}
        >
          {[1, 2, 4, 8, 12, 24, 48, 72].map(h => (
            <option key={h} value={h}>{h}h</option>
          ))}
        </select>
      </div>
    </div>
  )
}

// ── Failure Trace Alert ──────────────────────────────────────────────────

function FailureTraceAlert({ trace }: { trace: DiagnosticBundle['failure_trace'] }) {
  if (!trace.has_failures) return null

  return (
    <div className="border border-red-500/30 bg-red-500/10 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-2">
        <AlertTriangle className="w-5 h-5 text-red-400" />
        <span className="font-semibold text-red-400">Failures Detected</span>
      </div>
      {trace.root_cause_hint && (
        <p className="text-sm text-red-300 mb-3">{trace.root_cause_hint}</p>
      )}
      {trace.failed_scans.length > 0 && (
        <div className="text-sm space-y-1">
          {trace.failed_scans.map((fs, i) => (
            <div key={i} className="text-zinc-300">
              <span className="text-red-400 font-mono">{fs.type}</span>
              <span className="text-zinc-500 ml-1">({fs.job_id.slice(0, 8)})</span>
              {fs.error_hint && <span className="text-zinc-400 ml-2">— {fs.error_hint}</span>}
            </div>
          ))}
        </div>
      )}
      {trace.stalled && (
        <p className="text-sm text-amber-400 mt-2">Session was stalled — watchdog detected no progress</p>
      )}
      {trace.unhealthy_services.length > 0 && (
        <p className="text-sm text-amber-400 mt-2">
          Unhealthy services: {trace.unhealthy_services.join(', ')}
        </p>
      )}
    </div>
  )
}

// ── Session Info Card ────────────────────────────────────────────────────

function SessionInfoCard({ session }: { session: DiagnosticBundle['session'] }) {
  if (session._error) {
    return <div className="text-red-400 text-sm">Failed to load session: {session._error}</div>
  }

  const statusColor: Record<string, string> = {
    active: 'text-blue-400', completed: 'text-green-400', failed: 'text-red-400',
    stopped: 'text-yellow-400', stalled: 'text-amber-400',
  }

  return (
    <div className="bg-zinc-800/50 rounded-lg p-4 border border-zinc-700">
      <div className="flex items-center gap-3 mb-3">
        <Target className="w-5 h-5 text-zinc-400" />
        <h3 className="font-semibold text-lg">{session.session_name || 'Unnamed'}</h3>
        <span className={`text-sm font-medium ${statusColor[session.status || ''] || 'text-zinc-400'}`}>
          {session.status}
        </span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
        <div><span className="text-zinc-500">Target:</span> <span>{session.target_description}</span></div>
        <div><span className="text-zinc-500">Started:</span> <span>{session.started_at ? new Date(session.started_at).toLocaleString() : '-'}</span></div>
        <div><span className="text-zinc-500">Ended:</span> <span>{(session.ended_at || session.end_time) ? new Date((session.ended_at || session.end_time)!).toLocaleString() : 'running'}</span></div>
        <div><span className="text-zinc-500">Duration:</span> <span>{session.duration_seconds != null ? `${Math.floor(session.duration_seconds / 60)}m ${Math.round(session.duration_seconds % 60)}s` : '-'}</span></div>
      </div>
      {session.error && (
        <div className="mt-3 p-2 bg-red-500/10 rounded text-sm text-red-300 border border-red-500/20">
          {typeof session.error === 'string' ? session.error : JSON.stringify(session.error, null, 2)}
        </div>
      )}
    </div>
  )
}

// ── Collapsible Section ──────────────────────────────────────────────────

function Section({ title, count, defaultOpen, children, errorBadge }: {
  title: string
  count?: number
  defaultOpen?: boolean
  children: React.ReactNode
  errorBadge?: number
}) {
  const [open, setOpen] = useState(defaultOpen ?? false)
  return (
    <div className="border border-zinc-700 rounded-lg overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-4 py-3 bg-zinc-800/50 hover:bg-zinc-800 text-left"
        onClick={() => setOpen(!open)}
      >
        {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        <span className="font-medium">{title}</span>
        {count != null && <span className="text-xs text-zinc-500">({count})</span>}
        {errorBadge != null && errorBadge > 0 && (
          <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">{errorBadge} errors</span>
        )}
      </button>
      {open && <div className="p-4 border-t border-zinc-700">{children}</div>}
    </div>
  )
}

// ── Scan Jobs Table ──────────────────────────────────────────────────────

function ScanJobsTable({ scans }: { scans: ScanEntry[] }) {
  const [expanded, setExpanded] = useState<string | null>(null)

  if (!scans.length) return <p className="text-sm text-zinc-500">No scans recorded</p>

  return (
    <div className="space-y-1">
      {scans.map(scan => {
        const isExpanded = expanded === scan.job_id
        const isFailed = scan.status === 'failed' || scan.status === 'error'
        return (
          <div key={scan.job_id} className={`rounded border ${isFailed ? 'border-red-500/30 bg-red-500/5' : 'border-zinc-700'}`}>
            <button
              className="w-full flex items-center gap-3 px-3 py-2 text-sm text-left hover:bg-zinc-800/50"
              onClick={() => setExpanded(isExpanded ? null : scan.job_id)}
            >
              {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
              <span className="font-mono w-28">{scan.type}</span>
              <StatusDot status={scan.status === 'completed' ? 'healthy' : scan.status} />
              <span className={`w-20 ${isFailed ? 'text-red-400' : ''}`}>{scan.status}</span>
              <span className="text-zinc-500 w-16">
                {scan.duration_seconds != null ? `${Math.round(scan.duration_seconds)}s` : '-'}
              </span>
              <span className="text-zinc-600 font-mono text-xs">{scan.job_id.slice(0, 12)}</span>
            </button>
            {isExpanded && (
              <div className="px-4 py-3 border-t border-zinc-700/50 text-xs space-y-3">
                <div className="grid grid-cols-2 gap-2 text-zinc-400">
                  <div>Started: {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}</div>
                  <div>Completed: {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '-'}</div>
                </div>
                {scan.params && Object.keys(scan.params).length > 0 && (
                  <div>
                    <div className="text-zinc-500 mb-1">Parameters:</div>
                    <pre className="bg-zinc-900 p-2 rounded text-zinc-300 overflow-x-auto">{JSON.stringify(scan.params, null, 2)}</pre>
                  </div>
                )}
                {scan.result_summary && Object.keys(scan.result_summary).length > 0 && (
                  <div>
                    <div className="text-zinc-500 mb-1">Result Summary:</div>
                    <pre className="bg-zinc-900 p-2 rounded text-zinc-300 overflow-x-auto">{JSON.stringify(scan.result_summary, null, 2)}</pre>
                  </div>
                )}
                {scan.scanner_logs.length > 0 && (
                  <div>
                    <div className="text-zinc-500 mb-1">Scanner Logs ({scan.scanner_logs.length}):</div>
                    <div className="bg-zinc-900 rounded p-2 max-h-40 overflow-y-auto space-y-0.5">
                      {scan.scanner_logs.map((l: LogEntry, i: number) => (
                        <div key={i} className={`font-mono ${l.level?.toUpperCase() === 'ERROR' ? 'text-red-400' : 'text-zinc-400'}`}>
                          [{l.timestamp?.split('T')[1]?.split('.')[0] || ''}] {l.level} — {l.message}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Agent Conversation ───────────────────────────────────────────────────

function AgentConversation({ messages }: { messages: AgentMessage[] }) {
  if (!messages.length) return <p className="text-sm text-zinc-500">No messages</p>

  const agentColors: Record<string, string> = {
    System: 'text-zinc-500', Coordinator: 'text-blue-400', Scanner: 'text-green-400',
    Reporter: 'text-purple-400', Executor: 'text-amber-400', Analyst: 'text-cyan-400',
  }

  return (
    <div className="space-y-2 max-h-96 overflow-y-auto">
      {messages.map((msg, i) => {
        const isToolCall = msg.metadata?.message_type === 'tool_call'
        const isToolResult = msg.metadata?.message_type === 'tool_result'
        return (
          <div key={i} className={`text-sm ${isToolResult ? 'opacity-60' : ''}`}>
            <div className="flex items-center gap-2 mb-0.5">
              <span className={`font-semibold ${agentColors[msg.agent_name] || 'text-zinc-300'}`}>
                {msg.agent_name}
              </span>
              {msg.timestamp && (
                <span className="text-xs text-zinc-600">{msg.timestamp.split('T')[1]?.split('.')[0]}</span>
              )}
              {isToolCall && <span className="text-xs bg-amber-500/20 text-amber-400 px-1 rounded">tool call</span>}
              {isToolResult && <span className="text-xs bg-zinc-700 text-zinc-400 px-1 rounded">result</span>}
            </div>
            <div className={`pl-4 text-zinc-300 whitespace-pre-wrap break-words ${isToolCall ? 'font-mono text-xs bg-zinc-900 rounded p-2' : ''}`}>
              {msg.content.length > 1000 && !isToolCall
                ? msg.content.slice(0, 1000) + '\n... [truncated]'
                : msg.content}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Autogen Logs Panel ───────────────────────────────────────────────────

function AutogenLogsPanel({ logs }: { logs: LogEntry[] }) {
  const [filter, setFilter] = useState<'all' | 'error'>('all')
  const filtered = filter === 'error'
    ? logs.filter(l => l.level?.toUpperCase() === 'ERROR' || l.level?.toUpperCase() === 'CRITICAL')
    : logs

  return (
    <div>
      <div className="flex gap-2 mb-2">
        <button
          className={`text-xs px-2 py-1 rounded ${filter === 'all' ? 'bg-zinc-700' : 'bg-zinc-800 text-zinc-500'}`}
          onClick={() => setFilter('all')}
        >All ({logs.length})</button>
        <button
          className={`text-xs px-2 py-1 rounded ${filter === 'error' ? 'bg-red-500/20 text-red-400' : 'bg-zinc-800 text-zinc-500'}`}
          onClick={() => setFilter('error')}
        >Errors ({logs.filter(l => l.level?.toUpperCase() === 'ERROR').length})</button>
      </div>
      <div className="bg-zinc-900 rounded p-2 max-h-64 overflow-y-auto font-mono text-xs space-y-0.5">
        {filtered.length === 0 && <div className="text-zinc-600">No logs</div>}
        {filtered.map((l, i) => (
          <div key={i} className={l.level?.toUpperCase() === 'ERROR' ? 'text-red-400' : l.level?.toUpperCase() === 'WARNING' ? 'text-amber-400' : 'text-zinc-400'}>
            [{l.timestamp?.split('T')[1]?.split('.')[0] || ''}] {l.level} {l.message}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Service Health Snapshot ──────────────────────────────────────────────

// ── Webhook Events Panel ─────────────────────────────────────────────────

function WebhookEventsPanel({ events }: { events: WebhookEvent[] }) {
  if (!events.length) return <p className="text-sm text-zinc-500">No webhook events</p>

  const statusColors: Record<string, string> = {
    delivered: 'text-green-400 bg-green-500/10',
    pending: 'text-yellow-400 bg-yellow-500/10',
    failed: 'text-red-400 bg-red-500/10',
    retrying: 'text-orange-400 bg-orange-500/10',
  }

  const eventTypeColors: Record<string, string> = {
    scan_completed: 'text-blue-400',
    scan_failed: 'text-red-400',
    finding_high: 'text-orange-400',
    finding_critical: 'text-red-400',
    finding_exploitable: 'text-red-400',
    ingest_completed: 'text-green-400',
    scan_started: 'text-blue-300',
  }

  return (
    <div className="space-y-1">
      <div className="grid grid-cols-[100px_140px_70px_50px_1fr] gap-2 text-[10px] font-medium text-zinc-500 px-2 py-1 border-b border-zinc-800">
        <span>Time</span>
        <span>Event</span>
        <span>Status</span>
        <span>Code</span>
        <span>Detail</span>
      </div>
      {events.map(ev => {
        const ts = ev.created_at ? new Date(ev.created_at).toLocaleTimeString() : '?'
        const payload = ev.payload || {}
        const detail = ev.status === 'failed'
          ? ev.error_message || 'delivery failed'
          : (payload as Record<string, unknown>).source
            ? `${(payload as Record<string, unknown>).source}: ${JSON.stringify((payload as Record<string, unknown>).stats || (payload as Record<string, unknown>).data || {}).slice(0, 80)}`
            : JSON.stringify(payload).slice(0, 100)

        return (
          <div key={ev.id} className="grid grid-cols-[100px_140px_70px_50px_1fr] gap-2 text-[10px] px-2 py-1 hover:bg-zinc-800/50 border-b border-zinc-800/30">
            <span className="text-zinc-500 font-mono">{ts}</span>
            <span className={eventTypeColors[ev.event_type] || 'text-zinc-400'}>{ev.event_type}</span>
            <span className={`px-1.5 py-0.5 rounded text-center ${statusColors[ev.status] || 'text-zinc-400'}`}>{ev.status}</span>
            <span className="text-zinc-500 font-mono">{ev.response_code ?? '-'}</span>
            <span className="text-zinc-400 truncate" title={ev.error_message || JSON.stringify(ev.payload).slice(0, 300)}>
              {detail}
            </span>
          </div>
        )
      })}
    </div>
  )
}

function ServiceHealthSnapshot({ health }: { health: Record<string, unknown> | null }) {
  if (!health) return <p className="text-sm text-zinc-500">Health data unavailable</p>

  const services = (health as { services?: Record<string, { status: string }> }).services || {}
  return (
    <div className="grid grid-cols-3 md:grid-cols-5 gap-2 text-xs">
      {Object.entries(services).map(([name, info]) => (
        <div key={name} className="flex items-center gap-1.5">
          <StatusDot status={info.status} />
          <span className="text-zinc-400">{name.replace(/_/g, ' ')}</span>
        </div>
      ))}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────

export default function Diagnostics() {
  const [selectedId, setSelectedId] = useState<string | undefined>()
  const [hours, setHours] = useState(8)
  const [copied, setCopied] = useState(false)
  const setChatOpen = useUIStore(s => s.setChatOpen)

  // Auto-select most recent session on first load
  const { data: sessionsData } = useRecentDiagnosticSessions(hours)
  const effectiveId = selectedId || sessionsData?.sessions?.[0]?.session_id
  const { data: bundle, isLoading, refetch } = useDiagnosticBundle(effectiveId)

  const handleCopy = () => {
    if (!bundle) return
    navigator.clipboard.writeText(formatDiagnosticMarkdown(bundle))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleSendToChat = () => {
    if (!bundle) return
    const md = formatDiagnosticMarkdown(bundle)
    const store = useChatStore.getState()
    store.clearMessages()
    store.setPendingInput(
      `Analyze this diagnostic bundle and help me identify why the scan failed or stalled. Trace the flow of events and pinpoint the root cause:\n\n${md}`
    )
    setChatOpen(true)
  }

  const errorLogCount = bundle?.autogen_logs.filter(l => l.level?.toUpperCase() === 'ERROR').length || 0

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-6 h-6 text-zinc-400" />
          <h1 className="text-xl font-semibold">Diagnostic Log Pull</h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-zinc-700 hover:bg-zinc-600 rounded"
            onClick={() => refetch()}
            disabled={isLoading}
          >
            {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            Refresh
          </button>
          <button
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-zinc-700 hover:bg-zinc-600 rounded"
            onClick={handleCopy}
            disabled={!bundle}
          >
            <Copy className="w-4 h-4" />
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-500 rounded"
            onClick={handleSendToChat}
            disabled={!bundle}
          >
            <MessageSquare className="w-4 h-4" />
            Send to Chat
          </button>
        </div>
      </div>

      <SessionSelector
        selected={effectiveId}
        onSelect={setSelectedId}
        hours={hours}
        onHoursChange={setHours}
      />

      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-zinc-500" />
          <span className="ml-2 text-zinc-500">Pulling diagnostic data...</span>
        </div>
      )}

      {bundle && !isLoading && (
        <div className="space-y-4">
          <FailureTraceAlert trace={bundle.failure_trace} />
          <SessionInfoCard session={bundle.session} />

          <Section title="Scan Jobs" count={bundle.scans.length} defaultOpen errorBadge={bundle.failure_trace.failed_scans.length}>
            <ScanJobsTable scans={bundle.scans} />
          </Section>

          <Section title="Agent Conversation" count={bundle.messages.length}>
            <AgentConversation messages={bundle.messages} />
          </Section>

          <Section title="Autogen Runtime Logs" count={bundle.autogen_logs.length} errorBadge={errorLogCount}>
            <AutogenLogsPanel logs={bundle.autogen_logs} />
          </Section>

          {bundle.webhook_events?.length > 0 && (
            <Section
              title="Webhook Events"
              count={bundle.webhook_events.length}
              errorBadge={bundle.webhook_events.filter(e => e.status === 'failed' || e.status === 'retrying').length}
            >
              <WebhookEventsPanel events={bundle.webhook_events} />
            </Section>
          )}

          <Section title="Service Health">
            <ServiceHealthSnapshot health={bundle.service_health} />
          </Section>

          {bundle.watchdog && (
            <Section title="Watchdog Status">
              <pre className="bg-zinc-900 rounded p-3 text-xs text-zinc-300 overflow-x-auto">
                {JSON.stringify(bundle.watchdog, null, 2)}
              </pre>
            </Section>
          )}
        </div>
      )}

      {!bundle && !isLoading && effectiveId && (
        <div className="text-center py-12 text-zinc-500">
          <Clock className="w-8 h-8 mx-auto mb-2" />
          <p>Select a session to pull diagnostics</p>
        </div>
      )}
    </div>
  )
}
