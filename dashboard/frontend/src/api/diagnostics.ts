import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

// ── Types ────────────────────────────────────────────────────────────────

export interface DiagnosticSessionSummary {
  session_id: string
  session_name: string
  target_description: string
  status: string
  created_at: string
  end_time: string | null
}

export interface ScanEntry {
  type: string
  job_id: string
  status: string
  started_at: string | null
  completed_at: string | null
  duration_seconds: number | null
  params: Record<string, unknown>
  result_summary: Record<string, unknown> | null
  scanner_logs: LogEntry[]
}

export interface LogEntry {
  timestamp: string
  level: string
  message: string
  logger?: string
  module?: string
  function?: string
}

export interface FailureTrace {
  has_failures: boolean
  session_error: string | null
  failed_scans: { type: string; job_id: string; status: string; error_hint: string | null }[]
  autogen_errors: { timestamp: string; message: string }[]
  unhealthy_services: string[]
  stalled: boolean
  root_cause_hint: string | null
}

export interface AgentMessage {
  agent_name: string
  role: string
  content: string
  timestamp: string | null
  metadata?: {
    message_type?: 'tool_call' | 'tool_result'
    tool_calls?: { function: string; arguments: string; id: string }[]
  }
}

export interface WebhookEvent {
  id: string
  webhook_id: string
  event_type: string
  payload: Record<string, unknown>
  status: string
  attempt: number
  response_code: number | null
  error_message: string | null
  created_at: string
  delivered_at: string | null
}

export interface DiagnosticBundle {
  session: {
    session_id?: string
    session_name?: string
    target_description?: string
    status?: string
    started_at?: string
    created_at?: string
    ended_at?: string
    end_time?: string
    duration_seconds?: number | null
    error?: string | null
    message_count?: number
    configuration?: Record<string, unknown>
    _error?: string
  }
  scans: ScanEntry[]
  messages: AgentMessage[]
  messages_error?: string
  autogen_logs: LogEntry[]
  autogen_logs_error?: string
  webhook_events: WebhookEvent[]
  webhook_events_error?: string
  watchdog: Record<string, unknown> | null
  watchdog_error?: string
  service_health: Record<string, unknown> | null
  service_health_error?: string
  failure_trace: FailureTrace
  pulled_at: string
}

// ── Hooks ────────────────────────────────────────────────────────────────

export function useRecentDiagnosticSessions(hours = 8) {
  return useQuery({
    queryKey: ['diagnostic-sessions', hours],
    queryFn: () =>
      apiFetch<{ sessions: DiagnosticSessionSummary[] }>(
        `/diagnostics/recent-sessions?hours=${hours}`
      ),
  })
}

export function useDiagnosticBundle(sessionId: string | undefined) {
  return useQuery({
    queryKey: ['diagnostic-bundle', sessionId],
    queryFn: () =>
      apiFetch<DiagnosticBundle>(
        `/diagnostics/session-bundle?session_id=${sessionId}`
      ),
    enabled: !!sessionId,
    staleTime: 0,
  })
}

// ── Markdown Formatter ───────────────────────────────────────────────────

export function formatDiagnosticMarkdown(bundle: DiagnosticBundle): string {
  const s = bundle.session
  const lines: string[] = []

  lines.push(`# Diagnostic Bundle — ${s.session_name || 'Unknown Session'}`)
  lines.push(`*Pulled at ${bundle.pulled_at}*\n`)

  // Session info
  lines.push('## Session Info')
  lines.push(`- **Target:** ${s.target_description || 'N/A'}`)
  lines.push(`- **Status:** ${s.status || 'N/A'}`)
  lines.push(`- **Started:** ${s.started_at || s.created_at || 'N/A'}`)
  lines.push(`- **Ended:** ${s.ended_at || s.end_time || 'still running'}`)
  if (s.duration_seconds != null) {
    const mins = Math.floor(s.duration_seconds / 60)
    const secs = Math.round(s.duration_seconds % 60)
    lines.push(`- **Duration:** ${mins}m ${secs}s`)
  }
  if (s.error) lines.push(`- **Error:** ${s.error}`)
  lines.push('')

  // Failure analysis
  const ft = bundle.failure_trace
  if (ft.has_failures) {
    lines.push('## Failure Analysis')
    if (ft.root_cause_hint) lines.push(`**Root cause hint:** ${ft.root_cause_hint}\n`)
    if (ft.failed_scans.length) {
      lines.push('### Failed Scans')
      for (const fs of ft.failed_scans) {
        lines.push(`- **${fs.type}** (${fs.job_id.slice(0, 8)}): ${fs.error_hint || 'no error details'}`)
      }
      lines.push('')
    }
    if (ft.autogen_errors.length) {
      lines.push('### Autogen Errors')
      for (const e of ft.autogen_errors.slice(0, 10)) {
        lines.push(`- [${e.timestamp}] ${e.message}`)
      }
      lines.push('')
    }
    if (ft.unhealthy_services.length) {
      lines.push(`### Unhealthy Services: ${ft.unhealthy_services.join(', ')}`)
      lines.push('')
    }
  }

  // Scan jobs table
  if (bundle.scans.length) {
    lines.push('## Scan Jobs')
    lines.push('| Type | Status | Duration | Job ID |')
    lines.push('|------|--------|----------|--------|')
    for (const scan of bundle.scans) {
      const dur = scan.duration_seconds != null ? `${Math.round(scan.duration_seconds)}s` : '-'
      lines.push(`| ${scan.type} | ${scan.status} | ${dur} | ${scan.job_id.slice(0, 8)} |`)
    }
    lines.push('')
  }

  // Agent conversation (condensed)
  if (bundle.messages.length) {
    lines.push(`## Agent Conversation (${bundle.messages.length} messages)`)
    for (const msg of bundle.messages.slice(-30)) {
      const ts = msg.timestamp ? msg.timestamp.split('T')[1]?.split('.')[0] || '' : ''
      let content = msg.content || ''
      // Truncate long tool results
      if (msg.metadata?.message_type === 'tool_result' && content.length > 200) {
        content = content.slice(0, 200) + '... [truncated]'
      }
      if (content.length > 500) content = content.slice(0, 500) + '... [truncated]'
      lines.push(`**[${ts}] ${msg.agent_name}:** ${content}\n`)
    }
  }

  // Autogen error logs
  const errorLogs = bundle.autogen_logs.filter(l => l.level?.toUpperCase() === 'ERROR')
  if (errorLogs.length) {
    lines.push('## Autogen Error Logs')
    for (const l of errorLogs.slice(0, 20)) {
      lines.push(`- [${l.timestamp}] ${l.message}`)
    }
    lines.push('')
  }

  // Webhook events
  if (bundle.webhook_events?.length) {
    lines.push(`## Webhook Events (${bundle.webhook_events.length})`)
    lines.push('| Time | Event | Status | Code | Error |')
    lines.push('|------|-------|--------|------|-------|')
    for (const ev of bundle.webhook_events.slice(0, 30)) {
      const ts = ev.created_at ? new Date(ev.created_at).toLocaleTimeString() : '?'
      const code = ev.response_code ?? '-'
      const err = ev.error_message ? ev.error_message.slice(0, 60) : '-'
      const statusIcon = ev.status === 'delivered' ? 'OK' : ev.status === 'failed' ? 'FAIL' : ev.status
      lines.push(`| ${ts} | ${ev.event_type} | ${statusIcon} | ${code} | ${err} |`)
    }
    lines.push('')

    const failed = bundle.webhook_events.filter(e => e.status === 'failed' || e.status === 'retrying')
    if (failed.length) {
      lines.push(`### Webhook Failures (${failed.length})`)
      for (const ev of failed.slice(0, 10)) {
        const payload = JSON.stringify(ev.payload || {}).slice(0, 200)
        lines.push(`- **${ev.event_type}** (attempt ${ev.attempt}): ${ev.error_message || 'unknown error'}`)
        lines.push(`  Payload: \`${payload}\``)
      }
      lines.push('')
    }
  }

  // Service health
  if (bundle.service_health) {
    const svcs = (bundle.service_health as { services?: Record<string, { status: string }> }).services
    if (svcs) {
      const unhealthy = Object.entries(svcs).filter(([, v]) => v.status !== 'healthy')
      if (unhealthy.length) {
        lines.push('## Unhealthy Services')
        for (const [name, info] of unhealthy) {
          lines.push(`- ${name}: ${info.status}`)
        }
      }
    }
  }

  return lines.join('\n')
}
