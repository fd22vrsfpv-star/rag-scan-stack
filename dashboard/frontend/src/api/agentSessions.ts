import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import { POLL } from '@/lib/polling'

export function useAgentSessions() {
  return useQuery({
    queryKey: ['agent-sessions'],
    queryFn: () => apiFetch<{ sessions: AgentSession[] }>('/agent-sessions'),
    refetchInterval: POLL.FAST,
  })
}

export function useAgentSession(id: string | undefined) {
  return useQuery({
    queryKey: ['agent-session', id],
    queryFn: () => apiFetch<AgentSession>(`/agent-sessions/${id}`),
    enabled: !!id,
    refetchInterval: POLL.FAST,
    placeholderData: (prev: AgentSession | undefined) => prev,
    retry: 1,
  })
}

/** Per-scan-type flow summary.
 *
 * Served LIVE from the in-memory tracker while the session is active, and from
 * the persisted copy once it has ended — so this is fresher than reading
 * `session.metadata.scan_flow_summary`, which is frozen at teardown while scans
 * are often still running.
 */
export function useSessionFlowSummary(id: string | undefined) {
  return useQuery({
    queryKey: ['agent-session-flow-summary', id],
    queryFn: () => apiFetch<Record<string, unknown>>(`/agent-sessions/${id}/flow-summary`),
    enabled: !!id,
    refetchInterval: POLL.FAST,
    placeholderData: (prev: Record<string, unknown> | undefined) => prev,
    retry: 1,
  })
}

export function useAgentMessages(id: string | undefined) {
  return useQuery({
    queryKey: ['agent-messages', id],
    queryFn: () => apiFetch<{ messages: AgentMessage[] }>(`/agent-sessions/${id}/messages`),
    enabled: !!id,
    refetchInterval: POLL.FAST,
    placeholderData: (prev: { messages: AgentMessage[] } | undefined) => prev,
    retry: 1,
  })
}

export function useSessionScans(id: string | undefined) {
  return useQuery({
    queryKey: ['agent-session-scans', id],
    queryFn: () => apiFetch<SessionScansResponse>(`/agent-sessions/${id}/scans`),
    enabled: !!id,
    refetchInterval: POLL.FAST,
    placeholderData: (prev: SessionScansResponse | undefined) => prev,
    retry: 1,
  })
}

export function useStartSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: StartSessionParams) =>
      apiFetch('/agent-sessions', {
        method: 'POST',
        body: JSON.stringify(params),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent-sessions'] }),
  })
}

export function useStopSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/agent-sessions/${id}/stop`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent-sessions'] }),
  })
}

export function useResumeSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: ResumeSessionParams) =>
      apiFetch(`/agent-sessions/${id}/resume`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent-sessions'] }),
  })
}

/** What a paused LangGraph session is waiting for.
 *
 * Read from the session's Postgres checkpoint, so it is correct even after a
 * service restart. Only polled while the session is actually parked — a session
 * that is running has nothing pending and the extra request is pure noise.
 */
export function usePendingApproval(id: string | undefined, parked: boolean) {
  return useQuery({
    queryKey: ['agent-session-pending-approval', id],
    queryFn: () => apiFetch<PendingApproval>(`/agent-sessions/${id}/pending-approval`),
    enabled: !!id && parked,
    refetchInterval: POLL.FAST,
    retry: 1,
  })
}

/** Answer an approval interrupt; the SAME session continues from its checkpoint. */
export function useApproveSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: ApproveSessionParams) =>
      apiFetch(`/agent-sessions/${id}/approve`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: (_d, vars) => {
      qc.invalidateQueries({ queryKey: ['agent-sessions'] })
      qc.invalidateQueries({ queryKey: ['agent-session', vars.id] })
      qc.invalidateQueries({ queryKey: ['agent-session-pending-approval', vars.id] })
    },
  })
}

/** Which orchestration engine new sessions run on (langgraph | autogen). */
export function useAgentEngine() {
  return useQuery({
    queryKey: ['agent-engine'],
    queryFn: () => apiFetch<AgentEngineInfo>('/agent-sessions/engine'),
    staleTime: 60_000,
    retry: 1,
  })
}

export function useDeleteSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/agent-sessions/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent-sessions'] }),
  })
}

export function useClearSessionHistory() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch('/agent-sessions', { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent-sessions'] }),
  })
}

export interface AgentSession {
  session_id: string
  session_name: string
  target_description: string
  status: string
  max_rounds?: number
  auto_execute_scans?: boolean
  created_at: string
  updated_at?: string
  end_time?: string
  current_round?: number
  error?: string
  configuration?: {
    max_rounds?: number
    auto_execute_scans?: boolean
    initial_task?: string
    proxy?: string
    /** Engine this session actually ran on, resolved at start. Persisted so a
     *  past session still reports its engine after the default is flipped. */
    engine?: string
    enable_exploit_phase?: boolean
  }
}

export interface PendingApproval {
  session_id: string
  status?: string
  engine?: string
  awaiting_approval: boolean
  pending?: {
    kind?: string
    target?: string
    candidate?: string
    prompt?: string
  } | null
  answer_with?: string
}

export interface AgentEngineInfo {
  engine: string
  default: string
  env_AGENT_ENGINE?: string | null
  valid: string[]
  exploit_phase_default?: string | null
  availability: Record<string, { available: boolean; error: string | null }>
}

export interface AgentMessage {
  agent_name: string
  content: string
  timestamp: string
  round?: number
  role?: string
  metadata?: {
    message_type?: 'tool_call' | 'tool_result'
    tool_calls?: { function: string; arguments: string; id: string }[]
  }
}

export interface SessionScan {
  scan_id: string
  type: string
  job_id: string
  status: string
  params: Record<string, unknown>
  result_summary: Record<string, unknown> | null
  progress?: {
    stage?: string
    detail?: string
    phase_number?: number
    total_phases?: number
    total_hosts_discovered?: number
    input_domains?: number
    elapsed_seconds?: number
    phases_completed?: Record<string, unknown>
    targets_count?: number
    findings_count?: number
  } | null
  duration_seconds: number | null
  started_at: string
  completed_at: string | null
}

export interface SessionScansResponse {
  scans: SessionScan[]
  current_phase?: string
  summary?: {
    total_scans: number
    completed: number
    running: number
    failed: number
    by_type?: Record<string, { total: number; completed: number; running: number }>
  }
}

interface StartSessionParams {
  target_description: string
  session_name: string
  initial_task: string
  max_rounds: number
  auto_execute_scans: boolean
  proxy?: string
  /** Named port scope from knowledge/port_profiles.yaml. Omit to keep the
   *  scanner agent's built-in quick-then-deep policy. */
  port_profile?: string
  /** Named web scan depth from knowledge/web_profiles.yaml. Omit to keep each
   *  web tool's own defaults. */
  web_profile?: string
  /** Pin this session to an engine: 'langgraph' (default) or 'autogen' (legacy
   *  GroupChat, kept one release). Omit for the service default. */
  engine?: string
  /** LangGraph only: add the exploit phase. The session PAUSES at
   *  status='awaiting_approval' until an operator answers. */
  enable_exploit_phase?: boolean
}

export interface ApproveSessionParams {
  id: string
  approved: boolean
  /** Required when approved — the pending_exploits row to execute. */
  pending_exploit_id?: string
  note?: string
}

interface ResumeSessionParams {
  id: string
  max_rounds: number
  additional_instructions?: string
  proxy?: string
}
