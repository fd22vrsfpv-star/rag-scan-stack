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
  }
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
}

interface ResumeSessionParams {
  id: string
  max_rounds: number
  additional_instructions?: string
  proxy?: string
}
