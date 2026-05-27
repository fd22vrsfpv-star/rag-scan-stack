import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { RemoteNode, InstallationTask, ADAttackResult, ADAttackType } from '@/lib/types'
import { POLL } from '@/lib/polling'

// ── Nodes ──────────────────────────────────────────────────────────
export function useNodes() {
  return useQuery({
    queryKey: ['nodes'],
    queryFn: () => apiFetch<{ nodes: RemoteNode[] }>('/nodes'),
    refetchInterval: POLL.FAST, // 10s for active node management
    // Remove placeholderData for immediate updates
  })
}

export function useNode(id: string) {
  return useQuery({
    queryKey: ['node', id],
    queryFn: () => apiFetch<RemoteNode>(`/nodes/${id}`),
    enabled: !!id,
  })
}

export function useRegisterNode() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<{ id: string; proxy_port: number }>('/nodes/register', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useDecommissionNode() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ ok: boolean }>(`/nodes/${nodeId}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

// ── Scan through node ──────────────────────────────────────────────
export function useScanThroughNode() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeId, ...params }: { nodeId: string } & Record<string, unknown>) =>
      apiFetch<{ job_id: string }>(`/nodes/${nodeId}/scan`, {
        method: 'POST',
        body: JSON.stringify(params),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

// ── SOCKS management ───────────────────────────────────────────────
export function useStartSocks() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeId, sessionId }: { nodeId: string; sessionId?: string }) =>
      apiFetch<{ ok: boolean; port: number }>(`/nodes/${nodeId}/socks/start`, {
        method: 'POST',
        body: JSON.stringify({ session_id: sessionId }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useStopSocks() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ ok: boolean }>(`/nodes/${nodeId}/socks/stop`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

// ── Implants ───────────────────────────────────────────────────────
export function useGenerateImplant() {
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch<{ ok: boolean; name: string; size_bytes: number }>('/nodes/implants/generate', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  })
}

export function useImplants() {
  return useQuery({
    queryKey: ['implants'],
    queryFn: () => apiFetch<{ implants: unknown[] }>('/nodes/implants'),
  })
}

// ── Sessions ───────────────────────────────────────────────────────
export function useSliverSessions() {
  return useQuery({
    queryKey: ['sliver-sessions'],
    queryFn: () => apiFetch<{ sessions: unknown[] }>('/nodes/sessions'),
    refetchInterval: POLL.BACKGROUND,
    placeholderData: (prev) => prev as any,
  })
}

// ── AD Attacks ─────────────────────────────────────────────────────
export function useADAttackTypes() {
  return useQuery({
    queryKey: ['ad-attack-types'],
    queryFn: () => apiFetch<{ attacks: ADAttackType[] }>('/nodes/ad/attacks'),
  })
}

export function useADAttack() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      nodeId,
      attackType,
      ...payload
    }: {
      nodeId: string
      attackType: string
      target_domain?: string
      custom_args?: string
    }) =>
      apiFetch<{ result_id: string; status: string }>(`/nodes/${nodeId}/ad/${attackType}`, {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-results'] }),
  })
}

export function useADResults(nodeId: string) {
  return useQuery({
    queryKey: ['ad-results', nodeId],
    queryFn: () => apiFetch<{ results: ADAttackResult[] }>(`/nodes/${nodeId}/ad/results`),
    enabled: !!nodeId,
    refetchInterval: POLL.BACKGROUND,
    placeholderData: (prev) => prev as any,
  })
}

// ── Chisel config ──────────────────────────────────────────────────
export function useChiselConfig() {
  return useMutation({
    mutationFn: (payload: { server_host: string; node_name?: string }) =>
      apiFetch<{ command: string; socks_port: number }>('/nodes/chisel/config', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  })
}

// ── SSH Tunnels ───────────────────────────────────────────────────
export function useSSHKeys() {
  return useQuery({
    queryKey: ['ssh-keys'],
    queryFn: () => apiFetch<{ keys: string[] }>('/nodes/ssh/keys'),
  })
}

export function useSSHPublicKeys() {
  return useQuery({
    queryKey: ['ssh-public-keys'],
    queryFn: () => apiFetch<{ keys: string[] }>('/nodes/ssh/public-keys'),
  })
}

export function useSSHConnect() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: {
      name: string
      host: string
      user?: string
      ssh_port?: number
      key_name?: string
      network_segment?: string
      os_type?: string
      provider?: string
    }) =>
      apiFetch<{ id: string; name: string; proxy_port: number; status: string }>(
        '/nodes/ssh/connect',
        { method: 'POST', body: JSON.stringify(payload) },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function usePatchNode() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeId, ...payload }: { nodeId: string; os_type?: string }) =>
      apiFetch<{ ok: boolean }>(`/nodes/${nodeId}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

// ── Background Installation (stable across window closures) ────────────────
export function useCreateBackgroundInstall() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeId, ...payload }: { nodeId: string } & Record<string, unknown>) =>
      apiFetch<{ ok: boolean; task_id: string; message: string; status_url: string }>(
        `/nodes/${nodeId}/provision-background`,
        {
          method: 'POST',
          body: JSON.stringify(payload),
        }
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useInstallationTasks(nodeId: string) {
  return useQuery({
    queryKey: ['installation-tasks', nodeId],
    queryFn: () => apiFetch<{ tasks: InstallationTask[] }>(`/nodes/${nodeId}/installation-tasks`),
    enabled: !!nodeId,
    refetchInterval: 5000, // Poll every 5s for task updates
  })
}

export function useInstallationTask(nodeId: string, taskId: string) {
  return useQuery({
    queryKey: ['installation-task', nodeId, taskId],
    queryFn: () => apiFetch<InstallationTask>(`/nodes/${nodeId}/installation-tasks/${taskId}`),
    enabled: !!(nodeId && taskId),
    refetchInterval: 3000, // Poll every 3s for detailed progress
  })
}

export function useCancelInstallationTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeId, taskId }: { nodeId: string; taskId: string }) =>
      apiFetch<{ ok: boolean; message: string }>(`/nodes/${nodeId}/installation-tasks/${taskId}`, {
        method: 'DELETE',
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['installation-tasks'] }),
  })
}

// SSE-based provision and check tools — consumed directly in components
// (no React Query hooks needed for streaming)

export function useSSHDisconnect() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ ok: boolean }>(`/nodes/${nodeId}/ssh/disconnect`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useSSHReconnect() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ ok: boolean; status: string; proxy_port?: number }>(
        `/nodes/${nodeId}/ssh/reconnect`,
        { method: 'POST' },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useSSHExec() {
  return useMutation({
    mutationFn: ({ nodeId, command, timeout }: { nodeId: string; command: string; timeout?: number }) =>
      apiFetch<{ ok: boolean; stdout: string; stderr: string; exit_code: number; duration_ms?: number; error?: string }>(
        `/nodes/${nodeId}/ssh/exec`,
        { method: 'POST', body: JSON.stringify({ command, timeout }) },
      ),
  })
}

export function useSSHUpload() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeId, file, remotePath }: { nodeId: string; file: File; remotePath: string }) => {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('remote_path', remotePath)
      return apiFetch<{ ok: boolean }>(`/nodes/${nodeId}/ssh/upload`, {
        method: 'POST',
        body: formData,
        headers: {},  // Let browser set Content-Type with boundary
      })
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

// ── Remote Scan (execute tools directly on SSH dropbox) ──────────
export interface RemoteScanRequest {
  scan_type: string
  targets: string[]
  ports?: string
  rate?: number
  extra_args?: string[]
  timeout?: number
}

export function useRemoteScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: { nodeId: string; body: RemoteScanRequest }) =>
      apiFetch<{ ok: boolean; job_id: string; scan_type: string; duration_s: number; ingest: unknown }>(
        `/nodes/${params.nodeId}/ssh/remote-scan`,
        { method: 'POST', body: JSON.stringify(params.body) },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export function useSSHDownload() {
  return useMutation({
    mutationFn: async ({ nodeId, remotePath }: { nodeId: string; remotePath: string }) => {
      const resp = await fetch(`/api/nodes/${nodeId}/ssh/download`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ remote_path: remotePath }),
      })
      if (!resp.ok) throw new Error(await resp.text())
      const blob = await resp.blob()
      const filename = remotePath.split('/').pop() || 'download'
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      return { ok: true }
    },
  })
}

// ── WireGuard Tunnels ──────────────────────────────────────────────────
export interface WGPeer {
  id: string
  name: string
  public_key: string
  assigned_ip: string
  endpoint?: string
  created_at: string
  status: 'active' | 'inactive' | 'error' | 'online' | 'offline'
  install_status?: string  // Installation status from WireGuard client management
  installation_logs?: string[]
}

export interface WGPeerConfig {
  name: string
  node_id: string
  client_config: string
  qr_code?: string
}

export function useWGPeers() {
  return useQuery({
    queryKey: ['wg-peers'],
    queryFn: () => apiFetch<{ peers: WGPeer[] }>('/wg/peers'),
    refetchInterval: POLL.FAST, // 10s instead of 120s for active management
    // Remove placeholderData for immediate updates after deletion
  })
}

export function useCreateWGPeer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: { name: string; node_id: string; endpoint?: string; auto_install?: boolean }) =>
      apiFetch<WGPeerConfig>('/wg/peers', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wg-peers'] })
      qc.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useDeleteWGPeer() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (peerId: string) =>
      apiFetch<{ ok: boolean }>(`/wg/peers/${peerId}`, { method: 'DELETE' }),
    // Optimistic update: remove peer from UI and update node immediately
    onMutate: async (peerId: string) => {
      await qc.cancelQueries({ queryKey: ['wg-peers'] })
      await qc.cancelQueries({ queryKey: ['nodes'] })

      const previousPeers = qc.getQueryData(['wg-peers'])
      const previousNodes = qc.getQueryData(['nodes'])

      // Remove from WireGuard peers list
      qc.setQueryData(['wg-peers'], (old: any) => ({
        peers: old?.peers?.filter((p: any) => p.id !== peerId) ?? []
      }))

      // Update node to revert WireGuard status
      qc.setQueryData(['nodes'], (old: any) => ({
        nodes: old?.nodes?.map((node: any) =>
          node.id === peerId
            ? { ...node, tunnel_method: 'ssh', wg_public_key: null, wg_assigned_ip: null }
            : node
        ) ?? []
      }))

      return { previousPeers, previousNodes }
    },
    onError: (err, peerId, context) => {
      // Revert optimistic updates on error
      if (context?.previousPeers) qc.setQueryData(['wg-peers'], context.previousPeers)
      if (context?.previousNodes) qc.setQueryData(['nodes'], context.previousNodes)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wg-peers'] })
      qc.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useWGPeerConfig(peerId: string) {
  return useQuery({
    queryKey: ['wg-peer-config', peerId],
    queryFn: () => apiFetch<WGPeerConfig>(`/wg/peers/${peerId}/config`),
    enabled: !!peerId,
  })
}

// WireGuard client management hooks
export function useWGClientStatus() {
  return useMutation({
    mutationFn: (peerId: string) =>
      apiFetch<{ ok: boolean; status_output: string; error?: string; exit_code: number }>(`/wg/peers/${peerId}/client/status`, {
        method: 'POST',
      }),
  })
}

export function useStartWGClient() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (peerId: string) =>
      apiFetch<{ ok: boolean; output: string; error?: string; exit_code: number }>(`/wg/peers/${peerId}/client/start`, {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wg-peers'] })
      qc.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useStopWGClient() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (peerId: string) =>
      apiFetch<{ ok: boolean; output: string; error?: string; exit_code: number }>(`/wg/peers/${peerId}/client/stop`, {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wg-peers'] })
      qc.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useRestartWGClient() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (peerId: string) =>
      apiFetch<{ ok: boolean; output: string; error?: string; exit_code: number }>(`/wg/peers/${peerId}/client/restart`, {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wg-peers'] })
      qc.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}


// ── DigitalOcean Cloud Provisioning ─────────────────────────────────────────

export interface DOOptions {
  sizes: { slug: string; label: string; vcpus: number; memory: number; price: number }[]
  regions: { slug: string; label: string }[]
}

export interface DODroplet {
  id: number
  name: string
  ip: string
  status: string
  region: string
  size: string
  created_at: string
  image: string
}

export function useDODroplets() {
  return useQuery({
    queryKey: ['do-droplets'],
    queryFn: () => apiFetch<{ droplets: DODroplet[]; total: number }>('/cloud/do/droplets'),
    refetchInterval: POLL.BACKGROUND,
    placeholderData: (prev) => prev as any,
  })
}

export function useDOOptions() {
  return useQuery({
    queryKey: ['do-options'],
    queryFn: () => apiFetch<DOOptions>('/cloud/do/options'),
  })
}

export function useCreateDODroplet() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: { name: string; size: string; region: string; key_name?: string; os_type?: string }) =>
      apiFetch<{ ok: boolean; droplet_id?: string; status?: string; message?: string; name?: string }>(
        '/cloud/do/create', { method: 'POST', body: JSON.stringify(params) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useDOProvisionStatus(dropletId: string | null) {
  return useQuery({
    queryKey: ['do-provision-status', dropletId],
    queryFn: () => apiFetch<{ droplet_id: string; status: string; ip?: string; node_id?: string; socks_port?: number; error?: string }>(
      `/cloud/do/status/${dropletId}`),
    enabled: !!dropletId,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      if (status === 'online' || status === 'failed' || status === 'tunnel_error' || status === 'ssh_timeout') return false
      return 3000 // Poll every 3s while provisioning
    },
  })
}

export function useDestroyDODropletById() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (dropletId: number) =>
      apiFetch<{ ok: boolean; droplet_destroyed: boolean; node_removed: string | null }>(`/cloud/do/droplet-by-id/${dropletId}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['do-droplets'] })
      qc.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useDestroyDODroplet() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ ok: boolean; droplet_destroyed: boolean }>(`/cloud/do/droplet/${nodeId}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

// ── AWS EC2 ─────────────────────────────────────────────────────────

export interface AWSOptions {
  instance_types: { type: string; label: string; vcpus: number; memory: number; price: number }[]
  regions: { id: string; label: string }[]
  amis: Record<string, string>
}

export interface AWSInstance {
  id: string; name: string; ip: string; private_ip: string
  status: string; type: string; region: string; launched_at: string
}

export function useAWSOptions() {
  return useQuery({
    queryKey: ['aws-options'],
    queryFn: () => apiFetch<AWSOptions>('/cloud/aws/options'),
  })
}

export function useCreateAWSInstance() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: Record<string, unknown>) =>
      apiFetch<{ ok: boolean; instance_id: string; status: string }>('/cloud/aws/create', {
        method: 'POST', body: JSON.stringify(params),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useAWSProvisionStatus(instanceId: string | null) {
  return useQuery({
    queryKey: ['aws-provision-status', instanceId],
    queryFn: () => apiFetch<{ instance_id: string; status: string; ip?: string; node_id?: string; error?: string }>(
      `/cloud/aws/status/${instanceId}`),
    enabled: !!instanceId,
    refetchInterval: (query) => {
      const s = query.state.data?.status
      if (s === 'online' || s === 'failed' || s === 'tunnel_error' || s === 'ssh_timeout') return false
      return 3000
    },
  })
}

export function useAWSInstances(region = 'us-east-1') {
  return useQuery({
    queryKey: ['aws-instances', region],
    queryFn: () => apiFetch<{ instances: AWSInstance[]; total: number }>(`/cloud/aws/instances?region=${region}`),
    refetchInterval: POLL.BACKGROUND,
    placeholderData: (prev) => prev as any,
  })
}

export function useDestroyAWSInstanceById() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ instanceId, region }: { instanceId: string; region: string }) =>
      apiFetch<{ ok: boolean; terminated: boolean }>(`/cloud/aws/instance-by-id/${instanceId}?region=${region}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['aws-instances'] })
      qc.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

// ── Remote Kali MCP ─────────────────────────────────────────────────

export function useStartMcp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ ok: boolean; local_port: number }>(`/nodes/${nodeId}/start-mcp`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useStopMcp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ ok: boolean }>(`/nodes/${nodeId}/stop-mcp`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useMcpStatus(nodeId: string) {
  return useQuery({
    queryKey: ['mcp-status', nodeId],
    queryFn: () => apiFetch<{ active: boolean; local_port?: number }>(`/nodes/${nodeId}/mcp-status`),
    enabled: !!nodeId,
    refetchInterval: POLL.BACKGROUND,
    placeholderData: (prev) => prev as any,
  })
}

export function useMcpNodes() {
  return useQuery({
    queryKey: ['mcp-nodes'],
    queryFn: () => apiFetch<{ nodes: Array<{ node_id: string; local_port: number; node_name: string; active: boolean }> }>('/mcp-nodes'),
    refetchInterval: POLL.BACKGROUND,
    placeholderData: (prev) => prev as any,
  })
}

export interface TunnelEvent {
  id: number
  node_id: string
  node_name: string
  event: string
  detail: string
  created_at: string
}

export function useTunnelEvents(nodeId?: string) {
  return useQuery({
    queryKey: ['tunnel-events', nodeId],
    queryFn: () => apiFetch<{ events: TunnelEvent[] }>(
      `/tunnel-events${nodeId ? `?node_id=${nodeId}` : ''}`,
    ),
    refetchInterval: POLL.NORMAL,
    placeholderData: (prev) => prev as any,
  })
}


// ── IP Rotation ──────────────────────────────────────────────────────

export function useRotateDOIP() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeId, strategy = 'reserved_ip' }: { nodeId: string; strategy?: 'reserved_ip' | 'destroy_recreate' }) =>
      apiFetch<{ ok: boolean; status: string; old_ip: string; strategy: string }>(
        `/cloud/do/rotate-ip/${nodeId}?strategy=${strategy}`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nodes'] }),
  })
}

export function useDORotateStatus(nodeId: string | null) {
  return useQuery({
    queryKey: ['do-rotate-status', nodeId],
    queryFn: () => apiFetch<{
      status: string; old_ip: string; new_ip: string | null; error: string | null; node_id: string
    }>(`/cloud/do/rotate-status/${nodeId}`),
    enabled: !!nodeId,
    refetchInterval: (query) => {
      const s = query.state.data?.status
      if (s === 'online' || s === 'failed' || s === 'unknown') return false
      return 3000
    },
  })
}


// ── IP History ───────────────────────────────────────────────────────

export interface IPHistoryEntry {
  id: string
  node_id: string
  node_name: string
  ip_address: string
  cloud_provider: string
  cloud_resource_id: string | null
  region: string | null
  assigned_at: string
  released_at: string | null
  release_reason: string | null
  scan_count: number
  proxy_port: number | null
  metadata: Record<string, unknown>
}

export function useIPHistory(nodeId?: string) {
  return useQuery({
    queryKey: ['ip-history', nodeId],
    queryFn: () => apiFetch<{ history: IPHistoryEntry[] }>(
      `/cloud/ip-history${nodeId ? `?node_id=${nodeId}` : ''}`,
    ),
    refetchInterval: POLL.BACKGROUND,
    placeholderData: (prev) => prev as any,
  })
}
