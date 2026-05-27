import { useState, useRef } from 'react'
import PageHelp from '@/components/PageHelp'
import QRCode from 'react-qr-code'
import { WireGuardDiagnostics } from '@/components/WireGuardDiagnostics'
import {
  useNodes, useDecommissionNode, useScanThroughNode,
  useGenerateImplant, useChiselConfig,
  useADAttack, useADResults, useStartSocks, useStopSocks,
  useSSHKeys, useSSHConnect, useSSHDisconnect, useSSHReconnect, useSSHExec,
  useSSHUpload, useSSHDownload, useRemoteScan, usePatchNode,
  useDOOptions, useDODroplets, useCreateDODroplet, useDestroyDODroplet, useDestroyDODropletById, useDOProvisionStatus,
  useStartMcp, useStopMcp, useMcpStatus, useSSHPublicKeys,
  useAWSOptions, useCreateAWSInstance, useAWSProvisionStatus, useAWSInstances, useDestroyAWSInstanceById,
  useTunnelEvents,
  useRotateDOIP, useDORotateStatus, useIPHistory,
  useWGPeers, useCreateWGPeer, useDeleteWGPeer, useWGPeerConfig,
  useWGClientStatus, useStartWGClient, useStopWGClient, useRestartWGClient,
} from '@/api/nodes'
import type { IPHistoryEntry, WGPeer, WGPeerConfig } from '@/api/nodes'
import { AD_ATTACK_TYPES, NODE_STATUS_COLORS } from '@/lib/constants'
import type { RemoteNode } from '@/lib/types'
import { cn } from '@/lib/utils'
import { useUIStore } from '@/stores/ui'
import { Wifi, Trash2, Play, Square, Terminal, Shield, Download, Copy, Monitor, Upload, Key, Send, Star, Cloud, Plus, Cpu, X, Server, RefreshCw, Clock, Loader2, Activity, CheckCircle, AlertTriangle, XCircle, ChevronDown, ChevronUp, FileText } from 'lucide-react'

// ── Tab state ──────────────────────────────────────────────────────
type Tab = 'grid' | 'implants' | 'ad' | 'ssh' | 'wireguard' | 'commands'

export default function Nodes() {
  const [tab, setTab] = useState<Tab>('grid')

  return (
    <div className="space-y-4">
      <PageHelp id="nodes" title="How to use Remote Nodes">
        <p>Connect to remote scan boxes via <strong>SSH Tunnels</strong> — each gets a SOCKS5 proxy port. Use the <strong>Provision</strong> button to auto-install 70+ security tools. The <strong>Commands</strong> tab lets you run commands, upload/download files, and execute scans directly. Cloud tabs let you spin up DigitalOcean or AWS instances on demand.</p>
      </PageHelp>
      <div className="flex items-center gap-3">
        <Wifi className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold">Remote Nodes</h1>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {([
          ['grid', 'Node Grid'],
          ['ssh', 'SSH Tunnels'],
          ['wireguard', 'WireGuard'],
          ['commands', 'Remote Commands'],
          ['implants', 'Implant Generator'],
          ['ad', 'AD Attacks'],
        ] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={cn(
              'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
              tab === key
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'grid' && <NodeGrid />}
      {tab === 'ssh' && <SSHTunnels />}
      {tab === 'wireguard' && <WireGuardTunnels />}
      {tab === 'commands' && <RemoteCommands />}
      {tab === 'implants' && <ImplantGenerator />}
      {tab === 'ad' && <ADAttacks />}
    </div>
  )
}

// ── Tool Selection Modal ──────────────────────────────────────────
function ToolSelectionModal({
  nodeId,
  availableTools,
  selectedTools,
  setSelectedTools,
  onInstall,
  onCancel,
  loading
}: {
  nodeId: string
  availableTools: string[]
  selectedTools: string[]
  setSelectedTools: (tools: string[]) => void
  onInstall: () => void
  onCancel: () => void
  loading: boolean
}) {
  const toggleTool = (tool: string) => {
    setSelectedTools(
      selectedTools.includes(tool)
        ? selectedTools.filter(t => t !== tool)
        : [...selectedTools, tool]
    )
  }

  const selectPreset = (preset: string[]) => {
    setSelectedTools(preset.filter(tool => availableTools.includes(tool)))
  }

  // Tool presets for quick selection
  const presets = {
    essential: ['nmap', 'masscan', 'httpx', 'nuclei', 'subfinder'],
    web: ['httpx', 'nuclei', 'katana', 'ffuf', 'whatweb', 'wafw00f'],
    recon: ['nmap', 'subfinder', 'amass', 'dnsx', 'httpx', 'nuclei'],
    network: ['nmap', 'masscan', 'naabu', 'tlsx'],
    wireguard: ['wireguard']
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-card border border-border rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
        <h2 className="text-lg font-semibold mb-4">Select Tools to Install</h2>

        {loading ? (
          <div className="text-center py-4">Loading available tools...</div>
        ) : (
          <>
            {/* Quick Presets */}
            <div className="mb-4">
              <h3 className="text-sm font-medium mb-2">Quick Presets:</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(presets).map(([name, tools]) => (
                  <button
                    key={name}
                    onClick={() => selectPreset(tools)}
                    className="px-2 py-1 text-xs bg-muted hover:bg-muted/80 rounded border border-border"
                  >
                    {name} ({tools.filter(t => availableTools.includes(t)).length})
                  </button>
                ))}
                <button
                  onClick={() => setSelectedTools([...availableTools])}
                  className="px-2 py-1 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90"
                >
                  All Tools ({availableTools.length})
                </button>
                <button
                  onClick={() => setSelectedTools([])}
                  className="px-2 py-1 text-xs bg-destructive text-destructive-foreground rounded hover:bg-destructive/90"
                >
                  Clear
                </button>
              </div>
            </div>

            {/* Tool Grid */}
            <div className="mb-4">
              <h3 className="text-sm font-medium mb-2">
                Individual Tools ({selectedTools.length}/{availableTools.length} selected):
              </h3>
              <div className="grid grid-cols-3 gap-2 max-h-60 overflow-y-auto border border-border rounded p-2 bg-muted/30">
                {availableTools.map(tool => (
                  <label key={tool} className="flex items-center gap-2 cursor-pointer hover:bg-muted/50 p-1 rounded">
                    <input
                      type="checkbox"
                      checked={selectedTools.includes(tool)}
                      onChange={() => toggleTool(tool)}
                      className="rounded"
                    />
                    <span className="text-sm">{tool}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-2 justify-end">
              <button
                onClick={onCancel}
                className="px-3 py-2 text-sm bg-muted hover:bg-muted/80 rounded border border-border"
              >
                Cancel
              </button>
              <button
                onClick={onInstall}
                disabled={selectedTools.length === 0}
                className="px-3 py-2 text-sm bg-cyan-600 text-white rounded hover:bg-cyan-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Install {selectedTools.length} Tool{selectedTools.length === 1 ? '' : 's'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ── Time helpers ──────────────────────────────────────────────────
function formatRelative(ts: string): string {
  const diffMin = Math.floor((Date.now() - new Date(ts).getTime()) / 60000)
  if (diffMin < 1) return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffMin < 1440) return `${Math.floor(diffMin / 60)}h ago`
  return `${Math.floor(diffMin / 1440)}d ago`
}

const hasSSHFallback = (node: any): boolean => {
  return !!(
    node.metadata?.host &&
    node.metadata?.user &&
    node.metadata?.key_file &&
    (node.tunnel_method === 'wireguard' || node.tunnel_method === 'hybrid')
  )
}

function LastSeenBadge({ lastSeen, status, tunnelMethod, hasSSHFallback }: {
  lastSeen: string;
  status: string;
  tunnelMethod?: string;
  hasSSHFallback?: boolean;
}) {
  const diffMin = Math.floor((Date.now() - new Date(lastSeen).getTime()) / 60000)
  const label = formatRelative(lastSeen)
  const isRecent = diffMin < 5

  // Special handling for WireGuard nodes with SSH fallback
  const isWGWithFallback = status === 'offline' && (tunnelMethod === 'wireguard' || tunnelMethod === 'hybrid') && hasSSHFallback

  const color = status === 'online' && isRecent
    ? 'text-green-400'
    : status === 'online' && !isRecent
    ? 'text-yellow-400'
    : status === 'error'
    ? 'text-red-400'
    : isWGWithFallback
    ? 'text-orange-400'
    : 'text-muted-foreground'

  const dot = status === 'online' && isRecent
    ? 'bg-green-400'
    : status === 'online'
    ? 'bg-yellow-400'
    : status === 'error'
    ? 'bg-red-400'
    : isWGWithFallback
    ? 'bg-orange-400'
    : 'bg-gray-500'

  const tooltip = isWGWithFallback
    ? `${new Date(lastSeen).toLocaleString()} - WireGuard offline, SSH fallback available`
    : new Date(lastSeen).toLocaleString()

  return (
    <span className={cn('flex items-center gap-1', color)} title={tooltip}>
      <span className={cn('h-1.5 w-1.5 rounded-full', dot)} />
      {label}
      {isWGWithFallback && (
        <span className="text-xs text-orange-400 font-medium">[SSH]</span>
      )}
    </span>
  )
}

// ── Node Grid ──────────────────────────────────────────────────────
function NodeGrid() {
  const { data, isLoading } = useNodes()
  const wgPeersQuery = useWGPeers()
  const decomission = useDecommissionNode()
  const scanThrough = useScanThroughNode()
  const startSocks = useStartSocks()
  const stopSocks = useStopSocks()
  const defaultNodeId = useUIStore(s => s.defaultNodeId)
  const setDefaultNode = useUIStore(s => s.setDefaultNode)
  const [scanForm, setScanForm] = useState<{ nodeId: string; show: boolean }>({ nodeId: '', show: false })
  const [scanParams, setScanParams] = useState({ scan_type: 'nmap', target: '', ports: '1-1000' })

  const nodes = data?.nodes ?? []

  // Helper function to determine actual tunnel type for display
  const getTunnelDisplayType = (node: any) => {
    const peers = wgPeersQuery.data?.peers ?? []
    const wgPeer = peers.find(p => p.id === node.id)

    // Show "wireguard" if node has WireGuard peer with successful installation
    if (wgPeer && (wgPeer.install_status === 'active' || wgPeer.install_status === 'success')) {
      return 'wireguard'
    }

    // Otherwise show the database tunnel_method or fallback to node_type
    return node.tunnel_method || node.node_type
  }

  if (isLoading) return <div className="text-muted-foreground">Loading nodes...</div>
  if (!nodes.length) return (
    <div className="text-center py-12 text-muted-foreground">
      <Wifi className="h-12 w-12 mx-auto mb-3 opacity-30" />
      <p className="text-lg">No remote nodes connected</p>
      <p className="text-sm mt-1">Use the Implant Generator tab to create agents, or register Chisel nodes manually.</p>
    </div>
  )

  const PROVIDER_META: Record<string, { label: string; color: string }> = {
    digitalocean: { label: 'DigitalOcean', color: 'text-blue-400 border-blue-500/30 bg-blue-500/10' },
    aws: { label: 'AWS', color: 'text-orange-400 border-orange-500/30 bg-orange-500/10' },
    private: { label: 'Private', color: 'text-purple-400 border-purple-500/30 bg-purple-500/10' },
    unknown: { label: 'Unknown', color: 'text-zinc-400 border-zinc-500/30 bg-zinc-500/10' },
  }

  // Group nodes by provider
  const grouped: Record<string, typeof nodes> = {}
  for (const node of nodes) {
    const p = (node as any).metadata?.provider || 'unknown'
    if (!grouped[p]) grouped[p] = []
    grouped[p].push(node)
  }
  const providerOrder = ['digitalocean', 'aws', 'private', 'unknown']
  const sortedProviders = [...providerOrder.filter(p => grouped[p]?.length), ...Object.keys(grouped).filter(p => !providerOrder.includes(p) && grouped[p]?.length)]

  return (
    <div className="space-y-6">
      {sortedProviders.map(provider => {
        const meta = PROVIDER_META[provider] || PROVIDER_META.unknown
        return (
          <div key={provider}>
            <div className="flex items-center gap-2 mb-3">
              <span className={cn('px-2.5 py-1 rounded border text-xs font-medium', meta.color)}>{meta.label}</span>
              <span className="text-xs text-muted-foreground">{grouped[provider].length} node{grouped[provider].length !== 1 ? 's' : ''}</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {grouped[provider].map((node) => (
          <div key={node.id} className="border border-border rounded-lg p-4 bg-card space-y-3">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className={cn('h-2.5 w-2.5 rounded-full', NODE_STATUS_COLORS[node.status] || 'bg-gray-400')} />
                <span className="font-semibold text-sm">{node.name}</span>
                {defaultNodeId === node.id && (
                  <span className="flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-500/15 text-amber-300 border border-amber-500/30">
                    <Star className="h-2.5 w-2.5" /> DEFAULT
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1">
                <span className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground">{getTunnelDisplayType(node)}</span>
                {getTunnelDisplayType(node) === 'wireguard' && (
                  <span className="text-xs px-2 py-0.5 rounded bg-green-500/15 text-green-300 border border-green-500/30">
                    WG
                  </span>
                )}
              </div>
            </div>

            {/* Details */}
            <div className="grid grid-cols-2 gap-1 text-xs text-muted-foreground">
              {node.hostname && <div><span className="text-foreground">Host:</span> {node.hostname}</div>}
              {node.os && <div><span className="text-foreground">OS:</span> {node.os}</div>}
              {node.internal_ip && <div><span className="text-foreground">IP:</span> {node.internal_ip}</div>}
              {(node as any).wg_assigned_ip && (
                <div><span className="text-foreground">WG IP:</span> {(node as any).wg_assigned_ip}</div>
              )}
              {node.network_segment && <div><span className="text-foreground">Net:</span> {node.network_segment}</div>}
              {node.proxy_port && <div><span className="text-foreground">Proxy:</span> :{node.proxy_port}</div>}
              {node.first_seen && (
                <div title={new Date(node.first_seen).toLocaleString()}>
                  <span className="text-foreground">First:</span> {formatRelative(node.first_seen)}
                </div>
              )}
              {node.last_seen && (
                <div className="flex items-center gap-1">
                  <span className="text-foreground">Last:</span>
                  <LastSeenBadge
                    lastSeen={node.last_seen}
                    status={node.status}
                    tunnelMethod={node.tunnel_method}
                    hasSSHFallback={hasSSHFallback(node)}
                  />
                </div>
              )}
            </div>
            {(node as any).last_error && (
              <div className="text-[10px] text-red-400/80 bg-red-500/5 rounded px-2 py-1 border border-red-500/10">
                <span className="font-medium">Last error:</span> {(node as any).last_error.detail}
                <span className="text-red-400/50 ml-1">({formatRelative((node as any).last_error.at)})</span>
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-2 pt-1 border-t border-border">
              {node.node_type === 'sliver' && node.status !== 'online' && (
                <button
                  onClick={() => startSocks.mutate({ nodeId: node.id })}
                  className="flex items-center gap-1 px-2 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700"
                  disabled={startSocks.isPending}
                >
                  <Play className="h-3 w-3" /> Start SOCKS
                </button>
              )}
              {node.node_type === 'sliver' && node.status === 'online' && (
                <button
                  onClick={() => stopSocks.mutate(node.id)}
                  className="flex items-center gap-1 px-2 py-1 text-xs bg-yellow-600 text-white rounded hover:bg-yellow-700"
                  disabled={stopSocks.isPending}
                >
                  <Square className="h-3 w-3" /> Stop SOCKS
                </button>
              )}
              <button
                onClick={() => setScanForm({ nodeId: node.id, show: true })}
                className="flex items-center gap-1 px-2 py-1 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90"
              >
                <Terminal className="h-3 w-3" /> Scan Through
              </button>
              <button
                onClick={() => {
                  if (confirm(`Decommission node "${node.name}"?`)) {
                    decomission.mutate(node.id)
                  }
                }}
                className="flex items-center gap-1 px-2 py-1 text-xs bg-destructive text-destructive-foreground rounded hover:bg-destructive/90 ml-auto"
              >
                <Trash2 className="h-3 w-3" />
              </button>
            </div>
          </div>
        ))}
            </div>
          </div>
        )
      })}

      {/* Scan-through dialog */}
      {scanForm.show && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card border border-border rounded-lg p-6 w-full max-w-md space-y-4">
            <h3 className="font-semibold">Scan Through Node</h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-muted-foreground">Scan Type</label>
                <select
                  value={scanParams.scan_type}
                  onChange={(e) => setScanParams(p => ({ ...p, scan_type: e.target.value }))}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                >
                  <optgroup label="Port Scanning">
                    <option value="nmap">Nmap (TCP Connect)</option>
                    <option value="full">Full Port Scan</option>
                    <option value="masscan">Masscan</option>
                    <option value="udp">UDP Scan</option>
                    <option value="naabu">Naabu</option>
                  </optgroup>
                  <optgroup label="Recon">
                    <option value="subfinder">Subfinder</option>
                    <option value="dnsx">dnsx</option>
                    <option value="httpx">httpx</option>
                    <option value="tlsx">TLSX</option>
                    <option value="uncover">Uncover</option>
                    <option value="chaos">Chaos</option>
                    <option value="shuffledns">ShuffleDNS</option>
                    <option value="recon-pipeline">Recon Pipeline</option>
                    <option value="crtsh">crt.sh</option>
                    <option value="whatweb">WhatWeb</option>
                  </optgroup>
                  <optgroup label="Web">
                    <option value="web">Web Scan</option>
                    <option value="pipeline">Web Pipeline</option>
                    <option value="katana">Katana</option>
                    <option value="nikto">Nikto</option>
                  </optgroup>
                  <optgroup label="Vuln">
                    <option value="nuclei">Nuclei</option>
                  </optgroup>
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Target</label>
                <input
                  value={scanParams.target}
                  onChange={(e) => setScanParams(p => ({ ...p, target: e.target.value }))}
                  placeholder={['web', 'pipeline', 'nikto', 'katana'].includes(scanParams.scan_type) ? 'http://192.168.50.1' : '192.168.50.1 or example.com'}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Ports</label>
                <input
                  value={scanParams.ports}
                  onChange={(e) => setScanParams(p => ({ ...p, ports: e.target.value }))}
                  placeholder="1-1000"
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setScanForm({ nodeId: '', show: false })}
                className="px-3 py-1.5 text-sm border border-border rounded hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  const t = scanParams.target
                  const st = scanParams.scan_type
                  const payload: Record<string, unknown> = {
                    nodeId: scanForm.nodeId,
                    scan_type: st,
                    target: t,
                    targets: [t],
                    ports: scanParams.ports,
                  }
                  if (['web', 'pipeline', 'nikto', 'katana'].includes(st)) {
                    payload.target_url = t.startsWith('http') ? t : `http://${t}`
                  }
                  if (st === 'uncover') {
                    payload.query = t
                  }
                  scanThrough.mutate(payload as Parameters<typeof scanThrough.mutate>[0])
                  setScanForm({ nodeId: '', show: false })
                }}
                disabled={!scanParams.target || scanThrough.isPending}
                className="px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50"
              >
                Launch Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── SSH Tunnels ───────────────────────────────────────────────────
const QUICK_COMMANDS = ['id', 'uname -a', 'cat /etc/passwd', 'ip addr', 'netstat -tlnp', 'whoami', 'hostname', 'df -h']

function SSHTunnels() {
  const { data: nodesData } = useNodes()
  const { data: keysData } = useSSHKeys()
  const connectSSH = useSSHConnect()
  const disconnectSSH = useSSHDisconnect()
  const reconnectSSH = useSSHReconnect()
  const defaultNodeId = useUIStore(s => s.defaultNodeId)
  const setDefaultNode = useUIStore(s => s.setDefaultNode)
  const decommission = useDecommissionNode()
  const patchNode = usePatchNode()

  const [form, setForm] = useState({
    name: '', host: '', user: 'root', ssh_port: '22', key_name: '', network_segment: '', os_type: 'kali', provider: 'private',
  })
  const [activeNodeOp, setActiveNodeOp] = useState<string | null>(null) // "check:id" or "provision:id"
  const [nodeLogs, setNodeLogs] = useState<Record<string, { lines: string[]; done: boolean }>>({})
  const [showToolSelection, setShowToolSelection] = useState<string | null>(null) // nodeId when showing tool selection
  const [selectedTools, setSelectedTools] = useState<string[]>([])
  const [availableTools, setAvailableTools] = useState<string[]>([])
  const [loadingTools, setLoadingTools] = useState(false)

  const fetchAvailableTools = async (nodeId: string) => {
    setLoadingTools(true)
    try {
      const response = await fetch(`/api/nodes/${nodeId}/provision-status`)
      const data = await response.json()
      setAvailableTools(data.available_tools || [])
      setSelectedTools([]) // Reset selection
    } catch (error) {
      console.error('Failed to fetch tools:', error)
      setAvailableTools([])
    } finally {
      setLoadingTools(false)
    }
  }

  const openToolSelection = async (nodeId: string) => {
    setShowToolSelection(nodeId)
    await fetchAvailableTools(nodeId)
  }

  const startSSE = (nodeId: string, mode: 'check' | 'provision', tools?: string[]) => {
    const opKey = `${mode}:${nodeId}`
    setActiveNodeOp(opKey)
    setNodeLogs(prev => ({ ...prev, [nodeId]: { lines: [`[${mode}] Starting...`], done: false } }))
    setShowToolSelection(null) // Close tool selection

    const url = mode === 'check'
      ? `/api/nodes/${nodeId}/provision-status?live=true`
      : `/api/nodes/${nodeId}/provision`

    const addLine = (line: string) =>
      setNodeLogs(prev => ({ ...prev, [nodeId]: { lines: [...(prev[nodeId]?.lines ?? []), line], done: false } }))

    const fetchSSE = async () => {
      try {
        const payload = mode === 'provision' ? JSON.stringify(tools ? { tools } : {}) : undefined
        const resp = await fetch(url, {
          method: mode === 'provision' ? 'POST' : 'GET',
          headers: mode === 'provision' ? { 'Content-Type': 'application/json' } : {},
          body: payload,
        })
        const reader = resp.body?.getReader()
        if (!reader) { addLine('[error] No response stream'); return }
        const decoder = new TextDecoder()
        let buf = ''
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const parts = buf.split('\n')
          buf = parts.pop() || ''
          for (const part of parts) {
            const trimmed = part.trim()
            if (!trimmed.startsWith('data: ')) continue
            try {
              const evt = JSON.parse(trimmed.slice(6))
              if (evt.event === 'checking') {
                addLine(`[check] ${evt.tool} ...`)
              } else if (evt.event === 'installing') {
                addLine(`[install] ${evt.tool} — ${evt.cmd || ''}`)
              } else if (evt.event === 'tool') {
                const icon = (evt.installed || evt.status === 'installed' || evt.status === 'already_installed') ? '\u2713' : '\u2717'
                const status = evt.status || (evt.installed ? 'found' : 'missing')
                let detail = ''
                if (evt.version) detail = evt.version
                else if (evt.stdout && evt.status !== 'failed') detail = evt.stdout.slice(0, 200)
                else if (evt.path) detail = evt.path
                if (evt.stderr) detail = evt.stderr.slice(0, 200)
                else if (evt.status === 'failed' && evt.stdout) detail = evt.stdout.slice(0, 200)
                addLine(`  ${icon} ${evt.tool}: ${status}${detail ? ' — ' + detail : ''}`)
              } else if (evt.event === 'done') {
                const count = evt.installed?.length ?? evt.provisioned_tools?.length ?? 0
                addLine(`[done] ${count} tools available`)
              }
            } catch { /* ignore parse errors */ }
          }
        }
      } catch (err) {
        addLine(`[error] ${String(err)}`)
      }
      setNodeLogs(prev => ({ ...prev, [nodeId]: { lines: prev[nodeId]?.lines ?? [], done: true } }))
      setActiveNodeOp(null)
    }
    fetchSSE()
  }

  const sshNodes = (nodesData?.nodes ?? []).filter(n => n.node_type === 'ssh')
  const keys = keysData?.keys ?? []

  const handleConnect = () => {
    connectSSH.mutate({
      name: form.name,
      host: form.host,
      user: form.user,
      ssh_port: parseInt(form.ssh_port) || 22,
      key_name: form.key_name || keys[0] || 'id_rsa',
      network_segment: form.network_segment || undefined,
      os_type: form.os_type || 'kali',
      provider: form.provider || 'private',
    }, {
      onSuccess: () => {
        setForm({ name: '', host: '', user: 'root', ssh_port: '22', key_name: '', network_segment: '', os_type: 'kali', provider: 'private' })
      },
    })
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Left: Connection Form */}
      <div className="space-y-4">
        {/* Connection Form */}
        <div className="border border-border rounded-lg p-5 bg-card space-y-4">
          <div className="flex items-center gap-2">
            <Key className="h-5 w-5 text-cyan-500" />
            <h3 className="font-semibold">New SSH Connection</h3>
          </div>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground">Name</label>
                <input
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="jumpbox-1"
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Host</label>
                <input
                  value={form.host}
                  onChange={e => setForm(f => ({ ...f, host: e.target.value }))}
                  placeholder="10.0.0.5"
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="text-xs text-muted-foreground">User</label>
                <input
                  value={form.user}
                  onChange={e => setForm(f => ({ ...f, user: e.target.value }))}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">SSH Port</label>
                <input
                  value={form.ssh_port}
                  onChange={e => setForm(f => ({ ...f, ssh_port: e.target.value }))}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">SSH Key</label>
                <select
                  value={form.key_name}
                  onChange={e => setForm(f => ({ ...f, key_name: e.target.value }))}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                >
                  {keys.length === 0 && <option value="">No keys found</option>}
                  {keys.map(k => <option key={k} value={k}>{k}</option>)}
                </select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground">OS Type</label>
                <select
                  value={form.os_type}
                  onChange={e => setForm(f => ({ ...f, os_type: e.target.value }))}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                >
                  <option value="kali">Kali Linux</option>
                  <option value="ubuntu">Ubuntu</option>
                  <option value="debian">Debian</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Network Segment (optional)</label>
                <input
                  value={form.network_segment}
                  onChange={e => setForm(f => ({ ...f, network_segment: e.target.value }))}
                  placeholder="e.g. internal-corp"
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Provider</label>
                <select
                  value={form.provider}
                  onChange={e => setForm(f => ({ ...f, provider: e.target.value }))}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                >
                  <option value="private">Private</option>
                  <option value="digitalocean">DigitalOcean</option>
                  <option value="aws">AWS</option>
                  <option value="unknown">Unknown</option>
                </select>
              </div>
            </div>
          </div>
          <button
            onClick={handleConnect}
            disabled={!form.name || !form.host || connectSSH.isPending}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm bg-cyan-600 text-white rounded hover:bg-cyan-700 disabled:opacity-50"
          >
            {connectSSH.isPending ? 'Connecting...' : <><Wifi className="h-4 w-4" /> Connect</>}
          </button>
          {connectSSH.isError && (() => {
            const msg = connectSSH.error?.message || ''
            try {
              // Parse nested JSON detail from "API 500: {...}"
              const jsonStr = msg.replace(/^API \d+:\s*/, '')
              const detail = JSON.parse(jsonStr)?.detail || JSON.parse(jsonStr)
              const parsed = typeof detail === 'string' ? JSON.parse(detail) : detail
              return (
                <div className="text-xs text-red-500 space-y-0.5 mt-1">
                  <p className="font-medium">{parsed.error || msg}</p>
                  {parsed.hint && <p className="text-red-400">{parsed.hint}</p>}
                  {parsed.stderr && <pre className="text-[10px] text-red-400 bg-red-500/5 rounded p-1 max-h-20 overflow-y-auto whitespace-pre-wrap">{parsed.stderr}</pre>}
                </div>
              )
            } catch {
              return <p className="text-xs text-red-500 mt-1">{msg}</p>
            }
          })()}
        </div>

        {/* Cloud Provisioning */}
        <CloudProvision />
        <AWSCloudProvision />

        {/* Default Node Selector */}
        {sshNodes.length > 0 && (
          <div className="border border-amber-500/20 bg-amber-500/5 rounded-lg p-3 flex items-center gap-3">
            <Star className="h-4 w-4 text-amber-400 shrink-0" />
            <span className="text-sm font-medium">Default Scan Node:</span>
            <select
              value={defaultNodeId || ''}
              onChange={e => setDefaultNode(e.target.value || null)}
              className="bg-background rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            >
              <option value="">None (manual selection)</option>
              {sshNodes.filter(n => n.status === 'online').map(n => (
                <option key={n.id} value={n.id}>{n.name} — {n.hostname}:{n.proxy_port}</option>
              ))}
            </select>
            {defaultNodeId && (
              <button onClick={() => setDefaultNode(null)}
                className="text-xs text-muted-foreground hover:text-foreground">Clear</button>
            )}
          </div>
        )}

        {/* Connected SSH Nodes — grouped by provider */}
        <div className="border border-border rounded-lg p-5 bg-card space-y-3">
          <h3 className="font-semibold">SSH Tunnels ({sshNodes.length})</h3>
          {sshNodes.length === 0 && (
            <p className="text-sm text-muted-foreground">No SSH tunnels connected. Add one above.</p>
          )}
          {(() => {
            const providerOrder = ['digitalocean', 'aws', 'private', 'unknown']
            const providerLabels: Record<string, string> = {
              digitalocean: 'DigitalOcean', aws: 'AWS', private: 'Private', unknown: 'Unknown',
            }
            const providerColors: Record<string, string> = {
              digitalocean: 'text-blue-400 border-blue-500/30', aws: 'text-orange-400 border-orange-500/30',
              private: 'text-purple-400 border-purple-500/30', unknown: 'text-zinc-400 border-zinc-500/30',
            }
            const grouped: Record<string, typeof sshNodes> = {}
            for (const node of sshNodes) {
              const p = (node as any).metadata?.provider || 'unknown'
              if (!grouped[p]) grouped[p] = []
              grouped[p].push(node)
            }
            const sortedProviders = providerOrder.filter(p => grouped[p]?.length)
            // Add any providers not in the order list
            for (const p of Object.keys(grouped)) {
              if (!sortedProviders.includes(p)) sortedProviders.push(p)
            }
            return sortedProviders.map(provider => (
              <div key={provider} className="space-y-2">
                <div className={`flex items-center gap-2 text-xs font-medium ${providerColors[provider] || 'text-muted-foreground'}`}>
                  <span className={`px-2 py-0.5 rounded border ${providerColors[provider] || ''}`}>
                    {providerLabels[provider] || provider}
                  </span>
                  <span className="text-muted-foreground font-normal">({grouped[provider].length})</span>
                </div>
                {grouped[provider].map(node => (
              <div key={node.id} className="border border-border rounded p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={cn('h-2.5 w-2.5 rounded-full', NODE_STATUS_COLORS[node.status] || 'bg-gray-400')} />
                    <span className="font-medium text-sm">{node.name}</span>
                    {defaultNodeId === node.id && (
                      <span className="flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-500/15 text-amber-300 border border-amber-500/30">
                        <Star className="h-2.5 w-2.5" /> DEFAULT
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {(node.metadata as Record<string, unknown>)?.user as string || 'root'}@{node.hostname}
                  </span>
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  <div><span className="text-foreground">Status:</span> {node.status}</div>
                  <div><span className="text-foreground">Method:</span>
                    <span className={cn('ml-1 px-1.5 py-0.5 rounded text-[10px] font-medium',
                      node.tunnel_method === 'wireguard' ? 'bg-blue-500/20 text-blue-400' :
                      node.tunnel_method === 'hybrid' ? 'bg-purple-500/20 text-purple-400' :
                      'bg-green-500/20 text-green-400'
                    )}>
                      {node.tunnel_method === 'wireguard' ? 'WireGuard' :
                       node.tunnel_method === 'hybrid' ? 'Hybrid' : 'SSH'}
                    </span>
                  </div>
                  <div><span className="text-foreground">SOCKS:</span> :{node.proxy_port}</div>
                  <div><span className="text-foreground">SSH Port:</span> {(node.metadata as Record<string, unknown>)?.ssh_port as number || 22}</div>
                  <div><span className="text-foreground">Key:</span> <span className="font-mono">{(node.metadata as Record<string, unknown>)?.key_file as string || 'default'}</span></div>
                  {node.first_seen && (
                    <div title={new Date(node.first_seen).toLocaleString()}>
                      <span className="text-foreground">First:</span> {formatRelative(node.first_seen)}
                    </div>
                  )}
                  {node.last_seen && (
                    <div className="flex items-center gap-1">
                      <span className="text-foreground">Last:</span>
                      <LastSeenBadge
                        lastSeen={node.last_seen}
                        status={node.status}
                        tunnelMethod={node.tunnel_method}
                        hasSSHFallback={hasSSHFallback(node)}
                      />
                    </div>
                  )}
                  <div className="flex items-center gap-1">
                    <span className="text-foreground">OS:</span>
                    <select
                      value={((node.metadata as Record<string, unknown>)?.os_type as string) || 'kali'}
                      onChange={e => patchNode.mutate({ nodeId: node.id, os_type: e.target.value })}
                      className="bg-muted text-foreground text-[10px] font-medium px-1 py-0.5 rounded border border-border outline-none"
                    >
                      <option value="kali">Kali</option>
                      <option value="ubuntu">Ubuntu</option>
                      <option value="debian">Debian</option>
                    </select>
                  </div>
                  {node.network_segment && <div><span className="text-foreground">Net:</span> {node.network_segment}</div>}
                  {((node.metadata as Record<string, unknown>)?.provisioned_tools as string[])?.length > 0 && (
                    <div>
                      <span className="text-foreground">Tools:</span>{' '}
                      {((node.metadata as Record<string, unknown>).provisioned_tools as string[]).map(t => (
                        <span key={t} className="inline-block px-1 py-0.5 mr-0.5 rounded bg-green-500/10 text-green-500 text-[10px]">{t}</span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex gap-2 pt-1 border-t border-border">
                  {(node.status === 'online' || hasSSHFallback(node)) && (
                    <>
                      <button
                        onClick={() => disconnectSSH.mutate(node.id)}
                        disabled={disconnectSSH.isPending}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-yellow-600 text-white rounded hover:bg-yellow-700"
                      >
                        <Square className="h-3 w-3" /> Disconnect
                      </button>
                      <button
                        onClick={() => setDefaultNode(defaultNodeId === node.id ? null : node.id)}
                        className={cn(
                          "flex items-center gap-1 px-2 py-1 text-xs rounded border",
                          defaultNodeId === node.id
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            : 'bg-muted text-muted-foreground border-border hover:bg-muted/80'
                        )}
                      >
                        <Star className="h-3 w-3" /> {defaultNodeId === node.id ? 'Default' : 'Use as Default'}
                      </button>
                      <button
                        onClick={() => startSSE(node.id, 'check')}
                        disabled={activeNodeOp === `check:${node.id}` || activeNodeOp === `provision:${node.id}`}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-muted text-foreground border border-border rounded hover:bg-muted/80 disabled:opacity-50"
                      >
                        <Monitor className="h-3 w-3" /> {activeNodeOp === `check:${node.id}` ? 'Checking...' : 'Check Tools'}
                      </button>
                      <button
                        onClick={() => openToolSelection(node.id)}
                        disabled={activeNodeOp === `check:${node.id}` || activeNodeOp === `provision:${node.id}`}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-cyan-600 text-white rounded hover:bg-cyan-700 disabled:opacity-50"
                      >
                        <Download className="h-3 w-3" /> {activeNodeOp === `provision:${node.id}` ? 'Installing...' : 'Select Tools'}
                      </button>
                      {(node.metadata?.os_type === 'kali') && <McpButton nodeId={node.id} />}
                    </>
                  )}
                  {(node.status === 'offline' || node.status === 'error') && (
                    <button
                      onClick={() => reconnectSSH.mutate(node.id)}
                      disabled={reconnectSSH.isPending}
                      className="flex items-center gap-1 px-2 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
                    >
                      <Wifi className="h-3 w-3" /> {reconnectSSH.isPending ? 'Connecting...' : 'Reconnect'}
                    </button>
                  )}
                  <button
                    onClick={() => {
                      if (confirm(`Remove SSH tunnel "${node.name}"?`)) decommission.mutate(node.id)
                    }}
                    className="flex items-center gap-1 px-2 py-1 text-xs bg-destructive text-destructive-foreground rounded hover:bg-destructive/90 ml-auto"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
                {(node as any).last_error && (
                  <div className="text-[10px] text-red-400/80 bg-red-500/5 rounded px-2 py-1 border border-red-500/10">
                    <span className="font-medium">Last error:</span> {(node as any).last_error.detail}
                    <span className="text-red-400/50 ml-1">({formatRelative((node as any).last_error.at)})</span>
                  </div>
                )}
                {(node.status === 'online' || hasSSHFallback(node)) && node.metadata?.os_type === 'kali' && <McpStatusPanel nodeId={node.id} />}
                {nodeLogs[node.id] && nodeLogs[node.id].lines.length > 0 && (
                  <div className="border-t border-border pt-2 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-semibold text-muted-foreground">
                        {!nodeLogs[node.id].done && (
                          <span className="inline-block w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse mr-1.5" />
                        )}
                        Log Output
                      </span>
                      {nodeLogs[node.id].done && (
                        <button
                          onClick={() => setNodeLogs(prev => { const n = { ...prev }; delete n[node.id]; return n })}
                          className="text-[10px] text-muted-foreground hover:text-foreground"
                        >Clear</button>
                      )}
                    </div>
                    <div className="bg-background border border-border rounded p-2 max-h-40 overflow-y-auto font-mono text-[10px] leading-relaxed">
                      {nodeLogs[node.id].lines.map((line, i) => (
                        <div key={i} className={cn(
                          line.includes('\u2713') ? 'text-green-500'
                            : line.includes('\u2717') ? 'text-red-400'
                            : line.startsWith('[install]') ? 'text-cyan-500'
                            : line.startsWith('[error]') ? 'text-red-500'
                            : line.startsWith('[done]') ? 'text-green-400 font-semibold'
                            : 'text-muted-foreground',
                        )}>{line}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
              </div>
            ))
          })()}
        </div>
      </div>

      {/* Tunnel Event Log */}
      <TunnelEventLog />

      {/* Tool Selection Modal */}
      {showToolSelection && (
        <ToolSelectionModal
          nodeId={showToolSelection}
          availableTools={availableTools}
          selectedTools={selectedTools}
          setSelectedTools={setSelectedTools}
          onInstall={() => {
            startSSE(showToolSelection, 'provision', selectedTools)
          }}
          onCancel={() => setShowToolSelection(null)}
          loading={loadingTools}
        />
      )}
    </div>
  )
}

function TunnelEventLog() {
  const { data } = useTunnelEvents()
  const events = data?.events ?? []
  const [expanded, setExpanded] = useState(false)

  const eventColors: Record<string, string> = {
    connected: 'text-green-400',
    reconnected: 'text-green-400',
    disconnected: 'text-yellow-400',
    dropped: 'text-red-400',
    error: 'text-red-400',
    reconnecting: 'text-blue-400',
  }
  const eventIcons: Record<string, string> = {
    connected: '●', reconnected: '↻', disconnected: '○',
    dropped: '✕', error: '!', reconnecting: '⟳',
  }

  if (!events.length) return null

  const shown = expanded ? events : events.slice(0, 8)

  return (
    <div className="border border-border rounded-lg p-4 bg-card">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold">Tunnel Event Log</h3>
        <span className="text-[10px] text-muted-foreground">{events.length} events</span>
      </div>
      <div className="space-y-1 font-mono text-[11px]">
        {shown.map(e => (
          <div key={e.id} className="flex items-start gap-2">
            <span className="text-muted-foreground w-36 shrink-0">
              {new Date(e.created_at).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>
            <span className={`w-4 text-center ${eventColors[e.event] || 'text-muted-foreground'}`}>
              {eventIcons[e.event] || '·'}
            </span>
            <span className="font-medium w-28 shrink-0">{e.node_name}</span>
            <span className={eventColors[e.event] || 'text-muted-foreground'}>{e.event}</span>
            {e.detail && <span className="text-muted-foreground truncate">{e.detail}</span>}
          </div>
        ))}
      </div>
      {events.length > 8 && (
        <button onClick={() => setExpanded(!expanded)}
          className="mt-2 text-[10px] text-primary hover:underline">
          {expanded ? 'Show less' : `Show all ${events.length} events`}
        </button>
      )}
    </div>
  )
}

// ── DigitalOcean Cloud Provisioning ─────────────────────────────────
function CloudProvision() {
  const { data: optionsData } = useDOOptions()
  const createDroplet = useCreateDODroplet()
  const destroyDroplet = useDestroyDODroplet()
  const rotateDOIP = useRotateDOIP()
  const [rotatingNodeId, setRotatingNodeId] = useState<string | null>(null)
  const rotateStatus = useDORotateStatus(rotatingNodeId)
  const { data: pubKeysData } = useSSHPublicKeys()
  const { data: privKeysData } = useSSHKeys()
  const { data: nodesData } = useNodes()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', size: 's-1vcpu-1gb', region: 'nyc1', key_name: '', ssh_key_name: '' })
  const [provisioningId, setProvisioningId] = useState<string | null>(null)
  const { data: provStatus } = useDOProvisionStatus(provisioningId)

  const sizes = optionsData?.sizes ?? []
  const regions = optionsData?.regions ?? []
  const keys = pubKeysData?.keys ?? []
  const doNodes = (nodesData?.nodes ?? []).filter((n: any) => {
    const meta = (n.metadata || {}) as Record<string, unknown>
    return meta.source === 'digitalocean' || meta.provider === 'digitalocean'
  })

  const privKeys = privKeysData?.keys ?? []

  const handleCreate = () => {
    if (!form.name || !form.key_name || !form.ssh_key_name) return
    setProvisioningId(null)
    createDroplet.mutate(form, {
      onSuccess: (d) => {
        if (d.droplet_id) setProvisioningId(String(d.droplet_id))
        setShowForm(false)
      },
    })
  }

  return (
    <div className="border border-border rounded-lg p-4 bg-card space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Cloud className="h-4 w-4 text-blue-400" /> DigitalOcean Droplets
        </h3>
        <button onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1 px-2.5 py-1 text-xs rounded border border-blue-500/30 text-blue-400 hover:bg-blue-500/10">
          <Plus className="h-3 w-3" /> New Droplet
        </button>
      </div>

      {showForm && (
        <div className="border border-border rounded p-3 space-y-2 bg-muted/30">
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-muted-foreground">Name</label>
              <input value={form.name} onChange={e => setForm({...form, name: e.target.value})}
                placeholder="scan-node-1" className="w-full bg-background rounded px-2 py-1 text-sm border border-border" />
            </div>
            <div>
              <label className="text-[10px] text-muted-foreground">Public Key (for DO)</label>
              <select value={form.key_name} onChange={e => setForm({...form, key_name: e.target.value})}
                className="w-full bg-background rounded px-2 py-1 text-sm border border-border">
                <option value="">Select public key...</option>
                {keys.map((k: string) => <option key={k} value={k}>{k}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-muted-foreground">Private Key (for SSH tunnel)</label>
              <select value={form.ssh_key_name} onChange={e => setForm({...form, ssh_key_name: e.target.value})}
                className="w-full bg-background rounded px-2 py-1 text-sm border border-border">
                <option value="">Select private key...</option>
                {privKeys.map((k: string) => <option key={k} value={k}>{k}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-muted-foreground">Size</label>
              <select value={form.size} onChange={e => setForm({...form, size: e.target.value})}
                className="w-full bg-background rounded px-2 py-1 text-sm border border-border">
                {sizes.map(s => <option key={s.slug} value={s.slug}>{s.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-muted-foreground">Region</label>
              <select value={form.region} onChange={e => setForm({...form, region: e.target.value})}
                className="w-full bg-background rounded px-2 py-1 text-sm border border-border">
                {regions.map(r => <option key={r.slug} value={r.slug}>{r.label}</option>)}
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={handleCreate} disabled={!form.name || !form.key_name || !form.ssh_key_name || createDroplet.isPending}
              className="px-3 py-1.5 text-xs rounded bg-blue-500 text-white hover:bg-blue-600 disabled:opacity-50">
              {createDroplet.isPending ? 'Creating droplet...' : 'Create & Connect'}
            </button>
            <button onClick={() => setShowForm(false)} className="px-3 py-1.5 text-xs rounded border border-border hover:bg-muted">Cancel</button>
          </div>
          {createDroplet.error && <p className="text-xs text-red-500">{String(createDroplet.error)}</p>}
        </div>
      )}

      {provisioningId && provStatus && (
        <div className={cn("rounded p-2 text-xs border",
          provStatus.status === 'online' ? 'bg-green-500/10 border-green-500/30' :
          provStatus.status === 'failed' || provStatus.status === 'tunnel_error' ? 'bg-red-500/10 border-red-500/30' :
          'bg-blue-500/10 border-blue-500/30'
        )}>
          <div className="flex items-center gap-2">
            {!['online','failed','tunnel_error','ssh_timeout'].includes(provStatus.status) && (
              <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
            )}
            <span className="font-medium capitalize">{provStatus.status.replace('_', ' ')}</span>
            {provStatus.ip && <span className="font-mono">{provStatus.ip}</span>}
            {provStatus.socks_port && <span>SOCKS :{provStatus.socks_port}</span>}
            {provStatus.error && <span className="text-red-400">{provStatus.error}</span>}
          </div>
        </div>
      )}

      {doNodes.length > 0 && (
        <div className="space-y-1">
          {doNodes.map((node: any) => {
            const meta = (node.metadata || {}) as Record<string, unknown>
            return (
              <div key={node.id} className="flex items-center justify-between text-xs bg-muted/50 rounded px-2 py-1.5">
                <div className="flex items-center gap-2">
                  <span className={cn('h-2 w-2 rounded-full', NODE_STATUS_COLORS[node.status] || 'bg-gray-400')} />
                  <span className="font-medium">{node.name}</span>
                  <span className="font-mono text-muted-foreground">{node.hostname}</span>
                  <span className="text-muted-foreground">:{node.proxy_port}</span>
                  <span className="px-1 py-0.5 rounded text-[9px] bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    {String(meta.do_region)} / {String(meta.do_size)}
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => {
                      if (window.confirm(`Rotate IP for "${node.name}"?\n\nThis assigns a new Reserved IP (fast, droplet stays running).`)) {
                        rotateDOIP.mutate({ nodeId: node.id, strategy: 'reserved_ip' })
                        setRotatingNodeId(node.id)
                      }
                    }}
                    disabled={rotateDOIP.isPending || node.status === 'rotating'}
                    className="flex items-center gap-1 px-2 py-0.5 text-[10px] text-blue-400 hover:bg-blue-500/20 rounded border border-blue-500/20"
                    title="Fast: assign new Reserved IP (droplet stays running)"
                  >
                    {node.status === 'rotating' ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <RefreshCw className="h-2.5 w-2.5" />}
                    Rotate IP
                  </button>
                  <button
                    onClick={() => {
                      if (window.confirm(`Rebuild "${node.name}" with new IP?\n\nThis DESTROYS and recreates the droplet (~2min). Use if Reserved IP rotation didn't work.`)) {
                        rotateDOIP.mutate({ nodeId: node.id, strategy: 'destroy_recreate' })
                        setRotatingNodeId(node.id)
                      }
                    }}
                    disabled={rotateDOIP.isPending || node.status === 'rotating'}
                    className="flex items-center gap-1 px-2 py-0.5 text-[10px] text-amber-400 hover:bg-amber-500/20 rounded border border-amber-500/20"
                    title="Slow: destroy + recreate droplet (~2min)"
                  >
                    <RefreshCw className="h-2.5 w-2.5" /> Rebuild
                  </button>
                  <button
                    onClick={() => {
                      if (window.confirm(`Destroy droplet "${node.name}" (${node.hostname})? This will delete the DO droplet.`))
                        destroyDroplet.mutate(node.id)
                    }}
                    disabled={destroyDroplet.isPending}
                    className="flex items-center gap-1 px-2 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 rounded border border-red-500/20"
                  >
                    <Trash2 className="h-2.5 w-2.5" /> Destroy
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
      {doNodes.length === 0 && !showForm && (
        <p className="text-xs text-muted-foreground">No connected DigitalOcean droplets. Click "New Droplet" to spin one up.</p>
      )}

      {/* IP Rotation Status */}
      {rotatingNodeId && rotateStatus.data && rotateStatus.data.status !== 'unknown' && (
        <div className="bg-blue-500/10 border border-blue-500/20 rounded p-2 text-xs space-y-1">
          <div className="flex items-center gap-2">
            {rotateStatus.data.status !== 'online' && rotateStatus.data.status !== 'failed' && (
              <Loader2 className="h-3 w-3 animate-spin text-blue-400" />
            )}
            <span className="font-medium">IP Rotation: <span className="text-blue-400">{rotateStatus.data.status}</span></span>
            {rotateStatus.data.old_ip && <span className="text-muted-foreground">Old: {rotateStatus.data.old_ip}</span>}
            {rotateStatus.data.new_ip && <span className="text-green-400">New: {rotateStatus.data.new_ip}</span>}
          </div>
          {rotateStatus.data.error && <div className="text-red-400 text-[10px]">{rotateStatus.data.error}</div>}
          {(rotateStatus.data.status === 'online' || rotateStatus.data.status === 'failed') && (
            <button onClick={() => setRotatingNodeId(null)} className="text-[10px] text-muted-foreground hover:text-foreground">Dismiss</button>
          )}
        </div>
      )}

      {/* Remote DO Droplets from API */}
      <DORemoteDroplets />

      {/* IP History (all providers) */}
      <NodeIPHistory />
    </div>
  )
}


function NodeIPHistory({ provider, nodeId }: { provider?: string; nodeId?: string }) {
  const [expanded, setExpanded] = useState(false)
  const { data } = useIPHistory(nodeId)
  const history = (data?.history ?? []).filter(h => !provider || h.cloud_provider === provider)

  return (
    <details open={expanded} onToggle={(e) => setExpanded((e.target as HTMLDetailsElement).open)}>
      <summary className="text-[10px] font-semibold text-muted-foreground cursor-pointer flex items-center gap-1 mt-2">
        <Clock className="h-3 w-3" /> IP History {history.length > 0 && `(${history.length})`}
      </summary>
      <div className="mt-1 space-y-1 max-h-48 overflow-y-auto">
        {history.map((h) => (
          <div key={h.id} className={cn(
            'flex items-center justify-between text-[10px] px-2 py-1 rounded',
            h.released_at ? 'bg-muted/30 text-muted-foreground' : 'bg-green-500/10 border border-green-500/20'
          )}>
            <div className="flex items-center gap-2">
              <span className={cn('h-1.5 w-1.5 rounded-full', h.released_at ? 'bg-gray-400' : 'bg-green-500')} />
              <span className="font-mono font-medium">{h.ip_address}</span>
              {h.proxy_port && <span className="font-mono text-purple-400">:{h.proxy_port}</span>}
              <span className="text-muted-foreground">{h.cloud_provider}{h.region ? ` / ${h.region}` : ''}</span>
              {h.node_name && <span className="text-muted-foreground">({h.node_name})</span>}
            </div>
            <div className="flex items-center gap-2">
              {h.scan_count > 0 && (
                <span className="px-1 py-0.5 rounded text-[9px] bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {h.scan_count} scan{h.scan_count !== 1 ? 's' : ''}
                </span>
              )}
              <span className="text-muted-foreground">
                {new Date(h.assigned_at).toLocaleDateString()} {new Date(h.assigned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
              {h.released_at && (
                <span className="text-muted-foreground">
                  → {new Date(h.released_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  {h.release_reason && ` (${h.release_reason})`}
                </span>
              )}
              {!h.released_at && <span className="text-green-400 font-medium">Active</span>}
            </div>
          </div>
        ))}
        {history.length === 0 && <p className="text-[10px] text-muted-foreground">No IP history yet.</p>}
      </div>
    </details>
  )
}


function DORemoteDroplets() {
  const { data, isLoading } = useDODroplets()
  const { data: nodesData } = useNodes()
  const { data: privKeysData } = useSSHKeys()
  const destroyById = useDestroyDODropletById()
  const sshConnect = useSSHConnect()
  const droplets = data?.droplets ?? []
  const connectedIPs = new Set((nodesData?.nodes ?? []).filter((n: any) => n.node_type === 'ssh' && n.status === 'online').map((n: any) => n.metadata?.host))
  const privKeys = privKeysData?.keys ?? []
  const [connectForm, setConnectForm] = useState<{ dropletId: string; key: string } | null>(null)

  if (isLoading) return <p className="text-[10px] text-muted-foreground">Loading remote droplets...</p>
  if (!droplets.length) return null

  return (
    <div className="border-t border-border pt-3 mt-2">
      <h4 className="text-xs font-medium text-muted-foreground mb-2">Remote Droplets ({droplets.length})</h4>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border text-left text-muted-foreground">
              <th className="py-1.5 px-2 font-medium">Name</th>
              <th className="py-1.5 px-2 font-medium">IP</th>
              <th className="py-1.5 px-2 font-medium">Status</th>
              <th className="py-1.5 px-2 font-medium">Region</th>
              <th className="py-1.5 px-2 font-medium">Size</th>
              <th className="py-1.5 px-2 font-medium">Created</th>
              <th className="py-1.5 px-2 font-medium w-16"></th>
            </tr>
          </thead>
          <tbody>
            {droplets.map(d => (
              <tr key={d.id} className="border-b border-border/50 hover:bg-muted/30">
                <td className="py-1.5 px-2 font-medium">{d.name}</td>
                <td className="py-1.5 px-2 font-mono">{d.ip || '-'}</td>
                <td className="py-1.5 px-2">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                    d.status === 'active' ? 'bg-green-500/10 text-green-400' :
                    d.status === 'new' ? 'bg-blue-500/10 text-blue-400 animate-pulse' :
                    'bg-muted text-muted-foreground'
                  }`}>{d.status}</span>
                </td>
                <td className="py-1.5 px-2">{d.region}</td>
                <td className="py-1.5 px-2 font-mono">{d.size}</td>
                <td className="py-1.5 px-2 text-muted-foreground">{d.created_at ? new Date(d.created_at).toLocaleString() : '-'}</td>
                <td className="py-1.5 px-2">
                  <div className="flex items-center gap-1">
                    {d.status === 'active' && d.ip && !connectedIPs.has(d.ip) && (
                      connectForm?.dropletId === String(d.id) ? (
                        <div className="flex items-center gap-1">
                          <select
                            value={connectForm.key}
                            onChange={e => setConnectForm({ ...connectForm, key: e.target.value })}
                            className="px-1 py-0.5 text-[10px] bg-background border border-border rounded w-24"
                          >
                            <option value="">Key...</option>
                            {privKeys.map(k => <option key={k} value={k}>{k}</option>)}
                          </select>
                          <button
                            onClick={() => {
                              if (!connectForm.key) return
                              sshConnect.mutate({
                                name: d.name, host: d.ip, user: 'root', ssh_port: 22,
                                key_name: connectForm.key, os_type: 'ubuntu', provider: 'digitalocean',
                              } as any)
                              setConnectForm(null)
                            }}
                            disabled={!connectForm.key || sshConnect.isPending}
                            className="px-1.5 py-0.5 text-[10px] text-green-400 hover:bg-green-500/20 rounded border border-green-500/20 disabled:opacity-50"
                          >
                            <Wifi className="h-2.5 w-2.5" />
                          </button>
                          <button onClick={() => setConnectForm(null)} className="text-muted-foreground hover:text-foreground">
                            <X className="h-2.5 w-2.5" />
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setConnectForm({ dropletId: String(d.id), key: privKeys[0] || '' })}
                          className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] text-green-400 hover:bg-green-500/20 rounded border border-green-500/20"
                        >
                          <Wifi className="h-2.5 w-2.5" /> Connect
                        </button>
                      )
                    )}
                    {connectedIPs.has(d.ip) && (
                      <span className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] text-green-400">
                        <span className="w-1.5 h-1.5 rounded-full bg-green-500" /> Tunneled
                      </span>
                    )}
                    <button
                      onClick={() => {
                        if (window.confirm(`Destroy droplet "${d.name}" (${d.ip})? This will delete the DO droplet and remove any connected tunnel.`))
                          destroyById.mutate(d.id)
                      }}
                      disabled={destroyById.isPending}
                      className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 rounded border border-red-500/20"
                    >
                      <Trash2 className="h-2.5 w-2.5" /> Destroy
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── WireGuard Tunnels ──────────────────────────────────────────────
function WireGuardTunnels() {
  const { data: peersData } = useWGPeers()
  const { data: nodesData } = useNodes()
  const createPeer = useCreateWGPeer()
  const deletePeer = useDeleteWGPeer()

  // Client management hooks
  const checkClientStatus = useWGClientStatus()
  const startClient = useStartWGClient()
  const stopClient = useStopWGClient()
  const restartClient = useRestartWGClient()

  const [form, setForm] = useState({
    name: '',
    node_id: '',
    endpoint: '',
    auto_install: true,
  })
  const [showConfig, setShowConfig] = useState<WGPeerConfig | null>(null)
  const [showQR, setShowQR] = useState(false)
  const [showStatus, setShowStatus] = useState(false)
  const [systemStatus, setSystemStatus] = useState<any>(null)
  const [expandedPeers, setExpandedPeers] = useState<Set<string>>(new Set())
  const [clientStatus, setClientStatus] = useState<Record<string, any>>({})
  const [showClientOutput, setShowClientOutput] = useState<string | null>(null)

  const checkSystemStatus = async () => {
    setShowStatus(true)
    try {
      // Check multiple system components
      const checks = await Promise.allSettled([
        fetch('/api/wg/peers').then(r => ({service: 'WireGuard API', ok: r.ok, status: r.status})),
        fetch('/api/nodes').then(r => ({service: 'Node Manager', ok: r.ok, status: r.status})),
        fetch('/api/services/status').then(r => ({service: 'Services', ok: r.ok, status: r.status}))
      ])

      const results = checks.map((check, i) => {
        if (check.status === 'fulfilled') {
          const result = check.value as any
          return {
            ...result,
            icon: result.ok ? CheckCircle : XCircle,
            color: result.ok ? 'text-green-500' : 'text-red-500'
          }
        } else {
          return {
            service: ['WireGuard API', 'Node Manager', 'Services'][i],
            ok: false,
            status: 'Failed',
            icon: XCircle,
            color: 'text-red-500'
          }
        }
      })

      setSystemStatus(results)
    } catch (error) {
      console.error('Status check failed:', error)
      setSystemStatus([{
        service: 'System Check',
        ok: false,
        status: 'Error',
        icon: XCircle,
        color: 'text-red-500'
      }])
    }
  }

  const peers = peersData?.peers ?? []
  // Show SSH nodes for WireGuard peer creation (WireGuard peers can be created for any SSH node)
  const nodes = (nodesData?.nodes ?? []).filter(n => n.node_type === 'ssh')

  const handleCreatePeer = () => {
    if (!form.name || !form.node_id) return

    createPeer.mutate({
      name: form.name,
      node_id: form.node_id,
      endpoint: form.endpoint || undefined,
      auto_install: form.auto_install,
    }, {
      onSuccess: (config) => {
        setForm({ name: '', node_id: '', endpoint: '', auto_install: true })
        setShowConfig(config)
      },
      onError: (error) => {
        console.error('Failed to create WireGuard peer:', error)
        // Show user-friendly error message
        alert(`Failed to create WireGuard peer: ${error.message || 'Unknown error'}.\n\nPlease check the system diagnostics below for troubleshooting.`)
      },
    })
  }

  const handleTestPeer = async (peer: any) => {
    try {
      const response = await fetch(`/api/nodes/${peer.id}/proxy`)
      const result = await response.json()

      if (response.ok && result.proxy) {
        alert(`✅ WireGuard peer "${peer.name}" is reachable!\n\nSOCKS Proxy: ${result.proxy}\nStatus: ${result.status || 'online'}`)
      } else {
        alert(`❌ WireGuard peer "${peer.name}" connectivity test failed.\n\nError: ${result.error || 'No proxy available'}\n\nCheck that WireGuard tunnel is active and microsocks is running on the remote node.`)
      }
    } catch (error) {
      alert(`❌ Test failed for "${peer.name}"\n\nError: ${error}\n\nCheck network connectivity and WireGuard configuration.`)
    }
  }

  // Client management functions
  const handleCheckClientStatus = async (peer: any) => {
    try {
      const result = await checkClientStatus.mutateAsync(peer.id)
      setClientStatus(prev => ({ ...prev, [peer.id]: result }))
      if (result.status_output) {
        setShowClientOutput(result.status_output)
      }
    } catch (error) {
      alert(`❌ Failed to check client status for "${peer.name}"\n\nError: ${error}`)
    }
  }

  const handleStartClient = async (peer: any) => {
    try {
      const result = await startClient.mutateAsync(peer.id)
      setClientStatus(prev => ({ ...prev, [peer.id]: result }))
      if (result.ok) {
        alert(`✅ WireGuard client started on "${peer.name}"`)
      } else {
        setShowClientOutput(result.output || result.error || 'Failed to start')
      }
    } catch (error) {
      alert(`❌ Failed to start client on "${peer.name}"\n\nError: ${error}`)
    }
  }

  const handleStopClient = async (peer: any) => {
    try {
      const result = await stopClient.mutateAsync(peer.id)
      setClientStatus(prev => ({ ...prev, [peer.id]: result }))
      if (result.ok) {
        alert(`✅ WireGuard client stopped on "${peer.name}"`)
      } else {
        setShowClientOutput(result.output || result.error || 'Failed to stop')
      }
    } catch (error) {
      alert(`❌ Failed to stop client on "${peer.name}"\n\nError: ${error}`)
    }
  }

  const handleRestartClient = async (peer: any) => {
    try {
      const result = await restartClient.mutateAsync(peer.id)
      setClientStatus(prev => ({ ...prev, [peer.id]: result }))
      if (result.ok) {
        alert(`✅ WireGuard client restarted on "${peer.name}"`)
      } else {
        setShowClientOutput(result.output || result.error || 'Failed to restart')
      }
    } catch (error) {
      alert(`❌ Failed to restart client on "${peer.name}"\n\nError: ${error}`)
    }
  }

  const formatBytes = (bytes: number | undefined) => {
    if (!bytes) return '0 B'
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(1024))
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`
  }

  const formatHandshake = (handshake: string | undefined) => {
    if (!handshake) return 'Never'
    const ago = Math.floor((Date.now() - new Date(handshake).getTime()) / 1000)
    if (ago < 60) return `${ago}s ago`
    if (ago < 3600) return `${Math.floor(ago / 60)}m ago`
    if (ago < 86400) return `${Math.floor(ago / 3600)}h ago`
    return `${Math.floor(ago / 86400)}d ago`
  }

  const togglePeerExpanded = (peerId: string) => {
    setExpandedPeers(prev => {
      const newSet = new Set(prev)
      if (newSet.has(peerId)) {
        newSet.delete(peerId)
      } else {
        newSet.add(peerId)
      }
      return newSet
    })
  }

  const getInstallationStatusIcon = (status: string | undefined) => {
    switch (status) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-400" />
      case 'failed': return <XCircle className="h-4 w-4 text-red-400" />
      case 'pending': return <Clock className="h-4 w-4 text-yellow-400 animate-pulse" />
      case 'not_attempted': return <Monitor className="h-4 w-4 text-muted-foreground" />
      default: return <Monitor className="h-4 w-4 text-muted-foreground" />
    }
  }

  const getInstallationStatusText = (status: string | undefined) => {
    switch (status) {
      case 'success': return 'Installation Successful'
      case 'failed': return 'Installation Failed'
      case 'pending': return 'Installing...'
      case 'not_attempted': return 'Not Attempted'
      default: return 'Unknown Status'
    }
  }

  return (
    <div className="space-y-6">
      {/* System Diagnostics */}
      <WireGuardDiagnostics />

      {/* WireGuard Server Status */}
      <div className="bg-card border border-border rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <h2 className="text-lg font-semibold">WireGuard Server</h2>
          </div>
          <button
            onClick={checkSystemStatus}
            className="flex items-center gap-2 px-3 py-1 text-sm bg-primary/10 hover:bg-primary/20 text-primary rounded-md transition-colors"
          >
            <Activity className="h-4 w-4" />
            System Status
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-muted-foreground">Status:</span>
            <span className="ml-2 text-green-400 font-medium">Active</span>
          </div>
          <div>
            <span className="text-muted-foreground">Interface:</span>
            <span className="ml-2 font-mono">wg0</span>
          </div>
          <div>
            <span className="text-muted-foreground">Network:</span>
            <span className="ml-2 font-mono">10.66.0.0/24</span>
          </div>
        </div>

        {/* System Status Modal */}
        {showStatus && (
          <div className="mt-4 p-4 bg-muted/50 rounded-lg">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold flex items-center gap-2">
                <Activity className="h-4 w-4" />
                System Status Check
              </h3>
              <button
                onClick={() => setShowStatus(false)}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {systemStatus ? (
              <div className="space-y-2">
                {systemStatus.map((status: any, index: number) => {
                  const Icon = status.icon
                  return (
                    <div key={index} className="flex items-center gap-3 p-2 bg-background rounded border">
                      <Icon className={`h-4 w-4 ${status.color}`} />
                      <span className="flex-1 font-medium">{status.service}</span>
                      <span className="text-sm text-muted-foreground">HTTP {status.status}</span>
                    </div>
                  )
                })}
                <div className="mt-3 pt-3 border-t text-xs text-muted-foreground">
                  SSL: TLS 1.3 • Version: 2026.05.18-3 • Last check: {new Date().toLocaleTimeString()}
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Checking system status...
              </div>
            )}
          </div>
        )}
      </div>

      {/* Create Peer Form */}
      <div className="bg-card border border-border rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">Create WireGuard Peer</h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium mb-2">Peer Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="WG_node-name (auto-filled when node selected)"
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Associated Node</label>
            <select
              value={form.node_id}
              onChange={(e) => {
                const selectedNodeId = e.target.value
                const selectedNode = nodes.find(n => n.id === selectedNodeId)
                setForm(f => ({
                  ...f,
                  node_id: selectedNodeId,
                  // Auto-prefix name with "WG_" + node name if name field is empty OR starts with "WG_"
                  name: (!f.name || f.name.startsWith('WG_')) && selectedNode ? `WG_${selectedNode.name}` : f.name
                }))
              }}
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
            >
              <option value="">Select a node</option>
              {nodes.map(node => (
                <option key={node.id} value={node.id}>
                  {node.name} ({node.node_type})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Endpoint (Optional)</label>
            <input
              type="text"
              value={form.endpoint}
              onChange={(e) => setForm(f => ({ ...f, endpoint: e.target.value }))}
              placeholder="your-server.com:51820"
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
            />
          </div>

          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              id="auto_install"
              checked={form.auto_install}
              onChange={(e) => setForm(f => ({ ...f, auto_install: e.target.checked }))}
              className="rounded border-border focus:ring-primary"
            />
            <label htmlFor="auto_install" className="text-sm text-foreground">
              Automatically install WireGuard client on remote node
            </label>
          </div>
        </div>

        <button
          onClick={handleCreatePeer}
          disabled={!form.name || !form.node_id || createPeer.isPending}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
        >
          {createPeer.isPending ? (
            <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Creating...</>
          ) : (
            <><Plus className="h-4 w-4 mr-2" />Create Peer</>
          )}
        </button>
      </div>

      {/* Peers List */}
      <div className="bg-card border border-border rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">WireGuard Peers ({peers.length})</h3>

        {peers.length === 0 ? (
          <div className="text-center text-muted-foreground py-8">
            <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No WireGuard peers configured</p>
            <p className="text-sm">Create your first peer above to get started</p>
          </div>
        ) : (
          <div className="space-y-3">
            {peers.map(peer => (
              <div key={peer.id} className="border border-border rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={cn(
                      'w-3 h-3 rounded-full',
                      (peer.install_status === 'active' || peer.install_status === 'success') ? 'bg-green-400' :
                      peer.install_status === 'pending' ? 'bg-yellow-400 animate-pulse' :
                      peer.install_status === 'failed' ? 'bg-red-400' : 'bg-gray-400'
                    )} />
                    <div>
                      <h4 className="font-medium">{peer.name}</h4>
                      <p className="text-sm text-muted-foreground font-mono">{peer.assigned_ip}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleTestPeer(peer)}
                      className="p-2 text-green-400 hover:text-green-300 hover:bg-muted rounded-md"
                      title="Test WireGuard Connectivity"
                    >
                      <Activity className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => setShowConfig({
                        name: peer.name,
                        node_id: peer.id,
                        client_config: `[Interface]\nPrivateKey = ${peer.public_key}\nAddress = ${peer.assigned_ip}/24\n\n[Peer]\nPublicKey = <SERVER_KEY>\nEndpoint = <SERVER_ENDPOINT>\nAllowedIPs = 10.66.0.0/24\nPersistentKeepalive = 25`
                      })}
                      className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-md"
                      title="Show Config"
                    >
                      <Key className="h-4 w-4" />
                    </button>

                    {/* Client Management Buttons */}
                    <button
                      onClick={() => handleCheckClientStatus(peer)}
                      disabled={checkClientStatus.isPending}
                      className="p-2 text-blue-400 hover:text-blue-300 hover:bg-muted rounded-md"
                      title="Check Client Status"
                    >
                      {checkClientStatus.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Monitor className="h-4 w-4" />}
                    </button>

                    <button
                      onClick={() => handleStartClient(peer)}
                      disabled={startClient.isPending}
                      className="p-2 text-green-400 hover:text-green-300 hover:bg-muted rounded-md"
                      title="Start WireGuard Client"
                    >
                      {startClient.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                    </button>

                    <button
                      onClick={() => handleStopClient(peer)}
                      disabled={stopClient.isPending}
                      className="p-2 text-yellow-400 hover:text-yellow-300 hover:bg-muted rounded-md"
                      title="Stop WireGuard Client"
                    >
                      {stopClient.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Square className="h-4 w-4" />}
                    </button>

                    <button
                      onClick={() => handleRestartClient(peer)}
                      disabled={restartClient.isPending}
                      className="p-2 text-orange-400 hover:text-orange-300 hover:bg-muted rounded-md"
                      title="Restart WireGuard Client"
                    >
                      {restartClient.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                    </button>

                    <button
                      onClick={() => deletePeer.mutate(peer.id)}
                      disabled={deletePeer.isPending}
                      className="p-2 text-red-400 hover:text-red-300 hover:bg-muted rounded-md"
                      title="Delete Peer"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 mt-3 text-sm">
                  <div>
                    <span className="text-muted-foreground">Assigned IP:</span>
                    <p className="font-medium font-mono text-xs">{peer.assigned_ip}</p>
                  </div>
                </div>

                {/* Installation Status */}
                {peer.install_status && (
                  <div className="mt-3 pt-3 border-t border-border">
                    <button
                      onClick={() => togglePeerExpanded(peer.id)}
                      className="flex items-center gap-2 w-full text-left text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {getInstallationStatusIcon(peer.install_status === 'active' ? 'success' : peer.install_status)}
                      <span>{getInstallationStatusText(peer.install_status === 'active' ? 'success' : peer.install_status)}</span>
                      {expandedPeers.has(peer.id) ? <ChevronUp className="h-4 w-4 ml-auto" /> : <ChevronDown className="h-4 w-4 ml-auto" />}
                    </button>

                    {expandedPeers.has(peer.id) && peer.installation_logs && peer.installation_logs.length > 0 && (
                      <div className="mt-3 p-3 bg-muted/50 rounded-md">
                        <div className="flex items-center gap-2 mb-2">
                          <FileText className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm font-medium">Installation Logs</span>
                        </div>
                        <div className="space-y-1 max-h-32 overflow-y-auto">
                          {peer.installation_logs.map((log, index) => (
                            <div key={index} className="text-xs font-mono text-muted-foreground bg-background px-2 py-1 rounded border">
                              {log}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Config Modal */}
      {showConfig && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card border border-border rounded-lg p-6 max-w-2xl w-full mx-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">WireGuard Configuration</h3>
              <button
                onClick={() => setShowConfig(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Client Configuration</label>
                <textarea
                  value={showConfig.client_config}
                  readOnly
                  rows={10}
                  className="w-full px-3 py-2 border border-border rounded-md bg-muted font-mono text-sm"
                />
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(showConfig.client_config)
                  }}
                  className="flex items-center gap-2 px-3 py-2 bg-muted hover:bg-muted/80 rounded-md text-sm"
                >
                  <Copy className="h-4 w-4" />
                  Copy Config
                </button>

                <button
                  onClick={() => setShowQR(!showQR)}
                  className="flex items-center gap-2 px-3 py-2 bg-muted hover:bg-muted/80 rounded-md text-sm"
                >
                  <Monitor className="h-4 w-4" />
                  {showQR ? 'Hide' : 'Show'} QR Code
                </button>
              </div>

              {showQR && (
                <div className="flex justify-center p-6 bg-white rounded-lg">
                  <div className="text-center">
                    <div className="p-4 bg-white rounded-lg">
                      <QRCode
                        value={showConfig.client_config}
                        size={192}
                        style={{ height: "auto", maxWidth: "100%", width: "100%" }}
                        viewBox="0 0 256 256"
                      />
                    </div>
                    <p className="text-sm text-gray-600 mt-3 font-medium">
                      Scan with WireGuard mobile app
                    </p>
                    <p className="text-xs text-gray-500 mt-1">
                      {showConfig.name} configuration
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Client Output Modal */}
      {showClientOutput && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card border border-border rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[80vh] overflow-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">WireGuard Client Output</h3>
              <button
                onClick={() => setShowClientOutput(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="bg-muted/50 border border-border rounded-lg p-4">
              <pre className="text-sm text-foreground whitespace-pre-wrap font-mono">
                {showClientOutput}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}


// ── Remote Commands ─────────────────────────────────────────────────
function RemoteCommands() {
  const { data: nodesData } = useNodes()
  const execSSH = useSSHExec()
  const uploadSSH = useSSHUpload()
  const downloadSSH = useSSHDownload()
  const scanThrough = useScanThroughNode()
  const remoteScan = useRemoteScan()

  const [selectedNode, setSelectedNode] = useState('')
  const [command, setCommand] = useState('')
  const [execOutput, setExecOutput] = useState<Array<{ cmd: string; stdout: string; stderr: string; exit_code: number; duration_ms?: number }>>([])
  const [remotePath, setRemotePath] = useState('')
  const [uploadRemotePath, setUploadRemotePath] = useState('/tmp/')
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [scanForm, setScanForm] = useState<{ nodeId: string; show: boolean }>({ nodeId: '', show: false })
  const [scanParams, setScanParams] = useState({ scan_type: 'nmap', target: '', ports: '1-1000' })
  const [rsForm, setRsForm] = useState({ scan_type: 'masscan', targets: '', ports: '80,443', rate: '1000' })
  const [rsResult, setRsResult] = useState<string | null>(null)

  const sshNodes = (nodesData?.nodes ?? []).filter(n => n.node_type === 'ssh')

  const handleExec = () => {
    if (!selectedNode || !command.trim()) return
    execSSH.mutate({ nodeId: selectedNode, command: command.trim() }, {
      onSuccess: (data) => {
        setExecOutput(prev => [{
          cmd: command.trim(),
          stdout: data.stdout || '',
          stderr: data.stderr || data.error || '',
          exit_code: data.exit_code,
          duration_ms: data.duration_ms,
        }, ...prev].slice(0, 20))
        setCommand('')
      },
      onError: (err) => {
        setExecOutput(prev => [{
          cmd: command.trim(),
          stdout: '',
          stderr: err.message,
          exit_code: -1,
        }, ...prev].slice(0, 20))
      },
    })
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Left: Command Executor */}
      <div className="space-y-4">
        <div className="border border-border rounded-lg p-5 bg-card space-y-4">
          <div className="flex items-center gap-2">
            <Terminal className="h-5 w-5 text-green-500" />
            <h3 className="font-semibold">Remote Command Execution</h3>
          </div>

          {/* Node selector */}
          <div>
            <label className="text-xs text-muted-foreground">Target Node</label>
            <div className="flex gap-2 mt-1">
              <select
                value={selectedNode}
                onChange={e => setSelectedNode(e.target.value)}
                className="flex-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
              >
                <option value="">-- Select SSH node --</option>
                {sshNodes.filter(n => n.status === 'online').map(n => (
                  <option key={n.id} value={n.id}>
                    {n.name} ({n.hostname})
                  </option>
                ))}
              </select>
              <button
                onClick={() => { if (selectedNode) setScanForm({ nodeId: selectedNode, show: true }) }}
                disabled={!selectedNode}
                className="flex items-center gap-1 px-2 py-1.5 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50"
              >
                <Play className="h-3 w-3" /> Scan
              </button>
            </div>
          </div>

          {/* Command input */}
          <div className="flex gap-2">
            <input
              value={command}
              onChange={e => setCommand(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleExec() }}
              placeholder="Enter command..."
              disabled={!selectedNode}
              className="flex-1 px-3 py-1.5 text-sm bg-background border border-border rounded font-mono"
            />
            <button
              onClick={handleExec}
              disabled={!selectedNode || !command.trim() || execSSH.isPending}
              className="flex items-center gap-1 px-3 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
            >
              <Send className="h-3 w-3" /> Run
            </button>
          </div>

          {/* Quick commands */}
          <div className="flex flex-wrap gap-1">
            {QUICK_COMMANDS.map(cmd => (
              <button
                key={cmd}
                onClick={() => {
                  setCommand(cmd)
                  if (selectedNode) {
                    execSSH.mutate({ nodeId: selectedNode, command: cmd }, {
                      onSuccess: (data) => {
                        setExecOutput(prev => [{
                          cmd,
                          stdout: data.stdout || '',
                          stderr: data.stderr || data.error || '',
                          exit_code: data.exit_code,
                          duration_ms: data.duration_ms,
                        }, ...prev].slice(0, 20))
                      },
                    })
                  }
                }}
                disabled={!selectedNode}
                className="px-2 py-0.5 text-xs bg-muted text-muted-foreground rounded hover:bg-muted/80 disabled:opacity-50 font-mono"
              >
                {cmd}
              </button>
            ))}
          </div>

          {/* Output panel */}
          <div className="bg-black rounded p-3 max-h-[400px] overflow-y-auto font-mono text-xs space-y-3">
            {execOutput.length === 0 && (
              <span className="text-gray-500">Command output will appear here...</span>
            )}
            {execOutput.map((entry, i) => (
              <div key={i} className="space-y-1">
                <div className="text-cyan-400">$ {entry.cmd}
                  {entry.duration_ms !== undefined && (
                    <span className="text-gray-500 ml-2">({entry.duration_ms}ms)</span>
                  )}
                  <span className={cn('ml-2', entry.exit_code === 0 ? 'text-green-400' : 'text-red-400')}>
                    [exit: {entry.exit_code}]
                  </span>
                </div>
                {entry.stdout && <pre className="text-green-300 whitespace-pre-wrap">{entry.stdout}</pre>}
                {entry.stderr && <pre className="text-red-300 whitespace-pre-wrap">{entry.stderr}</pre>}
              </div>
            ))}
          </div>
        </div>

        {/* SCP Section */}
        <div className="border border-border rounded-lg p-5 bg-card space-y-4">
          <h3 className="font-semibold text-sm">File Transfer (SCP)</h3>

          {/* Upload */}
          <div className="space-y-2">
            <label className="text-xs text-muted-foreground">Upload File</label>
            <div className="flex gap-2">
              <input
                ref={fileInputRef}
                type="file"
                className="flex-1 text-xs file:mr-2 file:px-2 file:py-1 file:text-xs file:bg-muted file:border-0 file:rounded"
              />
              <input
                value={uploadRemotePath}
                onChange={e => setUploadRemotePath(e.target.value)}
                placeholder="/tmp/"
                className="w-32 px-2 py-1 text-xs bg-background border border-border rounded font-mono"
              />
              <button
                onClick={() => {
                  const file = fileInputRef.current?.files?.[0]
                  if (!file || !selectedNode) return
                  uploadSSH.mutate({ nodeId: selectedNode, file, remotePath: uploadRemotePath })
                }}
                disabled={!selectedNode || uploadSSH.isPending}
                className="flex items-center gap-1 px-2 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
              >
                <Upload className="h-3 w-3" /> Upload
              </button>
            </div>
          </div>

          {/* Download */}
          <div className="space-y-2">
            <label className="text-xs text-muted-foreground">Download File</label>
            <div className="flex gap-2">
              <input
                value={remotePath}
                onChange={e => setRemotePath(e.target.value)}
                placeholder="/etc/hosts"
                className="flex-1 px-2 py-1 text-xs bg-background border border-border rounded font-mono"
              />
              <button
                onClick={() => {
                  if (!selectedNode || !remotePath) return
                  downloadSSH.mutate({ nodeId: selectedNode, remotePath })
                }}
                disabled={!selectedNode || !remotePath || downloadSSH.isPending}
                className="flex items-center gap-1 px-2 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
              >
                <Download className="h-3 w-3" /> Download
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Remote Scan — run tools directly on SSH dropbox */}
      <div className="border border-border rounded-lg p-5 bg-card space-y-4">
        <h3 className="font-semibold">Remote Tool Execution</h3>
        <p className="text-xs text-muted-foreground">
          Run tools directly on a remote SSH host (e.g. masscan with raw sockets). Results are downloaded and ingested automatically.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-muted-foreground">SSH Node</label>
            <select
              value={selectedNode}
              onChange={e => setSelectedNode(e.target.value)}
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            >
              <option value="">-- Select SSH node --</option>
              {sshNodes.filter(n => n.status === 'online').map(n => (
                <option key={n.id} value={n.id}>{n.name} ({String((n.metadata as Record<string, unknown>)?.host ?? '')})</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Scan Type</label>
            <select
              value={rsForm.scan_type}
              onChange={e => setRsForm(f => ({ ...f, scan_type: e.target.value }))}
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            >
              <option value="masscan">masscan</option>
              <option value="nmap">nmap</option>
              <option value="httpx">httpx</option>
              <option value="nuclei">nuclei</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Targets (comma-separated)</label>
            <input
              value={rsForm.targets}
              onChange={e => setRsForm(f => ({ ...f, targets: e.target.value }))}
              placeholder="10.0.0.0/24, 192.168.1.0/24"
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Ports</label>
            <input
              value={rsForm.ports}
              onChange={e => setRsForm(f => ({ ...f, ports: e.target.value }))}
              placeholder="80,443"
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            />
          </div>
          {rsForm.scan_type === 'masscan' && (
            <div>
              <label className="text-xs text-muted-foreground">Rate</label>
              <input
                value={rsForm.rate}
                onChange={e => setRsForm(f => ({ ...f, rate: e.target.value }))}
                placeholder="1000"
                className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
              />
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              if (!selectedNode || !rsForm.targets.trim()) return
              const targets = rsForm.targets.split(',').map(t => t.trim()).filter(Boolean)
              remoteScan.mutate({
                nodeId: selectedNode,
                body: {
                  scan_type: rsForm.scan_type,
                  targets,
                  ports: rsForm.ports || undefined,
                  rate: rsForm.scan_type === 'masscan' ? parseInt(rsForm.rate) || 1000 : undefined,
                },
              }, {
                onSuccess: (data) => setRsResult(JSON.stringify(data, null, 2)),
                onError: (err) => setRsResult(`Error: ${err.message}`),
              })
            }}
            disabled={!selectedNode || !rsForm.targets.trim() || remoteScan.isPending}
            className="px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50"
          >
            {remoteScan.isPending ? 'Running...' : 'Run Remote Scan'}
          </button>
          {remoteScan.isPending && <span className="text-xs text-muted-foreground">This may take several minutes...</span>}
        </div>
        {rsResult && (
          <pre className="p-3 bg-black/80 text-green-400 rounded text-xs overflow-auto max-h-48 whitespace-pre-wrap">
            {rsResult}
          </pre>
        )}
      </div>

      {/* Scan-through dialog (reused) */}
      {scanForm.show && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card border border-border rounded-lg p-6 w-full max-w-md space-y-4">
            <h3 className="font-semibold">Scan Through SSH Tunnel</h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-muted-foreground">Scan Type</label>
                <select
                  value={scanParams.scan_type}
                  onChange={e => setScanParams(p => ({ ...p, scan_type: e.target.value }))}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                >
                  <optgroup label="Port Scanning">
                    <option value="nmap">Nmap (TCP Connect)</option>
                    <option value="full">Full Port Scan</option>
                    <option value="masscan">Masscan</option>
                    <option value="udp">UDP Scan</option>
                    <option value="naabu">Naabu</option>
                  </optgroup>
                  <optgroup label="Recon">
                    <option value="subfinder">Subfinder</option>
                    <option value="dnsx">dnsx</option>
                    <option value="httpx">httpx</option>
                    <option value="tlsx">TLSX</option>
                    <option value="uncover">Uncover</option>
                    <option value="chaos">Chaos</option>
                    <option value="shuffledns">ShuffleDNS</option>
                    <option value="recon-pipeline">Recon Pipeline</option>
                    <option value="crtsh">crt.sh</option>
                    <option value="whatweb">WhatWeb</option>
                  </optgroup>
                  <optgroup label="Web">
                    <option value="web">Web Scan</option>
                    <option value="pipeline">Web Pipeline</option>
                    <option value="katana">Katana</option>
                    <option value="nikto">Nikto</option>
                  </optgroup>
                  <optgroup label="Vuln">
                    <option value="nuclei">Nuclei</option>
                  </optgroup>
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Target</label>
                <input
                  value={scanParams.target}
                  onChange={e => setScanParams(p => ({ ...p, target: e.target.value }))}
                  placeholder={['web', 'pipeline', 'nikto', 'katana'].includes(scanParams.scan_type) ? 'http://192.168.50.1' : '192.168.50.1 or example.com'}
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Ports</label>
                <input
                  value={scanParams.ports}
                  onChange={e => setScanParams(p => ({ ...p, ports: e.target.value }))}
                  placeholder="1-1000"
                  className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
                />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setScanForm({ nodeId: '', show: false })}
                className="px-3 py-1.5 text-sm border border-border rounded hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  const t = scanParams.target
                  const st = scanParams.scan_type
                  const payload: Record<string, unknown> = {
                    nodeId: scanForm.nodeId,
                    scan_type: st,
                    target: t,
                    targets: [t],
                    ports: scanParams.ports,
                  }
                  if (['web', 'pipeline', 'nikto', 'katana'].includes(st)) {
                    payload.target_url = t.startsWith('http') ? t : `http://${t}`
                  }
                  if (st === 'uncover') {
                    payload.query = t
                  }
                  scanThrough.mutate(payload as Parameters<typeof scanThrough.mutate>[0])
                  setScanForm({ nodeId: '', show: false })
                }}
                disabled={!scanParams.target || scanThrough.isPending}
                className="px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50"
              >
                Launch Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Implant Generator ──────────────────────────────────────────────
function ImplantGenerator() {
  const generateImplant = useGenerateImplant()
  const chiselConfig = useChiselConfig()
  const [implantForm, setImplantForm] = useState({
    name: '', os: 'windows', arch: 'amd64', c2_host: '', format: 'exe',
  })
  const [chiselForm, setChiselForm] = useState({ server_host: '', node_name: 'node-1' })
  const [genResult, setGenResult] = useState<string | null>(null)

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Sliver Implant */}
      <div className="border border-border rounded-lg p-5 bg-card space-y-4">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-red-500" />
          <h3 className="font-semibold">Sliver Implant</h3>
        </div>
        <p className="text-xs text-muted-foreground">Generate a Sliver C2 implant for deployment on a remote node.</p>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground">Name</label>
            <input
              value={implantForm.name}
              onChange={(e) => setImplantForm(f => ({ ...f, name: e.target.value }))}
              placeholder="corp-dc01"
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted-foreground">OS</label>
              <select
                value={implantForm.os}
                onChange={(e) => setImplantForm(f => ({ ...f, os: e.target.value }))}
                className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
              >
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="darwin">macOS</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Arch</label>
              <select
                value={implantForm.arch}
                onChange={(e) => setImplantForm(f => ({ ...f, arch: e.target.value }))}
                className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
              >
                <option value="amd64">x86_64</option>
                <option value="arm64">ARM64</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">C2 Callback Host</label>
            <input
              value={implantForm.c2_host}
              onChange={(e) => setImplantForm(f => ({ ...f, c2_host: e.target.value }))}
              placeholder="10.0.0.5 (your external IP)"
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Format</label>
            <select
              value={implantForm.format}
              onChange={(e) => setImplantForm(f => ({ ...f, format: e.target.value }))}
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            >
              <option value="exe">EXE</option>
              <option value="shared">Shared Library (DLL/SO)</option>
              <option value="shellcode">Shellcode</option>
              <option value="service">Service</option>
            </select>
          </div>
        </div>

        <button
          onClick={() => {
            generateImplant.mutate(implantForm, {
              onSuccess: (data) => setGenResult(`Implant generated: ${data.name} (${data.size_bytes} bytes)`),
              onError: (err) => setGenResult(`Error: ${err.message}`),
            })
          }}
          disabled={!implantForm.name || !implantForm.c2_host || generateImplant.isPending}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50"
        >
          <Download className="h-4 w-4" /> Generate Implant
        </button>
        {genResult && <p className="text-xs text-muted-foreground">{genResult}</p>}
      </div>

      {/* Chisel Client */}
      <div className="border border-border rounded-lg p-5 bg-card space-y-4">
        <div className="flex items-center gap-2">
          <Monitor className="h-5 w-5 text-blue-500" />
          <h3 className="font-semibold">Chisel Tunnel</h3>
        </div>
        <p className="text-xs text-muted-foreground">Generate a Chisel client command for a lightweight SOCKS tunnel.</p>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground">Server Host (your external IP)</label>
            <input
              value={chiselForm.server_host}
              onChange={(e) => setChiselForm(f => ({ ...f, server_host: e.target.value }))}
              placeholder="10.0.0.5"
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Node Name</label>
            <input
              value={chiselForm.node_name}
              onChange={(e) => setChiselForm(f => ({ ...f, node_name: e.target.value }))}
              className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
            />
          </div>
        </div>

        <button
          onClick={() => {
            chiselConfig.mutate(chiselForm, {
              onSuccess: (data) => {
                setGenResult(data.command)
              },
              onError: (err) => setGenResult(`Error: ${err.message}`),
            })
          }}
          disabled={!chiselForm.server_host || chiselConfig.isPending}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
        >
          <Copy className="h-4 w-4" /> Generate Command
        </button>

        {genResult && chiselConfig.isSuccess && (
          <div className="bg-muted rounded p-3">
            <div className="flex justify-between items-center mb-1">
              <span className="text-xs text-muted-foreground">Run on remote machine:</span>
              <button
                onClick={() => navigator.clipboard.writeText(genResult)}
                className="text-xs text-primary hover:underline"
              >
                Copy
              </button>
            </div>
            <code className="text-xs break-all">{genResult}</code>
          </div>
        )}
      </div>
    </div>
  )
}

// ── AD Attacks ─────────────────────────────────────────────────────
function ADAttacks() {
  const { data: nodesData } = useNodes()
  const executeAD = useADAttack()
  const [selectedNode, setSelectedNode] = useState('')
  const [selectedAttack, setSelectedAttack] = useState('')
  const [domain, setDomain] = useState('')
  const { data: resultsData } = useADResults(selectedNode)

  const sliverNodes = (nodesData?.nodes ?? []).filter(
    (n) => n.node_type === 'sliver' && n.status === 'online'
  )
  const results = resultsData?.results ?? []

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Attack launcher */}
      <div className="border border-border rounded-lg p-5 bg-card space-y-4">
        <h3 className="font-semibold">Execute AD Attack</h3>

        <div>
          <label className="text-xs text-muted-foreground">Select Node</label>
          <select
            value={selectedNode}
            onChange={(e) => setSelectedNode(e.target.value)}
            className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
          >
            <option value="">-- Select online Sliver node --</option>
            {sliverNodes.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name} ({n.hostname || n.internal_ip || 'unknown'})
              </option>
            ))}
          </select>
          {!sliverNodes.length && (
            <p className="text-xs text-yellow-500 mt-1">No online Sliver nodes available</p>
          )}
        </div>

        <div>
          <label className="text-xs text-muted-foreground">Target Domain (optional)</label>
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="corp.local"
            className="w-full mt-1 px-3 py-1.5 text-sm bg-background border border-border rounded"
          />
        </div>

        <div className="space-y-3">
          {AD_ATTACK_TYPES.map((category) => (
            <div key={category.category}>
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                {category.category}
              </h4>
              <div className="grid grid-cols-1 gap-1">
                {category.attacks.map((attack) => (
                  <button
                    key={attack.id}
                    onClick={() => setSelectedAttack(attack.id)}
                    className={cn(
                      'flex items-center justify-between px-3 py-2 rounded text-sm text-left transition-colors',
                      selectedAttack === attack.id
                        ? 'bg-primary/10 text-primary border border-primary/30'
                        : 'bg-muted/50 hover:bg-muted text-foreground',
                    )}
                  >
                    <div>
                      <span className="font-medium">{attack.label}</span>
                      <span className="text-xs text-muted-foreground ml-2">{attack.desc}</span>
                    </div>
                    <span className="text-xs text-muted-foreground">{attack.tool}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>

        <button
          onClick={() => {
            if (!selectedNode || !selectedAttack) return
            executeAD.mutate({
              nodeId: selectedNode,
              attackType: selectedAttack,
              target_domain: domain || undefined,
            })
          }}
          disabled={!selectedNode || !selectedAttack || executeAD.isPending}
          className="w-full px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50"
        >
          {executeAD.isPending ? 'Executing...' : 'Execute Attack'}
        </button>
        {executeAD.isError && (
          <p className="text-xs text-red-500">{executeAD.error?.message}</p>
        )}
      </div>

      {/* Results panel */}
      <div className="border border-border rounded-lg p-5 bg-card space-y-3">
        <h3 className="font-semibold">Attack Results</h3>
        {!selectedNode && (
          <p className="text-sm text-muted-foreground">Select a node to view results</p>
        )}
        {selectedNode && !results.length && (
          <p className="text-sm text-muted-foreground">No results yet</p>
        )}
        <div className="space-y-2 max-h-[600px] overflow-y-auto">
          {results.map((r) => (
            <div key={r.id} className="border border-border rounded p-3 space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">{r.attack_type}</span>
                <span
                  className={cn(
                    'text-xs px-2 py-0.5 rounded',
                    r.status === 'completed' ? 'bg-green-600 text-white' :
                    r.status === 'running' ? 'bg-blue-600 text-white' :
                    r.status === 'failed' ? 'bg-red-600 text-white' :
                    'bg-muted text-muted-foreground',
                  )}
                >
                  {r.status}
                </span>
              </div>
              <div className="text-xs text-muted-foreground">
                {r.tool} | {r.findings_count ?? 0} findings
                {r.created_at && <> | {new Date(r.created_at).toLocaleString()}</>}
              </div>
              {r.error && <p className="text-xs text-red-500">{r.error}</p>}
              {r.parsed_results && Object.keys(r.parsed_results).length > 0 && (
                <details className="mt-1">
                  <summary className="text-xs text-primary cursor-pointer">View parsed results</summary>
                  <pre className="text-xs bg-muted rounded p-2 mt-1 max-h-40 overflow-auto">
                    {JSON.stringify(r.parsed_results, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── AWS EC2 Cloud Provisioning ───────────────────────
function AWSCloudProvision() {
  const { data: optionsData } = useAWSOptions()
  const createInstance = useCreateAWSInstance()
  const { data: pubKeysData } = useSSHPublicKeys()
  const { data: privKeysData } = useSSHKeys()
  const { data: awsInstancesData } = useAWSInstances()
  const { data: nodesData } = useNodes()
  const destroyById = useDestroyAWSInstanceById()
  const sshConnect = useSSHConnect()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', instance_type: 't3.micro', region: 'us-east-1', key_name: '', ssh_key_name: '' })
  const [provisioningId, setProvisioningId] = useState<string | null>(null)
  const { data: provStatus } = useAWSProvisionStatus(provisioningId)
  const [connectForm, setConnectForm] = useState<{ instanceId: string; key: string } | null>(null)

  const types = optionsData?.instance_types ?? []
  const regions = optionsData?.regions ?? []
  const pubKeys = pubKeysData?.keys ?? []
  const privKeys = privKeysData?.keys ?? []
  const instances = awsInstancesData?.instances ?? []
  const connectedIPs = new Set((nodesData?.nodes ?? []).filter((n: any) => n.node_type === 'ssh' && n.status === 'online').map((n: any) => n.metadata?.host))

  const handleCreate = () => {
    if (!form.name || !form.key_name || !form.ssh_key_name) return
    setProvisioningId(null)
    createInstance.mutate(form, {
      onSuccess: (d) => { if (d.instance_id) setProvisioningId(d.instance_id); setShowForm(false) },
    })
  }

  return (
    <div className="border border-border rounded-lg p-4 bg-card space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Server className="h-4 w-4 text-orange-400" /> AWS EC2 Instances
        </h3>
        <button onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1 px-2.5 py-1 text-xs rounded border border-orange-500/30 text-orange-400 hover:bg-orange-500/10">
          <Plus className="h-3 w-3" /> New Instance
        </button>
      </div>

      {showForm && (
        <div className="border border-border rounded p-3 space-y-2 bg-muted/30">
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-muted-foreground">Name</label>
              <input value={form.name} onChange={e => setForm({...form, name: e.target.value})}
                placeholder="scan-node-1" className="w-full bg-background rounded px-2 py-1 text-sm border border-border" />
            </div>
            <div className="col-span-2">
              <label className="text-[10px] text-muted-foreground">SSH Key (private key — public key auto-extracted for EC2)</label>
              <select value={form.ssh_key_name} onChange={e => setForm({...form, ssh_key_name: e.target.value, key_name: e.target.value})}
                className="w-full bg-background rounded px-2 py-1 text-sm border border-border">
                <option value="">Select SSH key...</option>
                {privKeys.map(k => <option key={k} value={k}>{k}</option>)}
              </select>
              <p className="text-[9px] text-muted-foreground mt-0.5">Public key will be auto-generated from this key and imported to EC2</p>
            </div>
            <div>
              <label className="text-[10px] text-muted-foreground">Instance Type</label>
              <select value={form.instance_type} onChange={e => setForm({...form, instance_type: e.target.value})}
                className="w-full bg-background rounded px-2 py-1 text-sm border border-border">
                {types.map(t => <option key={t.type} value={t.type}>{t.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-muted-foreground">Region</label>
              <select value={form.region} onChange={e => setForm({...form, region: e.target.value})}
                className="w-full bg-background rounded px-2 py-1 text-sm border border-border">
                {regions.map(r => <option key={r.id} value={r.id}>{r.label}</option>)}
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={handleCreate} disabled={!form.name || !form.ssh_key_name || createInstance.isPending}
              className="px-3 py-1.5 text-xs rounded bg-orange-500 text-white hover:bg-orange-600 disabled:opacity-50">
              {createInstance.isPending ? 'Launching...' : 'Create & Connect'}
            </button>
            <button onClick={() => setShowForm(false)} className="px-3 py-1.5 text-xs rounded border border-border hover:bg-muted">Cancel</button>
          </div>
          {createInstance.error && <p className="text-xs text-red-500">{String(createInstance.error)}</p>}
        </div>
      )}

      {/* Provisioning status */}
      {provisioningId && provStatus && provStatus.status !== 'unknown' && (
        <div className="p-2 rounded bg-muted/30 border border-border text-xs space-y-1">
          <div className="flex items-center gap-2">
            <span className={cn('w-2 h-2 rounded-full',
              provStatus.status === 'online' ? 'bg-green-500' :
              provStatus.status === 'failed' || provStatus.status === 'ssh_timeout' ? 'bg-red-500' :
              'bg-blue-500 animate-pulse'
            )} />
            <span className="font-medium">{provStatus.status}</span>
            {provStatus.ip && <span className="font-mono text-muted-foreground">{provStatus.ip}</span>}
          </div>
          {provStatus.error && <p className="text-red-500">{provStatus.error}</p>}
        </div>
      )}

      {/* Existing instances */}
      {instances.length > 0 && (
        <div className="border-t border-border pt-2">
          <h4 className="text-xs font-medium text-muted-foreground mb-2">EC2 Instances ({instances.length})</h4>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="py-1 px-2 font-medium">Name</th>
                <th className="py-1 px-2 font-medium">IP</th>
                <th className="py-1 px-2 font-medium">Status</th>
                <th className="py-1 px-2 font-medium">Type</th>
                <th className="py-1 px-2 font-medium w-32"></th>
              </tr>
            </thead>
            <tbody>
              {instances.map(inst => (
                <tr key={inst.id} className="border-b border-border/50 hover:bg-muted/30">
                  <td className="py-1.5 px-2 font-medium">{inst.name}</td>
                  <td className="py-1.5 px-2 font-mono">{inst.ip || '-'}</td>
                  <td className="py-1.5 px-2">
                    <span className={cn('px-1.5 py-0.5 rounded text-[10px]',
                      inst.status === 'running' ? 'bg-green-500/10 text-green-400' :
                      inst.status === 'pending' ? 'bg-blue-500/10 text-blue-400 animate-pulse' :
                      'bg-muted text-muted-foreground'
                    )}>{inst.status}</span>
                  </td>
                  <td className="py-1.5 px-2 font-mono">{inst.type}</td>
                  <td className="py-1.5 px-2">
                    <div className="flex items-center gap-1">
                      {inst.status === 'running' && inst.ip && !connectedIPs.has(inst.ip) && (
                        connectForm?.instanceId === inst.id ? (
                          <div className="flex items-center gap-1">
                            <select value={connectForm.key} onChange={e => setConnectForm({...connectForm, key: e.target.value})}
                              className="px-1 py-0.5 text-[10px] bg-background border border-border rounded w-24">
                              <option value="">Key...</option>
                              {privKeys.map(k => <option key={k} value={k}>{k}</option>)}
                            </select>
                            <button onClick={() => {
                              if (!connectForm.key) return
                              sshConnect.mutate({ name: inst.name, host: inst.ip, user: 'ubuntu', ssh_port: 22, key_name: connectForm.key, os_type: 'ubuntu', provider: 'aws' } as any)
                              setConnectForm(null)
                            }} disabled={!connectForm.key} className="px-1.5 py-0.5 text-[10px] text-green-400 hover:bg-green-500/20 rounded border border-green-500/20 disabled:opacity-50">
                              <Wifi className="h-2.5 w-2.5" />
                            </button>
                            <button onClick={() => setConnectForm(null)} className="text-muted-foreground"><X className="h-2.5 w-2.5" /></button>
                          </div>
                        ) : (
                          <button onClick={() => setConnectForm({ instanceId: inst.id, key: privKeys[0] || '' })}
                            className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] text-green-400 hover:bg-green-500/20 rounded border border-green-500/20">
                            <Wifi className="h-2.5 w-2.5" /> Connect
                          </button>
                        )
                      )}
                      {connectedIPs.has(inst.ip) && (
                        <span className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] text-green-400">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-500" /> Tunneled
                        </span>
                      )}
                      <button onClick={() => {
                        if (window.confirm(`Terminate "${inst.name}" (${inst.ip})? This will destroy the EC2 instance.`))
                          destroyById.mutate({ instanceId: inst.id, region: inst.region })
                      }} disabled={destroyById.isPending}
                        className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 rounded border border-red-500/20">
                        <Trash2 className="h-2.5 w-2.5" /> Terminate
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Remote Kali MCP Button + Status Panel ───────────
function McpButton({ nodeId }: { nodeId: string }) {
  const { data: status } = useMcpStatus(nodeId)
  const startMcp = useStartMcp()
  const stopMcp = useStopMcp()
  const active = status?.active ?? false

  return (
    <button
      onClick={() => active ? stopMcp.mutate(nodeId) : startMcp.mutate(nodeId)}
      disabled={startMcp.isPending || stopMcp.isPending}
      className={cn(
        'flex items-center gap-1 px-2 py-1 text-xs rounded disabled:opacity-50',
        active
          ? 'bg-green-600/20 text-green-400 border border-green-500/30 hover:bg-red-600/20 hover:text-red-400 hover:border-red-500/30'
          : 'bg-violet-600/20 text-violet-400 border border-violet-500/30 hover:bg-violet-600/30',
      )}
      title={active ? `MCP active on port ${status?.local_port} — click to stop` : 'Start Kali MCP server on this node'}
    >
      {startMcp.isPending ? <><Cpu className="h-3 w-3 animate-spin" /> Starting...</> : active ? (
        <><span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> MCP:{status?.local_port}</>
      ) : (
        <><Cpu className="h-3 w-3" /> Start MCP</>
      )}
    </button>
  )
}

function McpStatusPanel({ nodeId }: { nodeId: string }) {
  const { data: status } = useMcpStatus(nodeId)
  const active = status?.active ?? false
  if (!active) return null

  return (
    <div className="border-t border-border pt-2 mt-2">
      <div className="flex items-center gap-2 mb-1.5">
        <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
        <span className="text-xs font-semibold text-green-400">Kali MCP Server — Active</span>
        <span className="text-[10px] text-muted-foreground ml-auto">Port {status?.local_port} (forwarded)</span>
      </div>
      <div className="bg-muted/30 rounded p-2 space-y-1 text-[10px]">
        <div className="flex items-center gap-2">
          <span className="text-green-500">{'\u2713'}</span>
          <span className="text-muted-foreground">mcp-kali-server</span>
          <span className="text-foreground">running on remote node</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-green-500">{'\u2713'}</span>
          <span className="text-muted-foreground">SSH port forward</span>
          <span className="font-mono text-foreground">localhost:{status?.local_port} → remote:5000</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-green-500">{'\u2713'}</span>
          <span className="text-muted-foreground">Chat integration</span>
          <span className="text-foreground">tools auto-discovered for built-in chat</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-green-500">{'\u2713'}</span>
          <span className="text-muted-foreground">MCP proxy</span>
          <span className="font-mono text-foreground">/api/nodes/{nodeId.slice(0, 8)}/mcp-proxy</span>
        </div>
      </div>
    </div>
  )
}
