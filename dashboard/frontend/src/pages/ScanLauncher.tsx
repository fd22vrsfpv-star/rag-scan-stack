import { useState, useEffect, useRef } from 'react'
import PageHelp from '@/components/PageHelp'
import { useNavigate } from 'react-router-dom'
import { useLaunchScan } from '@/api/scans'
import { useFindings } from '@/api/findings'
import { useWordlists } from '@/api/reports'
import { useScopeNames, useScope } from '@/api/scope'
import { useNodes, useScanThroughNode, useWGPeers } from '@/api/nodes'
import { apiFetch } from '@/api/client'
import { useStartBurpScan, useConfigureBurpProxy } from '@/api/burp'
import { useEngagements, useEngagementScopes } from '@/api/engagements'
import { useTargetedReconLookup, useTargetedReconExecute } from '@/api/targeted-recon'
import { useAssetPorts } from '@/api/assets'
import type { ReconCommand } from '@/api/targeted-recon'
// Remote scan UI moved to Nodes page
import { useScanDefaultsStore } from '@/stores/scanDefaults'
import { useUIStore } from '@/stores/ui'
import { useCloudRecommendations, useRefreshCloudRecommendations, useUpdateCloudRecommendation, useCloudPosture } from '@/api/cloudSuggestor'
import { SCAN_CATEGORIES, SCAN_FIELDS, SECRET_TYPES, BRUTUS_PROTOCOLS, NUCLEI_TAG_PRESETS, type ScanMeta } from '@/lib/constants'
import { cn } from '@/lib/utils'
import { useQueryClient } from '@tanstack/react-query'
import { apiUrl } from '@/api/client'
import {
  Zap, Search, ScanLine, Radio, Bug, Globe, Layers, Server,
  Sword, Radar, Network, Globe2, Lock, Monitor, ShieldAlert, ShieldCheck, Download, Crosshair, X, Wifi, KeyRound, Upload, Briefcase, Cloud, FolderSearch, ScanSearch, Settings, ChevronDown, AlertTriangle,
} from 'lucide-react'

const ICONS: Record<string, React.ElementType> = {
  Zap, Search, ScanLine, Radio, Bug, Globe, Layers, Server,
  Sword, Radar, Network, Globe2, Lock, Monitor, ShieldAlert, ShieldCheck, KeyRound, Cloud, FolderSearch, ScanSearch,
}

// Tab icon mapping
const TAB_ICONS: Record<string, React.ElementType> = {
  'Pipelines': Layers,
  'Port Scanning': Radar,
  'Recon': Globe2,
  'Web': Globe,
  'Vuln': Bug,
  'Credentials': KeyRound,
  'AD / Internal': Server,
  'Cloud': Cloud,
}

// Target-related field keys that should be auto-filled from scope
const TARGET_KEYS = new Set(['target', 'targets', 'target_url', 'target_urls'])

// Pipeline items shown in the Pipelines tab
const PIPELINE_ITEMS = [
  { id: 'recon-pipeline', label: 'Recon Pipeline', desc: 'Full recon chain', icon: 'Layers' },
  { id: 'passive-recon', label: 'Passive Recon', desc: 'Passive-only + cert chain', icon: 'ShieldCheck' },
  { id: 'pipeline', label: 'Web Pipeline', desc: 'WAF→Katana→Playwright→Gobuster→Nikto→Nuclei→ZAP', icon: 'Layers' },
  { id: 'full', label: 'Full Port Scan', desc: 'Masscan→Nmap 1-65535', icon: 'ScanLine' },
  { id: 'web', label: 'Web Scan', desc: 'Gobuster + ZAP', icon: 'Globe' },
  { id: 'nmap', label: 'Nmap Pipeline', desc: 'Masscan + Nmap svc detect', icon: 'Search' },
]
const PIPELINE_IDS = new Set(PIPELINE_ITEMS.map(p => p.id))

// Scan types that do NOT support SOCKS proxy — on SSH nodes these get pushed
// to the remote end for direct execution instead of proxying
const NO_PROXY_SCANS = new Set(['playwright', 'brutus'])

// Flat lookup: scan id → metadata (proxy, touchesTarget, passive)
const SCAN_META: Record<string, ScanMeta> = {}
for (const cat of SCAN_CATEGORIES) {
  for (const s of cat.scans) {
    SCAN_META[s.id] = s
  }
}

function ScanBadges({ scanId }: { scanId: string }) {
  const meta = SCAN_META[scanId]
  if (!meta) return null
  return (
    <div className="flex gap-1 flex-wrap justify-center mt-1">
      {meta.proxy ? (
        <span className="px-1 py-0 rounded text-[8px] bg-blue-500/15 text-blue-400 border border-blue-500/20" title="Supports SOCKS proxy routing">PROXY</span>
      ) : (
        <span className="px-1 py-0 rounded text-[8px] bg-zinc-500/15 text-zinc-500 border border-zinc-500/20" title="Cannot route through SOCKS proxy">NO PROXY</span>
      )}
      {meta.touchesTarget ? (
        <span className="px-1 py-0 rounded text-[8px] bg-red-500/15 text-red-400 border border-red-500/20" title="Sends traffic directly to the target">TOUCHES TARGET</span>
      ) : (
        <span className="px-1 py-0 rounded text-[8px] bg-green-500/15 text-green-400 border border-green-500/20" title="No direct contact with target — queries third-party sources only">NO CONTACT</span>
      )}
      {meta.passive ? (
        <span className="px-1 py-0 rounded text-[8px] bg-cyan-500/15 text-cyan-400 border border-cyan-500/20" title="Passive OSINT — queries APIs and databases, no target interaction">PASSIVE</span>
      ) : null}
      {meta.remote ? (
        <span className="px-1 py-0 rounded text-[8px] bg-green-500/15 text-green-400 border border-green-500/20" title="Can run on a remote node via SOCKS proxy or SSH remote exec">REMOTE</span>
      ) : (
        <span className="px-1 py-0 rounded text-[8px] bg-red-500/15 text-red-400 border border-red-500/20" title="Cannot run on remote nodes — local execution only">NO REMOTE</span>
      )}
    </div>
  )
}

// Scan type → required fields
// SCAN_FIELDS imported from @/lib/constants

// Cloud import tool name mapping (scan id → ingest endpoint name)
const CLOUD_IMPORT_MAP: Record<string, string> = {
  'prowler-import': 'prowler',
  'scoutsuite-import': 'scoutsuite',
  'pacu-import': 'pacu',
  'cloudfox-import': 'cloudfox',
  'azurehound-import': 'azurehound',
  'microburst-import': 'microburst',
}

// Component for autofilling targets from port scan results
function AutofillFromPortScan({
  scanType,
  onAutofill
}: {
  scanType: string
  onAutofill: (updates: Record<string, string>) => void
}) {
  const [targetIP, setTargetIP] = useState('')
  const { data: portData, isLoading, error } = useAssetPorts(targetIP.trim())

  const handleAutofill = () => {
    if (!portData?.items?.length) return

    // Filter for web-relevant ports
    const webPorts = portData.items.filter(port => {
      const portNum = port.port
      return portNum === 80 || portNum === 443 || portNum === 8080 || portNum === 8443 || portNum === 8000 || portNum === 8888 || portNum === 3000 || portNum === 5000
    })

    if (webPorts.length === 0) return

    // Generate target URLs
    const targetUrls = webPorts.map(port => {
      const protocol = port.port === 443 || port.port === 8443 ? 'https' : 'http'
      const portSuffix = (port.port === 80 || port.port === 443) ? '' : `:${port.port}`
      return `${protocol}://${targetIP}${portSuffix}`
    })

    // Generate ports list
    const ports = webPorts.map(p => p.port).join(',')

    // Configure field names based on scan type
    const updates: Record<string, string> = {}

    if (scanType === 'nuclei') {
      updates.target = targetUrls[0] || '' // Nuclei typically takes single target
      updates.ports = ports
    } else if (scanType === 'web') {
      updates.target_urls = targetUrls.join('\n') // Web scanner uses textarea (newline-separated)
      updates.ports = ports
    } else if (scanType === 'whatweb' || scanType === 'zap') {
      updates.targets = targetUrls.join(',') // whatweb/zap use comma-separated
    }

    onAutofill(updates)
  }

  return (
    <div className="border border-border rounded-md p-2.5 space-y-2">
      <h5 className="text-xs font-medium text-muted-foreground">Autofill from Port Scan</h5>
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Enter target IP (e.g., 192.168.1.100)"
          value={targetIP}
          onChange={e => setTargetIP(e.target.value)}
          className="flex-1 bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
        />
        <button
          type="button"
          onClick={handleAutofill}
          disabled={!targetIP.trim() || isLoading || !portData?.items?.length}
          className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? 'Loading...' : 'Autofill'}
        </button>
      </div>
      {error && (
        <p className="text-xs text-red-400">Error loading port data</p>
      )}
      {portData && !isLoading && (
        <p className="text-xs text-muted-foreground">
          Found {portData.items?.length || 0} ports
          {portData.items && ` (${portData.items.filter(p => [80, 443, 8080, 8443, 8000, 8888, 3000, 5000].includes(p.port)).length} web ports)`}
        </p>
      )}
    </div>
  )
}

export default function ScanLauncher() {
  const [selected, setSelected] = useState<string | null>(null)
  const [params, setParams] = useState<Record<string, string>>({})
  const defaultNodeId = useUIStore(s => s.defaultNodeId)
  const [selectedNodeId, setSelectedNodeId] = useState(defaultNodeId || '')
  const globalEngagementId = useUIStore(s => s.selectedEngagementId)
  const setGlobalEngagement = useUIStore(s => s.setSelectedEngagement)
  const selectedEngagementId = globalEngagementId ?? ''
  const [activeTab, setActiveTab] = useState('Pipelines')
  // Smart Recon state
  const [reconTarget, setReconTarget] = useState('')
  const [reconPort, setReconPort] = useState('')
  // Passive recon state
  const [prCertChain, setPrCertChain] = useState(true)
  const [prCertIterations, setPrCertIterations] = useState(2)
  const [prSpider, setPrSpider] = useState(false)
  const [prSpiderDepth, setPrSpiderDepth] = useState(2)
  const [prPlanResult, setPrPlanResult] = useState<Record<string, unknown> | null>(null)
  const [prPlanLoading, setPrPlanLoading] = useState(false)
  const [importFile, setImportFile] = useState<File | null>(null)
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState<string | null>(null)
  const launch = useLaunchScan()
  const scanThroughNode = useScanThroughNode()
  const burpScan = useStartBurpScan()
  const burpProxy = useConfigureBurpProxy()
  const engagementsQuery = useEngagements()
  const engagements = engagementsQuery.data?.engagements ?? []
  const navigate = useNavigate()
  const { defaultTargets, defaultPorts, defaultRate, defaultScope, toolOverrides, activeProfile } = useScanDefaultsStore()
  const gobusterFindings = useFindings({ source: ['gobuster'], limit: 500 })
  const nodesQuery = useNodes()
  const wgPeersQuery = useWGPeers()
  const onlineNodes = (nodesQuery.data?.nodes ?? []).filter(n => n.status === 'online')

  // Helper function to determine actual tunnel type for display
  const getTunnelDisplayType = (node: any) => {
    const peers = wgPeersQuery.data?.peers ?? []
    const wgPeer = peers.find(p => p.id === node.id)

    // Show "wireguard" if node has WireGuard peer with successful installation
    if (wgPeer && (wgPeer.install_status === 'success' || wgPeer.install_status === 'active')) {
      return 'wireguard'
    }

    // Otherwise show the database tunnel_method or fallback to node_type
    return node.tunnel_method || node.node_type
  }

  // Block local scans setting — when enabled, hide "Direct (no proxy)" option
  const [blockLocal, setBlockLocal] = useState(false)
  useEffect(() => {
    apiFetch<{ value: string }>('/settings/config/block_local_scans')
      .then(r => setBlockLocal(r?.value?.toLowerCase() === 'true'))
      .catch(() => {})
  }, [])
  const wordlistsQuery = useWordlists()
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const cloudFileRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const sshNodes = (nodesQuery.data?.nodes ?? []).filter(n => n.node_type === 'ssh')

  // Cloud suggestor
  const cloudRecs = useCloudRecommendations()
  const cloudPosture = useCloudPosture()
  const refreshCloud = useRefreshCloudRecommendations()
  const updateCloudRec = useUpdateCloudRecommendation()

  // Scope selector state — initialize from persisted default or global engagement scope
  const globalScope = useUIStore(s => s.selectedScopeName)
  const [activeScope, setActiveScope] = useState(defaultScope || globalScope || '')
  const scopeNames = useScopeNames()
  const scopeData = useScope(activeScope)

  const scopeTargets = scopeData.data?.targets ?? []
  const engScopesQuery = useEngagementScopes(selectedEngagementId || undefined)
  const engagementScopes = engScopesQuery.data?.scopes ?? []

  // All tabs: Pipelines + each SCAN_CATEGORIES entry
  const tabs = ['Pipelines', 'Smart Recon', ...SCAN_CATEGORIES.map(c => c.name)]

  // Auto-fill target fields when scope data loads or scan type changes
  useEffect(() => {
    if (!activeScope || !scopeData.data || !selected) return
    const targets = scopeData.data.targets.map(t => t.target)
    if (targets.length === 0) return

    const updates = fillTargetFields(selected, targets)
    if (Object.keys(updates).length > 0) {
      setParams(prev => ({ ...prev, ...updates }))
    }
  }, [activeScope, scopeData.data, selected])

  // Parse multi-line defaultTargets into an array of trimmed, non-empty lines
  const parsedDefaults = defaultTargets
    .split(/[\r\n]+/)
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith('#'))

  // Helper: fill target fields from a list of target strings
  const fillTargetFields = (scanType: string, targets: string[]): Record<string, string> => {
    const fields = SCAN_FIELDS[scanType]
    if (!fields || targets.length === 0) return {}
    const fieldKeys = new Set(fields.map(f => f.key))
    const out: Record<string, string> = {}
    if (fieldKeys.has('target')) out.target = targets.length === 1 ? targets[0] : targets.join(',')
    if (fieldKeys.has('targets')) out.targets = targets.join(',')
    if (fieldKeys.has('target_url')) out.target_url = targets[0] || ''  // single URL only
    if (fieldKeys.has('target_urls')) out.target_urls = targets.join('\n')
    return out
  }

  const buildDefaults = (scanType: string): Record<string, string> => {
    const fields = SCAN_FIELDS[scanType]
    if (!fields) return {}
    const defaults: Record<string, string> = {}
    const fieldKeys = new Set(fields.map(f => f.key))

    // If scope is active and has targets, use those for target fields
    if (activeScope && scopeData.data && scopeData.data.targets.length > 0) {
      const targets = scopeData.data.targets.map(t => t.target)
      Object.assign(defaults, fillTargetFields(scanType, targets))
    } else if (!activeScope && parsedDefaults.length > 0) {
      // Only fall back to manual defaults when NO scope is selected
      Object.assign(defaults, fillTargetFields(scanType, parsedDefaults))
    }

    if (fieldKeys.has('ports') && defaultPorts) defaults.ports = scanType === 'masscan' ? '0-65535' : defaultPorts
    if (fieldKeys.has('rate') && defaultRate) defaults.rate = defaultRate
    // Merge tool-level overrides from Settings > Tool Options
    const overrides = toolOverrides[scanType]
    if (overrides) {
      for (const [k, v] of Object.entries(overrides)) {
        if (v && fieldKeys.has(k)) defaults[k] = v
      }
    }
    return defaults
  }

  const handleSelectScan = (scanId: string) => {
    setSelected(scanId)
    setParams(buildDefaults(scanId))
    setImportFile(null)
    setImportResult(null)
    // For no-proxy scans, clear node if current selection isn't SSH
    if (NO_PROXY_SCANS.has(scanId) && selectedNodeId) {
      const node = (nodesQuery.data?.nodes ?? []).find(n => n.id === selectedNodeId)
      if (node && node.node_type !== 'ssh') setSelectedNodeId('')
    }
  }

  const handleClearScope = () => {
    setActiveScope('')
    // Clear target fields back to manual defaults
    if (selected) {
      setParams(buildDefaults_manual(selected))
    }
  }

  // Build defaults without scope (for clearing)
  const buildDefaults_manual = (scanType: string): Record<string, string> => {
    const fields = SCAN_FIELDS[scanType]
    if (!fields) return {}
    const defaults: Record<string, string> = {}
    const fieldKeys = new Set(fields.map(f => f.key))
    Object.assign(defaults, fillTargetFields(scanType, parsedDefaults))
    if (fieldKeys.has('ports') && defaultPorts) defaults.ports = scanType === 'masscan' ? '0-65535' : defaultPorts
    if (fieldKeys.has('rate') && defaultRate) defaults.rate = defaultRate
    // Merge tool-level overrides from Settings > Tool Options
    const overrides = toolOverrides[scanType]
    if (overrides) {
      for (const [k, v] of Object.entries(overrides)) {
        if (v && fieldKeys.has(k)) defaults[k] = v
      }
    }
    return defaults
  }

  const handleLaunch = () => {
    if (!selected) return
    const parsed: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(params)) {
      if (!v) continue
      if (k === 'skip_phases_str') { parsed['skip_phases'] = v.split(',').map(s => s.trim()); continue }
      if (k === 'hashes') {
        // Pass hashes as newline-separated string for BFF to split
        parsed[k] = v
      } else if (k === 'target_urls') {
        const urls = v.split('\n').map(s => s.trim()).filter(Boolean)
        if (urls.length === 1) parsed['target_url'] = urls[0]
        else if (urls.length > 1) parsed['target_urls'] = urls
      } else if (k === 'targets') {
        const trimmed = v.trim()
        if (trimmed === 'from_httpx' || trimmed === 'from_db') parsed[k] = trimmed
        else parsed[k] = v.split(',').map(s => s.trim())
      }
      else if (k === 'rate' || k === 'depth' || k === 'max_paths' || k === 'limit' || k === 'aggression' || k === 'timeout' || k === 'timeout_sec' || k === 'max_playwright_urls') parsed[k] = Number(v)
      else if (v === 'true' || v === 'false') parsed[k] = v === 'true'
      else parsed[k] = v
    }

    // Inject passive-recon specific params
    if (selected === 'passive-recon') {
      parsed.include_cert_chain = prCertChain
      parsed.cert_chain_max_iterations = prCertIterations
      parsed.include_spider = prSpider
      parsed.spider_depth = prSpiderDepth
    }

    // Inject scope for all scan types
    if (activeScope) parsed.scope_name = activeScope

    if (selectedEngagementId) {
      parsed.engagement_id = selectedEngagementId
    }

    if (selected === 'burp-scan') {
      // Burp Suite headless scan — goes to Burp REST API, not normal scan routes
      const urls = parsed.target_urls as string[] || (parsed.target_url ? [parsed.target_url as string] : [])
      if (!urls.length) return

      // Configure SOCKS proxy on Burp if specified
      const proxyStr = parsed.burp_proxy as string
      if (proxyStr) {
        try {
          const proxyUrl = new URL(proxyStr.replace('socks5://', 'http://').replace('socks4://', 'http://'))
          burpProxy.mutate({
            proxy_host: proxyUrl.hostname,
            proxy_port: parseInt(proxyUrl.port) || 1080,
            socks_version: proxyStr.startsWith('socks4') ? 4 : 5,
            enabled: true,
          })
        } catch { /* invalid proxy URL, skip */ }
      }

      burpScan.mutate({
        urls,
        scan_config: (parsed.scan_config as string) || 'default',
      }, { onSuccess: () => navigate('/scans') })
      return
    }

    if (selectedNodeId) {
      // Route scan through remote node's SOCKS proxy (includes SSH tunnels)
      scanThroughNode.mutate(
        { nodeId: selectedNodeId, scan_type: selected, ...parsed },
        { onSuccess: () => navigate('/scans') },
      )
    } else {
      launch.mutate(
        { type: selected, params: parsed },
        { onSuccess: () => navigate('/scans') },
      )
    }
  }

  const handlePlanOnly = async () => {
    if (selected !== 'passive-recon') return
    const targets = (params.targets || '').split(',').map(s => s.trim()).filter(Boolean)
    if (targets.length === 0) return
    setPrPlanLoading(true)
    setPrPlanResult(null)
    try {
      const resp = await fetch(apiUrl('/scans/passive-recon'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets,
          include_cert_chain: prCertChain,
          cert_chain_max_iterations: prCertIterations,
          include_spider: prSpider,
          spider_depth: prSpiderDepth,
          scope_name: activeScope || undefined,
          plan_only: true,
        }),
      })
      const data = await resp.json()
      setPrPlanResult(data)
    } catch (err) {
      setPrPlanResult({ error: String(err) })
    } finally {
      setPrPlanLoading(false)
    }
  }

  const handleCloudImport = async () => {
    if (!selected || !importFile) return
    const toolName = CLOUD_IMPORT_MAP[selected]
    if (!toolName) return

    const formatStats = (s: any) =>
      `Imported ${s?.findings_inserted ?? 0} findings (${s?.records_seen ?? 0} records, ${s?.skipped ?? 0} skipped, ${s?.errors ?? 0} errors)`

    const parseResp = async (resp: Response) => {
      const raw = await resp.text()
      let data: any = null
      try { data = raw ? JSON.parse(raw) : null } catch { /* non-JSON (HTML error page, 502/504, etc.) */ }
      return { raw, data }
    }

    setImporting(true)
    setImportResult(null)
    try {
      const formData = new FormData()
      formData.append('file', importFile)
      if (selectedEngagementId) formData.append('engagement_id', selectedEngagementId)
      const resp = await fetch(apiUrl(`/import/${toolName}`), { method: 'POST', body: formData })
      const { raw, data } = await parseResp(resp)

      if (!resp.ok || !data) {
        // Special-case duplicate_ingest from the rag-api dedup guard so the
        // operator sees a clean message instead of a JSON blob.
        const d = data?.detail
        if (d && typeof d === 'object' && (d as any).error === 'duplicate_ingest') {
          const m = (d as any).message || 'A matching ingest is already running.'
          const jid = (d as any).existing_job_id
          setImportResult(`${m}${jid ? ` (existing job ${String(jid).slice(0, 8)}…)` : ''}`)
          return
        }
        const detail = (typeof d === 'object' ? (d as any).message || JSON.stringify(d) : d)
          || (raw && raw.length < 300 ? raw : `${resp.status} ${resp.statusText}`)
        setImportResult(`Error: ${detail}`)
        return
      }

      // Async import path (current MicroBurst flow): server returns a job_id, poll for completion.
      // Real-world MicroBurst dumps can have thousands of files and take hours,
      // so the polling cap is generous. The poll loop also detects stalls
      // (no progress for ~5 min) and surfaces them rather than silently hanging.
      if (data.job_id) {
        const jobId = data.job_id
        setImportResult(`Queued — job ${jobId.slice(0, 8)}…`)
        const deadline = Date.now() + 4 * 60 * 60 * 1000  // hard cap 4 hours
        let lastSeen = -1
        let lastProgressAt = Date.now()
        const startedAt = Date.now()

        while (Date.now() < deadline) {
          await new Promise(r => setTimeout(r, 2000))
          const sResp = await fetch(apiUrl(`/import/status/${jobId}`))
          const { data: sData } = await parseResp(sResp)
          if (!sResp.ok || !sData) continue
          const status = sData.status as string | undefined
          const prog = sData.progress || {}
          if (status === 'finished') {
            setImportResult(formatStats(sData.result || prog))
            return
          }
          if (status === 'failed' || status === 'canceled') {
            setImportResult(`Error: ${sData.error || status}`)
            return
          }
          // running / queued — show live progress and detect stall
          if (prog.records_seen != null) {
            if (prog.records_seen !== lastSeen) {
              lastSeen = prog.records_seen
              lastProgressAt = Date.now()
            }
            const elapsedMin = Math.floor((Date.now() - startedAt) / 60000)
            const stalledMin = Math.floor((Date.now() - lastProgressAt) / 60000)
            const stalledNote = stalledMin >= 5 ? ` ⚠ no progress for ${stalledMin}m` : ''
            setImportResult(
              `Running (${elapsedMin}m) — ${prog.records_seen} rows, ` +
              `${prog.findings_inserted ?? 0} inserted, ` +
              `${prog.files_processed ?? 0} files, ` +
              `${prog.identities_upserted ?? 0} identities${stalledNote}`,
            )
          }
        }
        setImportResult(`Polling cap (4h) reached for job ${jobId.slice(0, 8)}… — ingest may still be running. Check /jobs/${jobId} directly.`)
        return
      }

      // Synchronous path (other cloud imports — Prowler/AzureHound/etc.)
      setImportResult(formatStats(data.stats || {}))
    } catch (err) {
      setImportResult(`Error: ${String(err)}`)
    } finally {
      setImporting(false)
    }
  }

  const isCloudImport = selected ? selected in CLOUD_IMPORT_MAP : false

  return (
    <div className="space-y-4">
      <PageHelp id="scan-launcher" title="How to use Scan Launcher">
        <p>Choose a tool from the category tabs (Network, Web, Recon, etc.) and enter a target. Select a <strong>proxy node</strong> to run through a remote SSH tunnel. Try the <strong>Smart Recon</strong> tab — enter an IP + port and it recommends the best tools for that service with one-click execution. Results auto-ingest as findings.</p>
      </PageHelp>
      <div className="flex items-center gap-2">
        <h2 className="text-lg font-semibold">Launch Scan</h2>
        {activeProfile && (
          <span className={`px-2 py-0.5 text-[10px] font-medium rounded-full border ${
            activeProfile === 'redteam' ? 'bg-red-500/10 text-red-400 border-red-500/30'
              : activeProfile === 'pentest' ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
              : 'bg-purple-500/10 text-purple-400 border-purple-500/30'
          }`}>
            {activeProfile}
          </span>
        )}
      </div>

      {/* Engagement & Scope Selector */}
      <div className="bg-card border border-border rounded-lg p-3">
        {!selectedEngagementId && (
          <div className="bg-amber-500/10 border border-amber-500/30 rounded px-3 py-2 mb-3 text-xs text-amber-400 flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            Select an engagement before launching scans. All scans must belong to an engagement and scope.
          </div>
        )}
        <div className="flex items-center gap-3 flex-wrap">
          {/* Engagement selector (first) */}
          <Briefcase className="h-4 w-4 text-muted-foreground shrink-0" />
          <label className="text-sm font-medium shrink-0">Engagement:</label>
          <select
            value={selectedEngagementId}
            onChange={e => {
              const eid = e.target.value
              const eng = engagements.find(en => en.id === eid)
              setGlobalEngagement(eid || null, eng?.scope_name ?? null)
              setActiveScope('')  // Reset scope when engagement changes
            }}
            className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary max-w-xs"
          >
            <option value="">Select engagement...</option>
            {engagements.map(eng => (
              <option key={eng.id} value={eng.id}>{eng.name} ({eng.status})</option>
            ))}
          </select>

          {/* Scope selector (scoped to engagement) */}
          {selectedEngagementId && (
            <>
              <span className="text-border">|</span>
              <Crosshair className="h-4 w-4 text-muted-foreground shrink-0" />
              <label className="text-sm font-medium shrink-0">Scope:</label>
              <select
                value={activeScope}
                onChange={e => {
                  setActiveScope(e.target.value)
                  if (selected && !e.target.value) {
                    setParams(buildDefaults_manual(selected))
                  }
                }}
                className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary max-w-xs"
              >
                <option value="">All scopes</option>
                {(engagementScopes ?? []).map((s: any) => (
                  <option key={s.name} value={s.name}>{s.name} ({s.target_count} targets)</option>
                ))}
              </select>
              {activeScope && scopeData.data && (
                <>
                  <span className="px-2 py-0.5 bg-primary/10 text-primary text-xs rounded-full border border-primary/30">
                    {activeScope} ({scopeTargets.length} targets)
                  </span>
                  <button onClick={handleClearScope} className="text-muted-foreground hover:text-foreground" title="Clear scope">
                    <X className="h-4 w-4" />
                  </button>
                </>
              )}
            </>
          )}

          {/* Route through node — proxy mode or remote exec for no-proxy tools */}
          {onlineNodes.length > 0 && (
            <>
              <span className="text-border">|</span>
              <Wifi className="h-4 w-4 text-muted-foreground shrink-0" />
              <select
                value={selectedNodeId}
                onChange={e => setSelectedNodeId(e.target.value)}
                className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary max-w-xs"
              >
                {!blockLocal && <option value="">Direct (no proxy)</option>}
                {blockLocal && !selectedNodeId && onlineNodes.length > 0 && <option value="" disabled>Select a tunnel (local scans blocked)</option>}
                {blockLocal && onlineNodes.length === 0 && <option value="" disabled>No tunnels available (local scans blocked)</option>}
                {(selected && NO_PROXY_SCANS.has(selected)
                  ? sshNodes
                  : onlineNodes
                ).map(n => (
                  <option key={n.id} value={n.id}>{n.name} ({getTunnelDisplayType(n)} - :{n.proxy_port})</option>
                ))}
              </select>
              {blockLocal && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30">
                  Local blocked
                </span>
              )}
              {selected && NO_PROXY_SCANS.has(selected) && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-500 border border-amber-500/30">
                  {selectedNodeId ? 'Remote Exec (SSH)' : 'Needs SSH node — no proxy support'}
                </span>
              )}
            </>
          )}
        </div>
      </div>

      {/* Category Tabs */}
      <div className="border-b border-border">
        <div className="flex flex-wrap gap-0">
          {tabs.map(tab => {
            const TabIcon = TAB_ICONS[tab] || Zap
            return (
              <button
                key={tab}
                onClick={() => { setActiveTab(tab); setSelected(null); setImportFile(null); setImportResult(null) }}
                className={cn(
                  'flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-colors',
                  activeTab === tab
                    ? 'border-primary text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border',
                )}
              >
                <TabIcon className="h-3.5 w-3.5" />
                {tab}
              </button>
            )
          })}
        </div>
      </div>

      {/* Tab Content + Config Side Panel */}
      <div className="flex gap-4">
        {/* Tool Grid */}
        <div className="flex-1 min-w-0">
          {activeTab === 'Smart Recon' ? (
            <SmartReconPanel
              reconTarget={reconTarget} setReconTarget={setReconTarget}
              reconPort={reconPort} setReconPort={setReconPort}
              selectedEngagementId={selectedEngagementId}
            />
          ) : activeTab === 'Pipelines' ? (
            <div>
              <p className="text-xs text-muted-foreground mb-3">Multi-tool chains that run multiple tools in sequence</p>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
                {PIPELINE_ITEMS.map(st => {
                  const Icon = ICONS[st.icon] || Zap
                  return (
                    <button
                      key={st.id}
                      onClick={() => handleSelectScan(st.id)}
                      className={cn(
                        'flex flex-col items-center gap-2 p-4 rounded-lg border transition-colors text-center',
                        selected === st.id
                          ? 'border-primary bg-primary/10'
                          : 'border-border hover:border-primary/50 hover:bg-muted/50',
                      )}
                    >
                      <Icon className="h-6 w-6" />
                      <span className="text-xs font-medium">{st.label}</span>
                      <span className="text-[10px] text-muted-foreground">{st.desc}</span>
                      <ScanBadges scanId={st.id} />
                    </button>
                  )
                })}
              </div>
            </div>
          ) : (
            (() => {
              const cat = SCAN_CATEGORIES.find(c => c.name === activeTab)
              if (!cat) return null
              const tools = cat.scans.filter(s => !PIPELINE_IDS.has(s.id))
              return (
                <div className="space-y-4">
                  <p className="text-xs text-muted-foreground mb-3">{cat.desc}</p>
                  {tools.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No individual tools in this category.</p>
                  ) : (
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
                      {tools.map(st => {
                        const Icon = ICONS[st.icon] || Zap
                        return (
                          <button
                            key={st.id}
                            onClick={() => handleSelectScan(st.id)}
                            className={cn(
                              'flex flex-col items-center gap-2 p-4 rounded-lg border transition-colors text-center',
                              selected === st.id
                                ? 'border-primary bg-primary/10'
                                : 'border-border hover:border-primary/50 hover:bg-muted/50',
                            )}
                          >
                            <Icon className="h-6 w-6" />
                            <span className="text-xs font-medium">{st.label}</span>
                            <span className="text-[10px] text-muted-foreground">{st.desc}</span>
                            <ScanBadges scanId={st.id} />
                          </button>
                        )
                      })}
                    </div>
                  )}
                  {/* Cloud Scan Advisor — nested under the import tiles so the
                      operator picks a tool first, then sees the advisor's
                      recommendations + posture for that category. */}
                  {activeTab === 'Cloud' && (
                    <CloudRecommendationsPanel
                      recs={cloudRecs.data?.recommendations ?? []}
                      posture={cloudPosture.data}
                      onRefresh={() => refreshCloud.mutate()}
                      refreshing={refreshCloud.isPending}
                      onDismiss={(id) => updateCloudRec.mutate({ id, status: 'dismissed' })}
                      onAccept={(id) => updateCloudRec.mutate({ id, status: 'accepted' })}
                      onSelectTool={(toolId) => { handleSelectScan(toolId); }}
                    />
                  )}
                </div>
              )
            })()
          )}
        </div>

        {/* Configuration Panel (right side) */}
        {selected && !isCloudImport && SCAN_FIELDS[selected] && (
          <div className="w-80 shrink-0 bg-card border border-border rounded-lg p-4 space-y-3 self-start sticky top-4">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-semibold capitalize">{selected} Config</h3>
              <div className="flex gap-1.5">
                {selected === 'passive-recon' && (
                  <button
                    onClick={handlePlanOnly}
                    disabled={prPlanLoading}
                    className="px-3 py-1.5 bg-muted text-foreground rounded-md text-xs font-medium hover:bg-muted/80 border border-border disabled:opacity-50"
                  >
                    {prPlanLoading ? 'Planning...' : 'Plan Only'}
                  </button>
                )}
                <button
                  onClick={handleLaunch}
                  disabled={launch.isPending || scanThroughNode.isPending}
                  className="px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
                >
                  {(launch.isPending || scanThroughNode.isPending) ? 'Launching...' : 'Launch'}
                </button>
              </div>
            </div>
            {(launch.error || scanThroughNode.error) && (
              <p className="text-xs text-red-500">{String(launch.error || scanThroughNode.error)}</p>
            )}
            {SCAN_FIELDS[selected].map(field => (
              <div key={field.key}>
                <label className="block text-xs text-muted-foreground mb-1">{field.label}</label>
                {field.key === 'secret_type' && selected === 'brutus' ? (
                  <select
                    value={params.secret_type || 'password'}
                    onChange={e => setParams({ ...params, secret_type: e.target.value })}
                    className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
                  >
                    {SECRET_TYPES.map(st => (
                      <option key={st.value} value={st.value}>{st.label}</option>
                    ))}
                  </select>
                ) : field.key === 'protocols' && selected === 'brutus' ? (
                  <div className="space-y-1">
                    <input
                      type="text"
                      placeholder={field.placeholder}
                      value={params.protocols || ''}
                      onChange={e => setParams({ ...params, protocols: e.target.value })}
                      className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
                    />
                    <div className="flex flex-wrap gap-1">
                      {BRUTUS_PROTOCOLS.map(p => (
                        <button
                          key={p}
                          type="button"
                          onClick={() => {
                            const current = (params.protocols || '').split(',').map(s => s.trim()).filter(Boolean)
                            if (current.includes(p)) {
                              setParams({ ...params, protocols: current.filter(x => x !== p).join(',') })
                            } else {
                              setParams({ ...params, protocols: [...current, p].join(',') })
                            }
                          }}
                          className={cn(
                            'px-1.5 py-0.5 text-[10px] rounded border transition-colors',
                            (params.protocols || '').split(',').map(s => s.trim()).includes(p)
                              ? 'bg-primary text-primary-foreground border-primary'
                              : 'bg-muted border-border hover:border-primary/50'
                          )}
                        >
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : field.type === 'textarea' ? (
                  <>
                    <textarea
                      rows={4}
                      placeholder={field.placeholder}
                      value={params[field.key] || ''}
                      onChange={e => setParams({ ...params, [field.key]: e.target.value })}
                      className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary resize-y"
                    />
                    {field.key === 'target_urls' && (() => {
                      const findings = gobusterFindings.data?.findings ?? []
                      const pathCount = findings.length
                      return (
                        <button
                          type="button"
                          disabled={pathCount === 0}
                          onClick={() => {
                            const newUrls = findings
                              .map(f => {
                                const base = (f.url || '').replace(/\/$/, '')
                                const path = f.title || ''
                                if (!base) return ''
                                if (path.startsWith('/')) return base + path
                                if (path) return base + '/' + path
                                return base
                              })
                              .filter(Boolean)
                            const existing = (params[field.key] || '').split('\n').map(s => s.trim()).filter(Boolean)
                            const merged = [...new Set([...existing, ...newUrls])]
                            setParams({ ...params, [field.key]: merged.join('\n') })
                          }}
                          className="mt-1 flex items-center gap-1.5 text-xs text-primary hover:text-primary/80 disabled:text-muted-foreground disabled:cursor-not-allowed"
                        >
                          <Download className="h-3 w-3" />
                          Import from Gobuster ({pathCount} paths)
                        </button>
                      )
                    })()}
                  </>
                ) : field.type === 'toggle' ? (
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={params[field.key] !== undefined ? String(params[field.key]) === 'true' : field.placeholder === 'true'}
                      onChange={e => setParams({ ...params, [field.key]: e.target.checked ? 'true' : 'false' })}
                      className="h-4 w-4 rounded border-border"
                    />
                    <span className="text-sm text-muted-foreground">
                      {params[field.key] !== undefined
                        ? (String(params[field.key]) === 'true' ? 'Enabled' : 'Disabled')
                        : (field.placeholder === 'true' ? 'Enabled (default)' : 'Disabled (default)')}
                    </span>
                  </label>
                ) : field.type === 'select' && field.options ? (
                  <select
                    value={params[field.key] || ''}
                    onChange={e => {
                      const v = e.target.value
                      if (v) { setParams({ ...params, [field.key]: v }) }
                      else { const next = { ...params }; delete next[field.key]; setParams(next) }
                    }}
                    className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
                  >
                    {field.options.map((opt: { value: string; label: string }) => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={field.type}
                    placeholder={field.placeholder}
                    value={params[field.key] || ''}
                    onChange={e => setParams({ ...params, [field.key]: e.target.value })}
                    className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
                  />
                )}
              </div>
            ))}

            {/* Nuclei Tag Presets */}
            {selected === 'nuclei' && (
              <div className="border border-border rounded-md p-2.5 space-y-2">
                <h5 className="text-xs font-medium text-muted-foreground">Tag Presets</h5>
                <div className="flex flex-wrap gap-1.5">
                  {NUCLEI_TAG_PRESETS.map(preset => (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => setParams({ ...params, tags: preset.tags })}
                      className={cn(
                        'px-2 py-1 text-[10px] rounded border transition-colors',
                        params.tags === preset.tags
                          ? 'bg-primary text-primary-foreground border-primary'
                          : 'bg-muted border-border hover:border-primary/50',
                      )}
                      title={preset.desc}
                    >
                      {preset.label}
                    </button>
                  ))}
                  {params.tags && (
                    <button
                      type="button"
                      onClick={() => setParams({ ...params, tags: '' })}
                      className="px-2 py-1 text-[10px] rounded border border-border text-muted-foreground hover:text-foreground"
                    >
                      Clear
                    </button>
                  )}
                </div>
                {params.tags && (
                  <p className="text-[9px] text-muted-foreground font-mono">{params.tags}</p>
                )}
              </div>
            )}

            {/* Autofill from Port Scan (Nuclei and other web scanners) */}
            {(selected === 'nuclei' || selected === 'web' || selected === 'whatweb' || selected === 'zap') && (
              <AutofillFromPortScan
                scanType={selected}
                onAutofill={(updates) => setParams({ ...params, ...updates })}
              />
            )}

            {/* Wordlist Selector (Brutus only) */}
            {selected === 'brutus' && (
              <div className="border border-border rounded-md p-3 space-y-3 bg-muted/30">
                <h4 className="text-xs font-semibold flex items-center gap-1.5">
                  <KeyRound className="h-3.5 w-3.5" />
                  Wordlists
                </h4>
                <div>
                  <label className="block text-xs text-muted-foreground mb-1">Password Wordlist</label>
                  <select
                    value={params.wordlist_path || ''}
                    onChange={e => setParams({ ...params, wordlist_path: e.target.value })}
                    className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
                  >
                    <option value="">None (use inline passwords)</option>
                    {(wordlistsQuery.data?.wordlists ?? []).map(wl => (
                      <option key={wl.id} value={wl.path}>
                        {wl.name} ({wl.line_count?.toLocaleString() ?? '?'} lines)
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-muted-foreground mb-1">Username Wordlist</label>
                  <select
                    value={params.username_wordlist_path || ''}
                    onChange={e => setParams({ ...params, username_wordlist_path: e.target.value })}
                    className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
                  >
                    <option value="">None (use inline usernames)</option>
                    {(wordlistsQuery.data?.wordlists ?? []).map(wl => (
                      <option key={wl.id} value={wl.path}>
                        {wl.name} ({wl.line_count?.toLocaleString() ?? '?'} lines)
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex items-center gap-2">
                  <input ref={fileInputRef} type="file" accept=".txt,.lst,.dict,.wordlist" className="hidden"
                    onChange={async e => {
                      const file = e.target.files?.[0]
                      if (!file) return
                      setUploading(true)
                      try {
                        const formData = new FormData()
                        formData.append('file', file)
                        const resp = await fetch(apiUrl('/wordlists/upload'), { method: 'POST', body: formData })
                        if (!resp.ok) throw new Error('Upload failed')
                        queryClient.invalidateQueries({ queryKey: ['wordlists'] })
                      } catch (err) { console.error('Wordlist upload failed:', err) }
                      finally { setUploading(false); if (fileInputRef.current) fileInputRef.current.value = '' }
                    }}
                  />
                  <button type="button" disabled={uploading} onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-muted border border-border rounded-md hover:border-primary/50 disabled:opacity-50">
                    <Upload className="h-3 w-3" />
                    {uploading ? 'Uploading...' : 'Upload Wordlist'}
                  </button>
                </div>
              </div>
            )}

            {/* Passive Recon Options */}
            {selected === 'passive-recon' && (
              <div className="border border-border rounded-md p-3 space-y-3 bg-muted/30">
                <h4 className="text-xs font-semibold flex items-center gap-1.5">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  Passive Recon Options
                </h4>
                <div className="flex items-center justify-between">
                  <label className="text-xs text-muted-foreground">Cert Serial Chaining</label>
                  <button
                    type="button"
                    onClick={() => setPrCertChain(!prCertChain)}
                    className={cn('w-10 h-5 rounded-full transition-colors relative',
                      prCertChain ? 'bg-primary' : 'bg-muted border border-border')}
                  >
                    <span className={cn('absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform',
                      prCertChain ? 'translate-x-5' : 'translate-x-0.5')} />
                  </button>
                </div>
                {prCertChain && (
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Chain Iterations (1-3)</label>
                    <input type="number" min={1} max={3} value={prCertIterations}
                      onChange={e => setPrCertIterations(Math.min(3, Math.max(1, Number(e.target.value))))}
                      className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary" />
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <label className="text-xs text-muted-foreground">Web Spider (Katana)</label>
                  <button
                    type="button"
                    onClick={() => setPrSpider(!prSpider)}
                    className={cn('w-10 h-5 rounded-full transition-colors relative',
                      prSpider ? 'bg-primary' : 'bg-muted border border-border')}
                  >
                    <span className={cn('absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform',
                      prSpider ? 'translate-x-5' : 'translate-x-0.5')} />
                  </button>
                </div>
                {prSpider && (
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Spider Depth (1-5)</label>
                    <input type="number" min={1} max={5} value={prSpiderDepth}
                      onChange={e => setPrSpiderDepth(Math.min(5, Math.max(1, Number(e.target.value))))}
                      className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary" />
                  </div>
                )}
                {activeScope && (
                  <p className="text-[10px] text-cyan-500">New domains from cert chaining will be added to scope: {activeScope}</p>
                )}
                {prPlanResult && (
                  <div className="bg-background border border-border rounded-md p-2 max-h-48 overflow-y-auto">
                    <p className="text-[10px] font-semibold text-muted-foreground mb-1">Plan Preview</p>
                    <pre className="text-[10px] whitespace-pre-wrap text-foreground">{JSON.stringify(prPlanResult, null, 2)}</pre>
                  </div>
                )}
                <p className="text-[10px] text-muted-foreground">
                  No active tools: no port scans, no DNS brute force, no vuln scanning
                </p>
              </div>
            )}

            {/* Effective Options (profile overrides + defaults) */}
            {/* Launch Preview — shows all params that will be sent */}
            <LaunchPreview scanType={selected} params={params} toolOverrides={toolOverrides} onUpdateParam={(k, v) => setParams(p => ({ ...p, [k]: v }))} />

            {/* Schedule toggle */}
            <ScheduleToggle selected={selected} params={params} onScheduled={() => navigate('/opsec')} />
          </div>
        )}

        {/* Cloud Import Panel */}
        {selected && isCloudImport && (
          <div className="w-80 shrink-0 bg-card border border-border rounded-lg p-4 space-y-3 self-start sticky top-4">
            <h3 className="text-sm font-semibold capitalize">{CLOUD_IMPORT_MAP[selected]} Import</h3>
            <p className="text-xs text-muted-foreground">
              Upload output from <strong>{CLOUD_IMPORT_MAP[selected]}</strong> (run externally with your cloud credentials). Supported formats: JSON, JSONL, CSV{selected === 'microburst-import' ? ', ZIP' : ''}.
            </p>
            <div>
              <input
                ref={cloudFileRef}
                type="file"
                accept=".json,.jsonl,.csv,.js,.txt,.zip"
                className="hidden"
                onChange={e => {
                  setImportFile(e.target.files?.[0] || null)
                  setImportResult(null)
                }}
              />
              <button
                onClick={() => cloudFileRef.current?.click()}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 border-2 border-dashed border-border rounded-lg hover:border-primary/50 hover:bg-muted/50 transition-colors"
              >
                <Upload className="h-5 w-5 text-muted-foreground" />
                <span className="text-sm">{importFile ? importFile.name : 'Choose file...'}</span>
              </button>
            </div>
            {importFile && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span>{(importFile.size / 1024).toFixed(1)} KB</span>
                <button onClick={() => { setImportFile(null); setImportResult(null) }} className="text-red-400 hover:text-red-300">
                  <X className="h-3 w-3" />
                </button>
              </div>
            )}
            {!selectedEngagementId && (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded px-3 py-2 text-xs text-amber-400 flex items-center gap-2">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                Select an engagement above before importing — without one, findings won't be scoped or linked to assets.
              </div>
            )}
            <button
              onClick={handleCloudImport}
              disabled={!importFile || importing || !selectedEngagementId}
              className="w-full px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
              title={!selectedEngagementId ? 'Select an engagement first' : ''}
            >
              {importing ? 'Importing...' : 'Import Findings'}
            </button>
            {importResult && (
              <div className={cn(
                'text-xs p-2 rounded border',
                importResult.startsWith('Error')
                  ? 'bg-red-500/10 border-red-500/30 text-red-400'
                  : 'bg-green-500/10 border-green-500/30 text-green-400',
              )}>
                {importResult}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Cloud Recommendations Panel ───
import type { CloudRecommendation, CloudPosture } from '@/api/cloudSuggestor'

const PRIORITY_BADGE: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-400 text-black',
  low: 'bg-blue-600 text-white',
}

function CloudRecommendationsPanel({
  recs, posture, onRefresh, refreshing, onDismiss, onAccept, onSelectTool,
}: {
  recs: CloudRecommendation[]
  posture?: CloudPosture
  onRefresh: () => void
  refreshing: boolean
  onDismiss: (id: string) => void
  onAccept: (id: string) => void
  onSelectTool: (toolId: string) => void
}) {
  const hasCloudData = posture && (posture.total_cloud_findings > 0 || posture.active_cloud_creds > 0)
  const openRecs = recs.filter(r => r.status === 'open')

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cloud className="h-4 w-4 text-cyan-400" />
          <h3 className="text-sm font-semibold">Cloud Advisor</h3>
          {openRecs.length > 0 && (
            <span className="px-1.5 py-0.5 text-[10px] bg-primary/10 text-primary rounded-full border border-primary/30">
              {openRecs.length} suggestion{openRecs.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <button
          onClick={onRefresh}
          disabled={refreshing}
          className="px-3 py-1 text-xs bg-muted border border-border rounded-md hover:border-primary/50 disabled:opacity-50"
        >
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {!hasCloudData && openRecs.length === 0 && (
        <div className="text-xs text-muted-foreground bg-muted/50 rounded-md p-3">
          <p className="font-medium mb-1">No cloud data imported yet</p>
          <p>Start by importing <strong>Prowler</strong> or <strong>ScoutSuite</strong> output using the tools below. Run them externally against your cloud accounts, then upload the JSON output here.</p>
        </div>
      )}

      {openRecs.length > 0 && (
        <div className="space-y-2 max-h-60 overflow-y-auto">
          {openRecs.map(rec => (
            <div key={rec.id} className="flex items-start gap-2 p-2 bg-muted/30 rounded-md border border-border/50">
              <span className={cn('px-1.5 py-0.5 text-[10px] rounded font-medium shrink-0 mt-0.5', PRIORITY_BADGE[rec.priority] || 'bg-gray-500 text-white')}>
                {rec.priority}
              </span>
              <div className="flex-1 min-w-0 space-y-1">
                <p className="text-xs font-medium">{rec.rule_name}</p>
                <p className="text-[11px] text-muted-foreground">{rec.action}</p>
                {rec.command_hint && (
                  <code className="block text-[10px] text-cyan-400 bg-background rounded px-1.5 py-0.5 font-mono truncate cursor-pointer"
                    onClick={() => navigator.clipboard.writeText(rec.command_hint!)}
                    title="Click to copy"
                  >
                    {rec.command_hint}
                  </code>
                )}
              </div>
              <div className="flex flex-col gap-1 shrink-0">
                {rec.import_as && (
                  <button
                    onClick={() => onSelectTool(rec.import_as!)}
                    className="px-2 py-0.5 text-[10px] bg-primary text-primary-foreground rounded hover:bg-primary/80"
                  >
                    Import
                  </button>
                )}
                <button
                  onClick={() => onDismiss(rec.id)}
                  className="px-2 py-0.5 text-[10px] text-muted-foreground border border-border rounded hover:bg-muted"
                >
                  Dismiss
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {posture && hasCloudData && (
        <div className="flex gap-3 text-[10px] text-muted-foreground pt-1 border-t border-border/50">
          <span>Providers: {posture.providers.join(', ') || 'none'}</span>
          <span>Findings: {posture.total_cloud_findings}</span>
          <span>Creds: {posture.active_cloud_creds}</span>
          {posture.expiring_creds > 0 && (
            <span className="text-red-400">Expiring: {posture.expiring_creds}</span>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Schedule Toggle (I2) ───
import { useCreateScheduledScan, useScheduledScans } from '@/api/opsec'

function ScheduleToggle({ selected, params, onScheduled }: {
  selected: string | null; params: Record<string, string>; onScheduled: () => void
}) {
  const [isSchedule, setIsSchedule] = useState(false)
  const [scheduleAt, setScheduleAt] = useState('')
  const [jitter, setJitter] = useState(0)
  const createScheduled = useCreateScheduledScan()
  const { data: upcomingData } = useScheduledScans('scheduled')
  const upcoming = upcomingData?.scheduled_scans ?? []

  const handleSchedule = () => {
    if (!selected || !scheduleAt) return
    createScheduled.mutate({
      scan_type: selected,
      targets: params as any,
      parameters: params as any,
      scheduled_at: new Date(scheduleAt).toISOString(),
      jitter_seconds: jitter,
    }, { onSuccess: onScheduled })
  }

  return (
    <div className="space-y-2 border border-border rounded-md p-3">
      <label className="flex items-center gap-2 text-xs">
        <input type="checkbox" checked={isSchedule} onChange={e => setIsSchedule(e.target.checked)}
          className="rounded border-border" />
        Schedule for later
      </label>
      {isSchedule && (
        <div className="space-y-2">
          <input type="datetime-local" value={scheduleAt}
            onChange={e => setScheduleAt(e.target.value)}
            className="w-full px-2 py-1 text-xs rounded border border-border bg-background" />
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            Random jitter (seconds):
            <input type="number" min={0} max={300} value={jitter}
              onChange={e => setJitter(Number(e.target.value))}
              className="w-16 px-1 py-0.5 text-xs rounded border border-border bg-background" />
          </label>
          <button onClick={handleSchedule}
            disabled={!scheduleAt || !selected || createScheduled.isPending}
            className="w-full py-1.5 bg-blue-600 text-white rounded-md text-xs font-medium hover:bg-blue-500 disabled:opacity-50">
            {createScheduled.isPending ? 'Scheduling...' : 'Schedule Scan'}
          </button>
        </div>
      )}
      {upcoming.length > 0 && (
        <div className="text-[10px] text-muted-foreground mt-1">
          {upcoming.length} upcoming scheduled scan{upcoming.length !== 1 ? 's' : ''}
        </div>
      )}
    </div>
  )
}

// ─── Launch Preview — shows all effective params before launch ────
function LaunchPreview({ scanType, params, toolOverrides, onUpdateParam }: {
  scanType: string
  params: Record<string, string>
  toolOverrides: Record<string, Record<string, string>>
  onUpdateParam: (key: string, value: string) => void
}) {
  const [expanded, setExpanded] = useState(true)
  const fields = SCAN_FIELDS[scanType] || []
  const overrides = toolOverrides[scanType] || {}
  const TARGET_KEYS = new Set(['target', 'targets', 'target_url', 'target_urls', 'query', 'domain'])

  // Build full list of params that will be sent
  const allParams: Array<{ key: string; value: string; source: 'form' | 'profile' | 'default'; label?: string }> = []

  // From form fields (excluding targets — shown separately above)
  for (const f of fields) {
    if (TARGET_KEYS.has(f.key)) continue
    const val = params[f.key] || overrides[f.key] || f.placeholder || ''
    const source = params[f.key] ? 'form' : overrides[f.key] ? 'profile' : 'default'
    allParams.push({ key: f.key, value: val, source, label: f.label })
  }

  // Profile overrides not in SCAN_FIELDS
  const fieldKeys = new Set(fields.map(f => f.key))
  for (const [k, v] of Object.entries(overrides)) {
    if (!fieldKeys.has(k) && v && !TARGET_KEYS.has(k)) {
      allParams.push({ key: k, value: params[k] || v, source: params[k] ? 'form' : 'profile' })
    }
  }

  if (allParams.length === 0) return null

  return (
    <div className="border border-border rounded-md overflow-hidden bg-muted/10">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-muted/30"
      >
        <Settings className="h-3 w-3 text-muted-foreground" />
        <span className="font-medium">Launch Options</span>
        <span className="text-muted-foreground">({allParams.length})</span>
        <ChevronDown className={cn('h-3 w-3 ml-auto text-muted-foreground transition-transform', expanded && 'rotate-180')} />
      </button>
      {expanded && (
        <div className="px-3 pb-2 space-y-1 border-t border-border pt-2">
          {allParams.map(opt => (
            <div key={opt.key} className="flex items-center gap-2 text-[11px]">
              <span className="text-muted-foreground w-36 shrink-0 truncate" title={opt.label || opt.key}>
                {opt.label || opt.key}
              </span>
              {opt.value === 'true' || opt.value === 'false' || opt.key.includes('crawl') || opt.key.includes('extraction') || opt.key.includes('headless') ? (
                <label className="flex items-center gap-1.5">
                  <input
                    type="checkbox"
                    checked={String(params[opt.key] ?? opt.value) === 'true'}
                    onChange={e => onUpdateParam(opt.key, e.target.checked ? 'true' : 'false')}
                    className="h-3.5 w-3.5 rounded border-border"
                  />
                  <span className={String(params[opt.key] ?? opt.value) === 'true' ? 'text-green-400' : 'text-muted-foreground'}>
                    {String(params[opt.key] ?? opt.value) === 'true' ? 'On' : 'Off'}
                  </span>
                </label>
              ) : (
                <input
                  value={params[opt.key] || opt.value}
                  onChange={e => onUpdateParam(opt.key, e.target.value)}
                  className="flex-1 px-2 py-0.5 bg-background rounded border border-border font-mono text-[10px]"
                />
              )}
              {opt.source !== 'default' && (
                <span className={cn('text-[9px] px-1 rounded shrink-0',
                  opt.source === 'profile' ? 'bg-violet-500/10 text-violet-400' : 'bg-blue-500/10 text-blue-400',
                )}>
                  {opt.source}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}


// ── Smart Recon Panel ──────────────────────────────────────────────
function SmartReconPanel({ reconTarget, setReconTarget, reconPort, setReconPort, selectedEngagementId }: {
  reconTarget: string; setReconTarget: (v: string) => void
  reconPort: string; setReconPort: (v: string) => void
  selectedEngagementId: string | null
}) {
  // Debounce target/port so the lookup doesn't fire on every keystroke
  const [debouncedTarget, setDebouncedTarget] = useState(reconTarget)
  const [debouncedPort, setDebouncedPort] = useState(reconPort)
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedTarget(reconTarget); setDebouncedPort(reconPort) }, 400)
    return () => clearTimeout(t)
  }, [reconTarget, reconPort])

  const { data, isLoading, isFetching } = useTargetedReconLookup(
    debouncedTarget, debouncedPort ? parseInt(debouncedPort) : undefined
  )
  const execute = useTargetedReconExecute()

  // Nodes from independent query — doesn't reset when target/port changes
  const nodesQuery = useNodes()
  const onlineNodes = (nodesQuery.data?.nodes ?? []).filter(
    (n: { status: string }) => n.status === 'online'
  )

  const [selectedNode, setSelectedNode] = useState('')
  const [results, setResults] = useState<Record<string, { ok: boolean; stdout: string; stderr: string; ingest?: unknown }>>({})

  const commands = data?.commands ?? []
  const riskColors: Record<string, string> = {
    safe: 'text-green-400 bg-green-500/10 border-green-500/30',
    active: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    exploit: 'text-red-400 bg-red-500/10 border-red-500/30',
  }

  const handleExecute = (cmd: ReconCommand) => {
    if (!selectedNode) return
    execute.mutate({
      node_id: selectedNode,
      command: cmd.command,
      tool_name: cmd.tool,
      target: reconTarget,
      port: reconPort ? parseInt(reconPort) : undefined,
      engagement_id: selectedEngagementId || undefined,
    }, {
      onSuccess: (r) => setResults(prev => ({ ...prev, [cmd.command]: { ok: r.ok, stdout: r.stdout, stderr: r.stderr, ingest: r.ingest_result || r.structured_result } })),
      onError: (e) => setResults(prev => ({ ...prev, [cmd.command]: { ok: false, stdout: '', stderr: String(e) } })),
    })
  }

  return (
    <div className="space-y-4">
      <div>
        <p className="text-xs text-muted-foreground mb-3">
          Enter a target and port — the knowledge base recommends tools, scripts, and Metasploit modules for that service.
        </p>
        <div className="flex items-center gap-3">
          <div className="flex-1">
            <label className="text-xs text-muted-foreground">Target IP / Hostname</label>
            <input value={reconTarget} onChange={e => setReconTarget(e.target.value)}
              placeholder="192.168.1.100" className="w-full mt-1 bg-muted rounded px-3 py-1.5 text-sm border border-border" />
          </div>
          <div className="w-28">
            <label className="text-xs text-muted-foreground">Port</label>
            <input value={reconPort} onChange={e => setReconPort(e.target.value)}
              placeholder="22" className="w-full mt-1 bg-muted rounded px-3 py-1.5 text-sm border border-border" />
          </div>
          <div className="w-48">
            <label className="text-xs text-muted-foreground">Execute on</label>
            <select value={selectedNode} onChange={e => setSelectedNode(e.target.value)}
              className="w-full mt-1 bg-muted rounded px-3 py-1.5 text-sm border border-border">
              <option value="">Select node...</option>
              {onlineNodes.map((n: { id: string; name: string; node_type: string }) => (
                <option key={n.id} value={n.id}>{n.name} ({n.node_type})</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {isLoading && reconTarget && !data && <p className="text-sm text-muted-foreground">Looking up service...</p>}
      {isFetching && data && <p className="text-[10px] text-muted-foreground animate-pulse">Updating...</p>}

      {data && (
        <div className="space-y-3">
          {data.service_description && (
            <div className="bg-muted/30 border border-border rounded p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-semibold">{data.service || `Port ${data.port}`}</span>
                <span className="text-xs text-muted-foreground">{data.service_description}</span>
              </div>
              {data.common_vulns.length > 0 && (
                <div className="mt-2 space-y-0.5">
                  <span className="text-[10px] text-muted-foreground font-medium">Known vulnerabilities:</span>
                  {data.common_vulns.map((v, i) => (
                    <div key={i} className="text-[10px] text-red-400">{v}</div>
                  ))}
                </div>
              )}
            </div>
          )}

          {commands.length === 0 ? (
            <p className="text-sm text-muted-foreground">No recommendations for this target/port.</p>
          ) : (
            <div className="space-y-2">
              <span className="text-xs font-medium">{commands.length} recommended commands</span>
              {commands.map((cmd, i) => {
                const result = results[cmd.command]
                return (
                  <div key={i} className="border border-border rounded p-2.5 space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium border', riskColors[cmd.risk] || '')}>
                        {cmd.risk}
                      </span>
                      <span className="text-xs font-medium">{cmd.tool}</span>
                      <span className="text-[10px] text-muted-foreground flex-1">{cmd.purpose}</span>
                      {cmd.has_parser && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-primary/10 text-primary border border-primary/30">auto-ingest</span>
                      )}
                      <button
                        onClick={() => handleExecute(cmd)}
                        disabled={!selectedNode || execute.isPending}
                        className="px-2 py-0.5 text-[10px] font-medium rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                      >
                        {execute.isPending ? '...' : 'Run'}
                      </button>
                    </div>
                    <pre className="text-[10px] font-mono bg-muted rounded px-2 py-1 overflow-x-auto select-all">{cmd.command}</pre>
                    {result && (
                      <div className={cn('text-[10px] rounded p-1.5 border', result.ok ? 'bg-green-500/5 border-green-500/20' : 'bg-red-500/5 border-red-500/20')}>
                        {result.stdout && <pre className="whitespace-pre-wrap max-h-32 overflow-y-auto">{result.stdout.slice(0, 2000)}</pre>}
                        {result.stderr && <pre className="text-red-400 whitespace-pre-wrap">{result.stderr.slice(0, 500)}</pre>}
                        {result.ingest ? <span className="text-green-400 font-medium">Results ingested into dashboard</span> : null}
                      </div>
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
