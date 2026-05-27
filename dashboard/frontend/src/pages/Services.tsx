import { useState, useMemo, useEffect } from 'react'
import PageHelp from '@/components/PageHelp'
import { BUILD_VERSION } from '@/lib/constants'
import { cn } from '@/lib/utils'
import { useUIStore, ALPHA_LABELS } from '@/stores/ui'
import { useHealth, useOllamaStatus, useServiceStatus, useServiceControl, useContainerControl, useDiagnostics, ollamaLoadModel, ollamaUnloadModel, ollamaPullModel, useActiveModel, setActiveModel } from '@/api/reports'
import { apiFetch } from '@/api/client'
import { useQueryClient } from '@tanstack/react-query'
import { useSyncStatus } from '@/api/sync'
import type { ProfileStatus } from '@/api/reports'
import { useChatStore } from '@/stores/chat'
import { StatusDot } from '@/components/common/StatusDot'
import {
  ExternalLink, FileText, ScrollText, Container,
  Globe, Workflow, Cpu, Zap, Play, Square, Loader2,
  ChevronDown, ChevronRight, RefreshCw, Database,
  AlertTriangle, CheckCircle2, Search, Download, Power, PowerOff, MessageSquare, X,
  Server, XCircle,
} from 'lucide-react'

const CALLOUT_CARDS: Array<{ label: string; url: string; icon: any; note?: string; alpha?: boolean }> = [
  { label: 'Swagger Docs', url: 'https://localhost:7080/docs', icon: FileText, note: '--profile docs', alpha: true },
  { label: 'Webhooks UI', url: 'https://localhost:8000/webhooks/ui', icon: Globe },
  { label: 'Container Logs', url: 'https://localhost:8018', icon: Container },
  { label: 'Open WebUI', url: 'https://localhost:3000', icon: ScrollText },
  { label: 'N8N Workflows', url: 'https://localhost:5678', icon: Workflow, note: 'separate compose', alpha: true },
]

interface ServiceRow {
  name: string
  healthKey?: string
  description: string
  kongPath?: string
  port: number | null
  links?: { label: string; url: string }[]
  optional?: string
  alpha?: boolean
}

interface ServiceGroup {
  category: string
  services: ServiceRow[]
}

const SERVICE_GROUPS: ServiceGroup[] = [
  {
    category: 'Core',
    services: [
      {
        name: 'RAG API',
        healthKey: 'rag_api',
        description: 'Main API gateway for RAG pipeline',
        kongPath: '/api',
        port: 8000,
        links: [{ label: 'Docs', url: 'https://localhost:8000/docs' }],
      },
      {
        name: 'Scan Recommender',
        healthKey: 'scan_recommender',
        description: 'AI-powered scan recommendations',
        kongPath: '/recommender',
        port: 8013,
        links: [{ label: 'Docs', url: 'https://localhost:8013/docs' }, { label: 'Health', url: 'https://localhost:8013/health' }],
      },
      {
        name: 'Kong Gateway',
        description: 'Unified API gateway for all services',
        port: 7080,
        links: [{ label: 'Docs', url: 'https://localhost:7080/docs' }],
        optional: 'gateway',
        alpha: true,
      },
    ],
  },
  {
    category: 'Scanning',
    services: [
      {
        name: 'Nmap Scanner',
        healthKey: 'nmap_scanner',
        description: 'Network port & service scanning',
        kongPath: '/nmap',
        port: 8012,
        links: [{ label: 'Docs', url: 'https://localhost:8012/docs' }],
      },
      {
        name: 'Web Scanner',
        healthKey: 'web_scanner',
        description: 'Web vulnerability scanning pipeline',
        kongPath: '/webscan',
        port: 8010,
        links: [{ label: 'Docs', url: 'https://localhost:8010/docs' }],
      },
      {
        name: 'Nuclei',
        healthKey: 'nuclei',
        description: 'Template-based vulnerability scanner',
        kongPath: '/nuclei',
        port: 8011,
        links: [{ label: 'Docs', url: 'https://localhost:8011/docs' }, { label: 'Health', url: 'https://localhost:8011/health' }],
      },
      {
        name: 'Playwright Scanner',
        healthKey: 'playwright_scanner',
        description: 'Browser-based dynamic scanning',
        kongPath: '/playwright',
        port: 8014,
        links: [{ label: 'Docs', url: 'https://localhost:8014/docs' }, { label: 'Health', url: 'https://localhost:8014/health' }],
      },
      {
        name: 'ZAP Proxy',
        description: 'OWASP ZAP attack proxy',
        port: 8090,
      },
    ],
  },
  {
    category: 'Recon & OSINT',
    services: [
      {
        name: 'OSINT Runner',
        healthKey: 'osint_runner',
        description: 'Open-source intelligence gathering',
        kongPath: '/osint',
        port: 8024,
        links: [{ label: 'Docs', url: 'https://localhost:8024/docs' }],
      },
      {
        name: 'PD Runner',
        healthKey: 'pd_runner',
        description: 'ProjectDiscovery tool runner',
        kongPath: '/pd',
        port: 8023,
        links: [{ label: 'Docs', url: 'https://localhost:8023/docs' }],
      },
    ],
  },
  {
    category: 'Credentials & Exploits',
    services: [
      {
        name: 'Brutus',
        healthKey: 'brutus_runner',
        description: 'Credential brute-force runner',
        kongPath: '/brutus',
        port: 8026,
        links: [{ label: 'Docs', url: 'https://localhost:8026/docs' }, { label: 'Health', url: 'https://localhost:8026/health' }],
      },
      {
        name: 'Exploit Runner',
        healthKey: 'exploit_runner',
        description: 'Exploit execution engine',
        kongPath: '/exploit',
        port: 8017,
        links: [{ label: 'Docs', url: 'https://localhost:8017/docs' }],
      },
    ],
  },
  {
    category: 'Remote Nodes & C2',
    services: [
      {
        name: 'Node Manager',
        healthKey: 'node_manager',
        description: 'Orchestrates remote nodes, SOCKS allocation, AD attacks',
        port: 8027,
        links: [{ label: 'Docs', url: 'https://localhost:8027/docs' }, { label: 'Health', url: 'https://localhost:8027/health' }],
      },
      {
        name: 'Chisel Server',
        healthKey: 'chisel_server',
        description: 'Reverse tunnel server for remote node SOCKS proxies',
        port: 10443,
        alpha: true,
      },
      {
        name: 'Sliver C2',
        healthKey: 'sliver_server',
        description: 'Implant management and C2 framework',
        port: 31337,
        alpha: true,
      },
      {
        name: 'SSH Tunnel',
        healthKey: 'ssh_tunnel',
        description: 'Outbound SSH tunnel (SOCKS5 / reverse / local forward)',
        port: 1080,
        optional: 'ssh-tunnel',
      },
    ],
  },
  {
    category: 'Database',
    services: [
      {
        name: 'Local PostgreSQL',
        healthKey: 'postgres',
        description: 'Local rag-postgres container — PostgreSQL 16 + pgvector',
        port: 5432,
      },
      {
        name: 'DB Proxy',
        healthKey: 'db_tunnel',
        description: 'Forwards :5432 to remote Postgres (SSH tunnel or direct SSL)',
        port: null,
        optional: 'remote-db',
      },
      {
        name: 'Remote PostgreSQL',
        healthKey: 'remote_postgres',
        description: 'Shared PostgreSQL on remote VPS (multi-user)',
        port: null,
        optional: 'remote-db',
        links: [{ label: 'Sync Dashboard', url: '/sync' }],
      },
    ],
  },
  {
    category: 'AI & Agents',
    services: [
      {
        name: 'Autogen Agents',
        healthKey: 'autogen',
        description: 'Multi-agent orchestration',
        kongPath: '/autogen',
        port: 8015,
        links: [{ label: 'Docs', url: 'https://localhost:8015/docs' }],
      },
      {
        name: 'LLM Query',
        description: 'Direct LLM query interface',
        kongPath: '/llm',
        port: 8002,
      },
      {
        name: 'Ollama',
        healthKey: 'ollama',
        description: 'Local LLM model server',
        port: 11435,
        links: [{ label: 'Tags', url: 'https://localhost:11435/api/tags' }],
      },
      {
        name: 'vLLM',
        description: 'High-throughput LLM inference server',
        port: 8020,
        optional: 'vllm',
        alpha: true,
      },
      {
        name: 'N8N Workflows',
        description: 'Workflow automation platform',
        port: 5678,
        links: [{ label: 'Open', url: 'https://localhost:5678' }],
        optional: 'n8n',
        alpha: true,
      },
      {
        name: 'LibreChat',
        description: 'Open-source AI chat interface',
        port: 3080,
        links: [{ label: 'Open', url: 'https://localhost:3080' }],
        optional: 'librechat',
      },
    ],
  },
  {
    category: 'Documentation',
    services: [
      {
        name: 'Swagger UI',
        description: 'Interactive API documentation',
        kongPath: '/docs',
        port: null,
        links: [{ label: 'Open', url: 'https://localhost:7080/docs' }],
        optional: 'docs',
        alpha: true,
      },
      {
        name: 'OpenAPI Specs',
        description: 'Raw OpenAPI specification files',
        kongPath: '/specs',
        port: null,
        links: [{ label: 'Open', url: 'https://localhost:7080/specs' }],
        optional: 'docs',
      },
    ],
  },
]

const SERVICE_TABS = [
  { id: 'services', label: 'Services' },
  { id: 'database', label: 'Database' },
  { id: 'health', label: 'Health' },
  { id: 'gpu', label: 'GPU' },
  { id: 'optional', label: 'Optional Tools' },
] as const
type ServiceTab = typeof SERVICE_TABS[number]['id']

export default function Services() {
  const [activeTab, setActiveTab] = useState<ServiceTab>('services')
  const { data: health, isLoading } = useHealth()
  const { data: ollama } = useOllamaStatus()
  const alphaEnabled = useUIStore(s => s.alphaTestingEnabled)

  // Database connection testing
  const [dbTesting, setDbTesting] = useState(false)
  const [dbTestResult, setDbTestResult] = useState<{ ok: boolean; message?: string; error?: string; target?: string; mode?: string } | null>(null)
  const [dbMode, setDbMode] = useState<string>('local')

  // Fetch database mode
  useEffect(() => {
    const fetchDbMode = async () => {
      try {
        const res = await apiFetch<{ mode: string }>('/settings/database')
        setDbMode(res.mode || 'local')
      } catch (e) {
        setDbMode('local')
      }
    }
    fetchDbMode()
  }, [])

  const getStatus = (key?: string) => {
    if (!key || !health?.services) return undefined
    return health.services[key]?.status
  }

  const testDatabaseConnection = async () => {
    setDbTesting(true)
    setDbTestResult(null)
    try {
      const res = await apiFetch<{ ok: boolean; message?: string; error?: string; target?: string; mode?: string }>(
        '/settings/database/test',
        { method: 'POST' }
      )
      setDbTestResult(res)
    } catch (e: any) {
      setDbTestResult({ ok: false, error: e.message })
    } finally {
      setDbTesting(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHelp id="services" title="How to use Services">
        <p>Monitor all backend services. <strong>Green</strong> = healthy, <strong>Yellow</strong> = degraded, <strong>Red</strong> = unreachable. Click <strong>Logs</strong> on any service to see recent output. The <strong>Database</strong> section shows local and remote PostgreSQL status — a warning appears if both are running simultaneously. Stop/Start the local postgres from here. <strong>GPU tab</strong> shows VRAM breakdown, power, temperature, and driver info. <strong>Health Diagnostics</strong> scans all containers for errors including webhook delivery failures.</p>
      </PageHelp>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-lg font-semibold">Services</h2>
          <span className="text-[10px] text-muted-foreground font-mono">Build {BUILD_VERSION}</span>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border">
        {SERVICE_TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Services Tab ─────────────────────────────────────── */}
      {activeTab === 'services' && (
        <div className="space-y-6">
          <ServiceProfilesCard />

          {/* Dual-postgres warning - only show if remote DB is enabled */}
          {health?.warnings?.filter((w: { type: string; message: string; severity: string }) => {
            // Don't show dual_postgres warnings when in local-only mode
            if (w.type === 'dual_postgres' && (dbMode === 'local' || !dbMode)) return false
            return true
          }).map((w: { type: string; message: string; severity: string }, i: number) => (
            <div key={i} className="flex items-start gap-3 p-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10">
              <AlertTriangle className="h-5 w-5 text-yellow-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm font-medium text-yellow-400">{w.type === 'dual_postgres' ? 'Dual PostgreSQL Conflict' : 'Warning'}</p>
                <p className="text-xs text-yellow-400/80 mt-0.5">{w.message}</p>
              </div>
            </div>
          ))}

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="p-4 border-b border-border">
              <h3 className="text-sm font-semibold">Service Endpoints</h3>
              {isLoading && (
                <p className="text-xs text-muted-foreground mt-1">Checking health...</p>
              )}
            </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="px-4 py-2 w-8"></th>
                <th className="px-4 py-2">Service</th>
                <th className="px-4 py-2 hidden md:table-cell">Description</th>
                <th className="px-4 py-2">Kong Path</th>
                <th className="px-4 py-2">Direct Port</th>
                <th className="px-4 py-2">Links</th>
              </tr>
            </thead>
            <tbody>
              {SERVICE_GROUPS.map(group => (
                <GroupRows
                  key={group.category}
                  group={group}
                  getStatus={getStatus}
                  alphaEnabled={alphaEnabled}
                  health={health}
                  onTestDatabase={testDatabaseConnection}
                  dbTesting={dbTesting}
                  dbTestResult={dbTestResult}
                  dbMode={dbMode}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>

        </div>
      )}

      {/* ── Database Tab ─────────────────────────────────────── */}
      {activeTab === 'database' && (
        <div className="space-y-6">
          {(dbMode === 'remote' || dbMode === 'remote_direct') ? (
            <RemoteDbSyncCard />
          ) : (
            <LocalDbStatusCard />
          )}
        </div>
      )}

      {/* ── Health Tab ───────────────────────────────────────── */}
      {activeTab === 'health' && (
        <div className="space-y-6">
          <HealthDiagnosticsCard />
        </div>
      )}

      {/* ── GPU Tab ──────────────────────────────────────────── */}
      {activeTab === 'gpu' && (
        <div className="space-y-6">
          <OllamaStatusCard ollama={ollama} />
        </div>
      )}

      {/* ── Optional Tools Tab ───────────────────────────────── */}
      {activeTab === 'optional' && (
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold mb-3">External Tools & UIs</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
              {CALLOUT_CARDS.filter(card => !card.alpha || alphaEnabled).map(card => {
                const Icon = card.icon
                return (
                  <a
                    key={card.label}
                    href={card.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-3 p-3 rounded-lg border border-primary/10 bg-primary/5 hover:bg-primary/10 transition-colors"
                  >
                    <Icon className="h-5 w-5 text-primary shrink-0" />
                    <div className="flex flex-col min-w-0">
                      <span className="text-sm font-medium">{card.label}</span>
                      {card.note && (
                        <span className="text-[10px] text-muted-foreground">{card.note}</span>
                      )}
                    </div>
                    <ExternalLink className="h-3 w-3 text-muted-foreground ml-auto shrink-0" />
                  </a>
                )
              })}
            </div>
          </div>

          {/* Kong Gateway (alpha) */}
          {alphaEnabled && <div className="bg-card border border-border rounded-lg p-4">
            <h3 className="text-sm font-semibold mb-1">
              Kong Gateway
              <span className="ml-2 text-xs bg-muted text-muted-foreground rounded px-1.5 py-0.5 font-normal">
                --profile gateway
              </span>
            </h3>
            <p className="text-xs text-muted-foreground">
              All services are accessible through the unified gateway at{' '}
              <a
                href="https://localhost:7080"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline"
              >
                https://localhost:7080
              </a>{' '}
              using the Kong route paths listed in the Service Endpoints table.
              Start with <code className="text-xs bg-muted px-1 rounded">docker compose --profile gateway up -d</code>.
            </p>
          </div>}
        </div>
      )}
    </div>
  )
}

const PROFILE_LABELS: Record<string, { label: string; description: string }> = {
  scan: { label: 'Scanning', description: 'ZAP, Nuclei, Nmap, Web Scanner, OSINT, PD, Brutus, Playwright' },
  offensive: { label: 'Offensive', description: 'Exploit Runner, Metasploit, Kali, Sliver, Chisel, Node Manager' },
  ai: { label: 'AI & Agents', description: 'Autogen, MCP, LLM Query, Ollama' },
  'ssh-tunnel': { label: 'SSH Tunnel', description: 'Outbound SSH tunnel (SOCKS5 / reverse forward)' },
  optional: { label: 'Optional', description: 'Open WebUI, vLLM, Kong Gateway, Swagger UI, Specs, GRPO Trainer' },
}

function ServiceProfilesCard() {
  const { data, isLoading } = useServiceStatus()
  const control = useServiceControl()
  const containerControl = useContainerControl()
  const [busy, setBusy] = useState<string | null>(null)
  const [busyContainer, setBusyContainer] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  const profiles = data?.profiles ?? {}

  const handleAction = async (profile: string, action: 'start' | 'stop') => {
    setBusy(profile)
    try {
      await control.mutateAsync({ action, profile })
    } finally {
      setBusy(null)
    }
  }

  const handleContainerAction = async (name: string, action: 'start' | 'stop') => {
    setBusyContainer(name)
    try {
      await containerControl.mutateAsync({ action, name })
    } finally {
      setBusyContainer(null)
    }
  }

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Container className="h-4 w-4" />
        Service Profiles
        {isLoading && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
      </h3>
      <div className="space-y-3">
        {Object.entries(PROFILE_LABELS).map(([key, meta]) => {
          const ps: ProfileStatus | undefined = profiles[key]
          const isBusy = busy === key
          const isExpanded = expanded === key
          return (
            <div key={key} className="rounded-md border border-border bg-muted/10 overflow-hidden">
              {/* Profile header */}
              <div className="flex items-center gap-3 px-3 py-2.5">
                <button
                  onClick={() => setExpanded(isExpanded ? null : key)}
                  className="text-muted-foreground hover:text-foreground"
                >
                  {isExpanded
                    ? <ChevronDown className="h-3.5 w-3.5" />
                    : <ChevronRight className="h-3.5 w-3.5" />}
                </button>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold">{meta.label}</span>
                    {ps && (
                      <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${
                        ps.active ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                      }`}>
                        {ps.running}/{ps.total}
                      </span>
                    )}
                  </div>
                  <p className="text-[10px] text-muted-foreground leading-tight">{meta.description}</p>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button
                    onClick={() => handleAction(key, 'start')}
                    disabled={isBusy}
                    className="flex items-center gap-1 px-2 py-1 text-[10px] font-medium rounded bg-green-600/20 text-green-400 hover:bg-green-600/30 disabled:opacity-50"
                  >
                    {isBusy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                    Start All
                  </button>
                  <button
                    onClick={() => handleAction(key, 'stop')}
                    disabled={isBusy}
                    className="flex items-center gap-1 px-2 py-1 text-[10px] font-medium rounded bg-red-600/20 text-red-400 hover:bg-red-600/30 disabled:opacity-50"
                  >
                    {isBusy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Square className="h-3 w-3" />}
                    Stop All
                  </button>
                </div>
              </div>

              {/* Per-container rows */}
              {isExpanded && ps && (
                <div className="border-t border-border/50">
                  {ps.containers.map(c => {
                    const isCBusy = busyContainer === c.name
                    return (
                      <div
                        key={c.name}
                        className="flex items-center gap-3 px-4 py-1.5 border-b border-border/30 last:border-0 hover:bg-muted/20"
                      >
                        <span className={`inline-block h-2 w-2 rounded-full shrink-0 ${
                          c.running ? 'bg-green-500' : c.status === 'not_found' ? 'bg-gray-500' : 'bg-red-500'
                        }`} />
                        <span className="text-xs font-mono flex-1 min-w-0 truncate">{c.name}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${
                          c.running
                            ? 'bg-green-500/20 text-green-400'
                            : c.status === 'not_found'
                            ? 'bg-gray-500/20 text-gray-400'
                            : 'bg-red-500/20 text-red-400'
                        }`}>
                          {c.status}
                        </span>
                        <div className="flex gap-1.5 shrink-0">
                          {!c.running ? (
                            <button
                              onClick={() => handleContainerAction(c.name, 'start')}
                              disabled={isCBusy || c.status === 'not_found'}
                              className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded bg-green-600/20 text-green-400 hover:bg-green-600/30 disabled:opacity-50"
                            >
                              {isCBusy ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Play className="h-2.5 w-2.5" />}
                              Start
                            </button>
                          ) : (
                            <button
                              onClick={() => handleContainerAction(c.name, 'stop')}
                              disabled={isCBusy}
                              className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded bg-red-600/20 text-red-400 hover:bg-red-600/30 disabled:opacity-50"
                            >
                              {isCBusy ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Square className="h-2.5 w-2.5" />}
                              Stop
                            </button>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function OllamaStatusCard({ ollama }: { ollama?: import('@/api/reports').OllamaStatus }) {
  const [loadingModel, setLoadingModel] = useState<string | null>(null)
  const [pullInput, setPullInput] = useState('')
  const [pulling, setPulling] = useState(false)
  const chatModel = useChatStore(s => s.model)
  const setChatModel = useChatStore(s => s.setModel)
  const { data: activeModelData } = useActiveModel()
  const queryClient = useQueryClient()

  // The "global active model" used by agent scans (from DB)
  const globalModel = activeModelData?.model ?? chatModel

  if (!ollama) return null

  const gpu = ollama.gpu
  const vramUsedPct = gpu ? Math.round((gpu.vram_used_mb / gpu.vram_total_mb) * 100) : 0

  const handleSetActive = async (name: string) => {
    setChatModel(name)
    await setActiveModel(name)
    queryClient.invalidateQueries({ queryKey: ['ollama-active-model'] })
  }

  const handleLoad = async (name: string) => {
    setLoadingModel(name)
    await ollamaLoadModel(name)
    setLoadingModel(null)
  }

  const handleUnload = async (name: string) => {
    setLoadingModel(name)
    await ollamaUnloadModel(name)
    setLoadingModel(null)
  }

  const handlePull = async () => {
    if (!pullInput.trim()) return
    setPulling(true)
    await ollamaPullModel(pullInput.trim())
    setPulling(false)
    setPullInput('')
  }

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Cpu className="h-4 w-4" />
        Ollama LLM Server
        {ollama.version && (
          <span className="text-xs font-normal text-muted-foreground">v{ollama.version}</span>
        )}
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* GPU Card */}
        <div className="rounded-md border border-border p-3 bg-muted/10">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="h-4 w-4 text-yellow-500" />
            <span className="text-xs font-semibold">
              {gpu ? gpu.name : 'No GPU detected'}
            </span>
            {gpu?.type === 'apple_silicon' && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 font-medium">
                Unified Memory
              </span>
            )}
          </div>
          {gpu ? (
            <div className="space-y-2">
              <div>
                <div className="flex justify-between text-xs text-muted-foreground mb-1">
                  <span>{gpu.type === 'apple_silicon' ? 'Memory (Model Allocation)' : 'VRAM Usage'}</span>
                  <span>{gpu.vram_used_human} / {gpu.vram_total_human} ({vramUsedPct}%)</span>
                </div>
                <div className="h-2 rounded-full bg-muted overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      vramUsedPct > 90 ? 'bg-red-500' : vramUsedPct > 70 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${vramUsedPct}%` }}
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                <span>Free: {gpu.vram_free_human}</span>
                {gpu.utilization_pct != null && <span>Util: {gpu.utilization_pct}%</span>}
                {gpu.temperature_c != null && (
                  <span className={gpu.temperature_c > 80 ? 'text-red-400' : gpu.temperature_c > 60 ? 'text-yellow-400' : ''}>
                    Temp: {gpu.temperature_c}°C
                  </span>
                )}
                {gpu.power_w != null && <span>Power: {gpu.power_w}W / {gpu.power_cap_w ?? '?'}W</span>}
                {gpu.fan_pct != null && <span>Fan: {gpu.fan_pct}%</span>}
                {gpu.driver_version && <span>Driver: {gpu.driver_version}</span>}
                {gpu.cuda_version && <span>CUDA: {gpu.cuda_version}</span>}
              </div>
              {/* VRAM breakdown for loaded models */}
              {ollama.loaded_models.length > 0 && (
                <div className="border-t border-border pt-2 mt-1 space-y-1">
                  <span className="text-[10px] font-medium text-muted-foreground">VRAM Breakdown</span>
                  {ollama.loaded_models.map(m => {
                    const diskSize = ollama.available_models.find(a => a.name === m.name)?.size || 0
                    const vramSize = m.vram_bytes || m.total_bytes
                    const kvCache = vramSize - diskSize
                    const diskHuman = diskSize > 0 ? `${(diskSize / 1073741824).toFixed(1)}GB` : '?'
                    const vramHuman = m.vram_human || `${(vramSize / 1073741824).toFixed(1)}GB`
                    const kvHuman = kvCache > 0 ? `${(kvCache / 1073741824).toFixed(1)}GB` : '0'
                    return (
                      <div key={m.name} className="text-[10px] flex items-center gap-2">
                        <span className="font-medium w-28 truncate">{m.name}</span>
                        <span className="text-muted-foreground">Weights: {diskHuman}</span>
                        <span className="text-blue-400">KV Cache: {kvHuman}</span>
                        <span className="text-green-400">Total VRAM: {vramHuman}</span>
                        {m.context_length && <span className="text-muted-foreground">ctx: {m.context_length.toLocaleString()}</span>}
                      </div>
                    )
                  })}
                  {(() => {
                    const totalModelVram = ollama.loaded_models.reduce((s, m) => s + (m.vram_bytes || m.total_bytes), 0)
                    const totalGpuUsed = (gpu.vram_used_mb || 0) * 1048576
                    const cudaOverhead = totalGpuUsed - totalModelVram
                    if (cudaOverhead > 100 * 1048576) {
                      return (
                        <div className="text-[10px] text-muted-foreground">
                          CUDA/Driver overhead: ~{(cudaOverhead / 1073741824).toFixed(1)}GB
                        </div>
                      )
                    }
                    return null
                  })()}
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              Models will run on CPU (system RAM)
            </p>
          )}
        </div>

        {/* Active Chat Model */}
        <div className="rounded-md border border-border p-3 bg-muted/10">
          <div className="text-xs font-semibold mb-2 flex items-center gap-1.5">
            <MessageSquare className="h-3.5 w-3.5" />
            Active Chat Model
          </div>
          <select
            value={globalModel}
            onChange={e => handleSetActive(e.target.value)}
            className="w-full text-sm bg-muted rounded-md px-2 py-1.5 border border-border"
          >
            {ollama.available_models.map(m => (
              <option key={m.name} value={m.name}>
                {m.name} — {m.parameter_size} {m.quantization} ({m.size_human})
              </option>
            ))}
          </select>
          <p className="text-[10px] text-muted-foreground mt-1.5">
            Used by AI Chat and Agent Scans. Model loads into memory on first use.
          </p>
        </div>
      </div>

      {/* Loaded Models */}
      <div className="mt-4 rounded-md border border-border p-3 bg-muted/10">
        <div className="text-xs font-semibold mb-2">
          Loaded Models ({ollama.loaded_models.length})
        </div>
        {ollama.loaded_models.length > 0 ? (
          <div className="space-y-2">
            {ollama.loaded_models.map(m => (
              <div key={m.name} className="flex items-center justify-between gap-2">
                <div className="min-w-0 flex items-center gap-2">
                  <span className="text-xs font-medium">{m.name}</span>
                  <span className="text-[10px] text-muted-foreground">
                    {m.parameter_size} {m.quantization}
                  </span>
                  <span
                    className={`shrink-0 inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${
                      m.backend === 'gpu'
                        ? 'bg-green-500/20 text-green-400'
                        : m.backend === 'gpu+cpu'
                        ? 'bg-yellow-500/20 text-yellow-400'
                        : 'bg-blue-500/20 text-blue-400'
                    }`}
                  >
                    {m.backend === 'gpu'
                      ? `GPU ${m.vram_human}`
                      : m.backend === 'gpu+cpu'
                      ? `GPU+CPU ${m.gpu_percent}% VRAM`
                      : `CPU ${m.total_human}`}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  {globalModel !== m.name && (
                    <button
                      onClick={() => handleSetActive(m.name)}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-primary/20 text-primary hover:bg-primary/30"
                      title="Set as active model for chat + agent scans"
                    >
                      Use
                    </button>
                  )}
                  {globalModel === m.name && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/20 text-primary font-medium">
                      Active
                    </span>
                  )}
                  <button
                    onClick={() => handleUnload(m.name)}
                    disabled={loadingModel === m.name}
                    className="p-1 rounded text-muted-foreground hover:text-red-400 hover:bg-red-500/10"
                    title="Unload from memory"
                  >
                    {loadingModel === m.name ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <PowerOff className="h-3 w-3" />
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            No models currently loaded. Select a model below or send a chat message to load one.
          </p>
        )}
      </div>

      {/* Available Models */}
      {ollama.available_models.length > 0 && (
        <div className="mt-3">
          <div className="text-xs font-semibold mb-2">
            Available Models ({ollama.available_models.length})
          </div>
          <div className="space-y-1.5">
            {ollama.available_models.map(m => {
              const isLoaded = ollama.loaded_models.some(lm => lm.name === m.name)
              const isActive = globalModel === m.name
              return (
                <div
                  key={m.name}
                  className={`flex items-center justify-between px-2.5 py-1.5 rounded-md border text-xs ${
                    isActive
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : isLoaded
                      ? 'border-green-500/30 bg-green-500/10 text-green-400'
                      : 'border-border bg-muted/20 text-muted-foreground'
                  }`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {isLoaded && <span className="inline-block h-1.5 w-1.5 rounded-full bg-green-500 shrink-0" />}
                    <span className="font-medium">{m.name}</span>
                    <span className="text-[10px]">{m.parameter_size} {m.quantization}</span>
                    <span className="text-[10px]">{m.size_human}</span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {!isActive && (
                      <button
                        onClick={() => handleSetActive(m.name)}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-muted hover:bg-primary/20 hover:text-primary"
                        title="Set as active model for chat + agent scans"
                      >
                        Use
                      </button>
                    )}
                    {isActive && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/20 text-primary font-medium">
                        Active
                      </span>
                    )}
                    {!isLoaded ? (
                      <button
                        onClick={() => handleLoad(m.name)}
                        disabled={loadingModel === m.name}
                        className="p-1 rounded text-muted-foreground hover:text-green-400 hover:bg-green-500/10"
                        title="Load into memory"
                      >
                        {loadingModel === m.name ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Power className="h-3.5 w-3.5" />
                        )}
                      </button>
                    ) : (
                      <button
                        onClick={() => handleUnload(m.name)}
                        disabled={loadingModel === m.name}
                        className="p-1 rounded text-muted-foreground hover:text-red-400 hover:bg-red-500/10"
                        title="Unload from memory"
                      >
                        {loadingModel === m.name ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <PowerOff className="h-3.5 w-3.5" />
                        )}
                      </button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Pull new model */}
      <div className="mt-3 flex items-center gap-2">
        <input
          value={pullInput}
          onChange={e => setPullInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handlePull()}
          placeholder="Pull model (e.g. llama3.3:70b)"
          className="flex-1 text-xs bg-muted rounded-md px-2.5 py-1.5 border border-border outline-none placeholder:text-muted-foreground"
          disabled={pulling}
        />
        <button
          onClick={handlePull}
          disabled={pulling || !pullInput.trim()}
          className="inline-flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-md bg-primary/20 text-primary hover:bg-primary/30 disabled:opacity-50"
        >
          {pulling ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
          Pull
        </button>
      </div>
    </div>
  )
}

function LocalDbStatusCard() {
  const { data: health } = useHealth()
  const postgresStatus = health?.services?.postgres?.status

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Database className="h-4 w-4" />
        Local Database Status
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Local PostgreSQL Status */}
        <div className="rounded-md border border-border p-3 bg-muted/10">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground">Local PostgreSQL</span>
            <span className={`text-xs px-2 py-1 rounded-full ${
              postgresStatus === 'healthy' ? 'bg-green-500/20 text-green-400' :
              postgresStatus === 'degraded' ? 'bg-yellow-500/20 text-yellow-400' :
              'bg-red-500/20 text-red-400'
            }`}>
              {postgresStatus || 'Unknown'}
            </span>
          </div>
          <div className="text-xs text-muted-foreground">
            Container: rag-postgres:5432
          </div>
        </div>

        {/* Database Mode */}
        <div className="rounded-md border border-border p-3 bg-muted/10">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground">Mode</span>
            <span className="text-xs px-2 py-1 rounded-full bg-green-500/20 text-green-400">
              Local Only
            </span>
          </div>
          <div className="text-xs text-muted-foreground">
            Using local PostgreSQL container
          </div>
        </div>
      </div>

      <div className="mt-3 text-xs text-muted-foreground">
        All data is stored locally in the rag-postgres container.
        Switch to remote mode from{' '}
        <a href="/settings" className="text-primary hover:underline">Settings → Database</a>{' '}
        to enable database synchronization.
      </div>
    </div>
  )
}

function RemoteDbSyncCard() {
  const { data: syncStatus } = useSyncStatus('local')
  const { data: health } = useHealth()

  const rawTunnelStatus = health?.services?.db_tunnel?.status
  const remoteStatus = health?.services?.remote_postgres?.status
  const proxyType = health?.services?.db_tunnel?.proxy_type

  // If remote postgres is accessible, the proxy must be working even if the container check fails
  const tunnelStatus = rawTunnelStatus === 'healthy' ? 'healthy'
    : remoteStatus === 'healthy' ? 'healthy'
    : rawTunnelStatus || 'unknown'
  const isRemoteMode = tunnelStatus === 'healthy'
  const isDirect = proxyType === 'direct_ssl'

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Database className="h-4 w-4" />
        Remote Database & Sync
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Connection Status */}
        <div className="rounded-md border border-border p-3 bg-muted/10">
          <div className="text-xs font-semibold mb-2">Connection</div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Mode</span>
              <span className={`text-xs font-medium px-2 py-0.5 rounded ${
                isDirect ? 'bg-purple-500/20 text-purple-400' :
                isRemoteMode ? 'bg-blue-500/20 text-blue-400' : 'bg-gray-500/20 text-gray-400'
              }`}>
                {isDirect ? 'Remote (Direct SSL)' : isRemoteMode ? 'Remote (SSH Tunnel)' : 'Local'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">{isDirect ? 'Direct Proxy' : 'SSH Tunnel'}</span>
              <span className={`text-xs ${tunnelStatus === 'healthy' ? 'text-green-400' : 'text-gray-500'}`}>
                {tunnelStatus === 'healthy' ? 'Connected' : tunnelStatus === 'stopped' ? 'Stopped' : 'Not running'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Remote Postgres</span>
              <span className={`text-xs ${remoteStatus === 'healthy' ? 'text-green-400' : 'text-gray-500'}`}>
                {remoteStatus === 'healthy' ? 'Accessible' : 'Unavailable'}
              </span>
            </div>
          </div>
        </div>

        {/* Sync Status */}
        <div className="rounded-md border border-border p-3 bg-muted/10">
          <div className="text-xs font-semibold mb-2 flex items-center gap-2">
            <RefreshCw className="h-3 w-3" />
            Sync Status
          </div>
          {syncStatus ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Pending Push</span>
                <span className={`text-xs font-medium ${syncStatus.pending_push > 0 ? 'text-blue-400' : 'text-gray-400'}`}>
                  {syncStatus.pending_push} changes
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Conflicts</span>
                <span className={`text-xs font-medium ${syncStatus.pending_conflicts > 0 ? 'text-yellow-400' : 'text-gray-400'}`}>
                  {syncStatus.pending_conflicts}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Change Log</span>
                <span className="text-xs text-gray-400">{syncStatus.total_log_entries} entries</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Max LSN</span>
                <span className="text-xs text-gray-400 font-mono">{syncStatus.max_lsn || 0}</span>
              </div>
              <a
                href="/sync"
                className="block text-center text-xs text-primary hover:underline mt-1"
              >
                Open Sync Dashboard
              </a>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">Loading sync status...</p>
          )}
        </div>
      </div>

      {!isRemoteMode && (
        <p className="text-xs text-muted-foreground mt-3">
          Switch to remote mode from the{' '}
          <a href="/settings" className="text-primary hover:underline">Settings</a>{' '}
          page under Database tab.
        </p>
      )}
    </div>
  )
}

function HealthDiagnosticsCard() {
  const [enabled, setEnabled] = useState(false)
  const [sinceMinutes, setSinceMinutes] = useState(30)
  const [expandedContainer, setExpandedContainer] = useState<string | null>(null)
  const [cleaningStale, setCleaningStale] = useState(false)
  const [staleResult, setStaleResult] = useState<{ cleaned: number; job_ids: string[] } | null>(null)
  const { data, isLoading, refetch } = useDiagnostics(sinceMinutes, enabled)
  const [sysCheck, setSysCheck] = useState<any>(null)
  const [sysCheckLoading, setSysCheckLoading] = useState(false)
  const [fixLoading, setFixLoading] = useState(false)
  const [fixResult, setFixResult] = useState<any>(null)
  const [dbPool, setDbPool] = useState<any>(null)
  const [dbPoolLoading, setDbPoolLoading] = useState(false)

  const fetchDbPool = async () => {
    setDbPoolLoading(true)
    try {
      const res = await fetch('/api/db-pool')
      setDbPool(await res.json())
    } catch (e) {
      setDbPool({ status: 'error', error: String(e) })
    }
    setDbPoolLoading(false)
  }

  const runSystemCheck = async () => {
    setSysCheckLoading(true)
    setSysCheck(null)
    setFixResult(null)
    try {
      const res = await fetch('/api/system-check')
      setSysCheck(await res.json())
    } catch (e) {
      setSysCheck({ error: String(e) })
    }
    setSysCheckLoading(false)
  }

  const runSystemFix = async () => {
    setFixLoading(true)
    setFixResult(null)
    try {
      const res = await fetch('/api/system-fix', { method: 'POST' })
      const data = await res.json()
      setFixResult(data)
      if (data.check_after_fix) setSysCheck(data.check_after_fix)
    } catch (e) {
      setFixResult({ errors: [String(e)] })
    }
    setFixLoading(false)
  }

  const cleanupStaleScans = async () => {
    setCleaningStale(true)
    setStaleResult(null)
    try {
      const res = await fetch('/api/scans/cleanup-stale?max_age_hours=24', { method: 'POST' })
      const d = await res.json()
      setStaleResult(d)
    } catch { /* ignore */ }
    setCleaningStale(false)
  }

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          Health Diagnostics
        </h3>
        <div className="flex items-center gap-2">
          <a
            href="/diagnostics"
            className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white"
          >
            <Search className="w-3.5 h-3.5" />
            Diagnostic Log Pull
          </a>
          <select
            value={sinceMinutes}
            onChange={e => setSinceMinutes(Number(e.target.value))}
            className="text-[11px] px-2 py-1 rounded bg-muted border border-border"
          >
            <option value={10}>Last 10 min</option>
            <option value={30}>Last 30 min</option>
            <option value={60}>Last 1 hour</option>
            <option value={360}>Last 6 hours</option>
            <option value={1440}>Last 24 hours</option>
          </select>
          <button
            onClick={() => { setEnabled(true); refetch() }}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium bg-muted hover:bg-muted/80 border border-border"
          >
            {isLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            Scan Logs
          </button>
          <button
            onClick={runSystemCheck}
            disabled={sysCheckLoading}
            className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium bg-green-600 hover:bg-green-500 text-white"
          >
            {sysCheckLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />}
            System Check
          </button>
        </div>
      </div>

      {/* System Check Results */}
      {sysCheck && !sysCheck.error && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs">
            <span className={`font-medium ${sysCheck.summary?.overall === 'pass' ? 'text-green-500' : sysCheck.summary?.overall === 'degraded' ? 'text-yellow-500' : 'text-red-500'}`}>
              {sysCheck.summary?.overall === 'pass' ? <CheckCircle2 className="inline h-3.5 w-3.5 mr-1" /> : <AlertTriangle className="inline h-3.5 w-3.5 mr-1" />}
              {sysCheck.summary?.passed}/{sysCheck.summary?.total} checks passed
              {sysCheck.summary?.failed > 0 && <span className="text-red-500 ml-2">{sysCheck.summary.failed} failed</span>}
              {sysCheck.summary?.warnings > 0 && <span className="text-yellow-500 ml-2">{sysCheck.summary.warnings} warnings</span>}
            </span>
            {sysCheck.summary?.overall !== 'pass' && (
              <button
                onClick={runSystemFix}
                disabled={fixLoading}
                className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-amber-600 hover:bg-amber-500 text-white"
              >
                {fixLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                Fix Issues
              </button>
            )}
          </div>
          {fixResult && (
            <div className={`text-[10px] p-2 rounded ${fixResult.errors?.length ? 'bg-red-500/10 border border-red-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
              {fixResult.fixes_applied?.map((f: any, i: number) => (
                <div key={i} className="text-green-400">Applied: {f.detail}</div>
              ))}
              {fixResult.errors?.map((e: string, i: number) => (
                <div key={i} className="text-red-400">Error: {String(e)}</div>
              ))}
            </div>
          )}

          {/* Database */}
          <div className="bg-muted/30 rounded p-2">
            <div className="text-[10px] font-semibold text-muted-foreground mb-1 flex items-center gap-1">
              <Database className="h-3 w-3" /> Database Schema
              <span className={`ml-1 ${sysCheck.database?.status === 'pass' ? 'text-green-500' : 'text-red-500'}`}>
                [{sysCheck.database?.status}]
              </span>
            </div>
            {sysCheck.database?.checks?.map((c: any, i: number) => (
              <div key={i} className="text-[10px] flex items-center gap-1.5 py-0.5">
                <span className={c.status === 'pass' ? 'text-green-500' : c.status === 'fail' ? 'text-red-500' : 'text-yellow-500'}>
                  {c.status === 'pass' ? '✓' : c.status === 'fail' ? '✗' : '⚠'}
                </span>
                <span className="font-mono">{c.check}</span>
                <span className="text-muted-foreground">{c.detail}</span>
              </div>
            ))}
          </div>

          {/* DB Connection Pool */}
          <div className="bg-muted/30 rounded p-2">
            <div className="text-[10px] font-semibold text-muted-foreground mb-1 flex items-center gap-1">
              <Database className="h-3 w-3" /> DB Connection Pool
              {dbPool && (
                <span className={`ml-1 ${dbPool.status === 'healthy' ? 'text-green-500' : dbPool.status === 'degraded' ? 'text-yellow-500' : 'text-red-500'}`}>
                  [{dbPool.status}]
                </span>
              )}
              <button
                onClick={fetchDbPool}
                disabled={dbPoolLoading}
                className="ml-auto flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium bg-muted hover:bg-muted/80 border border-border"
              >
                {dbPoolLoading ? <Loader2 className="w-2.5 h-2.5 animate-spin" /> : <RefreshCw className="w-2.5 h-2.5" />}
                Refresh
              </button>
            </div>
            {!dbPool && !dbPoolLoading && (
              <div className="text-[10px] text-muted-foreground">Click Refresh to load pool stats</div>
            )}
            {dbPool && !dbPool.error && (
              <div className="space-y-1">
                <div className="flex gap-3 text-[10px]">
                  <span>Total: <span className="font-mono font-medium">{dbPool.total_connections}</span></span>
                  {dbPool.pool && (
                    <span className="text-muted-foreground">Pool: {dbPool.pool.minconn}-{dbPool.pool.maxconn}</span>
                  )}
                  <span>Blocked locks: <span className={`font-mono font-medium ${dbPool.blocked_locks > 0 ? 'text-red-500' : 'text-green-500'}`}>{dbPool.blocked_locks}</span></span>
                </div>
                <div className="grid grid-cols-3 gap-x-3 gap-y-0.5 text-[10px]">
                  {Object.entries(dbPool.states || {}).map(([state, count]: [string, any]) => (
                    <div key={state} className="flex items-center gap-1.5">
                      <span className={
                        state === 'idle' ? 'text-green-500' :
                        state === 'active' ? 'text-blue-400' :
                        state === 'idle in transaction' ? 'text-yellow-500' :
                        state?.includes('aborted') ? 'text-red-500' : 'text-muted-foreground'
                      }>
                        {state?.includes('aborted') ? '!' : state === 'active' ? '>' : state === 'idle' ? '-' : '~'}
                      </span>
                      <span className="font-mono">{state || 'null'}</span>
                      <span className="font-medium">{count}</span>
                    </div>
                  ))}
                </div>
                {dbPool.oldest_idle_tx_secs != null && (
                  <div className="text-[10px] text-muted-foreground">
                    Oldest idle-in-transaction: <span className={`font-mono ${dbPool.oldest_idle_tx_secs > 60 ? 'text-yellow-500' : ''}`}>{dbPool.oldest_idle_tx_secs}s</span>
                  </div>
                )}
                {dbPool.slow_queries?.length > 0 && (
                  <div className="mt-1">
                    <div className="text-[9px] font-semibold text-yellow-500 mb-0.5">Slow Queries ({'>'}5s)</div>
                    {dbPool.slow_queries.map((q: any, i: number) => (
                      <div key={i} className="text-[9px] font-mono text-muted-foreground truncate" title={q.query}>
                        PID {q.pid} ({q.state}, {q.duration_secs}s): {q.query}
                      </div>
                    ))}
                  </div>
                )}
                {dbPool.warnings?.length > 0 && (
                  <div className="mt-1 space-y-0.5">
                    {dbPool.warnings.map((w: string, i: number) => (
                      <div key={i} className="text-[9px] text-yellow-500">Warning: {w}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {dbPool?.error && (
              <div className="text-[10px] text-red-500">{dbPool.error}</div>
            )}
          </div>

          {/* Connectivity */}
          <div className="bg-muted/30 rounded p-2">
            <div className="text-[10px] font-semibold text-muted-foreground mb-1 flex items-center gap-1">
              <Globe className="h-3 w-3" /> Service Connectivity
              <span className={`ml-1 ${sysCheck.connectivity?.status === 'pass' ? 'text-green-500' : 'text-red-500'}`}>
                [{sysCheck.connectivity?.status}]
              </span>
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
              {Object.entries(sysCheck.connectivity?.services || {}).map(([name, info]: [string, any]) => (
                <div key={name} className="text-[10px] flex items-center gap-1.5">
                  <span className={info.status === 'pass' ? 'text-green-500' : info.status === 'fail' ? 'text-red-500' : 'text-yellow-500'}>
                    {info.status === 'pass' ? '✓' : info.status === 'fail' ? '✗' : '⚠'}
                  </span>
                  <span className="font-mono">{name}</span>
                  {info.error && <span className="text-red-400 truncate max-w-[150px]" title={info.error}>{String(info.error).slice(0, 30)}</span>}
                </div>
              ))}
            </div>
          </div>

          {/* End-to-End */}
          <div className="bg-muted/30 rounded p-2">
            <div className="text-[10px] font-semibold text-muted-foreground mb-1 flex items-center gap-1">
              <Workflow className="h-3 w-3" /> End-to-End Tests
              <span className={`ml-1 ${sysCheck.end_to_end?.status === 'pass' ? 'text-green-500' : 'text-red-500'}`}>
                [{sysCheck.end_to_end?.status}]
              </span>
            </div>
            {sysCheck.end_to_end?.tests?.map((t: any, i: number) => (
              <div key={i} className="text-[10px] flex items-center gap-1.5 py-0.5">
                <span className={t.status === 'pass' ? 'text-green-500' : 'text-red-500'}>
                  {t.status === 'pass' ? '✓' : '✗'}
                </span>
                <span className="font-mono">{t.test}</span>
                <span className="text-muted-foreground">{t.detail || t.error}</span>
              </div>
            ))}
          </div>

          {/* Advisories */}
          {sysCheck.advisories?.length > 0 && (
            <div className="bg-muted/30 rounded p-2">
              <div className="text-[10px] font-semibold text-muted-foreground mb-1 flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" /> Platform Advisories
                {sysCheck.summary?.advisories > 0 && (
                  <span className="text-yellow-500 ml-1">{sysCheck.summary.advisories} warnings</span>
                )}
              </div>
              <div className="space-y-2">
                {(sysCheck.advisories as any[]).map((a: any, i: number) => (
                  <details key={i} className={`text-[10px] rounded border ${
                    a.level === 'warning' ? 'border-yellow-500/30 bg-yellow-500/5' : 'border-border bg-card/50'
                  }`}>
                    <summary className="px-2 py-1.5 cursor-pointer flex items-center gap-1.5">
                      <span className={a.level === 'warning' ? 'text-yellow-500' : 'text-blue-400'}>
                        {a.level === 'warning' ? '⚠' : 'ℹ'}
                      </span>
                      <span className="font-medium">{a.title}</span>
                    </summary>
                    <div className="px-2 pb-2 space-y-1">
                      <p className="text-muted-foreground">{a.detail}</p>
                      {a.fix && (
                        <pre className="bg-background rounded p-2 border border-border text-[9px] font-mono whitespace-pre-wrap overflow-x-auto max-h-48 overflow-y-auto">{a.fix}</pre>
                      )}
                    </div>
                  </details>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      {sysCheck?.error && (
        <p className="text-xs text-red-500">{String(sysCheck.error)}</p>
      )}

      {/* LLM Performance Metrics */}
      <LlmMetricsPanel />

      {!enabled && !data && !sysCheck && (
        <p className="text-xs text-muted-foreground">
          Click "Scan Logs" to check container logs, or "System Check" to verify DB schema, service connectivity, and end-to-end functionality.
        </p>
      )}

      {data && (
        <>
          {/* Summary bar */}
          <div className="flex items-center gap-4 mb-3 text-xs">
            <span className="text-muted-foreground">{data.scanned} containers scanned</span>
            {data.total_errors === 0 ? (
              <span className="flex items-center gap-1 text-green-400">
                <CheckCircle2 className="w-3.5 h-3.5" />
                No errors found
              </span>
            ) : (
              <span className="flex items-center gap-1 text-red-400">
                <AlertTriangle className="w-3.5 h-3.5" />
                {data.total_errors} error{data.total_errors !== 1 ? 's' : ''} in {data.containers_with_errors} container{data.containers_with_errors !== 1 ? 's' : ''}
              </span>
            )}
          </div>

          {/* Container error list */}
          {data.containers.length > 0 && (
            <div className="space-y-1">
              {data.containers.map(c => (
                <div key={c.container} className="border border-border rounded">
                  <button
                    onClick={() => setExpandedContainer(expandedContainer === c.container ? null : c.container)}
                    className="w-full flex items-center justify-between px-3 py-2 text-xs hover:bg-muted/50"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${c.error_count > 0 ? 'bg-red-500' : 'bg-green-500'}`} />
                      <span className="font-mono font-medium">{c.container}</span>
                      <span className="text-muted-foreground">({c.status})</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`font-medium ${c.error_count > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>
                        {c.error_count > 0 ? `${c.error_count} error${c.error_count !== 1 ? 's' : ''}` : ''}
                      </span>
                      {expandedContainer === c.container ? (
                        <ChevronDown className="w-3 h-3 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="w-3 h-3 text-muted-foreground" />
                      )}
                    </div>
                  </button>
                  {expandedContainer === c.container && c.errors.length > 0 && (
                    <div className="border-t border-border bg-muted/20 max-h-60 overflow-y-auto">
                      {c.errors.map((err, i) => (
                        <div key={i} className="px-3 py-1.5 border-b border-border/30 text-[11px] font-mono">
                          {err.timestamp && (
                            <span className="text-muted-foreground mr-2">{err.timestamp.slice(11, 19)}</span>
                          )}
                          <span className="text-red-300 break-all">{err.message}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Stale scan cleanup */}
          <div className="mt-3 pt-3 border-t border-border/50 flex items-center gap-3">
            <button
              onClick={cleanupStaleScans}
              disabled={cleaningStale}
              className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
            >
              {cleaningStale ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
              Clean Up Stale Scans
            </button>
            <span className="text-[11px] text-muted-foreground">
              Marks running/queued scans older than 24h as lost
            </span>
            {staleResult && (
              <span className={`text-[11px] ${staleResult.cleaned > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
                {staleResult.cleaned > 0
                  ? `Cleaned ${staleResult.cleaned} stale scan${staleResult.cleaned !== 1 ? 's' : ''}`
                  : 'No stale scans found'}
              </span>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function GroupRows({
  group,
  getStatus,
  alphaEnabled,
  health,
  onTestDatabase,
  dbTesting,
  dbTestResult,
  dbMode,
}: {
  group: ServiceGroup
  getStatus: (key?: string) => string | undefined
  alphaEnabled: boolean
  health: any
  onTestDatabase?: () => void
  dbTesting?: boolean
  dbTestResult?: { ok: boolean; message?: string; error?: string; target?: string; mode?: string } | null
  dbMode?: string
}) {
  return (
    <>
      <tr className="bg-muted/30">
        <td colSpan={6} className="px-4 py-1.5 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          {group.category}
        </td>
      </tr>
      {group.services.filter(svc => {
        // Filter out alpha services if not enabled
        if (svc.alpha && !alphaEnabled) return false
        // Filter out remote database services when in local mode
        if ((dbMode || 'local') === 'local' && svc.optional === 'remote-db') return false
        return true
      }).map(svc => {
        const status = getStatus(svc.healthKey)
        const healthInfo = health?.services?.[svc.healthKey || '']
        const isUnhealthy = healthInfo && healthInfo.status !== 'healthy'
        const isOptional = healthInfo?.optional
        return (
          <ServiceRowWithLogs
            key={svc.name}
            svc={svc}
            status={status}
            healthInfo={healthInfo}
            isUnhealthy={isUnhealthy}
            isOptional={isOptional}
            allHealth={health?.services}
            onTestDatabase={svc.healthKey === 'postgres' ? onTestDatabase : undefined}
            dbTesting={svc.healthKey === 'postgres' ? dbTesting : undefined}
            dbTestResult={svc.healthKey === 'postgres' ? dbTestResult : undefined}
            dbMode={dbMode}
          />
        )
      })}
    </>
  )
}

function ContainerControl({ name, isRunning }: { name: string; isRunning: boolean }) {
  const [loading, setLoading] = useState(false)
  const [actionState, setActionState] = useState<'idle' | 'stopping' | 'starting' | 'done'>('idle')
  const queryClient = useQueryClient()

  const handleAction = async (action: 'start' | 'stop') => {
    if (action === 'stop') {
      const isDbContainer = name === 'rag-postgres'
      const warningMessage = isDbContainer
        ? `Stop container "${name}"? This will take the database offline.`
        : `Stop container "${name}"? This will disconnect remote database access.`
      if (!confirm(warningMessage)) return
    }
    setLoading(true)
    setActionState(action === 'stop' ? 'stopping' : 'starting')
    try {
      const resp = await fetch(`/api/services/${action}/container/${name}`, { method: 'POST' })
      const data = await resp.json()
      setActionState('done')
      // Bust server cache and refetch
      for (const delay of [2000, 5000, 10000]) {
        setTimeout(async () => {
          await fetch('/api/health?bust=true')
          queryClient.invalidateQueries({ queryKey: ['health'] })
        }, delay)
      }
    } catch { /* ignore */ }
    setLoading(false)
    setTimeout(() => setActionState('idle'), 5000)
  }

  const showRunning = actionState === 'stopping' ? true : actionState === 'starting' ? false : isRunning

  return (
    <div className="flex items-center gap-1">
      {showRunning ? (
        <button onClick={() => handleAction('stop')} disabled={loading}
          className="text-[10px] px-1.5 py-0.5 rounded border border-red-500/30 text-red-400 hover:bg-red-500/10 disabled:opacity-50 flex items-center gap-0.5">
          {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Power className="h-3 w-3" />}
          {actionState === 'stopping' ? 'Stopping...' : 'Stop'}
        </button>
      ) : (
        <button onClick={() => handleAction('start')} disabled={loading}
          className="text-[10px] px-1.5 py-0.5 rounded border border-green-500/30 text-green-400 hover:bg-green-500/10 disabled:opacity-50 flex items-center gap-0.5">
          {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Power className="h-3 w-3" />}
          {actionState === 'starting' ? 'Starting...' : 'Start'}
        </button>
      )}
      {actionState === 'done' && (
        <span className="text-[10px] text-green-400">Done</span>
      )}
    </div>
  )
}

function ServiceRowWithLogs({ svc, status, healthInfo, isUnhealthy, isOptional, allHealth, onTestDatabase, dbTesting, dbTestResult, dbMode }: {
  svc: ServiceRow; status: string | undefined; healthInfo: any; isUnhealthy: boolean; isOptional: boolean; allHealth?: Record<string, any>
  onTestDatabase?: () => void; dbTesting?: boolean; dbTestResult?: { ok: boolean; message?: string; error?: string; target?: string; mode?: string } | null
  dbMode?: string
}) {
  const [showLogs, setShowLogs] = useState(false)
  const [logs, setLogs] = useState<string[] | null>(null)
  const [logsLoading, setLogsLoading] = useState(false)

  // Map service name to container name for log fetching
  const containerName = svc.name.toLowerCase().replace(/\s+/g, '-').replace('rag-', '').replace('runner', '-runner')
  const containerMap: Record<string, string> = {
    'RAG API': 'rag-api', 'Nmap Scanner': 'nmap_scanner', 'Web Scanner': 'web-scanner',
    'Nuclei': 'nuclei-runner', 'PD Runner': 'pd-runner', 'OSINT Runner': 'osint-runner',
    'Brutus': 'brutus-runner', 'Playwright': 'playwright-scanner', 'Autogen Agents': 'autogen-agents',
    'Node Manager': 'node-manager', 'Scan Recommender': 'scan-recommender', 'Exploit Runner': 'exploit-runner',
    'Container Logs': 'container-logs', 'Ollama': 'ollama', 'Dashboard BFF': 'pentest-dashboard',
    'PostgreSQL': 'rag-postgres', 'DB Proxy': 'rag-db-tunnel',
    'Kali Listener': 'kali-listener',
  }
  const cName = containerMap[svc.name] || containerName

  const fetchLogs = async () => {
    setLogsLoading(true)
    try {
      const resp = await fetch(`/api/diagnostics/container-logs/${cName}?tail=50&since_minutes=60`)
      const data = await resp.json()
      setLogs(data.logs || data.lines || [data.error || 'No logs available'])
    } catch (e) {
      setLogs([`Error fetching logs: ${e}`])
    }
    setLogsLoading(false)
  }

  return (
    <>
      <tr className={`border-b border-border/50 hover:bg-muted/20 ${isUnhealthy && !isOptional ? 'bg-red-500/5' : ''}`}>
        <td className="px-4 py-2">
          {svc.healthKey ? (
            status ? <StatusDot status={status} /> : <span className="inline-block h-2 w-2 rounded-full bg-gray-400" />
          ) : (
            <span className="inline-block h-2 w-2 rounded-full bg-gray-600" />
          )}
        </td>
        <td className="px-4 py-2 font-medium">
          {svc.name}
          {svc.optional && (
            <span className="ml-2 text-xs bg-muted text-muted-foreground rounded px-1.5 py-0.5 font-normal">
              --profile {svc.optional}
            </span>
          )}
          {healthInfo?.version && (
            <span className="ml-2 text-[9px] font-mono text-purple-400 bg-purple-500/10 rounded px-1 py-0.5">
              v{healthInfo.version}
            </span>
          )}
          {isOptional && (
            <span className="ml-1 text-[9px] text-muted-foreground">(optional)</span>
          )}
          {isUnhealthy && healthInfo?.error && (
            <div className="text-[10px] text-red-400 mt-0.5 font-normal truncate max-w-xs" title={healthInfo.error}>
              {healthInfo.error.slice(0, 80)}
            </div>
          )}
          {svc.healthKey === 'postgres' && healthInfo && (
            <div className="text-[10px] mt-0.5 font-normal flex items-center gap-2 text-muted-foreground">
              {healthInfo.uptime && <span>{healthInfo.uptime}</span>}
              {healthInfo.warning && <span className="text-yellow-400 font-medium">{healthInfo.warning}</span>}
            </div>
          )}
          {svc.healthKey === 'scan_recommender' && (() => {
            const ragHealth = allHealth?.['rag_api']
            const edb = ragHealth?.exploitdb
            return edb ? (
              <div className="text-[10px] mt-0.5 font-normal flex items-center gap-2">
                {edb.loaded ? (
                  <span className="text-green-400">SearchSploit: {edb.count.toLocaleString()} exploits loaded</span>
                ) : (
                  <span className="text-yellow-400">SearchSploit: not loaded (download exploitdb CSV)</span>
                )}
              </div>
            ) : null
          })()}
          {svc.healthKey === 'db_tunnel' && healthInfo?.proxy_type && (
            <div className="text-[10px] mt-0.5 font-normal">
              <span className={cn('px-1.5 py-0.5 rounded',
                healthInfo.proxy_type === 'direct_ssl'
                  ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                  : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
              )}>
                {healthInfo.proxy_type === 'direct_ssl' ? 'Direct SSL' : 'SSH Tunnel'}
              </span>
              {healthInfo.note && <span className="text-muted-foreground ml-2">{healthInfo.note}</span>}
            </div>
          )}
          {svc.healthKey === 'remote_postgres' && healthInfo?.warning && (
            <div className="text-[10px] mt-0.5 font-normal text-yellow-400 font-medium">
              {healthInfo.warning}
            </div>
          )}
          {healthInfo?.tunnels && (
            <div className="text-[10px] mt-0.5 font-normal flex gap-2">
              {healthInfo.tunnels.online > 0 && <span className="text-green-400">{healthInfo.tunnels.online} online</span>}
              {healthInfo.tunnels.error > 0 && <span className="text-red-400">{healthInfo.tunnels.error} error</span>}
              {healthInfo.tunnels.offline > 0 && <span className="text-yellow-400">{healthInfo.tunnels.offline} offline</span>}
            </div>
          )}
          {healthInfo?.tunnel_errors?.length > 0 && (
            <div className="text-[10px] text-red-400/80 mt-0.5 font-normal space-y-0.5">
              {healthInfo.tunnel_errors.map((e: { name: string; host: string; status: string }, i: number) => (
                <div key={i}>{e.name} ({e.host}) — {e.status}</div>
              ))}
            </div>
          )}
        </td>
        <td className="px-4 py-2 text-muted-foreground hidden md:table-cell">{svc.description}</td>
            <td className="px-4 py-2">
              {svc.kongPath ? (
                <a
                  href={`https://localhost:7080${svc.kongPath}/health`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline font-mono text-xs"
                >
                  {svc.kongPath}
                </a>
              ) : (
                <span className="text-muted-foreground text-xs">—</span>
              )}
            </td>
            <td className="px-4 py-2">
              {svc.port ? (
                <a
                  href={`https://localhost:${svc.port}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline font-mono text-xs"
                >
                  :{svc.port}
                </a>
              ) : (
                <span className="text-muted-foreground text-xs">—</span>
              )}
            </td>
            <td className="px-4 py-2">
              <div className="flex gap-2">
                {svc.links?.map(link => (
                  <a key={link.label} href={link.url} target="_blank" rel="noopener noreferrer"
                    className="text-xs text-primary hover:underline">{link.label}</a>
                ))}
                <button
                  onClick={() => { setShowLogs(!showLogs); if (!logs) fetchLogs() }}
                  disabled={logsLoading}
                  className="text-[10px] px-1.5 py-0.5 rounded border border-border text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50"
                >
                  {logsLoading ? <Loader2 className="h-3 w-3 animate-spin inline" /> : <ScrollText className="h-3 w-3 inline" />}
                  {' '}Logs
                </button>
                {svc.healthKey === 'postgres' && (
                  <ContainerControl name="rag-postgres" isRunning={status === 'healthy' || status === 'degraded'} />
                )}
                {svc.healthKey === 'db_tunnel' && ((dbMode || 'local') === 'remote' || (dbMode || 'local') === 'remote_direct') && (
                  <div className="flex gap-1">
                    <ContainerControl name="rag-db-tunnel" isRunning={status === 'healthy' || status === 'degraded'} />
                    <ContainerControl name="ssh-tunnel" isRunning={status === 'healthy' || status === 'degraded'} />
                  </div>
                )}
                {svc.healthKey === 'postgres' && onTestDatabase && (
                  <button
                    onClick={onTestDatabase}
                    disabled={dbTesting}
                    className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-muted hover:bg-muted/80 border border-border"
                    title="Test Database Connection"
                  >
                    {dbTesting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Server className="w-3 h-3" />}
                    Test
                  </button>
                )}
              </div>
            </td>
          </tr>
          {showLogs && logs && (
            <tr>
              <td colSpan={6} className="px-4 py-2 bg-muted/20">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-muted-foreground font-mono">{cName} — last 50 lines</span>
                  <button onClick={fetchLogs} disabled={logsLoading}
                    className="text-[10px] text-primary hover:underline flex items-center gap-1">
                    <RefreshCw className={`h-3 w-3 ${logsLoading ? 'animate-spin' : ''}`} /> Refresh
                  </button>
                </div>
                <pre className="text-[10px] font-mono bg-black/40 rounded p-2 max-h-48 overflow-y-auto whitespace-pre-wrap text-muted-foreground">
                  {Array.isArray(logs) ? logs.join('\n') : String(logs)}
                </pre>
              </td>
            </tr>
          )}
          {svc.healthKey === 'postgres' && dbTestResult && (
            <tr>
              <td colSpan={6} className="px-4 py-2 bg-muted/10">
                <div className={cn('flex flex-col gap-1 text-xs', dbTestResult.ok ? 'text-green-400' : 'text-red-400')}>
                  <div className="flex items-center gap-1.5">
                    {dbTestResult.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                    <span className="font-medium">Database Connection Test:</span>
                    <span>{dbTestResult.ok ? dbTestResult.message : dbTestResult.error}</span>
                  </div>
                  {dbTestResult.target && (
                    <div className="ml-5 text-[10px] uppercase tracking-wider opacity-70">
                      target: <span className="font-mono normal-case opacity-100">{dbTestResult.target}</span>
                      {dbTestResult.mode && <span className="ml-2 opacity-70">[mode: {dbTestResult.mode}]</span>}
                    </div>
                  )}
                </div>
              </td>
            </tr>
          )}
        </>
  )
}


function LlmMetricsPanel() {
  const [show, setShow] = useState(false)
  const [summary, setSummary] = useState<any>(null)
  const [recent, setRecent] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [callerFilter, setCallerFilter] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const [sumRes, recRes] = await Promise.all([
        fetch('/api/llm/summary?days=7').then(r => r.json()),
        fetch(`/api/llm/metrics?limit=30${callerFilter ? '&caller=' + callerFilter : ''}`).then(r => r.json()),
      ])
      setSummary(sumRes)
      setRecent(recRes?.requests || [])
    } catch {}
    setLoading(false)
  }

  useEffect(() => { if (show) load() }, [show, callerFilter])

  if (!show) {
    return (
      <button onClick={() => setShow(true)}
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30">
        <Cpu className="h-3.5 w-3.5" /> LLM Performance Metrics
      </button>
    )
  }

  const callers = [...new Set((summary?.callers || []).map((c: any) => c.caller))]

  return (
    <div className="border border-border rounded-md p-3 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold flex items-center gap-1.5"><Cpu className="h-3.5 w-3.5" /> LLM Performance Metrics (7 days)</h4>
        <div className="flex items-center gap-2">
          <button onClick={load} disabled={loading} className="text-[10px] text-primary hover:underline">
            {loading ? 'Loading...' : 'Refresh'}
          </button>
          <button onClick={() => setShow(false)} className="text-muted-foreground hover:text-foreground">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Summary by caller */}
      {summary?.callers?.length > 0 && (
        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-muted/30 border-b border-border text-left">
                <th className="px-2 py-1.5 font-medium">Caller</th>
                <th className="px-2 py-1.5 font-medium">Model</th>
                <th className="px-2 py-1.5 font-medium text-right">Calls</th>
                <th className="px-2 py-1.5 font-medium text-right">Errors</th>
                <th className="px-2 py-1.5 font-medium text-right">Avg Latency</th>
                <th className="px-2 py-1.5 font-medium text-right">Avg tok/s</th>
                <th className="px-2 py-1.5 font-medium text-right">Total Tokens</th>
              </tr>
            </thead>
            <tbody>
              {summary.callers.map((c: any, i: number) => (
                <tr key={i} className="border-t border-border/30 hover:bg-muted/20 cursor-pointer"
                    onClick={() => setCallerFilter(callerFilter === c.caller ? '' : c.caller)}>
                  <td className={`px-2 py-1 font-mono ${callerFilter === c.caller ? 'text-primary font-bold' : ''}`}>{c.caller}</td>
                  <td className="px-2 py-1 font-mono text-muted-foreground">{c.model_name}</td>
                  <td className="px-2 py-1 text-right">{c.total_calls}</td>
                  <td className={`px-2 py-1 text-right ${c.error_count > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>{c.error_count}</td>
                  <td className="px-2 py-1 text-right font-mono">{c.avg_latency_ms ? `${(c.avg_latency_ms / 1000).toFixed(1)}s` : '—'}</td>
                  <td className="px-2 py-1 text-right font-mono text-primary">{c.avg_tok_per_sec ?? '—'}</td>
                  <td className="px-2 py-1 text-right font-mono">{c.total_tokens_used?.toLocaleString() ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Recent requests */}
      {recent.length > 0 && (
        <details open={!!callerFilter}>
          <summary className="text-[10px] text-muted-foreground cursor-pointer hover:text-foreground">
            Recent LLM calls ({recent.length}){callerFilter && ` — filtered: ${callerFilter}`}
          </summary>
          <div className="mt-1.5 max-h-48 overflow-auto">
            <table className="w-full text-[10px]">
              <thead>
                <tr className="bg-muted/20 text-left">
                  <th className="px-1.5 py-1">Time</th>
                  <th className="px-1.5 py-1">Caller</th>
                  <th className="px-1.5 py-1">Model</th>
                  <th className="px-1.5 py-1 text-right">Tokens</th>
                  <th className="px-1.5 py-1 text-right">tok/s</th>
                  <th className="px-1.5 py-1 text-right">Latency</th>
                  <th className="px-1.5 py-1">Status</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((r: any, i: number) => (
                  <tr key={i} className={`border-t border-border/20 ${r.is_error ? 'bg-red-500/5' : ''}`}>
                    <td className="px-1.5 py-0.5 text-muted-foreground">{r.created_at ? new Date(r.created_at).toLocaleTimeString() : '—'}</td>
                    <td className="px-1.5 py-0.5 font-mono">{r.caller || r.agent_name || '—'}</td>
                    <td className="px-1.5 py-0.5 font-mono text-muted-foreground">{r.model_name}</td>
                    <td className="px-1.5 py-0.5 text-right">{r.total_tokens ?? '—'}</td>
                    <td className="px-1.5 py-0.5 text-right text-primary font-mono">{r.tokens_per_sec ?? '—'}</td>
                    <td className="px-1.5 py-0.5 text-right font-mono">{r.latency_ms ? `${(r.latency_ms / 1000).toFixed(1)}s` : '—'}</td>
                    <td className="px-1.5 py-0.5">{r.is_error ? <span className="text-red-400">{r.error_message?.slice(0, 40) || 'error'}</span> : <span className="text-green-400">ok</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}

      {!loading && !summary?.callers?.length && recent.length === 0 && (
        <p className="text-xs text-muted-foreground">No LLM metrics recorded yet. Use AI Check on the Software tab to generate data.</p>
      )}
    </div>
  )
}
