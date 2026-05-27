import { useState, useEffect } from 'react'
import PageHelp from '@/components/PageHelp'
import { useQuery, useMutation } from '@tanstack/react-query'
import { useReportSummary, useReportFull, useExportPdf, useExportBurp, useExportZapXml, useExportZapReport, useExportSarif, useExportUrlList, useExportHar, useProxyReplay } from '@/api/reports'
import { apiFetch } from '@/api/client'
import { useEngagements, useEngagement } from '@/api/engagements'
import { useScopeNames, useScope } from '@/api/scope'
import { useUIStore } from '@/stores/ui'
import { SEVERITY_LEVELS, SOURCES } from '@/lib/constants'
import { cn } from '@/lib/utils'
import { FileText, Download, Eye, Briefcase, AlertTriangle, CheckCircle2, Loader2 } from 'lucide-react'
import ReactMarkdown from 'react-markdown'

export default function Reports() {
  const globalEngagementId = useUIStore(s => s.selectedEngagementId)
  const globalScope = useUIStore(s => s.selectedScopeName)
  const setGlobalEngagement = useUIStore(s => s.setSelectedEngagement)
  const alphaEnabled = useUIStore(s => s.alphaTestingEnabled)
  const { data: engData } = useEngagements()
  const engagements = engData?.engagements ?? []
  const { data: engDetail } = useEngagement(globalEngagementId || undefined)
  const { data: scopeNamesData } = useScopeNames()
  const scopeNames = scopeNamesData?.names ?? []
  const [selectedScope, setSelectedScope] = useState('')
  const scopeName = selectedScope || engDetail?.scope_name || globalScope || ''
  const { data: scopeData } = useScope(scopeName)

  const [title, setTitle] = useState('Penetration Test Report')
  const [target, setTarget] = useState('')
  const [severities, setSeverities] = useState<string[]>([])
  const [sources, setSources] = useState<string[]>([])

  // Live findings count based on current filters
  const findingsCountParams = new URLSearchParams({ limit: '1', offset: '0' })
  if (target) findingsCountParams.set('ip', target)
  if (severities.length) severities.forEach(s => findingsCountParams.append('severity', s))
  if (sources.length) sources.forEach(s => findingsCountParams.append('source', s))
  if (globalEngagementId) findingsCountParams.set('engagement_id', globalEngagementId)
  const { data: countData } = useQuery({
    queryKey: ['findings-count', target, severities, sources, globalEngagementId],
    queryFn: () => apiFetch<{ total: number; aggregations: { by_severity: Record<string, number>; by_source: Record<string, number> } }>(`/findings?${findingsCountParams}`),
    staleTime: 30000,
  })
  const [preview, setPreview] = useState<string | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)

  // Auto-fill target from engagement scope
  useEffect(() => {
    if (engDetail) {
      // Set report title from engagement name
      setTitle(`${engDetail.name} — Penetration Test Report`)
    }
  }, [engDetail])

  useEffect(() => {
    if (scopeData?.targets?.length) {
      const targets = scopeData.targets.map((t: { target: string }) =>
        t.target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '')
      )
      // Use first scope target as the report target
      if (targets[0] && !target) {
        setTarget(targets[0])
      }
    }
  }, [scopeData]) // eslint-disable-line react-hooks/exhaustive-deps

  const reportSummary = useReportSummary()
  const reportFull = useReportFull(target || undefined, undefined, scopeName || undefined)
  const exportPdf = useExportPdf()
  const exportBurp = useExportBurp()
  const exportZapXml = useExportZapXml()

  const toggleSev = (s: string) => setSeverities(prev =>
    prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]
  )
  const toggleSrc = (s: string) => setSources(prev =>
    prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]
  )

  const handlePreview = async () => {
    setPreviewError(null)
    const result = await reportFull.refetch()
    if (result.error) {
      setPreviewError(String(result.error))
      return
    }
    if (result.data) {
      const d = result.data
      if (d.rendered) {
        setPreview(d.rendered)
      } else {
        setPreview(JSON.stringify(d, null, 2))
      }
    }
  }

  const handleExport = () => {
    exportPdf.mutate(
      {
        title,
        target: target || undefined,
        severity_filter: severities.length ? severities : undefined,
        source_filter: sources.length ? sources : undefined,
      },
      {
        onSuccess: (blob) => {
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = 'pentest-report.pdf'
          a.click()
          URL.revokeObjectURL(url)
        },
      },
    )
  }

  const handleExportBurp = () => {
    exportBurp.mutate(
      {
        target: target || undefined,
        severity_filter: severities.length ? severities : undefined,
        source_filter: sources.length ? sources : undefined,
      },
      {
        onSuccess: (blob) => {
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = 'burp_sitemap_export.xml'
          a.click()
          URL.revokeObjectURL(url)
        },
      },
    )
  }

  const handleExportZapXml = () => {
    exportZapXml.mutate(undefined, {
      onSuccess: (blob) => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = 'zap_report.xml'
        a.click()
        URL.revokeObjectURL(url)
      },
    })
  }

  return (
    <div className="space-y-6">
      <PageHelp id="reports" title="How to use Reports">
        <p>Export findings for manual tools: <strong>HAR</strong> for Burp Suite (includes real request/response from ZAP), <strong>CSV</strong> for spreadsheets, <strong>SARIF</strong> for CI/CD. <strong>Proxy Replay</strong> pushes URLs through Burp/ZAP in 4 phases. A live <strong>findings count</strong> shows exactly how many findings will be exported. Install the <strong>Burp extension</strong> (<code>burp-extension/RagScanBridge.py</code>) for direct import with scope/engagement filtering.</p>
      </PageHelp>
      <h2 className="text-lg font-semibold">Reports</h2>

      <div className="bg-card border border-border rounded-lg p-4 max-w-2xl space-y-4">
        {/* Engagement selector */}
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Engagement</label>
          <select
            value={globalEngagementId ?? ''}
            onChange={e => {
              const eid = e.target.value || null
              const eng = engagements.find(en => en.id === eid)
              setGlobalEngagement(eid, eng?.scope_name ?? null)
            }}
            className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
          >
            <option value="">All Engagements</option>
            {engagements.filter(e => e.status !== 'archived').map(e => (
              <option key={e.id} value={e.id}>{e.name} ({e.status}){e.scope_name ? ` — ${e.scope_name}` : ''}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Scope</label>
          <select
            value={selectedScope}
            onChange={e => setSelectedScope(e.target.value)}
            className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
          >
            <option value="">{engDetail?.scope_name ? `From engagement (${engDetail.scope_name})` : 'All scopes'}</option>
            {scopeNames.map(s => (
              <option key={s.name} value={s.name}>{s.name} ({s.target_count} targets)</option>
            ))}
          </select>
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Report Title</label>
          <input
            value={title}
            onChange={e => setTitle(e.target.value)}
            className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
          />
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Target (optional — leave blank for all findings)</label>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="IP, hostname, or leave blank for all"
            className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
          />
          {/* Scope target chips — click to set as report target */}
          {scopeData?.targets && scopeData.targets.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              <span className="text-[10px] text-muted-foreground mr-1">Scope targets:</span>
              {scopeData.targets.map((t: { target: string }, i: number) => {
                const host = t.target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '')
                return (
                  <button
                    key={i}
                    onClick={() => setTarget(host)}
                    className={cn(
                      'px-1.5 py-0.5 rounded text-[10px] font-mono border transition-colors',
                      target === host
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border text-muted-foreground hover:border-primary/50',
                    )}
                  >
                    {host}
                  </button>
                )
              })}
            </div>
          )}
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1.5 block">Severity Filter</label>
          <div className="flex flex-wrap gap-1.5">
            {SEVERITY_LEVELS.map(s => (
              <button
                key={s}
                onClick={() => toggleSev(s)}
                className={cn(
                  'px-2 py-0.5 rounded text-xs border',
                  severities.includes(s) ? 'border-primary bg-primary/10' : 'border-border text-muted-foreground',
                )}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1.5 block">Source Filter</label>
          <div className="flex flex-wrap gap-1.5">
            {SOURCES.map(s => (
              <button
                key={s}
                onClick={() => toggleSrc(s)}
                className={cn(
                  'px-2 py-0.5 rounded text-xs border',
                  sources.includes(s) ? 'border-primary bg-primary/10' : 'border-border text-muted-foreground',
                )}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Findings count summary */}
        {countData && (
          <div className="bg-muted/30 border border-border rounded-lg p-3 space-y-2">
            <div className="flex items-center gap-3">
              <span className="text-sm font-semibold">{countData.total.toLocaleString()} findings</span>
              <span className="text-[10px] text-muted-foreground">match current filters — will be included in export</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(countData.aggregations?.by_severity || {})
                .filter(([, v]) => v > 0)
                .sort(([a], [b]) => {
                  const order = ['critical', 'high', 'medium', 'low', 'info', 'recon']
                  return order.indexOf(a) - order.indexOf(b)
                })
                .map(([sev, count]) => {
                  const colors: Record<string, string> = {
                    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
                    high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
                    medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
                    low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
                    info: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
                    recon: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
                  }
                  return (
                    <span key={sev} className={cn('px-2 py-0.5 rounded text-[10px] font-medium border', colors[sev] || colors.info)}>
                      {count} {sev}
                    </span>
                  )
                })}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(countData.aggregations?.by_source || {})
                .filter(([, v]) => v > 0)
                .sort(([, a], [, b]) => b - a)
                .map(([src, count]) => (
                  <span key={src} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-muted border border-border text-muted-foreground">
                    {src}: {count}
                  </span>
                ))}
            </div>
          </div>
        )}

        <div className="flex gap-2">
          <button
            onClick={handlePreview}
            disabled={reportFull.isFetching}
            className="flex items-center gap-2 px-3 py-1.5 bg-secondary text-secondary-foreground rounded-md text-sm hover:bg-secondary/80 disabled:opacity-50"
          >
            <Eye className="h-4 w-4" /> Preview
          </button>
          <button
            onClick={handleExport}
            disabled={exportPdf.isPending}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90 disabled:opacity-50"
          >
            <Download className="h-4 w-4" />
            {exportPdf.isPending ? 'Generating...' : 'Export PDF'}
          </button>
        </div>

        {/* Tool Export Formats */}
        <ExportFormats
          target={target}
          severities={severities}
          sources={sources}
          scopeDomains={scopeData?.targets?.map(t => t.target)}
          findingsTotal={countData?.total}
        />

        {previewError && <p className="text-xs text-red-500">{previewError}</p>}
        {reportFull.error && <p className="text-xs text-red-500">{String(reportFull.error)}</p>}
        {exportPdf.error && <p className="text-xs text-red-500">{String(exportPdf.error)}</p>}
      </div>

      {/* Preview */}
      {preview && (
        <div className="bg-card border border-border rounded-lg p-4">
          <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
            <FileText className="h-4 w-4" /> Report Preview
          </h3>
          <div className="prose prose-invert prose-sm max-w-none">
            <ReactMarkdown>{preview}</ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  )
}

const EXPORT_FORMATS = [
  {
    id: 'har',
    label: 'HAR File (Burp + ZAP)',
    desc: 'HTTP Archive with findings — import into Burp Suite or ZAP to populate sitemap/sites tree for manual testing',
    icon: '🔧',
  },
  {
    id: 'urls',
    label: 'URL List (text)',
    desc: 'One URL per line — seed Burp Spider, ZAP Spider, ffuf, or nuclei',
    icon: '🔗',
  },
  {
    id: 'sarif',
    label: 'SARIF (JSON)',
    desc: 'Static Analysis Results v2.1 — VS Code, GitHub Code Scanning, Azure DevOps',
    icon: '📋',
  },
  {
    id: 'burp-xml',
    label: 'Burp Sitemap XML (legacy)',
    desc: 'Legacy Burp sitemap format — use HAR instead for current Burp versions',
    icon: '📄',
  },
] as const

const PROXY_PRESETS = [
  { label: 'Burp Suite', url: 'http://192.168.1.181:8080' },
  { label: 'ZAP', url: 'http://host.docker.internal:8090' },
] as const

const IMPORT_INSTRUCTIONS: Record<string, { tool: string; steps: string[] }[]> = {
  'har': [
    {
      tool: 'Burp Suite — HARBringer Extension (recommended)',
      steps: [
        'Install HARBringer from Extensions > BApp Store (search "HARBringer")',
        'Extensions > HARBringer > Import HAR File',
        'Select the .har file — entries populate in Target > Site map and Proxy > HTTP history',
        'Finding details (severity, CVEs, evidence) are in the response body of each entry',
      ],
    },
    {
      tool: 'Burp Suite — Proxy Replay (no extension needed)',
      steps: [
        'Use the "Replay to Proxy" option below instead of HAR import',
        'Ensure Burp is listening on 127.0.0.1:8080',
        'Click Replay — URLs populate in Proxy > HTTP history and Target > Site map with real responses',
      ],
    },
    {
      tool: 'ZAP — Import/Export Add-on',
      steps: [
        'Ensure Import/Export add-on is installed (Marketplace > Import/Export)',
        'File > Import/Export > Import HAR (HTTP Archive)',
        'Select the .har file — entries appear in Sites tree and History tab',
      ],
    },
    {
      tool: 'Chrome DevTools (for inspection)',
      steps: [
        'Open DevTools (F12) > Network tab',
        'Click the import icon (arrow up) or drag-drop the .har file',
        'Entries appear in the network waterfall view',
      ],
    },
  ],
  'urls': [
    {
      tool: 'Burp Suite',
      steps: [
        'Target > Scope > Paste URLs from the file',
        'Or: Proxy tab > Intercept off, then run: while read url; do curl -sk -x http://127.0.0.1:8080 "$url"; done < urls.txt',
      ],
    },
    {
      tool: 'ZAP',
      steps: [
        'Ensure Import/Export add-on is installed',
        'File > Import/Export > Import a File Containing URLs',
        'Select the urls.txt file',
      ],
    },
    {
      tool: 'Other Tools',
      steps: [
        'nuclei: nuclei -l urls.txt -t cves/',
        'ffuf: ffuf -w urls.txt -u FUZZ',
        'httpx: httpx -l urls.txt -status-code -title',
      ],
    },
  ],
  'sarif': [
    {
      tool: 'VS Code',
      steps: [
        'Install "SARIF Viewer" extension from marketplace',
        'Open the .sarif file — findings appear in the SARIF Explorer panel',
        'Click any finding to see location, severity, and details',
      ],
    },
    {
      tool: 'GitHub Code Scanning',
      steps: [
        'Upload via API: gh api repos/{owner}/{repo}/code-scanning/sarifs -f sarif=@findings.sarif',
        'Findings appear in Security > Code scanning alerts',
      ],
    },
  ],
  'burp-xml': [
    {
      tool: 'Note',
      steps: [
        'Current Burp Suite versions no longer support sitemap XML import',
        'Use the HAR export or Proxy Replay option instead',
        'This format is kept for compatibility with older Burp versions and third-party tools',
      ],
    },
  ],
}

function ExportFormats({ target, severities, sources, scopeDomains, findingsTotal }: {
  target: string
  severities: string[]
  sources: string[]
  scopeDomains?: string[]
  findingsTotal?: number
}) {
  const exportHar = useExportHar()
  const exportBurp = useExportBurp()
  const exportSarif = useExportSarif()
  const exportUrls = useExportUrlList()
  const [error, setError] = useState<string | null>(null)

  const download = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleExport = (format: string) => {
    setError(null)
    const filterParams = {
      target: target || undefined,
      severity_filter: severities.length ? severities : undefined,
      source_filter: sources.length ? sources : undefined,
    }
    switch (format) {
      case 'har':
        exportHar.mutate(filterParams, {
          onSuccess: (blob) => download(blob, 'findings_export.har'),
          onError: (e) => setError(String(e)),
        })
        break
      case 'burp-xml':
        exportBurp.mutate(filterParams, {
          onSuccess: (blob) => download(blob, 'burp_sitemap_export.xml'),
          onError: (e) => setError(String(e)),
        })
        break
      case 'sarif':
        exportSarif.mutate({
          severity: severities.join(',') || undefined,
          source: sources.join(',') || undefined,
        }, {
          onSuccess: (blob) => download(blob, 'pentest_findings.sarif'),
          onError: (e) => setError(String(e)),
        })
        break
      case 'urls':
        exportUrls.mutate({
          domain: scopeDomains?.[0] || target || undefined,
        }, {
          onSuccess: (blob) => download(blob, 'urls.txt'),
          onError: (e) => setError(String(e)),
        })
        break
    }
  }

  const isPending = exportHar.isPending || exportBurp.isPending || exportSarif.isPending || exportUrls.isPending
  const [showInstructions, setShowInstructions] = useState<string | null>(null)

  return (
    <div className="border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Export for Tools</h3>
        {findingsTotal !== undefined && (
          <span className={cn(
            'px-2 py-0.5 rounded text-[10px] font-medium border',
            findingsTotal > 0 ? 'bg-primary/10 text-primary border-primary/30' : 'bg-muted text-muted-foreground border-border',
          )}>
            {findingsTotal.toLocaleString()} findings selected
          </span>
        )}
      </div>
      <p className="text-[10px] text-muted-foreground">
        Export findings in formats compatible with security testing tools. Severity and source filters above apply.
      </p>
      <div className="grid grid-cols-2 gap-2">
        {EXPORT_FORMATS.map(fmt => (
          <div key={fmt.id} className="flex flex-col">
            <button
              onClick={() => handleExport(fmt.id)}
              disabled={isPending}
              className={`flex items-start gap-2.5 p-3 rounded-t-md border border-border bg-muted/20 hover:bg-muted/50 text-left disabled:opacity-50 transition-colors ${showInstructions === fmt.id ? 'rounded-b-none border-b-0' : 'rounded-b-md'}`}
            >
              <span className="text-lg mt-0.5">{fmt.icon}</span>
              <div className="min-w-0 flex-1">
                <div className="text-xs font-medium">{fmt.label}</div>
                <div className="text-[10px] text-muted-foreground mt-0.5">{fmt.desc}</div>
              </div>
            </button>
            <button
              onClick={() => setShowInstructions(showInstructions === fmt.id ? null : fmt.id)}
              className={`text-[10px] px-3 py-1 border border-border border-t-0 text-muted-foreground hover:text-foreground hover:bg-accent/30 ${showInstructions === fmt.id ? '' : 'rounded-b-md'}`}
            >{showInstructions === fmt.id ? 'Hide instructions' : 'How to import'}</button>
            {showInstructions === fmt.id && (
              <div className="border border-border border-t-0 rounded-b-md bg-muted/10 px-3 py-2.5 text-[11px] space-y-2">
                {IMPORT_INSTRUCTIONS[fmt.id]?.map((section, i) => (
                  <div key={i}>
                    <div className="font-medium text-foreground">{section.tool}</div>
                    <ol className="list-decimal list-inside text-muted-foreground space-y-0.5 ml-1 mt-0.5">
                      {section.steps.map((step, j) => <li key={j}>{step}</li>)}
                    </ol>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
      {error && <p className="text-xs text-red-500">{error}</p>}

      {/* Enhanced Proxy Replay */}
      <ProxyReplaySection target={target} severities={severities} sources={sources} findingsTotal={findingsTotal} />
    </div>
  )
}


function ProxyReplaySection({ target, severities, sources, findingsTotal }: { target: string; severities: string[]; sources: string[]; findingsTotal?: number }) {
  const proxyReplay = useProxyReplay()
  const [proxyUrl, setProxyUrl] = useState('http://192.168.1.181:8080')
  const [replayProgress, setReplayProgress] = useState<{
    running: boolean; phase: string; progress: number; total: number; success: number; failed: number
  } | null>(null)
  const [dockerHostIp, setDockerHostIp] = useState('')
  // Persist proxy URL and docker host IP in DB settings
  const { data: savedProxy } = useQuery({
    queryKey: ['setting-burp-proxy-url'],
    queryFn: async () => {
      try { return (await apiFetch<{ value: string }>('/settings/config/burp_proxy_url')).value } catch { return null }
    },
  })
  const { data: savedDockerIp } = useQuery({
    queryKey: ['setting-docker-host-ip'],
    queryFn: async () => {
      try { return (await apiFetch<{ value: string }>('/settings/config/docker_host_ip')).value } catch { return null }
    },
  })
  useEffect(() => { if (savedProxy) setProxyUrl(savedProxy) }, [savedProxy])
  useEffect(() => { if (savedDockerIp) setDockerHostIp(savedDockerIp) }, [savedDockerIp])
  const saveSettings = useMutation({
    mutationFn: async (params: { proxy?: string; dockerIp?: string }) => {
      if (params.proxy) await apiFetch('/settings/config/burp_proxy_url', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value: params.proxy }) })
      if (params.dockerIp) await apiFetch('/settings/config/docker_host_ip', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value: params.dockerIp }) })
    },
  })
  const [replayResult, setReplayResult] = useState<string | null>(null)
  const [includeParams, setIncludeParams] = useState(true)
  const [includeAuth, setIncludeAuth] = useState(true)
  const [includePayloads, setIncludePayloads] = useState(true)
  const [order, setOrder] = useState<'sequential' | 'severity' | 'random'>('sequential')
  const [dryRunData, setDryRunData] = useState<Record<string, unknown> | null>(null)
  const [showConfirm, setShowConfirm] = useState(false)
  const [selectedNode, setSelectedNode] = useState<{ id: string; name: string; proxy_port: number } | null>(null)

  // Burp proxy test
  const testProxy = useMutation({
    mutationFn: () => apiFetch<{ ok: boolean; external_ip?: string; error?: string; elapsed_ms?: number; proxy_url?: string }>('/burp/test-proxy', { method: 'POST' }),
  })

  // Node list for SOCKS proxy auto-config
  const { data: nodesData } = useQuery({
    queryKey: ['nodes-for-proxy'],
    queryFn: () => apiFetch<{ nodes: { id: string; name: string; proxy_port: number; proxy_type: string; status: string }[] }>('/nodes'),
  })
  const onlineNodes = (nodesData?.nodes ?? []).filter(n => n.status === 'online' && n.proxy_port)

  // Configure Burp SOCKS proxy
  const configureSocks = useMutation({
    mutationFn: (nodeId: string) => apiFetch<{ ok: boolean; message: string; manual_config?: string }>('/burp/configure-proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: nodeId }),
    }),
  })

  const replayParams = {
    proxy_url: proxyUrl,
    severity: severities.length ? severities : undefined,
    source: sources.length ? sources : undefined,
    ip: target || undefined,
    limit: 1000,
    delay_ms: 50,
    include_params: includeParams,
    include_auth: includeAuth,
    include_payloads: includePayloads,
    order,
  }

  const handleDryRun = () => {
    setReplayResult(null)
    setDryRunData(null)
    proxyReplay.mutate({ ...replayParams, dry_run: true } as Parameters<typeof proxyReplay.mutate>[0], {
      onSuccess: (data) => setDryRunData(data as Record<string, unknown>),
      onError: (e) => setReplayResult(`Error: ${e}`),
    })
  }

  // Poll replay progress while running
  const pollProgress = () => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch('/api/reports/proxy-replay/status')
        const data = await res.json()
        setReplayProgress(data)
        if (!data.running) {
          clearInterval(interval)
          if (data.total > 0) {
            setReplayResult(`Done: ${data.success} sent, ${data.failed} failed out of ${data.total} requests`)
          }
        }
      } catch {
        clearInterval(interval)
      }
    }, 1500)
    return interval
  }

  const handleReplay = () => {
    setShowConfirm(false)
    setReplayResult(null)
    setDryRunData(null)
    setReplayProgress({ running: true, phase: 'starting', progress: 0, total: 0, success: 0, failed: 0 })
    const progressInterval = pollProgress()
    proxyReplay.mutate(replayParams, {
      onSuccess: (data) => {
        const phases = (data as Record<string, unknown>).phases as Record<string, number> | undefined
        const parts = [`${data.queued} requests queued`]
        if (phases) parts.push(`(${phases.base_urls} URLs, ${phases.parameters} params, ${phases.payloads} payloads)`)
        setReplayResult(parts.join(' '))
        // Keep polling until status shows not running
        setTimeout(() => clearInterval(progressInterval), 60000)
      },
      onError: (e) => {
        setReplayResult(`Error: ${e}`)
        clearInterval(progressInterval)
        setReplayProgress(null)
      },
    })
  }

  return (
    <div className="border-t border-border pt-3 mt-3 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold">Replay to Proxy (Burp / ZAP)</h4>
        {findingsTotal !== undefined && (
          <span className={cn(
            'px-2 py-0.5 rounded text-[10px] font-medium border',
            findingsTotal > 0 ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' : 'bg-muted text-muted-foreground border-border',
          )}>
            {findingsTotal.toLocaleString()} findings to replay
          </span>
        )}
      </div>
      <p className="text-[10px] text-muted-foreground">
        Send discovered URLs, parameters, credentials, and attack payloads through your proxy in 4 phases.
        <span className="text-orange-400 font-medium"> This contacts the target — use Dry Run first to preview.</span>
      </p>

      {/* Proxy URL + test */}
      <div className="flex items-center gap-2">
        <input value={proxyUrl} onChange={e => setProxyUrl(e.target.value)} placeholder="http://127.0.0.1:8080"
          className="flex-1 bg-muted rounded px-2.5 py-1.5 text-xs font-mono border border-border" />
        {PROXY_PRESETS.map(p => (
          <button key={p.label} onClick={() => setProxyUrl(p.url)}
            className={`px-2 py-1 text-[10px] rounded border ${proxyUrl === p.url ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'}`}
          >{p.label}</button>
        ))}
        <button onClick={() => saveSettings.mutate({ proxy: proxyUrl, dockerIp: dockerHostIp || undefined })}
          disabled={saveSettings.isPending}
          className="px-2 py-1 text-[10px] rounded border border-border text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50"
          title="Save settings"
        >{saveSettings.isSuccess ? 'Saved' : 'Save'}</button>
        <button onClick={() => testProxy.mutate()} disabled={testProxy.isPending}
          className="px-2.5 py-1 text-[10px] font-medium rounded border border-border text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50 flex items-center gap-1">
          {testProxy.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckCircle2 className="h-3 w-3" />}
          Test
        </button>
      </div>

      {/* Test result — prominent status card */}
      {testProxy.data && (
        <div className={cn(
          'flex items-center gap-3 px-3 py-2 rounded-lg border text-xs',
          testProxy.data.ok
            ? 'bg-green-500/10 border-green-500/30 text-green-400'
            : 'bg-red-500/10 border-red-500/30 text-red-400',
        )}>
          {testProxy.data.ok
            ? <CheckCircle2 className="h-4 w-4 shrink-0" />
            : <AlertTriangle className="h-4 w-4 shrink-0" />}
          <div>
            {testProxy.data.ok ? (
              <>
                <span className="font-medium">Proxy connected</span>
                <span className="text-green-400/70 ml-2">External IP: {testProxy.data.external_ip}</span>
                <span className="text-green-400/50 ml-2">{testProxy.data.elapsed_ms}ms</span>
              </>
            ) : (
              <>
                <span className="font-medium">Connection failed</span>
                <span className="text-red-400/70 ml-2">{testProxy.data.error}</span>
              </>
            )}
          </div>
        </div>
      )}
      {testProxy.isPending && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>Testing proxy connection...</span>
        </div>
      )}

      {/* Docker Host IP (for SOCKS proxy routing from external Burp) */}
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-muted-foreground whitespace-nowrap">Docker Host IP (for SOCKS):</span>
        <input value={dockerHostIp} onChange={e => setDockerHostIp(e.target.value)}
          placeholder="e.g. 192.168.1.100 — the IP Burp uses to reach SOCKS tunnels"
          className="flex-1 bg-muted rounded px-2.5 py-1.5 text-xs font-mono border border-border" />
      </div>

      {/* Auto SOCKS config for Burp */}
      {onlineNodes.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] text-muted-foreground">Set Burp SOCKS proxy:</span>
            {onlineNodes.map(n => (
              <button key={n.id} onClick={() => { configureSocks.mutate(n.id); setSelectedNode(n) }}
                disabled={configureSocks.isPending}
                className="px-2 py-0.5 text-[10px] rounded border border-border text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50">
                {n.name} (:{n.proxy_port})
              </button>
            ))}
            {configureSocks.data && (
              <span className={`text-[10px] ${configureSocks.data.ok ? 'text-green-400' : 'text-orange-400'}`}>
                {configureSocks.data.message || configureSocks.data.manual_config}
              </span>
            )}
          </div>
          {/* WSL2 port forward helper */}
          {selectedNode && (
            <details className="text-[10px] border border-border rounded p-2 bg-muted/20">
              <summary className="cursor-pointer text-primary font-medium">WSL2: Expose SOCKS port {selectedNode.proxy_port} to LAN for Burp</summary>
              <div className="mt-2 space-y-1.5">
                <p className="text-muted-foreground">Run in Windows <b>Admin PowerShell</b> to forward port {selectedNode.proxy_port} from Windows LAN to WSL2:</p>
                <pre className="bg-muted rounded p-2 font-mono text-[10px] select-all overflow-x-auto whitespace-pre-wrap">
{`# Add port forward (run once)
netsh interface portproxy add v4tov4 listenport=${selectedNode.proxy_port} listenaddress=0.0.0.0 connectport=${selectedNode.proxy_port} connectaddress=$(wsl hostname -I | ForEach-Object { $_.Trim().Split(' ')[0] })

# Allow through Windows Firewall
netsh advfirewall firewall add rule name="WSL2 SOCKS ${selectedNode.proxy_port}" dir=in action=allow protocol=tcp localport=${selectedNode.proxy_port}

# Verify
netsh interface portproxy show v4tov4`}
                </pre>
                <p className="text-muted-foreground">Then in Burp: <b>Project options &gt; Connections &gt; SOCKS proxy</b> &gt; {dockerHostIp || '<your-windows-ip>'}:{selectedNode.proxy_port} (SOCKS5)</p>
                <pre className="bg-muted rounded p-2 font-mono text-[10px] select-all overflow-x-auto whitespace-pre-wrap">
{`# To remove later:
netsh interface portproxy delete v4tov4 listenport=${selectedNode.proxy_port} listenaddress=0.0.0.0
netsh advfirewall firewall delete rule name="WSL2 SOCKS ${selectedNode.proxy_port}"`}
                </pre>
              </div>
            </details>
          )}
        </div>
      )}

      {/* Options */}
      <div className="flex items-center gap-4 flex-wrap">
        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
          <input type="checkbox" checked={includeParams} onChange={e => setIncludeParams(e.target.checked)} className="h-3 w-3" />
          Parameters
        </label>
        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
          <input type="checkbox" checked={includeAuth} onChange={e => setIncludeAuth(e.target.checked)} className="h-3 w-3" />
          Auth Tokens
        </label>
        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
          <input type="checkbox" checked={includePayloads} onChange={e => setIncludePayloads(e.target.checked)} className="h-3 w-3" />
          Attack Payloads
        </label>
        <select value={order} onChange={e => setOrder(e.target.value as typeof order)}
          className="bg-muted rounded px-2 py-1 text-xs border border-border">
          <option value="sequential">Sequential (crawl order)</option>
          <option value="severity">By Severity</option>
          <option value="random">Random</option>
        </select>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        <button onClick={handleDryRun} disabled={!proxyUrl || proxyReplay.isPending}
          className="px-3 py-1.5 text-xs rounded border border-border text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50 flex items-center gap-1">
          <Eye className="h-3 w-3" /> Dry Run
        </button>
        <button onClick={() => setShowConfirm(true)} disabled={!proxyUrl || proxyReplay.isPending}
          className="px-3 py-1.5 text-xs font-medium rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 flex items-center gap-1">
          <Download className="h-3 w-3" />
          {proxyReplay.isPending ? 'Sending...' : 'Replay All Phases'}
        </button>
      </div>

      {/* Dry run results */}
      {dryRunData && (
        <div className="bg-muted/30 border border-border rounded p-3 space-y-2 text-xs">
          <div className="flex items-center gap-2 text-orange-400">
            <AlertTriangle className="h-3.5 w-3.5" />
            <span className="font-medium">{String(dryRunData.warning)}</span>
          </div>
          <div className="grid grid-cols-4 gap-2 text-[10px]">
            {Object.entries((dryRunData.phases || {}) as Record<string, number>).map(([k, v]) => (
              <div key={k} className="border border-border rounded p-1.5 text-center">
                <div className="font-bold text-sm">{v}</div>
                <div className="text-muted-foreground">{k.replace('_', ' ')}</div>
              </div>
            ))}
          </div>
          {(dryRunData.samples as Record<string, unknown[]>)?.base_urls?.length > 0 && (
            <details className="text-[10px]">
              <summary className="cursor-pointer text-primary">Sample URLs ({((dryRunData.samples as Record<string, unknown[]>).base_urls || []).length} shown)</summary>
              <div className="mt-1 space-y-0.5 max-h-40 overflow-y-auto">
                {((dryRunData.samples as Record<string, unknown[]>).base_urls || []).map((s, i) => (
                  <div key={i} className="font-mono text-muted-foreground truncate">{(s as Record<string, string>).method} {(s as Record<string, string>).url}</div>
                ))}
              </div>
            </details>
          )}
        </div>
      )}

      {/* Confirmation dialog */}
      {showConfirm && (
        <div className="bg-red-500/5 border border-red-500/30 rounded p-3 space-y-2">
          <div className="flex items-center gap-2 text-red-400 text-xs font-medium">
            <AlertTriangle className="h-4 w-4" />
            This will send real HTTP requests to targets through {proxyUrl}
          </div>
          <p className="text-[10px] text-muted-foreground">Targets will see this traffic. Attack payloads will re-trigger vulnerabilities.</p>
          <div className="flex gap-2">
            <button onClick={() => setShowConfirm(false)} className="px-3 py-1 text-xs rounded border border-border text-muted-foreground">Cancel</button>
            <button onClick={handleReplay} className="px-3 py-1 text-xs font-medium rounded bg-red-600 text-white hover:bg-red-700">Confirm — Send Traffic</button>
          </div>
        </div>
      )}

      {/* Progress bar during replay */}
      {replayProgress?.running && (
        <div className="bg-blue-500/5 border border-blue-500/30 rounded p-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-400" />
              <span className="text-blue-400 font-medium">
                Sending to proxy: {replayProgress.phase || 'starting'}
              </span>
            </div>
            <span className="text-muted-foreground">
              {replayProgress.progress}/{replayProgress.total}
              {replayProgress.failed > 0 && <span className="text-red-400 ml-2">{replayProgress.failed} failed</span>}
            </span>
          </div>
          {replayProgress.total > 0 && (
            <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 rounded-full transition-all duration-300"
                style={{ width: `${Math.round((replayProgress.progress / replayProgress.total) * 100)}%` }}
              />
            </div>
          )}
        </div>
      )}

      {/* Final result */}
      {replayResult && <p className={`text-xs ${replayResult.startsWith('Error') ? 'text-red-500' : 'text-green-500'}`}>{replayResult}</p>}
    </div>
  )
}
