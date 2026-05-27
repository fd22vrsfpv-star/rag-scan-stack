import { useState, useMemo, useEffect, Fragment } from 'react'
import {
  useReconFindings, type ReconFilter,
  useParams, type ParamFilter, type DiscoveredParam,
  useReconDomains, useReconDomainOverview, useDomainSitemap,
  useAutoAssignUnknownScope, useExcludeDomain, useRestoreDomain,
  useScreenshots, useAllScreenshotMetadata, useScreenshotMetadata, useUpdateScreenshotMetadata,
  useServiceEnumFindings,
  type DomainSummary, type DomainDnsEntry,
} from '@/api/recon'
import { useTagSuggestions, useDeleteReconFindings, useMoveToScope } from '@/api/findings'
import { useScopeNames, useAddToScope } from '@/api/scope'
import { useUIStore } from '@/stores/ui'
import { DataTable } from '@/components/common/DataTable'
import { SeverityBadge } from '@/components/common/SeverityBadge'
import { SourceBadge } from '@/components/common/SourceBadge'
import { ScopeFilter } from '@/components/common/ScopeFilter'
import { useScopeFilter } from '@/hooks/useScopeFilter'
import type { ColumnDef } from '@tanstack/react-table'
import type { ReconFinding } from '@/lib/types'
import { X, Plus, Check, ChevronLeft, ChevronRight, ChevronDown, Globe, Search, Shield, ShieldAlert, ShieldCheck, Lock, FileText, Server, Wifi, MapPin, Camera, Tag, Radar, Trash2, Mail, AlertTriangle } from 'lucide-react'
import { apiUrl } from '@/api/client'
import { useLaunchScan } from '@/api/scans'
import { useScanThroughNode } from '@/api/nodes'
import { useContentExtractions, type ContentExtraction } from '@/api/reports'
import { cn, formatDate } from '@/lib/utils'
import { PREDEFINED_TAGS, TAG_COLORS, TAG_COLOR_DEFAULT } from '@/lib/constants'
import PopoutButton from '@/components/PopoutButton'

import { lazy, Suspense } from 'react'
const ScopeIntelligence = lazy(() => import('@/pages/ScopeIntelligence'))

type ExplorerTab = 'findings' | 'parameters' | 'domains' | 'screenshots' | 'scope-intel' | 'metadata'

const RECON_SOURCES = ['subfinder', 'dnsx', 'httpx', 'tlsx', 'crtsh', 'asnmap', 'whois', 'uncover', 'cloudlist', 'whatweb', 'wafw00f', 'gowitness'] as const
const RECON_TYPES = [
  'subdomain', 'dns_a', 'dns_aaaa', 'dns_cname', 'dns_mx', 'dns_ns',
  'tls_cert', 'ct_cert', 'asn_mapping', 'whois_record', 'whois_ip', 'search_result', 'cloud_asset', 'web_service', 'waf_detection',
] as const

function summarizeData(data: Record<string, unknown>): string {
  const parts: string[] = []
  if (data.host) parts.push(String(data.host))
  if (data.input) parts.push(String(data.input))
  if (data.a && Array.isArray(data.a)) parts.push(`A: ${(data.a as string[]).join(', ')}`)
  if (data.cname && Array.isArray(data.cname)) parts.push(`CNAME: ${(data.cname as string[]).join(', ')}`)
  if (data.subject_cn) parts.push(`CN: ${String(data.subject_cn)}`)
  if (data.common_name) parts.push(`CN: ${String(data.common_name)}`)
  if (data.issuer_name) parts.push(`Issuer: ${String(data.issuer_name)}`)
  if (data.asn) parts.push(`ASN: ${String(data.asn)}`)
  if (data.org) parts.push(String(data.org))
  if (data.url) parts.push(String(data.url))
  if (data.status_code) parts.push(`${String(data.status_code)}`)
  if (data.title) parts.push(String(data.title))
  if (data.webserver) parts.push(String(data.webserver))
  if (data.tech && Array.isArray(data.tech)) parts.push(`Tech: ${(data.tech as string[]).join(', ')}`)
  if (data.firewall) parts.push(`WAF: ${String(data.firewall)}`)
  if (data.manufacturer) parts.push(String(data.manufacturer))
  if (parts.length) return parts.join(' | ')
  const keys = Object.keys(data).slice(0, 3)
  return keys.map(k => `${k}: ${String(data[k])}`).join(', ')
}

function inferTargetType(finding: ReconFinding): string {
  if (finding.finding_type === 'subdomain' || finding.source === 'subfinder') return 'domain'
  if (finding.finding_type?.startsWith('dns_')) return 'domain'
  if (finding.finding_type === 'asn_mapping') return 'asn'
  const t = finding.target || ''
  if (/\/\d+$/.test(t)) return 'cidr'
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return 'ip'
  if (t.startsWith('http')) return 'url'
  return 'domain'
}

export default function ReconExplorer() {
  const [activeTab, setActiveTab] = useState<ExplorerTab>('findings')

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Recon & Scope Intelligence</h2>
        {window.location.pathname !== '/recon-popout' && (
          <PopoutButton path="/recon-popout" windowName="rag-recon-popout" />
        )}
      </div>

      <div className="flex gap-1 border-b border-border">
        {([
          ['findings', 'Findings'],
          ['parameters', 'Parameters'],
          ['domains', 'Domain Overview'],
          ['screenshots', 'Screenshots'],
          ['metadata', 'Extracted Metadata'],
          ['scope-intel', 'Scope Intel'],
        ] as [ExplorerTab, string][]).map(([t, label]) => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            className={cn(
              'px-3 py-1.5 text-sm border-b-2 transition-colors',
              activeTab === t ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {activeTab === 'findings' && <FindingsTab />}
      {activeTab === 'parameters' && <ParametersTab />}
      {activeTab === 'domains' && <DomainOverviewTab />}
      {activeTab === 'screenshots' && <ScreenshotsTab />}
      {activeTab === 'metadata' && <MetadataTab />}
      {activeTab === 'scope-intel' && <Suspense fallback={<p className="text-sm text-muted-foreground">Loading...</p>}><ScopeIntelligence /></Suspense>}
    </div>
  )
}

// ─── Parameters Tab ──────────────────────────────────────
const PARAM_TYPES = ['string', 'integer', 'float', 'boolean', 'email', 'uuid', 'path', 'encoded', 'other'] as const

function ParametersTab() {
  const [filters, setFilters] = useState<ParamFilter>({ limit: 200 })
  const { data, isLoading } = useParams(filters)
  const [selected, setSelected] = useState<DiscoveredParam | null>(null)
  const [viewMode, setViewMode] = useState<'grouped' | 'flat'>('grouped')
  const [expandedParams, setExpandedParams] = useState<Set<string>>(new Set())

  const params = data?.params ?? []
  const total = data?.total ?? 0

  // Group by param_name
  type ParamGroup = { name: string; type: string; totalHits: number; urls: typeof params; locations: Set<string>; methods: Set<string> }
  const paramGroups = useMemo<ParamGroup[]>(() => {
    const map = new Map<string, typeof params>()
    for (const p of params) {
      if (!map.has(p.param_name)) map.set(p.param_name, [])
      map.get(p.param_name)!.push(p)
    }
    return Array.from(map.entries()).map(([name, items]) => ({
      name,
      type: items[0]?.param_type || 'string',
      totalHits: items.reduce((sum, p) => sum + (p.occurrence_count || 0), 0),
      urls: items,
      locations: new Set(items.map(p => p.param_location)),
      methods: new Set(items.map(p => p.http_method)),
    })).sort((a, b) => b.totalHits - a.totalHits)
  }, [params])

  const columns = useMemo<ColumnDef<DiscoveredParam, unknown>[]>(() => [
    { accessorKey: 'url_pattern', header: 'URL Pattern', cell: ({ getValue }) => <span className="text-xs font-mono truncate block max-w-[250px]">{String(getValue())}</span> },
    { accessorKey: 'param_name', header: 'Param Name', size: 120, cell: ({ getValue }) => <span className="text-xs font-mono font-medium text-primary">{String(getValue())}</span> },
    {
      accessorKey: 'param_type', header: 'Type', size: 80,
      cell: ({ getValue }) => {
        const t = String(getValue())
        const colors: Record<string, string> = {
          integer: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
          uuid: 'text-purple-400 bg-purple-400/10 border-purple-400/30',
          email: 'text-green-400 bg-green-400/10 border-green-400/30',
          path: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
          encoded: 'text-red-400 bg-red-400/10 border-red-400/30',
          boolean: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/30',
        }
        return <span className={cn('px-1.5 py-0.5 rounded text-xs border', colors[t] || 'border-border text-muted-foreground')}>{t}</span>
      },
    },
    { accessorKey: 'http_method', header: 'Method', size: 70, cell: ({ getValue }) => <span className="text-xs font-mono">{String(getValue())}</span> },
    { accessorKey: 'param_location', header: 'Location', size: 80, cell: ({ getValue }) => <span className="text-xs">{String(getValue())}</span> },
    { accessorKey: 'occurrence_count', header: 'Hits', size: 60, cell: ({ getValue }) => <span className="text-xs font-medium">{String(getValue())}</span> },
    {
      accessorKey: 'sample_values', header: 'Samples', size: 180,
      cell: ({ getValue }) => {
        const vals = getValue() as string[] | null
        if (!vals?.length) return <span className="text-xs text-muted-foreground">-</span>
        return <span className="text-xs font-mono text-muted-foreground truncate block max-w-[180px]">{vals.slice(0, 3).join(', ')}</span>
      },
    },
    {
      accessorKey: 'last_seen', header: 'Last Seen', size: 130,
      cell: ({ getValue }) => {
        const v = getValue()
        return <span className="text-xs text-muted-foreground">{v ? formatDate(String(v)) : ''}</span>
      },
    },
  ], [])

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">{total} discovered parameters</span>
      </div>

      {/* Filters */}
      <div className="space-y-2">
        <div className="flex flex-wrap gap-1.5">
          <span className="text-xs text-muted-foreground py-1">Type:</span>
          {PARAM_TYPES.map(t => (
            <button
              key={t}
              onClick={() => setFilters({ ...filters, param_type: filters.param_type === t ? undefined : t })}
              className={cn(
                'px-2 py-0.5 rounded text-xs border',
                filters.param_type === t ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground',
              )}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            placeholder="Param name filter"
            value={filters.param_name || ''}
            onChange={e => setFilters({ ...filters, param_name: e.target.value || undefined })}
            className="bg-muted rounded-md px-3 py-1 text-sm border border-border outline-none focus:border-primary w-48"
          />
          <input
            placeholder="URL pattern filter"
            value={filters.url_pattern || ''}
            onChange={e => setFilters({ ...filters, url_pattern: e.target.value || undefined })}
            className="bg-muted rounded-md px-3 py-1 text-sm border border-border outline-none focus:border-primary flex-1"
          />
          <div className="flex items-center gap-1.5">
            <label className="text-xs text-muted-foreground">Min hits:</label>
            <input
              type="number"
              min={1}
              value={filters.min_occurrences ?? 1}
              onChange={e => setFilters({ ...filters, min_occurrences: parseInt(e.target.value) || 1 })}
              className="bg-muted rounded-md px-2 py-1 text-sm border border-border outline-none focus:border-primary w-16"
            />
          </div>
        </div>
      </div>

      {/* View toggle */}
      <div className="flex items-center gap-2">
        <button onClick={() => setViewMode('grouped')}
          className={cn('px-2.5 py-1 text-xs rounded border', viewMode === 'grouped' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground')}
        >By Parameter ({paramGroups.length})</button>
        <button onClick={() => setViewMode('flat')}
          className={cn('px-2.5 py-1 text-xs rounded border', viewMode === 'flat' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground')}
        >All Rows ({total})</button>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : viewMode === 'grouped' ? (
        <div className="border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground w-6"></th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">Parameter</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{width:80}}>Type</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{width:70}}>Hits</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{width:100}}>URLs</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">Location</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">Methods</th>
              </tr>
            </thead>
            <tbody>
              {paramGroups.map(g => {
                const expanded = expandedParams.has(g.name)
                const typeColors: Record<string, string> = {
                  integer: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
                  uuid: 'text-purple-400 bg-purple-400/10 border-purple-400/30',
                  email: 'text-green-400 bg-green-400/10 border-green-400/30',
                  path: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
                  encoded: 'text-red-400 bg-red-400/10 border-red-400/30',
                  boolean: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/30',
                }
                return (
                  <Fragment key={g.name}>
                    <tr className="border-b border-border/50 hover:bg-muted/30 cursor-pointer transition-colors"
                      onClick={() => setExpandedParams(prev => {
                        const n = new Set(prev); n.has(g.name) ? n.delete(g.name) : n.add(g.name); return n
                      })}
                    >
                      <td className="px-3 py-2 text-muted-foreground">
                        {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                      </td>
                      <td className="px-3 py-2">
                        <span className="font-mono font-medium text-primary text-sm">{g.name}</span>
                      </td>
                      <td className="px-3 py-2">
                        <span className={cn('px-1.5 py-0.5 rounded text-xs border', typeColors[g.type] || 'border-border text-muted-foreground')}>{g.type}</span>
                      </td>
                      <td className="px-3 py-2">
                        <span className="px-1.5 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-medium">{g.totalHits}</span>
                      </td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{g.urls.length} URLs</td>
                      <td className="px-3 py-2 text-xs">{[...g.locations].join(', ')}</td>
                      <td className="px-3 py-2 text-xs font-mono">{[...g.methods].join(', ')}</td>
                    </tr>
                    {expanded && g.urls.map((p, i) => (
                      <tr key={`${g.name}-${i}`}
                        className="border-b border-border/30 hover:bg-muted/20 cursor-pointer bg-card/50 transition-colors"
                        onClick={() => setSelected(p)}
                      >
                        <td className="px-3 py-1.5"></td>
                        <td className="px-3 py-1.5 pl-8 font-mono text-xs text-muted-foreground truncate max-w-[300px]">{p.url_pattern}</td>
                        <td className="px-3 py-1.5 text-xs">{p.param_type}</td>
                        <td className="px-3 py-1.5 text-xs">{p.occurrence_count}</td>
                        <td className="px-3 py-1.5 text-xs font-mono text-muted-foreground truncate max-w-[150px]">
                          {p.sample_values?.slice(0, 2).join(', ') || '-'}
                        </td>
                        <td className="px-3 py-1.5 text-xs">{p.param_location}</td>
                        <td className="px-3 py-1.5 text-xs font-mono">{p.http_method}</td>
                      </tr>
                    ))}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <DataTable
          data={params}
          columns={columns}
          onRowClick={setSelected}
        />
      )}

      {/* Detail slide-over */}
      {selected && (
        <div className="fixed inset-y-0 right-0 w-[500px] bg-card border-l border-border shadow-xl z-50 overflow-y-auto">
          <div className="flex items-center justify-between p-4 border-b border-border">
            <h3 className="text-sm font-semibold">Parameter Detail</h3>
            <button onClick={() => setSelected(null)} className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="p-4 space-y-3">
            <h4 className="text-sm font-medium font-mono text-primary">{selected.param_name}</h4>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div><span className="text-muted-foreground">URL Pattern:</span> <span className="font-mono">{selected.url_pattern}</span></div>
              <div><span className="text-muted-foreground">Type:</span> {selected.param_type}</div>
              <div><span className="text-muted-foreground">Method:</span> {selected.http_method}</div>
              <div><span className="text-muted-foreground">Location:</span> {selected.param_location}</div>
              <div><span className="text-muted-foreground">Occurrences:</span> {selected.occurrence_count}</div>
              <div><span className="text-muted-foreground">Source:</span> {selected.discovery_source}</div>
              {selected.first_seen && <div><span className="text-muted-foreground">First Seen:</span> {formatDate(selected.first_seen)}</div>}
              {selected.last_seen && <div><span className="text-muted-foreground">Last Seen:</span> {formatDate(selected.last_seen)}</div>}
            </div>
            {selected.sample_values?.length > 0 && (
              <div>
                <h5 className="text-xs font-medium text-muted-foreground mb-1">Sample Values</h5>
                <div className="space-y-1">
                  {selected.sample_values.map((v, i) => (
                    <div key={i} className="text-xs font-mono bg-muted rounded px-2 py-1">{v}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Findings Tab ────────────────────────────────────────
function FindingsTab() {
  const PAGE_SIZE = 200
  const [filters, setFilters] = useState<ReconFilter>({ limit: PAGE_SIZE })
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<ReconFinding | null>(null)
  const [viewMode, setViewMode] = useState<'domains' | 'flat'>('domains')
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set())
  const globalScope = useUIStore(s => s.selectedScopeName)
  const [scopeFilterVal, setScopeFilterVal] = useState(globalScope || '')
  const { matchesScope, isFiltering: isScopeFiltering } = useScopeFilter(scopeFilterVal)

  // Sync with global engagement scope
  useEffect(() => {
    setScopeFilterVal(globalScope || '')
  }, [globalScope])

  // Clear selections on scope change
  useEffect(() => {
    setSelectedIds(new Set())
    setExpandedDomains(new Set())
  }, [scopeFilterVal])
  const paginatedFilters = useMemo(() => ({ ...filters, offset: page * PAGE_SIZE }), [filters, page])
  const { data, isLoading } = useReconFindings(paginatedFilters)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [showScopePopover, setShowScopePopover] = useState(false)
  const [scopeName, setScopeName] = useState('default')
  const scopeNames = useScopeNames()
  const addToScope = useAddToScope()
  const deleteReconFindings = useDeleteReconFindings()

  const allFindings = data?.findings ?? []
  const findings = useMemo(() => {
    if (!isScopeFiltering) return allFindings
    return allFindings.filter(f => matchesScope(f.target || f.hostname || ''))
  }, [allFindings, isScopeFiltering, matchesScope])
  const total = isScopeFiltering ? findings.length : (data?.total ?? 0)

  // Group findings by domain for the domain view
  type DomainGroup = { domain: string; findings: typeof findings; sources: Record<string, number>; types: Record<string, number>; count: number; lastSeen: string }
  const domainGroups = useMemo<DomainGroup[]>(() => {
    const map = new Map<string, typeof findings>()
    for (const f of findings) {
      // Extract base domain from target
      const target = f.target || f.hostname || ''
      const parts = target.split('.')
      const domain = parts.length >= 2 ? parts.slice(-2).join('.') : target
      if (!map.has(domain)) map.set(domain, [])
      map.get(domain)!.push(f)
    }
    return Array.from(map.entries()).map(([domain, items]) => {
      const sources: Record<string, number> = {}
      const types: Record<string, number> = {}
      let lastSeen = ''
      for (const f of items) {
        sources[f.source] = (sources[f.source] || 0) + 1
        types[f.finding_type] = (types[f.finding_type] || 0) + 1
        if (f.created_at && f.created_at > lastSeen) lastSeen = f.created_at
      }
      return { domain, findings: items, sources, types, count: items.length, lastSeen }
    }).sort((a, b) => b.count - a.count)
  }, [findings])

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === findings.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(findings.map(f => f.id)))
    }
  }

  const moveToScope = useMoveToScope()

  const handleAddToScope = () => {
    const targetItems = findings
      .filter(f => selectedIds.has(f.id))
      .map(f => ({
        target: f.target,
        target_type: inferTargetType(f),
        source: f.source,
      }))
    if (!targetItems.length) return

    // If scope filter is active, MOVE instead of just adding
    if (scopeFilterVal) {
      moveToScope.mutate(
        { fromScope: scopeFilterVal, toScope: scopeName, targets: targetItems.map(t => t.target) },
        {
          onSuccess: () => {
            setShowScopePopover(false)
            setSelectedIds(new Set())
          },
        },
      )
    } else {
      addToScope.mutate(
        { name: scopeName, targets: targetItems },
        {
          onSuccess: () => {
            setShowScopePopover(false)
            setSelectedIds(new Set())
          },
        },
      )
    }
  }

  const updateFilters = (next: ReconFilter) => {
    setFilters(next)
    setPage(0)
  }

  const toggleFilter = (key: 'source' | 'finding_type' | 'severity' | 'provider', value: string) => {
    const current = filters[key] || []
    const next = current.includes(value)
      ? current.filter(v => v !== value)
      : [...current, value]
    updateFilters({ ...filters, [key]: next.length ? next : undefined })
  }

  const columns = useMemo<ColumnDef<ReconFinding, unknown>[]>(() => [
    {
      id: 'select',
      size: 40,
      header: () => (
        <input
          type="checkbox"
          checked={findings.length > 0 && selectedIds.size === findings.length}
          onChange={toggleSelectAll}
          className="accent-primary"
        />
      ),
      cell: ({ row }) => (
        <input
          type="checkbox"
          checked={selectedIds.has(row.original.id)}
          onChange={(e) => { e.stopPropagation(); toggleSelect(row.original.id) }}
          onClick={(e) => e.stopPropagation()}
          className="accent-primary"
        />
      ),
    },
    { accessorKey: 'source', header: 'Source', size: 100, cell: ({ getValue }) => <SourceBadge source={String(getValue())} /> },
    { accessorKey: 'finding_type', header: 'Type', size: 100, cell: ({ getValue }) => <span className="text-xs">{String(getValue())}</span> },
    { accessorKey: 'target', header: 'Target', cell: ({ getValue }) => <span className="text-xs font-mono">{String(getValue())}</span> },
    {
      id: 'summary',
      header: 'Summary',
      cell: ({ row }) => <span className="text-xs text-muted-foreground truncate block max-w-md">{summarizeData(row.original.data)}</span>,
    },
    { accessorKey: 'resolved_ip', header: 'Resolved IP', size: 120, cell: ({ getValue }) => <span className="text-xs font-mono">{String(getValue() ?? '')}</span> },
    {
      accessorKey: 'severity',
      header: 'Severity',
      size: 90,
      cell: ({ getValue }) => {
        const v = String(getValue() ?? '')
        return v ? <SeverityBadge severity={v} /> : <span className="text-xs text-muted-foreground">-</span>
      },
    },
    {
      accessorKey: 'created_at',
      header: 'Date',
      size: 140,
      cell: ({ getValue }) => {
        const v = getValue()
        return <span className="text-xs text-muted-foreground">{v ? formatDate(String(v)) : ''}</span>
      },
    },
  ], [findings, selectedIds])

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <ScopeFilter value={scopeFilterVal} onChange={setScopeFilterVal} />
        <span className="text-xs text-muted-foreground">{total} findings{isScopeFiltering ? ` in ${scopeFilterVal}` : ''}</span>
      </div>

      {/* Filters — only show sources/types/providers that have findings.
          Each row gets its own pt-2 + border-t so wrapped chip lists from
          the row above don't bleed into the next label. */}
      <div className="space-y-1">
        <div className="flex flex-wrap gap-1.5 items-start py-1.5">
          <span className="text-xs font-medium text-muted-foreground py-1 w-16 shrink-0">Source:</span>
          <div className="flex flex-wrap gap-1.5 flex-1">
            {Object.entries(data?.aggregations?.by_source ?? {})
              .sort(([, a], [, b]) => b - a)
              .map(([s, count]) => {
              const active = filters.source?.includes(s)
              return (
                <button
                  key={s}
                  onClick={() => toggleFilter('source', s)}
                  className={cn(
                    'px-2.5 py-1 rounded-md text-sm font-mono font-medium border transition-colors',
                    active ? 'border-primary bg-primary/15 text-primary ring-1 ring-primary/30' : 'border-border bg-muted/50 text-foreground hover:border-primary/50',
                  )}
                >
                  {s} <span className={cn('ml-1 text-xs', active ? 'text-primary/70' : 'text-muted-foreground')}>{count.toLocaleString()}</span>
                </button>
              )
            })}
            {!data?.aggregations?.by_source || Object.keys(data.aggregations.by_source).length === 0 ? (
              <span className="text-xs text-muted-foreground py-1">No sources with findings</span>
            ) : null}
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5 items-start py-1.5 border-t border-border/40">
          <span className="text-xs font-medium text-muted-foreground py-1 w-16 shrink-0">Type:</span>
          <div className="flex flex-wrap gap-1.5 flex-1">
            {Object.entries(data?.aggregations?.by_finding_type ?? {})
              .sort(([, a], [, b]) => b - a)
              .map(([t, count]) => (
              <button
                key={t}
                onClick={() => toggleFilter('finding_type', t)}
                className={cn(
                  'px-2.5 py-1 rounded-md text-sm font-medium border transition-colors',
                  filters.finding_type?.includes(t) ? 'border-primary bg-primary/15 text-primary ring-1 ring-primary/30' : 'border-border bg-muted/50 text-foreground hover:border-primary/50',
                )}
              >
                {t} <span className={cn('ml-1 text-xs', filters.finding_type?.includes(t) ? 'text-primary/70' : 'text-muted-foreground')}>{count.toLocaleString()}</span>
              </button>
            ))}
            {!data?.aggregations?.by_finding_type || Object.keys(data.aggregations.by_finding_type).length === 0 ? (
              <span className="text-xs text-muted-foreground py-1">No types with findings</span>
            ) : null}
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5 items-start py-1.5 border-t border-border/40">
          <span className="text-xs font-medium text-muted-foreground py-1 w-16 shrink-0">Provider:</span>
          <div className="flex flex-wrap gap-1.5 flex-1">
            {Object.entries(data?.aggregations?.by_provider ?? {})
              .sort(([, a], [, b]) => b - a)
              .map(([p, count]) => (
              <button
                key={p}
                onClick={() => toggleFilter('provider', p)}
                className={cn(
                  'px-2.5 py-1 rounded-md text-sm font-medium border transition-colors capitalize',
                  filters.provider?.includes(p) ? 'border-primary bg-primary/15 text-primary ring-1 ring-primary/30' : 'border-border bg-muted/50 text-foreground hover:border-primary/50',
                )}
              >
                {p} <span className={cn('ml-1 text-xs', filters.provider?.includes(p) ? 'text-primary/70' : 'text-muted-foreground')}>{count.toLocaleString()}</span>
              </button>
            ))}
            {!data?.aggregations?.by_provider || Object.keys(data.aggregations.by_provider).length === 0 ? (
              <span className="text-xs text-muted-foreground py-1">No cloud-tagged assets in current scope</span>
            ) : null}
          </div>
        </div>
        <div className="flex gap-2">
          <input
            placeholder="Target filter"
            value={filters.target || ''}
            onChange={e => updateFilters({ ...filters, target: e.target.value || undefined })}
            className="bg-muted rounded-md px-3 py-1 text-sm border border-border outline-none focus:border-primary w-48"
          />
          <input
            placeholder="Free text search"
            value={filters.search || ''}
            onChange={e => updateFilters({ ...filters, search: e.target.value || undefined })}
            className="bg-muted rounded-md px-3 py-1 text-sm border border-border outline-none focus:border-primary flex-1"
          />
        </div>
      </div>

      {/* Bulk action bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 bg-primary/10 border border-primary/30 rounded-lg px-4 py-2 relative">
          <span className="text-sm font-medium">{selectedIds.size} selected</span>
          <button
            onClick={() => setShowScopePopover(!showScopePopover)}
            className="flex items-center gap-1.5 px-3 py-1 bg-primary text-primary-foreground rounded-md text-sm"
          >
            <Plus className="h-3.5 w-3.5" /> Add to Scope
          </button>
          <button
            onClick={() => {
              if (!selectedIds.size) return
              if (!window.confirm(`Delete ${selectedIds.size} recon finding(s)? This cannot be undone.`)) return
              deleteReconFindings.mutate([...selectedIds], { onSuccess: () => setSelectedIds(new Set()) })
            }}
            disabled={deleteReconFindings.isPending}
            className="flex items-center gap-1.5 px-3 py-1 text-xs text-red-400 border border-red-500/30 rounded hover:bg-red-500/10"
          >
            <Trash2 className="h-3 w-3" /> Delete
          </button>
          <button
            onClick={() => setSelectedIds(new Set())}
            className="text-xs text-muted-foreground hover:text-foreground ml-auto"
          >
            Clear
          </button>

          {/* Scope popover */}
          {showScopePopover && (
            <div className="absolute top-full left-0 mt-1 z-50 bg-card border border-border rounded-lg shadow-xl p-4 w-80 space-y-3">
              <h4 className="text-sm font-semibold">Add to Scope</h4>
              <input
                placeholder="Scope name"
                value={scopeName}
                onChange={e => setScopeName(e.target.value)}
                className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
              />
              {(scopeNames.data?.names ?? []).length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {scopeNames.data!.names.map(s => (
                    <button
                      key={s.name}
                      onClick={() => setScopeName(s.name)}
                      className={cn(
                        'px-2 py-0.5 rounded text-xs border',
                        scopeName === s.name ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground',
                      )}
                    >
                      {s.name} ({s.target_count})
                    </button>
                  ))}
                </div>
              )}
              <div className="flex gap-2">
                <button
                  onClick={handleAddToScope}
                  disabled={!scopeName.trim() || addToScope.isPending}
                  className="flex-1 flex items-center justify-center gap-1.5 py-1.5 bg-primary text-primary-foreground rounded-md text-sm disabled:opacity-50"
                >
                  <Check className="h-3.5 w-3.5" />
                  {addToScope.isPending ? 'Adding...' : `Add ${selectedIds.size} targets`}
                </button>
                <button
                  onClick={() => setShowScopePopover(false)}
                  className="px-3 py-1.5 border border-border rounded-md text-sm text-muted-foreground hover:text-foreground"
                >
                  Cancel
                </button>
              </div>
              {addToScope.error && (
                <p className="text-xs text-red-500">{String(addToScope.error)}</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* View toggle */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setViewMode('domains')}
          className={cn('px-2.5 py-1 text-xs rounded border', viewMode === 'domains' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground')}
        >Domains ({domainGroups.length})</button>
        <button
          onClick={() => setViewMode('flat')}
          className={cn('px-2.5 py-1 text-xs rounded border', viewMode === 'flat' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground')}
        >All Findings ({total})</button>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : viewMode === 'domains' ? (
        /* Domain-grouped view */
        <div className="border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground w-6"></th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">Domain</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{width:80}}>Findings</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">Sources</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">Types</th>
                <th className="px-3 py-2 text-left text-xs font-medium text-muted-foreground" style={{width:140}}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {domainGroups.map(g => {
                const expanded = expandedDomains.has(g.domain)
                return (
                  <Fragment key={g.domain}>
                    <tr
                      className="border-b border-border/50 hover:bg-muted/30 cursor-pointer transition-colors"
                      onClick={() => setExpandedDomains(prev => {
                        const n = new Set(prev); n.has(g.domain) ? n.delete(g.domain) : n.add(g.domain); return n
                      })}
                    >
                      <td className="px-3 py-2 text-muted-foreground">
                        {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                      </td>
                      <td className="px-3 py-2 font-mono font-medium text-sm">{g.domain}</td>
                      <td className="px-3 py-2">
                        <span className="px-1.5 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-medium">{g.count}</span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(g.sources).sort((a,b) => b[1]-a[1]).map(([src, cnt]) => (
                            <span key={src} className="inline-flex items-center gap-0.5">
                              <SourceBadge source={src} />
                              <span className="text-[10px] text-muted-foreground">{cnt}</span>
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(g.types).sort((a,b) => b[1]-a[1]).slice(0,5).map(([t, cnt]) => (
                            <span key={t} className="px-1 py-0.5 rounded text-[10px] bg-muted text-muted-foreground border border-border">{t} ({cnt})</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{g.lastSeen ? formatDate(g.lastSeen) : ''}</td>
                    </tr>
                    {expanded && g.findings.slice(0, 100).map((f, fi) => (
                      <tr
                        key={`${g.domain}-${fi}`}
                        className="border-b border-border/30 hover:bg-muted/20 cursor-pointer bg-card/50 transition-colors"
                        onClick={() => setSelected(f)}
                      >
                        <td className="px-3 py-1.5"></td>
                        <td className="px-3 py-1.5 pl-8 font-mono text-xs">{f.target}</td>
                        <td className="px-3 py-1.5">
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-muted border border-border">{f.finding_type}</span>
                        </td>
                        <td className="px-3 py-1.5"><SourceBadge source={f.source} /></td>
                        <td className="px-3 py-1.5 text-xs text-muted-foreground truncate max-w-[300px]">{summarizeData(f.data)}</td>
                        <td className="px-3 py-1.5 text-xs text-muted-foreground">{f.created_at ? formatDate(f.created_at) : ''}</td>
                      </tr>
                    ))}
                    {expanded && g.findings.length > 100 && (
                      <tr className="border-b border-border/30 bg-card/50">
                        <td colSpan={6} className="px-3 py-1.5 text-xs text-muted-foreground text-center">
                          Showing 100 of {g.findings.length} findings — use the flat view to see all
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        /* Flat findings view */
        <DataTable
          data={findings}
          columns={columns}
          onRowClick={setSelected}
        />
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-muted-foreground">
            Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
          </span>
          <div className="flex items-center gap-2">
            <button
              disabled={page === 0}
              onClick={() => setPage(p => p - 1)}
              className="flex items-center gap-1 px-2 py-1 rounded text-xs border border-border text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="h-3.5 w-3.5" /> Prev
            </button>
            <span className="text-xs text-muted-foreground">
              Page {page + 1} of {Math.ceil(total / PAGE_SIZE)}
            </span>
            <button
              disabled={(page + 1) * PAGE_SIZE >= total}
              onClick={() => setPage(p => p + 1)}
              className="flex items-center gap-1 px-2 py-1 rounded text-xs border border-border text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed"
            >
              Next <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Detail slide-over */}
      {selected && (
        <div className="fixed inset-y-0 right-0 w-[500px] bg-card border-l border-border shadow-xl z-50 overflow-y-auto">
          <div className="flex items-center justify-between p-4 border-b border-border">
            <h3 className="text-sm font-semibold">Recon Finding Detail</h3>
            <button onClick={() => setSelected(null)} className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="p-4 space-y-3">
            <div className="flex items-center gap-2">
              <SourceBadge source={selected.source} />
              <span className="text-xs text-muted-foreground">{selected.finding_type}</span>
              {selected.severity && <SeverityBadge severity={selected.severity} />}
            </div>
            <h4 className="text-sm font-medium font-mono">{selected.target}</h4>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {selected.resolved_ip && (
                <div><span className="text-muted-foreground">Resolved IP:</span> <span className="font-mono">{selected.resolved_ip}</span></div>
              )}
              {selected.hostname && (
                <div><span className="text-muted-foreground">Hostname:</span> <span className="font-mono">{selected.hostname}</span></div>
              )}
              {selected.created_at && (
                <div><span className="text-muted-foreground">Date:</span> {formatDate(selected.created_at)}</div>
              )}
            </div>
            {/* GoWitness screenshot preview + summary */}
            {selected.source === 'gowitness' && selected.data && (() => {
              const d = selected.data as Record<string, unknown>
              const sc = Number(d.status_code) || 0
              return (
                <>
                  {d.screenshot && (
                    <div>
                      <h5 className="text-xs font-medium text-muted-foreground mb-1">Screenshot</h5>
                      <a href={`${apiUrl}/screenshots/${String(d.screenshot)}`} target="_blank" rel="noopener noreferrer"
                        className="block border border-border rounded overflow-hidden hover:border-primary transition-colors">
                        <img src={`${apiUrl}/screenshots/${String(d.screenshot)}`} alt={selected.target}
                          className="w-full h-auto" loading="lazy" />
                      </a>
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    {sc > 0 && (
                      <div><span className="text-muted-foreground">Status:</span> <span className={`font-mono ${sc >= 200 && sc < 300 ? 'text-green-400' : sc >= 400 ? 'text-red-400' : ''}`}>{sc}</span></div>
                    )}
                    {d.title ? <div><span className="text-muted-foreground">Title:</span> {String(d.title)}</div> : null}
                    {d.server ? <div><span className="text-muted-foreground">Server:</span> <span className="font-mono">{String(d.server)}</span></div> : null}
                    {d.redirect_to ? <div className="col-span-2"><span className="text-muted-foreground">Redirected:</span> <span className="font-mono text-[10px]">{String(d.redirect_to)}</span></div> : null}
                    {d.url ? <div className="col-span-2"><span className="text-muted-foreground">URL:</span> <a href={String(d.url)} target="_blank" rel="noopener noreferrer" className="font-mono text-primary hover:underline text-[10px]">{String(d.url)}</a></div> : null}
                  </div>
                </>
              )
            })()}
            <div>
              <h5 className="text-xs font-medium text-muted-foreground mb-1">Data (JSONB)</h5>
              <pre className="text-[10px] bg-muted rounded p-2 overflow-x-auto max-h-96 whitespace-pre-wrap">
                {JSON.stringify(selected.data, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Screenshots Tab ──────────────────────────────────────

function ScreenshotsTab() {
  const [search, setSearch] = useState('')
  const { data, isLoading } = useScreenshots(search || undefined)
  const { data: allMetaData } = useAllScreenshotMetadata()
  const screenshots = data?.screenshots ?? []
  const [lightbox, setLightbox] = useState<string | null>(null)

  // Build a path->tags lookup from bulk metadata
  const metaByPath = useMemo(() => {
    const map = new Map<string, string[]>()
    for (const m of allMetaData?.metadata ?? []) {
      if (m.tags?.length) map.set(m.path, m.tags)
    }
    return map
  }, [allMetaData])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">{data?.total ?? 0} screenshots captured</span>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
        <input
          placeholder="Filter by domain or filename..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="w-full bg-muted rounded-md pl-8 pr-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
        />
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading screenshots...</p>
      ) : screenshots.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
          <Camera className="h-12 w-12 mb-3 opacity-30" />
          <p className="text-sm">No screenshots captured yet</p>
          <p className="text-xs mt-1">Run GoWitness or the Recon Pipeline to capture web page screenshots</p>
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4">
          {screenshots.map(sc => {
            const thumbTags = metaByPath.get(sc.path) || []
            return (
              <button
                key={sc.path}
                onClick={() => setLightbox(sc.path)}
                className="group border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-colors bg-card text-left"
              >
                <div className="aspect-video bg-muted overflow-hidden">
                  <img
                    src={apiUrl(`/screenshots/${sc.path}`)}
                    alt={sc.filename}
                    loading="lazy"
                    className="w-full h-full object-cover object-top group-hover:scale-105 transition-transform"
                    onError={e => { (e.target as HTMLImageElement).style.display = 'none' }}
                  />
                </div>
                <div className="px-2 py-1.5 space-y-0.5">
                  <span className="text-[10px] font-mono text-foreground truncate block">
                    {sc.filename.replace('.png', '').split('-').join('.')}
                  </span>
                  <span className="text-[9px] text-muted-foreground">{sc.directory}</span>
                  {thumbTags.length > 0 && (
                    <div className="flex flex-wrap gap-0.5 mt-0.5">
                      {thumbTags.slice(0, 3).map(t => (
                        <span key={t} className={cn('px-1 py-0 rounded text-[8px] border', TAG_COLORS[t] || TAG_COLOR_DEFAULT)}>{t}</span>
                      ))}
                      {thumbTags.length > 3 && <span className="text-[8px] text-muted-foreground">+{thumbTags.length - 3}</span>}
                    </div>
                  )}
                </div>
              </button>
            )
          })}
        </div>
      )}

      {/* Lightbox with tag panel */}
      {lightbox && (
        <ScreenshotLightbox
          path={lightbox}
          filename={screenshots.find(s => s.path === lightbox)?.filename ?? ''}
          directory={screenshots.find(s => s.path === lightbox)?.directory}
          onClose={() => setLightbox(null)}
        />
      )}
    </div>
  )
}

// ─── Screenshot Lightbox with Tag Panel ──────────────────

function ScreenshotLightbox({ path, filename, directory, onClose }: {
  path: string; filename: string; directory?: string; onClose: () => void
}) {
  const { data: metaData } = useScreenshotMetadata(path)
  const updateMeta = useUpdateScreenshotMetadata()
  const { data: suggestionsData } = useTagSuggestions()
  const scopeNames = useScopeNames()
  const addToScope = useAddToScope()
  const [tagInput, setTagInput] = useState('')
  const [scopeTarget, setScopeTarget] = useState('')
  const [scopeAdded, setScopeAdded] = useState(false)

  const currentTags = metaData?.metadata?.tags ?? []

  const handleAddTag = (tag: string) => {
    const newTags = [...new Set([...currentTags, tag])]
    updateMeta.mutate({ path, filename, directory, tags: newTags })
  }

  const handleRemoveTag = (tag: string) => {
    updateMeta.mutate({ path, filename, directory, tags: currentTags.filter((t: string) => t !== tag) })
  }

  const handleAddToScope = () => {
    // Extract domain from filename
    const domain = filename.replace('.png', '').replace(/^https?---/, '').replace(/-\d+$/, '').split('-').join('.')
    if (!domain || !scopeTarget) return
    addToScope.mutate({ name: scopeTarget, targets: [{ target: domain, target_type: 'domain', source: 'screenshot-tag' }] }, {
      onSuccess: () => {
        updateMeta.mutate({ path, filename, directory, added_to_scope: scopeTarget })
        setScopeAdded(true)
        setTimeout(() => setScopeAdded(false), 2000)
      },
    })
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" onClick={onClose}>
      <div className="relative max-w-5xl max-h-[90vh] w-full overflow-y-auto" onClick={e => e.stopPropagation()}>
        <button onClick={onClose} className="absolute -top-10 right-0 text-white hover:text-gray-300">
          <X className="h-6 w-6" />
        </button>
        <img src={apiUrl(`/screenshots/${path}`)} alt="Screenshot" className="w-full h-auto rounded-lg shadow-2xl" />
        <p className="text-xs text-gray-400 mt-2 text-center font-mono">
          {filename.replace('.png', '').split('-').join('.')}
        </p>

        {/* Tag panel */}
        <div className="mt-3 bg-card border border-border rounded-lg p-3 space-y-2">
          <h5 className="text-xs font-medium text-muted-foreground flex items-center gap-1">
            <Tag className="h-3 w-3" /> Tags
          </h5>
          <div className="flex flex-wrap gap-1">
            {currentTags.map((t: string) => (
              <span key={t} className={cn('px-2 py-0.5 text-[10px] rounded border flex items-center gap-1', TAG_COLORS[t] || TAG_COLOR_DEFAULT)}>
                {t}
                <button onClick={() => handleRemoveTag(t)} className="hover:text-foreground"><X className="h-2.5 w-2.5" /></button>
              </span>
            ))}
            {currentTags.length === 0 && <span className="text-[10px] text-muted-foreground">No tags</span>}
          </div>
          <div className="flex gap-1">
            <input placeholder="Add tag..." value={tagInput} onChange={e => setTagInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && tagInput.trim()) {
                  handleAddTag(tagInput.trim().toLowerCase())
                  setTagInput('')
                }
              }}
              className="flex-1 px-2 py-0.5 text-xs rounded border border-border bg-background" list="sc-tag-suggestions" />
            <datalist id="sc-tag-suggestions">
              {(suggestionsData?.tags ?? []).map(t => <option key={t} value={t} />)}
            </datalist>
          </div>
          <div className="flex flex-wrap gap-1">
            {PREDEFINED_TAGS.filter(t => !currentTags.includes(t)).slice(0, 6).map(t => (
              <button key={t} onClick={() => handleAddTag(t)}
                className={cn('px-1.5 py-0 text-[9px] rounded border hover:opacity-80', TAG_COLORS[t] || TAG_COLOR_DEFAULT)}>
                + {t}
              </button>
            ))}
          </div>

          {/* Scope assignment */}
          <div className="flex gap-2 pt-1 border-t border-border mt-2">
            <select value={scopeTarget} onChange={e => setScopeTarget(e.target.value)}
              className="flex-1 px-2 py-1 text-xs rounded border border-border bg-background">
              <option value="">Add to scope...</option>
              {(scopeNames.data?.names ?? []).map((n: any) => {
                const name = typeof n === 'string' ? n : n.name
                return <option key={name} value={name}>{name}</option>
              })}
            </select>
            <button disabled={!scopeTarget || addToScope.isPending} onClick={handleAddToScope}
              className="px-3 py-1 text-xs rounded bg-primary text-primary-foreground disabled:opacity-50">
              {scopeAdded ? 'Added!' : 'Add'}
            </button>
          </div>
          {metaData?.metadata?.added_to_scope && (
            <span className="text-[10px] text-muted-foreground">Scope: {metaData.metadata.added_to_scope}</span>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Domain Overview Tab ──────────────────────────────────

function DomainOverviewTab() {
  const [search, setSearch] = useState('')
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null)
  const [drilldownDomain, setDrilldownDomain] = useState<string | null>(null) // subdomain drill-down
  const [showExcluded, setShowExcluded] = useState(false)
  const { data: domainsData, isLoading: domainsLoading } = useReconDomains(search || undefined, showExcluded)
  // Load overview for drilldown (subdomain) or selected domain
  const activeDomain = drilldownDomain || selectedDomain
  const { data: overview, isLoading: overviewLoading } = useReconDomainOverview(activeDomain)
  const excludeDomain = useExcludeDomain()
  const restoreDomain = useRestoreDomain()

  const domains = domainsData?.domains ?? []

  const handleExclude = (domain: string) => {
    excludeDomain.mutate([domain], {
      onSuccess: () => {
        if (selectedDomain === domain) setSelectedDomain(null)
      },
    })
  }

  const handleRestore = (domain: string) => {
    restoreDomain.mutate([domain])
  }

  const autoAssign = useAutoAssignUnknownScope()

  return (
    <div className="flex gap-4 min-h-[600px]">
      {/* Left panel — domain list */}
      <div className="w-72 shrink-0 space-y-3">
        <div className="relative">
          <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            placeholder="Search domains..."
            value={search}
            onChange={e => { setSearch(e.target.value); setSelectedDomain(null) }}
            className="w-full bg-muted rounded-md pl-8 pr-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
          />
        </div>

        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
            <input
              type="checkbox"
              checked={showExcluded}
              onChange={e => setShowExcluded(e.target.checked)}
              className="rounded border-border"
            />
            Show excluded ({domainsData?.excluded_count ?? 0})
          </label>
          <button
            onClick={() => autoAssign.mutate()}
            disabled={autoAssign.isPending}
            className="ml-auto px-2 py-1 text-[10px] rounded border border-amber-500/30 text-amber-400 hover:bg-amber-500/10 disabled:opacity-50"
            title="Auto-assign discovered items not in any scope to unknown_scope"
          >
            {autoAssign.isPending ? 'Assigning...' : autoAssign.data ? `${autoAssign.data.added} added` : 'Auto-assign Unscoped'}
          </button>
        </div>

        {domainsLoading ? (
          <p className="text-xs text-muted-foreground">Loading domains...</p>
        ) : domains.length === 0 ? (
          <p className="text-xs text-muted-foreground">No domains found</p>
        ) : (
          <div className="space-y-1 max-h-[calc(100vh-310px)] overflow-y-auto">
            <p className="text-xs text-muted-foreground mb-2">{domainsData?.total ?? 0} domains</p>
            {domains.map(d => (
              <div
                key={d.domain}
                className={cn(
                  'rounded-lg border p-2.5 transition-colors group relative',
                  (d as any).excluded
                    ? 'border-red-500/30 bg-red-500/5 opacity-60'
                    : selectedDomain === d.domain
                    ? 'border-primary bg-primary/10'
                    : 'border-border hover:border-primary/50 bg-card',
                )}
              >
                <button
                  onClick={() => { setSelectedDomain(d.domain); setDrilldownDomain(null) }}
                  className="w-full text-left"
                >
                  <div className="flex items-center gap-2">
                    <Globe className="h-3.5 w-3.5 text-primary shrink-0" />
                    <span className="text-sm font-mono font-medium truncate">{d.domain}</span>
                    {(d as any).excluded && (
                      <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/20 text-red-400 shrink-0">excluded</span>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1.5 ml-5.5">
                    {d.subdomain_count > 0 && <span className="text-[10px] text-muted-foreground">{d.subdomain_count} subs</span>}
                    {d.dns_count > 0 && <span className="text-[10px] text-muted-foreground">{d.dns_count} DNS</span>}
                    {d.http_count > 0 && <span className="text-[10px] text-muted-foreground">{d.http_count} HTTP</span>}
                    {d.tls_count > 0 && <span className="text-[10px] text-muted-foreground">{d.tls_count} TLS</span>}
                    {d.ct_count > 0 && <span className="text-[10px] text-muted-foreground">{d.ct_count} CT</span>}
                    <span className="text-[10px] text-muted-foreground font-medium">{d.total} total</span>
                  </div>
                </button>
                {/* Exclude / Restore button */}
                <button
                  onClick={e => { e.stopPropagation(); (d as any).excluded ? handleRestore(d.domain) : handleExclude(d.domain) }}
                  className={cn(
                    'absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity text-[10px] px-1.5 py-0.5 rounded',
                    (d as any).excluded
                      ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                      : 'bg-red-500/20 text-red-400 hover:bg-red-500/30',
                  )}
                  title={(d as any).excluded ? 'Restore to scope' : 'Mark out of scope'}
                >
                  {(d as any).excluded ? 'Restore' : 'Exclude'}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Right panel — domain detail */}
      <div className="flex-1 min-w-0">
        {!selectedDomain ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <div className="text-center space-y-2">
              <Globe className="h-10 w-10 mx-auto opacity-30" />
              <p className="text-sm">Select a domain to view its recon overview</p>
            </div>
          </div>
        ) : overviewLoading ? (
          <p className="text-sm text-muted-foreground">Loading overview for {activeDomain}...</p>
        ) : overview ? (
          <>
            {/* Breadcrumb when drilling into subdomain */}
            {drilldownDomain && (
              <div className="flex items-center gap-2 mb-3 text-xs">
                <button onClick={() => setDrilldownDomain(null)} className="text-primary hover:underline font-mono">{selectedDomain}</button>
                <ChevronRight className="h-3 w-3 text-muted-foreground" />
                <span className="font-mono font-medium">{drilldownDomain}</span>
              </div>
            )}
            <DomainDetail overview={overview} onSubdomainClick={(sub) => setDrilldownDomain(sub)} parentDomain={drilldownDomain ? selectedDomain : undefined} />
          </>
        ) : null}
      </div>
    </div>
  )
}

function DomainDetail({ overview, onSubdomainClick, parentDomain }: {
  overview: import('@/api/recon').DomainOverview
  onSubdomainClick?: (subdomain: string) => void
  parentDomain?: string
}) {
  const [openSection, setOpenSection] = useState<string>('subdomains')
  const [subFilter, setSubFilter] = useState('')
  const [sitemapFilter, setSitemapFilter] = useState('')
  const { data: sitemapData } = useDomainSitemap(openSection === 'sitemap' ? overview.domain : null)
  const { data: svcEnumData } = useServiceEnumFindings(overview.domain)
  const launch = useLaunchScan()
  const scanThroughNode = useScanThroughNode()
  const defaultNodeId = useUIStore(s => s.defaultNodeId)
  const [reconLaunched, setReconLaunched] = useState(false)
  const stats = overview.stats
  const sourceEntries = Object.entries(stats.by_source).sort((a, b) => b[1] - a[1])
  const maxSource = sourceEntries.length > 0 ? sourceEntries[0][1] : 1
  const filteredSubs = subFilter
    ? overview.subdomains.filter(s => s.name.toLowerCase().includes(subFilter.toLowerCase()))
    : overview.subdomains

  const handlePassiveRecon = () => {
    const scanParams = { targets: overview.domain, include_cert_chain: true, include_spider: false }
    if (defaultNodeId) {
      scanThroughNode.mutate(
        { nodeId: defaultNodeId, scan_type: 'passive-recon', ...scanParams },
        { onSuccess: () => setReconLaunched(true) },
      )
    } else {
      launch.mutate(
        { type: 'passive-recon', params: scanParams },
        { onSuccess: () => setReconLaunched(true) },
      )
    }
  }
  const isLaunching = launch.isPending || scanThroughNode.isPending

  return (
    <div className="space-y-4 overflow-y-auto max-h-[calc(100vh-220px)]">
      {/* Summary header */}
      <div className="border border-border rounded-lg p-4 bg-card">
        <div className="flex items-center gap-2 mb-3">
          <Globe className="h-4 w-4 text-primary" />
          <h3 className="text-base font-semibold font-mono">{overview.domain}</h3>
          <button
            onClick={handlePassiveRecon}
            disabled={isLaunching || reconLaunched}
            className={cn(
              'ml-auto px-3 py-1 text-xs rounded flex items-center gap-1.5',
              reconLaunched
                ? 'border border-green-500/30 text-green-400 bg-green-500/10'
                : 'border border-border hover:bg-accent text-muted-foreground hover:text-foreground'
            )}
          >
            <Radar className="h-3.5 w-3.5" />
            {isLaunching ? 'Launching...' : reconLaunched ? 'Recon Launched' : defaultNodeId ? 'Passive Recon (via node)' : 'Passive Recon'}
          </button>
        </div>
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 mb-3">
          <div className="text-center">
            <div className="text-xl font-bold text-primary">{stats.total_findings}</div>
            <div className="text-[10px] text-muted-foreground">Recon Findings</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold">{overview.subdomains.length}</div>
            <div className="text-[10px] text-muted-foreground">Subdomains</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold">{overview.http_services.length}</div>
            <div className="text-[10px] text-muted-foreground">HTTP Services</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold">{overview.tls_certs.length + overview.ct_certs.length}</div>
            <div className="text-[10px] text-muted-foreground">Certificates</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold">{stats.web_findings_count ?? overview.web_findings?.length ?? 0}</div>
            <div className="text-[10px] text-muted-foreground">Web Findings</div>
          </div>
          <div className="text-center">
            <div className="text-xl font-bold">{(stats.content_extractions_count ?? 0) + (stats.playwright_findings_count ?? 0)}</div>
            <div className="text-[10px] text-muted-foreground">Content Intel</div>
          </div>
        </div>
        {stats.first_seen && (
          <div className="flex gap-4 text-xs text-muted-foreground">
            <span>First seen: {formatDate(stats.first_seen)}</span>
            {stats.last_seen && <span>Last seen: {formatDate(stats.last_seen)}</span>}
          </div>
        )}
        {/* Source distribution */}
        {sourceEntries.length > 0 && (
          <div className="mt-3 space-y-1">
            <span className="text-[10px] text-muted-foreground font-medium">Source Distribution</span>
            <div className="flex flex-wrap gap-2">
              {sourceEntries.map(([src, cnt]) => (
                <div key={src} className="flex items-center gap-1.5">
                  <div className="h-1.5 rounded-full bg-primary/60" style={{ width: `${Math.max(12, (cnt / maxSource) * 80)}px` }} />
                  <span className="text-[10px] text-muted-foreground">{src} ({cnt})</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Security Concerns Banner */}
      <SecurityConcernsBanner overview={overview} svcEnum={svcEnumData} />

      {/* Email & DNS Infrastructure (from service enumeration) */}
      {svcEnumData && (svcEnumData.email.length > 0 || svcEnumData.dns.length > 0) && (
        <div className="border border-border rounded-lg p-3 bg-card space-y-3">
          <h4 className="text-xs font-semibold flex items-center gap-1.5">
            <Mail className="h-3.5 w-3.5 text-primary" /> Service Enumeration
          </h4>

          {/* Email findings */}
          {svcEnumData.email.length > 0 && (
            <div className="space-y-1.5">
              {svcEnumData.email.map((f: any, i: number) => {
                const d = typeof f.data === 'string' ? JSON.parse(f.data) : f.data
                return (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className={cn(
                      'px-1.5 py-0.5 rounded text-[9px] font-medium border shrink-0',
                      f.severity === 'info' ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                        : f.severity === 'low' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        : 'bg-red-500/10 text-red-400 border-red-500/30',
                    )}>
                      {f.finding_type}
                    </span>
                    <div className="flex-1 min-w-0">
                      {f.finding_type === 'spf' && (
                        <span>SPF: <span className="font-medium">{d.assessment || (d.exists ? 'present' : 'missing')}</span>
                          {d.all_policy && <span className="text-muted-foreground ml-1">({d.all_policy})</span>}
                        </span>
                      )}
                      {f.finding_type === 'dmarc' && (
                        <span>DMARC: <span className="font-medium">{d.policy || (d.exists ? 'present' : 'missing')}</span>
                          {d.assessment && <span className="text-muted-foreground ml-1">({d.assessment})</span>}
                        </span>
                      )}
                      {f.finding_type === 'dkim' && (
                        <span>DKIM: <span className="font-medium">{d.exists ? `${(d.selectors_found || []).length} selectors` : 'not found'}</span></span>
                      )}
                      {f.finding_type === 'mx_server' && (
                        <span className="font-mono">{d.host} <span className="text-muted-foreground">pri:{d.priority} tls:{d.tls ? 'yes' : 'no'}{d.provider ? ` (${d.provider})` : ''}</span></span>
                      )}
                      {f.finding_type === 'email_security' && (
                        <span>Email Security Score: <span className="font-bold text-primary">{d.score}</span>
                          {d.providers?.length > 0 && <span className="text-muted-foreground ml-1">Providers: {d.providers.join(', ')}</span>}
                        </span>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {/* DNS findings */}
          {svcEnumData.dns.length > 0 && (
            <div className="space-y-1.5">
              {svcEnumData.dns.map((f: any, i: number) => {
                const d = typeof f.data === 'string' ? JSON.parse(f.data) : f.data
                return (
                  <div key={`dns-${i}`} className="flex items-start gap-2 text-xs">
                    <span className={cn(
                      'px-1.5 py-0.5 rounded text-[9px] font-medium border shrink-0',
                      f.finding_type === 'zone_transfer' ? 'bg-red-500/10 text-red-400 border-red-500/30'
                        : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
                    )}>
                      {f.finding_type}
                    </span>
                    <div className="flex-1 min-w-0">
                      {f.finding_type === 'zone_transfer' && d.vulnerable && (
                        <span className="text-red-400 font-medium">ZONE TRANSFER ALLOWED — {d.records_transferred} records exposed</span>
                      )}
                      {f.finding_type === 'nameserver' && (
                        <span className="font-mono">{d.host} {d.software && <span className="text-muted-foreground">({d.software})</span>}</span>
                      )}
                      {f.finding_type === 'dns_records' && (
                        <span>{Object.keys(d.records || {}).length} record types: {Object.keys(d.records || {}).join(', ')}</span>
                      )}
                      {f.finding_type === 'reverse_dns' && (
                        <span>{d.resolved} PTR records from {d.total_ips} IPs</span>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* Collapsible sections */}
      <SectionToggle
        id="subdomains"
        label="Subdomains"
        count={overview.subdomains.length}
        icon={<Wifi className="h-3.5 w-3.5" />}
        open={openSection === 'subdomains'}
        onToggle={() => setOpenSection(openSection === 'subdomains' ? '' : 'subdomains')}
      >
        {overview.subdomains.length === 0 ? (
          <p className="text-xs text-muted-foreground">No subdomains discovered</p>
        ) : (
          <div>
            <div className="px-2 pb-2">
              <input
                placeholder="Filter subdomains..."
                value={subFilter}
                onChange={e => setSubFilter(e.target.value)}
                className="w-full bg-background rounded px-2 py-1 text-xs border border-border outline-none focus:border-primary"
              />
              {subFilter && <span className="text-[10px] text-muted-foreground ml-1">{filteredSubs.length} of {overview.subdomains.length}</span>}
            </div>
            <div className="max-h-80 overflow-y-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="py-1.5 px-2 font-medium">Subdomain</th>
                    <th className="py-1.5 px-2 font-medium">Resolved IP</th>
                    <th className="py-1.5 px-2 font-medium">First Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSubs.map((s, i) => (
                    <tr key={i} className="border-b border-border/50 hover:bg-primary/10 cursor-pointer transition-colors"
                      onClick={() => onSubdomainClick?.(s.name)}
                      title={`Click to view details for ${s.name}`}
                    >
                      <td className="py-1.5 px-2 font-mono text-primary hover:underline">{s.name}</td>
                      <td className="py-1.5 px-2 font-mono text-muted-foreground">{s.resolved_ip || '-'}</td>
                      <td className="py-1.5 px-2 text-muted-foreground">{s.first_seen ? formatDate(s.first_seen) : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </SectionToggle>

      <SectionToggle
        id="dns"
        label="DNS Records"
        count={Object.values(overview.dns_records).reduce((a, b) => a + b.length, 0)}
        icon={<Server className="h-3.5 w-3.5" />}
        open={openSection === 'dns'}
        onToggle={() => setOpenSection(openSection === 'dns' ? '' : 'dns')}
      >
        {Object.keys(overview.dns_records).length === 0 ? (
          <p className="text-xs text-muted-foreground">No DNS records found</p>
        ) : (
          <div className="space-y-3 max-h-80 overflow-y-auto">
            {Object.entries(overview.dns_records).map(([rtype, entries]) => (
              <div key={rtype}>
                <h5 className="text-xs font-medium text-primary mb-1">{rtype.replace('dns_', '').toUpperCase()} ({entries.length})</h5>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border text-left text-muted-foreground">
                      <th className="py-1 px-2 font-medium">Target</th>
                      <th className="py-1 px-2 font-medium">Values</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(entries as DomainDnsEntry[]).map((e, i) => (
                      <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                        <td className="py-1 px-2 font-mono">{e.target}</td>
                        <td className="py-1 px-2 font-mono text-muted-foreground">
                          {Array.isArray(e.values) ? (e.values as string[]).join(', ') : JSON.stringify(e.values)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        )}
      </SectionToggle>

      <SectionToggle
        id="http"
        label="HTTP Services"
        count={overview.http_services.length}
        icon={<Globe className="h-3.5 w-3.5" />}
        open={openSection === 'http'}
        onToggle={() => setOpenSection(openSection === 'http' ? '' : 'http')}
      >
        {overview.http_services.length === 0 ? (
          <p className="text-xs text-muted-foreground">No HTTP services discovered</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">URL</th>
                  <th className="py-1.5 px-2 font-medium">Status</th>
                  <th className="py-1.5 px-2 font-medium">Title</th>
                  <th className="py-1.5 px-2 font-medium">Server</th>
                  <th className="py-1.5 px-2 font-medium">Tech</th>
                </tr>
              </thead>
              <tbody>
                {overview.http_services.map((s, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                    <td className="py-1.5 px-2 font-mono max-w-[250px] truncate">{s.url}</td>
                    <td className="py-1.5 px-2">
                      <span className={cn(
                        'px-1.5 py-0.5 rounded text-[10px] font-medium',
                        Number(s.status_code) >= 200 && Number(s.status_code) < 300 ? 'bg-green-400/10 text-green-400' :
                        Number(s.status_code) >= 300 && Number(s.status_code) < 400 ? 'bg-yellow-400/10 text-yellow-400' :
                        Number(s.status_code) >= 400 ? 'bg-red-400/10 text-red-400' : 'bg-muted text-muted-foreground'
                      )}>
                        {s.status_code || '-'}
                      </span>
                    </td>
                    <td className="py-1.5 px-2 max-w-[200px] truncate text-muted-foreground">{s.title || '-'}</td>
                    <td className="py-1.5 px-2 font-mono text-muted-foreground">{s.webserver || '-'}</td>
                    <td className="py-1.5 px-2 text-muted-foreground max-w-[150px] truncate">
                      {s.tech?.length ? s.tech.join(', ') : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionToggle>

      <ScreenshotGallery domain={overview.domain} httpServices={overview.http_services}
        open={openSection === 'screenshots'} onToggle={() => setOpenSection(openSection === 'screenshots' ? '' : 'screenshots')} />

      {/* Web Findings */}
      <SectionToggle
        id="web-findings"
        label="Web Findings"
        count={overview.web_findings?.length ?? 0}
        icon={<Globe className="h-3.5 w-3.5" />}
        open={openSection === 'web-findings'}
        onToggle={() => setOpenSection(openSection === 'web-findings' ? '' : 'web-findings')}
      >
        {!overview.web_findings?.length ? (
          <p className="text-xs text-muted-foreground">No web findings for this domain</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">URL</th>
                  <th className="py-1.5 px-2 font-medium">Source</th>
                  <th className="py-1.5 px-2 font-medium">Name</th>
                  <th className="py-1.5 px-2 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody>
                {overview.web_findings.map((w, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                    <td className="py-1.5 px-2 font-mono max-w-[300px] truncate">{w.url}</td>
                    <td className="py-1.5 px-2"><SourceBadge source={w.source} /></td>
                    <td className="py-1.5 px-2 text-muted-foreground max-w-[200px] truncate">{w.name || '-'}</td>
                    <td className="py-1.5 px-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                        w.severity === 'critical' || w.severity === 'high' ? 'bg-red-400/10 text-red-400' :
                        w.severity === 'medium' ? 'bg-yellow-400/10 text-yellow-400' :
                        w.severity === 'low' ? 'bg-blue-400/10 text-blue-400' :
                        'bg-muted text-muted-foreground'
                      }`}>{w.severity}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionToggle>

      {/* Discovered Parameters */}
      <SectionToggle
        id="params"
        label="Discovered Parameters"
        count={overview.discovered_params?.length ?? 0}
        icon={<Search className="h-3.5 w-3.5" />}
        open={openSection === 'params'}
        onToggle={() => setOpenSection(openSection === 'params' ? '' : 'params')}
      >
        {!overview.discovered_params?.length ? (
          <p className="text-xs text-muted-foreground">No parameters discovered for this domain</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">Parameter</th>
                  <th className="py-1.5 px-2 font-medium">Occurrences</th>
                  <th className="py-1.5 px-2 font-medium">Types</th>
                  <th className="py-1.5 px-2 font-medium">Location</th>
                </tr>
              </thead>
              <tbody>
                {overview.discovered_params.map((p, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                    <td className="py-1.5 px-2 font-mono font-medium text-primary">{p.name}</td>
                    <td className="py-1.5 px-2">{p.count}</td>
                    <td className="py-1.5 px-2 text-muted-foreground">
                      {p.types.length ? p.types.map(t => (
                        <span key={t} className="inline-block px-1 py-0.5 bg-muted rounded text-[10px] mr-1">{t}</span>
                      )) : '-'}
                    </td>
                    <td className="py-1.5 px-2 text-muted-foreground">
                      {p.locations.length ? p.locations.map(l => (
                        <span key={l} className="inline-block px-1 py-0.5 bg-muted rounded text-[10px] mr-1">{l}</span>
                      )) : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionToggle>

      {/* Sitemap */}
      <SectionToggle
        id="sitemap"
        label="Sitemap"
        count={sitemapData?.total_urls ?? 0}
        icon={<Globe className="h-3.5 w-3.5" />}
        open={openSection === 'sitemap'}
        onToggle={() => setOpenSection(openSection === 'sitemap' ? '' : 'sitemap')}
      >
        {!sitemapData?.urls?.length ? (
          <p className="text-xs text-muted-foreground">No URLs discovered — run content-recon or katana spider first</p>
        ) : (() => {
          const filtered = sitemapFilter
            ? sitemapData.urls.filter(u => u.path.toLowerCase().includes(sitemapFilter.toLowerCase()))
            : sitemapData.urls
          // Group by directory (first path segment)
          const dirs = new Map<string, typeof filtered>()
          for (const u of filtered) {
            const parts = u.path.split('/').filter(Boolean)
            const dir = parts.length > 1 ? '/' + parts[0] : '/'
            if (!dirs.has(dir)) dirs.set(dir, [])
            dirs.get(dir)!.push(u)
          }
          return (
            <div>
              <div className="px-2 pb-2 flex items-center gap-2">
                <input
                  placeholder="Filter paths..."
                  value={sitemapFilter}
                  onChange={e => setSitemapFilter(e.target.value)}
                  className="flex-1 bg-background rounded px-2 py-1 text-xs border border-border outline-none focus:border-primary"
                />
                <span className="text-[10px] text-muted-foreground whitespace-nowrap">{filtered.length} of {sitemapData.urls.length} paths</span>
              </div>
              <div className="max-h-96 overflow-y-auto px-2">
                {Array.from(dirs.entries()).map(([dir, urls]) => (
                  <div key={dir} className="mb-2">
                    <div className="flex items-center gap-1 text-xs font-semibold text-muted-foreground py-1 border-b border-border/50">
                      <span className="font-mono">{dir}/</span>
                      <span className="text-[10px] font-normal">({urls.length})</span>
                    </div>
                    {urls.map((u, i) => (
                      <div key={i} className="flex items-center gap-2 py-0.5 text-xs hover:bg-muted/50 rounded px-1 group">
                        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                          u.status_code && u.status_code >= 200 && u.status_code < 300 ? 'bg-green-500' :
                          u.status_code && u.status_code >= 300 && u.status_code < 400 ? 'bg-yellow-500' :
                          u.status_code && u.status_code >= 400 ? 'bg-red-500' : 'bg-gray-400'
                        }`} />
                        <span className="font-mono flex-1 min-w-0 truncate">{u.path}</span>
                        {u.status_code && <span className="text-[10px] text-muted-foreground">{u.status_code}</span>}
                        <SourceBadge source={u.source} />
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )
        })()}
      </SectionToggle>

      <SectionToggle
        id="tls"
        label="TLS Certificates"
        count={overview.tls_certs.length}
        icon={<Lock className="h-3.5 w-3.5" />}
        open={openSection === 'tls'}
        onToggle={() => setOpenSection(openSection === 'tls' ? '' : 'tls')}
      >
        {overview.tls_certs.length === 0 ? (
          <p className="text-xs text-muted-foreground">No TLS certificates found</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">Host</th>
                  <th className="py-1.5 px-2 font-medium">Subject CN</th>
                  <th className="py-1.5 px-2 font-medium">Issuer</th>
                  <th className="py-1.5 px-2 font-medium">Expires</th>
                  <th className="py-1.5 px-2 font-medium">Serial</th>
                </tr>
              </thead>
              <tbody>
                {overview.tls_certs.map((c, i) => {
                  const expired = c.not_after ? new Date(c.not_after) < new Date() : false
                  return (
                    <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                      <td className="py-1.5 px-2 font-mono">{c.host}</td>
                      <td className="py-1.5 px-2 font-mono text-muted-foreground">{c.subject_cn || '-'}</td>
                      <td className="py-1.5 px-2 text-muted-foreground">{c.issuer || '-'}</td>
                      <td className="py-1.5 px-2">
                        <span className={expired ? 'text-red-400 font-medium' : 'text-muted-foreground'}>
                          {c.not_after || '-'}{expired ? ' (EXPIRED)' : ''}
                        </span>
                      </td>
                      <td className="py-1.5 px-2 font-mono text-muted-foreground text-[10px]">{c.serial || '-'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </SectionToggle>

      <SectionToggle
        id="ct"
        label="CT Log Certificates"
        count={overview.ct_certs.length}
        icon={<FileText className="h-3.5 w-3.5" />}
        open={openSection === 'ct'}
        onToggle={() => setOpenSection(openSection === 'ct' ? '' : 'ct')}
      >
        {overview.ct_certs.length === 0 ? (
          <p className="text-xs text-muted-foreground">No CT log certificates found</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">Common Name</th>
                  <th className="py-1.5 px-2 font-medium">Issuer</th>
                  <th className="py-1.5 px-2 font-medium">Expires</th>
                  <th className="py-1.5 px-2 font-medium">Serial</th>
                </tr>
              </thead>
              <tbody>
                {overview.ct_certs.map((c, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                    <td className="py-1.5 px-2 font-mono">{c.common_name}</td>
                    <td className="py-1.5 px-2 text-muted-foreground">{c.issuer_name || '-'}</td>
                    <td className="py-1.5 px-2 text-muted-foreground">{c.not_after || '-'}</td>
                    <td className="py-1.5 px-2 font-mono text-muted-foreground text-[10px]">{c.serial || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionToggle>

      <SectionToggle
        id="asn"
        label="ASN Mappings"
        count={overview.asn_mappings?.length ?? 0}
        icon={<MapPin className="h-3.5 w-3.5" />}
        open={openSection === 'asn'}
        onToggle={() => setOpenSection(openSection === 'asn' ? '' : 'asn')}
      >
        {!overview.asn_mappings?.length ? (
          <p className="text-xs text-muted-foreground">No ASN mappings found</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">IP</th>
                  <th className="py-1.5 px-2 font-medium">ASN</th>
                  <th className="py-1.5 px-2 font-medium">Organization</th>
                  <th className="py-1.5 px-2 font-medium">Country</th>
                  <th className="py-1.5 px-2 font-medium">CIDR</th>
                </tr>
              </thead>
              <tbody>
                {overview.asn_mappings.map((a, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                    <td className="py-1.5 px-2 font-mono">{a.ip}</td>
                    <td className="py-1.5 px-2 font-mono text-primary">{a.asn || '-'}</td>
                    <td className="py-1.5 px-2 text-muted-foreground">{a.org || '-'}</td>
                    <td className="py-1.5 px-2 text-muted-foreground">{a.country || '-'}</td>
                    <td className="py-1.5 px-2 font-mono text-muted-foreground">{a.cidr || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionToggle>
    </div>
  )
}

function ScreenshotGallery({ domain, httpServices, open, onToggle }: {
  domain: string
  httpServices: import('@/api/recon').DomainHttpService[]
  open: boolean; onToggle: () => void
}) {
  const { data: screenshotsData } = useScreenshots(domain)
  const { data: allMetaData } = useAllScreenshotMetadata()
  const screenshots = screenshotsData?.screenshots ?? []
  const [lightbox, setLightbox] = useState<string | null>(null)

  const metaByPath = useMemo(() => {
    const map = new Map<string, string[]>()
    for (const m of allMetaData?.metadata ?? []) {
      if (m.tags?.length) map.set(m.path, m.tags)
    }
    return map
  }, [allMetaData])

  return (
    <>
      <SectionToggle
        id="screenshots"
        label="Screenshots"
        count={screenshots.length}
        icon={<Camera className="h-3.5 w-3.5" />}
        open={open}
        onToggle={onToggle}
      >
        {screenshots.length === 0 ? (
          <p className="text-xs text-muted-foreground">No screenshots available. Run GoWitness or the Recon Pipeline to capture web page screenshots.</p>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
            {screenshots.map((sc) => {
              const thumbTags = metaByPath.get(sc.path) || []
              return (
                <button
                  key={sc.path}
                  onClick={() => setLightbox(sc.path)}
                  className="group border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-colors bg-muted"
                >
                  <img
                    src={apiUrl(`/screenshots/${sc.path}`)}
                    alt={sc.filename}
                    loading="lazy"
                    className="w-full h-32 object-cover object-top"
                    onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
                  />
                  <div className="px-2 py-1.5">
                    <span className="text-[10px] font-mono text-muted-foreground truncate block group-hover:text-foreground">
                      {sc.filename.replace('.png', '').split('-').join('.')}
                    </span>
                    {thumbTags.length > 0 && (
                      <div className="flex flex-wrap gap-0.5 mt-0.5">
                        {thumbTags.slice(0, 3).map(t => (
                          <span key={t} className={cn('px-1 py-0 rounded text-[8px] border', TAG_COLORS[t] || TAG_COLOR_DEFAULT)}>{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </button>
              )
            })}
          </div>
        )}
      </SectionToggle>

      {/* Lightbox with tag panel */}
      {lightbox && (
        <ScreenshotLightbox
          path={lightbox}
          filename={screenshots.find(s => s.path === lightbox)?.filename ?? ''}
          directory={screenshots.find(s => s.path === lightbox)?.directory}
          onClose={() => setLightbox(null)}
        />
      )}
    </>
  )
}

function SectionToggle({
  id, label, count, icon, open, onToggle, children,
}: {
  id: string; label: string; count: number; icon: React.ReactNode
  open: boolean; onToggle: () => void; children: React.ReactNode
}) {
  return (
    <div className="border border-border rounded-lg bg-card overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 p-3 text-left hover:bg-muted/50 transition-colors"
      >
        <span className={cn('text-primary transition-transform', open ? 'rotate-90' : '')}>{icon}</span>
        <span className="text-sm font-medium">{label}</span>
        <span className="text-xs text-muted-foreground ml-auto">{count} entries</span>
        <ChevronRight className={cn('h-3.5 w-3.5 text-muted-foreground transition-transform', open ? 'rotate-90' : '')} />
      </button>
      {open && (
        <div className="border-t border-border p-3">
          {children}
        </div>
      )}
    </div>
  )
}

// ─── Security Concerns Banner ───────────────────────
function SecurityConcernsBanner({ overview, svcEnum }: {
  overview: import('@/api/recon').DomainOverview
  svcEnum?: { email: any[]; dns: any[] } | null
}) {
  const concerns: Array<{ level: 'high' | 'medium' | 'low'; text: string }> = []

  // Check service enum data for issues
  if (svcEnum) {
    for (const f of svcEnum.email) {
      const d = typeof f.data === 'string' ? JSON.parse(f.data) : f.data
      if (f.finding_type === 'spf' && !d.exists)
        concerns.push({ level: 'medium', text: 'No SPF record — email spoofing possible' })
      else if (f.finding_type === 'spf' && d.all_policy === '+all')
        concerns.push({ level: 'high', text: 'SPF allows all senders (+all) — email spoofing wide open' })
      else if (f.finding_type === 'spf' && d.assessment === 'softfail')
        concerns.push({ level: 'low', text: 'SPF uses softfail (~all) — spoofed emails may still deliver' })
      if (f.finding_type === 'dmarc' && !d.exists)
        concerns.push({ level: 'medium', text: 'No DMARC record — no email authentication enforcement' })
      else if (f.finding_type === 'dmarc' && d.policy === 'none')
        concerns.push({ level: 'low', text: 'DMARC policy is "none" — monitoring only, no enforcement' })
      if (f.finding_type === 'dkim' && !d.exists)
        concerns.push({ level: 'low', text: 'No DKIM selectors found — email integrity not verified' })
      if (f.finding_type === 'mx_server' && d.tls === false)
        concerns.push({ level: 'medium', text: `MX server ${d.host} does not support STARTTLS` })
    }
    for (const f of svcEnum.dns) {
      const d = typeof f.data === 'string' ? JSON.parse(f.data) : f.data
      if (f.finding_type === 'zone_transfer' && d.vulnerable)
        concerns.push({ level: 'high', text: `DNS zone transfer allowed — ${d.records_transferred || 'all'} records exposed` })
    }
  }

  // Check web findings from overview
  const webFindings = overview.web_findings || []
  const highSevCount = webFindings.filter((f: any) => f.severity === 'high' || f.severity === 'critical').length
  if (highSevCount > 0)
    concerns.push({ level: 'high', text: `${highSevCount} high/critical web finding${highSevCount > 1 ? 's' : ''}` })

  // Check for missing WAF
  const noWaf = webFindings.some((f: any) => /no waf|not detected|none/i.test(f.name || f.title || ''))
  if (noWaf)
    concerns.push({ level: 'low', text: 'No WAF detected — web application may be directly exposed' })

  if (concerns.length === 0) return null

  const highCount = concerns.filter(c => c.level === 'high').length
  const medCount = concerns.filter(c => c.level === 'medium').length

  return (
    <div className={cn(
      'border rounded-lg p-3',
      highCount > 0 ? 'border-red-500/50 bg-red-500/5' : medCount > 0 ? 'border-amber-500/50 bg-amber-500/5' : 'border-yellow-500/30 bg-yellow-500/5',
    )}>
      <h4 className="text-xs font-semibold flex items-center gap-1.5 mb-2">
        <AlertTriangle className={cn('h-3.5 w-3.5', highCount > 0 ? 'text-red-400' : 'text-amber-400')} />
        Security Concerns ({concerns.length})
      </h4>
      <div className="space-y-1">
        {concerns.map((c, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className={cn(
              'w-1.5 h-1.5 rounded-full shrink-0',
              c.level === 'high' ? 'bg-red-500' : c.level === 'medium' ? 'bg-amber-500' : 'bg-yellow-500',
            )} />
            <span className={c.level === 'high' ? 'text-red-400' : c.level === 'medium' ? 'text-amber-400' : 'text-muted-foreground'}>
              {c.text}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}


// ─── Extracted Metadata Tab ─────────────────────────
function MetadataTab() {
  const { data, isLoading } = useContentExtractions()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())

  const extractions = data?.extractions ?? []

  // Build metadata items from extractions
  const metadataItems = useMemo(() => {
    const items: Array<{
      id: string; url: string; type: string; source: string;
      data: Record<string, unknown>; names: string[]; created_at: string;
    }> = []

    for (const ext of extractions) {
      const meta = (ext as any).metadata || {}
      const fileMetadata = (ext as any).file_metadata
      const names = (ext as any).names

      // EXIF extractions (file_metadata is populated)
      if (fileMetadata && Array.isArray(fileMetadata) && fileMetadata.length > 0) {
        for (const fm of fileMetadata) {
          items.push({
            id: `${ext.id}-exif-${items.length}`,
            url: ext.url,
            type: 'exif',
            source: meta.source || 'exif_extraction',
            data: typeof fm === 'object' ? fm : { raw: fm },
            names: Array.isArray(names) ? names : [],
            created_at: ext.created_at || '',
          })
        }
      } else if (fileMetadata && typeof fileMetadata === 'object' && !Array.isArray(fileMetadata)) {
        items.push({
          id: `${ext.id}-exif`,
          url: ext.url,
          type: 'exif',
          source: meta.source || 'exif_extraction',
          data: fileMetadata,
          names: Array.isArray(names) ? names : [],
          created_at: ext.created_at || '',
        })
      }

      // PDF extractions
      if (meta.source === 'pdf_extraction') {
        items.push({
          id: `${ext.id}-pdf`,
          url: ext.url,
          type: 'pdf',
          source: 'pdf_extraction',
          data: { word_corpus_length: ((ext as any).word_corpus || '').length, ...meta },
          names: Array.isArray(names) ? names : [],
          created_at: ext.created_at || '',
        })
      }
    }

    return items
  }, [extractions])

  // Filter
  const q = search.toLowerCase()
  const filtered = metadataItems.filter(item => {
    if (typeFilter && item.type !== typeFilter) return false
    if (q) {
      const dataStr = JSON.stringify(item.data).toLowerCase()
      return item.url.toLowerCase().includes(q) || dataStr.includes(q) || item.names.some(n => n.toLowerCase().includes(q))
    }
    return true
  })

  const types = [...new Set(metadataItems.map(m => m.type))]
  const exifCount = metadataItems.filter(m => m.type === 'exif').length
  const pdfCount = metadataItems.filter(m => m.type === 'pdf').length
  const namesFound = [...new Set(metadataItems.flatMap(m => m.names).filter(Boolean))]

  const toggleExpand = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  // Key EXIF fields of interest to pentesters
  const INTERESTING_FIELDS = ['Artist', 'XPAuthor', 'Copyright', 'CameraOwnerName', 'Software', 'Make', 'Model', 'GPSLatitude', 'GPSLongitude', 'GPSInfo', 'DateTime', 'DateTimeOriginal']

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-card border border-border rounded-lg p-3 text-center">
          <div className="text-2xl font-semibold text-blue-400">{metadataItems.length}</div>
          <div className="text-xs text-muted-foreground">Total Metadata</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-3 text-center">
          <div className="text-2xl font-semibold text-cyan-400">{exifCount}</div>
          <div className="text-xs text-muted-foreground">EXIF Images</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-3 text-center">
          <div className="text-2xl font-semibold text-amber-400">{pdfCount}</div>
          <div className="text-xs text-muted-foreground">PDF Documents</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-3 text-center">
          <div className="text-2xl font-semibold text-green-400">{namesFound.length}</div>
          <div className="text-xs text-muted-foreground">Names Discovered</div>
        </div>
      </div>

      {/* Names discovered */}
      {namesFound.length > 0 && (
        <div className="bg-card border border-border rounded-lg p-3">
          <h3 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
            <Tag className="h-3.5 w-3.5 text-green-400" /> Discovered Names
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {namesFound.map(name => (
              <span key={name} className="px-2 py-0.5 bg-green-500/10 text-green-400 text-xs rounded border border-green-500/30">
                {name}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-[350px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search URL, field values, names..."
            className="w-full pl-8 pr-8 py-1.5 text-sm bg-background border border-border rounded-md"
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
        {types.map(t => (
          <button
            key={t}
            onClick={() => setTypeFilter(typeFilter === t ? '' : t)}
            className={cn(
              'px-2.5 py-1 text-xs rounded border',
              typeFilter === t ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground',
            )}
          >
            {t.toUpperCase()} ({metadataItems.filter(m => m.type === t).length})
          </button>
        ))}
      </div>

      {/* Results */}
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading metadata...</p>
      ) : filtered.length === 0 ? (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <FileText className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">
            {metadataItems.length === 0
              ? 'No metadata extracted yet. Run a Content Recon scan with EXIF/PDF extraction enabled.'
              : 'No results match your filters.'}
          </p>
        </div>
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden divide-y divide-border">
          {filtered.map(item => {
            const isExpanded = expandedIds.has(item.id)
            const interestingEntries = Object.entries(item.data).filter(([k]) => INTERESTING_FIELDS.includes(k))
            const otherEntries = Object.entries(item.data).filter(([k]) => !INTERESTING_FIELDS.includes(k))
            const hasGPS = !!(item.data as any).GPSLatitude || !!(item.data as any).GPSLongitude || !!(item.data as any).GPSInfo

            return (
              <div key={item.id} className="px-4 py-3">
                {/* Header */}
                <div className="flex items-center gap-2 mb-1.5">
                  <span className={cn(
                    'px-1.5 py-0.5 text-[10px] font-medium rounded border',
                    item.type === 'exif' ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30',
                  )}>
                    {item.type.toUpperCase()}
                  </span>
                  {hasGPS && (
                    <span className="px-1.5 py-0.5 text-[10px] font-medium rounded border bg-red-500/10 text-red-400 border-red-500/30 flex items-center gap-0.5">
                      <MapPin className="h-2.5 w-2.5" /> GPS
                    </span>
                  )}
                  {item.names.length > 0 && (
                    <span className="px-1.5 py-0.5 text-[10px] font-medium rounded border bg-green-500/10 text-green-400 border-green-500/30">
                      {item.names.join(', ')}
                    </span>
                  )}
                  <span className="font-mono text-xs text-muted-foreground truncate flex-1">{item.url}</span>
                  <span className="text-[10px] text-muted-foreground shrink-0">{item.created_at ? formatDate(item.created_at) : ''}</span>
                </div>

                {/* Interesting fields (always visible) */}
                {interestingEntries.length > 0 && (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-x-4 gap-y-0.5 mb-1">
                    {interestingEntries.map(([k, v]) => (
                      <div key={k} className="text-xs">
                        <span className="text-muted-foreground">{k}:</span>{' '}
                        <span className={cn('font-mono',
                          k.startsWith('GPS') ? 'text-red-400' :
                          ['Artist', 'XPAuthor', 'Copyright', 'CameraOwnerName'].includes(k) ? 'text-green-400' :
                          'text-foreground'
                        )}>
                          {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Expand for all fields */}
                {otherEntries.length > 0 && (
                  <>
                    <button
                      onClick={() => toggleExpand(item.id)}
                      className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-1"
                    >
                      <ChevronRight className={cn('h-3 w-3 transition-transform', isExpanded ? 'rotate-90' : '')} />
                      {isExpanded ? 'Hide' : 'Show'} all {otherEntries.length + interestingEntries.length} fields
                    </button>
                    {isExpanded && (
                      <div className="mt-1 bg-muted/30 rounded p-2 text-xs font-mono space-y-0.5 max-h-[300px] overflow-y-auto">
                        {[...interestingEntries, ...otherEntries].map(([k, v]) => (
                          <div key={k}>
                            <span className="text-muted-foreground">{k}:</span>{' '}
                            <span className="text-foreground">{typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
