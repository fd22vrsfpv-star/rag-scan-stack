import { useState, useMemo } from 'react'
import { useScopeIntelligence, useScopeAnalysis, useExcludeFromScope, useTagSuggestions, type ScopeIntelligenceData, type ScopeIntelDnsEntry, type ScopeAnalysisData } from '@/api/findings'
import { useScopeNames, useAddToScope } from '@/api/scope'
import { useScreenshots, useAllScreenshotMetadata, useScreenshotMetadata, useUpdateScreenshotMetadata } from '@/api/recon'
import { apiUrl } from '@/api/client'
import { Crosshair, Wifi, Server, Globe, Lock, FileText, ChevronRight, Cpu, Network, Layers, MapPin, Camera, X, Tag, Shield, Target, Eye, LogIn, Ban, Zap, AlertTriangle, Plus } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { PREDEFINED_TAGS, TAG_COLORS, TAG_COLOR_DEFAULT } from '@/lib/constants'
import { useUIStore } from '@/stores/ui'
import {
  useScopeSuggestions, useClassifyUnknown, useAcceptSuggestion, useRejectSuggestion,
  useBulkAcceptSuggestions, useScopeClassificationRules, useCreateClassificationRule,
  useDeleteClassificationRule, useLearnRules,
  type ScopeSuggestion, type ScopeClassificationRule,
} from '@/api/scope'
import { SourceBadge } from '@/components/common/SourceBadge'

export default function ScopeIntelligence() {
  const globalScope = useUIStore(s => s.selectedScopeName)
  const setGlobalScope = useUIStore(s => s.setSelectedScope)
  const { data: scopeData } = useScopeNames()
  const scopes = (scopeData?.names ?? []).map((n: any) => typeof n === 'string' ? n : n.name)
  const selected = globalScope || scopes[0] || 'default'
  const setSelected = (name: string) => setGlobalScope(name || null)
  const { data: intel, isLoading } = useScopeIntelligence(selected)
  const [showAnalysis, setShowAnalysis] = useState(false)
  const [showAutoClassify, setShowAutoClassify] = useState(false)
  const { data: analysis, isLoading: analysisLoading } = useScopeAnalysis(showAnalysis ? selected : undefined)
  const [techFilter, setTechFilter] = useState<string | null>(null)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Crosshair className="h-5 w-5" /> Scope Intelligence
        </h2>
        <div className="flex items-center gap-2">
          <select value={selected} onChange={e => setSelected(e.target.value)}
            className="h-8 px-3 text-sm rounded border border-border bg-background">
            {scopes.map((s: string) => <option key={s} value={s}>{s}</option>)}
            {scopes.length === 0 && <option value="default">default</option>}
          </select>
          <button
            onClick={() => setShowAutoClassify(!showAutoClassify)}
            className={cn(
              'px-3 py-1.5 text-xs rounded flex items-center gap-1.5',
              showAutoClassify
                ? 'bg-amber-500 text-white'
                : 'border border-amber-500/30 text-amber-400 hover:bg-amber-500/10'
            )}
          >
            <Cpu className="h-3.5 w-3.5" /> Auto-Classify
          </button>
          <button
            onClick={() => setShowAnalysis(!showAnalysis)}
            className={cn(
              'px-3 py-1.5 text-xs rounded flex items-center gap-1.5',
              showAnalysis
                ? 'bg-primary text-primary-foreground'
                : 'border border-border hover:bg-muted/50'
            )}
          >
            <Target className="h-3.5 w-3.5" />
            {showAnalysis ? 'Hide Analysis' : 'Conduct Recon Analysis'}
          </button>
        </div>
      </div>

      {techFilter && (
        <div className="flex items-center gap-2 px-3 py-2 rounded border border-primary/30 bg-primary/5">
          <Cpu className="h-3.5 w-3.5 text-primary" />
          <span className="text-xs">Filtering by technology: <strong>{techFilter}</strong></span>
          <button onClick={() => setTechFilter(null)} className="ml-auto px-2 py-0.5 text-xs rounded border border-border hover:bg-muted">
            Clear filter
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading intelligence data...</div>
      ) : !intel || intel.stats.total_findings === 0 ? (
        <div className="text-sm text-muted-foreground">No recon data available for scope "{selected}". Run a recon pipeline to populate.</div>
      ) : (
        <>
          {showAnalysis && (
            analysisLoading ? (
              <div className="text-sm text-muted-foreground">Analyzing scope data...</div>
            ) : analysis ? (
              <AnalysisPanel analysis={analysis} />
            ) : null
          )}
          {showAutoClassify && <AutoClassifyPanel />}
          <IntelView intel={intel} techFilter={techFilter} setTechFilter={setTechFilter} techIndex={analysis?.technology_index} scopeNames={scopes} currentScope={selected} />
        </>
      )}
    </div>
  )
}

function IntelView({ intel, techFilter, setTechFilter, techIndex, scopeNames, currentScope }: {
  intel: ScopeIntelligenceData
  techFilter: string | null
  setTechFilter: (t: string | null) => void
  techIndex?: Record<string, { urls: string[]; ips: string[]; subdomains: string[] }>
  scopeNames: string[]
  currentScope: string
}) {
  const [openSection, setOpenSection] = useState<string>('subdomains')
  const excludeFromScope = useExcludeFromScope()
  const addToScope = useAddToScope()
  const [localExcluded, setLocalExcluded] = useState<Set<string>>(new Set())
  const [addedToScope, setAddedToScope] = useState<Map<string, string>>(new Map())
  const [scopePickerFor, setScopePickerFor] = useState<string | null>(null)
  const [searchFilter, setSearchFilter] = useState('')
  const stats = intel.stats
  const sourceEntries = Object.entries(stats.by_source).sort((a, b) => b[1] - a[1])
  const maxSource = sourceEntries.length > 0 ? sourceEntries[0][1] : 1

  // Tech filter: build sets of matching URLs/IPs/subdomains
  const filterUrls = useMemo(() => {
    if (!techFilter || !techIndex?.[techFilter]) return null
    return new Set(techIndex[techFilter].urls)
  }, [techFilter, techIndex])
  const filterIps = useMemo(() => {
    if (!techFilter || !techIndex?.[techFilter]) return null
    return new Set(techIndex[techFilter].ips)
  }, [techFilter, techIndex])

  // Parse search filter: supports "+term" (must include), "-term" (must exclude), plain text
  const parsedFilters = useMemo(() => {
    if (!searchFilter.trim()) return null
    const tokens = searchFilter.trim().split(/\s+/)
    const include: string[] = []
    const exclude: string[] = []
    for (const tok of tokens) {
      if (tok.startsWith('-') && tok.length > 1) {
        exclude.push(tok.slice(1).toLowerCase())
      } else if (tok.startsWith('+') && tok.length > 1) {
        include.push(tok.slice(1).toLowerCase())
      } else {
        include.push(tok.toLowerCase())
      }
    }
    return { include, exclude }
  }, [searchFilter])

  const matchesFilter = (text: string): boolean => {
    if (!parsedFilters) return true
    const lower = text.toLowerCase()
    if (parsedFilters.exclude.some(ex => lower.includes(ex))) return false
    if (parsedFilters.include.length > 0 && !parsedFilters.include.some(inc => lower.includes(inc))) return false
    return true
  }

  // Filtered data — apply tech filter, then search filter
  const filteredHttpServices = useMemo(() => {
    let items = intel.http_services
    if (techFilter) items = items.filter(s => s.tech?.includes(techFilter) || filterUrls?.has(s.url))
    if (parsedFilters) items = items.filter(s => matchesFilter(s.url) || matchesFilter(s.title || '') || matchesFilter(s.webserver || ''))
    return items
  }, [intel.http_services, techFilter, filterUrls, parsedFilters])

  const filteredSubdomains = useMemo(() => {
    let items = intel.subdomains
    if (techFilter && filterIps) items = items.filter(s => filterIps.has(s.resolved_ip))
    if (parsedFilters) items = items.filter(s => matchesFilter(s.name) || matchesFilter(s.resolved_ip || ''))
    return items
  }, [intel.subdomains, techFilter, filterIps, parsedFilters])

  const filteredIpAddresses = useMemo(() => {
    if (!parsedFilters) return intel.ip_addresses
    return intel.ip_addresses.filter(ip => matchesFilter(ip))
  }, [intel.ip_addresses, parsedFilters])

  const handleExclude = (target: string) => {
    excludeFromScope.mutate({ targets: [target], source: 'scope-intel' })
    setLocalExcluded(prev => new Set(prev).add(target))
  }

  const handleAddToScope = (subdomain: string, scopeName: string) => {
    addToScope.mutate({
      name: scopeName,
      targets: [{ target: subdomain, target_type: 'domain', source: 'scope-intel' }],
    }, {
      onSuccess: () => {
        setAddedToScope(prev => new Map(prev).set(subdomain, scopeName))
        setScopePickerFor(null)
      },
    })
  }

  return (
    <div className="space-y-4 overflow-y-auto max-h-[calc(100vh-180px)]">
      {/* Summary header */}
      <div className="border border-border rounded-lg p-4 bg-card">
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          <StatCard label="Total Findings" value={stats.total_findings} primary />
          <StatCard label="Domains" value={intel.domains.length} />
          <StatCard label="Subdomains" value={intel.subdomains.length} />
          <StatCard label="HTTP Services" value={intel.http_services.length} />
          <StatCard label="TLS Certs" value={intel.tls_certs.length} />
          <StatCard label="WHOIS" value={intel.whois_records?.length ?? 0} />
          <StatCard label="WAF Detections" value={intel.waf_detections?.length ?? 0} />
          <StatCard label="IP Addresses" value={intel.ip_addresses.length} />
          <StatCard label="Technologies" value={intel.technologies.length} />
        </div>

        {stats.first_seen && (
          <div className="flex gap-4 text-xs text-muted-foreground mt-3">
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

      {/* Search filter */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <input
            value={searchFilter}
            onChange={e => setSearchFilter(e.target.value)}
            placeholder="Filter subdomains & IPs... (prefix with + to include, - to exclude, e.g. +api -cdn)"
            className="w-full h-8 px-3 text-xs rounded border border-border bg-background placeholder:text-muted-foreground/60"
          />
          {searchFilter && (
            <button onClick={() => setSearchFilter('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
              <X className="h-3 w-3" />
            </button>
          )}
        </div>
        {searchFilter && (
          <span className="text-[10px] text-muted-foreground whitespace-nowrap">
            {filteredSubdomains.length} subdomains, {filteredIpAddresses.length} IPs
          </span>
        )}
      </div>

      {/* Domains + IPs inline cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Domains list */}
        <div className="border border-border rounded-lg p-3 bg-card">
          <h4 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1.5">
            <Globe className="h-3.5 w-3.5 text-primary" /> Scope Domains ({intel.domains.length})
          </h4>
          {intel.domains.length === 0 ? (
            <p className="text-xs text-muted-foreground">No domains</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {intel.domains.map(d => (
                <span key={d} className="px-2 py-0.5 rounded text-xs font-mono border border-primary/30 bg-primary/5 text-primary">{d}</span>
              ))}
            </div>
          )}
        </div>

        {/* IPs + Open Services */}
        <div className="border border-border rounded-lg p-3 bg-card">
          <h4 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1.5">
            <Network className="h-3.5 w-3.5 text-primary" /> IPs ({filteredIpAddresses.length}) & Services ({Object.values(intel.open_services).reduce((a, b) => a + b, 0)})
          </h4>
          <div className="flex gap-4">
            <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto flex-1">
              {filteredIpAddresses.slice(0, 30).map(ip => (
                <span key={ip} className="text-[10px] font-mono text-muted-foreground">{ip}</span>
              ))}
              {filteredIpAddresses.length > 30 && (
                <span className="text-[10px] text-muted-foreground">+{filteredIpAddresses.length - 30} more</span>
              )}
              {filteredIpAddresses.length === 0 && <span className="text-xs text-muted-foreground">No IPs{searchFilter ? ' match filter' : ' resolved'}</span>}
            </div>
            {Object.keys(intel.open_services).length > 0 && (
              <div className="space-y-0.5 border-l border-border pl-3 min-w-[140px]">
                {Object.entries(intel.open_services).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([svc, cnt]) => (
                  <div key={svc} className="flex items-center justify-between text-[10px]">
                    <span>{svc}</span>
                    <span className="text-muted-foreground ml-2">{cnt}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Technologies inline if any */}
      {intel.technologies.length > 0 && (
        <div className="border border-border rounded-lg p-3 bg-card">
          <h4 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1.5">
            <Cpu className="h-3.5 w-3.5 text-primary" /> Technology Stack ({intel.technologies.length})
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {intel.technologies.map((t, i) => (
              <button key={i} onClick={() => setTechFilter(techFilter === t.name ? null : t.name)}
                className={cn(
                  'px-2 py-0.5 rounded text-xs border transition-colors cursor-pointer',
                  techFilter === t.name
                    ? 'border-primary bg-primary/15 text-primary font-medium'
                    : 'border-border bg-muted/50 hover:border-primary/50'
                )}>
                {t.name} <span className="text-muted-foreground">x{t.count}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Collapsible detail sections */}
      <Section
        id="subdomains" label="Subdomains" count={filteredSubdomains.length}
        icon={<Wifi className="h-3.5 w-3.5" />}
        open={openSection === 'subdomains'} onToggle={() => setOpenSection(openSection === 'subdomains' ? '' : 'subdomains')}
      >
        {filteredSubdomains.length === 0 ? (
          <p className="text-xs text-muted-foreground">No subdomains discovered</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">Subdomain</th>
                  <th className="py-1.5 px-2 font-medium">Resolved IP</th>
                  <th className="py-1.5 px-2 font-medium">First Seen</th>
                  <th className="py-1.5 px-2 font-medium w-8"></th>
                </tr>
              </thead>
              <tbody>
                {filteredSubdomains.map((s, i) => (
                  <tr key={i} className={cn('border-b border-border/50 hover:bg-muted/50', localExcluded.has(s.name) && 'opacity-40')}>
                    <td className="py-1.5 px-2 font-mono">{s.name}</td>
                    <td className="py-1.5 px-2 font-mono text-muted-foreground">{s.resolved_ip || '-'}</td>
                    <td className="py-1.5 px-2 text-muted-foreground">{s.first_seen ? formatDate(s.first_seen) : '-'}</td>
                    <td className="py-1.5 px-2">
                      <div className="flex items-center gap-1 relative">
                        {addedToScope.has(s.name) ? (
                          <span className="text-[9px] text-green-400 whitespace-nowrap">+ {addedToScope.get(s.name)}</span>
                        ) : (
                          <button onClick={() => setScopePickerFor(scopePickerFor === s.name ? null : s.name)}
                            title="Add to scope"
                            className="text-muted-foreground hover:text-primary transition-colors">
                            <Plus className="h-3 w-3" />
                          </button>
                        )}
                        {!localExcluded.has(s.name) && !addedToScope.has(s.name) && (
                          <button onClick={() => handleExclude(s.name)} title="Mark out-of-scope"
                            className="text-muted-foreground hover:text-orange-400 transition-colors">
                            <Ban className="h-3 w-3" />
                          </button>
                        )}
                        {scopePickerFor === s.name && (
                          <div className="absolute right-0 top-full mt-1 z-20 bg-card border border-border rounded shadow-lg p-1.5 min-w-[140px]">
                            <p className="text-[9px] text-muted-foreground mb-1 px-1">Add to scope:</p>
                            {scopeNames.map(sc => (
                              <button key={sc} onClick={() => handleAddToScope(s.name, sc)}
                                className={cn(
                                  'block w-full text-left px-2 py-1 text-[11px] rounded hover:bg-muted/50 transition-colors',
                                  sc === currentScope && 'font-medium text-primary'
                                )}>
                                {sc}{sc === currentScope ? ' (current)' : ''}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section
        id="dns" label="DNS Records"
        count={Object.values(intel.dns_records).reduce((a, b) => a + b.length, 0)}
        icon={<Server className="h-3.5 w-3.5" />}
        open={openSection === 'dns'} onToggle={() => setOpenSection(openSection === 'dns' ? '' : 'dns')}
      >
        {Object.keys(intel.dns_records).length === 0 ? (
          <p className="text-xs text-muted-foreground">No DNS records found</p>
        ) : (
          <div className="space-y-3 max-h-80 overflow-y-auto">
            {Object.entries(intel.dns_records).map(([rtype, entries]) => (
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
                    {(entries as ScopeIntelDnsEntry[]).map((e, i) => (
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
      </Section>

      <Section
        id="http" label="HTTP Services" count={filteredHttpServices.length}
        icon={<Globe className="h-3.5 w-3.5" />}
        open={openSection === 'http'} onToggle={() => setOpenSection(openSection === 'http' ? '' : 'http')}
      >
        {filteredHttpServices.length === 0 ? (
          <p className="text-xs text-muted-foreground">No HTTP services discovered{techFilter ? ' (for this technology)' : ''}</p>
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
                  <th className="py-1.5 px-2 font-medium w-8"></th>
                </tr>
              </thead>
              <tbody>
                {filteredHttpServices.map((s, i) => {
                  let hostname = ''
                  try { hostname = new URL(s.url).hostname } catch {}
                  return (
                    <tr key={i} className={cn('border-b border-border/50 hover:bg-muted/50', localExcluded.has(hostname) && 'opacity-40')}>
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
                      <td className="py-1.5 px-2">
                        {hostname && !localExcluded.has(hostname) && (
                          <button onClick={() => handleExclude(hostname)} title="Mark out-of-scope"
                            className="text-muted-foreground hover:text-orange-400 transition-colors">
                            <Ban className="h-3 w-3" />
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <ScreenshotsSection
        open={openSection === 'screenshots'}
        onToggle={() => setOpenSection(openSection === 'screenshots' ? '' : 'screenshots')}
        domains={intel.domains}
      />

      <Section
        id="tls" label="TLS Certificates" count={intel.tls_certs.length}
        icon={<Lock className="h-3.5 w-3.5" />}
        open={openSection === 'tls'} onToggle={() => setOpenSection(openSection === 'tls' ? '' : 'tls')}
      >
        {intel.tls_certs.length === 0 ? (
          <p className="text-xs text-muted-foreground">No TLS certificates found</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">Host</th>
                  <th className="py-1.5 px-2 font-medium">Subject CN</th>
                  <th className="py-1.5 px-2 font-medium">Serial</th>
                  <th className="py-1.5 px-2 font-medium">Issuer</th>
                  <th className="py-1.5 px-2 font-medium">Expires</th>
                  <th className="py-1.5 px-2 font-medium">Serial</th>
                </tr>
              </thead>
              <tbody>
                {intel.tls_certs.map((c, i) => {
                  const expired = c.not_after ? new Date(c.not_after) < new Date() : false
                  return (
                    <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                      <td className="py-1.5 px-2 font-mono">{c.host}</td>
                      <td className="py-1.5 px-2 font-mono text-muted-foreground">{c.subject_cn || '-'}</td>
                      <td className="py-1.5 px-2 font-mono text-muted-foreground text-[10px]">{c.serial || '-'}</td>
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
      </Section>

      <Section
        id="ct" label="CT Log Certificates" count={intel.ct_certs.length}
        icon={<FileText className="h-3.5 w-3.5" />}
        open={openSection === 'ct'} onToggle={() => setOpenSection(openSection === 'ct' ? '' : 'ct')}
      >
        {intel.ct_certs.length === 0 ? (
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
                {intel.ct_certs.map((c, i) => (
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
      </Section>

      <Section
        id="asn" label="ASN Mappings" count={intel.asn_mappings?.length ?? 0}
        icon={<MapPin className="h-3.5 w-3.5" />}
        open={openSection === 'asn'} onToggle={() => setOpenSection(openSection === 'asn' ? '' : 'asn')}
      >
        {!intel.asn_mappings?.length ? (
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
                {intel.asn_mappings.map((a, i) => (
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
      </Section>

      {/* WHOIS Records */}
      <Section
        id="whois" label="WHOIS Records" count={intel.whois_records?.length ?? 0}
        icon={<FileText className="h-3.5 w-3.5" />}
        open={openSection === 'whois'} onToggle={() => setOpenSection(openSection === 'whois' ? '' : 'whois')}
      >
        {!intel.whois_records?.length ? (
          <p className="text-xs text-muted-foreground">No WHOIS data. Run the passive recon pipeline or a standalone WHOIS scan.</p>
        ) : (
          <div className="space-y-3">
            {intel.whois_records.map((w, i) => (
              <div key={i} className="border border-border rounded p-3 bg-accent/10">
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-mono font-medium text-sm">{w.domain}</span>
                  {w.registrant_country && (
                    <span className="px-1.5 py-0.5 bg-accent rounded text-[10px]">{w.registrant_country}</span>
                  )}
                </div>
                <div className="grid grid-cols-2 lg:grid-cols-3 gap-x-4 gap-y-1 text-xs">
                  {w.registrar && <div><span className="text-muted-foreground">Registrar:</span> {w.registrar}</div>}
                  {w.org && <div><span className="text-muted-foreground">Org:</span> {w.org}</div>}
                  {w.creation_date && <div><span className="text-muted-foreground">Created:</span> {w.creation_date}</div>}
                  {w.expiry_date && <div><span className="text-muted-foreground">Expires:</span> {w.expiry_date}</div>}
                  {w.registrant_name && <div><span className="text-muted-foreground">Registrant:</span> {w.registrant_name}</div>}
                  {w.registrant_email && <div><span className="text-muted-foreground">Email:</span> <span className="font-mono">{w.registrant_email}</span></div>}
                  {w.dnssec && <div><span className="text-muted-foreground">DNSSEC:</span> {w.dnssec}</div>}
                </div>
                {w.name_servers && w.name_servers.length > 0 && (
                  <div className="mt-1.5 text-xs">
                    <span className="text-muted-foreground">Name Servers:</span>{' '}
                    <span className="font-mono">{w.name_servers.join(', ')}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* WAF Detections */}
      <Section
        id="waf" label="WAF Detections" count={intel.waf_detections?.length ?? 0}
        icon={<Shield className="h-3.5 w-3.5" />}
        open={openSection === 'waf'} onToggle={() => setOpenSection(openSection === 'waf' ? '' : 'waf')}
      >
        {!intel.waf_detections?.length ? (
          <p className="text-xs text-muted-foreground">No WAF detections. Run wafw00f against target URLs.</p>
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1.5 px-2 font-medium">URL</th>
                  <th className="py-1.5 px-2 font-medium">Detected</th>
                  <th className="py-1.5 px-2 font-medium">WAF</th>
                  <th className="py-1.5 px-2 font-medium">Manufacturer</th>
                  <th className="py-1.5 px-2 font-medium">Seen</th>
                </tr>
              </thead>
              <tbody>
                {intel.waf_detections.map((w, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                    <td className="py-1.5 px-2 font-mono text-primary truncate max-w-[300px]">{w.url}</td>
                    <td className="py-1.5 px-2">
                      <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium',
                        w.detected ? 'bg-orange-500/15 text-orange-400' : 'bg-green-500/15 text-green-400'
                      )}>
                        {w.detected ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td className="py-1.5 px-2 font-medium">{w.firewall || '-'}</td>
                    <td className="py-1.5 px-2 text-muted-foreground">{w.manufacturer || '-'}</td>
                    <td className="py-1.5 px-2 text-muted-foreground">{w.created_at ? formatDate(w.created_at) : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════════════
   ANALYSIS PANEL — Red Team Recon Intelligence
   ═══════════════════════════════════════════════════════════════════════════ */

const PRIORITY_COLORS = {
  high: 'bg-red-500/15 text-red-400 border-red-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/15 text-green-400 border-green-500/30',
}

const STEALTH_COLORS = {
  passive: 'bg-green-500/15 text-green-400 border-green-500/30',
  low: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  medium: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
}

const CATEGORY_COLORS: Record<string, string> = {
  vuln: 'bg-red-500/15 text-red-400 border-red-500/30',
  credential: 'bg-pink-500/15 text-pink-400 border-pink-500/30',
  login: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  admin: 'bg-red-500/15 text-red-400 border-red-500/30',
  api: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  exposed_service: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
}

function AnalysisPanel({ analysis }: { analysis: ScopeAnalysisData }) {
  const [openPanel, setOpenPanel] = useState<string>('targets')
  const excludeFromScope = useExcludeFromScope()
  const [localExcluded, setLocalExcluded] = useState<Set<string>>(new Set())

  const handleExclude = (target: string) => {
    excludeFromScope.mutate({ targets: [target], source: 'recon-analysis' })
    setLocalExcluded(prev => new Set(prev).add(target))
  }

  const total = analysis.prioritized_targets.length + analysis.interesting_services.length +
    analysis.sensitive_pages.length + analysis.login_pages.length

  if (total === 0 && analysis.suggested_next_steps.length === 0) {
    return (
      <div className="border border-border rounded-lg p-4 bg-card text-sm text-muted-foreground">
        No analysis data yet. Run recon tools to populate intelligence.
      </div>
    )
  }

  return (
    <div className="border border-primary/20 rounded-lg bg-card overflow-hidden">
      <div className="px-4 py-3 border-b border-border bg-primary/5">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Target className="h-4 w-4 text-primary" /> Red Team Recon Analysis
        </h3>
        <p className="text-[10px] text-muted-foreground mt-0.5">Low-and-slow reconnaissance priorities based on collected intelligence</p>
      </div>

      <div className="p-3 space-y-2">
        {/* Prioritized Targets */}
        <AnalysisSection
          id="targets" label="Prioritized Targets" count={analysis.prioritized_targets.length}
          icon={<AlertTriangle className="h-3.5 w-3.5" />}
          open={openPanel === 'targets'} onToggle={() => setOpenPanel(openPanel === 'targets' ? '' : 'targets')}
        >
          {analysis.prioritized_targets.length === 0 ? (
            <p className="text-xs text-muted-foreground">No high-priority targets identified</p>
          ) : (
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="py-1 px-2 font-medium">Priority</th>
                    <th className="py-1 px-2 font-medium">Target</th>
                    <th className="py-1 px-2 font-medium">Category</th>
                    <th className="py-1 px-2 font-medium">Reasons</th>
                    <th className="py-1 px-2 w-8"></th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.prioritized_targets.map((t, i) => (
                    <tr key={i} className={cn('border-b border-border/50 hover:bg-muted/50', localExcluded.has(t.target) && 'opacity-40')}>
                      <td className="py-1.5 px-2">
                        <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium border', PRIORITY_COLORS[t.priority] || PRIORITY_COLORS.low)}>
                          {t.priority}
                        </span>
                      </td>
                      <td className="py-1.5 px-2 font-mono max-w-[200px] truncate">{t.target}</td>
                      <td className="py-1.5 px-2">
                        <span className={cn('px-1.5 py-0.5 rounded text-[10px] border', CATEGORY_COLORS[t.category] || 'bg-muted text-muted-foreground')}>
                          {t.category}
                        </span>
                      </td>
                      <td className="py-1.5 px-2 text-muted-foreground max-w-[300px]">
                        {t.reasons.map((r, j) => (
                          <span key={j} className="block text-[10px] leading-tight">{r}</span>
                        ))}
                      </td>
                      <td className="py-1.5 px-2">
                        {!localExcluded.has(t.target) && (
                          <button onClick={() => handleExclude(t.target)} title="Mark out-of-scope"
                            className="text-muted-foreground hover:text-orange-400 transition-colors">
                            <Ban className="h-3 w-3" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AnalysisSection>

        {/* Suggested Next Steps */}
        <AnalysisSection
          id="steps" label="Suggested Next Steps" count={analysis.suggested_next_steps.length}
          icon={<Zap className="h-3.5 w-3.5" />}
          open={openPanel === 'steps'} onToggle={() => setOpenPanel(openPanel === 'steps' ? '' : 'steps')}
        >
          {analysis.suggested_next_steps.length === 0 ? (
            <p className="text-xs text-muted-foreground">No gaps detected — good coverage</p>
          ) : (
            <div className="space-y-2">
              {analysis.suggested_next_steps.map((s, i) => (
                <div key={i} className="border border-border rounded p-2.5 bg-accent/5">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-medium">{s.tool}</span>
                    <span className="text-[10px] text-muted-foreground font-mono">{s.scan_type}</span>
                    <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium border ml-auto',
                      STEALTH_COLORS[s.stealth_level] || STEALTH_COLORS.medium
                    )}>
                      {s.stealth_level}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">{s.rationale}</p>
                  {s.target && (
                    <p className="text-[10px] font-mono text-muted-foreground mt-1 truncate">Target: {s.target}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </AnalysisSection>

        {/* Interesting Services */}
        <AnalysisSection
          id="services" label="Interesting Services" count={analysis.interesting_services.length}
          icon={<Eye className="h-3.5 w-3.5" />}
          open={openPanel === 'services'} onToggle={() => setOpenPanel(openPanel === 'services' ? '' : 'services')}
        >
          {analysis.interesting_services.length === 0 ? (
            <p className="text-xs text-muted-foreground">No notable services identified</p>
          ) : (
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="py-1 px-2 font-medium">Host:Port</th>
                    <th className="py-1 px-2 font-medium">Service</th>
                    <th className="py-1 px-2 font-medium">Product</th>
                    <th className="py-1 px-2 font-medium">Why Interesting</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.interesting_services.map((s, i) => (
                    <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                      <td className="py-1.5 px-2 font-mono">{s.host}:{s.port}</td>
                      <td className="py-1.5 px-2">{s.service || '-'}</td>
                      <td className="py-1.5 px-2 text-muted-foreground">
                        {[s.product, s.version].filter(Boolean).join(' ') || '-'}
                      </td>
                      <td className="py-1.5 px-2 text-muted-foreground text-[10px]">{s.interest_reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AnalysisSection>

        {/* Sensitive Pages */}
        <AnalysisSection
          id="sensitive" label="Sensitive Pages" count={analysis.sensitive_pages.length}
          icon={<FileText className="h-3.5 w-3.5" />}
          open={openPanel === 'sensitive'} onToggle={() => setOpenPanel(openPanel === 'sensitive' ? '' : 'sensitive')}
        >
          {analysis.sensitive_pages.length === 0 ? (
            <p className="text-xs text-muted-foreground">No sensitive pages discovered</p>
          ) : (
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="py-1 px-2 font-medium">URL</th>
                    <th className="py-1 px-2 font-medium">Type</th>
                    <th className="py-1 px-2 font-medium">Evidence</th>
                    <th className="py-1 px-2 font-medium">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.sensitive_pages.map((p, i) => (
                    <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                      <td className="py-1.5 px-2 font-mono max-w-[250px] truncate">{p.url}</td>
                      <td className="py-1.5 px-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] border border-border bg-muted/50">{p.page_type}</span>
                      </td>
                      <td className="py-1.5 px-2 text-muted-foreground text-[10px] max-w-[300px] truncate">{p.evidence}</td>
                      <td className="py-1.5 px-2 text-muted-foreground">{p.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AnalysisSection>

        {/* Login Pages */}
        <AnalysisSection
          id="logins" label="Login Pages" count={analysis.login_pages.length}
          icon={<LogIn className="h-3.5 w-3.5" />}
          open={openPanel === 'logins'} onToggle={() => setOpenPanel(openPanel === 'logins' ? '' : 'logins')}
        >
          {analysis.login_pages.length === 0 ? (
            <p className="text-xs text-muted-foreground">No login pages discovered</p>
          ) : (
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="py-1 px-2 font-medium">URL</th>
                    <th className="py-1 px-2 font-medium">Fields</th>
                    <th className="py-1 px-2 font-medium">CSRF</th>
                    <th className="py-1 px-2 font-medium">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.login_pages.map((lp, i) => (
                    <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
                      <td className="py-1.5 px-2 font-mono max-w-[250px] truncate">{lp.url}</td>
                      <td className="py-1.5 px-2 text-muted-foreground">
                        {lp.fields.length > 0 ? lp.fields.join(', ') : '-'}
                      </td>
                      <td className="py-1.5 px-2">
                        <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium',
                          lp.has_csrf ? 'bg-green-400/10 text-green-400' : 'bg-red-400/10 text-red-400'
                        )}>
                          {lp.has_csrf ? 'Yes' : 'No'}
                        </span>
                      </td>
                      <td className="py-1.5 px-2 text-muted-foreground">{lp.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AnalysisSection>

        {/* Out-of-Scope Candidates */}
        {analysis.out_of_scope_candidates.length > 0 && (
          <AnalysisSection
            id="oos" label="Potential Out-of-Scope" count={analysis.out_of_scope_candidates.length}
            icon={<Ban className="h-3.5 w-3.5" />}
            open={openPanel === 'oos'} onToggle={() => setOpenPanel(openPanel === 'oos' ? '' : 'oos')}
          >
            <div className="space-y-1">
              {analysis.out_of_scope_candidates.map((c, i) => (
                <div key={i} className={cn('flex items-center gap-2 px-2 py-1.5 rounded border border-border/50 text-xs',
                  localExcluded.has(c.target) && 'opacity-40'
                )}>
                  <span className="font-mono">{c.target}</span>
                  <span className="text-muted-foreground flex-1 text-[10px]">{c.reason}</span>
                  {!localExcluded.has(c.target) && (
                    <button onClick={() => handleExclude(c.target)}
                      className="px-2 py-0.5 text-[10px] rounded border border-orange-500/30 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 transition-colors">
                      Mark OOS
                    </button>
                  )}
                  {localExcluded.has(c.target) && (
                    <span className="text-[10px] text-muted-foreground">Excluded</span>
                  )}
                </div>
              ))}
            </div>
          </AnalysisSection>
        )}
      </div>
    </div>
  )
}

function AnalysisSection({
  id, label, count, icon, open, onToggle, children,
}: {
  id: string; label: string; count: number; icon: React.ReactNode
  open: boolean; onToggle: () => void; children: React.ReactNode
}) {
  return (
    <div className="border border-border/50 rounded bg-card/50 overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 p-2.5 text-left hover:bg-muted/50 transition-colors"
      >
        <span className={cn('text-primary transition-transform', open ? 'rotate-90' : '')}>{icon}</span>
        <span className="text-xs font-medium">{label}</span>
        <span className="text-[10px] text-muted-foreground ml-auto">{count}</span>
        <ChevronRight className={cn('h-3 w-3 text-muted-foreground transition-transform', open ? 'rotate-90' : '')} />
      </button>
      {open && (
        <div className="border-t border-border/50 p-2.5">
          {children}
        </div>
      )}
    </div>
  )
}

function ScreenshotsSection({ open, onToggle, domains }: { open: boolean; onToggle: () => void; domains?: string[] }) {
  // Filter screenshots by scope domains — use first domain as search term
  const searchTerm = domains?.length ? domains[0] : undefined
  const { data } = useScreenshots(searchTerm)
  const { data: allMetaData } = useAllScreenshotMetadata()
  // Client-side filter: keep only screenshots whose filename contains any scope domain
  const allScreenshots = data?.screenshots ?? []
  const screenshots = domains?.length
    ? allScreenshots.filter(sc => domains.some(d => sc.filename.includes(d.replace(/\./g, '-'))))
    : allScreenshots
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
      <Section
        id="screenshots" label="Screenshots" count={screenshots.length}
        icon={<Camera className="h-3.5 w-3.5" />}
        open={open} onToggle={onToggle}
      >
        {screenshots.length === 0 ? (
          <p className="text-xs text-muted-foreground">No screenshots captured. Run GoWitness or the Recon Pipeline.</p>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3 max-h-[500px] overflow-y-auto">
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
                  <div className="px-2 py-1.5">
                    <span className="text-[10px] font-mono text-foreground truncate block">
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
      </Section>

      {/* Screenshots lightbox with tag panel */}
      {lightbox && (
        <ScopeScreenshotLightbox
          path={lightbox}
          filename={screenshots.find(s => s.path === lightbox)?.filename ?? ''}
          directory={screenshots.find(s => s.path === lightbox)?.directory}
          onClose={() => setLightbox(null)}
        />
      )}
    </>
  )
}

function ScopeScreenshotLightbox({ path, filename, directory, onClose }: {
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
              className="flex-1 px-2 py-0.5 text-xs rounded border border-border bg-background" list="scope-sc-tag-suggestions" />
            <datalist id="scope-sc-tag-suggestions">
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
            <button disabled={!scopeTarget || addToScope.isPending}
              onClick={() => {
                const domain = filename.replace('.png', '').replace(/^https?---/, '').replace(/-\d+$/, '').split('-').join('.')
                if (!domain || !scopeTarget) return
                addToScope.mutate({ name: scopeTarget, targets: [{ target: domain, target_type: 'domain', source: 'screenshot-tag' }] }, {
                  onSuccess: () => {
                    updateMeta.mutate({ path, filename, directory, added_to_scope: scopeTarget })
                    setScopeAdded(true)
                    setTimeout(() => setScopeAdded(false), 2000)
                  },
                })
              }}
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

function StatCard({ label, value, primary }: { label: string; value: number; primary?: boolean }) {
  return (
    <div className="text-center">
      <div className={cn('text-2xl font-bold', primary ? 'text-primary' : '')}>{value}</div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  )
}

function AutoClassifyPanel() {
  const { data: sugData, isLoading: sugLoading } = useScopeSuggestions()
  const { data: rulesData } = useScopeClassificationRules()
  const classify = useClassifyUnknown()
  const accept = useAcceptSuggestion()
  const reject = useRejectSuggestion()
  const bulkAccept = useBulkAcceptSuggestions()
  const learnRules = useLearnRules()
  const createRule = useCreateClassificationRule()
  const deleteRule = useDeleteClassificationRule()
  const [bulkThreshold, setBulkThreshold] = useState(0.85)
  const [showRules, setShowRules] = useState(false)
  const [lastResult, setLastResult] = useState<Record<string, number> | null>(null)

  const suggestions = sugData?.suggestions ?? []
  const rules = rulesData?.rules ?? []

  return (
    <div className="bg-card border border-amber-500/30 rounded-lg p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Cpu className="h-4 w-4 text-amber-400" /> Auto-Classify Scope
        </h3>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowRules(!showRules)}
            className="px-2.5 py-1 text-xs rounded border border-border hover:bg-muted"
          >{showRules ? 'Hide Rules' : `Rules (${rules.length})`}</button>
          <button
            onClick={() => classify.mutate({}, { onSuccess: (d) => setLastResult(d as unknown as Record<string, number>) })}
            disabled={classify.isPending}
            className="px-3 py-1.5 text-xs rounded bg-amber-500 text-white hover:bg-amber-600 disabled:opacity-50 font-medium"
          >
            {classify.isPending ? 'Classifying...' : 'Classify Unknown Scope'}
          </button>
        </div>
      </div>

      {lastResult && (
        <div className="grid grid-cols-3 gap-3 text-center">
          <div className="bg-green-500/10 rounded p-2">
            <div className="text-lg font-bold text-green-400">{lastResult.auto_assigned ?? 0}</div>
            <div className="text-[10px] text-muted-foreground">Auto-assigned</div>
          </div>
          <div className="bg-amber-500/10 rounded p-2">
            <div className="text-lg font-bold text-amber-400">{lastResult.suggested ?? 0}</div>
            <div className="text-[10px] text-muted-foreground">Suggestions</div>
          </div>
          <div className="bg-muted rounded p-2">
            <div className="text-lg font-bold">{lastResult.unclassified ?? 0}</div>
            <div className="text-[10px] text-muted-foreground">Unclassified</div>
          </div>
        </div>
      )}

      {/* Suggestions */}
      {suggestions.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium">{suggestions.length} pending suggestions</span>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-muted-foreground">Min confidence:</span>
              <input type="range" min={0.5} max={0.95} step={0.05} value={bulkThreshold}
                onChange={e => setBulkThreshold(Number(e.target.value))} className="w-20 h-1" />
              <span className="text-xs font-mono w-8">{(bulkThreshold * 100).toFixed(0)}%</span>
              <button
                onClick={() => bulkAccept.mutate(bulkThreshold)}
                disabled={bulkAccept.isPending}
                className="px-2 py-1 text-[10px] rounded bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30"
              >{bulkAccept.isPending ? '...' : `Accept all ≥${(bulkThreshold * 100).toFixed(0)}%`}</button>
            </div>
          </div>
          <div className="max-h-64 overflow-y-auto space-y-1">
            {suggestions.map(s => (
              <div key={s.id} className="flex items-center gap-2 text-xs bg-muted/50 rounded px-2 py-1.5 hover:bg-muted">
                <span className="font-mono flex-1 truncate">{s.target}</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-primary/10 text-primary">{s.suggested_scope}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                  s.confidence >= 0.85 ? 'bg-green-500/10 text-green-400' :
                  s.confidence >= 0.7 ? 'bg-amber-500/10 text-amber-400' :
                  'bg-red-500/10 text-red-400'
                }`}>{(s.confidence * 100).toFixed(0)}%</span>
                <span className="px-1 py-0.5 rounded text-[9px] bg-muted border border-border">{s.method}</span>
                <button onClick={() => accept.mutate(s.id)} disabled={accept.isPending}
                  className="px-1.5 py-0.5 text-[10px] text-green-400 hover:bg-green-500/20 rounded">Accept</button>
                <button onClick={() => reject.mutate({ id: s.id })} disabled={reject.isPending}
                  className="px-1.5 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 rounded">Reject</button>
              </div>
            ))}
          </div>
        </div>
      )}
      {!sugLoading && suggestions.length === 0 && (
        <p className="text-xs text-muted-foreground">No pending suggestions. Click "Classify Unknown Scope" to generate.</p>
      )}

      {/* Rules Manager */}
      {showRules && (
        <div className="border-t border-border pt-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium">Classification Rules ({rules.length})</span>
            <button onClick={() => learnRules.mutate(undefined, {
              onSuccess: (d) => {
                const suggested = d.suggested_rules || []
                if (suggested.length === 0) { alert('No rule patterns found in past decisions'); return }
                // Auto-create the top suggested rule
                const top = suggested[0]
                if (window.confirm(`Create rule: "${top.name}" (${(top.confidence as number * 100).toFixed(0)}% confidence from ${top.evidence_count} decisions)?`)) {
                  createRule.mutate({
                    name: top.name as string,
                    scope_name: top.scope_name as string,
                    rule_type: top.rule_type as string,
                    conditions: top.conditions as Record<string, unknown>,
                  })
                }
              },
            })}
              disabled={learnRules.isPending}
              className="px-2 py-1 text-[10px] rounded border border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
            >{learnRules.isPending ? 'Analyzing...' : 'Learn from Decisions'}</button>
          </div>
          <div className="max-h-48 overflow-y-auto space-y-1">
            {rules.map((r, i) => (
              <div key={r.id || i} className="flex items-center gap-2 text-xs bg-muted/50 rounded px-2 py-1.5">
                <span className="font-medium flex-1 truncate">{r.name}</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-primary/10 text-primary">{r.scope_name}</span>
                <span className="px-1 py-0.5 rounded text-[9px] bg-muted border border-border">{r.rule_type}</span>
                {r.auto_apply && <span className="px-1 py-0.5 rounded text-[9px] bg-green-500/10 text-green-400">auto</span>}
                {r.source !== 'db' && <span className="px-1 py-0.5 rounded text-[9px] bg-muted text-muted-foreground">yaml</span>}
                {r.source === 'db' && (
                  <button onClick={() => deleteRule.mutate(r.id)}
                    className="px-1 py-0.5 text-[10px] text-red-400 hover:bg-red-500/20 rounded">Del</button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}


function Section({
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
