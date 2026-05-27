import { useState, useMemo } from 'react'
import {
  useContentExtractions, useContentSummary, useGenerateWordlist,
  useContentPatterns, useCreatePattern, useUpdatePattern, useDeletePattern,
  useUpdateExtraction, useDeleteExtraction, useCredentialGuess,
  type CredentialGuessResult,
  useSitemap, type SitemapEntry,
  type ContentExtraction, type ContentPattern,
} from '@/api/reports'
import { apiUrl } from '@/api/client'
import { useScopeNames, useScope } from '@/api/scope'
import { useEngagements } from '@/api/engagements'
import { useUIStore } from '@/stores/ui'
import { cn } from '@/lib/utils'
import {
  Mail, User, FolderOpen, Globe, Key, Cpu, MessageSquare, EyeOff,
  ChevronDown, ChevronRight, Loader2, FileText, Zap, Settings2, Pencil,
  Trash2, Plus, Check, X, ToggleLeft, ToggleRight, File, ScanSearch,
  Map, Download, ExternalLink, Filter, LogIn, Shield, Play,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { useLaunchScan } from '@/api/scans'
import { useCredentials } from '@/api/credentials'
import { useFollowUps } from '@/api/followups'

type Tab = 'extractions' | 'sitemap' | 'wordlists' | 'settings'
type ListType = 'passwords' | 'usernames' | 'directories'

const CATEGORIES = [
  { id: 'emails', label: 'Emails' },
  { id: 'secrets', label: 'Secrets / Keys' },
  { id: 'paths', label: 'Internal Paths' },
  { id: 'api_endpoints', label: 'API Endpoints' },
  { id: 'tech', label: 'Tech Indicators' },
  { id: 'comments', label: 'Sensitive Comments' },
  { id: 'custom', label: 'Custom' },
]

const MUTATIONS = [
  { id: 'capitalize', label: 'Capitalize' },
  { id: 'upper', label: 'ALL CAPS' },
  { id: 'leet', label: 'L33t Speak' },
  { id: 'append_numbers', label: 'Append Numbers' },
  { id: 'append_specials', label: 'Append Specials (!@#)' },
  { id: 'append_years', label: 'Append Years' },
]

const SOURCES = [
  { id: 'word_corpus', label: 'Page Text' },
  { id: 'emails', label: 'Emails' },
  { id: 'names', label: 'Names' },
  { id: 'tech_indicators', label: 'Tech Indicators' },
  { id: 'comments', label: 'Comments' },
  { id: 'hidden_inputs', label: 'Hidden Inputs' },
]

const EDITABLE_FIELDS = ['login_pages', 'emails', 'names', 'internal_paths', 'api_endpoints', 'exposed_keys', 'tech_indicators', 'comments', 'hidden_inputs', 'interesting_files', 'file_metadata'] as const

function SitemapProxyReplay({ domain, urlCount }: { domain: string; urlCount: number }) {
  const [proxyUrl, setProxyUrl] = useState('http://192.168.1.181:8080')
  const [sending, setSending] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const [progress, setProgress] = useState<{ running: boolean; progress: number; total: number; phase: string; success: number; failed: number } | null>(null)

  const handleReplay = async () => {
    setSending(true)
    setResult(null)
    setProgress({ running: true, phase: 'starting', progress: 0, total: 0, success: 0, failed: 0 })

    // Start polling progress
    const interval = setInterval(async () => {
      try {
        const res = await fetch('/api/reports/proxy-replay/status')
        const data = await res.json()
        setProgress(data)
        if (!data.running && data.total > 0) {
          clearInterval(interval)
          setResult(`Done: ${data.success} sent, ${data.failed} failed of ${data.total}`)
          setSending(false)
        }
      } catch { /* ignore */ }
    }, 1500)

    try {
      const res = await fetch('/api/reports/proxy-replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proxy_url: proxyUrl,
          ip: domain,
          limit: 2000,
          include_params: true,
          include_auth: false,
          include_payloads: false,
          order: 'sequential',
        }),
      })
      const data = await res.json()
      if (!data.ok) setResult(`Error: ${data.message || data.error || 'unknown'}`)
      else setResult(`${data.queued} requests queued to ${proxyUrl}`)
      // Let progress polling handle the final state
      setTimeout(() => clearInterval(interval), 120000)
    } catch (e) {
      setResult(`Error: ${e}`)
      clearInterval(interval)
      setSending(false)
    }
  }

  return (
    <div className="flex items-center gap-1.5">
      <input
        value={proxyUrl}
        onChange={e => setProxyUrl(e.target.value)}
        className="w-48 bg-muted rounded px-2 py-1 text-[10px] font-mono border border-border"
        placeholder="http://127.0.0.1:8080"
      />
      <button
        onClick={handleReplay}
        disabled={sending || !proxyUrl}
        className="px-3 py-1.5 bg-orange-500/10 border border-orange-500/30 text-orange-400 rounded text-xs hover:bg-orange-500/20 flex items-center gap-1 disabled:opacity-50"
      >
        {sending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
        {sending ? 'Sending...' : 'Replay to Proxy'}
      </button>
      {progress?.running && progress.total > 0 && (
        <span className="text-[10px] text-blue-400">
          {progress.progress}/{progress.total} ({progress.phase})
        </span>
      )}
      {result && (
        <span className={`text-[10px] ${result.startsWith('Error') ? 'text-red-400' : 'text-green-400'}`}>
          {result}
        </span>
      )}
    </div>
  )
}

export default function ContentIntel() {
  const [tab, setTab] = useState<Tab>('extractions')
  const [assetFilter, setAssetFilter] = useState('')  // searches by IP, hostname, or URL

  // Global engagement/scope — single source of truth
  const selectedEngagement = useUIStore(s => s.selectedEngagementId) ?? ''
  const selectedScope = useUIStore(s => s.selectedScopeName) ?? ''
  const setGlobalEngagement = useUIStore(s => s.setSelectedEngagement)
  const setGlobalScope = useUIStore(s => s.setSelectedScope)

  // Scope & Engagement data
  const { data: scopeNamesData } = useScopeNames()
  const { data: engagementsData } = useEngagements()
  const scopeNames = scopeNamesData?.names ?? []
  const engagements = engagementsData?.engagements ?? []

  const handleEngagementChange = (eid: string) => {
    const eng = engagements.find(e => e.id === eid)
    setGlobalEngagement(eid || null, eng?.scope_name ?? null)
  }

  const handleScopeChange = (name: string) => {
    setGlobalScope(name || null)
  }

  // Get scope targets for domain chips
  const { data: scopeData } = useScope(selectedScope)
  const scopeTargets = scopeData?.targets ?? []
  const scopeDomains = [...new Set(
    scopeTargets
      .map(t => t.target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, ''))
      .filter(Boolean)
  )].sort()

  return (
    <div className="space-y-4">
      {/* Header with Scope / Engagement / Asset filters */}
      <div className="flex items-center justify-between gap-4">
        <h2 className="text-lg font-semibold shrink-0">Content Intelligence</h2>
        <div className="flex items-center gap-2 flex-wrap flex-1 justify-end">
          {selectedEngagement && (
            <span className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded border border-border">
              {engagements.find(e => e.id === selectedEngagement)?.name || 'Engagement'}
            </span>
          )}
          {scopeNames.length > 0 && (
            <select
              value={selectedScope}
              onChange={e => handleScopeChange(e.target.value)}
              className="h-8 px-2 text-xs rounded border border-border bg-card min-w-[120px]"
            >
              <option value="">Scope...</option>
              {scopeNames.map(s => (
                <option key={s.name} value={s.name}>{s.name} ({s.target_count})</option>
              ))}
            </select>
          )}
          <input
            className="px-3 py-1.5 bg-card border border-border rounded text-sm w-56"
            placeholder="Search IP or hostname..."
            value={assetFilter}
            onChange={e => setAssetFilter(e.target.value)}
          />
        </div>
      </div>

      {/* Scope domain chips (collapsible) */}
      {selectedScope && scopeDomains.length > 0 && (
        <ScopeTargetChips domains={scopeDomains} />
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {([
          ['extractions', 'Extractions'],
          ['sitemap', 'Sitemap'],
          ['wordlists', 'Wordlist Generator'],
          ['settings', 'Patterns & Settings'],
        ] as [Tab, string][]).map(([t, label]) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              'px-4 py-2 text-sm border-b-2 transition-colors -mb-px',
              tab === t
                ? 'border-primary text-primary font-medium'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {t === 'settings' && <Settings2 className="h-3.5 w-3.5 inline mr-1.5 -mt-0.5" />}
            {label}
          </button>
        ))}
      </div>

      {tab === 'extractions' && <ExtractionsTab assetFilter={assetFilter} scopeDomains={scopeDomains} />}
      {tab === 'sitemap' && <SitemapTab assetFilter={assetFilter} scopeDomains={scopeDomains} selectedScope={selectedScope} />}
      {tab === 'wordlists' && <WordlistsTab assetFilter={assetFilter} />}
      {tab === 'settings' && <SettingsTab />}
    </div>
  )
}

/* ───────────── Extractions Tab ───────────── */

type CategoryFilter = typeof EDITABLE_FIELDS[number] | null

const CATEGORY_META: Record<string, { icon: typeof Mail; label: string; color: string; summaryKey: string }> = {
  login_pages:     { icon: LogIn,         label: 'Login Pages',     color: 'text-rose-400',   summaryKey: 'total_login_pages' },
  emails:          { icon: Mail,          label: 'Emails',          color: 'text-blue-400',   summaryKey: 'total_emails' },
  exposed_keys:    { icon: Key,           label: 'Exposed Keys',    color: 'text-red-400',    summaryKey: 'total_exposed_keys' },
  internal_paths:  { icon: FolderOpen,    label: 'Internal Paths',  color: 'text-amber-400',  summaryKey: 'total_paths' },
  api_endpoints:   { icon: Globe,         label: 'API Endpoints',   color: 'text-green-400',  summaryKey: 'total_api_endpoints' },
  names:           { icon: User,          label: 'Names',           color: 'text-purple-400', summaryKey: 'total_names' },
  tech_indicators: { icon: Cpu,           label: 'Tech Indicators', color: 'text-cyan-400',   summaryKey: 'total_tech_indicators' },
  comments:        { icon: MessageSquare, label: 'Comments',        color: 'text-orange-400', summaryKey: 'total_comments' },
  hidden_inputs:       { icon: EyeOff,        label: 'Hidden Inputs',       color: 'text-pink-400',   summaryKey: 'total_hidden_inputs' },
  interesting_files:   { icon: File,          label: 'Interesting Files',   color: 'text-yellow-400', summaryKey: 'total_interesting_files' },
  file_metadata:       { icon: ScanSearch,    label: 'File Metadata',       color: 'text-emerald-400', summaryKey: 'total_file_metadata' },
}

function ExtractionsTab({ assetFilter, scopeDomains }: { assetFilter: string; scopeDomains?: string[] }) {
  const { data: extractionsData, isLoading } = useContentExtractions(assetFilter || undefined)
  const { data: summaryData, isLoading: loadingSummary } = useContentSummary(assetFilter || undefined)
  const updateExtraction = useUpdateExtraction()
  const deleteExtraction = useDeleteExtraction()
  const [activeCategory, setActiveCategory] = useState<CategoryFilter>(null)
  const [editingField, setEditingField] = useState<{ id: string; field: string } | null>(null)
  const [editValue, setEditValue] = useState('')
  const [showAll, setShowAll] = useState(false)

  const summary = summaryData?.summary
  const rawExtractions = extractionsData?.extractions ?? []
  // Filter by scope domains unless "Show All" is active
  const extractions = !showAll && scopeDomains && scopeDomains.length > 0
    ? rawExtractions.filter(ext => scopeDomains.some(d => ext.url.includes(d)))
    : rawExtractions
  const isFiltered = !showAll && scopeDomains && scopeDomains.length > 0 && rawExtractions.length > extractions.length

  const startEdit = (ext: ContentExtraction, field: typeof EDITABLE_FIELDS[number]) => {
    const val = ext[field as keyof ContentExtraction]
    setEditingField({ id: ext.id, field })
    setEditValue(JSON.stringify(val, null, 2))
  }

  const saveEdit = () => {
    if (!editingField) return
    try {
      const parsed = JSON.parse(editValue)
      updateExtraction.mutate({ id: editingField.id, [editingField.field]: parsed })
      setEditingField(null)
    } catch { /* invalid JSON */ }
  }

  // Build flat list of items for the selected category across all extractions
  const categoryItems = activeCategory ? extractions
    .map(ext => {
      const val = ext[activeCategory as keyof ContentExtraction]
      const items = Array.isArray(val) ? val : []
      return { ext, items, count: items.length }
    })
    .filter(r => r.count > 0) : []

  return (
    <div className="space-y-4">
      {/* Summary Cards — clickable category filters */}
      {loadingSummary ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading summary...
        </div>
      ) : summary ? (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
          {EDITABLE_FIELDS.map(field => {
            const meta = CATEGORY_META[field]
            if (!meta) return null
            const count = (summary as unknown as Record<string, number>)[meta.summaryKey] ?? 0
            const isActive = activeCategory === field
            return (
              <button
                key={field}
                onClick={() => setActiveCategory(isActive ? null : field)}
                className={cn(
                  'bg-card border rounded-lg p-3 text-left transition-all',
                  isActive ? 'border-primary ring-1 ring-primary/30' : 'border-border hover:border-primary/50',
                )}
              >
                <div className="flex items-center gap-2 mb-1">
                  <meta.icon className={cn('h-4 w-4', meta.color)} />
                  <span className="text-xs text-muted-foreground">{meta.label}</span>
                </div>
                <span className="text-xl font-bold">{count.toLocaleString()}</span>
              </button>
            )
          })}
          <button
            onClick={() => setActiveCategory(null)}
            className={cn(
              'bg-card border rounded-lg p-3 text-left transition-all',
              !activeCategory ? 'border-primary ring-1 ring-primary/30' : 'border-border hover:border-primary/50',
            )}
          >
            <div className="flex items-center gap-2 mb-1">
              <FileText className="h-4 w-4 text-zinc-400" />
              <span className="text-xs text-muted-foreground">All</span>
            </div>
            <span className="text-xl font-bold">{summary.total_extractions}</span>
          </button>
        </div>
      ) : null}

      {/* Show All toggle + count */}
      {(isFiltered || showAll) && (
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAll(!showAll)}
            className={cn(
              'h-7 px-3 text-xs rounded border flex items-center gap-1.5',
              showAll
                ? 'border-primary bg-primary/15 text-primary'
                : 'border-border bg-background text-muted-foreground hover:bg-accent'
            )}
          >
            {showAll ? <ToggleRight className="h-3.5 w-3.5" /> : <ToggleLeft className="h-3.5 w-3.5" />}
            {showAll ? 'Showing All' : 'Show All'}
          </button>
          <span className="text-xs text-muted-foreground">
            {extractions.length} of {rawExtractions.length} extractions
            {!showAll && rawExtractions.length > extractions.length && ` (${rawExtractions.length - extractions.length} hidden by scope filter)`}
          </span>
        </div>
      )}

      {/* Category detail view — grouped by site with expand/collapse */}
      {activeCategory && (
        <CategoryDetailView
          activeCategory={activeCategory}
          categoryItems={categoryItems}
          onClose={() => setActiveCategory(null)}
          onEdit={startEdit}
        />
      )}

      {/* All extractions view (when no category selected) */}
      {!activeCategory && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-border">
            <h3 className="text-sm font-semibold">All Extractions by URL</h3>
          </div>
          {isLoading ? (
            <div className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading...
            </div>
          ) : extractions.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">
              No content extractions found. Run a Playwright scan with DOM capture enabled.
            </p>
          ) : (
            <CollapsibleUrlList
              items={extractions}
              renderItem={ext => {
                const fieldCounts = EDITABLE_FIELDS
                  .map(f => {
                    const v = ext[f as keyof ContentExtraction]
                    return { field: f, count: Array.isArray(v) ? v.length : 0 }
                  })
                  .filter(fc => fc.count > 0)

                return (
                  <div key={ext.id} className="px-4 py-2.5 hover:bg-accent/30">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-xs truncate flex-1">{ext.url}</span>
                      <button
                        onClick={() => { if (confirm('Delete this extraction?')) deleteExtraction.mutate(ext.id) }}
                        className="p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive shrink-0"
                        title="Delete"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {fieldCounts.map(({ field, count }) => {
                        const meta = CATEGORY_META[field]
                        if (!meta) return null
                        return (
                          <button
                            key={field}
                            onClick={() => setActiveCategory(field)}
                            className="flex items-center gap-1 px-2 py-0.5 rounded bg-accent/50 hover:bg-accent text-xs"
                          >
                            <meta.icon className={cn('h-3 w-3', meta.color)} />
                            <span>{meta.label}</span>
                            <span className="font-medium text-primary">{count}</span>
                          </button>
                        )
                      })}
                      {fieldCounts.length === 0 && (
                        <span className="text-xs text-muted-foreground">No items extracted</span>
                      )}
                    </div>
                  </div>
                )
              }}
            />
          )}
        </div>
      )}

      {/* Edit Modal */}
      {editingField && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setEditingField(null)}>
          <div className="bg-card border border-border rounded-lg w-full max-w-3xl max-h-[80vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3 border-b border-border">
              <div>
                <h3 className="text-sm font-semibold">Edit {CATEGORY_META[editingField.field as keyof typeof CATEGORY_META]?.label || editingField.field}</h3>
                <p className="text-[10px] text-muted-foreground mt-0.5">JSON array — edit carefully. Changes save immediately.</p>
              </div>
              <button onClick={() => setEditingField(null)} className="text-muted-foreground hover:text-foreground">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              <textarea
                className="w-full bg-muted rounded px-3 py-2 text-xs font-mono border border-border min-h-[400px] resize-y"
                value={editValue}
                onChange={e => setEditValue(e.target.value)}
                spellCheck={false}
              />
            </div>
            <div className="flex justify-end gap-2 px-5 py-3 border-t border-border">
              <button onClick={() => setEditingField(null)} className="px-3 py-1.5 text-xs rounded border border-border text-muted-foreground hover:text-foreground">
                Cancel
              </button>
              <button onClick={saveEdit} className="px-3 py-1.5 text-xs font-medium rounded bg-primary text-primary-foreground hover:bg-primary/90 flex items-center gap-1">
                <Check className="h-3 w-3" /> Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Category Detail View (grouped by site) ────────────────────────────

function CategoryDetailView({ activeCategory, categoryItems, onClose, onEdit }: {
  activeCategory: string
  categoryItems: { ext: ContentExtraction; items: unknown[]; count: number }[]
  onClose: () => void
  onEdit: (ext: ContentExtraction, field: typeof EDITABLE_FIELDS[number]) => void
}) {
  const [expandedSites, setExpandedSites] = useState<Set<string>>(new Set())
  const [apiFilter, setApiFilter] = useState<{ method?: string; type?: string; confidence?: string }>({})
  const { data: followUpData } = useFollowUps({ status: 'open' })
  const followUps = followUpData?.follow_ups ?? []

  // Group by hostname
  const grouped = useMemo(() => {
    const groups: Record<string, { hostname: string; entries: typeof categoryItems }> = {}
    for (const item of categoryItems) {
      let hostname = 'unknown'
      try { hostname = new URL(item.ext.url).hostname } catch { hostname = item.ext.url.split('/')[0] || 'unknown' }
      if (!groups[hostname]) groups[hostname] = { hostname, entries: [] }
      groups[hostname].entries.push(item)
    }
    return Object.values(groups).sort((a, b) => {
      const ac = a.entries.reduce((s, e) => s + e.count, 0)
      const bc = b.entries.reduce((s, e) => s + e.count, 0)
      return bc - ac
    })
  }, [categoryItems])

  // Follow-up flags indexed by hostname
  const flagsByHost = useMemo(() => {
    const map: Record<string, { title: string; severity: string }[]> = {}
    for (const fu of followUps) {
      const t = fu.target || ''
      let host = t
      try { host = new URL(t.startsWith('http') ? t : `https://${t}`).hostname } catch { host = t.split('/')[0].split(':')[0] }
      if (!host) continue
      if (!map[host]) map[host] = []
      const label = fu.title?.split(' — ')[0]?.split(' -- ')[0] || fu.title
      if (!map[host].some(f => f.title === label)) {
        map[host].push({ title: label, severity: fu.severity })
      }
    }
    return map
  }, [followUps])

  // For api_endpoints: extract unique methods, types, confidence levels for filter buttons
  const apiFilterOptions = useMemo(() => {
    if (activeCategory !== 'api_endpoints') return null
    const methods = new Set<string>()
    const types = new Set<string>()
    const confs = new Set<string>()
    for (const item of categoryItems) {
      for (const ep of item.items as { method?: string; api_type?: string; confidence?: string }[]) {
        if (ep.method) methods.add(ep.method.toUpperCase())
        if (ep.api_type) types.add(ep.api_type)
        if (ep.confidence) confs.add(ep.confidence)
      }
    }
    return { methods: [...methods].sort(), types: [...types].sort(), confs: [...confs] }
  }, [activeCategory, categoryItems])

  const toggleSite = (hostname: string) => {
    setExpandedSites(prev => {
      const next = new Set(prev)
      next.has(hostname) ? next.delete(hostname) : next.add(hostname)
      return next
    })
  }
  const isAllExpanded = expandedSites.size >= grouped.length
  const totalItems = categoryItems.reduce((s, r) => s + r.count, 0)

  const sevColors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    info: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30',
  }

  // Filter api_endpoint items if filters active
  const filterEndpoints = (items: unknown[]) => {
    if (activeCategory !== 'api_endpoints') return items
    if (!apiFilter.method && !apiFilter.type && !apiFilter.confidence) return items
    return (items as { method?: string; api_type?: string; confidence?: string }[]).filter(ep => {
      if (apiFilter.method && ep.method?.toUpperCase() !== apiFilter.method) return false
      if (apiFilter.type && ep.api_type !== apiFilter.type) return false
      if (apiFilter.confidence && ep.confidence !== apiFilter.confidence) return false
      return true
    })
  }

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          {(() => { const m = CATEGORY_META[activeCategory]; return m ? <m.icon className={cn('h-4 w-4', m.color)} /> : null })()}
          {CATEGORY_META[activeCategory]?.label ?? activeCategory}
          <span className="text-xs font-normal text-muted-foreground">
            ({totalItems} items across {grouped.length} sites)
          </span>
        </h3>
        <div className="flex items-center gap-2">
          <button onClick={() => setExpandedSites(isAllExpanded ? new Set() : new Set(grouped.map(g => g.hostname)))}
            className="text-[10px] text-primary hover:underline">{isAllExpanded ? 'Collapse All' : 'Expand All'}</button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* API Endpoint filter buttons */}
      {apiFilterOptions && (
        <div className="px-4 py-2 border-b border-border flex items-center gap-2 flex-wrap">
          <span className="text-[10px] text-muted-foreground">Method:</span>
          {['', ...apiFilterOptions.methods].map(m => (
            <button key={m} onClick={() => setApiFilter(p => ({ ...p, method: m || undefined }))}
              className={cn('px-1.5 py-0.5 text-[10px] rounded border font-mono font-bold',
                (apiFilter.method || '') === m ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'
              )}>{m || 'All'}</button>
          ))}
          <span className="text-[10px] text-muted-foreground ml-2">Type:</span>
          {['', ...apiFilterOptions.types].map(t => (
            <button key={t} onClick={() => setApiFilter(p => ({ ...p, type: t || undefined }))}
              className={cn('px-1.5 py-0.5 text-[10px] rounded border',
                (apiFilter.type || '') === t ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'
              )}>{t || 'All'}</button>
          ))}
          <span className="text-[10px] text-muted-foreground ml-2">Confidence:</span>
          {['', ...apiFilterOptions.confs].map(c => (
            <button key={c} onClick={() => setApiFilter(p => ({ ...p, confidence: c || undefined }))}
              className={cn('px-1.5 py-0.5 text-[10px] rounded border',
                (apiFilter.confidence || '') === c ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground',
                c === 'high' ? 'text-green-400' : c === 'medium' ? 'text-amber-400' : ''
              )}>{c || 'All'}</button>
          ))}
        </div>
      )}

      {grouped.length === 0 ? (
        <p className="p-4 text-sm text-muted-foreground">No {CATEGORY_META[activeCategory]?.label.toLowerCase()} found.</p>
      ) : (
        <div className="divide-y divide-border">
          {grouped.map(group => {
            const isOpen = expandedSites.has(group.hostname)
            const siteCount = group.entries.reduce((s, e) => s + e.count, 0)
            const hostFlags = flagsByHost[group.hostname] || []
            return (
              <div key={group.hostname}>
                <button
                  onClick={() => toggleSite(group.hostname)}
                  className="w-full flex items-center gap-2 px-4 py-2 hover:bg-accent/30 text-left"
                >
                  <ChevronRight className={cn('h-3 w-3 text-muted-foreground transition-transform shrink-0', isOpen && 'rotate-90')} />
                  <span className="font-mono text-xs font-medium truncate">{group.hostname}</span>
                  <span className="text-xs text-muted-foreground shrink-0">{siteCount} items</span>
                  {hostFlags.map((flag, fi) => (
                    <span key={fi} className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium border shrink-0', sevColors[flag.severity] || sevColors.info)}>
                      {flag.title}
                    </span>
                  ))}
                </button>
                {isOpen && (
                  <div className="pl-7 pr-4 pb-3 space-y-3">
                    {group.entries.map(({ ext, items, count }) => {
                      const filtered = filterEndpoints(items)
                      if (filtered.length === 0 && (apiFilter.method || apiFilter.type || apiFilter.confidence)) return null
                      return (
                        <div key={ext.id}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono text-[10px] text-muted-foreground truncate">{ext.url}</span>
                            <div className="flex items-center gap-1.5 shrink-0">
                              <span className="text-[10px] font-medium text-primary">{filtered.length}</span>
                              <button onClick={() => onEdit(ext, activeCategory as typeof EDITABLE_FIELDS[number])}
                                className="p-0.5 rounded hover:bg-accent text-muted-foreground hover:text-foreground" title="Edit">
                                <Pencil className="h-3 w-3" />
                              </button>
                            </div>
                          </div>
                          <FieldDisplay field={activeCategory} value={filtered} />
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Collapsible URL List ────────────────────────────
const COLLAPSE_THRESHOLD = 5

const SCOPE_CHIP_LIMIT = 5

function ScopeTargetChips({ domains, onSelect, selectedDomain }: { domains: string[]; onSelect?: (d: string) => void; selectedDomain?: string }) {
  const [expanded, setExpanded] = useState(false)
  const shouldCollapse = domains.length > SCOPE_CHIP_LIMIT
  const visible = shouldCollapse && !expanded ? domains.slice(0, SCOPE_CHIP_LIMIT) : domains

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <span className="text-xs text-muted-foreground">{onSelect ? 'Quick select' : 'Scope targets'} ({domains.length}):</span>
      {visible.map(d => onSelect ? (
        <button
          key={d}
          onClick={() => onSelect(d)}
          className={cn(
            'px-2 py-0.5 rounded text-xs border font-mono',
            selectedDomain === d ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:bg-accent',
          )}
        >
          {d}
        </button>
      ) : (
        <span key={d} className="px-2 py-0.5 bg-accent rounded text-xs font-mono">{d}</span>
      ))}
      {shouldCollapse && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="px-2 py-0.5 text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-0.5"
        >
          <ChevronDown className={cn('h-3 w-3 transition-transform', expanded ? 'rotate-180' : '')} />
          {expanded ? 'Show less' : `+${domains.length - SCOPE_CHIP_LIMIT} more`}
        </button>
      )}
    </div>
  )
}

function CollapsibleUrlList<T>({ items, renderItem }: { items: T[]; renderItem: (item: T, idx: number) => React.ReactNode }) {
  const [expanded, setExpanded] = useState(false)
  const shouldCollapse = items.length > COLLAPSE_THRESHOLD
  const visible = shouldCollapse && !expanded ? items.slice(0, COLLAPSE_THRESHOLD) : items

  return (
    <div className="divide-y divide-border">
      {visible.map((item, i) => renderItem(item, i))}
      {shouldCollapse && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full px-4 py-2 text-xs text-muted-foreground hover:text-foreground hover:bg-accent/30 flex items-center justify-center gap-1.5 transition-colors"
        >
          {expanded ? (
            <><ChevronDown className="h-3 w-3 rotate-180" /> Show less ({COLLAPSE_THRESHOLD} of {items.length})</>
          ) : (
            <><ChevronDown className="h-3 w-3" /> Show all {items.length} URLs ({items.length - COLLAPSE_THRESHOLD} more)</>
          )}
        </button>
      )}
    </div>
  )
}

function FieldDisplay({ field, value }: { field: string; value: unknown }) {
  if (field === 'login_pages' && Array.isArray(value)) {
    return <LoginPageDisplay pages={value as ContentExtraction['login_pages']} />
  }
  if (field === 'exposed_keys' && Array.isArray(value)) {
    return <>{(value as { type: string; value_preview: string }[]).map((k, i) => (
      <div key={i} className="text-xs font-mono text-muted-foreground">
        <span className="text-red-300">[{k.type}]</span> {k.value_preview}
      </div>
    ))}</>
  }
  if (field === 'tech_indicators' && Array.isArray(value)) {
    return <>{(value as { type: string; value: string }[]).map((t, i) => (
      <div key={i} className="text-xs font-mono text-muted-foreground">
        <span className="text-cyan-300">[{t.type}]</span> {t.value}
      </div>
    ))}</>
  }
  if (field === 'comments' && Array.isArray(value)) {
    return <>{(value as { content: string }[]).map((c, i) => (
      <div key={i} className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">{c.content}</div>
    ))}</>
  }
  if (field === 'hidden_inputs' && Array.isArray(value)) {
    return <>{(value as { name: string; value: string }[]).map((h, i) => (
      <div key={i} className="text-xs font-mono text-muted-foreground">{h.name}={h.value || '(empty)'}</div>
    ))}</>
  }
  if (field === 'file_metadata' && Array.isArray(value)) {
    const alertColors: Record<string, string> = {
      user_disclosure: 'text-orange-300 bg-orange-400/10',
      org_disclosure: 'text-amber-300 bg-amber-400/10',
      gps_disclosure: 'text-red-300 bg-red-400/10',
      hostname_disclosure: 'text-red-400 bg-red-400/10',
      path_disclosure: 'text-purple-300 bg-purple-400/10',
      software_disclosure: 'text-blue-300 bg-blue-400/10',
    }
    return <>{(value as { path: string; url: string; file_type: string; size_bytes: number; metadata: Record<string, string>; alerts: { type: string; detail: string }[] }[]).map((f, i) => (
      <div key={i} className="border border-border rounded p-2 mb-2 bg-accent/10">
        <div className="flex items-center gap-2 mb-1.5">
          <ScanSearch className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
          <span className="text-xs font-mono font-medium">{f.path}</span>
          <span className="text-[10px] text-muted-foreground">{f.file_type} — {(f.size_bytes / 1024).toFixed(1)}KB</span>
        </div>
        {f.alerts.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-1.5">
            {f.alerts.map((a, j) => (
              <span key={j} className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium', alertColors[a.type] || 'text-muted-foreground bg-accent')}>
                {a.detail}
              </span>
            ))}
          </div>
        )}
        <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
          {Object.entries(f.metadata).map(([k, v]) => (
            <div key={k} className="text-[11px]">
              <span className="text-muted-foreground">{k}:</span>{' '}
              <span className="font-mono">{v}</span>
            </div>
          ))}
        </div>
      </div>
    ))}</>
  }
  if (field === 'api_endpoints' && Array.isArray(value)) {
    const methodColors: Record<string, string> = {
      GET: 'text-green-400 bg-green-400/10', POST: 'text-blue-400 bg-blue-400/10',
      PUT: 'text-amber-400 bg-amber-400/10', PATCH: 'text-orange-400 bg-orange-400/10',
      DELETE: 'text-red-400 bg-red-400/10', OPTIONS: 'text-zinc-400 bg-zinc-400/10',
    }
    const typeColors: Record<string, string> = {
      rest: 'text-green-300', graphql: 'text-purple-300', websocket: 'text-cyan-300',
      soap: 'text-amber-300', grpc: 'text-blue-300', spec: 'text-pink-300', rpc: 'text-orange-300',
    }
    return <>{(value as { url: string; path: string; method: string; api_type?: string; confidence?: string; source?: string; signals?: string[] }[]).map((ep, i) => (
      <div key={i} className="flex items-start gap-2 py-1 border-b border-border/30 last:border-0">
        <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 mt-0.5', methodColors[ep.method?.toUpperCase()] || 'text-zinc-400 bg-zinc-400/10')}>
          {ep.method?.toUpperCase() || 'GET'}
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-mono truncate">{ep.path || ep.url}</div>
          <div className="flex items-center gap-2 mt-0.5">
            {ep.api_type && (
              <span className={cn('text-[10px] font-medium', typeColors[ep.api_type] || 'text-muted-foreground')}>
                {ep.api_type}
              </span>
            )}
            {ep.confidence && (
              <span className={cn('text-[10px]',
                ep.confidence === 'high' ? 'text-green-400' : ep.confidence === 'medium' ? 'text-amber-400' : 'text-muted-foreground'
              )}>{ep.confidence}</span>
            )}
            {ep.source && <span className="text-[10px] text-muted-foreground">{ep.source}</span>}
          </div>
        </div>
      </div>
    ))}</>
  }
  if (field === 'interesting_files' && Array.isArray(value)) {
    const catColors: Record<string, string> = {
      document: 'text-blue-300', archive: 'text-amber-300', backup: 'text-red-300',
      sensitive: 'text-red-400', config: 'text-orange-300', text: 'text-zinc-300',
      script: 'text-green-300', meta: 'text-purple-300', robots_path: 'text-purple-200',
    }
    return <>{(value as { path: string; category: string; content?: string; source?: string }[]).map((f, i) => (
      <div key={i} className="text-xs font-mono text-muted-foreground flex items-center gap-2">
        <span className={cn('shrink-0', catColors[f.category] || 'text-muted-foreground')}>[{f.category}]</span>
        <span>{f.path}</span>
        {f.source && <span className="text-muted-foreground/50">({f.source})</span>}
        {f.content && (
          <details className="inline">
            <summary className="cursor-pointer text-primary text-[10px] ml-1">content</summary>
            <pre className="mt-1 p-2 bg-muted rounded text-[10px] whitespace-pre-wrap max-h-40 overflow-y-auto">{f.content}</pre>
          </details>
        )}
      </div>
    ))}</>
  }
  if (Array.isArray(value)) {
    return (
      <div className="flex flex-wrap gap-1">
        {(value as unknown[]).slice(0, 50).map((item, i) => (
          <span key={i} className="px-2 py-0.5 bg-accent rounded text-xs font-mono">
            {typeof item === 'object' && item !== null
              ? String((item as Record<string, unknown>).path || (item as Record<string, unknown>).url || (item as Record<string, unknown>).name || JSON.stringify(item))
              : String(item)}
          </span>
        ))}
        {value.length > 50 && <span className="text-xs text-muted-foreground">+{value.length - 50} more</span>}
      </div>
    )
  }
  return <span className="text-xs font-mono text-muted-foreground">{typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
}

/* ───────────── Login Page Display with Brutus / Auth Scan actions ───────────── */

type LoginPage = ContentExtraction['login_pages'][number]

function LoginPageDisplay({ pages }: { pages: LoginPage[] }) {
  const launch = useLaunchScan()
  const credGuess = useCredentialGuess()
  const { data: credsData } = useCredentials()
  const credentials = credsData?.credentials ?? []
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null)
  const [selectedCred, setSelectedCred] = useState<string>('')
  const [launchedJobs, setLaunchedJobs] = useState<Record<number, string>>({})
  const [guessResults, setGuessResults] = useState<Record<number, CredentialGuessResult>>({})
  const [editedUsers, setEditedUsers] = useState<Record<number, string>>({})
  const [editedPasswords, setEditedPasswords] = useState<Record<number, string>>({})

  const confidenceColors: Record<string, string> = {
    high: 'bg-red-500/15 text-red-300 border-red-500/30',
    medium: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    low: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
  }
  const typeLabels: Record<string, string> = {
    password_form: 'Password Form', login_link: 'Login Link',
    login_title: 'Login Title', login_heading: 'Login Heading',
    auth_endpoint: 'Auth Endpoint',
  }

  const handleAnalyze = (page: LoginPage, idx: number, autoLaunch = true) => {
    const loginUrl = page.url.startsWith('http') ? page.url : ''
    if (!loginUrl) return
    credGuess.mutate(
      { login_url: loginUrl },
      {
        onSuccess: (data) => {
          setGuessResults(prev => ({ ...prev, [idx]: data }))
          const users = (data.usernames ?? []).map((u: { value: string }) => u.value).join(',')
          const passwords = (data.passwords ?? []).map((p: { value: string }) => p.value).join(',')
          setEditedUsers(prev => ({ ...prev, [idx]: users }))
          setEditedPasswords(prev => ({ ...prev, [idx]: passwords }))

          // Auto-launch Brutus with the generated credentials
          if (autoLaunch && users && passwords) {
            const host = loginUrl.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '')
            const protocol = loginUrl.startsWith('https') ? 'https' : 'http'
            launch.mutate(
              {
                type: 'brutus',
                params: {
                  targets: host,
                  protocols: protocol,
                  usernames: users,
                  passwords: passwords,
                  secret_type: 'password',
                },
              },
              {
                onSuccess: (brutusData) => setLaunchedJobs(prev => ({ ...prev, [idx]: brutusData.job_id })),
              }
            )
          }
        },
      }
    )
  }

  const handleLaunchBrutus = (page: LoginPage, idx: number) => {
    const target = page.url.startsWith('http') ? page.url : ''
    if (!target) return
    const host = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '')
    const protocol = target.startsWith('https') ? 'https' : 'http'
    launch.mutate(
      {
        type: 'brutus',
        params: {
          targets: host,
          protocols: protocol,
          usernames: editedUsers[idx] || 'admin',
          passwords: editedPasswords[idx] || 'admin',
          secret_type: 'password',
        },
      },
      {
        onSuccess: (data) => setLaunchedJobs(prev => ({ ...prev, [idx]: data.job_id })),
      }
    )
  }

  const handleAuthScan = (page: LoginPage, idx: number) => {
    const target = page.url.startsWith('http') ? page.url : ''
    if (!target || !selectedCred) return
    const cred = credentials.find(c => c.id === selectedCred)
    if (!cred) return
    launch.mutate(
      {
        type: 'playwright',
        params: {
          url: target,
          use_zap_proxy: true,
          run_security_checks: true,
          auth_username: cred.username,
          auth_password: cred.credential_value || cred.cracked_value || '',
          auth_login_url: target,
        },
      },
      {
        onSuccess: (data) => setLaunchedJobs(prev => ({ ...prev, [idx]: data.job_id })),
      }
    )
  }

  return (
    <>
      {pages.map((page, i) => {
        const guess = guessResults[i]
        return (
          <div key={i} className="border border-border rounded p-2.5 mb-2 bg-accent/10">
            {/* Header: confidence + type + URL */}
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <LogIn className="h-3.5 w-3.5 text-rose-400 shrink-0" />
              <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-medium border', confidenceColors[page.confidence] || confidenceColors.low)}>
                {page.confidence}
              </span>
              <span className="text-[10px] text-muted-foreground">{typeLabels[page.type] || page.type}</span>
              <span className="font-mono text-xs truncate flex-1">{page.url}</span>
            </div>

            {/* Login page details */}
            {page.username_fields && page.username_fields.length > 0 && (
              <div className="text-[11px] text-muted-foreground mb-1">
                <span className="text-zinc-400">Username fields:</span>{' '}
                {page.username_fields.map((f, j) => (
                  <span key={j} className="font-mono px-1 py-0.5 bg-accent rounded text-[10px] mr-1">{f}</span>
                ))}
              </div>
            )}
            {page.form_actions && page.form_actions.length > 0 && (
              <div className="text-[11px] text-muted-foreground mb-1">
                <span className="text-zinc-400">Form action:</span>{' '}
                {page.form_actions.map((a, j) => <span key={j} className="font-mono text-[10px]">{a}</span>)}
              </div>
            )}
            {page.indicator_text && (
              <div className="text-[11px] text-muted-foreground mb-1">
                <span className="text-zinc-400">Indicator:</span> &quot;{page.indicator_text}&quot;
              </div>
            )}

            {/* Action buttons */}
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              <button
                onClick={() => handleAnalyze(page, i)}
                disabled={!page.url.startsWith('http') || credGuess.isPending}
                className={cn(
                  'flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium border transition-colors',
                  'bg-violet-500/10 text-violet-300 border-violet-500/30 hover:bg-violet-500/20',
                  'disabled:opacity-40 disabled:cursor-not-allowed',
                )}
                title="AI analyzes content intel, generates credential guesses, and auto-launches Brutus"
              >
                {credGuess.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : launch.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                {credGuess.isPending ? 'Analyzing (may take 30-60s)...' : launch.isPending ? 'Launching Brutus...' : guess ? 'Re-Analyze & Test' : 'Analyze & Brute Force'}
              </button>
              {credGuess.isError && !guess && (
                <span className="text-[10px] text-red-400">
                  Analysis failed — {String(credGuess.error).includes('timeout') || String(credGuess.error).includes('500')
                    ? 'LLM timed out. Ensure the model is loaded (GPU tab) and try again.'
                    : String(credGuess.error).slice(0, 100)}
                </span>
              )}

              <button
                onClick={() => setExpandedIdx(expandedIdx === i ? null : i)}
                className={cn(
                  'flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium border transition-colors',
                  'bg-blue-500/10 text-blue-300 border-blue-500/30 hover:bg-blue-500/20',
                )}
                title="Scan authenticated with credentials from vault"
              >
                <Shield className="h-3 w-3" />
                Authenticated Scan
                {expandedIdx === i ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              </button>

              {launchedJobs[i] && (
                <Link to={`/scans/${launchedJobs[i]}`} className="flex items-center gap-1 text-[10px] text-primary hover:underline">
                  <ExternalLink className="h-3 w-3" /> Job {launchedJobs[i].slice(0, 8)}
                </Link>
              )}
            </div>

            {/* LLM Analysis Results */}
            {guess && (
              <div className="mt-2 p-3 bg-muted/50 rounded border border-violet-500/20 space-y-3">
                <div className="flex items-center gap-2">
                  <Zap className="h-3.5 w-3.5 text-violet-400" />
                  <span className="text-xs font-medium text-violet-300">AI Credential Analysis</span>
                  <span className="text-[10px] text-muted-foreground">
                    ({guess.model} | {guess.intel_summary?.emails_found} emails, {guess.intel_summary?.names_found} names, {guess.intel_summary?.tech_indicators} tech)
                  </span>
                </div>

                {/* Analysis summary */}
                {guess.analysis && (
                  <div className="text-[11px] text-muted-foreground border-l-2 border-violet-500/30 pl-2">
                    {guess.analysis}
                  </div>
                )}

                {/* Username guesses with rationale */}
                {guess.usernames && guess.usernames.length > 0 && (
                  <div>
                    <div className="text-[10px] text-zinc-400 mb-1">USERNAMES ({guess.usernames.length} guesses)</div>
                    <div className="flex flex-wrap gap-1 mb-1.5">
                      {guess.usernames.map((u, j) => (
                        <span key={j} className="px-1.5 py-0.5 bg-accent rounded text-[10px] font-mono" title={u.rationale}>
                          {u.value}
                        </span>
                      ))}
                    </div>
                    <input
                      className="w-full px-2 py-1 bg-card border border-border rounded text-xs font-mono"
                      value={editedUsers[i] ?? ''}
                      onChange={e => setEditedUsers(prev => ({ ...prev, [i]: e.target.value }))}
                      placeholder="Edit usernames (comma-separated)"
                    />
                  </div>
                )}

                {/* Password guesses with rationale */}
                {guess.passwords && guess.passwords.length > 0 && (
                  <div>
                    <div className="text-[10px] text-zinc-400 mb-1">PASSWORDS ({guess.passwords.length} guesses)</div>
                    <div className="flex flex-wrap gap-1 mb-1.5">
                      {guess.passwords.map((p, j) => (
                        <span key={j} className="px-1.5 py-0.5 bg-accent rounded text-[10px] font-mono" title={p.rationale}>
                          {p.value}
                        </span>
                      ))}
                    </div>
                    <input
                      className="w-full px-2 py-1 bg-card border border-border rounded text-xs font-mono"
                      value={editedPasswords[i] ?? ''}
                      onChange={e => setEditedPasswords(prev => ({ ...prev, [i]: e.target.value }))}
                      placeholder="Edit passwords (comma-separated)"
                    />
                  </div>
                )}

                {guess.parse_error && (
                  <div className="text-[10px] text-amber-400">Note: {guess.parse_error}</div>
                )}

                {/* Launch Brutus with these guesses */}
                <button
                  onClick={() => handleLaunchBrutus(page, i)}
                  disabled={launch.isPending || (!editedUsers[i] && !editedPasswords[i])}
                  className={cn(
                    'flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border transition-colors',
                    'bg-red-500/10 text-red-300 border-red-500/30 hover:bg-red-500/20',
                    'disabled:opacity-40 disabled:cursor-not-allowed',
                  )}
                >
                  <Play className="h-3.5 w-3.5" />
                  {launch.isPending ? 'Launching Brutus...' : 'Launch Brutus with These Credentials'}
                </button>
              </div>
            )}

            {/* Credential vault selector for authenticated scan */}
            {expandedIdx === i && (
              <div className="mt-2 p-2 bg-muted/50 rounded border border-border space-y-2">
                <div className="text-[11px] text-muted-foreground">Select credentials from vault to authenticate:</div>
                {credentials.length === 0 ? (
                  <div className="text-[11px] text-muted-foreground/60">
                    No credentials in vault. Add credentials via the Credential Vault page.
                  </div>
                ) : (
                  <div className="flex items-center gap-2 flex-wrap">
                    <select
                      value={selectedCred}
                      onChange={e => setSelectedCred(e.target.value)}
                      className="h-7 px-2 text-[11px] rounded border border-border bg-card min-w-[200px]"
                    >
                      <option value="">Select credential...</option>
                      {credentials.map(c => (
                        <option key={c.id} value={c.id}>
                          {c.username}{c.domain ? `@${c.domain}` : ''} [{c.credential_type}] ({c.status})
                        </option>
                      ))}
                    </select>
                    <button
                      onClick={() => handleAuthScan(page, i)}
                      disabled={!selectedCred || !page.url.startsWith('http') || launch.isPending}
                      className={cn(
                        'flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium border transition-colors',
                        'bg-green-500/10 text-green-300 border-green-500/30 hover:bg-green-500/20',
                        'disabled:opacity-40 disabled:cursor-not-allowed',
                      )}
                    >
                      <Play className="h-3 w-3" />
                      {launch.isPending ? 'Launching...' : 'Launch Auth Scan'}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </>
  )
}

/* ───────────── Sitemap Tab ───────────── */

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-300',
  high: 'bg-orange-500/20 text-orange-300',
  medium: 'bg-yellow-500/20 text-yellow-300',
  low: 'bg-blue-500/20 text-blue-300',
  info: 'bg-zinc-500/20 text-zinc-300',
}

function SitemapTab({ assetFilter, scopeDomains: parentScopeDomains, selectedScope: parentScope }: {
  assetFilter: string; scopeDomains?: string[]; selectedScope?: string
}) {
  const [domain, setDomain] = useState('')
  const [searchDomain, setSearchDomain] = useState('')
  const [sourceFilter, setSourceFilter] = useState<string | null>(null)
  const [methodFilter, setMethodFilter] = useState<string | null>(null)

  const scopeDomains = parentScopeDomains ?? []

  const { data, isLoading } = useSitemap(searchDomain || undefined, assetFilter || undefined)

  const allUrls = data?.urls ?? []

  // Apply local filters
  const urls = allUrls.filter(u => {
    if (sourceFilter && !u.sources.includes(sourceFilter)) return false
    if (methodFilter && !u.methods.includes(methodFilter)) return false
    return true
  })

  // Aggregate stats
  const allSources = [...new Set(allUrls.flatMap(u => u.sources))].sort()
  const allMethods = [...new Set(allUrls.flatMap(u => u.methods))].sort()
  const totalFindings = allUrls.reduce((s, u) => s + u.findings, 0)
  const totalParams = allUrls.reduce((s, u) => s + u.params.length, 0)
  const withFindings = allUrls.filter(u => u.findings > 0).length

  const handleSearch = () => setSearchDomain(domain)
  const handleScopeDomain = (d: string) => {
    setDomain(d)
    setSearchDomain(d)
  }

  // Build tree structure from URLs
  const tree = buildUrlTree(urls)

  return (
    <div className="space-y-4">
      {/* Scope domain quick-select (collapsible) */}
      {scopeDomains.length > 0 && (
        <ScopeTargetChips domains={scopeDomains} onSelect={handleScopeDomain} selectedDomain={searchDomain} />
      )}

      {/* Search + Export */}
      <div className="flex items-center gap-3">
        <div className="flex-1 flex gap-2">
          <input
            className="flex-1 px-3 py-1.5 bg-card border border-border rounded text-sm"
            placeholder="Domain (e.g. demo.testfire.net)"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
          />
          <button onClick={handleSearch}
            className="px-4 py-1.5 bg-primary text-primary-foreground rounded text-sm font-medium">
            Load Sitemap
          </button>
        </div>
        {searchDomain && allUrls.length > 0 && (
          <div className="flex gap-1">
            <a
              href={apiUrl(`/content-intel/sitemap/export/burp?domain=${encodeURIComponent(searchDomain)}`)}
              className="px-3 py-1.5 bg-card border border-border rounded text-xs hover:bg-accent flex items-center gap-1"
              download
            >
              <Download className="h-3 w-3" /> Burp XML
            </a>
            <a
              href={apiUrl(`/content-intel/sitemap/export/urls?domain=${encodeURIComponent(searchDomain)}`)}
              className="px-3 py-1.5 bg-card border border-border rounded text-xs hover:bg-accent flex items-center gap-1"
              download
            >
              <Download className="h-3 w-3" /> URL List
            </a>
            <button
              onClick={async () => {
                const res = await fetch('/api/reports/export-har', {
                  method: 'POST', headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ target: searchDomain, limit: 2000 }),
                })
                if (res.ok) {
                  const blob = await res.blob()
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a'); a.href = url; a.download = `${searchDomain}_sitemap.har`; a.click()
                }
              }}
              className="px-3 py-1.5 bg-card border border-border rounded text-xs hover:bg-accent flex items-center gap-1"
            >
              <Download className="h-3 w-3" /> HAR Export
            </button>
            <SitemapProxyReplay domain={searchDomain} urlCount={allUrls.length} />
          </div>
        )}
      </div>

      {/* Stats bar */}
      {allUrls.length > 0 && (
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span><strong className="text-foreground">{allUrls.length}</strong> URLs</span>
          <span><strong className="text-foreground">{withFindings}</strong> with findings</span>
          <span><strong className="text-foreground">{totalFindings}</strong> total findings</span>
          <span><strong className="text-foreground">{totalParams}</strong> params</span>
          <span className="flex-1" />
          <Link to={`/scope-intel`} className="text-primary hover:underline flex items-center gap-1">
            <ExternalLink className="h-3 w-3" /> Scope Intel
          </Link>
          <Link to={`/recon`} className="text-primary hover:underline flex items-center gap-1">
            <ExternalLink className="h-3 w-3" /> OSINT Explorer
          </Link>
        </div>
      )}

      {/* Source / Method filters */}
      {allUrls.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          <Filter className="h-3.5 w-3.5 text-muted-foreground mt-0.5" />
          {allSources.map(s => (
            <button key={s} onClick={() => setSourceFilter(sourceFilter === s ? null : s)}
              className={cn('px-2 py-0.5 rounded text-xs border',
                sourceFilter === s ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground')}>
              {s}
            </button>
          ))}
          <span className="text-border">|</span>
          {allMethods.map(m => (
            <button key={m} onClick={() => setMethodFilter(methodFilter === m ? null : m)}
              className={cn('px-2 py-0.5 rounded text-xs border font-mono',
                methodFilter === m ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground')}>
              {m}
            </button>
          ))}
        </div>
      )}

      {/* URL Table */}
      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading sitemap...
        </div>
      ) : !searchDomain && !assetFilter ? (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <Map className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">Enter a domain to load the sitemap.</p>
        </div>
      ) : urls.length === 0 ? (
        <p className="text-sm text-muted-foreground p-4">No URLs found for this domain. Run a Content Recon or Web scan first.</p>
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="max-h-[600px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="bg-accent/30 sticky top-0">
                <tr>
                  <th className="text-left px-3 py-2 font-medium">URL</th>
                  <th className="text-left px-2 py-2 font-medium w-20">Method</th>
                  <th className="text-left px-2 py-2 font-medium w-16">Status</th>
                  <th className="text-left px-2 py-2 font-medium w-24">Sources</th>
                  <th className="text-center px-2 py-2 font-medium w-16">Findings</th>
                  <th className="text-left px-2 py-2 font-medium w-24">Severity</th>
                  <th className="text-center px-2 py-2 font-medium w-16">Params</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {urls.map((entry, i) => (
                  <tr key={i} className="hover:bg-accent/20">
                    <td className="px-3 py-1.5 font-mono truncate max-w-[400px]" title={entry.url}>
                      {entry.url}
                    </td>
                    <td className="px-2 py-1.5 font-mono">
                      {entry.methods.join(', ')}
                    </td>
                    <td className="px-2 py-1.5">
                      {entry.status_codes.map(s => (
                        <span key={s} className={cn('px-1 rounded mr-0.5',
                          s >= 200 && s < 300 ? 'text-green-400' :
                          s >= 300 && s < 400 ? 'text-blue-400' :
                          s >= 400 ? 'text-red-400' : '')}>{s}</span>
                      ))}
                    </td>
                    <td className="px-2 py-1.5">
                      <div className="flex flex-wrap gap-0.5">
                        {entry.sources.slice(0, 3).map(s => (
                          <span key={s} className="px-1 bg-accent rounded text-[10px]">{s}</span>
                        ))}
                        {entry.sources.length > 3 && <span className="text-[10px] text-muted-foreground">+{entry.sources.length - 3}</span>}
                      </div>
                    </td>
                    <td className="px-2 py-1.5 text-center">
                      {entry.findings > 0 && (
                        <span className="font-medium text-primary">{entry.findings}</span>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      <div className="flex gap-0.5">
                        {entry.severities
                          .sort((a, b) => (SEVERITY_ORDER[a] ?? 9) - (SEVERITY_ORDER[b] ?? 9))
                          .map(s => (
                            <span key={s} className={cn('px-1 rounded text-[10px]', SEVERITY_COLORS[s] || '')}>{s}</span>
                          ))}
                      </div>
                    </td>
                    <td className="px-2 py-1.5 text-center">
                      {entry.params.length > 0 && (
                        <span className="font-medium text-amber-400" title={entry.params.map(p => p.name).join(', ')}>
                          {entry.params.length}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

function buildUrlTree(_urls: SitemapEntry[]): void {
  // placeholder for future tree view
}

/* ───────────── Wordlists Tab ───────────── */

function WordlistsTab({ assetFilter }: { assetFilter: string }) {
  const generateWordlist = useGenerateWordlist()
  const [listType, setListType] = useState<ListType>('passwords')
  const [minLength, setMinLength] = useState(5)
  const [enableMutations, setEnableMutations] = useState(true)
  const [selectedMutations, setSelectedMutations] = useState<string[]>(MUTATIONS.map(m => m.id))
  const [selectedSources, setSelectedSources] = useState<string[]>(SOURCES.map(s => s.id))

  const toggleMutation = (id: string) =>
    setSelectedMutations(prev => prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id])
  const toggleSource = (id: string) =>
    setSelectedSources(prev => prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id])

  const handleGenerate = () => {
    generateWordlist.mutate({
      asset_id: assetFilter || undefined,
      list_type: listType,
      min_word_length: minLength,
      enable_mutations: enableMutations,
      mutations: selectedMutations,
      include_sources: selectedSources,
    })
  }

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Zap className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold">CeWL Wordlist Generator</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">List Type</label>
          <div className="flex gap-2">
            {(['passwords', 'usernames', 'directories'] as ListType[]).map(t => (
              <button key={t} onClick={() => setListType(t)}
                className={cn('px-3 py-1.5 rounded text-xs border transition-colors',
                  listType === t ? 'bg-primary/20 border-primary text-primary' : 'border-border text-muted-foreground hover:bg-accent')}>
                {t}
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Min Word Length: {minLength}</label>
          <input type="range" min={3} max={12} value={minLength}
            onChange={e => setMinLength(Number(e.target.value))} className="w-full" />
        </div>
        <div>
          <label className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
            <input type="checkbox" checked={enableMutations} onChange={e => setEnableMutations(e.target.checked)} />
            Enable Mutations
          </label>
        </div>
      </div>

      {enableMutations && listType === 'passwords' && (
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Mutations</label>
          <div className="flex flex-wrap gap-2">
            {MUTATIONS.map(m => (
              <label key={m.id} className="flex items-center gap-1.5 text-xs">
                <input type="checkbox" checked={selectedMutations.includes(m.id)} onChange={() => toggleMutation(m.id)} />
                {m.label}
              </label>
            ))}
          </div>
        </div>
      )}

      <div>
        <label className="text-xs text-muted-foreground mb-1 block">Include Sources</label>
        <div className="flex flex-wrap gap-2">
          {SOURCES.map(s => (
            <label key={s.id} className="flex items-center gap-1.5 text-xs">
              <input type="checkbox" checked={selectedSources.includes(s.id)} onChange={() => toggleSource(s.id)} />
              {s.label}
            </label>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-4">
        <button onClick={handleGenerate} disabled={generateWordlist.isPending}
          className="px-4 py-2 bg-primary text-primary-foreground rounded text-sm font-medium hover:bg-primary/90 disabled:opacity-50 flex items-center gap-2">
          {generateWordlist.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
          Generate Wordlist
        </button>
        {generateWordlist.isSuccess && generateWordlist.data && (
          <div className="text-sm text-green-400">
            Generated <span className="font-mono font-semibold">{generateWordlist.data.name}</span>
            {' — '}{generateWordlist.data.line_count.toLocaleString()} lines
          </div>
        )}
        {generateWordlist.isError && (
          <div className="text-sm text-red-400">{(generateWordlist.error as Error).message}</div>
        )}
      </div>
    </div>
  )
}

/* ───────────── Settings Tab ───────────── */

function SettingsTab() {
  const { data: patternsData, isLoading } = useContentPatterns()
  const createPattern = useCreatePattern()
  const updatePattern = useUpdatePattern()
  const deletePattern = useDeletePattern()

  const [showAdd, setShowAdd] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [form, setForm] = useState({ category: 'custom', name: '', pattern: '', label: '', description: '', enabled: true })

  const patterns = patternsData?.patterns ?? []
  const grouped = CATEGORIES.map(cat => ({
    ...cat,
    patterns: patterns.filter(p => p.category === cat.id),
  }))

  const resetForm = () => {
    setForm({ category: 'custom', name: '', pattern: '', label: '', description: '', enabled: true })
    setShowAdd(false)
    setEditId(null)
  }

  const startEdit = (p: ContentPattern) => {
    setEditId(p.id)
    setForm({
      category: p.category,
      name: p.name,
      pattern: p.pattern,
      label: p.label || '',
      description: p.description || '',
      enabled: p.enabled,
    })
    setShowAdd(true)
  }

  const handleSave = () => {
    if (!form.name || !form.pattern) return
    if (editId) {
      updatePattern.mutate({ id: editId, ...form }, { onSuccess: resetForm })
    } else {
      createPattern.mutate(form, { onSuccess: resetForm })
    }
  }

  return (
    <div className="space-y-4">
      {/* Add / Edit form */}
      <div className="bg-card border border-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold">Extraction Patterns</h3>
          {!showAdd && (
            <button onClick={() => { resetForm(); setShowAdd(true) }}
              className="px-3 py-1.5 bg-primary text-primary-foreground rounded text-xs font-medium flex items-center gap-1">
              <Plus className="h-3 w-3" /> Add Pattern
            </button>
          )}
        </div>

        {showAdd && (
          <div className="border border-border rounded-lg p-3 mb-4 space-y-3 bg-accent/10">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Category</label>
                <select value={form.category} onChange={e => setForm({ ...form, category: e.target.value })}
                  className="w-full bg-muted rounded px-2 py-1.5 text-sm border border-border">
                  {CATEGORIES.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Name</label>
                <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                  className="w-full bg-muted rounded px-2 py-1.5 text-sm border border-border"
                  placeholder="e.g. slack_webhook" />
              </div>
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Regex Pattern</label>
              <input value={form.pattern} onChange={e => setForm({ ...form, pattern: e.target.value })}
                className="w-full bg-muted rounded px-2 py-1.5 text-sm font-mono border border-border"
                placeholder="e.g. hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+" />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Label (display name)</label>
                <input value={form.label} onChange={e => setForm({ ...form, label: e.target.value })}
                  className="w-full bg-muted rounded px-2 py-1.5 text-sm border border-border"
                  placeholder="e.g. Slack Webhook URL" />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Description</label>
                <input value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
                  className="w-full bg-muted rounded px-2 py-1.5 text-sm border border-border"
                  placeholder="What this pattern detects" />
              </div>
            </div>
            <div className="flex items-center gap-4">
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
                Enabled
              </label>
              <div className="flex-1" />
              <button onClick={resetForm} className="px-3 py-1.5 rounded text-xs border border-border hover:bg-accent">Cancel</button>
              <button onClick={handleSave}
                disabled={!form.name || !form.pattern || createPattern.isPending || updatePattern.isPending}
                className="px-3 py-1.5 bg-primary text-primary-foreground rounded text-xs font-medium disabled:opacity-50 flex items-center gap-1">
                {(createPattern.isPending || updatePattern.isPending) && <Loader2 className="h-3 w-3 animate-spin" />}
                {editId ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        )}

        {/* Pattern list by category */}
        {isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading patterns...
          </div>
        ) : patterns.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No custom patterns defined. Add patterns to extend the content analyzer's detection capabilities.
          </p>
        ) : (
          <div className="space-y-4">
            {grouped.filter(g => g.patterns.length > 0).map(group => (
              <div key={group.id}>
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  {group.label} ({group.patterns.length})
                </h4>
                <div className="space-y-1">
                  {group.patterns.map(p => (
                    <div key={p.id} className="flex items-center gap-3 px-3 py-2 rounded border border-border bg-accent/5 hover:bg-accent/20">
                      <button
                        onClick={() => updatePattern.mutate({ id: p.id, enabled: !p.enabled })}
                        className={cn('shrink-0', p.enabled ? 'text-green-400' : 'text-muted-foreground')}
                        title={p.enabled ? 'Disable' : 'Enable'}
                      >
                        {p.enabled ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                      </button>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">{p.name}</span>
                          {p.label && p.label !== p.name && (
                            <span className="text-xs text-muted-foreground">({p.label})</span>
                          )}
                          {p.is_builtin && (
                            <span className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 rounded text-[10px]">builtin</span>
                          )}
                        </div>
                        <div className="text-xs font-mono text-muted-foreground truncate">{p.pattern}</div>
                        {p.description && (
                          <div className="text-xs text-muted-foreground/60 mt-0.5">{p.description}</div>
                        )}
                      </div>
                      <button onClick={() => startEdit(p)}
                        className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground" title="Edit">
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      {!p.is_builtin && (
                        <button
                          onClick={() => { if (confirm(`Delete pattern "${p.name}"?`)) deletePattern.mutate(p.id) }}
                          className="p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive" title="Delete">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Built-in patterns reference */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Built-in Patterns (always active)</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
          {[
            { cat: 'Emails', desc: 'Standard email regex with false-positive filtering (image retina, CSS @rules)' },
            { cat: 'Secrets', desc: 'API keys, Bearer tokens, passwords, AWS keys, secrets in JS assignments' },
            { cat: 'Paths', desc: 'Internal paths from href/src/action/data-* attributes and JS string literals' },
            { cat: 'API Endpoints', desc: '/api/*, /v1/*, /graphql, /rest/*, /ws/* in JS and HTML' },
            { cat: 'Tech', desc: 'Generator meta, WordPress/Drupal/Joomla, JS frameworks (React, Next, Vue, Angular)' },
            { cat: 'Comments', desc: 'HTML comments containing password, TODO, FIXME, debug, admin, secret, credential' },
            { cat: 'JS Configs', desc: 'window.config, window.env, __APP_CONFIG__, __INITIAL_STATE__, __NEXT_DATA__' },
            { cat: 'Names', desc: 'Meta author tags, schema.org "name" fields' },
          ].map(b => (
            <div key={b.cat} className="flex gap-2 p-2 rounded bg-accent/10">
              <span className="font-semibold text-primary shrink-0 w-24">{b.cat}</span>
              <span className="text-muted-foreground">{b.desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

/* ───────────── Shared components ───────────── */

function SummaryCard({ icon: Icon, label, count, color }: {
  icon: typeof Mail; label: string; count: number; color: string
}) {
  return (
    <div className="bg-card border border-border rounded-lg p-3">
      <div className="flex items-center gap-2 mb-1">
        <Icon className={cn('h-4 w-4', color)} />
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <span className="text-xl font-bold">{count.toLocaleString()}</span>
    </div>
  )
}
