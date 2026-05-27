import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { apiUrl } from '@/api/client'
import PageHelp from '@/components/PageHelp'
import PopoutButton from '@/components/PopoutButton'
import {
  Users as UsersIcon,
  Shield,
  UserPlus,
  RefreshCw,
  Search,
  Key,
  Cloud,
  X,
  ExternalLink,
  Download,
  CheckSquare,
  Square,
  ChevronLeft,
  ChevronRight,
  Loader2,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface Identity {
  id: string
  provider: string
  identifier: string
  display_name: string | null
  principal_type: string | null
  status: string
  mfa_state: string | null
  last_signin: string | null
  tenant_id: string | null
  domain: string | null
  is_admin: boolean
  is_guest: boolean
  is_dirsync: boolean
  tags: string[]
  sources: string[]
  first_seen: string | null
  last_seen: string | null
  has_credential: boolean
}

interface IdentityDetail extends Identity {
  raw: any
  credentials: Array<{
    id: string
    username: string
    domain: string | null
    credential_type: string
    status: string
    source: string
    created_at: string | null
  }>
  recon_findings: Array<{
    id: string
    source: string
    finding_type: string
    target: string
    severity: string
    created_at: string | null
  }>
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info:     'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
}

export default function Users() {
  // Seed initial filter state from URL params so deep links from the
  // popout-detail group chips and other pages actually filter.
  // (The detail popout writes ?member_of=<group>; without this, opening
  // such a link landed on /users with no filter and showed every row.)
  const [searchParams] = useSearchParams()
  const _initial = (key: string) => searchParams.get(key) || ''
  const [provider, setProvider] = useState<string>(_initial('provider'))
  const [principalType, setPrincipalType] = useState<string>(_initial('principal_type'))
  const [search, setSearch] = useState<string>(_initial('search'))
  const [adminOnly, setAdminOnly] = useState(_initial('is_admin') === 'true')
  const [guestOnly, setGuestOnly] = useState(_initial('is_guest') === 'true')
  const [credOnly, setCredOnly] = useState(_initial('has_credential') === 'true')
  const [activeOnly, setActiveOnly] = useState(true)  // default ON for spray hygiene
  const [groupFilter, setGroupFilter] = useState<string>(_initial('member_of'))
  const [page, setPage] = useState(0)               // 0-indexed
  const [pageSize, setPageSize] = useState(200)
  const [exportingAll, setExportingAll] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  // Wrap each filter setter so a filter change ALSO resets paging to 0 in
  // the same React batch. Previously this was a useEffect — but useEffects
  // run after the next render, so the FIRST query after a filter change
  // briefly fired with the stale offset (e.g. offset=1000 of a 34-row group),
  // returning an empty result before the page-reset query landed.
  const _onFilter = <T,>(setter: React.Dispatch<React.SetStateAction<T>>) =>
    (v: T) => { setter(v); setPage(0) }
  const setProviderF      = _onFilter(setProvider)
  const setPrincipalTypeF = _onFilter(setPrincipalType)
  const setSearchF        = _onFilter(setSearch)
  const setAdminOnlyF     = _onFilter(setAdminOnly)
  const setGuestOnlyF     = _onFilter(setGuestOnly)
  const setCredOnlyF      = _onFilter(setCredOnly)
  const setActiveOnlyF    = _onFilter(setActiveOnly)
  const setGroupFilterF   = _onFilter(setGroupFilter)
  // Per-row selection map for bulk export. Keyed by id, value is the full
  // row so selections survive pagination — without this, switching pages
  // would drop earlier-page selections from the export.
  const [selectedForExport, setSelectedForExport] = useState<Map<string, Identity>>(new Map())
  const [selectingAll, setSelectingAll] = useState(false)

  const toggleSelect = (row: Identity) => {
    setSelectedForExport(prev => {
      const next = new Map(prev)
      if (next.has(row.id)) next.delete(row.id); else next.set(row.id, row)
      return next
    })
  }
  const selectAllVisible = (rows: Identity[]) => {
    setSelectedForExport(prev => {
      const next = new Map(prev)
      rows.forEach(r => next.set(r.id, r))
      return next
    })
  }
  const clearSelection = () => setSelectedForExport(new Map())

  const downloadBlob = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }
  const exportTxt = (rows: Identity[]) => {
    // One identifier per line — standard input format for spray / kerbrute / MailSniper
    const lines = rows.map(r => r.identifier).filter(Boolean)
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    downloadBlob(lines.join('\n') + '\n',
                 `spray-list-${stamp}.txt`, 'text/plain;charset=utf-8')
  }
  const exportCsv = (rows: Identity[]) => {
    const header = [
      'id', 'provider', 'identifier', 'display_name', 'principal_type',
      'status', 'mfa_state', 'last_signin', 'tenant_id', 'domain',
      'is_admin', 'is_guest', 'is_dirsync', 'has_credential',
      'tags', 'sources', 'first_seen', 'last_seen',
    ].join(',')
    const esc = (v: any) => {
      if (v == null) return ''
      const s = String(v).replace(/"/g, '""')
      return /[",\n]/.test(s) ? `"${s}"` : s
    }
    const body = rows.map(r => [
      esc(r.id), esc(r.provider), esc(r.identifier), esc(r.display_name),
      esc(r.principal_type), esc(r.status), esc(r.mfa_state), esc(r.last_signin),
      esc(r.tenant_id), esc(r.domain),
      r.is_admin, r.is_guest, r.is_dirsync, r.has_credential,
      esc((r.tags || []).join('|')), esc((r.sources || []).join('|')),
      esc(r.first_seen), esc(r.last_seen),
    ].join(','))
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    downloadBlob([header, ...body].join('\n') + '\n',
                 `identities-${stamp}.csv`, 'text/csv;charset=utf-8')
  }

  const summaryQ = useQuery({
    queryKey: ['identities', 'summary'],
    queryFn: async () => (await fetch(apiUrl('/identities/summary'))).json(),
    refetchInterval: 30_000,
  })

  // Distinct groups derived from `member_of:<group>` tags. Used to populate
  // the group-filter dropdown so an operator can pick e.g. "Domain Admins"
  // and export only that group's members.
  const groupsQ = useQuery({
    queryKey: ['identities', 'groups'],
    queryFn: async () => {
      const r = await fetch(apiUrl('/identities/groups'))
      if (!r.ok) throw new Error(await r.text())
      return r.json() as Promise<{ results: Array<{ name: string; members: number }> }>
    },
    refetchInterval: 60_000,
  })
  const groups = groupsQ.data?.results ?? []

  // Build the filter portion of the params (excluding limit/offset). Used by
  // both the paged list query AND the "export all matching" loop below.
  const buildFilterParams = () => {
    const p = new URLSearchParams()
    if (provider) p.set('provider', provider)
    if (principalType) p.set('principal_type', principalType)
    if (search) p.set('search', search)
    if (adminOnly) p.set('is_admin', 'true')
    if (guestOnly) p.set('is_guest', 'true')
    if (credOnly) p.set('has_credential', 'true')
    if (groupFilter) p.set('member_of', groupFilter)
    return p
  }

  const params = buildFilterParams()
  params.set('limit', String(pageSize))
  params.set('offset', String(page * pageSize))

  const listQ = useQuery({
    queryKey: ['identities', 'list', params.toString()],
    queryFn: async () => {
      const r = await fetch(apiUrl(`/identities?${params.toString()}`))
      if (!r.ok) throw new Error(await r.text())
      return r.json()
    },
  })

  // Fetch every row matching the current filters, paging in batches up to
  // PAGE_BATCH at a time. Used by the "Export all (filtered)" buttons so the
  // operator doesn't have to manually click through pages to build a spray
  // list of e.g. 5,000 users.
  const fetchAllMatching = async (): Promise<Identity[]> => {
    const PAGE_BATCH = 2000  // matches the API's max per-request limit
    const all: Identity[] = []
    const filterParams = buildFilterParams()
    filterParams.set('limit', String(PAGE_BATCH))
    let off = 0
    // Hard cap so a runaway loop can't lock the UI
    const HARD_CAP = 100_000
    while (all.length < HARD_CAP) {
      filterParams.set('offset', String(off))
      const r = await fetch(apiUrl(`/identities?${filterParams.toString()}`))
      if (!r.ok) throw new Error(await r.text())
      const j = await r.json()
      const got: Identity[] = j.results ?? []
      all.push(...got)
      if (got.length < PAGE_BATCH) break
      off += PAGE_BATCH
    }
    return all
  }

  const exportAllFiltered = async (mode: 'txt' | 'csv') => {
    setExportingAll(true)
    try {
      let rows = await fetchAllMatching()
      if (activeOnly) rows = rows.filter(r => r.status !== 'disabled')
      if (mode === 'txt') exportTxt(rows)
      else exportCsv(rows)
    } catch (e) {
      console.error('export-all failed:', e)
      alert(`Export failed: ${e}`)
    } finally {
      setExportingAll(false)
    }
  }

  // Add every row matching the current filters to the selection — paged
  // through in 2000-row batches up to HARD_CAP. This lets the operator
  // pick e.g. "all 8,000 admins" then de-select a handful before exporting.
  const selectAllMatching = async () => {
    setSelectingAll(true)
    try {
      let rows = await fetchAllMatching()
      if (activeOnly) rows = rows.filter(r => r.status !== 'disabled')
      setSelectedForExport(prev => {
        const next = new Map(prev)
        rows.forEach(r => next.set(r.id, r))
        return next
      })
    } catch (e) {
      console.error('select-all failed:', e)
      alert(`Select all failed: ${e}`)
    } finally {
      setSelectingAll(false)
    }
  }

  const detailQ = useQuery({
    queryKey: ['identities', 'detail', selectedId],
    queryFn: async () => {
      if (!selectedId) return null
      const r = await fetch(apiUrl(`/identities/${selectedId}`))
      if (!r.ok) throw new Error(await r.text())
      return r.json() as Promise<IdentityDetail>
    },
    enabled: !!selectedId,
  })

  const summary = summaryQ.data || {}
  const rows: Identity[] = listQ.data?.results ?? []
  // Client-side hide-disabled filter (the API doesn't accept a status filter
  // yet — small enough page sizes that filtering here is fine).
  const visibleRows = activeOnly
    ? rows.filter(r => r.status !== 'disabled')
    : rows
  const allVisibleSelected = visibleRows.length > 0
    && visibleRows.every(r => selectedForExport.has(r.id))
  const totalMatching = listQ.data?.total ?? 0

  const tile = (label: string, value: number | undefined, color: string, Icon: any) => (
    <div className="bg-card border border-border rounded-lg p-3 flex items-center gap-3">
      <div className={cn('p-2 rounded-md', color)}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="text-xl font-semibold">{value ?? '—'}</div>
      </div>
    </div>
  )

  return (
    <div className="space-y-4">
      <PageHelp id="users" title="How to use Users">
        <p>Detected user/SP/guest identities aggregated across tools (MicroBurst, AzureHound today; netexec/impacket coming). Each row is keyed on (<code>provider</code>, <code>identifier</code>) — a UPN, AppId, or sAMAccountName depending on source. The <strong>Has Credential</strong> badge is a left-join against <code>credential_vault</code>; click any row to see linked creds and the recon findings that surfaced this identity.</p>
      </PageHelp>

      <div className="flex items-center gap-2">
        <h2 className="text-lg font-semibold flex items-center gap-2"><UsersIcon className="h-5 w-5" />Users / Identities</h2>
        {window.location.pathname !== '/users-popout' && (
          <PopoutButton path="/users-popout" windowName="rag-users-popout" className="ml-auto px-2 py-1 text-xs rounded border border-border hover:bg-muted flex items-center gap-1 text-muted-foreground hover:text-foreground" />
        )}
        <button
          onClick={() => { listQ.refetch(); summaryQ.refetch() }}
          className={cn('px-2 py-1 text-xs rounded border border-border hover:bg-muted flex items-center gap-1', window.location.pathname === '/users-popout' && 'ml-auto')}
        >
          <RefreshCw className="h-3 w-3" /> Refresh
        </button>
      </div>

      {/* Summary tiles */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {tile('Total', summary.total, 'bg-blue-500/15 text-blue-400', UsersIcon)}
        {tile('Admins', summary.admins, 'bg-red-500/15 text-red-400', Shield)}
        {tile('Guests', summary.guests, 'bg-amber-500/15 text-amber-400', UserPlus)}
        {tile('Dirsync', summary.dirsync, 'bg-purple-500/15 text-purple-400', RefreshCw)}
        {tile('Service Principals', summary.service_principals, 'bg-cyan-500/15 text-cyan-400', Cloud)}
        {tile('Providers', summary.providers, 'bg-zinc-500/15 text-zinc-400', Cloud)}
      </div>

      {/* Filter bar */}
      <div className="bg-card border border-border rounded-lg p-3 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1 bg-muted rounded-md px-2 py-1">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text" value={search} onChange={e => setSearchF(e.target.value)}
            placeholder="search UPN / display name"
            className="bg-transparent outline-none text-sm w-56"
          />
        </div>
        <select
          value={provider} onChange={e => setProviderF(e.target.value)}
          className="bg-muted rounded-md px-2 py-1 text-sm border border-border outline-none"
        >
          <option value="">all providers</option>
          <option value="azure">azure</option>
          <option value="on_prem_ad">on_prem_ad</option>
          <option value="aws">aws</option>
          <option value="gcp">gcp</option>
        </select>
        <select
          value={principalType} onChange={e => setPrincipalTypeF(e.target.value)}
          className="bg-muted rounded-md px-2 py-1 text-sm border border-border outline-none"
        >
          <option value="">all types</option>
          <option value="user">user</option>
          <option value="guest">guest</option>
          <option value="service_principal">service_principal</option>
          <option value="group">group</option>
          <option value="computer">computer</option>
        </select>
        <GroupCombobox
          groups={groups}
          value={groupFilter}
          onChange={setGroupFilterF}
        />
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={adminOnly} onChange={e => setAdminOnlyF(e.target.checked)} />
          Admins only
        </label>
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={guestOnly} onChange={e => setGuestOnlyF(e.target.checked)} />
          Guests only
        </label>
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={credOnly} onChange={e => setCredOnlyF(e.target.checked)} />
          Has credential
        </label>
        <label className="flex items-center gap-1 text-sm" title="Hide rows where status='disabled' so they don't pollute spray lists">
          <input type="checkbox" checked={activeOnly} onChange={e => setActiveOnlyF(e.target.checked)} />
          Hide disabled
        </label>
        <span className="ml-auto text-xs text-muted-foreground">
          {(() => {
            const total = listQ.data?.total ?? 0
            const start = page * pageSize + 1
            const end = page * pageSize + visibleRows.length
            return listQ.isFetching
              ? 'loading…'
              : total === 0
                ? '0 results'
                : `${start.toLocaleString()}–${end.toLocaleString()} of ${total.toLocaleString()}`
          })()}
        </span>
      </div>

      {/* Toolbar: selection actions on the left, export-all-filtered on the right */}
      <div className="flex flex-wrap items-center gap-2">
        {selectedForExport.size > 0 && (
          <div className="bg-primary/10 border border-primary/30 rounded-lg p-2 flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium">{selectedForExport.size.toLocaleString()} selected</span>
            <button
              onClick={() => exportTxt(Array.from(selectedForExport.values()))}
              className="px-3 py-1 text-xs rounded border border-border bg-card hover:bg-muted flex items-center gap-1"
              title="One identifier per line — for spray / kerbrute / MailSniper"
            >
              <Download className="h-3 w-3" /> Export TXT
            </button>
            <button
              onClick={() => exportCsv(Array.from(selectedForExport.values()))}
              className="px-3 py-1 text-xs rounded border border-border bg-card hover:bg-muted flex items-center gap-1"
              title="UPN, name, type, flags — for spreadsheet review"
            >
              <Download className="h-3 w-3" /> Export CSV
            </button>
            <button
              onClick={clearSelection}
              className="px-2 py-1 text-xs rounded text-muted-foreground hover:text-foreground"
            >
              Clear
            </button>
          </div>
        )}
        <button
          onClick={selectAllMatching}
          disabled={selectingAll || totalMatching === 0}
          className="px-3 py-1 text-xs rounded border border-border bg-card hover:bg-muted disabled:opacity-50 flex items-center gap-1"
          title={`Add every row matching the current filters to the selection (~${totalMatching.toLocaleString()} rows)`}
        >
          {selectingAll ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckSquare className="h-3 w-3" />}
          Select all matching ({totalMatching.toLocaleString()})
        </button>
        <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
          <span>Export all matching filter:</span>
          <button
            onClick={() => exportAllFiltered('txt')}
            disabled={exportingAll}
            className="px-3 py-1 rounded border border-border bg-card hover:bg-muted disabled:opacity-50 flex items-center gap-1"
            title={`Fetches every row matching the current filters and downloads as a spray list (~${(listQ.data?.total ?? 0).toLocaleString()} rows)`}
          >
            {exportingAll ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
            All as TXT
          </button>
          <button
            onClick={() => exportAllFiltered('csv')}
            disabled={exportingAll}
            className="px-3 py-1 rounded border border-border bg-card hover:bg-muted disabled:opacity-50 flex items-center gap-1"
          >
            {exportingAll ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
            All as CSV
          </button>
        </div>
      </div>

      {/* Main table + side detail */}
      <div className="flex gap-4">
        <div className="flex-1 min-w-0 bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left w-8">
                  <button
                    onClick={() => allVisibleSelected ? clearSelection() : selectAllVisible(visibleRows)}
                    className="text-muted-foreground hover:text-foreground"
                    title={allVisibleSelected ? 'Clear selection' : `Select all ${visibleRows.length} visible`}
                  >
                    {allVisibleSelected
                      ? <CheckSquare className="h-4 w-4" />
                      : <Square className="h-4 w-4" />}
                  </button>
                </th>
                <th className="px-3 py-2 text-left">Identifier</th>
                <th className="px-3 py-2 text-left">Display Name</th>
                <th className="px-3 py-2 text-left">Type</th>
                <th className="px-3 py-2 text-left">Flags</th>
                <th className="px-3 py-2 text-left">Sources</th>
                <th className="px-3 py-2 text-left">Provider</th>
                <th className="px-3 py-2 text-left">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.length === 0 && !listQ.isFetching && (
                <tr><td colSpan={8} className="px-3 py-6 text-center text-muted-foreground">
                  No identities yet. Import a MicroBurst zip or AzureHound JSON to populate.
                </td></tr>
              )}
              {visibleRows.map(r => (
                <tr
                  key={r.id}
                  onClick={() => setSelectedId(r.id)}
                  className={cn(
                    'border-t border-border cursor-pointer hover:bg-muted/30',
                    selectedId === r.id && 'bg-muted/50',
                    selectedForExport.has(r.id) && 'bg-primary/5',
                  )}
                >
                  <td className="px-3 py-2 w-8" onClick={e => { e.stopPropagation(); toggleSelect(r) }}>
                    {selectedForExport.has(r.id)
                      ? <CheckSquare className="h-4 w-4 text-primary" />
                      : <Square className="h-4 w-4 text-muted-foreground hover:text-foreground" />}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{r.identifier}</td>
                  <td className="px-3 py-2">{r.display_name || <span className="text-muted-foreground">—</span>}</td>
                  <td className="px-3 py-2 text-xs">{r.principal_type || '—'}</td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {r.is_admin && <span className="px-1.5 py-0.5 text-[10px] rounded border bg-red-500/15 text-red-400 border-red-500/30">admin</span>}
                      {r.is_guest && <span className="px-1.5 py-0.5 text-[10px] rounded border bg-amber-500/15 text-amber-400 border-amber-500/30">guest</span>}
                      {r.is_dirsync && <span className="px-1.5 py-0.5 text-[10px] rounded border bg-purple-500/15 text-purple-400 border-purple-500/30">dirsync</span>}
                      {r.has_credential && <span className="px-1.5 py-0.5 text-[10px] rounded border bg-emerald-500/15 text-emerald-400 border-emerald-500/30 flex items-center gap-0.5"><Key className="h-2.5 w-2.5" />cred</span>}
                      {r.status === 'disabled' && <span className="px-1.5 py-0.5 text-[10px] rounded border bg-zinc-500/15 text-zinc-400 border-zinc-500/30">disabled</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs">{r.sources.join(', ')}</td>
                  <td className="px-3 py-2 text-xs">{r.provider}</td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {r.last_seen ? new Date(r.last_seen).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {/* Pagination footer */}
          {(() => {
            const total = listQ.data?.total ?? 0
            const totalPages = Math.max(1, Math.ceil(total / pageSize))
            const canPrev = page > 0
            const canNext = page < totalPages - 1
            return (
              <div className="flex items-center justify-between gap-2 border-t border-border px-3 py-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Rows per page</span>
                  <select
                    value={pageSize}
                    onChange={e => { setPageSize(Number(e.target.value)); setPage(0) }}
                    className="bg-muted border border-border rounded px-1.5 py-0.5 outline-none"
                  >
                    {[50, 100, 200, 500, 1000, 2000].map(n => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </select>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setPage(p => Math.max(0, p - 1))}
                    disabled={!canPrev}
                    className="p-1 rounded border border-border hover:bg-muted disabled:opacity-30"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                  </button>
                  <span className="text-muted-foreground">
                    Page {page + 1} of {totalPages.toLocaleString()}
                  </span>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                    disabled={!canNext}
                    className="p-1 rounded border border-border hover:bg-muted disabled:opacity-30"
                  >
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            )
          })()}
        </div>

        {selectedId && (
          <div className="w-96 shrink-0 bg-card border border-border rounded-lg p-4 self-start sticky top-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">Identity detail</h3>
              <div className="flex items-center gap-1">
                {window.location.pathname === '/users' && (
                  <PopoutButton
                    path={`/users-popout/${selectedId}`}
                    windowName={`rag-user-${selectedId}`}
                    label=""
                    title="Open this identity in an independent browser window"
                    className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
                  />
                )}
                <button onClick={() => setSelectedId(null)} className="text-muted-foreground hover:text-foreground p-1">
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
            {detailQ.isLoading && <div className="text-xs text-muted-foreground">loading…</div>}
            {detailQ.data && (
              <div className="space-y-3 text-xs">
                <div>
                  <div className="text-muted-foreground">Identifier</div>
                  <div className="font-mono break-all">{detailQ.data.identifier}</div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div><div className="text-muted-foreground">Type</div><div>{detailQ.data.principal_type || '—'}</div></div>
                  <div><div className="text-muted-foreground">Status</div><div>{detailQ.data.status}</div></div>
                  <div><div className="text-muted-foreground">MFA</div><div>{detailQ.data.mfa_state || '—'}</div></div>
                  <div><div className="text-muted-foreground">Tenant</div><div className="font-mono break-all">{detailQ.data.tenant_id || '—'}</div></div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1">Sources</div>
                  <div className="flex flex-wrap gap-1">
                    {detailQ.data.sources.map(s => (
                      <span key={s} className="px-1.5 py-0.5 rounded border bg-muted/50 border-border">{s}</span>
                    ))}
                  </div>
                </div>

                {(() => {
                  const memberGroups = (detailQ.data.tags || [])
                    .filter(t => t.startsWith('member_of:'))
                    .map(t => t.slice('member_of:'.length))
                    .sort((a, b) => a.localeCompare(b))
                  if (memberGroups.length === 0) return null
                  const copyAll = () => {
                    navigator.clipboard?.writeText(memberGroups.join('\n'))
                  }
                  return (
                    <div>
                      <div className="text-muted-foreground mb-1 flex items-center gap-1">
                        <UsersIcon className="h-3 w-3" /> Groups ({memberGroups.length})
                        <button
                          onClick={copyAll}
                          className="ml-auto text-[10px] text-muted-foreground hover:text-foreground underline"
                          title="Copy all group names to clipboard"
                        >
                          copy
                        </button>
                      </div>
                      <div className="flex flex-wrap gap-1 max-h-48 overflow-y-auto">
                        {memberGroups.map(g => (
                          <button
                            key={g}
                            onClick={() => { setGroupFilterF(g); setSelectedId(null) }}
                            className="px-1.5 py-0.5 rounded border bg-muted/40 border-border hover:bg-primary/10 hover:border-primary/40 text-left"
                            title={`Filter the table to members of "${g}"`}
                          >
                            {g}
                          </button>
                        ))}
                      </div>
                    </div>
                  )
                })()}

                <div>
                  <div className="text-muted-foreground mb-1 flex items-center gap-1">
                    <Key className="h-3 w-3" /> Linked credentials ({detailQ.data.credentials.length})
                  </div>
                  {detailQ.data.credentials.length === 0 ? (
                    <div className="text-muted-foreground italic">none yet</div>
                  ) : (
                    <ul className="space-y-1">
                      {detailQ.data.credentials.map(c => (
                        <li key={c.id} className="border border-border rounded px-2 py-1">
                          <span className="font-mono">{c.username}</span>
                          <span className="ml-1 text-muted-foreground">({c.credential_type}, {c.status})</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div>
                  <div className="text-muted-foreground mb-1">Recon findings ({detailQ.data.recon_findings.length})</div>
                  <ul className="space-y-1 max-h-48 overflow-y-auto">
                    {detailQ.data.recon_findings.map(f => (
                      <li key={f.id} className="border border-border rounded px-2 py-1">
                        <span className={cn('px-1 py-0.5 mr-1 rounded text-[10px] border', SEVERITY_COLOR[f.severity] || SEVERITY_COLOR.info)}>{f.severity}</span>
                        <span className="font-mono">{f.finding_type}</span>
                        <span className="ml-1 text-muted-foreground">via {f.source}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <details className="text-[11px]">
                  <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Raw merged source data</summary>
                  <pre className="mt-1 bg-muted/40 rounded p-2 overflow-x-auto max-h-64 whitespace-pre-wrap">
                    {JSON.stringify(detailQ.data.raw, null, 2)}
                  </pre>
                </details>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}


/**
 * Searchable combobox for the group filter. Replaces the native <select>
 * because that became unusable once 14k groups arrived — browser type-ahead
 * on a long <option> list only matches the first character and is
 * case-sensitive in most engines. This widget filters case-insensitively
 * by substring as the operator types.
 */
function GroupCombobox({
  groups, value, onChange,
}: {
  groups: Array<{ name: string; members: number }>
  value: string
  onChange: (v: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const filtered = (() => {
    const q = query.trim().toLowerCase()
    const list = q
      ? groups.filter(g => g.name.toLowerCase().includes(q))
      : groups
    // Cap render to avoid laying out 14k DOM nodes; the user narrows via search.
    return list.slice(0, 200)
  })()

  const close = () => { setOpen(false); setQuery('') }
  const select = (name: string) => { onChange(name); close() }

  return (
    <div className="relative">
      <button
        type="button"
        disabled={groups.length === 0}
        onClick={() => setOpen(o => !o)}
        className="bg-muted rounded-md px-2 py-1 text-sm border border-border outline-none max-w-[18rem] truncate text-left disabled:opacity-50 inline-flex items-center gap-1"
        title="Filter to members of a specific group (built from member_of:* tags) — type to search case-insensitively"
      >
        {groups.length === 0 ? 'no groups ingested' : (value || 'all groups')}
        {value && (
          <X
            className="h-3 w-3 ml-auto text-muted-foreground hover:text-foreground"
            onClick={e => { e.stopPropagation(); onChange('') }}
          />
        )}
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={close} />
          <div className="absolute left-0 top-full mt-1 w-[24rem] max-w-[80vw] bg-card border border-border rounded-md shadow-xl z-40 max-h-[26rem] overflow-hidden flex flex-col">
            <div className="p-2 border-b border-border">
              <input
                autoFocus
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder={`Search ${groups.length.toLocaleString()} groups…`}
                className="w-full bg-muted rounded px-2 py-1 text-sm outline-none border border-transparent focus:border-border"
              />
            </div>
            <div className="overflow-y-auto">
              {!query && value !== '' && (
                <button
                  onClick={() => select('')}
                  className="w-full text-left px-3 py-1.5 text-xs hover:bg-muted/60 border-b border-border"
                >clear · show all groups</button>
              )}
              {filtered.length === 0 ? (
                <div className="px-3 py-3 text-xs text-muted-foreground italic">no matches</div>
              ) : (
                filtered.map(g => (
                  <button
                    key={g.name}
                    onClick={() => select(g.name)}
                    className={cn(
                      'w-full text-left px-3 py-1.5 text-xs hover:bg-muted/60 flex items-center gap-2',
                      g.name === value && 'bg-primary/10',
                    )}
                  >
                    <span className="flex-1 truncate" title={g.name}>{g.name}</span>
                    <span className="text-muted-foreground tabular-nums">{g.members.toLocaleString()}</span>
                  </button>
                ))
              )}
              {query && groups.filter(g => g.name.toLowerCase().includes(query.trim().toLowerCase())).length > 200 && (
                <div className="px-3 py-1.5 text-[10px] text-muted-foreground italic border-t border-border">
                  showing first 200 — keep typing to narrow
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
