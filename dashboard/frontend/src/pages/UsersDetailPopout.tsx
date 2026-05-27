import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Key, Users as UsersIcon, ExternalLink } from 'lucide-react'
import { apiUrl } from '@/api/client'
import { cn } from '@/lib/utils'

interface IdentityDetail {
  id: string
  provider: string
  identifier: string
  display_name: string | null
  principal_type: string | null
  status: string
  mfa_state: string | null
  tenant_id: string | null
  domain: string | null
  is_admin: boolean
  is_guest: boolean
  is_dirsync: boolean
  tags: string[]
  sources: string[]
  raw: any
  credentials: Array<{ id: string; username: string; credential_type: string; status: string; source: string }>
  recon_findings: Array<{ id: string; source: string; finding_type: string; severity: string }>
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info:     'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
}

/**
 * Standalone popout for a single identity (Users → row → "Pop out" button).
 * Mounted at /users-popout/:id outside AppShell so the sidebar/top-bar don't
 * render — the operator gets the full detail in a window they can pin to a
 * second monitor.
 */
export default function UsersDetailPopout() {
  const { id } = useParams<{ id: string }>()
  const detailQ = useQuery({
    queryKey: ['identities', 'detail', id],
    queryFn: async () => {
      const r = await fetch(apiUrl(`/identities/${id}`))
      if (!r.ok) throw new Error(await r.text())
      return r.json() as Promise<IdentityDetail>
    },
    enabled: !!id,
  })

  const item = detailQ.data
  const memberGroups = (item?.tags || [])
    .filter(t => t.startsWith('member_of:'))
    .map(t => t.slice('member_of:'.length))
    .sort((a, b) => a.localeCompare(b))

  return (
    <div className="min-h-screen bg-background text-foreground p-6 max-w-4xl mx-auto">
      {detailQ.isLoading && <div className="text-sm text-muted-foreground">loading…</div>}
      {detailQ.error && <div className="text-sm text-red-400">Error: {String((detailQ.error as Error).message)}</div>}
      {item && (
        <div className="space-y-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h1 className="text-xl font-semibold flex items-center gap-2">
                <UsersIcon className="h-5 w-5" />
                {item.display_name || item.identifier}
              </h1>
              <div className="font-mono text-xs text-muted-foreground break-all mt-1">{item.identifier}</div>
            </div>
            <div className="flex items-center gap-1">
              {item.is_admin && <span className="px-1.5 py-0.5 text-[11px] rounded border bg-red-500/15 text-red-400 border-red-500/30">admin</span>}
              {item.is_guest && <span className="px-1.5 py-0.5 text-[11px] rounded border bg-amber-500/15 text-amber-400 border-amber-500/30">guest</span>}
              {item.is_dirsync && <span className="px-1.5 py-0.5 text-[11px] rounded border bg-purple-500/15 text-purple-400 border-purple-500/30">dirsync</span>}
              {item.status === 'disabled' && <span className="px-1.5 py-0.5 text-[11px] rounded border bg-zinc-500/15 text-zinc-400 border-zinc-500/30">disabled</span>}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-card border border-border rounded-lg p-3 text-xs">
            <div><div className="text-muted-foreground">Type</div><div>{item.principal_type || '—'}</div></div>
            <div><div className="text-muted-foreground">Status</div><div>{item.status}</div></div>
            <div><div className="text-muted-foreground">MFA</div><div>{item.mfa_state || '—'}</div></div>
            <div><div className="text-muted-foreground">Provider</div><div>{item.provider}</div></div>
            <div className="col-span-2"><div className="text-muted-foreground">Tenant</div><div className="font-mono break-all">{item.tenant_id || '—'}</div></div>
            <div className="col-span-2"><div className="text-muted-foreground">Domain</div><div className="font-mono break-all">{item.domain || '—'}</div></div>
          </div>

          <div className="bg-card border border-border rounded-lg p-3">
            <div className="text-xs text-muted-foreground mb-1">Sources</div>
            <div className="flex flex-wrap gap-1">
              {item.sources.map(s => (
                <span key={s} className="px-2 py-0.5 text-xs rounded border bg-muted/50 border-border">{s}</span>
              ))}
            </div>
          </div>

          {memberGroups.length > 0 && (
            <div className="bg-card border border-border rounded-lg p-3">
              <div className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                <UsersIcon className="h-3 w-3" /> Groups ({memberGroups.length})
                <button
                  onClick={() => navigator.clipboard?.writeText(memberGroups.join('\n'))}
                  className="ml-auto text-[10px] text-muted-foreground hover:text-foreground underline"
                  title="Copy all group names to clipboard"
                >copy all</button>
              </div>
              <div className="flex flex-wrap gap-1 max-h-72 overflow-y-auto">
                {memberGroups.map(g => (
                  <a
                    key={g}
                    href={`/users?member_of=${encodeURIComponent(g)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="px-1.5 py-0.5 text-xs rounded border bg-muted/40 border-border hover:bg-primary/10 hover:border-primary/40 inline-flex items-center gap-1"
                    title={`Open Users in main window filtered to members of "${g}"`}
                  >
                    {g}
                    <ExternalLink className="h-2.5 w-2.5 opacity-60" />
                  </a>
                ))}
              </div>
            </div>
          )}

          <div className="bg-card border border-border rounded-lg p-3">
            <div className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
              <Key className="h-3 w-3" /> Linked credentials ({item.credentials.length})
            </div>
            {item.credentials.length === 0 ? (
              <div className="text-xs text-muted-foreground italic">none yet</div>
            ) : (
              <ul className="space-y-1 text-xs">
                {item.credentials.map(c => (
                  <li key={c.id} className="border border-border rounded px-2 py-1">
                    <span className="font-mono">{c.username}</span>
                    <span className="ml-2 text-muted-foreground">({c.credential_type}, {c.status})</span>
                    <span className="ml-2 text-muted-foreground">via {c.source}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="bg-card border border-border rounded-lg p-3">
            <div className="text-xs text-muted-foreground mb-2">Recon findings ({item.recon_findings.length})</div>
            {item.recon_findings.length === 0 ? (
              <div className="text-xs text-muted-foreground italic">none</div>
            ) : (
              <ul className="space-y-1 text-xs max-h-72 overflow-y-auto">
                {item.recon_findings.map(f => (
                  <li key={f.id} className="border border-border rounded px-2 py-1">
                    <span className={cn('px-1 py-0.5 mr-1 rounded text-[10px] border', SEVERITY_COLOR[f.severity] || SEVERITY_COLOR.info)}>{f.severity}</span>
                    <span className="font-mono">{f.finding_type}</span>
                    <span className="ml-1 text-muted-foreground">via {f.source}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <details className="bg-card border border-border rounded-lg p-3 text-xs">
            <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Raw merged source data</summary>
            <pre className="mt-2 bg-muted/40 rounded p-2 overflow-x-auto max-h-96 whitespace-pre-wrap break-words">
              {JSON.stringify(item.raw, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  )
}
