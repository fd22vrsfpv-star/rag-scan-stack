import { useState } from 'react'
import { ShieldCheck, AlertTriangle, RefreshCw, Copy, Check, Plus } from 'lucide-react'
import { useToolCatalog, useToolCoverage, useAdoptTool } from '@/api/servicePrompts'
import { cn } from '@/lib/utils'

/** Past this, the snapshot is old enough that a recently installed tool is
 *  likely missing from it. Not a failure — a prompt to re-run the refresh. */
const STALE_AFTER_DAYS = 7

function humanAge(seconds: number | null): string {
  if (seconds == null) return 'unknown'
  const d = Math.floor(seconds / 86400)
  if (d >= 1) return `${d} day${d === 1 ? '' : 's'} ago`
  const h = Math.floor(seconds / 3600)
  if (h >= 1) return `${h} hour${h === 1 ? '' : 's'} ago`
  const m = Math.floor(seconds / 60)
  return m >= 1 ? `${m} min ago` : 'just now'
}

const LABELS: Record<string, string> = {
  nmap_scripts: 'nmap scripts',
  msf_modules: 'metasploit modules',
  nuclei_templates: 'nuclei templates',
  nuclei_tags: 'nuclei tags',
  binaries: 'binaries',
  tool_flags: 'tools with known flags',
}

function CopyCmd({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="flex items-start gap-2">
      <code className="flex-1 bg-muted rounded px-2 py-1 text-[11px] font-mono break-all">
        {cmd}
      </code>
      <button
        onClick={() => {
          navigator.clipboard?.writeText(cmd)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        }}
        className="p-1 text-muted-foreground hover:text-foreground shrink-0"
        title="Copy"
      >
        {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
    </div>
  )
}

/**
 * What the recommendation validator knows, and whether it can still be trusted.
 *
 * The validator rejects scan recommendations naming tools that do not exist —
 * a live run produced `smb Vuln-MS17-010` and `smb-enum-links`, neither of which
 * is a real nmap script. It checks against a SNAPSHOT of the catalogs, taken by
 * an explicit refresh so that validation never depends on live containers. The
 * cost of that choice is silent staleness, which is what the age below is for.
 */

/**
 * Cross-check: what the KB recommends vs what is installed.
 *
 * Two failures in opposite directions, and the validator catches NEITHER — it
 * only gates nmap/metasploit/nuclei, so a recommendation for `snmp-check` (which
 * the shipped YAML contains and nothing can run) passes straight through and
 * fails at dispatch.
 */
function CoverageSection() {
  const { data, isLoading } = useToolCoverage()
  const adopt = useAdoptTool()
  const [svc, setSvc] = useState<Record<string, string>>({})
  const [done, setDone] = useState<Record<string, string>>({})

  if (isLoading) return <p className="text-[11px] text-muted-foreground">Checking coverage…</p>
  if (!data) return null
  if (!data.ok) {
    return <p className="text-[11px] text-yellow-400">{data.reason}</p>
  }

  return (
    <div className="space-y-2 border-t border-border pt-2">
      <h4 className="text-xs font-semibold">KB vs installed tools</h4>

      {data.unrunnable.length > 0 && (
        <div className="space-y-1">
          <p className="text-[11px] text-yellow-400 flex items-start gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
            <span>
              <strong>{data.unrunnable.length}</strong> tool(s) the KB recommends are
              installed nowhere. These are not blocked by the validator — it only gates{' '}
              nmap/metasploit/nuclei — so they reach dispatch and fail there.
            </span>
          </p>
          <div className="max-h-32 overflow-y-auto text-[10px] font-mono space-y-0.5 pl-5">
            {data.unrunnable.slice(0, 20).map(u => (
              <div key={u.tool} className="text-muted-foreground">
                <span className="text-foreground">{u.tool}</span>
                {' — '}{u.referenced_by.join(', ')}
                {u.references > u.referenced_by.length && ` +${u.references - u.referenced_by.length}`}
              </div>
            ))}
          </div>
          <p className="text-[10px] text-muted-foreground pl-5">
            Fix by installing them on a node, declaring them in{' '}
            <code className="font-mono">tool_catalogs.local.json</code> if they live where the
            probe cannot see, or removing them from the service in KB Overrides.
          </p>
        </div>
      )}

      {data.uncatalogued.length > 0 && (
        <div className="space-y-1">
          <p className="text-[11px] text-muted-foreground">
            <strong>{data.uncatalogued_total ?? data.uncatalogued.length}</strong> tool(s) are
            provisioned on a node but no KB entry mentions them, so they can never be
            recommended. Adopt one into a service to make it usable:
          </p>
          <div className="max-h-40 overflow-y-auto space-y-1 pl-1">
            {data.uncatalogued.map(t => (
              <div key={t} className="flex items-center gap-1.5">
                <code className="text-[10px] font-mono w-28 shrink-0">{t}</code>
                {done[t] ? (
                  <span className="text-[10px] text-green-400">added to {done[t]}</span>
                ) : (
                  <>
                    <input
                      value={svc[t] ?? ''}
                      onChange={e => setSvc(v => ({ ...v, [t]: e.target.value }))}
                      placeholder="service (e.g. http)"
                      className="flex-1 min-w-0 bg-muted rounded px-1.5 py-0.5 text-[10px] border border-border"
                    />
                    <button
                      disabled={!svc[t]?.trim() || adopt.isPending}
                      onClick={async () => {
                        try {
                          await adopt.mutateAsync({ tool: t, service: svc[t].trim() })
                          setDone(d => ({ ...d, [t]: svc[t].trim() }))
                        } catch (e) {
                          alert(e instanceof Error ? e.message : 'Adopt failed')
                        }
                      }}
                      className="flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] border border-border rounded disabled:opacity-40"
                    >
                      <Plus className="h-3 w-3" /> Add
                    </button>
                  </>
                )}
              </div>
            ))}
          </div>
          <p className="text-[10px] text-muted-foreground">
            Adopting seeds the override from the service's existing YAML entry first, so it
            adds to those recommendations rather than replacing them. A tool that is not
            actually installed is refused.
          </p>
        </div>
      )}

      {data.unrunnable.length === 0 && data.uncatalogued.length === 0 && (
        <p className="text-[11px] text-muted-foreground">
          Everything the KB recommends is installed, and every provisioned tool is referenced.
        </p>
      )}
    </div>
  )
}

export function ValidatorPanel() {
  const { data, isLoading, error, refetch, isFetching } = useToolCatalog()

  if (isLoading) {
    return <div className="text-xs text-muted-foreground">Loading validator status…</div>
  }
  if (error || !data) {
    return (
      <div className="text-xs text-red-400">
        Could not read validator status: {error instanceof Error ? error.message : 'unknown'}
      </div>
    )
  }

  const missing = !data.exists
  const stale = data.age_seconds != null && data.age_seconds > STALE_AFTER_DAYS * 86400
  const total = Object.values(data.counts).reduce((a, b) => a + b, 0)

  return (
    <div className="bg-card border border-border rounded-lg p-3 space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h3 className="text-sm font-semibold flex items-center gap-1.5">
          <ShieldCheck className="h-4 w-4" /> Recommendation validator
        </h3>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1 px-2 py-1 text-[10px] border border-border rounded disabled:opacity-50"
        >
          <RefreshCw className={cn('h-3 w-3', isFetching && 'animate-spin')} /> Reload
        </button>
      </div>

      <p className="text-[11px] text-muted-foreground">
        Rejects scan recommendations that name tools which do not exist, before they
        are dispatched. Checked against a snapshot of what the scanners and nodes can
        actually run — so it needs re-taking whenever you install something new.
      </p>

      {missing ? (
        <div className="text-xs text-yellow-400 flex items-start gap-1.5">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>
            No catalog found at <code className="font-mono">{data.path}</code> — validation is
            <strong> disabled</strong>, and every recommendation passes unchecked. Run the
            refresh below.
          </span>
        </div>
      ) : (
        <>
          <div className="flex items-baseline gap-2 flex-wrap">
            <span className={cn('text-xs', stale ? 'text-yellow-400' : 'text-muted-foreground')}>
              Last refreshed <strong>{humanAge(data.age_seconds)}</strong>
            </span>
            <span className="text-[10px] text-muted-foreground">
              ({total.toLocaleString()} entries)
            </span>
            {stale && (
              <span className="text-[10px] text-yellow-400 flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                anything installed since then is invisible to it
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
            {Object.entries(data.counts)
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => (
                <div key={k} className="bg-muted/40 rounded px-2 py-1">
                  <div className="text-sm font-medium">{v.toLocaleString()}</div>
                  <div className="text-[10px] text-muted-foreground">{LABELS[k] ?? k}</div>
                </div>
              ))}
          </div>

          {/* The scope limit matters as much as the contents: a tool outside this
              list is never rejected, however implausible the invocation. */}
          <p className="text-[10px] text-muted-foreground">
            Gated scanners: {data.validated_scanners.join(', ')}. Anything else
            (hydra, snmpwalk, gobuster…) passes unvalidated — there is no closed
            vocabulary to check it against.
          </p>

          {data.supplement?.exists && (
            <p className="text-[10px] text-muted-foreground">
              Operator supplement:{' '}
              {Object.entries(data.supplement.counts)
                .filter(([k]) => !k.startsWith('_'))
                .map(([k, v]) => `${v.toLocaleString()} ${LABELS[k] ?? k}`)
                .join(', ') || 'empty'}
              {data.supplement.notes?.length ? ` — ${data.supplement.notes[0]}` : ''}
            </p>
          )}

          {data.nodes && data.nodes.length > 0 && (
            <div className="text-[10px] text-muted-foreground">
              Nodes contributing tools:{' '}
              {data.nodes.map(n => (
                <span key={n.name} className="mr-2">
                  {n.name} ({n.tools} tools, {n.status})
                </span>
              ))}
            </div>
          )}
        </>
      )}

      <CoverageSection />

      <details className="text-[11px]">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
          How to update it
        </summary>
        <div className="mt-2 space-y-2 pl-1">
          <div>
            <p className="text-muted-foreground mb-1">
              1. Re-read the local scanner containers:
            </p>
            <CopyCmd cmd="./scripts/refresh-tool-catalogs.sh" />
          </div>
          <div>
            <p className="text-muted-foreground mb-1">
              2. Optional — inventory a remote node, so tools only it has are not
              rejected. <code className="font-mono">--common</code> also reports which
              well-known Kali tools that node is missing:
            </p>
            <CopyCmd cmd="./scripts/inventory-node.sh &lt;node_id&gt; --common" />
          </div>
          <div>
            <p className="text-muted-foreground mb-1">3. Reload the recommender:</p>
            <CopyCmd cmd="docker compose restart scan-recommender" />
          </div>
          <p className="text-muted-foreground pt-1">
            To declare a tool the probe cannot see — on an offline node, or behind a
            pipe — add it to{' '}
            <code className="font-mono">knowledge/tool_catalogs.local.json</code>. That
            file is merged as authoritative and never overwritten by the refresh.
          </p>
        </div>
      </details>
    </div>
  )
}
