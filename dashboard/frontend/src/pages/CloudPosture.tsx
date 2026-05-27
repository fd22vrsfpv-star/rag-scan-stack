import { useState, useEffect } from 'react'
import {
  useCloudRecommendations,
  useRefreshCloudRecommendations,
  useUpdateCloudRecommendation,
  useCloudPosture,
  useCloudTriageLatest,
  useRunCloudTriage,
} from '@/api/cloudSuggestor'
import type { CloudRecommendation } from '@/api/cloudSuggestor'
import { cn } from '@/lib/utils'
import { Cloud, RefreshCw, CheckCircle, XCircle, Copy, Filter, Brain, Sparkles, Zap, KeyRound, Loader2, X, Radar } from 'lucide-react'
import { apiFetch } from '@/api/client'

type TakeoverHit = {
  target: string
  detector_id: string
  vulnerable: boolean
  http_status: number | null
  claim_hint?: string
}
type TakeoverRunResult = {
  ok?: boolean
  debounced?: boolean
  next_eligible_in_s?: number
  candidates_examined?: number
  confirmed?: number
  inserted?: number
  updated?: number
  proxy_used?: boolean
  by_detector?: Record<string, number>
  preview?: TakeoverHit[]
  dry_run?: boolean
  engagement_ids?: string[]
}

const PRIORITY_BADGE: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-400 text-black',
  low: 'bg-blue-600 text-white',
}

const STATUS_OPTIONS = ['open', 'accepted', 'dismissed'] as const
const PRIORITY_OPTIONS = ['critical', 'high', 'medium', 'low'] as const

export default function CloudPosture() {
  const [statusFilter, setStatusFilter] = useState<string>('open')
  const [priorityFilter, setPriorityFilter] = useState<string>('')
  const [providerFilter, setProviderFilter] = useState<string>('')
  const [sortMode, setSortMode] = useState<'ai' | 'static'>('ai')
  const [triageModel, setTriageModel] = useState<string>('')
  const [takeoverRunning, setTakeoverRunning] = useState<false | 'preview' | 'commit'>(false)
  const [takeoverResult, setTakeoverResult] = useState<TakeoverRunResult | null>(null)
  const [takeoverError, setTakeoverError] = useState<string | null>(null)

  const runTakeoverHunter = async (mode: 'preview' | 'commit') => {
    setTakeoverRunning(mode); setTakeoverError(null)
    try {
      const r = await apiFetch<TakeoverRunResult>('/agents/takeover-hunter/run', {
        method: 'POST',
        body: JSON.stringify({
          dry_run: mode === 'preview',
          force: true,
        }),
      })
      setTakeoverResult(r)
    } catch (e) {
      setTakeoverError(String(e))
    } finally {
      setTakeoverRunning(false)
    }
  }

  const cloudRecs = useCloudRecommendations({
    status: statusFilter || undefined,
    priority: priorityFilter || undefined,
    provider: providerFilter || undefined,
  })
  const posture = useCloudPosture()
  const refreshCloud = useRefreshCloudRecommendations()
  const updateCloudRec = useUpdateCloudRecommendation()
  const triageLatest = useCloudTriageLatest({ provider: providerFilter || undefined })
  const runTriage = useRunCloudTriage()

  const rawRecs = cloudRecs.data?.recommendations ?? []
  // The API already sorts triage_order ASC NULLS LAST then priority. When the
  // operator flips to static mode, sort by priority alone client-side so the
  // AI ranking is hidden but reasoning text is still available on hover.
  const recs = sortMode === 'static'
    ? [...rawRecs].sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3 } as const
        return (order[a.priority] ?? 9) - (order[b.priority] ?? 9)
      })
    : rawRecs
  const postureData = posture.data
  const hasCloudData = postureData && (postureData.total_cloud_findings > 0 || postureData.active_cloud_creds > 0)
  const triage = triageLatest.data
  const hasTriage = !!(triage && triage.present && (triage.top_actions?.length || triage.summary))

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cloud className="h-5 w-5 text-cyan-400" />
          <h1 className="text-lg font-bold">Cloud Posture</h1>
          {recs.length > 0 && (
            <span className="px-2 py-0.5 text-xs bg-primary/10 text-primary rounded-full border border-primary/30">
              {recs.length} result{recs.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={triageModel}
            onChange={e => setTriageModel(e.target.value)}
            placeholder="model (optional)"
            list="triage-model-suggestions"
            className="px-2 py-1.5 text-xs bg-muted border border-border rounded-md w-44 outline-none focus:border-purple-500/50 font-mono"
            title="Override the triage LLM for this run (leave blank for default). Faster models avoid timeouts; e.g. gemma4:latest, deepseek-r1:14b"
          />
          <datalist id="triage-model-suggestions">
            <option value="gemma4:latest" />
            <option value="gemma4:31b" />
            <option value="deepseek-r1:14b" />
            <option value="deepseek-r1:32b" />
            <option value="qwen3-vl:30b" />
            <option value="deepseek-v4-flash:cloud" />
          </datalist>
          <button
            onClick={() => runTriage.mutate({
              provider: providerFilter || undefined,
              force: true,
              model: triageModel.trim() || undefined,
            })}
            disabled={runTriage.isPending || recs.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-purple-500/10 border border-purple-500/30 text-purple-400 rounded-md hover:bg-purple-500/20 disabled:opacity-50"
            title="Run the AI triage agent — re-rank open recs by attack-chain order + state. Type a model name in the input to swap LLMs for this run."
          >
            <Brain className={cn('h-3 w-3', runTriage.isPending && 'animate-pulse')} />
            {runTriage.isPending ? 'Triaging…' : 'Re-triage (AI)'}
          </button>
          <button
            onClick={() => runTakeoverHunter('preview')}
            disabled={!!takeoverRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 rounded-md hover:bg-cyan-500/20 disabled:opacity-50"
            title="Probe DNS recon findings for dangling cloud-resource takeovers (S3, Azure WebApps, GitHub Pages, Heroku, etc.). Active engagements only; routes through the configured proxy. Preview = no DB writes."
          >
            <Radar className={cn('h-3 w-3', takeoverRunning === 'preview' && 'animate-pulse')} />
            {takeoverRunning === 'preview' ? 'Probing…' : 'Preview Takeovers'}
          </button>
          <button
            onClick={() => {
              if (window.confirm('Run takeover hunter and write subdomain_takeover findings to the DB? Probes external resources via the configured proxy.')) {
                runTakeoverHunter('commit')
              }
            }}
            disabled={!!takeoverRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-cyan-600/15 border border-cyan-500/40 text-cyan-300 rounded-md hover:bg-cyan-500/25 disabled:opacity-50"
            title="Run takeover hunter and persist confirmed takeovers as subdomain_takeover findings."
          >
            <Radar className={cn('h-3 w-3', takeoverRunning === 'commit' && 'animate-pulse')} />
            {takeoverRunning === 'commit' ? 'Hunting…' : 'Hunt Takeovers'}
          </button>
          <button
            onClick={() => refreshCloud.mutate()}
            disabled={refreshCloud.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-muted border border-border rounded-md hover:border-primary/50 disabled:opacity-50"
          >
            <RefreshCw className={cn('h-3 w-3', refreshCloud.isPending && 'animate-spin')} />
            {refreshCloud.isPending ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* AI Triage panel — top-3 next-actions plan + LLM summary */}
      {hasTriage && (
        <div className="bg-gradient-to-br from-purple-500/5 to-cyan-500/5 border border-purple-500/30 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-purple-400" />
              AI Suggested Next Actions
              {triage?.cached && <span className="text-[10px] font-normal text-muted-foreground">(cached)</span>}
            </h3>
            <div className="text-[10px] text-muted-foreground">
              {triage?.model && <span>{triage.model}</span>}
              {triage?.created_at && (
                <span className="ml-2">
                  {new Date(triage.created_at).toLocaleString()}
                </span>
              )}
            </div>
          </div>
          {triage?.summary && (
            <p className="text-xs text-muted-foreground leading-relaxed">{triage.summary}</p>
          )}
          {(triage?.top_actions || []).length > 0 && (
            <ol className="space-y-1.5">
              {(triage!.top_actions || []).map((act, i) => (
                <li key={act.id || i} className="flex items-start gap-2 text-xs">
                  <span className="shrink-0 inline-flex items-center justify-center w-5 h-5 rounded-full bg-purple-500/20 text-purple-300 font-semibold text-[10px]">
                    {i + 1}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium">{act.title}</p>
                    {act.why && <p className="text-muted-foreground text-[11px] mt-0.5">{act.why}</p>}
                  </div>
                </li>
              ))}
            </ol>
          )}
          {triage?.error && (
            <p className="text-[11px] text-red-400">⚠ Triage error: {triage.error}</p>
          )}
        </div>
      )}

      {/* Takeover Hunter results */}
      {(takeoverResult || takeoverError) && (
        <div className="bg-cyan-500/5 border border-cyan-500/30 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <Radar className="h-4 w-4 text-cyan-400" />
              Takeover Hunter
              {takeoverResult?.dry_run && <span className="text-[10px] font-normal text-muted-foreground">(preview — nothing written)</span>}
            </h3>
            <button
              onClick={() => { setTakeoverResult(null); setTakeoverError(null) }}
              className="text-muted-foreground hover:text-foreground"
              title="Dismiss"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          {takeoverError && (
            <p className="text-xs text-red-400">⚠ {takeoverError}</p>
          )}
          {takeoverResult?.debounced && (
            <p className="text-xs text-yellow-400">
              Debounced — last run was within 10 min. Try again in {takeoverResult.next_eligible_in_s}s, or use Hunt (force) above.
            </p>
          )}
          {takeoverResult && !takeoverResult.debounced && (
            <>
              <div className="text-xs text-muted-foreground">
                {takeoverResult.candidates_examined ?? 0} candidate{takeoverResult.candidates_examined === 1 ? '' : 's'} examined
                {' · '}<span className="text-cyan-300 font-medium">{takeoverResult.confirmed ?? 0} confirmed</span>
                {takeoverResult.dry_run
                  ? ''
                  : <> · {takeoverResult.inserted ?? 0} inserted, {takeoverResult.updated ?? 0} updated</>}
                {takeoverResult.proxy_used && <> · <span className="text-green-400">via proxy</span></>}
              </div>
              {takeoverResult.by_detector && Object.keys(takeoverResult.by_detector).length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(takeoverResult.by_detector).map(([id, n]) => (
                    <span key={id} className="px-1.5 py-0.5 text-[10px] rounded bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 font-mono">
                      {id}: {n}
                    </span>
                  ))}
                </div>
              )}
              {takeoverResult.preview && takeoverResult.preview.length > 0 && (
                <div className="mt-2 space-y-1 max-h-64 overflow-y-auto">
                  {takeoverResult.preview.map(hit => (
                    <div key={hit.target + hit.detector_id} className="text-xs flex items-start gap-2 py-1 border-b border-cyan-500/10 last:border-0">
                      <span className={cn('px-1 rounded text-[10px] font-mono shrink-0',
                        hit.vulnerable ? 'bg-red-500/20 text-red-300' : 'bg-yellow-500/20 text-yellow-300')}>
                        {hit.detector_id}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="font-mono truncate">{hit.target}</p>
                        {hit.claim_hint && <p className="text-[10px] text-muted-foreground">{hit.claim_hint}</p>}
                      </div>
                      {hit.http_status != null && <span className="text-[10px] text-muted-foreground">HTTP {hit.http_status}</span>}
                    </div>
                  ))}
                </div>
              )}
              {takeoverResult.confirmed === 0 && !takeoverResult.dry_run && (
                <p className="text-[11px] text-muted-foreground italic">No dangling resources detected. (Re-run after fresh recon scans.)</p>
              )}
            </>
          )}
        </div>
      )}

      {/* Posture Summary */}
      {postureData && hasCloudData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatCard label="Providers" value={postureData.providers.join(', ') || 'none'} />
          <StatCard label="Cloud Findings" value={postureData.total_cloud_findings} />
          <StatCard label="Active Creds" value={postureData.active_cloud_creds} />
          {postureData.expiring_creds > 0 && (
            <StatCard label="Expiring Creds" value={postureData.expiring_creds} className="text-red-400" />
          )}
          {Object.entries(postureData.by_severity).map(([sev, count]) => (
            <StatCard key={sev} label={sev} value={count} />
          ))}
        </div>
      )}

      {!hasCloudData && recs.length === 0 && (
        <div className="text-sm text-muted-foreground bg-muted/50 rounded-lg p-6 text-center">
          <Cloud className="h-8 w-8 mx-auto mb-2 text-muted-foreground/50" />
          <p className="font-medium mb-1">No cloud data imported yet</p>
          <p className="text-xs">Import <strong>Prowler</strong> or <strong>ScoutSuite</strong> output via the Cloud tab in Launch Scan to get started.</p>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <Filter className="h-3.5 w-3.5 text-muted-foreground" />
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="px-2 py-1 text-xs bg-background border border-border rounded-md"
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          value={priorityFilter}
          onChange={e => setPriorityFilter(e.target.value)}
          className="px-2 py-1 text-xs bg-background border border-border rounded-md"
        >
          <option value="">All priorities</option>
          {PRIORITY_OPTIONS.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        {postureData?.providers && postureData.providers.length > 0 && (
          <select
            value={providerFilter}
            onChange={e => setProviderFilter(e.target.value)}
            className="px-2 py-1 text-xs bg-background border border-border rounded-md"
          >
            <option value="">All providers</option>
            {postureData.providers.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        )}
        <div className="ml-auto flex items-center gap-1 text-[10px] uppercase text-muted-foreground">
          <span>Sort:</span>
          <button
            onClick={() => setSortMode('ai')}
            className={cn(
              'px-2 py-1 rounded border flex items-center gap-1',
              sortMode === 'ai'
                ? 'bg-purple-500/20 border-purple-500/40 text-purple-300'
                : 'border-border text-muted-foreground hover:bg-muted',
            )}
            title="AI triage ranking (uses cloud_triage_agent's order)"
          >
            <Brain className="h-3 w-3" /> AI
          </button>
          <button
            onClick={() => setSortMode('static')}
            className={cn(
              'px-2 py-1 rounded border flex items-center gap-1',
              sortMode === 'static'
                ? 'bg-card border-primary/40 text-primary'
                : 'border-border text-muted-foreground hover:bg-muted',
            )}
            title="Static priority sort (critical → high → medium → low)"
          >
            <Zap className="h-3 w-3" /> Static
          </button>
        </div>
      </div>

      {/* Recommendations List */}
      {recs.length > 0 && (
        <div className="space-y-2">
          {recs.map(rec => (
            <RecommendationCard
              key={rec.id}
              rec={rec}
              onDismiss={() => updateCloudRec.mutate({ id: rec.id, status: 'dismissed' })}
              onAccept={() => updateCloudRec.mutate({ id: rec.id, status: 'accepted' })}
            />
          ))}
        </div>
      )}

      {cloudRecs.isLoading && (
        <div className="flex justify-center py-8">
          <div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, className }: { label: string; value: string | number; className?: string }) {
  return (
    <div className="bg-card border border-border rounded-lg p-3">
      <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
      <p className={cn('text-sm font-semibold mt-0.5', className)}>{value}</p>
    </div>
  )
}

// Recs that target the credential vault are dead ends in the static UI
// (the command_hint just says "Navigate to Credentials tab"). For these
// we show an "Auto-import to vault" button that runs vault_import_agent.
function isVaultRec(rec: CloudRecommendation): boolean {
  return rec.tool === 'credential_vault'
      || /credential.?vault/i.test(rec.tool || '')
      || /to credential vault|credentials tab|to.*vault/i.test(rec.action || '')
      || /to credential vault|credentials tab|to.*vault/i.test(rec.command_hint || '')
}

// Map a rule_id to the recon source we should pull from.
function inferSourceForRec(rec: CloudRecommendation): string {
  const r = (rec.rule_id || '').toLowerCase()
  const t = (rec.trigger_source || '').toLowerCase()
  if (t) return t
  if (r.includes('microburst')) return 'microburst'
  if (r.includes('cloudfox')) return 'cloudfox'
  if (r.includes('azurehound')) return 'azurehound'
  return 'microburst'
}

interface VaultProposal {
  username: string
  domain: string | null
  credential_type: string
  credential_value: string | null
  notes: string | null
  source: string
  source_entity_id: string
  engagement_id: string | null
  _finding_target?: string
  _finding_type?: string
  _finding_severity?: string
}

function VaultImportModal({ rec, onClose, onAccept }: {
  rec: CloudRecommendation
  onClose: () => void
  onAccept: () => void
}) {
  const [phase, setPhase] = useState<'preview' | 'committing' | 'done'>('preview')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [proposals, setProposals] = useState<VaultProposal[]>([])
  const [meta, setMeta] = useState<any>({})
  const [result, setResult] = useState<any>(null)

  useEffect(() => {
    (async () => {
      try {
        const body = {
          source: inferSourceForRec(rec),
          dry_run: true,
          limit: 200,
        }
        const r = await apiFetch<any>('/vault/import-from-recon', {
          method: 'POST', body: JSON.stringify(body),
        })
        setProposals(r.proposals || [])
        setMeta({
          examined: r.candidates_examined,
          skipped: r.skipped_already_imported,
          model: r.model,
          totalProposed: r.proposal_count,
        })
      } catch (e) {
        setError(String(e))
      } finally {
        setLoading(false)
      }
    })()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rec.id])

  const commit = async () => {
    setPhase('committing'); setError(null)
    try {
      const body = {
        source: inferSourceForRec(rec),
        dry_run: false,
        limit: 1000,
      }
      const r = await apiFetch<any>('/vault/import-from-recon', {
        method: 'POST', body: JSON.stringify(body),
      })
      setResult(r)
      setPhase('done')
      onAccept()  // mark the rec accepted/completed
    } catch (e) {
      setError(String(e))
      setPhase('preview')
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-[760px] max-h-[80vh] bg-card border border-border rounded-lg shadow-xl flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-border">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-emerald-400" />
            AI Vault Import — {rec.rule_name}
          </h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {loading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Asking the agent to extract credentials…
              {meta.model && <span className="text-[10px]">({meta.model})</span>}
            </div>
          )}
          {error && (
            <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded p-2">
              {error}
            </div>
          )}
          {!loading && !error && phase !== 'done' && (
            <>
              <div className="text-xs text-muted-foreground">
                Examined {meta.examined} finding{meta.examined === 1 ? '' : 's'},
                {' '}{meta.skipped} already in vault,
                {' '}<strong className="text-foreground">{proposals.length} new credential{proposals.length === 1 ? '' : 's'}</strong> proposed.
                {meta.model && <span className="ml-2 text-[10px]">model: <span className="font-mono">{meta.model}</span></span>}
              </div>
              {proposals.length === 0 ? (
                <div className="text-sm text-muted-foreground italic">
                  No new credentials to import.
                </div>
              ) : (
                <div className="border border-border rounded overflow-hidden">
                  <table className="w-full text-xs">
                    <thead className="bg-muted/40 text-[10px] uppercase text-muted-foreground">
                      <tr>
                        <th className="px-2 py-1 text-left">Username</th>
                        <th className="px-2 py-1 text-left">Type</th>
                        <th className="px-2 py-1 text-left">Domain</th>
                        <th className="px-2 py-1 text-left">Value?</th>
                        <th className="px-2 py-1 text-left">From finding</th>
                      </tr>
                    </thead>
                    <tbody>
                      {proposals.slice(0, 100).map((p, i) => (
                        <tr key={p.source_entity_id + ':' + i} className="border-t border-border">
                          <td className="px-2 py-1 font-mono break-all">{p.username}</td>
                          <td className="px-2 py-1">
                            <span className="px-1.5 py-0.5 rounded border bg-muted/40 text-[10px] font-mono">
                              {p.credential_type}
                            </span>
                          </td>
                          <td className="px-2 py-1 font-mono break-all">{p.domain || '—'}</td>
                          <td className="px-2 py-1">
                            {p.credential_value
                              ? <span className="text-emerald-400">✓ captured</span>
                              : <span className="text-muted-foreground">— (reference only)</span>}
                          </td>
                          <td className="px-2 py-1 font-mono text-[10px] text-muted-foreground break-all">
                            {p._finding_type}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {proposals.length > 100 && (
                    <div className="text-[10px] text-muted-foreground px-2 py-1 border-t border-border">
                      Showing first 100 of {proposals.length}. All {proposals.length} will be imported on confirm.
                    </div>
                  )}
                </div>
              )}
            </>
          )}
          {phase === 'committing' && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Importing…
            </div>
          )}
          {phase === 'done' && result && (
            <div className="text-sm bg-emerald-500/10 border border-emerald-500/30 rounded p-3 text-emerald-300">
              Imported <strong>{result.imported}</strong> credentials.
              {result.proposed > result.imported && (
                <span className="text-muted-foreground"> ({result.proposed - result.imported} skipped — likely already in vault)</span>
              )}
              {result.errors?.length > 0 && (
                <details className="mt-2 text-[11px] text-red-400">
                  <summary className="cursor-pointer">{result.errors.length} error{result.errors.length === 1 ? '' : 's'}</summary>
                  <pre className="mt-1 bg-card rounded p-2 whitespace-pre-wrap">
                    {result.errors.join('\n')}
                  </pre>
                </details>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 p-3 border-t border-border">
          {phase === 'preview' && (
            <>
              <button onClick={onClose}
                className="px-3 py-1.5 text-xs border border-border rounded hover:bg-muted">
                Cancel
              </button>
              <button
                onClick={commit}
                disabled={loading || proposals.length === 0}
                className="px-3 py-1.5 text-xs bg-emerald-600/20 text-emerald-300 border border-emerald-600/40 rounded hover:bg-emerald-600/30 disabled:opacity-50 flex items-center gap-1"
              >
                <KeyRound className="h-3 w-3" />
                Import {proposals.length || ''} credential{proposals.length === 1 ? '' : 's'}
              </button>
            </>
          )}
          {phase === 'done' && (
            <button onClick={onClose}
              className="px-3 py-1.5 text-xs bg-primary text-primary-foreground rounded">
              Close
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function RecommendationCard({ rec, onDismiss, onAccept }: {
  rec: CloudRecommendation
  onDismiss: () => void
  onAccept: () => void
}) {
  const [showVaultModal, setShowVaultModal] = useState(false)
  const isVault = isVaultRec(rec)
  return (
    <div className="flex items-start gap-3 p-3 bg-card border border-border rounded-lg">
      <div className="flex flex-col items-center gap-1 shrink-0 mt-0.5">
        {typeof rec.triage_order === 'number' && (
          <span
            className="px-1.5 py-0.5 text-[10px] rounded font-mono bg-purple-500/15 text-purple-300 border border-purple-500/30"
            title="AI triage rank — lower is do-first"
          >
            #{rec.triage_order}
          </span>
        )}
        <span className={cn('px-1.5 py-0.5 text-[10px] rounded font-medium', PRIORITY_BADGE[rec.priority] || 'bg-gray-500 text-white')}>
          {rec.priority}
        </span>
      </div>
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <p className="text-sm font-medium">{rec.rule_name}</p>
          {rec.provider && (
            <span className="px-1.5 py-0.5 text-[10px] bg-muted rounded">{rec.provider}</span>
          )}
          <span className={cn(
            'px-1.5 py-0.5 text-[10px] rounded',
            rec.status === 'open' ? 'bg-blue-500/20 text-blue-400' :
            rec.status === 'accepted' ? 'bg-green-500/20 text-green-400' :
            'bg-zinc-500/20 text-zinc-400'
          )}>
            {rec.status}
          </span>
        </div>
        {rec.triage_reasoning && (
          <p className="text-[11px] text-purple-300/80 italic flex items-start gap-1">
            <Brain className="h-3 w-3 shrink-0 mt-0.5" />
            <span>{rec.triage_reasoning}</span>
          </p>
        )}
        <p className="text-xs text-muted-foreground">{rec.action}</p>
        {rec.trigger_summary && (
          <p className="text-[11px] text-muted-foreground/70">Trigger: {rec.trigger_summary}</p>
        )}
        {rec.command_hint && (
          <code
            className="flex items-center gap-1 text-[10px] text-cyan-400 bg-background rounded px-2 py-1 font-mono cursor-pointer hover:bg-muted w-fit max-w-full"
            onClick={() => navigator.clipboard.writeText(rec.command_hint!)}
            title="Click to copy"
          >
            <Copy className="h-2.5 w-2.5 shrink-0" />
            <span className="truncate">{rec.command_hint}</span>
          </code>
        )}
      </div>
      {rec.status === 'open' && (
        <div className="flex flex-col gap-1 shrink-0">
          {isVault ? (
            <button
              onClick={() => setShowVaultModal(true)}
              className="flex items-center gap-1 px-2 py-1 text-[10px] bg-emerald-600/20 text-emerald-300 border border-emerald-600/40 rounded hover:bg-emerald-600/30"
              title="Run the AI vault-import agent: extract credentials from the underlying recon_findings and add them to the vault"
            >
              <KeyRound className="h-3 w-3" /> Auto-import
            </button>
          ) : (
            <button
              onClick={onAccept}
              className="flex items-center gap-1 px-2 py-1 text-[10px] bg-green-600/20 text-green-400 border border-green-600/30 rounded hover:bg-green-600/30"
            >
              <CheckCircle className="h-3 w-3" /> Accept
            </button>
          )}
          <button
            onClick={onDismiss}
            className="flex items-center gap-1 px-2 py-1 text-[10px] text-muted-foreground border border-border rounded hover:bg-muted"
          >
            <XCircle className="h-3 w-3" /> Dismiss
          </button>
        </div>
      )}
      {showVaultModal && (
        <VaultImportModal
          rec={rec}
          onClose={() => setShowVaultModal(false)}
          onAccept={onAccept}
        />
      )}
    </div>
  )
}
