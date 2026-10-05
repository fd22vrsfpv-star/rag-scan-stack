// Scope Pivot & Typosquats panel — operator surface for the typosquat
// detector + cert/ASN pivot review workflow.
//
// Pass an `engagementId` to bind the panel to a specific engagement (used
// on the Engagements → Scope tab). Omit it to render an engagement picker
// (used on the standalone Scope Intelligence page as a fallback).
//
// Design: operator complaint from the first UI pass was that
// "going into the one domain with thousands of subdomains is clunky" —
// the panel's natural home is at the ENGAGEMENT level (one picker already
// in context), not inside a single-scope drill-down. The dropdown-form
// stays as a graceful fallback for the standalone page.
import { useState } from 'react'
import { Zap, Target } from 'lucide-react'
import { cn } from '@/lib/utils'
import { usePivotSuggestions, useRunTyposquatPivot, useReviewPivotSuggestion } from '@/api/scope'
import { useEngagements } from '@/api/engagements'

export function ScopePivotPanel({ engagementId: fixedEid }: { engagementId?: string }) {
  const [methodFilter, setMethodFilter] = useState<string>('')
  const [pickedEid, setPickedEid] = useState<string>('')
  const [lastRunSummary, setLastRunSummary] = useState<string>('')
  const effectiveEid = fixedEid || pickedEid

  const { data: suggestionsData, isLoading } = usePivotSuggestions({
    status: 'pending',
    method: methodFilter || undefined,
  })
  const { data: engagementsData } = useEngagements()
  const runPivot = useRunTyposquatPivot()
  const review = useReviewPivotSuggestion()
  const suggestions = suggestionsData?.suggestions ?? []
  const engagements = engagementsData?.engagements ?? []

  const handleRun = async () => {
    if (!effectiveEid) { setLastRunSummary('select an engagement first'); return }
    try {
      const r = await runPivot.mutateAsync({ engagementId: effectiveEid, checkResolution: false, autoBlockAt: 0.85 })
      const s = r.summary
      setLastRunSummary(
        `seeds=${s.seeds} candidates=${s.total_candidates} suggestions=${s.suggestions_written} auto-blocked=${s.denylist_added}`
        + (s.errors.length ? ` (${s.errors.length} errors)` : '')
      )
    } catch (e: unknown) {
      setLastRunSummary(`error: ${(e as Error).message}`)
    }
  }

  const methodBadge = (m: string) => {
    const cls = m === 'typosquat' ? 'bg-amber-500/15 text-amber-300'
      : m === 'cert_pivot' ? 'bg-blue-500/15 text-blue-300'
      : m === 'asn_pivot' ? 'bg-emerald-500/15 text-emerald-300'
      : 'bg-gray-500/15 text-gray-400'
    return <span className={cn('px-1.5 py-0.5 rounded text-[9px] font-medium', cls)}>{m}</span>
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Target className="h-4 w-4" />
        Scope Pivot & Typosquats
      </div>
      <p className="text-[11px] text-muted-foreground">
        <strong className="text-foreground">Typosquat pivot</strong>: generates lookalike variants
        (edit, QWERTY, homoglyph, bitsquat, IDN, TLD swap) of each in-scope apex, scores each, writes
        pending suggestions, and auto-adds high-confidence (≥0.85) hits to the global
        <code className="mx-1 text-amber-300">not_in_scope</code> deny-list. The scope gate refuses
        dispatch to anything on the deny-list for every engagement.
      </p>

      {/* Run bar — hide engagement picker when panel is bound to a known engagement */}
      <div className="flex items-center gap-2 flex-wrap p-2 bg-muted/20 border border-border rounded">
        {!fixedEid && (
          <>
            <span className="text-[11px] text-muted-foreground">Engagement:</span>
            <select
              value={pickedEid}
              onChange={e => setPickedEid(e.target.value)}
              className="h-6 px-1 rounded border border-border bg-background text-[11px] min-w-[180px]"
            >
              <option value="">— select —</option>
              {engagements.map(e => (
                <option key={e.id} value={e.id}>{e.name}</option>
              ))}
            </select>
          </>
        )}
        <button
          onClick={handleRun}
          disabled={!effectiveEid || runPivot.isPending}
          className="h-6 px-2 text-[11px] rounded bg-primary hover:bg-primary/80 text-primary-foreground disabled:opacity-40 inline-flex items-center gap-1"
          title="Run the typosquat generator + scorer against this engagement's apex scope. Writes scope_suggestions and auto-adds high-confidence hits to the global not_in_scope deny-list."
        >
          <Zap className="w-3 h-3" />
          {runPivot.isPending ? 'running…' : 'Run typosquat pivot'}
        </button>
        {lastRunSummary && (
          <span className="text-[10px] font-mono text-muted-foreground ml-2">{lastRunSummary}</span>
        )}
      </div>

      {/* Method filter */}
      <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
        <span>Filter:</span>
        {(['', 'typosquat', 'cert_pivot', 'asn_pivot'] as const).map(m => (
          <button key={m || 'all'}
            onClick={() => setMethodFilter(m)}
            className={cn('h-6 px-2 rounded border transition-colors',
              methodFilter === m ? 'border-primary bg-primary/10 text-primary' : 'border-border hover:bg-accent')}
          >{m || 'all'}</button>
        ))}
        <span className="ml-auto text-[10px]">
          {suggestions.length} pending{suggestionsData?.total ? ` of ${suggestionsData.total}` : ''}
        </span>
      </div>

      {/* Suggestions table */}
      {isLoading ? (
        <p className="text-[11px] text-muted-foreground">Loading…</p>
      ) : suggestions.length === 0 ? (
        <p className="text-[11px] text-muted-foreground italic">
          No pending suggestions. Run the typosquat pivot above or wait for the
          cert/ASN pipeline to land its proposals.
        </p>
      ) : (
        <div className="max-h-80 overflow-y-auto">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="py-1 px-2 font-medium">Target</th>
                <th className="py-1 px-2 font-medium w-20">Method</th>
                <th className="py-1 px-2 font-medium w-16">Score</th>
                <th className="py-1 px-2 font-medium">Reasoning</th>
                <th className="py-1 px-2 font-medium w-28">Actions</th>
              </tr>
            </thead>
            <tbody>
              {suggestions.map(s => (
                <tr key={s.id} className="border-b border-border/50 hover:bg-muted/50 align-top">
                  <td className="py-1.5 px-2 font-mono">{s.target}</td>
                  <td className="py-1.5 px-2">{methodBadge(s.method)}</td>
                  <td className="py-1.5 px-2 font-mono">{s.confidence?.toFixed(2) ?? '—'}</td>
                  <td className="py-1.5 px-2 text-[10px] text-muted-foreground">{s.reasoning}</td>
                  <td className="py-1.5 px-2">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => review.mutate({ id: s.id, action: 'accept' })}
                        disabled={review.isPending}
                        className="h-6 px-2 text-[10px] rounded bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30"
                        title={s.method === 'typosquat'
                          ? 'Confirm as a typosquat. Adds to the global not_in_scope deny-list; the scope gate will refuse all dispatch to this target.'
                          : 'Promote to the active engagement\'s in-scope list.'}
                      >Confirm</button>
                      <button
                        onClick={() => review.mutate({ id: s.id, action: 'reject' })}
                        disabled={review.isPending}
                        className="h-6 px-2 text-[10px] rounded border border-border hover:bg-accent"
                        title="Mark as a false positive. No deny-list entry; the suggestion drops out of the pending view."
                      >Reject</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
