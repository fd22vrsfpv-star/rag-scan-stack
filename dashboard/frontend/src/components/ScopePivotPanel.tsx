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
import { useState, useMemo, useEffect } from 'react'
import { Zap, Target } from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  usePivotSuggestions,
  useRunTyposquatPivot,
  useRunCertPivot,
  useRunAsnPivot,
  useReviewPivotSuggestion,
  useBulkReviewPivotSuggestions,
} from '@/api/scope'
import { useEngagements } from '@/api/engagements'

export function ScopePivotPanel({ engagementId: fixedEid }: { engagementId?: string }) {
  const [methodFilter, setMethodFilter] = useState<string>('')
  const [pickedEid, setPickedEid] = useState<string>('')
  const [lastRunSummary, setLastRunSummary] = useState<string>('')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkSummary, setBulkSummary] = useState<string>('')
  const effectiveEid = fixedEid || pickedEid

  const { data: suggestionsData, isLoading } = usePivotSuggestions({
    status: 'pending',
    method: methodFilter || undefined,
  })
  const { data: engagementsData } = useEngagements()
  const runPivot = useRunTyposquatPivot()
  const runCert = useRunCertPivot()
  const runAsn = useRunAsnPivot()
  const review = useReviewPivotSuggestion()
  const bulkReview = useBulkReviewPivotSuggestions()
  const suggestions = suggestionsData?.suggestions ?? []
  const engagements = engagementsData?.engagements ?? []

  // Drop stale selections when the pending set changes (a filter switch
  // or a successful bulk commit should empty the box).
  const visibleIds = useMemo(() => new Set(suggestions.map(s => s.id)), [suggestions])
  useEffect(() => {
    setSelectedIds(prev => {
      const next = new Set<string>()
      for (const id of prev) if (visibleIds.has(id)) next.add(id)
      return next.size === prev.size ? prev : next
    })
  }, [visibleIds])

  const allVisibleChecked = suggestions.length > 0 && suggestions.every(s => selectedIds.has(s.id))
  const toggleOne = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }
  const toggleAllVisible = () => {
    setSelectedIds(prev => {
      if (allVisibleChecked) {
        const next = new Set(prev)
        for (const s of suggestions) next.delete(s.id)
        return next
      }
      const next = new Set(prev)
      for (const s of suggestions) next.add(s.id)
      return next
    })
  }

  const runBulk = async (action: 'accept' | 'reject') => {
    const ids = Array.from(selectedIds)
    if (!ids.length) { setBulkSummary('nothing selected'); return }
    // Bias toward the honest action — a bulk Confirm on typosquats is
    // destructive-adjacent (adds to a typosquats scope the gate denies),
    // so warn when the selection spans methods or the count is large.
    const typoCount = suggestions.filter(s => selectedIds.has(s.id) && s.method === 'typosquat').length
    const promoteCount = ids.length - typoCount
    if (action === 'accept') {
      const parts: string[] = []
      if (typoCount) parts.push(`${typoCount} typosquat → this engagement's typosquats scope`)
      if (promoteCount) parts.push(`${promoteCount} cert/ASN pivot → this engagement's new_for_review scope (gate still refuses dispatch)`)
      const msg = `Confirm ${ids.length} suggestions?\n\n${parts.join('\n')}\n\nThis is reversible per-row from the suggestion lists.`
      if (!window.confirm(msg)) return
    }
    try {
      const r = await bulkReview.mutateAsync({ ids, action })
      setBulkSummary(`${action}: ${r.processed}/${r.requested} processed`)
      setSelectedIds(new Set())
    } catch (e: unknown) {
      setBulkSummary(`error: ${(e as Error).message}`)
    }
  }

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

  const handleRunCert = async () => {
    if (!effectiveEid) { setLastRunSummary('select an engagement first'); return }
    try {
      const r = await runCert.mutateAsync({ engagementId: effectiveEid })
      const s = r.summary
      setLastRunSummary(
        `cert-pivot: seeds=${s.seeds} certs=${s.certs_examined} candidates=${s.candidates} suggestions=${s.suggestions_written}`
        + (s.errors.length ? ` (${s.errors.join('; ')})` : '')
      )
    } catch (e: unknown) {
      setLastRunSummary(`error: ${(e as Error).message}`)
    }
  }

  const handleRunAsn = async () => {
    if (!effectiveEid) { setLastRunSummary('select an engagement first'); return }
    try {
      const r = await runAsn.mutateAsync({ engagementId: effectiveEid })
      const s = r.summary
      setLastRunSummary(
        `asn-pivot: seeds=${s.seeds} asns=${s.asns_matched} candidates=${s.candidates} suggestions=${s.suggestions_written}`
        + (s.errors.length ? ` (${s.errors.join('; ')})` : '')
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
        pending suggestions, and auto-adds high-confidence (≥0.85) hits to this engagement's
        <code className="mx-1 text-amber-300">typosquats</code> scope. The scope gate's deny-list
        loader reads every engagement's typosquats scope, so refusal is cross-engagement.
      </p>
      <p className="text-[11px] text-muted-foreground">
        <strong className="text-blue-300">Cert pivot</strong> flags domains sharing a TLS
        certificate SAN with an in-scope host (a same-owner signal);{' '}
        <strong className="text-emerald-300">ASN pivot</strong> suggests the CIDR ranges of the
        ASNs your in-scope hosts live in. Both are passive (they read recon already collected)
        and land accepted targets in this engagement's
        <code className="mx-1 text-foreground">new_for_review</code> scope — visible under the
        engagement but gate-refused until you promote them to a live scope.
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
          title="Run the typosquat generator + scorer against this engagement's apex scope. Writes scope_suggestions and auto-adds high-confidence hits to this engagement's typosquats scope."
        >
          <Zap className="w-3 h-3" />
          {runPivot.isPending ? 'running…' : 'Run typosquat pivot'}
        </button>
        <button
          onClick={handleRunCert}
          disabled={!effectiveEid || runCert.isPending}
          className="h-6 px-2 text-[11px] rounded bg-blue-500/15 hover:bg-blue-500/25 text-blue-300 border border-blue-500/30 disabled:opacity-40 inline-flex items-center gap-1"
          title="Cert pivot: scans TLS certs already collected on this engagement's in-scope hosts (tlsx/crtsh) and flags SANs in a different registrable domain — a same-owner signal. Passive (no new traffic). Accepted hits land in this engagement's new_for_review scope (gate still refuses dispatch)."
        >
          <Zap className="w-3 h-3" />
          {runCert.isPending ? 'running…' : 'Run cert pivot'}
        </button>
        <button
          onClick={handleRunAsn}
          disabled={!effectiveEid || runAsn.isPending}
          className="h-6 px-2 text-[11px] rounded bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 disabled:opacity-40 inline-flex items-center gap-1"
          title="ASN pivot: reads asnmap results already collected for this engagement and suggests the CIDR ranges of the ASNs the in-scope hosts live in (cloud/CDN dropped unless the AS name matches the org). Passive (no new traffic). Accepted ranges land in this engagement's new_for_review scope (gate still refuses dispatch)."
        >
          <Zap className="w-3 h-3" />
          {runAsn.isPending ? 'running…' : 'Run ASN pivot'}
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

      {/* Bulk action bar — appears whenever anything is selected */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-2 flex-wrap p-2 bg-primary/5 border border-primary/30 rounded">
          <span className="text-[11px] font-medium">{selectedIds.size} selected</span>
          <button
            onClick={() => runBulk('accept')}
            disabled={bulkReview.isPending}
            className="h-6 px-2 text-[11px] rounded bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 disabled:opacity-40"
            title="Confirm every selected suggestion. Typosquats go into this engagement's typosquats scope; cert/ASN pivots go into this engagement's new_for_review scope. The gate refuses dispatch to both until you promote a target to a live scope."
          >
            Confirm selected
          </button>
          <button
            onClick={() => runBulk('reject')}
            disabled={bulkReview.isPending}
            className="h-6 px-2 text-[11px] rounded border border-border hover:bg-accent disabled:opacity-40"
            title="Mark every selected suggestion as a false positive. No deny-list or scope changes; the rows drop out of the pending view."
          >
            Reject selected
          </button>
          <button
            onClick={() => setSelectedIds(new Set())}
            className="h-6 px-2 text-[11px] rounded border border-border hover:bg-accent"
          >
            Clear
          </button>
          {bulkSummary && (
            <span className="text-[10px] font-mono text-muted-foreground ml-2">{bulkSummary}</span>
          )}
        </div>
      )}

      {/* Suggestions table */}
      {isLoading ? (
        <p className="text-[11px] text-muted-foreground">Loading…</p>
      ) : suggestions.length === 0 ? (
        <p className="text-[11px] text-muted-foreground italic">
          No pending suggestions. Run the typosquat, cert, or ASN pivot above.
          Cert/ASN pivots read recon already collected (tlsx/crtsh for certs,
          asnmap for ASNs) — run that recon first if a pivot finds nothing.
        </p>
      ) : (
        <div className="max-h-80 overflow-y-auto">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="py-1 px-2 font-medium w-6">
                  <input
                    type="checkbox"
                    checked={allVisibleChecked}
                    ref={el => {
                      if (el) el.indeterminate = !allVisibleChecked && suggestions.some(s => selectedIds.has(s.id))
                    }}
                    onChange={toggleAllVisible}
                    aria-label="Select all visible suggestions"
                    className="cursor-pointer"
                  />
                </th>
                <th className="py-1 px-2 font-medium">Target</th>
                <th className="py-1 px-2 font-medium w-20">Method</th>
                <th className="py-1 px-2 font-medium w-16">Score</th>
                <th className="py-1 px-2 font-medium">Reasoning</th>
                <th className="py-1 px-2 font-medium w-28">Actions</th>
              </tr>
            </thead>
            <tbody>
              {suggestions.map(s => (
                <tr key={s.id} className={cn(
                  'border-b border-border/50 hover:bg-muted/50 align-top',
                  selectedIds.has(s.id) && 'bg-primary/5',
                )}>
                  <td className="py-1.5 px-2">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(s.id)}
                      onChange={() => toggleOne(s.id)}
                      aria-label={`Select ${s.target}`}
                      className="cursor-pointer"
                    />
                  </td>
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
                          ? "Confirm as a typosquat. Adds to this engagement's typosquats scope; the scope gate's deny-list loader reads it (and every engagement's typosquats scope) so dispatch is refused everywhere."
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
