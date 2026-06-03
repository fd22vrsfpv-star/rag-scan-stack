import { useState } from 'react'
import {
  useKBServices,
  useKBService,
  useUpsertKBService,
  useDeleteKBOverride,
  type KBServiceSummary,
} from '@/api/kb'
import {
  useRagAsk,
  useRagFeedback,
  useRagFeedbackStats,
  useRagTrainingPreview,
  useRagTrainingExport,
  useRagEvalRun,
  useRagEvalHistory,
  type RagAskResponse,
  type RagRetrievedChunk,
  type RagTrainingExportResult,
  type RagEvalRun,
} from '@/api/rag'

/**
 * "Training data" panel — Layer 3 of the RAG feedback loop.
 *
 * Shows how many rows the current rag_query_log + rag_feedback would
 * produce in each training dataset format (embedding triplets,
 * reranker rows, GRPO RLHF rows), and offers a one-click export that
 * writes them as JSONL to `/datasets/rag-<timestamp>/` on the host
 * (bind-mounted from the scan-recommender container).  The
 * grpo_trainer service, when deployed, picks the same files up.
 */
function TrainingDataPanel() {
  const [days, setDays] = useState(90)
  const { data: preview } = useRagTrainingPreview(days)
  const exportMut = useRagTrainingExport()
  const [lastResult, setLastResult] = useState<RagTrainingExportResult | null>(null)

  const handleExport = async () => {
    setLastResult(null)
    try {
      const res = await exportMut.mutateAsync({ days })
      setLastResult(res)
    } catch {
      // surfaced via exportMut.error
    }
  }

  const ready = (preview?.triplets ?? 0) + (preview?.reranker_rows ?? 0) + (preview?.grpo_rows ?? 0)
  const haveData = ready > 0

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Training data (Layer 3)</h3>
          <p className="text-xs text-muted-foreground">
            Convert operator feedback into fine-tuning datasets.  Exports
            three JSONL files: embedding triplets (hard negatives),
            reranker rows (top-K with per-chunk labels), and GRPO RLHF
            rows for LLM training.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-[10px] text-muted-foreground">window</label>
          <select
            value={days}
            onChange={e => setDays(Number(e.target.value))}
            className="h-7 rounded-md border border-border bg-background px-2 text-xs"
          >
            <option value={7}>7d</option>
            <option value={30}>30d</option>
            <option value={90}>90d</option>
            <option value={365}>365d</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div className="rounded border border-border bg-muted/10 p-2 text-center">
          <div className="text-lg font-mono font-semibold">
            {preview?.triplets ?? '—'}
          </div>
          <div className="text-[10px] text-muted-foreground">
            embedding triplets<br />
            <span className="text-[9px]">(query, +ve, hard −ve)</span>
          </div>
        </div>
        <div className="rounded border border-border bg-muted/10 p-2 text-center">
          <div className="text-lg font-mono font-semibold">
            {preview?.reranker_rows ?? '—'}
          </div>
          <div className="text-[10px] text-muted-foreground">
            reranker rows<br />
            <span className="text-[9px]">(query, top-K labeled)</span>
          </div>
        </div>
        <div className="rounded border border-border bg-muted/10 p-2 text-center">
          <div className="text-lg font-mono font-semibold">
            {preview?.grpo_rows ?? '—'}
          </div>
          <div className="text-[10px] text-muted-foreground">
            GRPO rows<br />
            <span className="text-[9px]">(RLHF prompt/response)</span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={handleExport}
          disabled={exportMut.isPending || !haveData}
          className="h-7 px-3 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          title={haveData ? 'Export to /datasets/' : 'No feedback rows in the selected window'}
        >
          {exportMut.isPending ? 'Exporting…' : 'Export training data'}
        </button>
        {!haveData && preview && (
          <span className="text-[10px] text-muted-foreground">
            Rate some answers above to generate training data.
          </span>
        )}
        {lastResult?.exported && (
          <span className="text-xs text-green-400 font-mono truncate">
            ✓ wrote {Object.values(lastResult.files ?? {}).reduce((a, b) => a + b, 0)} rows
            to <code>{lastResult.output_dir}</code>
          </span>
        )}
        {lastResult && !lastResult.exported && lastResult.reason && (
          <span className="text-xs text-amber-400">{lastResult.reason}</span>
        )}
        {exportMut.error && (
          <span className="text-xs text-red-400 font-mono">
            {exportMut.error instanceof Error ? exportMut.error.message : String(exportMut.error)}
          </span>
        )}
      </div>
    </div>
  )
}


/**
 * "Retrieval quality" panel — Layer 4 Phase A.
 *
 * Re-runs the feedback-rated queries through the live retrieval
 * pipeline, scores them against operator-labeled helpful chunks,
 * persists the result.  Lets us prove whether a future model swap
 * (embedding fine-tune, reranker, etc.) actually improves retrieval
 * vs. just claiming it does.
 */
function RetrievalQualityPanel() {
  const [modelLabel, setModelLabel] = useState('baseline')
  const [notes, setNotes] = useState('')
  const runMut = useRagEvalRun()
  const { data: history } = useRagEvalHistory(10)
  const latest = history?.runs?.[0]

  const fmt = (v: number | null | undefined) =>
    v == null ? '—' : v.toFixed(3)

  const handleRun = async () => {
    try {
      await runMut.mutateAsync({
        model_label: modelLabel || 'baseline',
        notes: notes.trim() || null,
      })
      setNotes('')
    } catch {
      // surfaced via runMut.error
    }
  }

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Retrieval quality (Phase A)</h3>
          <p className="text-xs text-muted-foreground">
            Replay every feedback-rated query through the current retrieval
            pipeline and score against operator labels.  The score is the
            only honest answer to "did fine-tuning actually help?" — track
            it before and after every model swap.
          </p>
        </div>
        <div className="flex flex-col items-end gap-1 text-[10px] text-muted-foreground">
          {latest ? (
            <>
              <span>
                last run: <strong className="text-foreground">{latest.model_label}</strong>
                {' '}· n={latest.eval_set_size}
              </span>
              <span>
                {new Date(latest.created_at).toLocaleString()}
              </span>
            </>
          ) : (
            <span>no eval runs yet</span>
          )}
        </div>
      </div>

      {/* Metric grid */}
      <div className="grid grid-cols-4 gap-2">
        <MetricCell label="NDCG@3" value={fmt(latest?.ndcg_at_3)} />
        <MetricCell label="NDCG@5" value={fmt(latest?.ndcg_at_5)} />
        <MetricCell label="MRR" value={fmt(latest?.mrr)} />
        <MetricCell label="Recall@5" value={fmt(latest?.recall_at_5)} />
      </div>

      {/* Run controls */}
      <div className="flex items-end gap-2 flex-wrap">
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-muted-foreground">model_label</label>
          <input
            value={modelLabel}
            onChange={e => setModelLabel(e.target.value)}
            placeholder="baseline"
            className="h-7 w-32 rounded-md border border-border bg-background px-2 text-xs"
          />
        </div>
        <div className="flex flex-col gap-1 flex-1 min-w-[200px]">
          <label className="text-[10px] text-muted-foreground">notes (optional)</label>
          <input
            value={notes}
            onChange={e => setNotes(e.target.value)}
            placeholder='e.g. "after re-ingest with markdown chunker"'
            className="h-7 rounded-md border border-border bg-background px-2 text-xs"
          />
        </div>
        <button
          onClick={handleRun}
          disabled={runMut.isPending}
          className="h-7 px-3 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {runMut.isPending ? 'Running…' : 'Run evaluation'}
        </button>
      </div>

      {runMut.data && !runMut.data.ran && (
        <p className="text-xs text-amber-400">
          {runMut.data.reason ?? 'No rated queries to evaluate yet.'}
        </p>
      )}
      {runMut.error && (
        <p className="text-xs text-red-400 font-mono">
          {runMut.error instanceof Error ? runMut.error.message : String(runMut.error)}
        </p>
      )}

      {/* History table */}
      {history?.runs && history.runs.length > 1 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Recent runs</h4>
          <div className="overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="py-1 px-1.5">When</th>
                  <th className="py-1 px-1.5">Model</th>
                  <th className="py-1 px-1.5 text-right">n</th>
                  <th className="py-1 px-1.5 text-right">NDCG@3</th>
                  <th className="py-1 px-1.5 text-right">NDCG@5</th>
                  <th className="py-1 px-1.5 text-right">MRR</th>
                  <th className="py-1 px-1.5 text-right">R@5</th>
                  <th className="py-1 px-1.5">Notes</th>
                </tr>
              </thead>
              <tbody>
                {history.runs.map((r: RagEvalRun) => (
                  <tr key={r.id} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="py-1 px-1.5 text-muted-foreground whitespace-nowrap">
                      {new Date(r.created_at).toLocaleString(undefined, {
                        month: 'short', day: 'numeric',
                        hour: '2-digit', minute: '2-digit',
                      })}
                    </td>
                    <td className="py-1 px-1.5 font-mono">{r.model_label}</td>
                    <td className="py-1 px-1.5 text-right">{r.eval_set_size}</td>
                    <td className="py-1 px-1.5 text-right font-mono">{fmt(r.ndcg_at_3)}</td>
                    <td className="py-1 px-1.5 text-right font-mono">{fmt(r.ndcg_at_5)}</td>
                    <td className="py-1 px-1.5 text-right font-mono">{fmt(r.mrr)}</td>
                    <td className="py-1 px-1.5 text-right font-mono">{fmt(r.recall_at_5)}</td>
                    <td className="py-1 px-1.5 text-muted-foreground truncate max-w-[180px]">
                      {r.notes ?? '—'}
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


function MetricCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-border bg-muted/10 p-2 text-center">
      <div className="text-base font-mono font-semibold">{value}</div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  )
}


function SourceBadge({ source }: { source: string }) {
  const colors: Record<string, string> = {
    yaml: 'bg-blue-500/20 text-blue-400',
    override: 'bg-amber-500/20 text-amber-400',
    both: 'bg-green-500/20 text-green-400',
  }
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${colors[source] || 'bg-muted text-muted-foreground'}`}>
      {source}
    </span>
  )
}


/**
 * "Ask the Knowledge Base" — interactive RAG querying with operator
 * feedback (Layer 1: every call writes a rag_query_log row; Layer 2:
 * per-chunk thumbs up/down + overall rating + comment write rag_feedback
 * rows).  Hard-negative signal (chunks marked unhelpful despite high
 * similarity) is the most valuable training data this surface produces.
 */
function AskKnowledgeBase() {
  const [question, setQuestion] = useState('')
  const [topK, setTopK] = useState(6)
  const [response, setResponse] = useState<RagAskResponse | null>(null)
  // Per-chunk feedback state, keyed by chunk_id.  +1 = thumbs up,
  // -1 = thumbs down, undefined = no opinion yet.
  const [chunkRatings, setChunkRatings] = useState<Record<number, 1 | -1>>({})
  const [overallRating, setOverallRating] = useState<-1 | 0 | 1>(0)
  const [comment, setComment] = useState('')
  const [submittedFeedbackFor, setSubmittedFeedbackFor] = useState<string | null>(null)

  const ask = useRagAsk()
  const submitFeedback = useRagFeedback()
  const { data: stats } = useRagFeedbackStats(30)

  const handleAsk = async () => {
    if (!question.trim()) return
    setResponse(null)
    setChunkRatings({})
    setOverallRating(0)
    setComment('')
    setSubmittedFeedbackFor(null)
    try {
      const r = await ask.mutateAsync({ q: question, top_k: topK })
      setResponse(r)
    } catch {
      // Surfaced via ask.error below
    }
  }

  const handleSubmitFeedback = async () => {
    if (!response?.query_log_id) return
    const helpful = Object.entries(chunkRatings)
      .filter(([, r]) => r === 1)
      .map(([id]) => Number(id))
    const unhelpful = Object.entries(chunkRatings)
      .filter(([, r]) => r === -1)
      .map(([id]) => Number(id))
    try {
      await submitFeedback.mutateAsync({
        query_log_id: response.query_log_id,
        rating: overallRating,
        helpful_chunk_ids: helpful,
        unhelpful_chunk_ids: unhelpful,
        comment: comment.trim() || undefined,
      })
      setSubmittedFeedbackFor(response.query_log_id)
    } catch {
      // Error surfaced via submitFeedback.error
    }
  }

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Ask the Knowledge Base</h3>
          <p className="text-xs text-muted-foreground">
            Natural-language RAG query over playbooks + ExploitDB.  Rate the
            answer + mark individual chunks helpful/unhelpful to feed the
            training pipeline.
          </p>
        </div>
        {stats?.summary && (
          <div className="text-[10px] text-muted-foreground text-right">
            <div>
              <strong className="text-foreground">{stats.summary.queries}</strong>{' '}
              queries · last {stats.days}d
            </div>
            <div>
              👍 {stats.summary.thumbs_up} · 👎 {stats.summary.thumbs_down}
              {stats.summary.queries > 0 && (
                <>
                  {' '}·{' '}
                  {Math.round(
                    (stats.summary.feedback_rows / stats.summary.queries) * 100,
                  )}
                  % rated
                </>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="flex items-start gap-2">
        <textarea
          value={question}
          onChange={e => setQuestion(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) handleAsk()
          }}
          placeholder="e.g. how do I brute force ssh?  (Ctrl/Cmd+Enter to submit)"
          rows={2}
          className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs font-mono resize-none"
        />
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-muted-foreground">top_k</label>
          <input
            type="number"
            min={1}
            max={25}
            value={topK}
            onChange={e => setTopK(Math.max(1, Math.min(25, Number(e.target.value) || 6)))}
            className="w-14 rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
          <button
            onClick={handleAsk}
            disabled={ask.isPending || !question.trim()}
            className="px-3 py-1.5 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {ask.isPending ? 'Asking…' : 'Ask'}
          </button>
        </div>
      </div>

      {ask.error && (
        <p className="text-xs text-red-400 font-mono">
          Error: {ask.error instanceof Error ? ask.error.message : String(ask.error)}
        </p>
      )}

      {response && (
        <div className="space-y-3 border-t border-border pt-3">
          {/* Answer */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <h4 className="text-xs font-semibold">Answer</h4>
              <span className="text-[10px] text-muted-foreground">
                {response.duration_ms}ms · log id:{' '}
                <code className="font-mono">
                  {response.query_log_id?.slice(0, 8) ?? '—'}
                </code>
              </span>
            </div>
            <pre className="text-xs whitespace-pre-wrap font-sans bg-muted/30 rounded p-2 border border-border">
              {response.answer || '(empty response from LLM)'}
            </pre>
          </div>

          {/* Retrieved chunks with per-chunk feedback */}
          {response.retrieved && response.retrieved.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold mb-2">
                Retrieved chunks ({response.retrieved.length})
              </h4>
              <div className="space-y-2">
                {response.retrieved.map((c: RagRetrievedChunk, i: number) => {
                  const rating = chunkRatings[c.chunk_id]
                  return (
                    <div
                      key={c.chunk_id}
                      className="flex items-start gap-2 p-2 rounded border border-border bg-muted/10"
                    >
                      <div className="flex flex-col gap-1 shrink-0">
                        <button
                          onClick={() =>
                            setChunkRatings(prev => ({
                              ...prev,
                              [c.chunk_id]: rating === 1 ? (undefined as unknown as 1) : 1,
                            }))
                          }
                          title="Helpful"
                          className={`w-6 h-6 rounded text-xs ${
                            rating === 1
                              ? 'bg-green-500/30 border border-green-500/50 text-green-400'
                              : 'bg-background border border-border hover:bg-muted'
                          }`}
                        >
                          👍
                        </button>
                        <button
                          onClick={() =>
                            setChunkRatings(prev => ({
                              ...prev,
                              [c.chunk_id]: rating === -1 ? (undefined as unknown as -1) : -1,
                            }))
                          }
                          title="Not helpful (despite high similarity — hard negative)"
                          className={`w-6 h-6 rounded text-xs ${
                            rating === -1
                              ? 'bg-red-500/30 border border-red-500/50 text-red-400'
                              : 'bg-background border border-border hover:bg-muted'
                          }`}
                        >
                          👎
                        </button>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-[10px] text-muted-foreground flex items-center gap-2">
                          <span className="font-mono">#{i + 1}</span>
                          <span>
                            <strong className="text-foreground">{c.title}</strong>
                            {c.section_header && (
                              <>
                                {' > '}
                                <span className="text-blue-400">{c.section_header}</span>
                              </>
                            )}
                          </span>
                          <span className="ml-auto font-mono">
                            sim={c.similarity.toFixed(3)}
                          </span>
                        </div>
                        <div className="text-[10px] text-muted-foreground font-mono truncate">
                          {c.path}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Overall rating + comment + submit */}
          <div className="space-y-2 border-t border-border pt-2">
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Overall:</span>
              <button
                onClick={() => setOverallRating(overallRating === 1 ? 0 : 1)}
                className={`px-2 py-1 text-xs rounded ${
                  overallRating === 1
                    ? 'bg-green-500/30 border border-green-500/50 text-green-400'
                    : 'bg-background border border-border hover:bg-muted'
                }`}
              >
                👍 Useful
              </button>
              <button
                onClick={() => setOverallRating(overallRating === -1 ? 0 : -1)}
                className={`px-2 py-1 text-xs rounded ${
                  overallRating === -1
                    ? 'bg-red-500/30 border border-red-500/50 text-red-400'
                    : 'bg-background border border-border hover:bg-muted'
                }`}
              >
                👎 Not useful
              </button>
            </div>
            <textarea
              value={comment}
              onChange={e => setComment(e.target.value)}
              placeholder="Optional comment — what was missing, wrong, or could be improved?"
              rows={2}
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs resize-none"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={handleSubmitFeedback}
                disabled={
                  submitFeedback.isPending ||
                  !response.query_log_id ||
                  (overallRating === 0 &&
                    Object.keys(chunkRatings).length === 0 &&
                    !comment.trim())
                }
                className="h-7 px-3 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {submitFeedback.isPending ? 'Submitting…' : 'Submit feedback'}
              </button>
              {submittedFeedbackFor === response.query_log_id && (
                <span className="text-xs text-green-400">✓ feedback recorded</span>
              )}
              {submitFeedback.error && (
                <span className="text-xs text-red-400 font-mono">
                  {submitFeedback.error instanceof Error
                    ? submitFeedback.error.message
                    : String(submitFeedback.error)}
                </span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ServiceDetail({ name, onClose }: { name: string; onClose: () => void }) {
  const { data, isLoading } = useKBService(name)
  const deleteMut = useDeleteKBOverride()

  if (isLoading) return <p className="text-sm text-muted-foreground p-4">Loading...</p>
  if (!data) return <p className="text-sm text-muted-foreground p-4">Not found</p>

  const d = data.data
  return (
    <div className="border border-border rounded-lg bg-card p-4 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-bold">{data.name}</h3>
          <SourceBadge source={data.source} />
        </div>
        <div className="flex gap-2">
          {(data.source === 'override' || data.source === 'both') && (
            <button
              onClick={() => { deleteMut.mutate(name); onClose() }}
              className="text-xs px-2 py-1 rounded border border-border hover:bg-destructive/20 text-destructive"
            >
              Remove Override
            </button>
          )}
          <button onClick={onClose} className="text-xs px-2 py-1 rounded border border-border hover:bg-accent">
            Close
          </button>
        </div>
      </div>

      {d.description && <p className="text-xs text-muted-foreground">{d.description}</p>}

      {d.ports && d.ports.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Ports</h4>
          <div className="flex flex-wrap gap-1">
            {d.ports.map(p => (
              <span key={p} className="px-1.5 py-0.5 bg-muted rounded text-xs font-mono">{p}</span>
            ))}
          </div>
        </div>
      )}

      {d.tools && d.tools.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Tools ({d.tools.length})</h4>
          <div className="space-y-1">
            {d.tools.map((t, i) => (
              <div key={i} className="text-xs bg-muted/30 rounded p-2">
                <span className="font-medium">{t.name}</span>
                {t.purpose && <span className="text-muted-foreground"> &mdash; {t.purpose}</span>}
                {t.command && (
                  <pre className="mt-1 text-[11px] font-mono text-primary bg-muted/50 rounded px-2 py-1 overflow-x-auto">
                    {t.command}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {d.metasploit && d.metasploit.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Metasploit Modules ({d.metasploit.length})</h4>
          <div className="space-y-1">
            {d.metasploit.map((m, i) => (
              <div key={i} className="text-xs bg-muted/30 rounded p-2">
                <code className="font-mono text-primary">{m.module}</code>
                {m.purpose && <span className="text-muted-foreground ml-2">{m.purpose}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {d.nuclei_tags && d.nuclei_tags.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Nuclei Tags</h4>
          <div className="flex flex-wrap gap-1">
            {d.nuclei_tags.map(t => (
              <span key={t} className="px-1.5 py-0.5 bg-primary/10 text-primary rounded text-xs">{t}</span>
            ))}
          </div>
        </div>
      )}

      {d.common_vulns && d.common_vulns.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Common Vulnerabilities</h4>
          <div className="space-y-1">
            {d.common_vulns.map((v, i) => (
              <div key={i} className="text-xs text-muted-foreground">
                {typeof v === 'string' ? v : JSON.stringify(v)}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function AddServiceForm({ onDone }: { onDone: () => void }) {
  const upsert = useUpsertKBService()
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [ports, setPorts] = useState('')
  const [toolName, setToolName] = useState('')
  const [toolCmd, setToolCmd] = useState('')
  const [toolPurpose, setToolPurpose] = useState('')
  const [tools, setTools] = useState<{ name: string; command: string; purpose: string }[]>([])

  const addTool = () => {
    if (!toolName) return
    setTools(prev => [...prev, { name: toolName, command: toolCmd, purpose: toolPurpose }])
    setToolName('')
    setToolCmd('')
    setToolPurpose('')
  }

  const submit = () => {
    if (!name.trim()) return
    const parsedPorts = ports
      .split(',')
      .map(p => parseInt(p.trim(), 10))
      .filter(p => !isNaN(p))
    upsert.mutate(
      {
        name: name.trim().toLowerCase(),
        data: {
          description: desc,
          ports: parsedPorts,
          tools,
          metasploit: [],
          nuclei_tags: [],
          common_vulns: [],
        },
      },
      { onSuccess: onDone },
    )
  }

  return (
    <div className="border border-border rounded-lg bg-card p-4 space-y-3">
      <h3 className="text-sm font-bold">Add New Service</h3>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        <input
          placeholder="Service name (e.g. redis)"
          value={name}
          onChange={e => setName(e.target.value)}
          className="h-8 rounded-md border border-border bg-background px-2 text-xs"
        />
        <input
          placeholder="Ports (e.g. 6379)"
          value={ports}
          onChange={e => setPorts(e.target.value)}
          className="h-8 rounded-md border border-border bg-background px-2 text-xs"
        />
        <input
          placeholder="Description"
          value={desc}
          onChange={e => setDesc(e.target.value)}
          className="h-8 rounded-md border border-border bg-background px-2 text-xs"
        />
      </div>

      {/* Inline add tool */}
      <div className="border-t border-border pt-2">
        <p className="text-xs font-medium mb-1">Tools</p>
        <div className="flex gap-1 flex-wrap">
          {tools.map((t, i) => (
            <span key={i} className="px-1.5 py-0.5 bg-muted rounded text-xs">
              {t.name}
              <button onClick={() => setTools(prev => prev.filter((_, idx) => idx !== i))} className="ml-1 text-destructive">&times;</button>
            </span>
          ))}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-1 mt-1">
          <input placeholder="Tool name" value={toolName} onChange={e => setToolName(e.target.value)}
            className="h-7 rounded border border-border bg-background px-2 text-xs" />
          <input placeholder="Command" value={toolCmd} onChange={e => setToolCmd(e.target.value)}
            className="h-7 rounded border border-border bg-background px-2 text-xs" />
          <input placeholder="Purpose" value={toolPurpose} onChange={e => setToolPurpose(e.target.value)}
            className="h-7 rounded border border-border bg-background px-2 text-xs" />
          <button onClick={addTool}
            className="h-7 px-2 text-xs rounded border border-border hover:bg-accent">Add Tool</button>
        </div>
      </div>

      <div className="flex gap-2 pt-1">
        <button onClick={submit} disabled={upsert.isPending || !name.trim()}
          className="h-8 px-3 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
          Save Service
        </button>
        <button onClick={onDone}
          className="h-8 px-3 text-xs rounded-md border border-border hover:bg-accent">
          Cancel
        </button>
      </div>
    </div>
  )
}

export default function KnowledgeBase() {
  const { data, isLoading } = useKBServices()
  const [selected, setSelected] = useState<string | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [search, setSearch] = useState('')

  const services = (data?.services || []).filter(
    s =>
      !search ||
      s.name.includes(search.toLowerCase()) ||
      s.description.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Knowledge Base</h2>
        <div className="flex items-center gap-2">
          <input
            placeholder="Search services..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="h-8 w-48 rounded-md border border-border bg-background px-2 text-xs"
          />
          <button
            onClick={() => { setShowAdd(true); setSelected(null) }}
            className="h-8 px-3 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90"
          >
            Add Service
          </button>
        </div>
      </div>

      {showAdd && <AddServiceForm onDone={() => setShowAdd(false)} />}
      {selected && <ServiceDetail name={selected} onClose={() => setSelected(null)} />}

      <AskKnowledgeBase />
      <TrainingDataPanel />
      <RetrievalQualityPanel />

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        {isLoading ? (
          <p className="text-sm text-muted-foreground p-4">Loading knowledge base...</p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="text-left px-3 py-2 font-medium">Service</th>
                <th className="text-left px-3 py-2 font-medium">Ports</th>
                <th className="text-center px-3 py-2 font-medium">Tools</th>
                <th className="text-center px-3 py-2 font-medium">MSF</th>
                <th className="text-center px-3 py-2 font-medium">Nuclei</th>
                <th className="text-left px-3 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {services.map((svc: KBServiceSummary) => (
                <tr
                  key={svc.name}
                  onClick={() => { setSelected(svc.name); setShowAdd(false) }}
                  className="border-b border-border hover:bg-muted/20 cursor-pointer"
                >
                  <td className="px-3 py-2 font-medium">{svc.name}</td>
                  <td className="px-3 py-2 text-muted-foreground font-mono">
                    {svc.ports.slice(0, 5).join(', ')}{svc.ports.length > 5 ? '...' : ''}
                  </td>
                  <td className="px-3 py-2 text-center">{svc.tool_count}</td>
                  <td className="px-3 py-2 text-center">{svc.msf_count}</td>
                  <td className="px-3 py-2 text-center">{svc.nuclei_tags.length}</td>
                  <td className="px-3 py-2"><SourceBadge source={svc.source} /></td>
                </tr>
              ))}
              {services.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-muted-foreground">
                    {search ? 'No services match your search' : 'No services loaded'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        {data?.count ?? 0} services loaded from YAML knowledge base + database overrides
      </p>
    </div>
  )
}
