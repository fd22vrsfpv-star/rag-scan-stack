import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

// ---- Types ----

export interface RagRetrievedChunk {
  chunk_id: number
  title: string
  section_header: string | null
  path: string
  similarity: number
  edb_id: number | null
}

export interface RagAskResponse {
  answer: string
  sources: string[]
  retrieved: RagRetrievedChunk[]
  query_log_id: string | null
  duration_ms: number
}

export interface RagFeedbackPayload {
  query_log_id: string
  rating: number // -1 (down), 0 (neutral), 1 (up); 2-5 reserved for star-scale
  helpful_chunk_ids?: number[]
  unhelpful_chunk_ids?: number[]
  comment?: string
  reviewer_id?: string
}

export interface RagFeedbackStats {
  days: number
  summary: {
    queries: number
    feedback_rows: number
    thumbs_up: number
    thumbs_down: number
    star_rated: number
  }
  hard_negative_chunks: Array<{
    chunk_id: number
    times_marked_unhelpful: number
  }>
}

// ---- Hooks ----

/**
 * Ask the knowledge base a question.  POST instead of GET because the
 * call has side effects (writes a row to rag_query_log).  Returns the
 * answer along with the retrieved chunks and a query_log_id that the
 * feedback hook below references.
 */
export function useRagAsk() {
  return useMutation({
    mutationFn: (req: { q: string; top_k?: number }) =>
      apiFetch<RagAskResponse>('/rag/ask', {
        method: 'POST',
        body: JSON.stringify({ q: req.q, top_k: req.top_k ?? 6 }),
      }),
  })
}

/**
 * Submit operator feedback on a /rag/ask call.  Invalidates the stats
 * query so the dashboard updates immediately.
 */
export function useRagFeedback() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: RagFeedbackPayload) =>
      apiFetch<{ ok: boolean; feedback_id: string; created_at: string }>(
        '/rag/feedback',
        {
          method: 'POST',
          body: JSON.stringify(payload),
        },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rag-feedback-stats'] })
    },
  })
}

/**
 * Summary stats for the feedback loop.  Used on the KnowledgeBase page
 * to show "how many queries, what fraction rated, top hard-negative
 * chunks" so operators can see whether they've produced enough training
 * data to be useful yet.
 */
export function useRagFeedbackStats(days: number = 30) {
  return useQuery({
    queryKey: ['rag-feedback-stats', days],
    queryFn: () =>
      apiFetch<RagFeedbackStats>(`/rag/feedback/stats?days=${days}`),
    staleTime: 60_000,
  })
}

// ---- Layer 3: training-data extraction ----

export interface RagTrainingPreview {
  days: number
  min_rating: number | null
  raw_feedback_rows: number
  triplets: number
  reranker_rows: number
  grpo_rows: number
}

export interface RagTrainingExportResult {
  ok: boolean
  exported: boolean
  reason?: string
  output_dir?: string
  exported_at?: string
  days?: number
  raw_feedback_rows?: number
  triplets?: number
  reranker_rows?: number
  grpo_rows?: number
  files?: Record<string, number>
}

/** Preview of how many training rows the current feedback would extract
 * (embedding triplets, reranker rows, GRPO RLHF rows).  Cheap; safe to
 * poll. */
export function useRagTrainingPreview(days: number = 90) {
  return useQuery({
    queryKey: ['rag-training-preview', days],
    queryFn: () =>
      apiFetch<RagTrainingPreview>(`/rag/training/preview?days=${days}`),
    staleTime: 60_000,
  })
}

/** Materialise the three training datasets as JSONL on the host
 * (bind-mounted to /datasets/rag-YYYYMMDD-HHMMSS/). */
export function useRagTrainingExport() {
  return useMutation({
    mutationFn: (req: { days?: number; min_rating?: number | null }) =>
      apiFetch<RagTrainingExportResult>('/rag/training/export', {
        method: 'POST',
        body: JSON.stringify({
          days: req.days ?? 90,
          min_rating: req.min_rating ?? null,
        }),
      }),
  })
}
