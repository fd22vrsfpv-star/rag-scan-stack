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
