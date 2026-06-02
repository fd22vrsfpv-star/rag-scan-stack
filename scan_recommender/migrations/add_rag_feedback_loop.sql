-- RAG feedback loop: rag_query_log + rag_feedback.
--
-- Layer 1 captures every /rag/ask call (query, embedding, top-K chunks,
-- similarity scores, LLM answer, duration, engagement_id) so we can
-- analyse retrieval quality offline.
--
-- Layer 2 closes the loop: operators rate answers + mark specific chunks
-- helpful or unhelpful via the dashboard.  The unhelpful set (chunks the
-- operator marked NOT relevant despite a high similarity score) is the
-- "hard negative" signal -- the most valuable training data for
-- embedding fine-tuning.
--
-- Idempotent: the same statements also run from _ensure_schema() in
-- scan_recommender/exploits_rag.py on container startup, so this file
-- is mainly for operators who want to apply it out of band.

-- NB: vector dimension must match exploit_chunks.embedding's dim.  768
-- is the default for nomic-embed-text.  _ensure_schema() reads the dim
-- dynamically; if you're applying this SQL by hand, substitute the
-- correct dim before running.
CREATE TABLE IF NOT EXISTS public.rag_query_log (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    query           text NOT NULL,
    query_embedding vector(768),
    top_k_chunk_ids bigint[],
    top_k_sims      float[],
    llm_answer      text,
    source          text NOT NULL,
    engagement_id   uuid,
    duration_ms     integer,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rag_query_log_created_idx
    ON public.rag_query_log(created_at DESC);
CREATE INDEX IF NOT EXISTS rag_query_log_engagement_idx
    ON public.rag_query_log(engagement_id) WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS rag_query_log_source_idx
    ON public.rag_query_log(source);

CREATE TABLE IF NOT EXISTS public.rag_feedback (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    query_log_id        uuid NOT NULL REFERENCES public.rag_query_log(id) ON DELETE CASCADE,
    rating              smallint CHECK (rating BETWEEN -1 AND 5),
    helpful_chunk_ids   bigint[],
    unhelpful_chunk_ids bigint[],
    comment             text,
    engagement_id       uuid,
    reviewer_id         text,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rag_feedback_query_log_idx
    ON public.rag_feedback(query_log_id);
CREATE INDEX IF NOT EXISTS rag_feedback_rating_idx
    ON public.rag_feedback(rating);
CREATE INDEX IF NOT EXISTS rag_feedback_engagement_idx
    ON public.rag_feedback(engagement_id) WHERE engagement_id IS NOT NULL;
