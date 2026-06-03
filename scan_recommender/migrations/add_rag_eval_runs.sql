-- RAG retrieval evaluation: one row per /rag/eval/run invocation.
--
-- Replays every feedback-rated query in rag_query_log through the
-- current retrieval pipeline and scores the result against
-- operator-labeled helpful chunks (NDCG@K, MRR, recall@K, precision@K).
-- Tracking these over time is the only honest answer to "is fine-tuning
-- actually making retrieval better?" -- before/after numbers on the
-- same gold set.
--
-- Idempotent: also runs from _ensure_schema() in exploits_rag.py.

CREATE TABLE IF NOT EXISTS public.rag_eval_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    model_label     text NOT NULL,
    embed_model     text,
    eval_set_size   integer NOT NULL,
    ndcg_at_3       float,
    ndcg_at_5       float,
    ndcg_at_10      float,
    mrr             float,
    recall_at_3     float,
    recall_at_5     float,
    recall_at_10    float,
    precision_at_3  float,
    precision_at_5  float,
    per_query       jsonb,
    notes           text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rag_eval_runs_created_idx
    ON public.rag_eval_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS rag_eval_runs_model_idx
    ON public.rag_eval_runs(model_label);
