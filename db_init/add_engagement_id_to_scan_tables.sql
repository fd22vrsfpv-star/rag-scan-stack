-- =============================================================================
-- add_engagement_id_to_scan_tables.sql
--
-- Engagement isolation for scan-execution tables (Phase 1 of Option B).
--
-- Findings/assets are already engagement-scoped, but jobs / tasks /
-- scan_recommendations / pending_exploits / exploit_results were not -- so
-- when an operator switched to a new customer's engagement, the previous
-- engagement's scans and exploit queue still showed in the UI.  That broke
-- the engagement-isolation guarantee called out in CLAUDE.md and the README.
--
-- This migration:
--   * Adds a nullable engagement_id FK to each scan-execution table.
--   * ON DELETE SET NULL: deleting an engagement preserves scan history
--     (it loses its engagement context, but isn't destroyed).
--   * Creates partial indexes (engagement_id IS NOT NULL) for the dominant
--     "show me scans for engagement X" query pattern.
--
-- Backward compatibility:
--   Existing rows keep engagement_id = NULL.  Views must hide NULL rows when
--   an engagement is active so legacy/unscoped data doesn't leak across
--   engagements.  An "All / unscoped" admin view is the only place NULL
--   rows should appear.
--
-- Idempotent: safe to re-run.  All statements use IF NOT EXISTS.
-- =============================================================================

ALTER TABLE public.jobs                 ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;
ALTER TABLE public.tasks                ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;
ALTER TABLE public.scan_recommendations ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;
ALTER TABLE public.pending_exploits     ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;
ALTER TABLE public.exploit_results      ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_jobs_engagement                  ON public.jobs(engagement_id)                 WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_engagement                 ON public.tasks(engagement_id)                WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_engagement  ON public.scan_recommendations(engagement_id) WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pending_exploits_engagement      ON public.pending_exploits(engagement_id)     WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploit_results_engagement       ON public.exploit_results(engagement_id)      WHERE engagement_id IS NOT NULL;
