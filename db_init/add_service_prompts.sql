-- ============================================================================
-- Migration: per-service / per-port prompts + RAG training data
-- ============================================================================
-- Adds:
--   1. public.service_prompts — operator-authored guidance injected into the
--      LLM's tool-selection prompt whenever a matching service/port is seen.
--   2. service / port / doc_kind columns on public.exploit_chunks so training
--      documents can be scoped and retrieved per service or port.
--
-- Idempotent — safe to re-run. Apply with:
--   docker exec -i rag-postgres psql -U app -d scans < db_init/add_service_prompts.sql
-- See db_init/MIGRATION_GUIDE.md for the other apply paths.
-- ============================================================================

\connect scans

-- ── 1. service_prompts ──────────────────────────────────────────────────────
-- selector_type determines which columns are meaningful:
--   'service'      → service set, port NULL   (e.g. all http)
--   'port'         → port set, service NULL   (e.g. anything on 8080)
--   'port_service' → both set                 (e.g. http on 8080)
-- Resolution is most-specific-first: port_service → port → service.
CREATE TABLE IF NOT EXISTS public.service_prompts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    selector_type   text NOT NULL
                    CHECK (selector_type IN ('service','port','port_service','tech')),
    service         text,
    tech            text,
    port            integer CHECK (port IS NULL OR (port > 0 AND port <= 65535)),
    title           text NOT NULL,
    prompt          text NOT NULL DEFAULT '',
    training_notes  text,
    tags            text[] NOT NULL DEFAULT '{}'::text[],
    priority        integer NOT NULL DEFAULT 100,
    enabled         boolean NOT NULL DEFAULT true,
    engagement_id   uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    rag_ingested_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- Enforce that the selector columns match the declared selector_type, so a
    -- row can never be silently unreachable by the resolver.
    CONSTRAINT service_prompts_selector_shape CHECK (
        (selector_type = 'service'      AND service IS NOT NULL AND port IS NULL     AND tech IS NULL)
     OR (selector_type = 'port'         AND port    IS NOT NULL AND service IS NULL  AND tech IS NULL)
     OR (selector_type = 'port_service' AND port    IS NOT NULL AND service IS NOT NULL AND tech IS NULL)
     OR (selector_type = 'tech'         AND tech    IS NOT NULL AND service IS NULL  AND port IS NULL)
    )
);

-- ── 1b. Upgrade an existing service_prompts table to the 'tech' selector ────
-- Installs created before web-scan support have neither the column nor the
-- widened CHECK constraints. Both are re-created unconditionally so this stays
-- idempotent and converges older installs onto the current shape.
ALTER TABLE public.service_prompts ADD COLUMN IF NOT EXISTS tech text;

ALTER TABLE public.service_prompts DROP CONSTRAINT IF EXISTS service_prompts_selector_type_check;
ALTER TABLE public.service_prompts ADD CONSTRAINT service_prompts_selector_type_check
    CHECK (selector_type IN ('service','port','port_service','tech'));

ALTER TABLE public.service_prompts DROP CONSTRAINT IF EXISTS service_prompts_selector_shape;
ALTER TABLE public.service_prompts ADD CONSTRAINT service_prompts_selector_shape CHECK (
    (selector_type = 'service'      AND service IS NOT NULL AND port IS NULL     AND tech IS NULL)
 OR (selector_type = 'port'         AND port    IS NOT NULL AND service IS NULL  AND tech IS NULL)
 OR (selector_type = 'port_service' AND port    IS NOT NULL AND service IS NOT NULL AND tech IS NULL)
 OR (selector_type = 'tech'         AND tech    IS NOT NULL AND service IS NULL  AND port IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_service_prompts_tech
    ON public.service_prompts (lower(tech)) WHERE tech IS NOT NULL;

-- One rule per (selector, engagement). COALESCE keeps NULLs from defeating the
-- uniqueness check — in Postgres, NULL <> NULL, so a plain UNIQUE would allow
-- unlimited duplicate global rules.
-- `tech` MUST be part of the key: for selector_type='tech' both service and
-- port are NULL, so without it every tech rule would collapse onto the same
-- index entry and only one could ever exist.
-- Dropped first so installs created before the tech selector get the widened
-- key rather than silently keeping the old 4-column one.
DROP INDEX IF EXISTS idx_service_prompts_selector;
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_prompts_selector
    ON public.service_prompts (
        selector_type,
        COALESCE(service, ''),
        COALESCE(tech, ''),
        COALESCE(port, -1),
        COALESCE(engagement_id, '00000000-0000-0000-0000-000000000000'::uuid)
    );

CREATE INDEX IF NOT EXISTS idx_service_prompts_service
    ON public.service_prompts (lower(service)) WHERE service IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_service_prompts_port
    ON public.service_prompts (port) WHERE port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_service_prompts_engagement
    ON public.service_prompts (engagement_id);
CREATE INDEX IF NOT EXISTS idx_service_prompts_enabled
    ON public.service_prompts (enabled) WHERE enabled = true;

DROP TRIGGER IF EXISTS trg_service_prompts_updated ON public.service_prompts;
CREATE TRIGGER trg_service_prompts_updated
  BEFORE UPDATE ON public.service_prompts
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- ── 2. exploit_chunks: service/port scoping for training documents ──────────
-- Nullable so every existing ExploitDB and playbook row keeps working
-- unchanged; retrieval only filters when a service/port is supplied.
ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS service  text;
ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS port     integer;
ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS doc_kind text;
-- Detected technology (wordpress, tomcat, …) a training doc applies to, so
-- web-scan guidance can be retrieved by what's actually running on the target
-- rather than only by service/port.
ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS tech     text;

-- Partial indexes: the vast majority of rows (ExploitDB) have NULLs here, so
-- indexing only the populated rows keeps these small.
CREATE INDEX IF NOT EXISTS idx_exploit_chunks_service
    ON public.exploit_chunks (lower(service)) WHERE service IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploit_chunks_port
    ON public.exploit_chunks (port) WHERE port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploit_chunks_doc_kind
    ON public.exploit_chunks (doc_kind) WHERE doc_kind IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploit_chunks_tech
    ON public.exploit_chunks (lower(tech)) WHERE tech IS NOT NULL;

-- Mirrors the permissions block in ensure_all_tables.sql.
GRANT ALL PRIVILEGES ON public.service_prompts TO app;
DO $$ BEGIN
  GRANT ALL PRIVILEGES ON public.service_prompts TO scans;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

SELECT 'add_service_prompts.sql complete' AS status;
