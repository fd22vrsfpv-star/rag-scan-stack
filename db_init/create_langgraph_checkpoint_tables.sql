-- create_langgraph_checkpoint_tables.sql
-- ============================================================================
-- LangGraph durable checkpoint tables (AGENT_ENGINE=langgraph).
--
-- These four tables are LIBRARY-MANAGED by langgraph-checkpoint-postgres
-- (`PostgresSaver.setup()`, called on every langgraph session start and on
-- resume). They are declared here so that:
--   * a fresh install has them before the first agent session runs,
--   * scripts/post-install-check.sh can assert them like any other table,
--   * the schema is visible to the SQL-column guard instead of being invisible
--     runtime magic.
--
-- The DDL below is copied VERBATIM from the library's own migration list
-- (langgraph.checkpoint.postgres.base.MIGRATIONS, langgraph-checkpoint 4.x) so
-- the declared shape cannot drift from what the library creates.
--
-- IMPORTANT: `checkpoint_migrations` is deliberately left EMPTY here. The
-- library reads MAX(v) from it to decide which migrations to apply; with no
-- rows it re-applies all of them, and every one is idempotent
-- (CREATE TABLE IF NOT EXISTS / ALTER ... DROP NOT NULL /
-- ADD COLUMN IF NOT EXISTS / CREATE INDEX CONCURRENTLY IF NOT EXISTS). Seeding
-- version rows here would make the library SKIP migrations it has not run —
-- which is how a hand-mirrored schema silently drifts. Do not seed them.
--
-- Safe to run multiple times.
-- ============================================================================

\connect scans

CREATE TABLE IF NOT EXISTS public.checkpoint_migrations (
    v INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS public.checkpoints (
    thread_id TEXT NOT NULL,
    checkpoint_ns TEXT NOT NULL DEFAULT '',
    checkpoint_id TEXT NOT NULL,
    parent_checkpoint_id TEXT,
    type TEXT,
    checkpoint JSONB NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id)
);

CREATE TABLE IF NOT EXISTS public.checkpoint_blobs (
    thread_id TEXT NOT NULL,
    checkpoint_ns TEXT NOT NULL DEFAULT '',
    channel TEXT NOT NULL,
    version TEXT NOT NULL,
    type TEXT NOT NULL,
    blob BYTEA,
    PRIMARY KEY (thread_id, checkpoint_ns, channel, version)
);

CREATE TABLE IF NOT EXISTS public.checkpoint_writes (
    thread_id TEXT NOT NULL,
    checkpoint_ns TEXT NOT NULL DEFAULT '',
    checkpoint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    channel TEXT NOT NULL,
    type TEXT,
    blob BYTEA NOT NULL,
    task_path TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id, task_id, idx)
);

-- thread_id is the agent session id, so every lookup is by thread.
CREATE INDEX IF NOT EXISTS checkpoints_thread_id_idx ON public.checkpoints(thread_id);
CREATE INDEX IF NOT EXISTS checkpoint_blobs_thread_id_idx ON public.checkpoint_blobs(thread_id);
CREATE INDEX IF NOT EXISTS checkpoint_writes_thread_id_idx ON public.checkpoint_writes(thread_id);

GRANT ALL PRIVILEGES ON public.checkpoint_migrations TO app;
GRANT ALL PRIVILEGES ON public.checkpoints TO app;
GRANT ALL PRIVILEGES ON public.checkpoint_blobs TO app;
GRANT ALL PRIVILEGES ON public.checkpoint_writes TO app;
